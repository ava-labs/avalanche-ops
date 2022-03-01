use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

pub mod errors;

/// ref. https://doc.rust-lang.org/reference/items/modules.html
pub mod aws;

/// ref. https://doc.rust-lang.org/reference/items/modules.html
pub mod utils;
use crate::utils::{random, time};

/// ref. https://doc.rust-lang.org/reference/items/modules.html
pub mod avalanche;
use crate::avalanche::{config as avalanche_config, constants, genesis, key};

/// ref. https://doc.rust-lang.org/reference/items/modules.html
pub mod dev;

pub const DEFAULT_KEYS_TO_GENERATE: usize = 5;

/// Default machine beacon nodes size.
/// only required for custom networks
pub const DEFAULT_MACHINE_BEACON_NODES: u32 = 2;
pub const MIN_MACHINE_BEACON_NODES: u32 = 1;
pub const MAX_MACHINE_BEACON_NODES: u32 = 10; // TODO: allow higher number?

/// Default machine non-beacon nodes size.
pub const DEFAULT_MACHINE_NON_BEACON_NODES: u32 = 2;
pub const MIN_MACHINE_NON_BEACON_NODES: u32 = 1;
pub const MAX_MACHINE_NON_BEACON_NODES: u32 = 200; // TODO: allow higher number?

/// Represents network-level configuration shared among all nodes.
/// The node-level configuration is generated during each
/// bootstrap process (e.g., certificates) and not defined
/// in this cluster-level "Config".
/// At the beginning, the user is expected to provide this configuration.
/// "Clone" is for deep-copying.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    /// User-provided ID of the cluster/test.
    /// This is NOT the avalanche node ID.
    /// This is NOT the avalanche network ID.
    #[serde(default)]
    pub id: String,

    /// AWS resources if run in AWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_resources: Option<aws::Resources>,
    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,
    /// Install artifacts to share with remote machines.
    pub install_artifacts: InstallArtifacts,
    /// Represents the configuration for "avalanchego".
    /// Set as if run in remote machines.
    /// For instance, "config-file" must be the path valid
    /// in the remote machines.
    /// Must be "kebab-case" to be compatible with "avalanchego".
    pub avalanchego_config: avalanche_config::AvalancheGo,
    /// Generated key infos.
    /// Only pre-funded for custom networks with a custom genesis file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_seed_private_keys: Option<Vec<key::PrivateKeyInfo>>,
}

/// Defines how the underlying infrastructure is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_nodes: Option<u32>,
    #[serde(default)]
    pub non_beacon_nodes: u32,
    #[serde(default)]
    pub instance_types: Option<Vec<String>>,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct InstallArtifacts {
    /// "avalanched" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "install/avalanched" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    #[serde(default)]
    pub avalanched_bin: String,
    /// AvalancheGo binary path in the local environment.
    /// The file is "compressed" and uploaded to remote storage
    /// to be shared with remote machines.
    ///
    ///  build
    ///    ├── avalanchego (the binary from compiling the app directory)
    ///    └── plugins
    ///        └── evm
    #[serde(default)]
    pub avalanchego_bin: String,
    /// Plugin directories in the local environment.
    /// Files (if any) are uploaded to the remote storage to be shared
    /// with remote machiens.
    #[serde(default)]
    pub plugins_dir: Option<String>,
    /// Genesis "DRAFT" file path in the local machine.
    /// Some fields to be overwritten (e.g., initial stakers with beacon nodes).
    /// MUST BE NON-EMPTY for custom network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_draft_file_path: Option<String>,
    // TODO: support https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coreth_evm_config_file_path: Option<String>,
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String),
    Vpc(String),
    AsgBeaconNodes(String),
    AsgNonBeaconNodes(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::AsgBeaconNodes(id) => format!("{}-asg-beacon-nodes", id),
            StackName::AsgNonBeaconNodes(id) => format!("{}-asg-non-beacon-nodes", id),
        }
    }
}

impl Spec {
    /// Creates a default Status based on the network ID.
    /// For custom networks, it generates the "keys" number of keys
    /// and pre-funds them in the genesis file path, which is
    /// included in "InstallArtifacts.genesis_draft_file_path".
    pub fn default_aws(
        region: &str,
        avalanched_bin: &str,
        avalanchego_bin: &str,
        plugins_dir: Option<String>,
        coreth_evm_config_file_path: Option<String>,
        avalanchego_config: avalanche_config::AvalancheGo,
        keys: usize,
    ) -> Self {
        // [year][month][date]-[system host-based id]
        let s3_bucket = format!("avalanche-ops-{}-{}", time::get(6), random::sid(10));

        let network_id = avalanchego_config.network_id;
        let (id, beacon_nodes, non_beacon_nodes) =
            match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                Some(v) => (
                    random::generate_id(format!("aops-{}", *v).as_str()),
                    0,
                    DEFAULT_MACHINE_NON_BEACON_NODES,
                ),
                None => (
                    random::generate_id("aops-custom"),
                    DEFAULT_MACHINE_BEACON_NODES,
                    DEFAULT_MACHINE_NON_BEACON_NODES,
                ),
            };

        let (generated_seed_keys, genesis_draft_file_path) = {
            if avalanchego_config.is_custom_network() {
                let (genesis, _generated_seed_keys) =
                    genesis::AvalancheGo::new(network_id, keys).expect("unexpected None genesis");
                let genesis_draft_file_path =
                    Some(random::tmp_path(15, Some(".json")).expect("unexpected None tmp_path"));
                genesis
                    .sync(
                        &genesis_draft_file_path
                            .clone()
                            .expect("unexpected None genesis draft file path"),
                    )
                    .expect("unexpected sync failure");
                (_generated_seed_keys, genesis_draft_file_path)
            } else {
                let mut _generated_seed_keys: Vec<key::PrivateKeyInfo> = Vec::new();
                let ewoq_key = key::Key::from_private_key(key::EWOQ_KEY)
                    .expect("unexpected key creation failure");
                _generated_seed_keys.push(
                    ewoq_key
                        .to_info(network_id)
                        .expect("unexpected to_info failure"),
                );
                for _ in 1..keys {
                    let k = key::Key::generate().expect("unexpected key generate failure");
                    let info = k.to_info(network_id).expect("unexpected to_info failure");
                    _generated_seed_keys.push(info);
                }
                (_generated_seed_keys, None)
            }
        };
        Self {
            id,

            aws_resources: Some(aws::Resources {
                region: String::from(region),
                s3_bucket,
                ..aws::Resources::default()
            }),

            machine: Machine {
                beacon_nodes: Some(beacon_nodes),
                non_beacon_nodes,
                instance_types: Some(vec![
                    String::from("c6a.large"),
                    String::from("m6a.large"),
                    String::from("m5.large"),
                    String::from("c5.large"),
                ]),
            },

            install_artifacts: InstallArtifacts {
                avalanched_bin: avalanched_bin.to_string(),
                avalanchego_bin: avalanchego_bin.to_string(),
                plugins_dir,
                genesis_draft_file_path,
                coreth_evm_config_file_path,
            },

            avalanchego_config,
            generated_seed_private_keys: Some(generated_seed_keys),
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Spec to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current spec to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Spec to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Spec to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading Spec from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = match File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to open {} ({})", file_path, e),
                ));
            }
        };
        serde_yaml::from_reader(f).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e));
        })
    }

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating Spec");

        if self.id.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "'id' cannot be empty"));
        }

        // some AWS resources have tag limit of 32-character
        if self.id.len() > 28 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'id' length cannot be >28 (got {})", self.id.len()),
            ));
        }

        match &self.aws_resources {
            Some(v) => {
                if v.region.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "'machine.region' cannot be empty",
                    ));
                }
            }
            None => {}
        }
        if self.aws_resources.is_some() {
            let aws_resources = self
                .aws_resources
                .clone()
                .expect("unexpected None aws_resources");
            if aws_resources.db_backup_s3_region.is_some()
                && aws_resources.db_backup_s3_bucket.is_none()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "{} missing corresponding bucket",
                        aws_resources
                            .db_backup_s3_bucket
                            .expect("unexpected aws_resources.db_backup_s3_bucket")
                    ),
                ));
            }
            if aws_resources.db_backup_s3_bucket.is_some()
                && aws_resources.db_backup_s3_key.is_none()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "{} missing corresponding key",
                        aws_resources
                            .db_backup_s3_bucket
                            .expect("unexpected aws_resources.db_backup_s3_bucket")
                    ),
                ));
            }
            if aws_resources.db_backup_s3_bucket.is_some()
                && aws_resources.db_backup_s3_region.is_none()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "{} missing corresponding region",
                        aws_resources
                            .db_backup_s3_bucket
                            .expect("unexpected aws_resources.db_backup_s3_bucket")
                    ),
                ));
            }
        }

        if self.machine.non_beacon_nodes < MIN_MACHINE_NON_BEACON_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_beacon_nodes' {} <minimum {}",
                    self.machine.non_beacon_nodes, MIN_MACHINE_NON_BEACON_NODES
                ),
            ));
        }
        if self.machine.non_beacon_nodes > MAX_MACHINE_NON_BEACON_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_beacon_nodes' {} >maximum {}",
                    self.machine.non_beacon_nodes, MAX_MACHINE_NON_BEACON_NODES
                ),
            ));
        }

        if !Path::new(&self.install_artifacts.avalanched_bin).exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "avalanched_bin {} does not exist",
                    self.install_artifacts.avalanched_bin
                ),
            ));
        }
        if !Path::new(&self.install_artifacts.avalanchego_bin).exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "avalanchego_bin {} does not exist",
                    self.install_artifacts.avalanchego_bin
                ),
            ));
        }
        if self.install_artifacts.plugins_dir.is_some()
            && !Path::new(
                &self
                    .install_artifacts
                    .plugins_dir
                    .clone()
                    .expect("unexpected None install_artifacts.plugins_dir"),
            )
            .exists()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "plugins_dir {} does not exist",
                    self.install_artifacts
                        .plugins_dir
                        .clone()
                        .expect("unexpected None install_artifacts.plugins_dir")
                ),
            ));
        }

        if !self.avalanchego_config.is_custom_network() {
            if self.machine.beacon_nodes.unwrap_or(0) > 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify non-zero 'machine.beacon_nodes' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
            if self.install_artifacts.genesis_draft_file_path.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("cannot specify 'install_artifacts.genesis_draft_file_path' for network_id {:?}", self.avalanchego_config.network_id),
                ));
            }
        }

        if self.avalanchego_config.is_custom_network() {
            if self.machine.beacon_nodes.unwrap_or(0) == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot specify 0 for 'machine.beacon_nodes' for custom network",
                ));
            }
            if self.machine.beacon_nodes.unwrap_or(0) < MIN_MACHINE_BEACON_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.beacon_nodes' {} below min {}",
                        self.machine.beacon_nodes.unwrap_or(0),
                        MIN_MACHINE_BEACON_NODES
                    ),
                ));
            }
            if self.machine.beacon_nodes.unwrap_or(0) > MAX_MACHINE_BEACON_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.beacon_nodes' {} exceeds limit {}",
                        self.machine.beacon_nodes.unwrap_or(0),
                        MAX_MACHINE_BEACON_NODES
                    ),
                ));
            }
            if self.install_artifacts.genesis_draft_file_path.is_none() {
                return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!("MUST specify 'install_artifacts.genesis_draft_file_path' for custom network_id {}", self.avalanchego_config.network_id),
                        ));
            }
            if !Path::new(
                &self
                    .install_artifacts
                    .genesis_draft_file_path
                    .clone()
                    .expect("unexpected None install_artifacts.genesis_draft_file_path"),
            )
            .exists()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "install_artifacts.genesis_draft_file_path {} does not exist",
                        self.install_artifacts
                            .genesis_draft_file_path
                            .clone()
                            .expect("unexpected None install_artifacts.genesis_draft_file_path")
                    ),
                ));
            }
        }
        if self.install_artifacts.coreth_evm_config_file_path.is_some()
            && !Path::new(
                &self
                    .install_artifacts
                    .coreth_evm_config_file_path
                    .clone()
                    .expect("unexpected None install_artifacts.coreth_evm_config_file_path"),
            )
            .exists()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "install_artifacts.coreth_evm_config_file_path {} does not exist",
                    self.install_artifacts
                        .coreth_evm_config_file_path
                        .clone()
                        .expect("unexpected None install_artifacts.coreth_evm_config_file_path")
                ),
            ));
        };

        Ok(())
    }
}

#[test]
fn test_spec() {
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    use rust_embed::RustEmbed;
    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;
    let genesis_json = Asset::get("artifacts/sample.genesis.json").unwrap();
    let genesis_json_contents = std::str::from_utf8(genesis_json.data.as_ref()).unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(genesis_json_contents.as_bytes());
    assert!(ret.is_ok());
    let genesis_draft_file_path = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanched_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanchego_bin = f.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let plugin_path = tmp_dir.path().join(random::string(10));
    let mut f = File::create(&plugin_path).unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let plugins_dir = tmp_dir.path().as_os_str().to_str().unwrap();

    // test just to see how "read_dir" works in Rust
    for entry in fs::read_dir(plugins_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        info!("read_dir: {:?}", path);
    }

    let id = random::string(10);
    let bucket = format!("test-{}", time::get(8));

    let contents = format!(
        r#"

id: {}

aws_resources:
  region: us-west-2
  s3_bucket: {}

machine:
  beacon_nodes: 10
  non_beacon_nodes: 20
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large

install_artifacts:
  avalanched_bin: {}
  avalanchego_bin: {}
  plugins_dir: {}
  genesis_draft_file_path: {}

avalanchego_config:
  config-file: {}
  network-id: 1337
  genesis: {}
  snow-sample-size: {}
  snow-quorum-size: {}
  http-port: {}
  staking-port: {}
  db-dir: {}

"#,
        id,
        bucket,
        avalanched_bin,
        avalanchego_bin,
        plugins_dir,
        genesis_draft_file_path,
        avalanche_config::DEFAULT_CONFIG_FILE_PATH,
        avalanche_config::DEFAULT_GENESIS_PATH,
        avalanche_config::DEFAULT_SNOW_SAMPLE_SIZE,
        avalanche_config::DEFAULT_SNOW_QUORUM_SIZE,
        avalanche_config::DEFAULT_HTTP_PORT,
        avalanche_config::DEFAULT_STAKING_PORT,
        avalanche_config::DEFAULT_DB_DIR,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let ret = Spec::load(config_path);
    assert!(ret.is_ok());
    let cfg = ret.unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let mut avalanchego_config = avalanche_config::AvalancheGo::new();
    avalanchego_config.config_file = Some(String::from(avalanche_config::DEFAULT_CONFIG_FILE_PATH));
    avalanchego_config.genesis = Some(String::from(avalanche_config::DEFAULT_GENESIS_PATH));
    avalanchego_config.network_id = 1337;
    avalanchego_config.snow_sample_size = Some(avalanche_config::DEFAULT_SNOW_SAMPLE_SIZE);
    avalanchego_config.snow_quorum_size = Some(avalanche_config::DEFAULT_SNOW_QUORUM_SIZE);
    avalanchego_config.http_port = Some(avalanche_config::DEFAULT_HTTP_PORT);
    avalanchego_config.staking_port = Some(avalanche_config::DEFAULT_STAKING_PORT);
    avalanchego_config.db_dir = String::from(avalanche_config::DEFAULT_DB_DIR);

    let orig = Spec {
        id: id.clone(),

        aws_resources: Some(aws::Resources {
            region: String::from("us-west-2"),
            s3_bucket: bucket.clone(),
            ..aws::Resources::default()
        }),

        machine: Machine {
            beacon_nodes: Some(10),
            non_beacon_nodes: 20,
            instance_types: Some(vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ]),
        },

        install_artifacts: InstallArtifacts {
            avalanched_bin: avalanched_bin.to_string(),
            avalanchego_bin: avalanchego_bin.to_string(),
            plugins_dir: Some(plugins_dir.to_string()),
            genesis_draft_file_path: Some(String::from(genesis_draft_file_path)),
            coreth_evm_config_file_path: None,
        },

        avalanchego_config,
        generated_seed_private_keys: None,
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);

    assert!(cfg.aws_resources.is_some());
    let aws_reesources = cfg.aws_resources.unwrap();
    assert_eq!(aws_reesources.region, "us-west-2");
    assert_eq!(aws_reesources.s3_bucket, bucket);

    assert_eq!(cfg.install_artifacts.avalanched_bin, avalanched_bin);
    assert_eq!(cfg.install_artifacts.avalanchego_bin, avalanchego_bin);
    assert_eq!(
        cfg.install_artifacts
            .plugins_dir
            .unwrap_or(String::from("")),
        plugins_dir.to_string()
    );
    assert_eq!(
        cfg.install_artifacts
            .genesis_draft_file_path
            .unwrap_or(String::from("")),
        genesis_draft_file_path
    );

    assert_eq!(cfg.machine.beacon_nodes.unwrap_or(0), 10);
    assert_eq!(cfg.machine.non_beacon_nodes, 20);
    assert!(cfg.machine.instance_types.is_some());
    let instance_types = cfg.machine.instance_types.unwrap();
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");

    assert_eq!(cfg.avalanchego_config.clone().network_id, 1337);
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .config_file
            .unwrap_or("".to_string()),
        avalanche_config::DEFAULT_CONFIG_FILE_PATH,
    );
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .genesis
            .unwrap_or("".to_string()),
        avalanche_config::DEFAULT_GENESIS_PATH,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().snow_sample_size.unwrap_or(0),
        20
    );
    assert_eq!(
        cfg.avalanchego_config.clone().snow_quorum_size.unwrap_or(0),
        15
    );
    assert_eq!(
        cfg.avalanchego_config.clone().http_port.unwrap_or(0),
        avalanche_config::DEFAULT_HTTP_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().staking_port.unwrap_or(0),
        avalanche_config::DEFAULT_STAKING_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().db_dir,
        avalanche_config::DEFAULT_DB_DIR,
    );
}
