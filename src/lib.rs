use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

pub mod avalanchego;
pub mod aws;
pub mod aws_cloudformation;
pub mod aws_cloudwatch;
pub mod aws_ec2;
pub mod aws_kms;
pub mod aws_s3;
pub mod aws_sts;
pub mod bash;
pub mod cert;
pub mod compress;
pub mod constants;
pub mod dev_machine;
pub mod envelope;
pub mod errors;
pub mod formatting;
pub mod http;
pub mod humanize;
pub mod id;
pub mod key;
pub mod node;
pub mod random;
mod time;

pub const DEFAULT_KEYS_TO_GENERATE: usize = 5;

/// Default machine beacon nodes size.
pub const DEFAULT_MACHINE_BEACON_NODES: u32 = 3;
/// Default machine non-beacon nodes size.
pub const DEFAULT_MACHINE_NON_BEACON_NODES: u32 = 2;

/// only required for custom networks
pub const MIN_MACHINE_BEACON_NODES: u32 = 1;
pub const MAX_MACHINE_BEACON_NODES: u32 = 10;

/// required for all node kinds
pub const MIN_MACHINE_NON_BEACON_NODES: u32 = 1;
/// TODO: support higher limit?
pub const MAX_MACHINE_NON_BEACON_NODES: u32 = 200;

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
    pub avalanchego_config: avalanchego::Config,
    /// Generated key infos.
    /// Only pre-funded for custom networks with a custom genesis file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_keys: Option<Vec<key::Info>>,
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
        avalanched_bin: &str,
        avalanchego_bin: &str,
        plugins_dir: Option<String>,
        avalanchego_config: avalanchego::Config,
        keys: usize,
    ) -> Self {
        // [year][month][date]-[system host-based id]
        let bucket = format!("avalanche-ops-{}-{}", time::get(6), id::sid(7));

        let network_id = avalanchego_config.network_id;
        let (id, beacon_nodes, non_beacon_nodes) =
            match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                Some(v) => (
                    id::generate(format!("aops-{}", *v).as_str()),
                    0,
                    DEFAULT_MACHINE_NON_BEACON_NODES,
                ),
                None => (
                    id::generate("aops-custom"),
                    DEFAULT_MACHINE_BEACON_NODES,
                    DEFAULT_MACHINE_NON_BEACON_NODES,
                ),
            };

        let mut generated_keys: Vec<key::Info> = Vec::new();
        let mut genesis_draft_file_path = Some(random::tmp_path(15).unwrap());
        if avalanchego_config.is_custom_network() {
            let (genesis, _generated_keys) = avalanchego::Genesis::new(network_id, keys).unwrap();
            genesis
                .sync(&genesis_draft_file_path.clone().unwrap())
                .unwrap();
            generated_keys = _generated_keys;
        } else {
            let ewoq_key = key::Key::from_private_key(key::EWOQ_KEY).unwrap();
            generated_keys.push(ewoq_key.to_info(network_id).unwrap());
            for _ in 1..keys {
                let k = key::Key::generate().unwrap();
                let info = k.to_info(network_id).unwrap();
                generated_keys.push(info);
            }
            genesis_draft_file_path = None;
        }

        Self {
            id,

            aws_resources: Some(aws::Resources {
                region: String::from("us-west-2"),
                bucket,
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
            },

            avalanchego_config,
            generated_keys: Some(generated_keys),
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
        let parent_dir = path.parent().unwrap();
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
            && !Path::new(&self.install_artifacts.plugins_dir.clone().unwrap()).exists()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "plugins_dir {} does not exist",
                    self.install_artifacts.plugins_dir.clone().unwrap()
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
                    .unwrap(),
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
                            .unwrap()
                    ),
                ));
            }
        }

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
  bucket: {}

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
        avalanchego::DEFAULT_CONFIG_FILE_PATH,
        avalanchego::DEFAULT_GENESIS_PATH,
        avalanchego::DEFAULT_SNOW_SAMPLE_SIZE,
        avalanchego::DEFAULT_SNOW_QUORUM_SIZE,
        avalanchego::DEFAULT_HTTP_PORT,
        avalanchego::DEFAULT_STAKING_PORT,
        avalanchego::DEFAULT_DB_DIR,
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

    let mut avago_config = avalanchego::Config::new();
    avago_config.config_file = Some(String::from(avalanchego::DEFAULT_CONFIG_FILE_PATH));
    avago_config.genesis = Some(String::from(avalanchego::DEFAULT_GENESIS_PATH));
    avago_config.network_id = 1337;
    avago_config.snow_sample_size = Some(avalanchego::DEFAULT_SNOW_SAMPLE_SIZE);
    avago_config.snow_quorum_size = Some(avalanchego::DEFAULT_SNOW_QUORUM_SIZE);
    avago_config.http_port = Some(avalanchego::DEFAULT_HTTP_PORT);
    avago_config.staking_port = Some(avalanchego::DEFAULT_STAKING_PORT);
    avago_config.db_dir = Some(String::from(avalanchego::DEFAULT_DB_DIR));

    let orig = Spec {
        id: id.clone(),

        aws_resources: Some(aws::Resources {
            region: String::from("us-west-2"),
            bucket: bucket.clone(),
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
        },

        avalanchego_config: avago_config,
        generated_keys: None,
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);

    assert!(cfg.aws_resources.is_some());
    let aws_reesources = cfg.aws_resources.unwrap();
    assert_eq!(aws_reesources.region, "us-west-2");
    assert_eq!(aws_reesources.bucket, bucket);

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
        avalanchego::DEFAULT_CONFIG_FILE_PATH,
    );
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .genesis
            .unwrap_or("".to_string()),
        avalanchego::DEFAULT_GENESIS_PATH,
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
        avalanchego::DEFAULT_HTTP_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().staking_port.unwrap_or(0),
        avalanchego::DEFAULT_STAKING_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .db_dir
            .unwrap_or("".to_string()),
        avalanchego::DEFAULT_DB_DIR,
    );
}
