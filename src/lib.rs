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
use crate::avalanche::{
    avalanchego::{config as avalanchego_config, genesis as avalanchego_genesis},
    constants,
    coreth::config as coreth_config,
    key, node,
};

/// ref. https://doc.rust-lang.org/reference/items/modules.html
pub mod dev;

pub const DEFAULT_KEYS_TO_GENERATE: usize = 2;

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
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
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
    pub avalanchego_config: avalanchego_config::Config,
    /// If non-empty, the JSON-encoded data are saved to a file
    /// in Path::new(&avalanchego_config.chain_config_dir).join("C").
    pub coreth_config: coreth_config::Config,
    /// If non-empty, the JSON-encoded data are saved to a file
    /// and used for "--genesis" in Path::new(&avalanchego_config.genesis).
    /// This includes "coreth_genesis::Genesis".
    /// Names after "_template" since it has not included
    /// initial stakers yet with to-be-created node IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanchego_genesis_template: Option<avalanchego_genesis::Genesis>,

    /// Generated key infos.
    /// Only pre-funded for custom networks with a custom genesis file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_seed_private_keys: Option<Vec<key::PrivateKeyInfo>>,

    /// Current all nodes. May be stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_nodes: Option<Vec<node::Node>>,
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
        avalanchego_config: avalanchego_config::Config,
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

        let (avalanchego_genesis_template, generated_seed_keys) = {
            if avalanchego_config.is_custom_network() {
                let (a, b) = avalanchego_genesis::Genesis::new(network_id, keys)
                    .expect("unexpected None genesis");
                (Some(a), b)
            } else {
                let mut seed_keys: Vec<key::PrivateKeyInfo> = Vec::new();
                let ewoq_key = key::Key::from_private_key(key::EWOQ_KEY)
                    .expect("unexpected key creation failure");
                seed_keys.push(
                    ewoq_key
                        .to_info(network_id)
                        .expect("unexpected to_info failure"),
                );
                for _ in 1..keys {
                    let k = key::Key::generate().expect("unexpected key generate failure");
                    let info = k.to_info(network_id).expect("unexpected to_info failure");
                    seed_keys.push(info);
                }
                (None, seed_keys)
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
            },

            avalanchego_config,
            coreth_config: coreth_config::Config::default(),
            avalanchego_genesis_template,

            generated_seed_private_keys: Some(generated_seed_keys),

            current_nodes: None,
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

        let f = File::open(&file_path).map_err(|e| {
            return Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            );
        })?;
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
            if self.avalanchego_genesis_template.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify 'avalanchego_genesis_template' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
            if self.machine.beacon_nodes.unwrap_or(0) > 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify non-zero 'machine.beacon_nodes' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
        } else {
            if self.avalanchego_genesis_template.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "must specify 'avalanchego_genesis_template' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
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
        }

        Ok(())
    }
}

#[test]
fn test_spec() {
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

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

avalanchego_config:
  config-file: /etc/avalanche.config.json
  network-id: 1
  db-type: leveldb
  db-dir: /avalanche-data
  log-dir: /var/log/avalanche
  log-level: INFO
  http-port: 9650
  http-host: 0.0.0.0
  http-tls-enabled: false
  staking-enabled: true
  staking-port: 9651
  staking-tls-key-file: "/etc/pki/tls/certs/avalanched.pki.key"
  staking-tls-cert-file: "/etc/pki/tls/certs/avalanched.pki.crt"
  snow-sample-size: 20
  snow-quorum-size: 15
  snow-concurrent-repolls: 24
  snow-max-time-processing: "5m"
  snow-rogue-commit-threshold: 40
  snow-virtuous-commit-threshold: 40
  index-enabled: false
  index-allow-incomplete: false
  api-admin-enabled: true
  api-info-enabled: true
  api-keystore-enabled: true
  api-metrics-enabled: true
  api-health-enabled: true
  api-ipcs-enabled: true
  chain-config-dir: /etc/avalanche/configs/chains
  subnet-config-dir: /etc/avalanche/configs/subnets
  profile-dir: /var/log/avalanche-profile/avalanche
  network-minimum-timeout: "3s"

coreth_config:
  coreth-admin-api-enabled: true
  metrics-enabled: true
  log-level: "info"


"#,
        id, bucket, avalanched_bin, avalanchego_bin, plugins_dir,
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

    let mut avalanchego_config = avalanchego_config::Config::default();
    avalanchego_config.genesis = None;
    avalanchego_config.network_id = 1;

    let orig = Spec {
        id: id.clone(),

        aws_resources: Some(aws::Resources {
            region: String::from("us-west-2"),
            s3_bucket: bucket.clone(),
            ..aws::Resources::default()
        }),

        machine: Machine {
            beacon_nodes: None,
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
        },

        avalanchego_config,
        coreth_config: coreth_config::Config::default(),
        avalanchego_genesis_template: None,

        generated_seed_private_keys: None,
        current_nodes: None,
    };

    assert_eq!(cfg, orig);
    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

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

    assert!(cfg.machine.beacon_nodes.is_none());
    assert_eq!(cfg.machine.non_beacon_nodes, 20);
    assert!(cfg.machine.instance_types.is_some());
    let instance_types = cfg.machine.instance_types.unwrap();
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");

    assert_eq!(cfg.avalanchego_config.clone().network_id, 1);
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .config_file
            .unwrap_or("".to_string()),
        avalanchego_config::DEFAULT_CONFIG_FILE_PATH,
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
        cfg.avalanchego_config.clone().http_port,
        avalanchego_config::DEFAULT_HTTP_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().staking_port,
        avalanchego_config::DEFAULT_STAKING_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().db_dir,
        avalanchego_config::DEFAULT_DB_DIR,
    );
}

/// Represents the S3/storage key path.
/// MUST be kept in sync with "cloudformation/avalanche-node/ec2_instance_role.yaml".
pub enum StorageNamespace {
    ConfigFile(String),
    DevMachineConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),

    /// Valid genesis file with initial stakers.
    /// Only updated after beacon nodes become active.
    GenesisFile(String),

    AvalanchedBin(String),
    AvalancheBin(String),
    AvalancheBinCompressed(String),
    PluginsDir(String),

    PkiKeyDir(String),

    /// before db downloads
    DiscoverProvisioningBeaconNodesDir(String),
    DiscoverProvisioningBeaconNode(String, node::Node),
    DiscoverProvisioningNonBeaconNodesDir(String),
    DiscoverProvisioningNonBeaconNode(String, node::Node),

    DiscoverBootstrappingBeaconNodesDir(String),
    DiscoverBootstrappingBeaconNode(String, node::Node),

    DiscoverReadyBeaconNodesDir(String),
    DiscoverReadyBeaconNode(String, node::Node),
    DiscoverReadyNonBeaconNodesDir(String),
    DiscoverReadyNonBeaconNode(String, node::Node),

    BackupsDir(String),

    EventsUpdateArtifactsDir(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::ConfigFile(id) => format!("{}/avalanche-ops.config.yaml", id),
            StorageNamespace::DevMachineConfigFile(id) => format!("{}/dev-machine.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }

            StorageNamespace::GenesisFile(id) => format!("{}/genesis.json", id),

            StorageNamespace::AvalanchedBin(id) => format!("{}/install/avalanched", id),
            StorageNamespace::AvalancheBin(id) => format!("{}/install/avalanche", id),
            StorageNamespace::AvalancheBinCompressed(id) => {
                format!("{}/install/avalanche.zstd", id)
            }
            StorageNamespace::PluginsDir(id) => format!("{}/install/plugins", id),

            StorageNamespace::PkiKeyDir(id) => {
                format!("{}/pki", id)
            }

            StorageNamespace::DiscoverProvisioningBeaconNodesDir(id) => {
                format!("{}/discover/provisioning-non-beacon-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverProvisioningNonBeaconNodesDir(id) => {
                format!("{}/discover/provisioning-non-beacon-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningNonBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverBootstrappingBeaconNodesDir(id) => {
                format!("{}/discover/bootstrapping-beacon-nodes", id)
            }
            StorageNamespace::DiscoverBootstrappingBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/bootstrapping-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverReadyBeaconNodesDir(id) => {
                format!("{}/discover/ready-beacon-nodes", id)
            }
            StorageNamespace::DiscoverReadyBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverReadyNonBeaconNodesDir(id) => {
                format!("{}/discover/ready-non-beacon-nodes", id)
            }
            StorageNamespace::DiscoverReadyNonBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-non-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::BackupsDir(id) => {
                format!("{}/backups", id)
            }

            // TODO: if non-empty and last modified delta is <5-min, trigger updates
            // TODO: implement helper to add new artifacts
            StorageNamespace::EventsUpdateArtifactsDir(id) => {
                format!("{}/events/update-artifacts", id)
            }
        }
    }

    pub fn parse_node_from_path(storage_path: &str) -> io::Result<node::Node> {
        let p = Path::new(storage_path);
        let file_name = match p.file_name() {
            Some(v) => v,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    String::from("failed Path.file_name (None)"),
                ));
            }
        };
        let file_name = file_name.to_str().unwrap();
        let splits: Vec<&str> = file_name.split('_').collect();
        if splits.len() != 2 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "file name {} of storage_path {} expected two splits for '_' (got {})",
                    file_name,
                    storage_path,
                    splits.len(),
                ),
            ));
        }

        let compressed_id = splits[1];
        match node::Node::decompress_base58(compressed_id.replace(".yaml", "")) {
            Ok(node) => Ok(node),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed node::Node::decompress_base64 {}", e),
                ));
            }
        }
    }
}

#[test]
fn test_storage_path() {
    use crate::random;
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random::string(10);
    let instance_id = random::string(5);
    let node_id = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_ip = "1.2.3.4";

    let node = node::Node::new(
        node::Kind::NonBeacon,
        &instance_id,
        node_id,
        node_ip,
        "http",
        9650,
    );
    let p = StorageNamespace::DiscoverReadyNonBeaconNode(
        id,
        node::Node {
            kind: String::from("non-beacon"),
            machine_id: instance_id.clone(),
            node_id: node_id.to_string(),
            public_ip: node_ip.to_string(),
            http_endpoint: format!("http://{}:9650", node_ip),
        },
    );
    let storage_path = p.encode();
    info!("KeyPath: {}", storage_path);

    let node_parsed = StorageNamespace::parse_node_from_path(&storage_path).unwrap();
    assert_eq!(node, node_parsed);
}

#[test]
fn test_append_slash() {
    let s = "hello";
    assert_eq!(append_slash(s), "hello/");

    let s = "hello/";
    assert_eq!(append_slash(s), "hello/");
}

pub fn append_slash(k: &str) -> String {
    let n = k.len();
    if &k[n - 1..] == "/" {
        String::from(k)
    } else {
        format!("{}/", k)
    }
}
