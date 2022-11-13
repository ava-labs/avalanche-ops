mod avalanched;
pub mod aws;

use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use avalanche_types::{
    avalanchego::{config as avalanchego_config, genesis as avalanchego_genesis},
    constants,
    coreth::config as coreth_config,
    key, node,
    subnet_evm::{config as subnet_evm_config, genesis as subnet_evm_genesis},
};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};

/// Represents each anchor/non-anchor node.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Node {
    pub kind: String,
    pub machine_id: String,
    pub node_id: String,
    pub public_ip: String,
    pub http_endpoint: String,
}

impl Node {
    pub fn new(
        kind: node::Kind,
        machine_id: &str,
        node_id: &str,
        public_ip: &str,
        http_scheme: &str,
        http_port: u32,
    ) -> Self {
        Self {
            kind: String::from(kind.as_str()),
            machine_id: String::from(machine_id),
            node_id: String::from(node_id),
            public_ip: String::from(public_ip),
            http_endpoint: format!("{}://{}:{}", http_scheme, public_ip, http_port),
        }
    }

    /// Converts to string with YAML encoder.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize to YAML {}", e),
            )),
        }
    }

    /// Saves the current anchor node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing Node to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Node info to YAML {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        log::info!("loading node from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(file_path).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            )
        })?;

        serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }

    /// Encodes the object in YAML format, compresses, and apply base58.
    /// Used for shortening S3 file name.
    pub fn compress_base58(&self) -> io::Result<String> {
        let d = match serde_yaml::to_string(self) {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Node to YAML {}", e),
                ));
            }
        };
        let compressed =
            compress_manager::pack(d.as_bytes(), compress_manager::Encoder::ZstdBase58(3))?;
        Ok(String::from_utf8(compressed).expect("unexpected None String::from_utf8"))
    }

    /// Reverse of "compress_base64".
    pub fn decompress_base58(d: String) -> io::Result<Self> {
        let decompressed =
            compress_manager::unpack(d.as_bytes(), compress_manager::Decoder::ZstdBase58)?;
        serde_yaml::from_slice(&decompressed)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }
}

#[test]
fn test_node() {
    let d = r#"
kind: anchor
machine_id: i-123123
node_id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
public_ip: 1.2.3.4
http_endpoint: http://1.2.3.4:9650

"#;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(d.as_bytes());
    assert!(ret.is_ok());
    let node_path = f.path().to_str().unwrap();

    let ret = Node::load(node_path);
    assert!(ret.is_ok());
    let node = ret.unwrap();

    let ret = node.sync(node_path);
    assert!(ret.is_ok());

    let orig = Node::new(
        node::Kind::Anchor,
        "i-123123",
        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
        "1.2.3.4",
        "http",
        9650,
    );
    assert_eq!(node, orig);

    // manually check to make sure the serde deserializer works
    assert_eq!(node.kind, String::from("anchor"));
    assert_eq!(node.machine_id, String::from("i-123123"));
    assert_eq!(
        node.node_id,
        String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg")
    );
    assert_eq!(node.public_ip, String::from("1.2.3.4"));
    assert_eq!(node.http_endpoint, String::from("http://1.2.3.4:9650"));

    let encoded_yaml = node.encode_yaml().unwrap();
    log::info!("node.encode_yaml: {}", encoded_yaml);
    let compressed = node.compress_base58().unwrap();
    log::info!("node.compress_base64: {}", compressed);
    let decompressed_node = Node::decompress_base58(compressed).unwrap();
    assert_eq!(node, decompressed_node);
}

/// Default machine anchor nodes size.
/// only required for custom networks
pub const DEFAULT_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MIN_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_ANCHOR_NODES: u32 = 10;

/// Default machine non-anchor nodes size.
/// "1" is better in order to choose only one AZ for static EBS provision.
/// If one wants to run multiple nodes, it should create multiple groups
/// of avalanche ops clusters.
pub const DEFAULT_MACHINE_NON_ANCHOR_NODES: u32 = 2;
pub const MIN_MACHINE_NON_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_NON_ANCHOR_NODES: u32 = 20;

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

    /// AAD tag used for envelope encryption with KMS.
    #[serde(default)]
    pub aad_tag: String,
    /// AWS resources if run in AWS.
    pub aws_resources: aws::Resources,

    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,
    /// Install artifacts to share with remote machines.
    pub install_artifacts: InstallArtifacts,

    /// Flag to pass to the "avalanched" command-line interface.
    pub avalanched_config: avalanched::Flags,

    /// Set "true" to disable NLB.
    #[serde(default)]
    pub disable_nlb: bool,
    /// Set "true" to disable CloudWatch log auto removal.
    #[serde(default)]
    pub disable_logs_auto_removal: bool,
    /// Interval in seconds to fetch metrics.
    #[serde(default)]
    pub metrics_fetch_interval_seconds: u64,

    /// Represents the configuration for "avalanchego".
    /// Set as if run in remote machines.
    /// For instance, "config-file" must be the path valid
    /// in the remote machines.
    /// MUST BE "kebab-case" to be compatible with "avalanchego".
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_evm_genesis: Option<subnet_evm_genesis::Genesis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_evm_config: Option<subnet_evm_config::Config>,

    /// NOTE: Only required for custom networks with pre-funded wallets!
    /// These are used for custom primary network genesis generation.
    /// The first key will have locked P-chain balance with initial stake duration in genesis.
    /// Except the first key in the list, all keys have immediately unlocked P-chain balance.
    /// Should never be used for mainnet as it's store in plaintext for testing purposes only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_insecure_hot_key_infos: Option<Vec<key::secp256k1::Info>>,

    /// Current all nodes. May be stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_nodes: Option<Vec<Node>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Endpoints>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_rules: Option<prometheus_manager::Rules>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Endpoints {
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metamask_rpc_c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_rpc_c: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::default()
    }
}

impl Endpoints {
    pub fn default() -> Self {
        Self {
            http_rpc: None,
            http_rpc_x: None,
            http_rpc_p: None,
            http_rpc_c: None,
            metrics: None,
            health: None,
            liveness: None,
            metamask_rpc_c: None,
            websocket_rpc_c: None,
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Endpoints to YAML {}", e),
            )),
        }
    }
}

/// Defines how the underlying infrastructure is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_nodes: Option<u32>,
    #[serde(default)]
    pub non_anchor_nodes: u32,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
    #[serde(default)]
    pub use_spot_instance: bool,
    #[serde(default)]
    pub disable_spot_instance_for_anchor_nodes: bool,
    #[serde(default)]
    pub use_elastic_ips: bool,

    /// Initial EBS volume size in GB.
    /// Can be resized with no downtime.
    /// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html
    #[serde(default)]
    pub volume_size_in_gb: u32,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct InstallArtifacts {
    /// "avalanched" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/avalanched" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanched_bin: Option<String>,

    /// AvalancheGo binary path in the local environment.
    /// The file is "compressed" and uploaded to remote storage
    /// to be shared with remote machines.
    ///
    ///  build
    ///    ├── avalanchego (the binary from compiling the app directory)
    ///    └── plugins
    ///        └── evm
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanchego_bin: Option<String>,

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
    AsgAnchorNodes(String),
    AsgNonAnchorNodes(String),
    SsmDocRestartNodeWhitelistSubnet(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::AsgAnchorNodes(id) => format!("{}-asg-anchor-nodes", id),
            StackName::AsgNonAnchorNodes(id) => format!("{}-asg-non-anchor-nodes", id),
            StackName::SsmDocRestartNodeWhitelistSubnet(id) => {
                format!("{}-ssm-doc-restart-node-whitelist-subnet", id)
            }
        }
    }
}

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,
    pub network_name: String,

    pub key_files_dir: String,
    pub keys_to_generate: usize,

    pub region: String,
    pub preferred_az_index: usize,
    pub use_spot_instance: bool,
    pub disable_spot_instance_for_anchor_nodes: bool,
    pub volume_size_in_gb: u32,

    pub use_elastic_ips: bool,

    pub disable_nlb: bool,
    pub disable_logs_auto_removal: bool,
    pub metrics_fetch_interval_seconds: u64,

    pub aad_tag: String,

    pub nlb_acm_certificate_arn: String,

    pub install_artifacts_avalanched_bin: String,
    pub install_artifacts_avalanche_bin: String,
    pub install_artifacts_plugins_dir: String,

    pub avalanched_log_level: String,
    pub avalanched_use_default_config: bool,
    pub avalanched_publish_periodic_node_info: bool,

    pub avalanchego_log_level: String,
    pub avalanchego_whitelisted_subnets: String,
    pub avalanchego_http_tls_enabled: bool,
    pub avalanchego_state_sync_ids: String,
    pub avalanchego_state_sync_ips: String,
    pub avalanchego_profile_continuous_enabled: bool,
    pub avalanchego_profile_continuous_freq: String,
    pub avalanchego_profile_continuous_max_files: String,

    pub coreth_metrics_enabled: bool,
    pub coreth_continuous_profiler_enabled: bool,
    pub coreth_offline_pruning_enabled: bool,
    pub coreth_state_sync_enabled: bool,
    pub coreth_state_sync_metrics_enabled: bool,

    pub enable_subnet_evm: bool,

    pub subnet_evm_gas_limit: u64,
    pub subnet_evm_auto_contract_deployer_allow_list_config: bool,
    pub subnet_evm_auto_contract_native_minter_config: bool,
    pub subnet_evm_auto_fee_manager_config: bool,

    pub spec_file_path: String,
}

pub const ARCH_AMD64: &str = "amd64";
pub const ARCH_ARM64: &str = "arm64";

lazy_static! {
    /// Avalanche consensus paper used "c5.large" for testing 125 ~ 2,000 nodes
    /// Avalanche test net ("fuji") runs "c5.2xlarge"
    ///
    /// https://aws.amazon.com/ec2/instance-types/c6a/
    /// c6a.large:   2  vCPU + 4  GiB RAM
    /// c6a.xlarge:  4  vCPU + 8  GiB RAM
    /// c6a.2xlarge: 8  vCPU + 16 GiB RAM
    /// c6a.4xlarge: 16 vCPU + 32 GiB RAM
    /// c6a.8xlarge: 32 vCPU + 64 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m6a/
    /// m6a.large:   2  vCPU + 8  GiB RAM
    /// m6a.xlarge:  4  vCPU + 16 GiB RAM
    /// m6a.2xlarge: 8  vCPU + 32 GiB RAM
    /// m6a.4xlarge: 16 vCPU + 64 GiB RAM
    /// m6a.8xlarge: 32 vCPU + 128 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m5/
    /// m5.large:   2  vCPU + 8  GiB RAM
    /// m5.xlarge:  4  vCPU + 16 GiB RAM
    /// m5.2xlarge: 8  vCPU + 32 GiB RAM
    /// m5.4xlarge: 16 vCPU + 64 GiB RAM
    /// m5.8xlarge: 32 vCPU + 128 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/c5/
    /// c5.large:   2  vCPU + 4  GiB RAM
    /// c5.xlarge:  4  vCPU + 8  GiB RAM
    /// c5.2xlarge: 8  vCPU + 16 GiB RAM
    /// c5.4xlarge: 16 vCPU + 32 GiB RAM
    /// c5.9xlarge: 32 vCPU + 72 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/r5/
    /// r5.large:   2  vCPU + 16 GiB RAM
    /// r5.xlarge:  4  vCPU + 32 GiB RAM
    /// r5.2xlarge: 8  vCPU + 64 GiB RAM
    /// r5.4xlarge: 16 vCPU + 128 GiB RAM
    /// r5.8xlarge: 32 vCPU + 256 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/t3/
    /// t3.large:    2  vCPU + 8 GiB RAM
    /// t3.xlarge:   4  vCPU + 16 GiB RAM
    /// t3.2xlarge:  8  vCPU + 32 GiB RAM
    ///
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_AMD64: Vec<String> = vec![
        String::from("c6a.xlarge"),
        String::from("m6a.xlarge"),
        String::from("m5.xlarge"),
        String::from("c5.xlarge"),
    ];

    /// Avalanche consensus paper used "c5.large" for testing 125 ~ 2,000 nodes
    /// Avalanche test net ("fuji") runs "c5.2xlarge"
    ///
    /// Graviton 3 (in preview)
    /// https://aws.amazon.com/ec2/instance-types/c7g/
    /// c7g.large:   2 vCPU + 8  GiB RAM
    /// c7g.xlarge:  4 vCPU + 16 GiB RAM
    /// c7g.2xlarge: 8 vCPU + 32 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/c6g/
    /// c6g.large:   2 vCPU + 4  GiB RAM
    /// c6g.xlarge:  4 vCPU + 8  GiB RAM
    /// c6g.2xlarge: 8 vCPU + 16 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/m6g/
    /// m6g.large:   2 vCPU + 8  GiB RAM
    /// m6g.xlarge:  4 vCPU + 16 GiB RAM
    /// m6g.2xlarge: 8 vCPU + 32 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/r6g/
    /// r6g.large:   2 vCPU + 16 GiB RAM
    /// r6g.xlarge:  4 vCPU + 32 GiB RAM
    /// r6g.2xlarge: 8 vCPU + 64 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/t4/
    /// t4g.large:   2 vCPU + 8 GiB RAM
    /// t4g.xlarge:  4 vCPU + 16 GiB RAM
    /// t4g.2xlarge: 8 vCPU + 32 GiB RAM
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_ARM64: Vec<String> = vec![
        String::from("c6g.xlarge"),
        String::from("m6g.xlarge"),
        String::from("r6g.xlarge"),
        String::from("t4g.xlarge"),
    ];
}

pub fn default_rules() -> prometheus_manager::Rules {
    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let filters_raw = Asset::get("artifacts/default.metrics.rules.yaml").unwrap();
    let filters_raw = std::str::from_utf8(filters_raw.data.as_ref()).unwrap();
    serde_yaml::from_str(filters_raw).unwrap()
}

impl Spec {
    /// Creates a default spec.
    pub fn default_aws(opts: DefaultSpecOption) -> Self {
        let network_id = match constants::NETWORK_NAME_TO_NETWORK_ID.get(opts.network_name.as_str())
        {
            Some(v) => *v,
            None => constants::DEFAULT_CUSTOM_NETWORK_ID,
        };

        let mut avalanched_config = avalanched::Flags {
            log_level: opts.avalanched_log_level,
            use_default_config: opts.avalanched_use_default_config,
            publish_periodic_node_info: None,
        };
        if opts.avalanched_publish_periodic_node_info {
            avalanched_config.publish_periodic_node_info = Some(true);
        }

        let mut avalanchego_config = match network_id {
            1 => avalanchego_config::Config::default_main(),
            5 => avalanchego_config::Config::default_fuji(),
            _ => avalanchego_config::Config::default_custom(),
        };
        avalanchego_config.log_level = Some(opts.avalanchego_log_level);

        // only set values if non empty
        // otherwise, avalanchego will fail with "couldn't load node config: read .: is a directory"
        // TODO: use different certs than staking?
        if opts.avalanchego_http_tls_enabled {
            avalanchego_config.http_tls_enabled = Some(true);
            avalanchego_config.http_tls_key_file = avalanchego_config.staking_tls_key_file.clone();
            avalanchego_config.http_tls_cert_file =
                avalanchego_config.staking_tls_cert_file.clone();
        }

        if !opts.avalanchego_state_sync_ids.is_empty() {
            avalanchego_config.state_sync_ids = Some(opts.avalanchego_state_sync_ids.clone());
        };
        if !opts.avalanchego_state_sync_ips.is_empty() {
            avalanchego_config.state_sync_ips = Some(opts.avalanchego_state_sync_ips.clone());
        };
        if opts.avalanchego_profile_continuous_enabled {
            avalanchego_config.profile_continuous_enabled = Some(true);
        }
        if !opts.avalanchego_profile_continuous_freq.is_empty() {
            avalanchego_config.profile_continuous_freq =
                Some(opts.avalanchego_profile_continuous_freq.clone());
        };
        if !opts.avalanchego_profile_continuous_max_files.is_empty() {
            let profile_continuous_max_files = opts.avalanchego_profile_continuous_max_files;
            let profile_continuous_max_files = profile_continuous_max_files.parse::<u32>().unwrap();
            avalanchego_config.profile_continuous_max_files = Some(profile_continuous_max_files);
        };
        if !opts.avalanchego_whitelisted_subnets.is_empty() {
            avalanchego_config.whitelisted_subnets = Some(opts.avalanchego_whitelisted_subnets);
        } else if opts.enable_subnet_evm {
            panic!("enable_subnet_evm true but avalanchego_whitelisted_subnets is empty")
        }

        let network_id = avalanchego_config.network_id;
        let id = {
            if !opts.spec_file_path.is_empty() {
                let spec_file_stem = Path::new(&opts.spec_file_path).file_stem().unwrap();
                spec_file_stem.to_str().unwrap().to_string()
            } else {
                match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                    Some(v) => id_manager::time::with_prefix(format!("aops-{}", *v).as_str()),
                    None => id_manager::time::with_prefix("aops-custom"),
                }
            }
        };
        let (anchor_nodes, non_anchor_nodes) =
            match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                Some(_) => (None, DEFAULT_MACHINE_NON_ANCHOR_NODES),
                None => (
                    Some(DEFAULT_MACHINE_ANCHOR_NODES),
                    DEFAULT_MACHINE_NON_ANCHOR_NODES,
                ),
            };

        if !opts.key_files_dir.is_empty() {
            log::info!("creating key-files-dir '{}'", opts.key_files_dir);
            fs::create_dir_all(&opts.key_files_dir).unwrap();
        }

        let mut test_key_infos: Vec<key::secp256k1::Info> = Vec::new();
        let mut test_keys: Vec<key::secp256k1::private_key::Key> = Vec::new();
        for i in 0..opts.keys_to_generate {
            let k = {
                if i < key::secp256k1::TEST_KEYS.len() {
                    key::secp256k1::TEST_KEYS[i].clone()
                } else {
                    key::secp256k1::private_key::Key::generate()
                        .expect("unexpected key generate failure")
                }
            };

            let info = k
                .to_info(network_id)
                .expect("unexpected private_key_info_entry failure");
            test_key_infos.push(info.clone());

            test_keys.push(k);

            if !opts.key_files_dir.is_empty() {
                // file name is eth address with 0x, contents are "private_key_hex"
                let p = Path::new(&opts.key_files_dir).join(Path::new(&info.eth_address));
                log::info!("writing key file {:?}", p);

                let mut f = File::create(p).unwrap();
                f.write_all(prefix_manager::strip_0x(&info.private_key_hex).as_bytes())
                    .unwrap();
            }
        }

        let avalanchego_genesis_template = {
            if avalanchego_config.is_custom_network() {
                let g = avalanchego_genesis::Genesis::new(network_id, &test_keys)
                    .expect("unexpected None genesis");
                Some(g)
            } else {
                None
            }
        };

        let (subnet_evm_genesis, subnet_evm_config) = {
            if opts.enable_subnet_evm {
                let mut genesis = subnet_evm_genesis::Genesis::new(&test_keys)
                    .expect("failed to generate genesis");

                let mut admin_addresses: Vec<String> = Vec::new();
                for key_info in test_key_infos.iter() {
                    admin_addresses.push(key_info.eth_address.clone());
                }

                let mut chain_config = subnet_evm_genesis::ChainConfig::default();
                if opts.subnet_evm_gas_limit > 0 {
                    let mut fee_config = subnet_evm_genesis::FeeConfig::default();
                    fee_config.gas_limit = Some(opts.subnet_evm_gas_limit);
                    chain_config.fee_config = Some(fee_config);

                    genesis.gas_limit = primitive_types::U256::from(opts.subnet_evm_gas_limit);
                }
                if opts.subnet_evm_auto_contract_deployer_allow_list_config {
                    chain_config.contract_deployer_allow_list_config =
                        Some(subnet_evm_genesis::ContractDeployerAllowListConfig {
                            allow_list_admins: Some(admin_addresses.clone()),
                            ..subnet_evm_genesis::ContractDeployerAllowListConfig::default()
                        });
                }
                if opts.subnet_evm_auto_contract_native_minter_config {
                    chain_config.contract_native_minter_config =
                        Some(subnet_evm_genesis::ContractNativeMinterConfig {
                            allow_list_admins: Some(admin_addresses.clone()),
                            ..subnet_evm_genesis::ContractNativeMinterConfig::default()
                        });
                }
                if opts.subnet_evm_auto_fee_manager_config {
                    chain_config.fee_manager_config = Some(subnet_evm_genesis::FeeManagerConfig {
                        allow_list_admins: Some(admin_addresses),
                        ..subnet_evm_genesis::FeeManagerConfig::default()
                    });
                }
                genesis.config = Some(chain_config);

                let subnet_evm_config = subnet_evm_config::Config::default();

                (Some(genesis), Some(subnet_evm_config))
            } else {
                (None, None)
            }
        };

        // [year][month][date]-[system host-based id]
        let s3_bucket = format!(
            "avalanche-ops-{}-{}-{}",
            id_manager::time::timestamp(6),
            id_manager::system::string(10),
            opts.region
        );
        let mut aws_resources = aws::Resources {
            region: opts.region,
            s3_bucket,
            ..aws::Resources::default()
        };
        if !opts.nlb_acm_certificate_arn.is_empty() {
            aws_resources.nlb_acm_certificate_arn = Some(opts.nlb_acm_certificate_arn);
        }

        let mut install_artifacts = InstallArtifacts {
            avalanched_bin: None,
            avalanchego_bin: None,
            plugins_dir: None,
        };
        if !opts.install_artifacts_avalanched_bin.is_empty() {
            install_artifacts.avalanched_bin = Some(opts.install_artifacts_avalanched_bin);
        }
        if !opts.install_artifacts_avalanche_bin.is_empty() {
            install_artifacts.avalanchego_bin = Some(opts.install_artifacts_avalanche_bin);
        }
        if !opts.install_artifacts_plugins_dir.is_empty() {
            install_artifacts.plugins_dir = Some(opts.install_artifacts_plugins_dir);
        }

        let mut coreth_config = coreth_config::Config::default();
        if opts.coreth_metrics_enabled {
            coreth_config.metrics_enabled = Some(true);
        }
        if opts.coreth_continuous_profiler_enabled {
            coreth_config.continuous_profiler_dir =
                Some(String::from(coreth_config::DEFAULT_PROFILE_DIR));
            coreth_config.continuous_profiler_frequency =
                Some(coreth_config::DEFAULT_PROFILE_FREQUENCY);
            coreth_config.continuous_profiler_max_files =
                Some(coreth_config::DEFAULT_PROFILE_MAX_FILES);
        }
        if opts.coreth_offline_pruning_enabled {
            coreth_config.offline_pruning_enabled = Some(true);
        }
        if opts.coreth_state_sync_enabled {
            coreth_config.state_sync_enabled = Some(true);
            if !opts.avalanchego_state_sync_ids.is_empty() {
                coreth_config.state_sync_ids = Some(opts.avalanchego_state_sync_ids.clone());
            }
        }
        if opts.coreth_state_sync_metrics_enabled {
            coreth_config.state_sync_metrics_enabled = Some(true);
        }

        let state_sync_enabled = if let Some(b) = coreth_config.state_sync_enabled {
            b
        } else {
            false
        };
        let volume_size_in_gb = if opts.volume_size_in_gb > 0 {
            opts.volume_size_in_gb
        } else {
            if avalanchego_config.is_mainnet() {
                if state_sync_enabled {
                    500
                } else {
                    1024
                }
            } else if !avalanchego_config.is_custom_network() {
                // fuji/*
                if state_sync_enabled {
                    250
                } else {
                    600
                }
            } else {
                if state_sync_enabled {
                    200
                } else {
                    400
                }
            }
        };

        let machine = Machine {
            anchor_nodes,
            non_anchor_nodes,

            // TODO: support "arm64"
            arch: ARCH_AMD64.to_string(),
            instance_types: DEFAULT_EC2_INSTANCE_TYPES_AMD64.to_vec(),

            use_spot_instance: opts.use_spot_instance,
            disable_spot_instance_for_anchor_nodes: opts.disable_spot_instance_for_anchor_nodes,
            use_elastic_ips: opts.use_elastic_ips,

            volume_size_in_gb,
        };

        Self {
            id,
            aad_tag: opts.aad_tag,

            aws_resources,
            machine,
            install_artifacts,

            avalanched_config,

            disable_nlb: opts.disable_nlb,
            disable_logs_auto_removal: opts.disable_logs_auto_removal,
            metrics_fetch_interval_seconds: opts.metrics_fetch_interval_seconds,

            avalanchego_config,
            coreth_config,
            avalanchego_genesis_template,

            subnet_evm_genesis,
            subnet_evm_config,

            test_insecure_hot_key_infos: Some(test_key_infos),

            current_nodes: None,
            endpoints: None,

            metrics_rules: Some(default_rules()),
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec to YAML {}", e),
            )),
        }
    }

    /// Saves the current spec to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing Spec to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec info to YAML {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        log::info!("loading Spec from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(file_path).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            )
        })?;
        serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        log::info!("validating Spec");

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

        if self.aws_resources.region.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'machine.region' cannot be empty",
            ));
        }

        if self.machine.non_anchor_nodes < MIN_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} <minimum {}",
                    self.machine.non_anchor_nodes, MIN_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if self.machine.non_anchor_nodes > MAX_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} >maximum {}",
                    self.machine.non_anchor_nodes, MAX_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if !self.avalanchego_config.is_custom_network() && self.machine.non_anchor_nodes != 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' must be 1 (set to {}) in order to maximize the benefit of static EBS provision per AZ",
                    self.machine.non_anchor_nodes
                ),
            ));
        }

        if self.subnet_evm_config.is_some() && self.avalanchego_config.whitelisted_subnets.is_none()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'subnet_evm_config' is some but 'avalanchego_config.whitelisted_subnets' is none",
            ));
        }

        if let Some(v) = &self.install_artifacts.avalanched_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanched_bin {} does not exist", v),
                ));
            }
        }
        if let Some(v) = &self.install_artifacts.avalanchego_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanchego_bin {} does not exist", v),
                ));
            }
        }
        if let Some(v) = &self.install_artifacts.plugins_dir {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("plugins_dir {} does not exist", v),
                ));
            }
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
            if self.machine.anchor_nodes.unwrap_or(0) > 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify non-zero 'machine.anchor_nodes' for network_id {:?}",
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
            if self.machine.anchor_nodes.unwrap_or(0) == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot specify 0 for 'machine.anchor_nodes' for custom network",
                ));
            }
            if self.machine.anchor_nodes.unwrap_or(0) < MIN_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.anchor_nodes' {} below min {}",
                        self.machine.anchor_nodes.unwrap_or(0),
                        MIN_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
            if self.machine.anchor_nodes.unwrap_or(0) > MAX_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.anchor_nodes' {} exceeds limit {}",
                        self.machine.anchor_nodes.unwrap_or(0),
                        MAX_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalancheup-aws --lib -- test_spec --exact --show-output
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
    let plugin_path = tmp_dir.path().join(random_manager::string(10));
    let mut f = File::create(&plugin_path).unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let plugins_dir = tmp_dir.path().as_os_str().to_str().unwrap();

    // test just to see how "read_dir" works in Rust
    for entry in fs::read_dir(plugins_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        log::info!("read_dir: {:?}", path);
    }

    let id = random_manager::string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

id: {}

aad_tag: test

aws_resources:
  region: us-west-2
  preferred_az_index: 2
  use_spot_instance: false
  disable_spot_instance_for_anchor_nodes: false
  s3_bucket: {}

machine:
  non_anchor_nodes: 1
  arch: amd64
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large
  volume_size_in_gb: 500

install_artifacts:
  avalanched_bin: {}
  avalanchego_bin: {}
  plugins_dir: {}

avalanched_config:
  log_level: info
  use_default_config: false
  publish_periodic_node_info: false

disable_nlb: false
disable_logs_auto_removal: false
metrics_fetch_interval_seconds: 5000

avalanchego_config:
  config-file: /data/avalanche-configs/config.json
  network-id: 1
  db-type: leveldb
  db-dir: /data
  log-dir: /var/log/avalanche
  log-level: INFO
  log-format: json
  http-port: 9650
  http-host: 0.0.0.0
  http-tls-enabled: false
  staking-enabled: true
  staking-port: 9651
  staking-tls-key-file: "/data/staking.key"
  staking-tls-cert-file: "/data/staking.crt"
  snow-sample-size: 20
  snow-quorum-size: 15
  index-enabled: false
  index-allow-incomplete: false
  api-admin-enabled: true
  api-info-enabled: true
  api-keystore-enabled: true
  api-metrics-enabled: true
  api-health-enabled: true
  api-ipcs-enabled: true
  chain-config-dir: /data/avalanche-configs/chains
  subnet-config-dir: /data/avalanche-configs/subnets
  profile-dir: /var/log/avalanche-profile/avalanche
  throttler-inbound-node-max-at-large-bytes: 2097152
  throttler-inbound-at-large-alloc-size: 6291456

coreth_config:
  coreth-admin-api-enabled: true
  offline-pruning-enabled: false
  offline-pruning-data-directory: /data/c-chain-offline-pruning
  metrics-enabled: true
  pruning-enabled: true
  log-level: "info"
  log-json-format: true
  state-sync-enabled: true
  eth-apis:
  - eth
  - eth-filter
  - net
  - web3
  - internal-eth
  - internal-blockchain
  - internal-transaction


"#,
        id, bucket, avalanched_bin, avalanchego_bin, plugins_dir,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let cfg = Spec::load(config_path).unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let avalanchego_config = avalanchego_config::Config::default_main();
    let orig = Spec {
        id: id.clone(),
        aad_tag: String::from("test"),

        aws_resources: aws::Resources {
            region: String::from("us-west-2"),
            preferred_az_index: 2,
            s3_bucket: bucket.clone(),
            ..aws::Resources::default()
        },

        machine: Machine {
            anchor_nodes: None,
            non_anchor_nodes: 1,
            arch: "amd64".to_string(),
            instance_types: vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ],
            use_spot_instance: false,
            disable_spot_instance_for_anchor_nodes: false,
            use_elastic_ips: false,
            volume_size_in_gb: 500,
        },

        install_artifacts: InstallArtifacts {
            avalanched_bin: Some(avalanched_bin.to_string()),
            avalanchego_bin: Some(avalanchego_bin.to_string()),
            plugins_dir: Some(plugins_dir.to_string()),
        },

        avalanched_config: avalanched::Flags {
            log_level: String::from("info"),
            use_default_config: false,
            publish_periodic_node_info: Some(false),
        },

        disable_nlb: false,
        disable_logs_auto_removal: false,
        metrics_fetch_interval_seconds: 5000,

        avalanchego_config,
        coreth_config: coreth_config::Config::default(),
        avalanchego_genesis_template: None,

        subnet_evm_genesis: None,
        subnet_evm_config: None,

        test_insecure_hot_key_infos: None,
        current_nodes: None,
        endpoints: None,

        metrics_rules: None,
    };

    assert_eq!(cfg, orig);
    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.aad_tag, "test");

    assert_eq!(cfg.aws_resources.region, "us-west-2");
    assert_eq!(cfg.aws_resources.preferred_az_index, 2);
    assert_eq!(cfg.aws_resources.s3_bucket, bucket);

    assert_eq!(
        cfg.install_artifacts
            .avalanched_bin
            .unwrap_or(String::new()),
        avalanched_bin
    );
    assert_eq!(
        cfg.install_artifacts
            .avalanchego_bin
            .unwrap_or(String::new()),
        avalanchego_bin
    );
    assert_eq!(
        cfg.install_artifacts.plugins_dir.unwrap_or(String::new()),
        plugins_dir.to_string()
    );

    assert!(cfg.machine.anchor_nodes.is_none());
    assert_eq!(cfg.machine.non_anchor_nodes, 1);
    let instance_types = cfg.machine.instance_types;
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
/// MUST be kept in sync with "cfn-templates/ec2_instance_role.yaml".
pub enum StorageNamespace {
    ConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),

    /// Valid genesis file with initial stakers.
    /// Only updated after anchor nodes become active.
    GenesisFile(String),

    AvalanchedBin(String),
    AvalancheBinCompressed(String),
    PluginsDir(String),

    PkiKeyDir(String),
    MetricsRules(String),

    /// before db downloads
    DiscoverProvisioningAnchorNodesDir(String),
    DiscoverProvisioningAnchorNode(String, Node),
    DiscoverProvisioningNonAnchorNodesDir(String),
    DiscoverProvisioningNonAnchorNode(String, Node),

    DiscoverBootstrappingAnchorNodesDir(String),
    DiscoverBootstrappingAnchorNode(String, Node),

    DiscoverReadyAnchorNodesDir(String),
    DiscoverReadyAnchorNode(String, Node),
    DiscoverReadyNonAnchorNodesDir(String),
    DiscoverReadyNonAnchorNode(String, Node),

    BackupsDir(String),

    /// If this "event" file has been modified for the last x-min,
    /// avalanched triggers updates events based on the install artifacts
    /// in "EventsUpdateArtifactsInstallDir"
    EventsUpdateArtifactsEvent(String),
    EventsUpdateArtifactsInstallDirAvalancheBinCompressed(String),
    EventsUpdateArtifactsInstallDirPluginsDir(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::ConfigFile(id) => format!("{}/avalanche-ops.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }

            StorageNamespace::GenesisFile(id) => format!("{}/genesis.json", id),

            StorageNamespace::AvalanchedBin(id) => format!("{}/bootstrap/install/avalanched", id),
            StorageNamespace::AvalancheBinCompressed(id) => {
                format!("{}/bootstrap/install/avalanche.zstd", id)
            }
            StorageNamespace::PluginsDir(id) => format!("{}/bootstrap/install/plugins", id),

            StorageNamespace::PkiKeyDir(id) => {
                format!("{}/pki", id)
            }
            StorageNamespace::MetricsRules(id) => {
                format!("{}/avalanche-telemetry-cloudwatch.rules.yaml", id)
            }

            StorageNamespace::DiscoverProvisioningAnchorNodesDir(id) => {
                format!("{}/discover/provisioning-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverProvisioningNonAnchorNodesDir(id) => {
                format!("{}/discover/provisioning-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningNonAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverBootstrappingAnchorNodesDir(id) => {
                format!("{}/discover/bootstrapping-anchor-nodes", id)
            }
            StorageNamespace::DiscoverBootstrappingAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/bootstrapping-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverReadyAnchorNodesDir(id) => {
                format!("{}/discover/ready-anchor-nodes", id)
            }
            StorageNamespace::DiscoverReadyAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverReadyNonAnchorNodesDir(id) => {
                format!("{}/discover/ready-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverReadyNonAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::BackupsDir(id) => {
                format!("{}/backups", id)
            }

            StorageNamespace::EventsUpdateArtifactsEvent(id) => {
                format!("{}/events/update-artifacts/event", id)
            }
            StorageNamespace::EventsUpdateArtifactsInstallDirAvalancheBinCompressed(id) => {
                format!("{}/events/update-artifacts/install/avalanche.zstd", id)
            }
            StorageNamespace::EventsUpdateArtifactsInstallDirPluginsDir(id) => {
                format!("{}/events/update-artifacts/install/plugins", id)
            }
        }
    }

    pub fn parse_node_from_path(storage_path: &str) -> io::Result<Node> {
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
        match Node::decompress_base58(compressed_id.replace(".yaml", "")) {
            Ok(node) => Ok(node),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed node::Node::decompress_base64 {}", e),
            )),
        }
    }
}

#[test]
fn test_storage_path() {
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random_manager::string(10);
    let instance_id = random_manager::string(5);
    let node_id = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_ip = "1.2.3.4";

    let node = Node::new(
        node::Kind::NonAnchor,
        &instance_id,
        node_id,
        node_ip,
        "http",
        9650,
    );
    let p = StorageNamespace::DiscoverReadyNonAnchorNode(
        id,
        Node {
            kind: String::from("non-anchor"),
            machine_id: instance_id.clone(),
            node_id: node_id.to_string(),
            public_ip: node_ip.to_string(),
            http_endpoint: format!("http://{}:9650", node_ip),
        },
    );
    let storage_path = p.encode();
    log::info!("KeyPath: {}", storage_path);

    let node_parsed = StorageNamespace::parse_node_from_path(&storage_path).unwrap();
    assert_eq!(node, node_parsed);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct NodeInfo {
    pub local_node: Node,
    pub avalanchego_config: avalanchego_config::Config,
    pub coreth_config: coreth_config::Config,
}

impl NodeInfo {
    pub fn new(
        local_node: Node,
        avalanchego_config: avalanchego_config::Config,
        coreth_config: coreth_config::Config,
    ) -> Self {
        Self {
            local_node,
            avalanchego_config,
            coreth_config,
        }
    }

    pub fn sync(&self, file_path: String) -> io::Result<()> {
        log::info!("syncing Info to '{}'", file_path);
        let path = Path::new(&file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let d = serde_json::to_vec(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize NodeInfo info to JSON {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}
