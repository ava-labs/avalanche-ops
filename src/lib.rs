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
pub mod genesis;
pub mod http;
pub mod humanize;
pub mod id;
pub mod random;
mod time;

/// Default machine beacon nodes size.
pub const DEFAULT_MACHINE_BEACON_NODES: u32 = 3;
/// Default machine non-beacon nodes size.
pub const DEFAULT_MACHINE_NON_BEACON_NODES: u32 = 2;

pub const MIN_MACHINE_BEACON_NODES: u32 = 1; // only required for custom networks
pub const MAX_MACHINE_BEACON_NODES: u32 = 10; // TODO: support higher number
pub const MIN_MACHINE_NON_BEACON_NODES: u32 = 1;
pub const MAX_MACHINE_NON_BEACON_NODES: u32 = 20; // TODO: support higher number

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
    pub aws_resources: Option<AWSResources>,
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
}

/// Represents the current AWS resource status.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AWSResources {
    /// AWS region to create resources.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub region: String,

    /// Name of the bucket to store (or download from)
    /// the configuration and resources (e.g., S3).
    /// If not exists, it creates automatically.
    /// If exists, it skips creation and uses the existing one.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub bucket: String,

    /// AWS STS caller loaded from its local environment.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<aws_sts::Identity>,

    /// KMS CMK ID to encrypt resources.
    /// None if not created yet.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_id: Option<String>,
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_arn: Option<String>,

    /// EC2 key pair name for SSH access to EC2 instances.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_name: Option<String>,
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_path: Option<String>,

    /// CloudFormation stack name for EC2 instance role.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,
    /// Instance profile ARN from "cloudformation_ec2_instance_role".
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_profile_arn: Option<String>,

    /// CloudFormation stack name for VPC.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc: Option<String>,
    /// VPC ID from "cloudformation_vpc".
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_id: Option<String>,
    /// Security group ID from "cloudformation_vpc".
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_security_group_id: Option<String>,
    /// Public subnet IDs from "cloudformation_vpc".
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_public_subnet_ids: Option<Vec<String>>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for beacon nodes.
    /// None if mainnet.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_beacon_nodes: Option<String>,
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_beacon_nodes_logical_id: Option<String>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for non-beacon nodes.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_beacon_nodes: Option<String>,
    /// Only updated after creation.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_beacon_nodes_logical_id: Option<String>,

    /// Empty if the node itself is a beacon node.
    /// Non-empty to specify pre-provisioned beacon nodes in the network.
    /// This is read-only and should not be manually configured by the user.
    /// The node provisioner should update this field, so that
    /// the node agent can download and use this for its "--bootstrap-ips"
    /// and "--bootstrap-ids" flags.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon_nodes: Option<Vec<BeaconNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_beacon_nodes: Option<Vec<NonBeaconNode>>,
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
    /// Genesis file path in the local machine.
    /// MUST BE NON-EMPTY for custom network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_file_path: Option<String>,
}

impl Spec {
    /// Creates a default Status based on the network ID.
    pub fn default_aws(
        avalanched_bin: &str,
        avalanchego_bin: &str,
        plugins_dir: Option<String>,
        genesis_file_path: Option<String>,
        avalanchego_config: avalanchego::Config,
    ) -> Self {
        let beacon_nodes = match avalanchego_config.network_id {
            Some(id) => match id {
                1 => 0, // "mainnet"
                2 => 0, // "cascade"
                3 => 0, // "denali"
                4 => 0, // "everest"
                5 => 0, // "fuji"
                _ => DEFAULT_MACHINE_BEACON_NODES,
            },
            _ => DEFAULT_MACHINE_BEACON_NODES,
        };

        Self {
            id: crate::id::generate("avalanche-ops"),

            aws_resources: Some(AWSResources {
                region: String::from("us-west-2"),
                bucket: format!("avalanche-ops-{}", crate::time::get(8)), // [year][month][date]

                identity: None,

                kms_cmk_id: None,
                kms_cmk_arn: None,

                ec2_key_name: None,
                ec2_key_path: None,

                cloudformation_ec2_instance_role: None,
                cloudformation_ec2_instance_profile_arn: None,

                cloudformation_vpc: None,
                cloudformation_vpc_id: None,
                cloudformation_vpc_security_group_id: None,
                cloudformation_vpc_public_subnet_ids: None,

                cloudformation_asg_beacon_nodes: None,
                cloudformation_asg_beacon_nodes_logical_id: None,

                cloudformation_asg_non_beacon_nodes: None,
                cloudformation_asg_non_beacon_nodes_logical_id: None,

                beacon_nodes: None,
                non_beacon_nodes: None,
            }),

            machine: Machine {
                beacon_nodes: Some(beacon_nodes),
                non_beacon_nodes: DEFAULT_MACHINE_NON_BEACON_NODES,
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
                plugins_dir,
                genesis_file_path,
            },

            avalanchego_config,
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

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating Spec");

        if self.id.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "'id' cannot be empty"));
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

        if self.avalanchego_config.network_id.is_some() {
            let network_id = self.avalanchego_config.network_id.unwrap();
            match network_id {
                1 => {
                    // "mainnet"
                    if self.machine.beacon_nodes.unwrap_or(0) > 0 {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "cannot specify non-zero 'machine.beacon_nodes' for mainnet",
                        ));
                    }
                }
                2 => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "network '{}' is not supported yet in this tooling",
                            network_id
                        ),
                    ));
                }
                3 => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "network '{}' is not supported yet in this tooling",
                            network_id
                        ),
                    ));
                }
                4 => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "network '{}' is not supported yet in this tooling",
                            network_id
                        ),
                    ));
                }
                5 => {
                    // fuji
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "network '{}' is not supported yet in this tooling",
                            network_id
                        ),
                    ));
                }
                _ => {
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
            }
        }

        Ok(())
    }
}

pub fn load_spec(file_path: &str) -> io::Result<Spec> {
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
        return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
    })
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
    let genesis_file_path = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanched_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanchego_bin = f.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let plugin_path = tmp_dir.path().join(crate::random::string(10));
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

    let id = crate::random::string(10);
    let bucket = format!("test-{}", crate::time::get(8));

    let contents = format!(
        r#"

id: {}

aws_resources:
  region: us-west-2
  bucket: {}
  beacon_nodes:
  - ip: 1.2.3.4
    id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
  - ip: 1.2.3.5
    id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LX
  - ip: 1.2.3.6
    id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LY
  non_beacon_nodes:
  - ip: 1.2.3.9

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
  genesis_file_path: {}

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
        genesis_file_path,
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

    let ret = load_spec(config_path);
    assert!(ret.is_ok());
    let cfg = ret.unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let mut avago_config = avalanchego::Config::new();
    avago_config.config_file = Some(String::from(avalanchego::DEFAULT_CONFIG_FILE_PATH));
    avago_config.genesis = Some(String::from(avalanchego::DEFAULT_GENESIS_PATH));
    avago_config.network_id = Some(1337);
    avago_config.snow_sample_size = Some(avalanchego::DEFAULT_SNOW_SAMPLE_SIZE);
    avago_config.snow_quorum_size = Some(avalanchego::DEFAULT_SNOW_QUORUM_SIZE);
    avago_config.http_port = Some(avalanchego::DEFAULT_HTTP_PORT);
    avago_config.staking_port = Some(avalanchego::DEFAULT_STAKING_PORT);
    avago_config.db_dir = Some(String::from(avalanchego::DEFAULT_DB_DIR));

    let orig = Spec {
        id: id.clone(),

        aws_resources: Some(AWSResources {
            region: String::from("us-west-2"),
            bucket: bucket.clone(),

            identity: None,

            kms_cmk_id: None,
            kms_cmk_arn: None,

            ec2_key_name: None,
            ec2_key_path: None,

            cloudformation_ec2_instance_role: None,
            cloudformation_ec2_instance_profile_arn: None,

            cloudformation_vpc: None,
            cloudformation_vpc_id: None,
            cloudformation_vpc_security_group_id: None,
            cloudformation_vpc_public_subnet_ids: None,

            cloudformation_asg_beacon_nodes: None,
            cloudformation_asg_beacon_nodes_logical_id: None,

            cloudformation_asg_non_beacon_nodes: None,
            cloudformation_asg_non_beacon_nodes_logical_id: None,

            beacon_nodes: Some(vec![
                BeaconNode {
                    ip: String::from("1.2.3.4"),
                    id: String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"),
                },
                BeaconNode {
                    ip: String::from("1.2.3.5"),
                    id: String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LX"),
                },
                BeaconNode {
                    ip: String::from("1.2.3.6"),
                    id: String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LY"),
                },
            ]),
            non_beacon_nodes: Some(vec![NonBeaconNode {
                ip: String::from("1.2.3.9"),
            }]),
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
            genesis_file_path: Some(String::from(genesis_file_path)),
        },

        avalanchego_config: avago_config,
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
    assert!(aws_reesources.beacon_nodes.is_some());
    let beacons = match aws_reesources.beacon_nodes {
        Some(v) => v,
        None => panic!("unexpected None beacon_nodes"),
    };
    assert_eq!(beacons[0].ip, "1.2.3.4");
    assert_eq!(beacons[0].id, "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg");
    assert_eq!(beacons[1].ip, "1.2.3.5");
    assert_eq!(beacons[1].id, "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LX");
    assert_eq!(beacons[2].ip, "1.2.3.6");
    assert_eq!(beacons[2].id, "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3LY");
    let non_beacons = match aws_reesources.non_beacon_nodes {
        Some(v) => v,
        None => panic!("unexpected None non-beacon_nodes"),
    };
    assert_eq!(non_beacons[0].ip, "1.2.3.9");

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
            .genesis_file_path
            .unwrap_or(String::from("")),
        genesis_file_path
    );

    assert_eq!(cfg.machine.beacon_nodes.unwrap_or(0), 10);
    assert_eq!(cfg.machine.non_beacon_nodes, 20);
    assert!(cfg.machine.instance_types.is_some());
    let instance_types = cfg.machine.instance_types.unwrap();
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");

    assert_eq!(cfg.avalanchego_config.clone().network_id.unwrap(), 1337);
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

/// Represents a non-beacon node.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct NonBeaconNode {
    #[serde(default)]
    pub ip: String,
}

impl NonBeaconNode {
    pub fn new(ip: String) -> Self {
        Self { ip }
    }
}

/// Represents each beacon node.
/// Only required for custom networks.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct BeaconNode {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub id: String,
}

impl BeaconNode {
    pub fn new(ip: String, id: String) -> Self {
        Self { ip, id }
    }

    /// Saves the current beacon node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing BeaconNode to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize BeaconNode to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

pub fn load_beacon_node(file_path: &str) -> io::Result<BeaconNode> {
    info!("loading beacon node from {}", file_path);

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
        return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
    })
}

#[test]
fn test_beacon_node() {
    let d = r#"
ip: 1.2.3.4
id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
    
"#;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(d.as_bytes());
    assert!(ret.is_ok());
    let beacon_node_path = f.path().to_str().unwrap();

    let ret = load_beacon_node(beacon_node_path);
    assert!(ret.is_ok());
    let beacon_node = ret.unwrap();

    let ret = beacon_node.sync(beacon_node_path);
    assert!(ret.is_ok());

    let orig = BeaconNode::new(
        String::from("1.2.3.4"),
        String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"),
    );

    assert_eq!(beacon_node, orig);
    // manually check to make sure the serde deserializer works
    assert_eq!(beacon_node.ip, String::from("1.2.3.4"));
    assert_eq!(
        beacon_node.id,
        String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg")
    );
}

/// Defines the node type.
/// Must be either "beacon" or "non-beacon"
pub enum NodeType {
    Beacon,
    NonBeacon,
}

impl NodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeType::Beacon => "beacon",
            NodeType::NonBeacon => "non-beacon",
        }
    }
    pub fn from_str(&self, s: &str) -> io::Result<Self> {
        match s {
            "beacon" => Ok(NodeType::Beacon),
            "non-beacon" => Ok(NodeType::NonBeacon),
            "non_beacon" => Ok(NodeType::NonBeacon),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("unknown node type '{}'", s),
            )),
        }
    }
}
