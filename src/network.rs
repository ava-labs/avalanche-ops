use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::aws_sts;

/// Default snow sample size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_SAMPLE_SIZE: u32 = 20;

/// Default snow quorum size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_QUORUM_SIZE: u32 = 15;

/// Default HTTP port.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_HTTP_PORT: u32 = 9650;

/// Default staking port.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_STAKING_PORT: u32 = 9651;

pub const MIN_MACHINE_BEACON_NODES: u32 = 1; // only required for custom networks
pub const MAX_MACHINE_BEACON_NODES: u32 = 10; // TODO: support higher number
pub const MIN_MACHINE_NON_BEACON_NODES: u32 = 1;
pub const MAX_MACHINE_NON_BEACON_NODES: u32 = 20; // TODO: support higher number

/// Default machine beacon nodes size.
pub const DEFAULT_MACHINE_BEACON_NODES: u32 = 3;

/// Default machine non-beacon nodes size.
pub const DEFAULT_MACHINE_NON_BEACON_NODES: u32 = 2;

/// Represents network-level configuration shared among all nodes.
/// The node-level configuration is generated during each
/// bootstrap process (e.g., certificates) and not defined
/// in this cluster-level "Config".
/// At the beginning, the user is expected to provide this configuration.
/// "Clone" is for deep-copying.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// User-provided ID of the cluster/test.
    /// This is NOT the avalanche node ID.
    /// This is NOT the avalanche network ID.
    #[serde(default)]
    pub id: String,

    /// Network ID.
    /// Only supports: "mainnet" and custom name.
    /// MUST NOT BE EMPTY.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants#NetworkName
    #[serde(default)]
    pub network_id: String,

    /// The sample size k, snowball.Parameters.K.
    /// If zero, use the default value set via avalanche node code.
    #[serde(default)]
    pub snow_sample_size: Option<u32>,
    /// The quorum size α, snowball.Parameters.Alpha.
    /// If zero, use the default value set via avalanche node code.
    #[serde(default)]
    pub snow_quorum_size: Option<u32>,

    /// HTTP port.
    /// If zero, default to the value set via avalanche node code.
    #[serde(default)]
    pub http_port: Option<u32>,
    /// Staking port.
    /// If zero, default to the value set via avalanche node code.
    #[serde(default)]
    pub staking_port: Option<u32>,

    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,

    /// Specified AWS resources if run in AWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_resources: Option<AWSResources>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_arn: Option<String>,

    /// EC2 key pair name for SSH access to EC2 instances.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_path: Option<String>,

    /// CloudFormation stack name for EC2 instance role.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,

    /// CloudFormation stack name for VPC.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc: Option<String>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for beacon nodes.
    /// None if mainnet.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_beacon_nodes: Option<String>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for non-beacon nodes.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_beacon_nodes: Option<String>,

    /// Empty if the node itself is a beacon node.
    /// Non-empty to specify pre-provisioned beacon nodes in the network.
    /// This is read-only and should not be manually configured by the user.
    /// The node provisioner should update this field, so that
    /// the node agent can download and use this for its "--bootstrap-ips"
    /// and "--bootstrap-ids" flags.
    /// Read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon_nodes: Option<Vec<BeaconNode>>,
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

impl Config {
    /// Creates a default Status based on the network ID.
    pub fn default_aws(network_id: &str) -> Self {
        let beacon_nodes = match network_id {
            "mainnet" => 0,
            _ => DEFAULT_MACHINE_BEACON_NODES,
        };

        Self {
            id: crate::id::generate("avalanche-ops"),
            network_id: String::from(network_id),

            snow_sample_size: Some(DEFAULT_SNOW_SAMPLE_SIZE),
            snow_quorum_size: Some(DEFAULT_SNOW_QUORUM_SIZE),

            http_port: Some(DEFAULT_HTTP_PORT),
            staking_port: Some(DEFAULT_STAKING_PORT),

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

            aws_resources: Some(AWSResources {
                region: String::from("us-west-2"),
                bucket: format!("avalanche-ops-{}", crate::time::get(8)), // [year][month][date]

                identity: None,
                kms_cmk_id: None,
                kms_cmk_arn: None,
                ec2_key_name: None,
                ec2_key_path: None,
                cloudformation_ec2_instance_role: None,
                cloudformation_vpc: None,
                cloudformation_asg_beacon_nodes: None,
                cloudformation_asg_non_beacon_nodes: None,
                beacon_nodes: None,
            }),
        }
    }

    /// Returns true if the topology is mainnet.
    pub fn is_mainnet(&self) -> bool {
        self.network_id == "mainnet"
    }

    /// Converts to string.
    pub fn to_string(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current configuration to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing network Config to '{}'", file_path);

        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }

    /// Validates the configuration.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating the network configuration");

        if self.id.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "'id' cannot be empty"));
        }
        if self.network_id.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'network_id' cannot be empty",
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

        // network specific validations
        match self.network_id.as_str() {
            "mainnet" => {
                if self.machine.beacon_nodes.unwrap_or(0) > 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot specify non-zero 'machine.beacon_nodes' for mainnet",
                    ));
                }
            }
            "cascade" | "denali" | "everest" | "fuji" | "testnet" | "testing" | "local" => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "network '{}' is not supported yet in this tooling",
                        self.network_id
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

        Ok(())
    }
}

pub fn load_config(file_path: &str) -> io::Result<Config> {
    info!("loading config from {}", file_path);

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
fn test_config() {
    let _ = env_logger::builder().is_test(true).try_init();

    assert!(Config::default_aws("mainnet").validate().is_ok());
    assert!(Config::default_aws("mycustom").validate().is_ok());

    let id = crate::random::string(10);
    let bucket = format!("test-{}", crate::time::get(8));

    let contents = format!(
        r#"

id: {}
network_id: hello

snow_sample_size: 20
snow_quorum_size: 15

http_port: 9650
staking_port: 9651

machine:
  beacon_nodes: 10
  non_beacon_nodes: 20
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large

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

"#,
        id, bucket,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let p = f.path().to_str().unwrap();

    let ret = load_config(p);
    assert!(ret.is_ok());
    let cfg = ret.unwrap();

    let ret = cfg.sync(p);
    assert!(ret.is_ok());

    let orig = Config {
        id: id.clone(),
        network_id: String::from("hello"),

        snow_sample_size: Some(20),
        snow_quorum_size: Some(15),

        http_port: Some(9650),
        staking_port: Some(9651),

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
        aws_resources: Some(AWSResources {
            region: String::from("us-west-2"),
            bucket: bucket.clone(),

            identity: None,
            kms_cmk_id: None,
            kms_cmk_arn: None,
            ec2_key_name: None,
            ec2_key_path: None,
            cloudformation_ec2_instance_role: None,
            cloudformation_vpc: None,
            cloudformation_asg_beacon_nodes: None,
            cloudformation_asg_non_beacon_nodes: None,

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
        }),
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.network_id, "hello");
    assert_eq!(cfg.snow_sample_size.unwrap_or(0), 20);
    assert_eq!(cfg.snow_quorum_size.unwrap_or(0), 15);
    assert_eq!(cfg.http_port.unwrap_or(0), 9650);
    assert_eq!(cfg.staking_port.unwrap_or(0), 9651);

    assert_eq!(cfg.machine.beacon_nodes.unwrap_or(0), 10);
    assert_eq!(cfg.machine.non_beacon_nodes, 20);
    assert!(cfg.machine.instance_types.is_some());
    let instance_types = cfg.machine.instance_types.unwrap();
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");

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
