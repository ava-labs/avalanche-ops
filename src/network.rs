use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

pub const MIN_TOPOLOGY_BEACON_NODES: u32 = 1; // only required for custom networks
pub const MAX_TOPOLOGY_BEACON_NODES: u32 = 10; // TODO: support higher number
pub const MIN_TOPOLOGY_NON_BEACON_NODES: u32 = 1;
pub const MAX_TOPOLOGY_NON_BEACON_NODES: u32 = 20; // TODO: support higher number

/// Default topology beacon nodes size.
pub const DEFAULT_TOPOLOGY_BEACON_NODES: u32 = 3;

/// Default topology non-beacon nodes size.
pub const DEFAULT_TOPOLOGY_NON_BEACON_NODES: u32 = 2;

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

    /// Name of the bucket to store (or download from)
    /// the configuration and resources (e.g., S3).
    /// If not exists, it creates automatically.
    /// If exists, it skips creation and uses the existing one.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub bucket: String,

    /// Defines how network is set up.
    /// MUST BE NON-EMPTY.
    pub topology: Topology,

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

    /// Empty if the node itself is a beacon node.
    /// Non-empty to specify pre-provisioned beacon nodes in the network.
    /// This is read-only and should not be manually configured by the user.
    /// The node provisioner should update this field, so that
    /// the node agent can download and use this for its "--bootstrap-ips"
    /// and "--bootstrap-ids" flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon_nodes: Option<Vec<BeaconNode>>,
}

/// Defines how network is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Topology {
    #[serde(default)]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_nodes: Option<u32>,
    #[serde(default)]
    pub non_beacon_nodes: u32,
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
    pub fn default(network_id: &str) -> Self {
        let beacon_nodes = match network_id {
            "mainnet" => 0,
            _ => MIN_TOPOLOGY_BEACON_NODES,
        };

        // [year][month]
        let bucket_name = format!(
            "avalanche-ops-{}-{}",
            crate::time::get(6),
            crate::random::string(5),
        );
        Self {
            id: crate::id::generate("test"),
            bucket: bucket_name,
            topology: Topology {
                region: String::from("us-west-2"),
                beacon_nodes: Some(beacon_nodes),
                non_beacon_nodes: MIN_TOPOLOGY_NON_BEACON_NODES,
            },

            network_id: String::from(network_id),

            snow_sample_size: Some(DEFAULT_SNOW_SAMPLE_SIZE),
            snow_quorum_size: Some(DEFAULT_SNOW_QUORUM_SIZE),

            http_port: Some(DEFAULT_HTTP_PORT),
            staking_port: Some(DEFAULT_STAKING_PORT),

            beacon_nodes: None,
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

        if self.topology.region.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'topology.region' cannot be empty",
            ));
        }

        // network specific validations
        match self.network_id.as_str() {
            "mainnet" => {
                if self.topology.beacon_nodes.unwrap_or(0) > 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot specify non-zero 'topology.beacon_nodes' for mainnet",
                    ));
                }
                if self.beacon_nodes.is_some() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot specify 'beacon_nodes' for mainnet",
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
                if self.topology.beacon_nodes.unwrap_or(0) == 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot specify 0 for 'topology.beacon_nodes' for custom network",
                    ));
                }
                if self.topology.beacon_nodes.unwrap_or(0) > MAX_TOPOLOGY_BEACON_NODES {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "'topology.beacon_nodes' {} exceeds limit {}",
                            self.topology.beacon_nodes.unwrap_or(0),
                            MAX_TOPOLOGY_BEACON_NODES
                        ),
                    ));
                }
            }
        }

        if self.topology.non_beacon_nodes < MIN_TOPOLOGY_NON_BEACON_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'topology.non_beacon_nodes' {} <minimum {}",
                    self.topology.non_beacon_nodes, MIN_TOPOLOGY_NON_BEACON_NODES
                ),
            ));
        }
        if self.topology.non_beacon_nodes > MAX_TOPOLOGY_NON_BEACON_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'topology.non_beacon_nodes' {} >maximum {}",
                    self.topology.non_beacon_nodes, MAX_TOPOLOGY_NON_BEACON_NODES
                ),
            ));
        }

        Ok(())
    }
}

pub fn load_config(file_path: &str) -> io::Result<Config> {
    info!("loading config from {}", file_path);

    let path = Path::new(file_path);
    if !path.exists() {
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

    assert!(Config::default("mainnet").validate().is_ok());
    assert!(Config::default("mycustom").validate().is_ok());

    let id = crate::random::string(10);
    let bucket = format!("test-{}", crate::time::get(8));

    let contents = format!(
        r#"

id: {}
bucket: {}
topology:
  region: us-west-2
  beacon_nodes: 10
  non_beacon_nodes: 20

network_id: hello

snow_sample_size: 20
snow_quorum_size: 15

http_port: 9650
staking_port: 9651

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
        bucket: bucket.clone(),
        topology: Topology {
            region: String::from("us-west-2"),
            beacon_nodes: Some(10),
            non_beacon_nodes: 20,
        },

        network_id: String::from("hello"),

        snow_sample_size: Some(20),
        snow_quorum_size: Some(15),

        http_port: Some(9650),
        staking_port: Some(9651),

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
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.bucket, bucket);
    assert_eq!(cfg.topology.region, "us-west-2");
    assert_eq!(cfg.topology.beacon_nodes.unwrap_or(0), 10);
    assert_eq!(cfg.topology.non_beacon_nodes, 20);
    assert_eq!(cfg.network_id, "hello");
    assert_eq!(cfg.snow_sample_size.unwrap_or(0), 20);
    assert_eq!(cfg.snow_quorum_size.unwrap_or(0), 15);
    assert_eq!(cfg.http_port.unwrap_or(0), 9650);
    assert_eq!(cfg.staking_port.unwrap_or(0), 9651);
    assert!(cfg.beacon_nodes.is_some());
    let beacons = match cfg.beacon_nodes {
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
