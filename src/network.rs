use std::{
    fs::File,
    io::{self, Error, ErrorKind},
    path::Path,
    string::String,
};

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    // User-provided ID of the cluster/test.
    // This is NOT the avalanche node ID.
    // This is NOT the avalanche network ID.
    #[serde(default)]
    pub id: String,

    // Network ID (e.g., fuji, custom).
    #[serde(default)]
    pub network_id: String,

    // The sample size k, snowball.Parameters.K.
    // If zero, use the default value set via avalanche node code.
    #[serde(default)]
    pub snow_sample_size: u32,
    // The quorum size α, snowball.Parameters.Alpha.
    // If zero, use the default value set via avalanche node code.
    #[serde(default)]
    pub snow_quorum_size: u32,

    #[serde(default)]
    pub http_port: u32,
    #[serde(default)]
    pub staking_port: u32,

    // Empty if the node is a beacon node.
    // Non-empty to specify pre-provisioned beacon nodes in the network.
    pub beacon_nodes: Option<Vec<BeaconNode>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct BeaconNode {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub id: String,
}

pub fn load_config(file_path: &str) -> io::Result<Config> {
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
fn test_load_config() {
    let _ = env_logger::builder().is_test(true).try_init();
    use std::io::Write;

    let id = crate::random::string(10);
    let contents = format!(
        r#"

id: {}
network_id: custom

snow_sample_size: 100
snow_quorum_size: 100

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
        id
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let p = f.path().to_str().unwrap();

    let ret = load_config(p);
    assert!(ret.is_ok());

    let orig = Config {
        id: id.clone(),
        network_id: String::from("custom"),

        snow_sample_size: 100,
        snow_quorum_size: 100,

        http_port: 9650,
        staking_port: 9651,

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
    let cfg = ret.unwrap();
    assert_eq!(cfg, orig);

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.network_id, "custom");
    assert_eq!(cfg.snow_sample_size, 100);
    assert_eq!(cfg.snow_quorum_size, 100);
    assert_eq!(cfg.http_port, 9650);
    assert_eq!(cfg.staking_port, 9651);
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
