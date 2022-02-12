use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::compress;

/// Defines the node type.
/// Must be either "beacon" or "non-beacon"
pub enum Kind {
    Beacon,
    NonBeacon,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Beacon => "beacon",
            Kind::NonBeacon => "non-beacon",
        }
    }
    pub fn from_str(&self, s: &str) -> io::Result<Self> {
        match s {
            "beacon" => Ok(Kind::Beacon),
            "non-beacon" => Ok(Kind::NonBeacon),
            "non_beacon" => Ok(Kind::NonBeacon),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("unknown node type '{}'", s),
            )),
        }
    }
}

/// Represents each beacon/non-beacon node.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Node {
    pub kind: String,
    pub machine_id: String,
    pub id: String,
    pub ip: String,
}

impl Node {
    pub fn new(kind: Kind, machine_id: &str, id: &str, ip: &str) -> Self {
        Self {
            kind: String::from(kind.as_str()),
            machine_id: String::from(machine_id),
            id: String::from(id),
            ip: String::from(ip),
        }
    }

    /// Converts to string with YAML encoder.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current beacon node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Node to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Node to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading node from {}", file_path);

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

    /// Encodes the object in YAML format, compresses, and apply base58.
    /// Used for shortening S3 file name.
    pub fn compress_base58(&self) -> io::Result<String> {
        let d = match serde_yaml::to_vec(self) {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Node to YAML {}", e),
                ));
            }
        };
        compress::to_zstd_base58(&d, None)
    }

    /// Reverse of "compress_base64".
    pub fn decompress_base58(d: String) -> io::Result<Self> {
        let decompressed = compress::from_zstd_base58(d)?;
        serde_yaml::from_slice(&decompressed).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e));
        })
    }
}

#[test]
fn test_node() {
    let d = r#"
kind: beacon
machine_id: i-123123
id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
ip: 1.2.3.4

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
        Kind::Beacon,
        "i-123123",
        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
        "1.2.3.4",
    );
    assert_eq!(node, orig);

    // manually check to make sure the serde deserializer works
    assert_eq!(node.kind, String::from("beacon"));
    assert_eq!(node.machine_id, String::from("i-123123"));
    assert_eq!(
        node.id,
        String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg")
    );
    assert_eq!(node.ip, String::from("1.2.3.4"));

    let encoded_yaml = node.encode_yaml().unwrap();
    info!("node.encode_yaml: {}", encoded_yaml);
    let compressed = node.compress_base58().unwrap();
    info!("node.compress_base64: {}", compressed);
    let decompressed_node = Node::decompress_base58(compressed).unwrap();
    assert_eq!(node, decompressed_node);
}
