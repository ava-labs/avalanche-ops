use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::{
    avalanche::{avalanchego::config as avalanchego_config, coreth::config as coreth_config, key},
    utils::compress,
};

/// Defines the node type.
/// MUST BE either "anchor" or "non-anchor"
#[derive(Eq, PartialEq, Clone)]
pub enum Kind {
    Anchor,
    NonAnchor,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Anchor => "anchor",
            Kind::NonAnchor => "non-anchor",
        }
    }
    pub fn from_str(&self, s: &str) -> io::Result<Self> {
        match s {
            "anchor" => Ok(Kind::Anchor),
            "non-anchor" => Ok(Kind::NonAnchor),
            "non_anchor" => Ok(Kind::NonAnchor),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("unknown node type '{}'", s),
            )),
        }
    }
}

/// Represents each anchor/non-beacon node.
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
        kind: Kind,
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
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current anchor node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Node to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
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
        let compressed = compress::pack(&d, compress::Encoder::ZstdBase58(3))?;
        Ok(String::from_utf8(compressed).expect("unexpected None String::from_utf8"))
    }

    /// Reverse of "compress_base64".
    pub fn decompress_base58(d: String) -> io::Result<Self> {
        let decompressed = compress::unpack(d.as_bytes(), compress::Decoder::ZstdBase58)?;
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
        Kind::Anchor,
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
    info!("node.encode_yaml: {}", encoded_yaml);
    let compressed = node.compress_base58().unwrap();
    info!("node.compress_base64: {}", compressed);
    let decompressed_node = Node::decompress_base58(compressed).unwrap();
    assert_eq!(node, decompressed_node);
}

/// Loads a node ID from the PEM-encoded X509 certificate.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
pub fn load_id(cert_path: &str) -> io::Result<String> {
    info!("loading node ID from certificate {}", cert_path);
    if !Path::new(cert_path).exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("cert path {} does not exists", cert_path),
        ));
    }

    let pub_key_contents = fs::read(cert_path).unwrap();
    let pub_key = X509::from_pem(&pub_key_contents.to_vec()).unwrap();

    // ref. "tls.Certificate.Leaf.Raw" in Go
    // ref. "tls.X509KeyPair"
    // ref. "x509.ParseCertificate/parseCertificate"
    // ref. "x509.Certificate.Leaf"
    let pub_key_der = pub_key.to_der().unwrap();

    // "ids.ToShortID(hashing.PubkeyBytesToAddress(StakingTLSCert.Leaf.Raw))"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
    encode_id(&pub_key_der.to_vec())
}

/// Encodes the cert raw bytes to a node ID.
/// It applies "sha256" and "ripemd160" on "Certificate.Leaf.Raw".
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
fn encode_id(cert_raw: &[u8]) -> io::Result<String> {
    let short_address = key::bytes_to_short_address(cert_raw)?;

    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.PrefixedString
    // ref. "PrefixedString(constants.NodeIDPrefix)"
    let mut node_id = String::from("NodeID-");
    node_id.push_str(&short_address);
    Ok(node_id)
}

#[test]
fn test_id() {
    let _ = env_logger::builder().is_test(true).try_init();

    // copied from "avalanchego/staking/local/staking1.key,crt"
    // verified by "avalanchego-compatibility/node-id" for compatibility with Go
    let expected = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_id = load_id("./artifacts/staker1.insecure.crt").unwrap();
    assert_eq!(node_id, expected);

    let expected = "NodeID-MFrZFVCXPv5iCn6M9K6XduxGTYp891xXZ";
    let node_id = load_id("./artifacts/staker2.insecure.crt").unwrap();
    assert_eq!(node_id, expected);

    let expected = "NodeID-NFBbbJ4qCmNaCzeW7sxErhvWqvEQMnYcN";
    let node_id = load_id("./artifacts/staker3.insecure.crt").unwrap();
    assert_eq!(node_id, expected);

    let expected = "NodeID-GWPcbFJZFfZreETSoWjPimr846mXEKCtu";
    let node_id = load_id("./artifacts/staker4.insecure.crt").unwrap();
    assert_eq!(node_id, expected);

    let expected = "NodeID-P7oB2McjBGgW2NXXWVYjV8JEDFoW9xDE5";
    let node_id = load_id("./artifacts/staker5.insecure.crt").unwrap();
    assert_eq!(node_id, expected);

    // generated by "examples/cert.rs"
    // verified by "avalanchego-compatibility/local-node-id" for compatibility with Go
    //
    // e.g.,
    // cargo run --example cert \
    // -- ./artifacts/test.insecure.key \
    // ./artifacts/test.insecure.crt
    let expected = "NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG";
    let node_id = load_id("./artifacts/test.insecure.crt").unwrap();
    assert_eq!(node_id, expected);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Info {
    pub local_node: Node,
    pub avalanchego_config: avalanchego_config::Config,
    pub coreth_config: coreth_config::Config,
}

impl Info {
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
        info!("syncing Info to '{}'", file_path);
        let path = Path::new(&file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Info to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(&file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}
