use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
    string::String,
};

use lazy_static::lazy_static;
use log::info;
use openssl::x509::X509;

use crate::{formatting, key, packer};
use utils::{cmp, hash};

pub const ID_LEN: usize = 32;
pub const SHORT_ID_LEN: usize = 20;
pub const NODE_ID_LEN: usize = 20;
pub const NODE_ID_ENCODE_PREFIX: &str = "NodeID-";

lazy_static! {
    static ref EMPTY: Vec<u8> = vec![0; ID_LEN];
    static ref SHORT_EMPTY: Vec<u8> = vec![0; SHORT_ID_LEN];
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ID
#[derive(Debug, Clone)]
pub struct Id {
    pub d: Vec<u8>,
}

impl Default for Id {
    fn default() -> Self {
        Self::default()
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        cmp::eq_u8_vectors(&self.d, &other.d)
    }
}
impl Eq for Id {}

impl Id {
    pub fn default() -> Self {
        Self { d: EMPTY.to_vec() }
    }

    pub fn empty() -> Self {
        Self { d: EMPTY.to_vec() }
    }

    pub fn is_empty(&self) -> bool {
        (*self) == Self::empty()
    }

    /// If the passed array is shorter than the ID_LEN,
    /// it fills in with zero.
    pub fn new(d: &[u8]) -> Self {
        assert!(d.len() <= ID_LEN);
        let mut d: Vec<u8> = Vec::from(d);
        if d.len() < ID_LEN {
            d.resize(ID_LEN, 0);
        }
        Self { d }
    }

    pub fn create_from_str(s: &str) -> Self {
        assert!(s.len() <= ID_LEN);
        let mut d: Vec<u8> = Vec::from(s.as_bytes());
        if d.len() < ID_LEN {
            d.resize(ID_LEN, 0);
        }
        Self { d }
    }

    pub fn string(&self) -> String {
        formatting::encode_cb58_with_checksum(&self.d)
    }

    /// ref. "ids.ID.Prefix(output_index)"
    pub fn prefix(&self, prefixes: &[u64]) -> Self {
        let n = prefixes.len() + packer::U64_LEN + 32;
        let packer = packer::Packer::new(n, n);
        for pfx in prefixes {
            packer.pack_u64(*pfx);
        }
        packer.pack_bytes(&self.d);

        let b = packer.take_bytes();
        let d = hash::compute_sha256(&b);
        Self::new(&d)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- ids::test_id --exact --show-output
/// ref. "avalanchego/ids.TestIDMarshalJSON"
#[test]
fn test_id() {
    let id = Id::new(&<Vec<u8>>::from([
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
        0xc3, 0x2b, 0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, //
        0x59, 0xa7,
    ]));
    assert_eq!(
        id.string(),
        "TtF4d2QWbk5vzQGTEPrN48x6vwgAoAmKQ9cbp79inpQmcRKES"
    );

    let id = Id::create_from_str("ava labs");
    assert_eq!(
        id.string(),
        "jvYi6Tn9idMi7BaymUVi9zWjg5tpmW7trfKG1AYJLKZJ2fsU7"
    );
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID
#[derive(Debug, Clone)]
pub struct ShortId {
    pub d: Vec<u8>,
}

impl Default for ShortId {
    fn default() -> Self {
        Self::default()
    }
}

impl PartialEq for ShortId {
    fn eq(&self, other: &Self) -> bool {
        cmp::eq_u8_vectors(&self.d, &other.d)
    }
}
impl Eq for ShortId {}

impl ShortId {
    pub fn default() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn empty() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        (*self) == Self::empty()
    }

    pub fn new(d: &[u8]) -> Self {
        assert_eq!(d.len(), SHORT_ID_LEN);
        let d = Vec::from(d);
        Self { d }
    }

    pub fn string(&self) -> String {
        formatting::encode_cb58_with_checksum(&self.d)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- ids::test_short_id --exact --show-output
#[test]
fn test_short_id() {
    let id = ShortId::new(&<Vec<u8>>::from([
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
    ]));
    assert_eq!(id.string(), "6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx");
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID
#[derive(Debug, Clone)]
pub struct NodeId {
    pub d: Vec<u8>,
}

impl Default for NodeId {
    fn default() -> Self {
        Self::default()
    }
}

impl PartialEq for NodeId {
    fn eq(&self, other: &Self) -> bool {
        cmp::eq_u8_vectors(&self.d, &other.d)
    }
}
impl Eq for NodeId {}

impl NodeId {
    pub fn default() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn empty() -> Self {
        Self {
            d: SHORT_EMPTY.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        (*self) == Self::empty()
    }

    pub fn new(d: &[u8]) -> Self {
        assert_eq!(d.len(), SHORT_ID_LEN);
        let d = Vec::from(d);
        Self { d }
    }

    /// Loads a node ID from the PEM-encoded X509 certificate.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
    pub fn from_cert_file(cert_file_path: &str) -> io::Result<Self> {
        info!("loading node ID from certificate {}", cert_file_path);
        if !Path::new(cert_file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("cert path {} does not exists", cert_file_path),
            ));
        }

        let pub_key_contents = fs::read(cert_file_path).unwrap();
        let pub_key = X509::from_pem(&pub_key_contents.to_vec()).unwrap();

        // ref. "tls.Certificate.Leaf.Raw" in Go
        // ref. "tls.X509KeyPair"
        // ref. "x509.ParseCertificate/parseCertificate"
        // ref. "x509.Certificate.Leaf"
        let pub_key_der = pub_key.to_der().unwrap();

        // "ids.ToShortID(hashing.PubkeyBytesToAddress(StakingTLSCert.Leaf.Raw))"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
        Self::from_cert_raw(&pub_key_der.to_vec())
    }

    /// Encodes the cert raw bytes to a node ID.
    /// It applies "sha256" and "ripemd160" on "Certificate.Leaf.Raw".
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
    pub fn from_cert_raw(cert_raw: &[u8]) -> io::Result<Self> {
        let short_address = key::bytes_to_short_address_bytes(cert_raw)?;
        let node_id = Self::new(&short_address);
        Ok(node_id)
    }

    pub fn string_short_id(&self) -> String {
        formatting::encode_cb58_with_checksum(&self.d)
    }

    pub fn string(&self) -> String {
        let mut node_id = String::from(NODE_ID_ENCODE_PREFIX);
        node_id.push_str(&self.string_short_id());
        node_id
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- ids::test_from_cert_file --exact --show-output
#[test]
fn test_from_cert_file() {
    let _ = env_logger::builder().is_test(true).try_init();

    let id = NodeId::new(&<Vec<u8>>::from([
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
    ]));
    assert_eq!(id.string(), "NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx");
    assert_eq!(id.string_short_id(), "6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx");

    // copied from "avalanchego/staking/local/staking1.key,crt"
    // verified by "avalanchego-compatibility/node-id" for compatibility with Go
    let node_id = NodeId::from_cert_file("./artifacts/staker1.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg");

    let node_id = NodeId::from_cert_file("./artifacts/staker2.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-MFrZFVCXPv5iCn6M9K6XduxGTYp891xXZ");

    let node_id = NodeId::from_cert_file("./artifacts/staker3.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-NFBbbJ4qCmNaCzeW7sxErhvWqvEQMnYcN");

    let node_id = NodeId::from_cert_file("./artifacts/staker4.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-GWPcbFJZFfZreETSoWjPimr846mXEKCtu");

    let node_id = NodeId::from_cert_file("./artifacts/staker5.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-P7oB2McjBGgW2NXXWVYjV8JEDFoW9xDE5");

    let node_id = NodeId::from_cert_file("./artifacts/test.insecure.crt").unwrap();
    assert_eq!(node_id.string(), "NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG");
}
