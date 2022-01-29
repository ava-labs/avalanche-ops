use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
};

use crate::{random, time};

use bitcoin::util::base58;
use log::info;
use openssl::{pkey::PKey, sha::sha256};
use ripemd::{Digest, Ripemd160};

/// Generates a random ID with the prefix followed by a
/// timestamp and random characters.
pub fn generate(pfx: &str) -> String {
    format!("{}-{}-{}", pfx, time::get(10), random::string(12))
}

#[test]
fn test_generate() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let id1 = generate("avax");
    let id2 = generate("avax");
    assert_ne!(id1, id2);

    info!("id1: {:?}", id1);
    info!("id2: {:?}", id2);
}

/// Loads a node ID from the PEM-encoded PKCS#8 key.
/// ref. "avalanchego/node/Node.Initialize"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
pub fn load_node_id(key_path: &str) -> io::Result<String> {
    info!("loading node ID from key {}", key_path);
    let path = Path::new(key_path);
    if !path.exists() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("key path {} does not exists", key_path),
        ));
    }

    let key_contents = fs::read(key_path).unwrap();
    let priv_key = PKey::private_key_from_pem(&key_contents.to_vec()).unwrap();

    // ref. "tls.Certificate.Leaf.Raw" in Go
    // ref. "x509.ParseCertificate/parseCertificate" and "x509.Certificate.Raw"
    // let pub_key_der = priv_key.private_key_to_pem_pkcs8().unwrap();
    let pub_key_der = priv_key.public_key_to_pem().unwrap();

    // "ids.ToShortID(hashing.PubkeyBytesToAddress(n.Config.StakingTLSCert.Leaf.Raw))"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
    let node_id = encode_node_id(&pub_key_der.to_vec());
    Ok(node_id)
}

/// Encodes the cert raw bytes to a node ID.
/// It applies "sha256" and "ripemd160" on "Certificate.Leaf.Raw".
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
pub fn encode_node_id(d: &[u8]) -> String {
    let sha256_hashed = sha256(d);

    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    // already in "type ShortID [20]byte" format
    let ripemd160_hashed = Ripemd160::digest(sha256_hashed);

    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.String
    let id = base58::encode_slice(&ripemd160_hashed);

    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.PrefixedString
    // ref. "PrefixedString(constants.NodeIDPrefix)"
    let mut node_id = String::from("NodeID-");
    node_id.push_str(&id);
    node_id
}

// TODO: fix this

#[test]
fn test_node_id() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let node_id = load_node_id("./artifacts/staker1.insecure.key").unwrap();
    info!("node_id: {}", node_id);
    assert_eq!(node_id, "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg");
}
