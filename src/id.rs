use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
};

use bitcoin::util::base58;
use log::info;
use openssl::{sha::sha256, x509::X509};
use ripemd::{Digest, Ripemd160};

use crate::{random, time};

/// Generates a random ID with the prefix followed by a
/// timestamp and random characters.
pub fn generate(pfx: &str) -> String {
    format!("{}-{}-{}", pfx, time::get(6), random::string(6))
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

/// Creates an ID based on host information.
pub fn sid(n: usize) -> String {
    let id = format!(
        "{}-{}-{}",
        whoami::username(),
        whoami::hostname(),
        whoami::platform()
    );

    let mut hasher = Ripemd160::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();

    let mut id = hex::encode(&result[..]);
    if n > 0 && id.len() > n {
        id.truncate(n);
    }
    id
}

#[test]
fn test_sid() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let id1 = sid(10);
    let id2 = sid(10);
    assert_eq!(id1, id2);

    info!("id1: {:?}", id1);
    info!("id2: {:?}", id2);
}

/// Loads a node ID from the PEM-encoded X509 certificate.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/node#Node.Initialize
pub fn load_node_id(cert_path: &str) -> io::Result<String> {
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
    encode_node_id(&pub_key_der.to_vec())
}

const CHECKSUM_LENGTH: usize = 4;

/// Encodes the cert raw bytes to a node ID.
/// It applies "sha256" and "ripemd160" on "Certificate.Leaf.Raw".
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
fn encode_node_id(cert_raw: &[u8]) -> io::Result<String> {
    // "hashing.PubkeyBytesToAddress"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
    let sha256_digest = sha256(cert_raw);

    // "hashing.PubkeyBytesToAddress"
    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    // already in "type ShortID [20]byte" format
    let ripemd160_sha256 = Ripemd160::digest(sha256_digest);

    // "ids.ToShortID" merely enforces "ripemd160" size!
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
    if ripemd160_sha256.len() != 20 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "ripemd160 of sha256(cert) must be 20-byte, got {}",
                ripemd160_sha256.len()
            ),
        ));
    }

    // convert the short ID to string!
    // "ids.ShortID.String" appends checksum to the digest bytes
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.String
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/formatting#EncodeWithChecksum
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#Checksum

    // "hash := ComputeHash256Array(bytes)"
    let checksum = sha256(&ripemd160_sha256);

    // hash[len(hash)-length:]
    let checksum_length = checksum.len();
    let checksum = &checksum[checksum_length - CHECKSUM_LENGTH..];

    let mut checked = ripemd160_sha256.to_vec();
    let mut checksum = checksum.to_vec();
    checked.append(&mut checksum);

    // ref. "utils/formatting encode.CB58"
    // ref. "base58.Encode"
    let hashed = base58::encode_slice(&checked);

    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.PrefixedString
    // ref. "PrefixedString(constants.NodeIDPrefix)"
    let mut node_id = String::from("NodeID-");
    node_id.push_str(&hashed);
    Ok(node_id)
}

#[test]
fn test_node_id() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::warn;

    // copied from "avalanchego/staking/local/staking1.key,crt"
    // verified by "avalanchego-compatibility/node-id" for compatibility with Go
    let expected = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_id = load_node_id("./artifacts/staker1.insecure.crt").unwrap();
    if node_id.ne(expected) {
        warn!("unexpected node_id {}, expected {}", node_id, expected);
    }
    assert_eq!(node_id, expected);

    // generated by "examples/cert.rs"
    // verified by "avalanchego-compatibility/node-id" for compatibility with Go
    //
    // e.g.,
    // cargo run --example cert \
    // -- ./artifacts/test.insecure.key \
    // ./artifacts/test.insecure.crt
    let expected = "NodeID-29HTAG5cfN2fw79A67Jd5zY9drcT51EBG";
    let node_id = load_node_id("./artifacts/test.insecure.crt").unwrap();
    if node_id.ne(expected) {
        warn!("unexpected node_id {}, expected {}", node_id, expected);
    }
    assert_eq!(node_id, expected);
}
