use std::io::{self, Error, ErrorKind};

use ethereum_types::{Address, H256};
use ring::digest::{digest, SHA256};
use ripemd::{Digest, Ripemd160};
use secp256k1::{self, PublicKey};
use sha3::Keccak256;

use crate::ids;
use avalanche_utils::prefix;

/// Converts public key bytes to the short address bytes (20-byte).
/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn hash_sha256_ripemd160<S>(pub_key_bytes: S) -> io::Result<Vec<u8>>
where
    S: AsRef<[u8]>,
{
    let digest_sha256 = digest(&SHA256, pub_key_bytes.as_ref());

    // "hashing.PubkeyBytesToAddress"
    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    // already in "type ShortID [20]byte" format
    let sha256_ripemd160 = Ripemd160::digest(&digest_sha256);

    // "ids.ToShortID" merely enforces "ripemd160" size!
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
    if sha256_ripemd160.len() != 20 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "ripemd160 of sha256 must be 20-byte, got {}",
                sha256_ripemd160.len()
            ),
        ));
    }

    Ok(sha256_ripemd160.to_vec())
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn to_short_bytes(public_key: &PublicKey) -> io::Result<Vec<u8>> {
    let public_key_bytes_compressed = public_key.serialize();
    hash_sha256_ripemd160(&public_key_bytes_compressed)
}

/// "hashing.PubkeyBytesToAddress"
/// ref. "pk.PublicKey().Address().Bytes()"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn to_short(public_key: &PublicKey) -> io::Result<ids::ShortId> {
    let public_key_bytes_compressed = public_key.serialize();
    ids::ShortId::from_public_key_bytes(&public_key_bytes_compressed)
}

/// Encodes the public key in ETH address format.
/// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/crypto#PubkeyToAddress
/// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/common#Address.Hex
pub fn to_eth(public_key: &PublicKey) -> io::Result<String> {
    let public_key_bytes_uncompressed = public_key.serialize_uncompressed();

    // ref. "Keccak256(pubBytes[1:])[12:]"
    let digest_h256 = keccak256(&public_key_bytes_uncompressed[1..]);
    let digest_h256 = &digest_h256.0[12..];

    let addr = Address::from_slice(digest_h256);
    let addr_hex = hex::encode(addr);

    // make EIP-55 compliant
    let addr_eip55 = eth_checksum(&addr_hex);
    Ok(prefix::prepend_0x(&addr_eip55))
}

fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(&Keccak256::digest(data.as_ref()))
}

/// ref. https://github.com/Ethereum/EIPs/blob/master/EIPS/eip-55.md
fn eth_checksum(addr: &str) -> String {
    let addr_lower_case = prefix::strip_0x(addr).to_lowercase();
    let digest_h256 = keccak256(&addr_lower_case.as_bytes());

    // this also works...
    //
    // addr_lower_case
    //     .chars()
    //     .enumerate()
    //     .map(|(i, c)| {
    //         if matches!(c, 'a' | 'b' | 'c' | 'd' | 'e' | 'f')
    //             && (digest_h256[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0)
    //         {
    //             c.to_ascii_uppercase()
    //         } else {
    //             c
    //         }
    //     })
    //     .collect::<String>()

    checksum_eip55(&addr_lower_case, &hex::encode(digest_h256))
}

/// ref. https://github.com/Ethereum/EIPs/blob/master/EIPS/eip-55.md
fn checksum_eip55(addr: &str, addr_hash: &str) -> String {
    let mut chksum = String::new();
    for (c, hash_char) in addr.chars().zip(addr_hash.chars()) {
        if hash_char.to_digit(16) >= Some(8) {
            chksum.extend(c.to_uppercase());
        } else {
            chksum.push(c);
        }
    }
    chksum
}
