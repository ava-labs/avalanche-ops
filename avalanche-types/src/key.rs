use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use bitcoin::hashes::hex::ToHex;
use ethereum_types::{Address, H256};
use lazy_static::lazy_static;
use log::info;
use ripemd::{Digest, Ripemd160};
use rust_embed::RustEmbed;
use secp256k1::{self, rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::Keccak256;

use crate::{constants, formatting};
use utils::{hash, prefix};

pub const PRIVATE_KEY_ENCODE_PREFIX: &str = "PrivateKey-";

lazy_static! {
    pub static ref TEST_KEYS: Vec<Key> = {
        #[derive(RustEmbed)]
        #[folder = "artifacts/"]
        #[prefix = "artifacts/"]
        struct Asset;

        let key_file = Asset::get("artifacts/test.insecure.secp256k1.keys").unwrap();
        let text = std::str::from_utf8(key_file.data.as_ref()).expect("failed to load key file");

        let mut lines = text.lines();
        let mut keys: Vec<Key> = Vec::new();
        let mut added = HashMap::new();
        loop {
            if let Some(s) = lines.next() {
                if added.get(s).is_some() {
                    panic!("test key '{}' added before (redundant!)", s)
                }
                keys.push(Key::from_private_key(s).unwrap());
                added.insert(s, true);
                continue;
            }
            break;
        }
        keys
    };
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- key::test_keys --exact --show-output
#[test]
fn test_keys() {
    let _ = env_logger::builder().is_test(true).try_init();
    for k in TEST_KEYS.iter() {
        info!("test key eth address {:?}", k.eth_address);
    }
    info!("total {} test keys are found", TEST_KEYS.len());
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Key {
    #[serde(skip_serializing, skip_deserializing)]
    pub secret_key: Option<SecretKey>,
    #[serde(skip_serializing, skip_deserializing)]
    pub public_key: Option<PublicKey>,

    /// AVAX wallet compatible private key.
    /// NEVER save mainnet-funded wallet keys here.
    pub private_key: String,
    /// Used for importing keys in MetaMask and subnet-cli.
    /// ref. https://github.com/ava-labs/subnet-cli/blob/5b69345a3fba534fb6969002f41c8d3e69026fed/internal/key/key.go#L238-L258
    /// NEVER save mainnet-funded wallet keys here.
    pub private_key_hex: String,

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
    pub short_address: String,

    /// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/common#Address
    pub eth_address: String,
}

impl Key {
    /// Generates a new Secp256k1 key.
    pub fn generate() -> io::Result<Self> {
        info!("generating secp256k1 key");

        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);

        let short_address = public_key_to_short_address(&public_key)?;
        let eth_address = public_key_to_eth_address(&public_key)?;

        // ref. https://github.com/rust-bitcoin/rust-secp256k1/pull/396
        let priv_bytes = secret_key.secret_bytes();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        private_key.push_str(&enc);
        let private_key_hex = hex::encode(&priv_bytes);

        Ok(Self {
            secret_key: Some(secret_key),
            public_key: Some(public_key),
            private_key,
            private_key_hex,
            short_address,
            eth_address,
        })
    }

    /// Loads the specified Secp256k1 key with CB58 encoding.
    /// Takes the "private_key" field in the "Key" struct.
    pub fn from_private_key(encoded_priv_key: &str) -> io::Result<Self> {
        let raw = String::from(encoded_priv_key).replace(PRIVATE_KEY_ENCODE_PREFIX, "");

        let priv_bytes = formatting::decode_cb58_with_checksum(&raw)?;
        if priv_bytes.len() != secp256k1::constants::SECRET_KEY_SIZE {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "unexpected secret key size ({}, expected {})",
                    priv_bytes.len(),
                    secp256k1::constants::SECRET_KEY_SIZE
                ),
            ));
        }

        let secret_key = match SecretKey::from_slice(&priv_bytes) {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to load secret key ({})", e),
                ));
            }
        };

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let short_address = public_key_to_short_address(&public_key)?;
        let eth_address = public_key_to_eth_address(&public_key)?;

        // ref. https://github.com/rust-bitcoin/rust-secp256k1/pull/396
        let priv_bytes = secret_key.secret_bytes();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        private_key.push_str(&enc);
        let private_key_hex = hex::encode(&priv_bytes);

        Ok(Self {
            secret_key: Some(secret_key),
            public_key: Some(public_key),
            private_key,
            private_key_hex,
            short_address,
            eth_address,
        })
    }

    /// Loads the specified Secp256k1 key with hex encoding.
    /// Takes the "private_key" field in the "Key" struct.
    pub fn from_private_key_eth(encoded_priv_key: &str) -> io::Result<Self> {
        let priv_bytes = match hex::decode(encoded_priv_key) {
            Ok(b) => b,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to decode hex private key ({})", e),
                ));
            }
        };
        if priv_bytes.len() != secp256k1::constants::SECRET_KEY_SIZE {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "unexpected secret key size ({}, expected {})",
                    priv_bytes.len(),
                    secp256k1::constants::SECRET_KEY_SIZE
                ),
            ));
        }
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        Self::from_private_key(&enc)
    }

    /// Implements "crypto.PublicKeySECP256K1R.Address()" and "formatting.FormatAddress".
    /// "human readable part" (hrp) must be valid output from "constants.GetHRP(networkID)".
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants
    pub fn address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String> {
        let hrp = match constants::NETWORK_ID_TO_HRP.get(&network_id) {
            Some(v) => v,
            None => constants::FALLBACK_HRP,
        };
        // ref. "pk.PublicKey().Address().Bytes()"
        let short_address_bytes = public_key_to_short_address_bytes(
            &self.public_key.expect("unexpected empty public_key"),
        )?;

        // ref. "formatting.FormatAddress(chainIDAlias, hrp, pubBytes)"
        formatting::address(chain_id_alias, hrp, &short_address_bytes)
    }

    pub fn short_address_bytes(&self) -> io::Result<Vec<u8>> {
        public_key_to_short_address_bytes(&self.public_key.expect("unexpected empty public_key"))
    }

    pub fn info(&self, network_id: u32) -> io::Result<PrivateKeyInfo> {
        let x = self.address("X", network_id)?;
        let p = self.address("P", network_id)?;
        let c = self.address("C", network_id)?;
        Ok(PrivateKeyInfo {
            private_key: self.private_key.clone(),
            private_key_hex: self.private_key_hex.clone(),
            x_address: x,
            p_address: p,
            c_address: c,
            short_address: self.short_address.clone(),
            eth_address: self.eth_address.clone(),
        })
    }
}

/// "hashing.PubkeyBytesToAddress"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn bytes_to_short_address(d: &[u8]) -> io::Result<String> {
    let short_address_bytes = bytes_to_short_address_bytes(d)?;

    // "ids.ShortID.String"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.String
    Ok(formatting::encode_cb58_with_checksum(&short_address_bytes))
}

/// "hashing.PubkeyBytesToAddress"
/// ref. "pk.PublicKey().Address().Bytes()"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
fn public_key_to_short_address(public_key: &PublicKey) -> io::Result<String> {
    let public_key_bytes_compressed = public_key.serialize();
    bytes_to_short_address(&public_key_bytes_compressed)
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
fn bytes_to_short_address_bytes(d: &[u8]) -> io::Result<Vec<u8>> {
    let digest_sha256 = hash::compute_sha256(d);

    // "hashing.PubkeyBytesToAddress"
    // acquire hash digest in the form of GenericArray,
    // which in this case is equivalent to [u8; 20]
    // already in "type ShortID [20]byte" format
    let ripemd160_sha256 = Ripemd160::digest(digest_sha256);

    // "ids.ToShortID" merely enforces "ripemd160" size!
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ToShortID
    if ripemd160_sha256.len() != 20 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "ripemd160 of sha256 must be 20-byte, got {}",
                ripemd160_sha256.len()
            ),
        ));
    }

    Ok(ripemd160_sha256.to_vec())
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn public_key_to_short_address_bytes(public_key: &PublicKey) -> io::Result<Vec<u8>> {
    let public_key_bytes_compressed = public_key.serialize();
    bytes_to_short_address_bytes(&public_key_bytes_compressed)
}

/// Encodes the public key in ETH address format.
/// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/crypto#PubkeyToAddress
/// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/common#Address.Hex
pub fn public_key_to_eth_address(public_key: &PublicKey) -> io::Result<String> {
    let public_key_bytes_uncompressed = public_key.serialize_uncompressed();

    // ref. "Keccak256(pubBytes[1:])[12:]"
    let digest_h256 = keccak256(&public_key_bytes_uncompressed[1..]);
    let digest_h256 = &digest_h256.0[12..];

    let addr = Address::from_slice(digest_h256);
    let addr_hex = addr.to_hex(); // "hex::encode"

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

    checksum_eip55(&addr_lower_case, &digest_h256.to_hex())
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- key::test_key --exact --show-output
#[test]
fn test_key() {
    let _ = env_logger::builder().is_test(true).try_init();

    let generated_key = Key::generate().unwrap();
    info!("{}", generated_key.private_key);
    info!("{}", generated_key.short_address.clone());
    info!("{}", generated_key.address("X", 9999).unwrap());

    let parsed_key = Key::from_private_key(&generated_key.private_key).unwrap();
    info!("{}", parsed_key.private_key);
    info!("{}", parsed_key.short_address.clone());
    info!("{}", parsed_key.address("X", 9999).unwrap());

    assert_eq!(generated_key.private_key, parsed_key.private_key);
    assert_eq!(
        generated_key.short_address.clone(),
        parsed_key.short_address.clone()
    );
    assert_eq!(
        generated_key.address("X", 9999).unwrap(),
        parsed_key.address("X", 9999).unwrap()
    );

    let random_key =
        Key::from_private_key("PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "6Y3kysjF9jnHnYkdS9yGAuoHyae2eNmeV"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        random_key.eth_address,
        "0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"
    );

    // test random keys generated by "avalanchego/utils/crypto.FactorySECP256K1R"
    // and make sure both generate the same addresses
    // use "avalanche-ops/avalanchego-compatibility/key/main.go"
    // to generate keys and addresses with "avalanchego"
    let random_key =
        Key::from_private_key("PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "AFmizAhcFuJm3u3Jih8TQ7ACCJnUY3yTK"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1vkzy5p2qtumx9svjs9pvds48s0hcw80fkqcky9"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1vkzy5p2qtumx9svjs9pvds48s0hcw80fkqcky9"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1vkzy5p2qtumx9svjs9pvds48s0hcw80fkqcky9"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs"
    );
    assert_eq!(
        random_key.eth_address,
        "0x613040a239BDfCF110969fecB41c6f92EA3515C0"
    );

    let random_key =
        Key::from_private_key("PrivateKey-SoNEe44ACVQttLGrhrPPn7hi2h8ok43R7zgQALiZZ2im2S6yj")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "3a94aab8123f3be575ea9679f893da5182e8b707e26f06159c264399113aef2a"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "LeKrndtsMxcLMzHz3w4uo1XtLDpfi66c"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1qwmslrrqdv4slxvynhy9csq069l0u8mqagsplc"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1qwmslrrqdv4slxvynhy9csq069l0u8mqagsplc"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1qwmslrrqdv4slxvynhy9csq069l0u8mqagsplc"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1qwmslrrqdv4slxvynhy9csq069l0u8mqwjzmcd"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1qwmslrrqdv4slxvynhy9csq069l0u8mqwjzmcd"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1qwmslrrqdv4slxvynhy9csq069l0u8mqwjzmcd"
    );
    assert_eq!(
        random_key.eth_address,
        "0x0a63aCC3735e825D7D13243FD76bAd49331baE0E"
    );

    let random_key =
        Key::from_private_key("PrivateKey-qDaD5aAZs7EBq5TWEBa9LLBusBhXZY5PM831JExRhoM6nfAc5")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "6d7b68fca444069f3e65644848b215f1ecd4a90de8403734866dbb6af1c8957d"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "McqzEWWmhaqfHjieL2Pxiy95hzXDMb848"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1ug5lw6rut5pg97028xq0tclc7lkhz5hnnu5ypj"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1ug5lw6rut5pg97028xq0tclc7lkhz5hnnu5ypj"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1ug5lw6rut5pg97028xq0tclc7lkhz5hnnu5ypj"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1ug5lw6rut5pg97028xq0tclc7lkhz5hnqxx7x8"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1ug5lw6rut5pg97028xq0tclc7lkhz5hnqxx7x8"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1ug5lw6rut5pg97028xq0tclc7lkhz5hnqxx7x8"
    );
    assert_eq!(
        random_key.eth_address,
        "0x2fc922Bee902520c4681c5bbd97908C727664e56"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2VfFU6KsGt4mcppQ5kvdKws6Jgxn32cwfEL9B1FEv72BqvxdtW")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "c4c55bfa3b5fd618fbd63e8cd62a8e0277f6e008cf76472e0a00941c6d326b46"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "JsrcoBpKWod6gkAQAcgyJCh7u7nmNuDfi"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1csv945xrn0t8jgq0mpn2kvx3h7cnwg44s373js"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1csv945xrn0t8jgq0mpn2kvx3h7cnwg44s373js"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1csv945xrn0t8jgq0mpn2kvx3h7cnwg44s373js"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1csv945xrn0t8jgq0mpn2kvx3h7cnwg44rtvt49"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1csv945xrn0t8jgq0mpn2kvx3h7cnwg44rtvt49"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1csv945xrn0t8jgq0mpn2kvx3h7cnwg44rtvt49"
    );
    assert_eq!(
        random_key.eth_address,
        "0x0C85f27550cab3127FB6Da84E6DDceCf34272fD0"
    );

    let random_key =
        Key::from_private_key("PrivateKey-TZykRxv83FSZsf6QkENwYApnEhBLPpgJ88r1MD1iBvEXqj2gJ")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "3c53c620aeb35bc15146b84688a5f478aaa1528e41c8ef11014b50ef4b110870"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "Q6j6SupDqiWLsMY3nRr4wEBxC3Six2W9a"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1l4spcm52qwv7gmdldzyrq9u20neg7x0n9kj6tv"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1l4spcm52qwv7gmdldzyrq9u20neg7x0n9kj6tv"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1l4spcm52qwv7gmdldzyrq9u20neg7x0n9kj6tv"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1l4spcm52qwv7gmdldzyrq9u20neg7x0nkvqqve"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1l4spcm52qwv7gmdldzyrq9u20neg7x0nkvqqve"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1l4spcm52qwv7gmdldzyrq9u20neg7x0nkvqqve"
    );
    assert_eq!(
        random_key.eth_address,
        "0x4afB753C643890880ba343897a4D591dCf48149D"
    );

    let random_key =
        Key::from_private_key("PrivateKey-D4cxxtZYXPJEPsJDhibRJYNGu8G9oNqHRegZDqaCLrxLAPYJF")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "1b63a1eb7537baac2eef64d111caa99af41e7ce9b0ce9d067276af3fa9e8a777"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "H5GUwiytWzwGDay3mhtdDqdt4RqFkYhko"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1kpgfn9gwg6edgxzqvtn48h5ukpwwe7enmjr6f8"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1kpgfn9gwg6edgxzqvtn48h5ukpwwe7enmjr6f8"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1kpgfn9gwg6edgxzqvtn48h5ukpwwe7enmjr6f8"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1kpgfn9gwg6edgxzqvtn48h5ukpwwe7engg3qwj"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1kpgfn9gwg6edgxzqvtn48h5ukpwwe7engg3qwj"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1kpgfn9gwg6edgxzqvtn48h5ukpwwe7engg3qwj"
    );
    assert_eq!(
        random_key.eth_address,
        "0x35649adb63CDfB9bF83E39b51292dFe74b157Eb5"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2TAuVGfEZkGahWD19CbTzWoynkTHZGM3Bn1AD3Vensno6Uphor")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "bf1ebb0dcbc9f92c34a1beea6950c291d5eef8cc724477b43e3c4bca69af50aa"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "Q9RUX7iHDwGiss4xRcPswgCWJUJ4oenfG"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1lh32df5c5sajgp8pxyjj2f3zk2elhpnqyvlqvk"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1lh32df5c5sajgp8pxyjj2f3zk2elhpnqyvlqvk"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1lh32df5c5sajgp8pxyjj2f3zk2elhpnqyvlqvk"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1lh32df5c5sajgp8pxyjj2f3zk2elhpnqhkd6tr"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1lh32df5c5sajgp8pxyjj2f3zk2elhpnqhkd6tr"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1lh32df5c5sajgp8pxyjj2f3zk2elhpnqhkd6tr"
    );
    assert_eq!(
        random_key.eth_address,
        "0xA17a36938519B78935D94D2c7ab140F8ba465ABf"
    );

    let random_key =
        Key::from_private_key("PrivateKey-F1gtp8JRhuEnJWnnpQg6pMY5MXAny968z6GsZMZWpyb8Ae1dr")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "1fd0cdc3f62d6854af1397a14521efd4c073f35e003901312d7fa6bcd5c68c79"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "E65fLiZ7dyBPFfNmXhYsEhPnMUVZsodce"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1378ek97upwrukv9n22sy7k4enjkgqapcr8l8k0"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1378ek97upwrukv9n22sy7k4enjkgqapcr8l8k0"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1378ek97upwrukv9n22sy7k4enjkgqapcr8l8k0"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1378ek97upwrukv9n22sy7k4enjkgqapcsada36"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1378ek97upwrukv9n22sy7k4enjkgqapcsada36"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1378ek97upwrukv9n22sy7k4enjkgqapcsada36"
    );
    assert_eq!(
        random_key.eth_address,
        "0x2436E31acb71b31044d0e16ba3798a2b6A845ace"
    );

    let random_key =
        Key::from_private_key("PrivateKey-BfJbL9SsyXBW9LbWrLSMDjWufPz6diNpu9vw5TQwpDBdWwohk")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "1834abcea6a56a4d7f1e2c3ad13a8b762a7c79ad5819fa30f31488943e82626a"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "Cka83XSSmLBYQYPRSLqYj13UzQDFTSUW4"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1srnwkx0daefkq0ljuym029sua8zs7pnq8244wf"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1srnwkx0daefkq0ljuym029sua8zs7pnq8244wf"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1srnwkx0daefkq0ljuym029sua8zs7pnq8244wf"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1srnwkx0daefkq0ljuym029sua8zs7pnq5s80fu"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1srnwkx0daefkq0ljuym029sua8zs7pnq5s80fu"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1srnwkx0daefkq0ljuym029sua8zs7pnq5s80fu"
    );
    assert_eq!(
        random_key.eth_address,
        "0x04d6C02f9232D93EF5A6A9ec0867503a28D44Ea5"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2uyRJTVv8ot4V8Q7nUYGPwh2EigA3XzXdYcEwUMx6jsPr4Hwmh")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "fbfa28bf2c3244b8c8444bc7ee00e45cf7db4546d466f85a9b2686a9b989ed3d"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "MTo6jn3kNBsfNhUPFpvDi9YEjT66J2Lr6"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1upeulemvk20cmqujlk6mas4gwdqhs6e8a6vjtr"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1upeulemvk20cmqujlk6mas4gwdqhs6e8a6vjtr"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1upeulemvk20cmqujlk6mas4gwdqhs6e8a6vjtr"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1upeulemvk20cmqujlk6mas4gwdqhs6e8wq7gvk"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1upeulemvk20cmqujlk6mas4gwdqhs6e8wq7gvk"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1upeulemvk20cmqujlk6mas4gwdqhs6e8wq7gvk"
    );
    assert_eq!(
        random_key.eth_address,
        "0xc3227327AbBa51017463868C3927EE2a8248cF51"
    );

    let random_key =
        Key::from_private_key("PrivateKey-85SNqwYiMTzaNMgJ9pKKkMHv9abL8G9qrtNzLzRGSo3dkP9yE")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "10116daa3ffc9e7ae2022cb51fb7f6d6dc5267a97b167185c9cfe2d994f5c56b"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "FbXSaYGEDuSqTCxSasWLhPeduNaMLwCVy"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax15qv4pp07zlqnjxkr2uufx92uc6jrccag38ztld"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax15qv4pp07zlqnjxkr2uufx92uc6jrccag38ztld"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax15qv4pp07zlqnjxkr2uufx92uc6jrccag38ztld"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom15qv4pp07zlqnjxkr2uufx92uc6jrccagzas3cc"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom15qv4pp07zlqnjxkr2uufx92uc6jrccagzas3cc"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom15qv4pp07zlqnjxkr2uufx92uc6jrccagzas3cc"
    );
    assert_eq!(
        random_key.eth_address,
        "0x687aF4572B3A49E9853D0ae71eaF1ddFE7b4CBbF"
    );

    let random_key =
        Key::from_private_key("PrivateKey-kFMUxLFyNagSBxL6Gyx8UrxMD4SdPKNPtkR6Nof1u3tuJ4tDv")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "6232dbcd903ccc481cbf25857b0730f1d1acfb90a2b9e2dbe1f36850545ac441"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "BihdeRASbrbf9BH679tZZTe8SiVBV18EX"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1wk2r4c28zlgrtnfav03wzqx4ghvysj6rssytfc"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1wk2r4c28zlgrtnfav03wzqx4ghvysj6rssytfc"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1wk2r4c28zlgrtnfav03wzqx4ghvysj6rssytfc"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1wk2r4c28zlgrtnfav03wzqx4ghvysj6rr2k3wd"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1wk2r4c28zlgrtnfav03wzqx4ghvysj6rr2k3wd"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1wk2r4c28zlgrtnfav03wzqx4ghvysj6rr2k3wd"
    );
    assert_eq!(
        random_key.eth_address,
        "0x56d09F3E92Be640b211C5b9B86ee3eAdCD489CE5"
    );

    let random_key =
        Key::from_private_key("PrivateKey-cHuK2MmeHFDqYyb5SWh6xZ14zLoSj2Br2EoaL5DtC1NDP7CAm")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "50222b0286da82d163711ee2694e8e46a04ee4383c64cb514e4b2f4821f45cff"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "KRu9gTeCfrWopLy4tRHYW8fMskfpLSs2U"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1egnu0ra99npw35dwnr7zp59dzzd58wyxq5rtdf"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1egnu0ra99npw35dwnr7zp59dzzd58wyxq5rtdf"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1egnu0ra99npw35dwnr7zp59dzzd58wyxq5rtdf"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1egnu0ra99npw35dwnr7zp59dzzd58wyxnw332u"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1egnu0ra99npw35dwnr7zp59dzzd58wyxnw332u"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1egnu0ra99npw35dwnr7zp59dzzd58wyxnw332u"
    );
    assert_eq!(
        random_key.eth_address,
        "0x3050EF785c8904E7845F066e98CdD628Cc68f6E9"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2GrEehWjxhniGbsU8SZ5iMufpsbrNTMjQETK6eqi7TUcLWvzaE")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "a7aed4607b3fe09d5e16dca270aa1f064d06f3e74b07986429015abdc45775c3"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "9eDGn8JMHz8MM6QJQmrQ6Uf9bFjo57nMy"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1tm92gxhy73j3w685tg4a3p6syt9swv82a55kfm"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1tm92gxhy73j3w685tg4a3p6syt9swv82a55kfm"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1tm92gxhy73j3w685tg4a3p6syt9swv82a55kfm"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1tm92gxhy73j3w685tg4a3p6syt9swv82wwxvww"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1tm92gxhy73j3w685tg4a3p6syt9swv82wwxvww"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1tm92gxhy73j3w685tg4a3p6syt9swv82wwxvww"
    );
    assert_eq!(
        random_key.eth_address,
        "0x7bC6130728791EF93f13e98932fd9d208a397136"
    );

    let random_key =
        Key::from_private_key("PrivateKey-cfMoaiqCXauTGmi4Tbwrq9kRcHfmiS3fqBRYu6vxDpBxoc8cW")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "50f9357cc1f1ad6b5922ea45df3dce43275751420c8e6b17aa80e0b4ddfcf4c7"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "CLaqpS1Xd3xL1QZHb1jpCfkPjKqsBC9A6"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax103wcjkxal3835dw0mlq0qs290as7q5vaz85xte"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax103wcjkxal3835dw0mlq0qs290as7q5vaz85xte"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax103wcjkxal3835dw0mlq0qs290as7q5vaz85xte"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom103wcjkxal3835dw0mlq0qs290as7q5va3axuvv"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom103wcjkxal3835dw0mlq0qs290as7q5va3axuvv"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom103wcjkxal3835dw0mlq0qs290as7q5va3axuvv"
    );
    assert_eq!(
        random_key.eth_address,
        "0xB2B91960A07fD07Ce5Ddd8d703fC530F7821D843"
    );

    let random_key =
        Key::from_private_key("PrivateKey-geaod8DmFdjKpXzVcyXtZ61aoa4xxTygf7qruufFhSvNnc6Z1")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "5a068cf3af83165a17171bce24294354e997de5e07a076e8e1cf151637a74297"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "8tSdLgxcnZhJ6bjtGEkLz5iymSuhkstbY"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax126phezer246ffl9gdp3vzdns2aplw94uz464zp"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax126phezer246ffl9gdp3vzdns2aplw94uz464zp"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax126phezer246ffl9gdp3vzdns2aplw94uz464zp"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom126phezer246ffl9gdp3vzdns2aplw94u30g095"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom126phezer246ffl9gdp3vzdns2aplw94u30g095"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom126phezer246ffl9gdp3vzdns2aplw94u30g095"
    );
    assert_eq!(
        random_key.eth_address,
        "0x86f65D20C03Af8798Abeabb480c735b0DB0b0F87"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2C1set4amHqBTFJbfBvC2NdCWmeQiR1mpwT9x9CfD9hanr1TQF")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "9cb50683d048c5c77ae6bd4710e03fbf54e84426eb3e51d2a55c6aff98863245"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "JHs18HveD7UtNsrgztvhzLhm13gYK8yMh"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1hk4g3r3u49y47lhrsclflfh7te8kcuxf8xfq47"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1hk4g3r3u49y47lhrsclflfh7te8kcuxf8xfq47"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1hk4g3r3u49y47lhrsclflfh7te8kcuxf8xfq47"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1hk4g3r3u49y47lhrsclflfh7te8kcuxf5um6jt"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1hk4g3r3u49y47lhrsclflfh7te8kcuxf5um6jt"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1hk4g3r3u49y47lhrsclflfh7te8kcuxf5um6jt"
    );
    assert_eq!(
        random_key.eth_address,
        "0x1A660C1010d0f02206784B37693245f282563128"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2o8tErrYbxCYvfCh1pY6XYmxreppnrkTM6aGwzuaQTAgNVz8ct")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "ec740ea3a0cd92192565f88523a996b52121002ba982698d0671af7e40bacdbd"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "La9JUXfkw22m2YXotqmeji1Pv4DMQu3om"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax166hsh5up22hn5q4n9fp5pkp9mqagktetdc475z"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax166hsh5up22hn5q4n9fp5pkp9mqagktetdc475z"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax166hsh5up22hn5q4n9fp5pkp9mqagktetdc475z"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom166hsh5up22hn5q4n9fp5pkp9mqagktet7z8ynh"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom166hsh5up22hn5q4n9fp5pkp9mqagktet7z8ynh"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom166hsh5up22hn5q4n9fp5pkp9mqagktet7z8ynh"
    );
    assert_eq!(
        random_key.eth_address,
        "0xee08E740C974475936562df5189d82049b3a3813"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2wcVsSwLnTb8NYhYqvMUVWKQv9BtZKVW2uWFZzzpx6AmRDFgXG")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "ffb30b47a3dbc705d098d3c4b4d1dc6b10cd970a084bdbc99200fba97c8f57ff"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "55Xow8gQeKEwe8yupbz34MnQttWb3q9h7"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax19ja7989dgt76cp8sguwenl3urxs7vcal2sgle2"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax19ja7989dgt76cp8sguwenl3urxs7vcal2sgle2"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax19ja7989dgt76cp8sguwenl3urxs7vcal2sgle2"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom19ja7989dgt76cp8sguwenl3urxs7vcale2697l"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom19ja7989dgt76cp8sguwenl3urxs7vcale2697l"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom19ja7989dgt76cp8sguwenl3urxs7vcale2697l"
    );
    assert_eq!(
        random_key.eth_address,
        "0x65505c554F316186691375b59D7E5d70A533620E"
    );

    let random_key =
        Key::from_private_key("PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "8c2bae69b0e1f6f3a5e784504ee93279226f997c5a6771b9bd6b881a8fee1e9d"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "Q4MzFZZDPHRPAHFeDs3NiyyaZDvxHKivf"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1lnk637g0edwnqc2tn8tel39652fswa3xmgyghf"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1lnk637g0edwnqc2tn8tel39652fswa3xmgyghf"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1lnk637g0edwnqc2tn8tel39652fswa3xmgyghf"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1lnk637g0edwnqc2tn8tel39652fswa3xgjkjsu"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1lnk637g0edwnqc2tn8tel39652fswa3xgjkjsu"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1lnk637g0edwnqc2tn8tel39652fswa3xgjkjsu"
    );
    assert_eq!(
        random_key.eth_address,
        "0x99b9DEA54C48Dfea6aA9A4Ca4623633EE04ddbB5"
    );

    let random_key =
        Key::from_private_key("PrivateKey-2MMvUMsxx6zsHSNXJdFD8yc5XkancvwyKPwpw4xUK3TCGDuNBY")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "b1ed77ad48555d49f03a7465f0685a7d86bfd5f3a3ccf1be01971ea8dec5471c"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "B6D4v1VtPYLbiUvYXtW4Px8oE9imC2vGW"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1d6kkj0qh4wcmus3tk59npwt3rluc6en78w0wqa"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1d6kkj0qh4wcmus3tk59npwt3rluc6en78w0wqa"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1d6kkj0qh4wcmus3tk59npwt3rluc6en78w0wqa"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1d6kkj0qh4wcmus3tk59npwt3rluc6en755a58g"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1d6kkj0qh4wcmus3tk59npwt3rluc6en755a58g"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1d6kkj0qh4wcmus3tk59npwt3rluc6en755a58g"
    );
    assert_eq!(
        random_key.eth_address,
        "0x7464A61A3CBD2D6bD6a367D3243029F3638246CE"
    );

    let random_key =
        Key::from_private_key("PrivateKey-cxb7KpGWhDMALTjNNSJ7UQkkomPesyWAPUaWRGdyeBNzR6f35")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "51a5e21237263396a5dfce60496d0ca3829d23fd33c38e6d13ae53b4810df9ca"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "P5wdRuZeaDt28eHMP5S3w9ZdoBfo7wuzF"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax17fpqs358de5lgu7a5ftpw2t8axf0pm33g6kyqx"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax17fpqs358de5lgu7a5ftpw2t8axf0pm33g6kyqx"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax17fpqs358de5lgu7a5ftpw2t8axf0pm33g6kyqx"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom17fpqs358de5lgu7a5ftpw2t8axf0pm33mqy78n"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom17fpqs358de5lgu7a5ftpw2t8axf0pm33mqy78n"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom17fpqs358de5lgu7a5ftpw2t8axf0pm33mqy78n"
    );
    assert_eq!(
        random_key.eth_address,
        "0x2bf91d42766c80Cb56fF482031b247EeC3792cCd"
    );

    let random_key =
        Key::from_private_key("PrivateKey-CrRUUNvaKMeVPLiBi3CtiRFUmhxiNyoxHDSXn49kHpwamVa33")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "1ae961d78f0aa9cff24b05a6f0c29e819657a70185f1d45c0925729d369434b4"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "EFrUyQGU9ha4ffGK8eKZQCGmNvvRbe589"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1j95v8t4d7w2zetq6pcve0734tlyk9sv90dl0xq"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1j95v8t4d7w2zetq6pcve0734tlyk9sv90dl0xq"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1j95v8t4d7w2zetq6pcve0734tlyk9sv90dl0xq"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1j95v8t4d7w2zetq6pcve0734tlyk9sv9uhd4p4"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1j95v8t4d7w2zetq6pcve0734tlyk9sv9uhd4p4"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1j95v8t4d7w2zetq6pcve0734tlyk9sv9uhd4p4"
    );
    assert_eq!(
        random_key.eth_address,
        "0x4c25b4981bbA2E3b0b69d4d4996E187bd19642f3"
    );

    let random_key =
        Key::from_private_key("PrivateKey-293XmTLSSwGHAWc28dj6ueRzuVPgmTrWtDRM52sgHHVZET22vP")
            .unwrap();
    assert_eq!(
        random_key.private_key_hex.clone(),
        "95f5cb99b2c1b642fcd3e0aed7f3e052611b653cea1ea37502433b64d31f0413"
    );
    assert_eq!(
        random_key,
        Key::from_private_key_eth(&random_key.private_key_hex.clone()).unwrap(),
    );
    assert_eq!(
        random_key.short_address.clone(),
        "ER4mQAk2wJHWyyB6DKBE7fCY6qduoxPw1"
    );
    assert_eq!(
        random_key.address("X", 1).unwrap(),
        "X-avax1jvnv9av3ul5v9l6kjfntntaw8dquy0yaudp2rz"
    );
    assert_eq!(
        random_key.address("P", 1).unwrap(),
        "P-avax1jvnv9av3ul5v9l6kjfntntaw8dquy0yaudp2rz"
    );
    assert_eq!(
        random_key.address("C", 1).unwrap(),
        "C-avax1jvnv9av3ul5v9l6kjfntntaw8dquy0yaudp2rz"
    );
    assert_eq!(
        random_key.address("X", 9999).unwrap(),
        "X-custom1jvnv9av3ul5v9l6kjfntntaw8dquy0ya0hnsyh"
    );
    assert_eq!(
        random_key.address("P", 9999).unwrap(),
        "P-custom1jvnv9av3ul5v9l6kjfntntaw8dquy0ya0hnsyh"
    );
    assert_eq!(
        random_key.address("C", 9999).unwrap(),
        "C-custom1jvnv9av3ul5v9l6kjfntntaw8dquy0ya0hnsyh"
    );
    assert_eq!(
        random_key.eth_address,
        "0xcCBC5eefcf31684BC474c59D0F9Ba26af5174D99"
    );
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PrivateKeyInfo {
    /// CB58-encoded private key with the prefix "PrivateKey-".
    pub private_key: String,
    pub private_key_hex: String,
    pub x_address: String,
    pub p_address: String,
    pub c_address: String,
    pub short_address: String,
    pub eth_address: String,
}

impl PrivateKeyInfo {
    /// Converts to string.
    pub fn to_string(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize PrivateKeyInfo to YAML {}", e),
                ));
            }
        }
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading PrivateKeyInfo from {}", file_path);

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

    pub fn sync(&self, file_path: String) -> io::Result<()> {
        info!("syncing key info to '{}'", file_path);
        let path = Path::new(&file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(&self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize key info to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(&file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain
/// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.8/wallet/chain/p/builder.go
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Keychain {
    pub key: Key,
}

impl Keychain {
    pub fn new(key: Key) -> Self {
        Self { key }
    }
}
