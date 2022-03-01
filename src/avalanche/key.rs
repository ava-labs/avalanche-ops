use std::{
    fs::File,
    io::{self, Error, ErrorKind},
    path::Path,
    string::String,
};

use bitcoin::hashes::hex::ToHex;
use ethereum_types::{Address, H256};
use log::info;
use ring::digest::{digest, SHA256};
use ripemd::{Digest, Ripemd160};
use secp256k1::{self, rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::Keccak256;

use crate::avalanche::{constants, formatting};

pub const PRIVATE_KEY_ENCODE_PREFIX: &str = "PrivateKey-";
pub const EWOQ_KEY: &str = "PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN";

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Key {
    #[serde(skip_serializing, skip_deserializing)]
    pub secret_key: Option<SecretKey>,
    #[serde(skip_serializing, skip_deserializing)]
    pub public_key: Option<PublicKey>,

    pub encoded_private_key: String,
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

        let priv_bytes = secret_key.serialize_secret();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut encoded_private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        encoded_private_key.push_str(&enc);

        Ok(Self {
            secret_key: Some(secret_key),
            public_key: Some(public_key),
            encoded_private_key,
            short_address,
            eth_address,
        })
    }

    /// Loads the specified Secp256k1 key with CB58 encoding.
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

        let priv_bytes = secret_key.serialize_secret();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut encoded_private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        encoded_private_key.push_str(&enc);
        Ok(Self {
            secret_key: Some(secret_key),
            public_key: Some(public_key),
            encoded_private_key,
            short_address,
            eth_address,
        })
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
        let short_address_bytes = public_key_to_short_address_bytes(&self.public_key.unwrap())?;

        // ref. "formatting.FormatAddress(chainIDAlias, hrp, pubBytes)"
        formatting::address(chain_id_alias, hrp, &short_address_bytes)
    }

    pub fn to_info(&self, network_id: u32) -> io::Result<PrivateKeyInfo> {
        let x = self.address("X", network_id)?;
        let p = self.address("P", network_id)?;
        let c = self.address("C", network_id)?;
        Ok(PrivateKeyInfo {
            private_key: self.encoded_private_key.clone(),
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
pub fn public_key_to_short_address(public_key: &PublicKey) -> io::Result<String> {
    let public_key_bytes_compressed = public_key.serialize();
    bytes_to_short_address(&public_key_bytes_compressed)
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
fn bytes_to_short_address_bytes(d: &[u8]) -> io::Result<Vec<u8>> {
    let digest_sha256 = compute_sha256(d);

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

fn compute_sha256(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().into()
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
fn public_key_to_short_address_bytes(public_key: &PublicKey) -> io::Result<Vec<u8>> {
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
    Ok(prepend_0x(&addr_eip55))
}

fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(&Keccak256::digest(data.as_ref()))
}

/// ref. https://github.com/Ethereum/EIPs/blob/master/EIPS/eip-55.md
fn eth_checksum(addr: &str) -> String {
    let addr_lower_case = strip_0x(addr).to_lowercase();
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

fn strip_0x(addr: &str) -> &str {
    if &addr[0..2] == "0x" {
        &addr[2..]
    } else {
        addr
    }
}

fn prepend_0x(addr: &str) -> String {
    if &addr[0..2] == "0x" {
        String::from(addr)
    } else {
        format!("0x{}", addr)
    }
}

#[test]
fn test_key() {
    let _ = env_logger::builder().is_test(true).try_init();

    let key1 = Key::generate().unwrap();
    info!("{}", key1.encoded_private_key);
    info!("{}", key1.short_address.clone());
    info!("{}", key1.address("X", 9999).unwrap());

    let key2 = Key::from_private_key(&key1.encoded_private_key).unwrap();
    info!("{}", key2.encoded_private_key);
    info!("{}", key2.short_address.clone());
    info!("{}", key2.address("X", 9999).unwrap());

    assert_eq!(key1.encoded_private_key, key2.encoded_private_key);
    assert_eq!(key1.short_address.clone(), key2.short_address.clone());
    assert_eq!(
        key1.address("X", 9999).unwrap(),
        key2.address("X", 9999).unwrap()
    );

    let ewoq_key = Key::from_private_key(&EWOQ_KEY).unwrap();
    info!("{}", ewoq_key.encoded_private_key);
    assert_eq!(
        ewoq_key.short_address.clone(),
        "6Y3kysjF9jnHnYkdS9yGAuoHyae2eNmeV"
    );
    assert_eq!(
        ewoq_key.address("X", 1).unwrap(),
        "X-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        ewoq_key.address("P", 1).unwrap(),
        "P-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        ewoq_key.address("C", 1).unwrap(),
        "C-avax18jma8ppw3nhx5r4ap8clazz0dps7rv5ukulre5"
    );
    assert_eq!(
        ewoq_key.address("X", 9999).unwrap(),
        "X-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        ewoq_key.address("P", 9999).unwrap(),
        "P-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        ewoq_key.address("C", 9999).unwrap(),
        "C-custom18jma8ppw3nhx5r4ap8clazz0dps7rv5u9xde7p"
    );
    assert_eq!(
        ewoq_key.eth_address,
        "0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"
    );

    // test random keys generated by "avalanchego/utils/crypto.FactorySECP256K1R"
    // and make sure both generate the same addresses
    // use "avalanche-ops/avalanchego-compatibility/key/main.go"
    // to generate keys and addresses with "avalanchego"
    let random_key =
        Key::from_private_key("PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67")
            .unwrap();
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
    info!("{}", random_key.encoded_private_key);
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
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PrivateKeyInfo {
    /// CB58-encoded private key with the prefix "PrivateKey-".
    pub private_key: String,
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
}
