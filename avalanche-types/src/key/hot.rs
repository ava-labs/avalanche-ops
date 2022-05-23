use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    str::{self, FromStr},
    string::String,
};

use lazy_static::lazy_static;
use log::info;
use rust_embed::RustEmbed;
use secp256k1::{self, rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{
    constants, formatting, ids,
    key::{self, address},
};
use avalanche_utils::cmp;

lazy_static! {
    pub static ref TEST_KEYS: Vec<Key> = {
        #[derive(RustEmbed)]
        #[folder = "artifacts/"]
        #[prefix = "artifacts/"]
        struct Asset;

        let key_file =
            Asset::get("artifacts/test.insecure.secp256k1.key.infos.no.mnemonic.json").unwrap();
        let key_file_data = key_file.data;
        let key_infos: Vec<PrivateKeyInfoEntry> = serde_json::from_slice(&key_file_data).unwrap();

        let mut keys: Vec<Key> = Vec::new();
        for ki in key_infos.iter() {
            let k = Key::from_private_key(ki.private_key.clone()).unwrap();
            keys.push(k);
        }
        keys
    };
}

/// Loads keys from texts, assuming each key is line-separated.
pub fn load_encoded_keys(d: &[u8]) -> io::Result<Vec<Key>> {
    let text = match str::from_utf8(d) {
        Ok(s) => s,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to convert str from_utf8 {}", e),
            ));
        }
    };

    let mut lines = text.lines();
    let mut line_cnt = 1;

    let mut keys: Vec<Key> = Vec::new();
    let mut added = HashMap::new();
    loop {
        if let Some(s) = lines.next() {
            if added.get(s).is_some() {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("key at line {} already added before", line_cnt),
                ));
            }

            keys.push(Key::from_private_key(s).unwrap());

            added.insert(s, true);
            line_cnt += 1;
            continue;
        }
        break;
    }
    Ok(keys)
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- hot::test_load_test_keys --exact --show-output
#[test]
fn test_load_test_keys() {
    let _ = env_logger::builder().is_test(true).try_init();
    for k in TEST_KEYS.iter() {
        info!("test key eth address {:?}", k.eth_address);
    }
    info!("total {} test keys are found", TEST_KEYS.len());
}

/// ref. https://doc.rust-lang.org/book/ch10-02-traits.html
impl key::ReadOnly for Key {
    fn get_address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String> {
        self.address(chain_id_alias, network_id)
    }

    fn get_short_address(&self) -> ids::ShortId {
        self.short_address.clone()
    }

    fn get_eth_address(&self) -> String {
        self.eth_address.clone()
    }
}

/// ref. https://doc.rust-lang.org/std/str/trait.FromStr.html
impl FromStr for Key {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_private_key(s)
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Key {
    #[serde(skip_serializing, skip_deserializing)]
    pub secret_key: Option<SecretKey>,
    #[serde(skip_serializing, skip_deserializing)]
    pub public_key: Option<PublicKey>,

    /// Mnemonic phrase (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_phrase: Option<String>,

    /// AVAX wallet compatible private key.
    /// NEVER save mainnet-funded wallet keys here.
    pub private_key: String,
    /// Used for importing keys in MetaMask and subnet-cli.
    /// ref. https://github.com/ava-labs/subnet-cli/blob/5b69345a3fba534fb6969002f41c8d3e69026fed/internal/key/key.go#L238-L258
    /// NEVER save mainnet-funded wallet keys here.
    pub private_key_hex: String,

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
    #[serde(deserialize_with = "ids::must_deserialize_short_id")]
    pub short_address: ids::ShortId,

    /// ref. https://pkg.go.dev/github.com/ethereum/go-ethereum/common#Address
    pub eth_address: String,
}

pub const PRIVATE_KEY_ENCODE_PREFIX: &str = "PrivateKey-";

impl Key {
    /// Generates a new Secp256k1 key.
    pub fn generate() -> io::Result<Self> {
        info!("generating secp256k1 key");

        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);

        let short_address = address::to_short(&public_key)?;
        let eth_address = address::to_eth(&public_key)?;

        // ref. https://github.com/rust-bitcoin/rust-secp256k1/pull/396
        let priv_bytes = secret_key.secret_bytes();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        private_key.push_str(&enc);
        let private_key_hex = hex::encode(&priv_bytes);

        Ok(Self {
            mnemonic_phrase: None,
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
    pub fn from_private_key<S>(encoded_priv_key: S) -> io::Result<Self>
    where
        S: Into<String>,
    {
        let raw = encoded_priv_key
            .into()
            .replace(PRIVATE_KEY_ENCODE_PREFIX, "");

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

        let short_address = address::to_short(&public_key)?;
        let eth_address = address::to_eth(&public_key)?;

        // ref. https://github.com/rust-bitcoin/rust-secp256k1/pull/396
        let priv_bytes = secret_key.secret_bytes();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        private_key.push_str(&enc);
        let private_key_hex = hex::encode(&priv_bytes);

        Ok(Self {
            mnemonic_phrase: None,
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
    pub fn from_private_key_raw<S>(raw: S) -> io::Result<Self>
    where
        S: AsRef<[u8]>,
    {
        let pfx = PRIVATE_KEY_ENCODE_PREFIX.as_bytes();
        let pos = {
            if cmp::eq_vectors(pfx, &raw.as_ref()[0..pfx.len()]) {
                pfx.len()
            } else {
                0
            }
        };

        if raw.as_ref()[pos..].len() != secp256k1::constants::SECRET_KEY_SIZE {
            let encoded_priv_key =
                String::from_utf8(raw.as_ref()[pos..].to_vec()).map_err(|e| {
                    return Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "failed convert {}-byte to string ({})",
                            raw.as_ref()[pos..].len(),
                            e
                        ),
                    );
                })?;
            return Self::from_private_key(&encoded_priv_key);
        }

        let secret_key = match SecretKey::from_slice(&raw.as_ref()[pos..]) {
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

        let short_address = address::to_short(&public_key)?;
        let eth_address = address::to_eth(&public_key)?;

        // ref. https://github.com/rust-bitcoin/rust-secp256k1/pull/396
        let priv_bytes = secret_key.secret_bytes();
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        let mut private_key = String::from(PRIVATE_KEY_ENCODE_PREFIX);
        private_key.push_str(&enc);
        let private_key_hex = hex::encode(&priv_bytes);

        Ok(Self {
            mnemonic_phrase: None,
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
    pub fn from_private_key_eth<S>(encoded_priv_key: S) -> io::Result<Self>
    where
        S: AsRef<[u8]>,
    {
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
                    "unexpected secret key size {} (expected {})",
                    priv_bytes.len(),
                    secp256k1::constants::SECRET_KEY_SIZE
                ),
            ));
        }
        let enc = formatting::encode_cb58_with_checksum(&priv_bytes);
        Self::from_private_key(&enc)
    }

    pub fn address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String> {
        let hrp = match constants::NETWORK_ID_TO_HRP.get(&network_id) {
            Some(v) => v,
            None => constants::FALLBACK_HRP,
        };
        // ref. "pk.PublicKey().Address().Bytes()"
        let short_address_bytes =
            address::to_short_bytes(&self.public_key.expect("unexpected empty public_key"))?;

        // ref. "formatting.FormatAddress(chainIDAlias, hrp, pubBytes)"
        formatting::address(chain_id_alias, hrp, &short_address_bytes)
    }

    pub fn short_address_bytes(&self) -> io::Result<Vec<u8>> {
        address::to_short_bytes(&self.public_key.expect("unexpected empty public_key"))
    }

    pub fn private_key_info_entry(&self, network_id: u32) -> io::Result<PrivateKeyInfoEntry> {
        let x_address = self.address("X", network_id)?;
        let p_address = self.address("P", network_id)?;
        let c_address = self.address("C", network_id)?;
        let mut addresses: HashMap<String, key::NetworkAddressEntry> = HashMap::new();
        addresses.insert(
            format!("{}", network_id),
            key::NetworkAddressEntry {
                x_address,
                p_address,
                c_address,
            },
        );
        Ok(PrivateKeyInfoEntry {
            mnemonic_phrase: self.mnemonic_phrase.clone(),
            private_key: self.private_key.clone(),
            private_key_hex: self.private_key_hex.clone(),
            addresses,
            short_address: self.short_address.clone(),
            eth_address: self.eth_address.clone(),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- hot::test_soft_key --exact --show-output
#[test]
fn test_soft_key() {
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

    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let test_keys_file =
        Asset::get("artifacts/test.insecure.secp256k1.key.infos.no.mnemonic.json").unwrap();
    let test_keys_file_contents = std::str::from_utf8(test_keys_file.data.as_ref()).unwrap();
    let key_infos: Vec<PrivateKeyInfoEntry> =
        serde_json::from_slice(&test_keys_file_contents.as_bytes()).unwrap();

    for (pos, ki) in key_infos.iter().enumerate() {
        info!("checking the key info at {}", pos);

        let k = Key::from_private_key(&ki.private_key).unwrap();
        assert_eq!(
            k,
            Key::from_private_key_eth(&k.private_key_hex.clone()).unwrap(),
        );
        assert_eq!(
            k,
            Key::from_private_key_raw(&k.private_key.as_bytes()).unwrap(),
        );

        assert_eq!(k.private_key_hex.clone(), ki.private_key_hex);

        assert_eq!(
            k.address("X", 1).unwrap(),
            ki.addresses.get("1").unwrap().x_address
        );
        assert_eq!(
            k.address("P", 1).unwrap(),
            ki.addresses.get("1").unwrap().p_address
        );
        assert_eq!(
            k.address("C", 1).unwrap(),
            ki.addresses.get("1").unwrap().c_address
        );

        assert_eq!(
            k.address("X", 9999).unwrap(),
            ki.addresses.get("9999").unwrap().x_address
        );
        assert_eq!(
            k.address("P", 9999).unwrap(),
            ki.addresses.get("9999").unwrap().p_address
        );
        assert_eq!(
            k.address("C", 9999).unwrap(),
            ki.addresses.get("9999").unwrap().c_address
        );

        assert_eq!(k.short_address, ki.short_address);
        assert_eq!(k.eth_address, ki.eth_address);
    }
}

// test random keys generated by "avalanchego/utils/crypto.FactorySECP256K1R"
// and make sure both generate the same addresses
// use "avalanche-ops/avalanchego-compatibility/key/main.go"
// to generate keys and addresses with "avalanchego"
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PrivateKeyInfoEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_phrase: Option<String>,

    /// CB58-encoded private key with the prefix "PrivateKey-".
    pub private_key: String,
    pub private_key_hex: String,

    pub addresses: HashMap<String, key::NetworkAddressEntry>,

    #[serde(deserialize_with = "ids::must_deserialize_short_id")]
    pub short_address: ids::ShortId,
    pub eth_address: String,
}

impl PrivateKeyInfoEntry {
    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading PrivateKeyInfoEntry from {}", file_path);

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

/// ref. https://doc.rust-lang.org/std/string/trait.ToString.html
/// ref. https://doc.rust-lang.org/std/fmt/trait.Display.html
/// Use "Self.to_string()" to directly invoke this
impl fmt::Display for PrivateKeyInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_yaml::to_string(&self).unwrap();
        write!(f, "{}", s)
    }
}
