use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    str::{self, FromStr},
    string::String,
};

use bip32::{DerivationPath, Language, Mnemonic, XPrv};
use bitcoin::hashes::hex::ToHex;
use ethereum_types::{Address, H256};
use lazy_static::lazy_static;
use log::info;
use ripemd::{Digest, Ripemd160};
use rust_embed::RustEmbed;
use secp256k1::{self, rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::Keccak256;

use crate::{constants, formatting, ids, secp256k1fx};
use utils::{cmp, hash, prefix};

pub const PRIVATE_KEY_ENCODE_PREFIX: &str = "PrivateKey-";

lazy_static! {
    pub static ref TEST_KEYS: Vec<Key> = {
        #[derive(RustEmbed)]
        #[folder = "artifacts/"]
        #[prefix = "artifacts/"]
        struct Asset;

        let key_file = Asset::get("artifacts/test.insecure.secp256k1.key.infos.mnemonic.json").unwrap();
        let key_file_data = key_file.data;
        let  key_infos: Vec<PrivateKeyInfoEntry> =
            serde_json::from_slice(&key_file_data).unwrap();

        let mut keys: Vec<Key> = Vec::new();
        for ki in key_infos.iter() {
            let k = Key::from_mnemonic_phrase(ki.mnemonic_phrase.clone().unwrap()).unwrap();
            keys.push(k);
        }
        keys
    };

    /// ref. https://github.com/ava-labs/avalanche-wallet/blob/v0.3.8/src/js/wallets/MnemonicWallet.ts
    pub static ref AVAX_ACCOUNT_DERIVIATION_PATH: DerivationPath = {
        "m/44'/9000'/0'".parse().unwrap()
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- soft_key::test_load_test_keys --exact --show-output
#[test]
fn test_load_test_keys() {
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
    pub fn from_private_key_raw(raw: &[u8]) -> io::Result<Self> {
        let pfx = PRIVATE_KEY_ENCODE_PREFIX.as_bytes();
        let pos = {
            if cmp::eq_u8_vectors(pfx, &raw[0..pfx.len()]) {
                pfx.len()
            } else {
                0
            }
        };

        if raw[pos..].len() != secp256k1::constants::SECRET_KEY_SIZE {
            let encoded_priv_key = String::from_utf8(raw[pos..].to_vec()).map_err(|e| {
                return Error::new(
                    ErrorKind::InvalidInput,
                    format!("failed convert {}-byte to string ({})", raw[pos..].len(), e),
                );
            })?;
            return Self::from_private_key(&encoded_priv_key);
        }

        let secret_key = match SecretKey::from_slice(&raw[pos..]) {
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

    pub fn from_mnemonic_phrase<S>(phrase: S) -> io::Result<Self>
    where
        S: AsRef<str>,
    {
        let mnemonic = Mnemonic::new(phrase, Language::English).map_err(|e| {
            return Error::new(
                ErrorKind::Other,
                format!("failed to read mnemonic phrase ({})", e),
            );
        })?;
        let seed = mnemonic.to_seed("password");

        // ref. https://github.com/ava-labs/avalanche-wallet/blob/v0.3.8/src/js/wallets/MnemonicWallet.ts
        let child_xprv =
            XPrv::derive_from_path(&seed, &AVAX_ACCOUNT_DERIVIATION_PATH).map_err(|e| {
                return Error::new(
                    ErrorKind::Other,
                    format!("failed to derive AVAX account path ({})", e),
                );
            })?;

        let pk = child_xprv.private_key().to_bytes();

        let mut key = Self::from_private_key_raw(&pk.to_vec())?;
        key.mnemonic_phrase = Some(String::from(mnemonic.phrase()));
        Ok(key)
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
        let x_address = self.address("X", network_id)?;
        let p_address = self.address("P", network_id)?;
        let c_address = self.address("C", network_id)?;
        Ok(PrivateKeyInfo {
            mnemonic_phrase: self.mnemonic_phrase.clone(),
            private_key: self.private_key.clone(),
            private_key_hex: self.private_key_hex.clone(),
            x_address,
            p_address,
            c_address,
            short_address: self.short_address.clone(),
            eth_address: self.eth_address.clone(),
        })
    }

    /// Returns "None" if the output owners are still locked or the threshold is NOT met.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain.Match
    pub fn match_threshold(
        &self,
        output_owners: &secp256k1fx::OutputOwners,
        time: u64,
    ) -> Option<Vec<u32>> {
        if output_owners.locktime > time {
            // output owners are still locked
            return None;
        }

        let mut sig_indices: Vec<u32> = Vec::new();
        for (pos, short_addr) in output_owners.addrs.iter().enumerate() {
            if self.short_address != *short_addr {
                continue;
            }
            sig_indices.push(pos as u32);

            if (sig_indices.len() as u32) == output_owners.threshold {
                break;
            }
        }

        let n = sig_indices.len();
        if (n as u32) == output_owners.threshold {
            Some(sig_indices)
        } else {
            None
        }
    }

    /// Returns "None" if the threshold is NOT met.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain.Spend
    /// TODO: support "secp256k1fx::MintOutput"
    pub fn spend(
        &self,
        output: &secp256k1fx::TransferOutput,
        time: u64,
    ) -> Option<secp256k1fx::TransferInput> {
        let res = self.match_threshold(&output.output_owners, time);
        let threshold_met = res.is_some();
        if !threshold_met {
            return None;
        }

        let sig_indices = res.unwrap();
        Some(secp256k1fx::TransferInput {
            amount: output.amount,
            sig_indices,
        })
    }
}

/// Only supports "English" for now.
/// ref. https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// ref. https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
/// ref. https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
/// ref. https://iancoleman.io/bip39/
pub fn generate_mnemonic_phrase_24_word() -> String {
    let m = Mnemonic::random(&mut rand_core::OsRng, Language::English);
    let s = m.phrase();
    assert_eq!(s.split(' ').count(), 24);
    String::from(s)
}

/// "hashing.PubkeyBytesToAddress"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn bytes_to_short_address(d: &[u8]) -> io::Result<ids::ShortId> {
    let short_address_bytes = bytes_to_short_address_bytes(d)?;

    // "ids.ShortID.String"
    // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/ids#ShortID.String
    let encoded = formatting::encode_cb58_with_checksum(&short_address_bytes);
    ids::ShortId::from_str(&encoded)
}

/// "hashing.PubkeyBytesToAddress"
/// ref. "pk.PublicKey().Address().Bytes()"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
fn public_key_to_short_address(public_key: &PublicKey) -> io::Result<ids::ShortId> {
    let public_key_bytes_compressed = public_key.serialize();
    bytes_to_short_address(&public_key_bytes_compressed)
}

/// "hashing.PubkeyBytesToAddress" and "ids.ToShortID"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/hashing#PubkeyBytesToAddress
pub fn bytes_to_short_address_bytes(d: &[u8]) -> io::Result<Vec<u8>> {
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- soft_key::test_soft_key --exact --show-output
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
        Asset::get("artifacts/test.insecure.secp256k1.key.infos.mnemonic.json").unwrap();
    let test_keys_file_contents = std::str::from_utf8(test_keys_file.data.as_ref()).unwrap();
    let mut key_infos: Vec<PrivateKeyInfoEntry> =
        serde_json::from_slice(&test_keys_file_contents.as_bytes()).unwrap();

    let test_keys_file =
        Asset::get("artifacts/test.insecure.secp256k1.key.infos.no.mnemonic.json").unwrap();
    let test_keys_file_contents = std::str::from_utf8(test_keys_file.data.as_ref()).unwrap();
    let key_infos_no_mnemonic: Vec<PrivateKeyInfoEntry> =
        serde_json::from_slice(&test_keys_file_contents.as_bytes()).unwrap();

    key_infos.extend(key_infos_no_mnemonic);
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

        if ki.mnemonic_phrase.is_some() {
            let mut k2 = k.clone();
            k2.mnemonic_phrase = ki.mnemonic_phrase.clone();
            assert_eq!(
                k2,
                Key::from_mnemonic_phrase(&ki.mnemonic_phrase.clone().unwrap()).unwrap(),
            );
        }

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

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PrivateKeyInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_phrase: Option<String>,

    /// CB58-encoded private key with the prefix "PrivateKey-".
    pub private_key: String,
    pub private_key_hex: String,

    pub x_address: String,
    pub p_address: String,
    pub c_address: String,

    #[serde(deserialize_with = "ids::must_deserialize_short_id")]
    pub short_address: ids::ShortId,
    pub eth_address: String,
}

impl PrivateKeyInfo {
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

/// ref. https://doc.rust-lang.org/std/string/trait.ToString.html
/// ref. https://doc.rust-lang.org/std/fmt/trait.Display.html
/// Use "Self.to_string()" to directly invoke this
impl fmt::Display for PrivateKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_yaml::to_string(&self).unwrap();
        write!(f, "{}", s)
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

    pub private_key: String,
    pub private_key_hex: String,

    pub addresses: HashMap<String, PrivateKeyInfoEntryAddress>,

    #[serde(deserialize_with = "ids::must_deserialize_short_id")]
    pub short_address: ids::ShortId,
    pub eth_address: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PrivateKeyInfoEntryAddress {
    pub x_address: String,
    pub p_address: String,
    pub c_address: String,
}

/// Support multiple keys as a chain.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain
/// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/p/builder.go
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Keychain {
    pub keys: Vec<Key>,
    pub short_addr_to_key_index: HashMap<ids::ShortId, u32>,
}

impl Keychain {
    pub fn new(keys: Vec<Key>) -> Self {
        let mut short_addr_to_key_index = HashMap::new();
        for (pos, k) in keys.iter().enumerate() {
            short_addr_to_key_index.insert(k.short_address.to_owned(), pos as u32);
        }
        Self {
            keys,
            short_addr_to_key_index,
        }
    }

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain.Get
    pub fn get(&self, short_addr: &ids::ShortId) -> Option<Key> {
        self.short_addr_to_key_index
            .get(short_addr)
            .map(|k| self.keys[(*k) as usize].clone())
    }

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain.Match
    pub fn match_threshold(
        &self,
        output_owners: &secp256k1fx::OutputOwners,
        time: u64,
    ) -> Option<(Vec<u32>, Vec<Key>)> {
        if output_owners.locktime > time {
            // output owners are still locked
            return None;
        }

        let mut sig_indices: Vec<u32> = Vec::new();
        let mut keys: Vec<Key> = Vec::new();
        for (pos, addr) in output_owners.addrs.iter().enumerate() {
            let key = self.get(addr);
            if key.is_none() {
                continue;
            }
            sig_indices.push(pos as u32);
            keys.push(key.unwrap());

            if (keys.len() as u32) == output_owners.threshold {
                break;
            }
        }

        let n = keys.len();
        if (n as u32) == output_owners.threshold {
            Some((sig_indices, keys))
        } else {
            None
        }
    }

    /// Returns "None" if the threshold is NOT met.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain.Spend
    /// TODO: support spend on "secp256k1fx::MintOutput"
    pub fn spend(
        &self,
        output: &secp256k1fx::TransferOutput,
        time: u64,
    ) -> Option<(secp256k1fx::TransferInput, Vec<Key>)> {
        let res = self.match_threshold(&output.output_owners, time);
        let threshold_met = res.is_some();
        if !threshold_met {
            return None;
        }

        let (sig_indices, keys) = res.unwrap();
        Some((
            secp256k1fx::TransferInput {
                amount: output.amount,
                sig_indices,
            },
            keys,
        ))
    }
}
