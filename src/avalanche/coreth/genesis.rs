use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use crate::utils::big_int;

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#Genesis
/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/params#ChainConfig
/// ref. https://github.com/ava-labs/avalanchego/tree/dev/genesis
/// ref. https://github.com/ava-labs/avalanche-network-runner/blob/main/local/default/genesis.json
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ChainConfig>,

    #[serde(with = "big_int::serde_hex_format")]
    pub nonce: BigInt,
    #[serde(with = "big_int::serde_hex_format")]
    pub timestamp: BigInt,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<String>,

    #[serde(with = "big_int::serde_hex_format")]
    pub gas_limit: BigInt,
    #[serde(with = "big_int::serde_hex_format")]
    pub difficulty: BigInt,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<String>,

    /// MUST BE ordered by its key in order for all nodes to have the same JSON outputs.
    /// ref. https://doc.rust-lang.org/std/collections/index.html#use-a-btreemap-when
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc: Option<BTreeMap<String, AllocAccount>>,

    #[serde(with = "big_int::serde_hex_format")]
    pub number: BigInt,
    #[serde(with = "big_int::serde_hex_format")]
    pub gas_used: BigInt,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    #[serde(rename = "baseFeePerGas", skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<String>,
}

/// On the X-Chain, one AVAX is 10^9  units.
/// On the P-Chain, one AVAX is 10^9  units.
/// On the C-Chain, one AVAX is 10^18 units.
/// "0x52B7D2DCC80CD2E4000000" is "100000000000000000000000000" (100,000,000 AVAX).
/// ref. https://www.rapidtables.com/convert/number/hex-to-decimal.html
pub const DEFAULT_INITIAL_AMOUNT: &str = "0x52B7D2DCC80CD2E4000000";

impl Default for Genesis {
    fn default() -> Self {
        Self::default()
    }
}

impl Genesis {
    pub fn default() -> Self {
        let mut alloc = BTreeMap::new();
        alloc.insert(
            // ref. https://github.com/ava-labs/coreth/blob/v0.8.6/params/config.go#L95-L114
            // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.6/genesis/genesis_local.go#L106
            String::from("8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"),
            AllocAccount::default(),
        );
        Self {
            config: Some(ChainConfig::default()),
            nonce: BigInt::default(),
            timestamp: BigInt::default(),
            extra_data: Some(String::from("0x00")),

            gas_limit: big_int::from_hex("0x5f5e100").expect("failed to parse big_int"),

            difficulty: BigInt::default(),
            mix_hash: Some(String::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )),
            coinbase: Some(String::from("0x0000000000000000000000000000000000000000")),
            alloc: Some(alloc),
            number: BigInt::default(),
            gas_used: BigInt::default(),
            parent_hash: Some(String::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )),
            base_fee: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to JSON {}", e),
                ));
            }
        }
    }

    /// Saves the current anchor node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Genesis to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Genesis to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/params#ChainConfig
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub homestead_block: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dao_fork_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dao_fork_support: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip150_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip150_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip155_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip158_block: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub byzantium_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constantinople_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub petersburg_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub istanbul_block: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muir_glacier_block: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub apricot_phase1_block_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apricot_phase2_block_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apricot_phase3_block_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apricot_phase4_block_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apricot_phase5_block_timestamp: Option<u64>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::default()
    }
}

impl ChainConfig {
    pub fn default() -> Self {
        Self {
            // don't use local ID "43112" to avoid config override
            // ref. https://github.com/ava-labs/coreth/blob/v0.8.6/plugin/evm/vm.go#L326-L328
            // ref. https://github.com/ava-labs/avalanche-ops/issues/8
            chain_id: Some(1000777),
            homestead_block: Some(0),

            dao_fork_block: Some(0),
            dao_fork_support: Some(true),

            eip150_block: Some(0),
            eip150_hash: Some(String::from(
                "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
            )),

            eip155_block: Some(0),
            eip158_block: Some(0),

            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            muir_glacier_block: Some(0),

            apricot_phase1_block_timestamp: Some(0),
            apricot_phase2_block_timestamp: Some(0),
            apricot_phase3_block_timestamp: None,
            apricot_phase4_block_timestamp: None,
            apricot_phase5_block_timestamp: None,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisAlloc
/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisAccount
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AllocAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<BTreeMap<String, String>>,

    #[serde(with = "big_int::serde_hex_format")]
    pub balance: BigInt,

    /// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisMultiCoinBalance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcbalance: Option<BTreeMap<String, u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
}

impl Default for AllocAccount {
    fn default() -> Self {
        Self::default()
    }
}

impl AllocAccount {
    pub fn default() -> Self {
        Self {
            code: None,
            storage: None,
            balance: big_int::from_hex(DEFAULT_INITIAL_AMOUNT).expect("failed to parse big_int"),
            mcbalance: None,
            nonce: None,
        }
    }
}

#[test]
fn test_parse() {
    let _ = env_logger::builder().is_test(true).try_init();

    // ref. https://github.com/ava-labs/avalanche-network-runner/blob/main/local/default/genesis.json
    let resp: Genesis = serde_json::from_str(
        r#"
{
        "config": {
            "chainId": 1000777,
            "homesteadBlock": 0,
            "daoForkBlock": 0,
            "daoForkSupport": true,
            "eip150Block": 0,
            "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "muirGlacierBlock": 0,
            "apricotPhase1BlockTimestamp": 0,
            "apricotPhase2BlockTimestamp": 0
        },
        "nonce": "0x0",
        "timestamp": "0x0",
        "extraData": "0x00",
        "gasLimit": "0x5f5e100",
        "difficulty": "0x0",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {
            "8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC": {
                "balance": "0x52B7D2DCC80CD2E4000000"
            }
        },
        "number": "0x0",
        "gasUsed": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
"#,
    )
    .unwrap();

    let expected = Genesis::default();
    assert_eq!(resp, expected);

    let d = Genesis::default();
    let d = d.encode_json().unwrap();
    info!("{}", d);
}
