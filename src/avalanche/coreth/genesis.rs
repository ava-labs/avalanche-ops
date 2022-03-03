use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

// TODO: use big.Int
// TODO: pre-allocate funds for generated keys

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#Genesis
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ChainConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc: Option<HashMap<String, AllocAccount>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<u64>,
}

impl Default for Genesis {
    fn default() -> Self {
        Self::default()
    }
}

impl Genesis {
    pub fn default() -> Self {
        let mut alloc = HashMap::new();
        alloc.insert(
            String::from("8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"),
            AllocAccount {
                code: None,
                storage: None,

                // TODO: parse to "50000000000000000000000000"
                balance: Some(String::from("0x295BE96E64066972000000")),

                mcbalance: None,
                nonce: None,
            },
        );
        Self {
            config: Some(ChainConfig {
                chain_id: Some(43112),
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
            }),
            nonce: Some(String::from("0x0")),
            timestamp: Some(String::from("0x0")),
            extra_data: Some(String::from("0x00")),

            // TODO: parse to "100000000"
            gas_limit: Some(String::from("0x5f5e100")),

            difficulty: Some(String::from("0x0")),
            mix_hash: Some(String::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )),
            coinbase: Some(String::from("0x0000000000000000000000000000000000000000")),
            alloc: Some(alloc),
            number: Some(String::from("0x0")),
            gas_used: Some(String::from("0x0")),
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

    /// Saves the current beacon node to disk
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

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisAlloc
/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisAccount
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AllocAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    /// ref. https://pkg.go.dev/github.com/ava-labs/coreth/core#GenesisMultiCoinBalance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcbalance: Option<HashMap<String, u64>>,
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
            balance: None,
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
            "chainId": 43112,
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
                "balance": "0x295BE96E64066972000000"
            }
        },
        "number": "0x0",
        "gasUsed": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
"#,
    )
    .unwrap();

    let mut alloc = HashMap::new();
    alloc.insert(
        String::from("8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"),
        AllocAccount {
            code: None,
            storage: None,

            // TODO: parse to "50000000000000000000000000"
            balance: Some(String::from("0x295BE96E64066972000000")),

            mcbalance: None,
            nonce: None,
        },
    );
    let expected = Genesis {
        config: Some(ChainConfig {
            chain_id: Some(43112),
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
        }),
        nonce: Some(String::from("0x0")),
        timestamp: Some(String::from("0x0")),
        extra_data: Some(String::from("0x00")),

        // TODO: parse to "100000000"
        gas_limit: Some(String::from("0x5f5e100")),

        difficulty: Some(String::from("0x0")),
        mix_hash: Some(String::from(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )),
        coinbase: Some(String::from("0x0000000000000000000000000000000000000000")),
        alloc: Some(alloc),
        number: Some(String::from("0x0")),
        gas_used: Some(String::from("0x0")),
        parent_hash: Some(String::from(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )),
        base_fee: None,
    };
    assert_eq!(resp, expected);

    let d = Genesis::default();
    let d = d.encode_json().unwrap();
    info!("{}", d);
}
