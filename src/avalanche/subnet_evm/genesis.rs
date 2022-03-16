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

use crate::utils::big_int::{self, big_int_hex_format};

/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/core#Genesis
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/params#ChainConfig
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ChainConfig>,

    #[serde(with = "big_int_hex_format")]
    pub nonce: BigInt,
    #[serde(with = "big_int_hex_format")]
    pub timestamp: BigInt,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<String>,

    #[serde(with = "big_int_hex_format")]
    pub gas_limit: BigInt,
    #[serde(with = "big_int_hex_format")]
    pub difficulty: BigInt,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<String>,

    /// MUST BE ordered by its key in order for all nodes to have the same JSON outputs.
    /// ref. https://doc.rust-lang.org/std/collections/index.html#use-a-btreemap-when
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc: Option<BTreeMap<String, AllocAccount>>,

    /// WARNING: Big airdrop data may cause OOM in subnet-evm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub airdrop_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub airdrop_amount: Option<String>,

    #[serde(with = "big_int_hex_format")]
    pub number: BigInt,
    #[serde(with = "big_int_hex_format")]
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
            // ref. https://github.com/ava-labs/subnet-evm/blob/master/networks/11111/genesis.json
            String::from("6f0f6DA1852857d7789f68a28bba866671f3880D"),
            AllocAccount::default(),
        );
        Self {
            config: Some(ChainConfig::default()),

            nonce: BigInt::default(),
            timestamp: BigInt::default(),
            extra_data: Some(String::from("0x00")),

            gas_limit: big_int::from_hex("0x1312D00").expect("failed to parse big_int"),

            difficulty: BigInt::default(),
            mix_hash: Some(String::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )),
            coinbase: Some(String::from("0x0000000000000000000000000000000000000000")),

            alloc: Some(alloc),

            airdrop_hash: None,
            airdrop_amount: None,

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

/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/params#ChainConfig
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub homestead_block: Option<u64>,

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

    #[serde(rename = "subnetEVMTimestamp", skip_serializing_if = "Option::is_none")]
    pub subnet_evm_timestamp: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_config: Option<FeeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_fee_recipients: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_deployer_allow_list_config: Option<ContractDeployerAllowListConfig>,
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
            chain_id: Some(2000777),
            homestead_block: Some(0),

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

            subnet_evm_timestamp: Some(0),

            fee_config: Some(FeeConfig::default()),
            allow_fee_recipients: None,

            contract_deployer_allow_list_config: Some(ContractDeployerAllowListConfig::default()),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/params#FeeConfig
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_block_rate: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_base_fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_gas: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_change_denominator: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_block_gas_cost: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_block_gas_cost: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_gas_cost_step: Option<u64>,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self::default()
    }
}

impl FeeConfig {
    pub fn default() -> Self {
        Self {
            gas_limit: Some(20000000),
            target_block_rate: Some(2),

            min_base_fee: Some(1000000000),
            target_gas: Some(100000000),
            base_fee_change_denominator: Some(48),

            min_block_gas_cost: Some(0),
            max_block_gas_cost: Some(10000000),
            block_gas_cost_step: Some(500000),
        }
    }
}

/// ref. https://github.com/ava-labs/subnet-evm/blob/master/precompile/contract_deployer_allow_list.go
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContractDeployerAllowListConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<u64>,
    #[serde(rename = "adminAddresses", skip_serializing_if = "Option::is_none")]
    pub allow_list_admins: Option<Vec<String>>,
}

impl Default for ContractDeployerAllowListConfig {
    fn default() -> Self {
        Self::default()
    }
}

impl ContractDeployerAllowListConfig {
    pub fn default() -> Self {
        Self {
            block_timestamp: Some(0),
            allow_list_admins: None,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/core#GenesisAlloc
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/core#GenesisAccount
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AllocAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<BTreeMap<String, String>>,

    #[serde(with = "big_int_hex_format")]
    pub balance: BigInt,

    /// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/core#GenesisMultiCoinBalance
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
            balance: big_int::from_hex(DEFAULT_INITIAL_AMOUNT)
                .expect("failed to parse initial amount"),
            mcbalance: None,
            nonce: None,
        }
    }
}

#[test]
fn test_parse() {
    let _ = env_logger::builder().is_test(true).try_init();

    // ref. https://github.com/ava-labs/subnet-evm/blob/master/networks/11111/genesis.json
    let resp: Genesis = serde_json::from_str(
        r#"
{
        "config": {
            "chainId": 2000777,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "muirGlacierBlock": 0,
            "subnetEVMTimestamp": 0,
            "feeConfig": {
                "gasLimit": 20000000,
                "minBaseFee": 1000000000,
                "targetGas": 100000000,
                "baseFeeChangeDenominator": 48,
                "minBlockGasCost": 0,
                "maxBlockGasCost": 10000000,
                "targetBlockRate": 2,
                "blockGasCostStep": 500000
            },
            "contractDeployerAllowListConfig": { "blockTimestamp": 0 }
        },
        "alloc": {
            "6f0f6DA1852857d7789f68a28bba866671f3880D": {
                "balance": "0x52B7D2DCC80CD2E4000000"
            }
        },
        "nonce": "0x0",
        "timestamp": "0x0",
        "extraData": "0x00",
        "gasLimit": "0x1312D00",
        "difficulty": "0x0",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
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
