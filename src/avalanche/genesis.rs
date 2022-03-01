use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
    time::SystemTime,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::avalanche::key;

/// Represents Avalanche network genesis configuration.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#Config
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AvalancheGo {
    #[serde(rename = "networkID")]
    pub network_id: u32,

    #[serde(rename = "allocations", skip_serializing_if = "Option::is_none")]
    pub allocations: Option<Vec<Allocation>>,

    /// Unix time for start time.
    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    /// Number of seconds to stake for the initial stakers.
    #[serde(
        rename = "initialStakeDuration",
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_stake_duration: Option<u64>,
    #[serde(
        rename = "initialStakeDurationOffset",
        skip_serializing_if = "Option::is_none"
    )]
    pub initial_stake_duration_offset: Option<u64>,
    /// Must be come from "initial_stakers".
    /// Must be the list of X-chain addresses.
    /// Initial staked funds cannot be empty.
    #[serde(rename = "initialStakedFunds", skip_serializing_if = "Option::is_none")]
    pub initial_staked_funds: Option<Vec<String>>,
    /// Must be non-empty for an existing network.
    /// Non-beacon nodes request "GetAcceptedFrontier" from initial stakers
    /// (not from specified beacon nodes).
    #[serde(rename = "initialStakers", skip_serializing_if = "Option::is_none")]
    pub initial_stakers: Option<Vec<Staker>>,

    #[serde(rename = "cChainGenesis", skip_serializing_if = "Option::is_none")]
    pub c_chain_genesis: Option<String>,

    #[serde(rename = "message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub const DEFAULT_CUSTOM_NETWORK_ID: u32 = 9999;
pub const DEFAULT_INITIAL_STAKE_DURATION: u64 = 31536000; // 1 year
pub const DEFAULT_INITIAL_STAKE_DURATION_OFFSET: u64 = 5400; // 1.5 hour

/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/params#ChainConfig
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/params#ChainConfig
pub const DEFAULT_C_CHAIN_GENESIS: &str = r#"
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
"#;

impl Default for AvalancheGo {
    fn default() -> Self {
        Self::default()
    }
}

impl AvalancheGo {
    pub fn default() -> Self {
        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            network_id: DEFAULT_CUSTOM_NETWORK_ID, // mainnet
            allocations: Some(Vec::new()),
            start_time: Some(now_unix),
            initial_stake_duration: Some(DEFAULT_INITIAL_STAKE_DURATION),
            initial_stake_duration_offset: Some(DEFAULT_INITIAL_STAKE_DURATION_OFFSET),
            initial_staked_funds: Some(Vec::new()),
            initial_stakers: Some(vec![Staker::default()]),
            c_chain_genesis: Some(String::from(DEFAULT_C_CHAIN_GENESIS)),
            message: Some(String::new()),
        }
    }

    /// Creates a new Genesis object with "keys" number of generated
    /// pre-funded keys.
    pub fn new(network_id: u32, keys: usize) -> io::Result<(Self, Vec<key::PrivateKeyInfo>)> {
        let mut initial_staked_funds: Vec<String> = Vec::new();
        let mut allocations: Vec<Allocation> = Vec::new();
        let mut seed_priv_keys: Vec<key::PrivateKeyInfo> = Vec::new();
        for _ in 0..keys {
            let k = key::Key::generate()?;
            let info = k.to_info(network_id)?;

            // use the default allocation
            let mut alloc = Allocation::default();
            alloc.avax_addr = Some(info.x_address.clone());
            alloc.eth_addr = Some(info.eth_address.clone());

            initial_staked_funds.push(info.x_address.clone());
            allocations.push(alloc);
            seed_priv_keys.push(info);
        }
        Ok((
            Self {
                network_id,
                initial_staked_funds: Some(initial_staked_funds),
                allocations: Some(allocations),
                ..Default::default()
            },
            seed_priv_keys,
        ))
    }

    /// Converts to string.
    pub fn to_string(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to JSON {}", e),
                ));
            }
        }
    }

    /// Saves the current configuration to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing genesis Config to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to JSON {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading genesis from {}", file_path);

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
        serde_json::from_reader(f).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
        })
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#Allocation
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Allocation {
    #[serde(rename = "avaxAddr", skip_serializing_if = "Option::is_none")]
    pub avax_addr: Option<String>,
    /// "eth_addr" can be any value, not used in "avalanchego".
    /// This field is only used for memos.
    #[serde(rename = "ethAddr", skip_serializing_if = "Option::is_none")]
    pub eth_addr: Option<String>,
    /// Initially allocated amount.
    /// On the X-Chain, one AVAX is 10^9  units.
    /// On the P-Chain, one AVAX is 10^9  units.
    /// On the C-Chain, one AVAX is 10^18 units.
    #[serde(rename = "initialAmount", skip_serializing_if = "Option::is_none")]
    pub initial_amount: Option<u64>,
    #[serde(rename = "unlockSchedule", skip_serializing_if = "Option::is_none")]
    pub unlock_schedule: Option<Vec<LockedAmount>>,
}

pub const DEFAULT_INITIAL_AMOUNT: u64 = 300000000000000000;

impl Default for Allocation {
    fn default() -> Self {
        Self::default()
    }
}

impl Allocation {
    pub fn default() -> Self {
        Self {
            avax_addr: None,
            eth_addr: None,
            initial_amount: Some(DEFAULT_INITIAL_AMOUNT),
            unlock_schedule: Some(vec![LockedAmount::default()]),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#LockedAmount
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct LockedAmount {
    /// Amount to lock for the duration of "locktime"
    /// in addition to the initial amount.
    /// On the X-Chain, one AVAX is 10^9  units.
    /// On the P-Chain, one AVAX is 10^9  units.
    /// On the C-Chain, one AVAX is 10^18 units.
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Unix timestamp to unlock the "amount".
    #[serde(rename = "locktime", skip_serializing_if = "Option::is_none")]
    pub locktime: Option<u64>,
}

pub const DEFAULT_LOCKED_AMOUNT: u64 = 100000000000000000;

impl Default for LockedAmount {
    fn default() -> Self {
        Self::default()
    }
}

impl LockedAmount {
    pub fn default() -> Self {
        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            amount: Some(DEFAULT_LOCKED_AMOUNT),
            locktime: Some(now_unix + 300),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#Staker
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Staker {
    #[serde(rename = "nodeID", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(rename = "rewardAddress", skip_serializing_if = "Option::is_none")]
    pub reward_address: Option<String>,
    #[serde(rename = "delegationFee", skip_serializing_if = "Option::is_none")]
    pub delegation_fee: Option<u32>,
}

pub const DEFAULT_DELEGATION_FEE: u32 = 62500;

impl Default for Staker {
    fn default() -> Self {
        Self::default()
    }
}

impl Staker {
    pub fn default() -> Self {
        Self {
            node_id: None,
            reward_address: None,
            delegation_fee: Some(DEFAULT_DELEGATION_FEE),
        }
    }
}

#[test]
fn test_genesis() {
    use crate::random;
    let _ = env_logger::builder().is_test(true).try_init();

    let genesis = AvalancheGo {
        network_id: 1337,

        allocations: Some(vec![Allocation {
            eth_addr: Some(String::from("a")),
            avax_addr: Some(String::from("a")),
            initial_amount: Some(10),
            unlock_schedule: Some(vec![LockedAmount {
                amount: Some(10),
                locktime: Some(100),
            }]),
        }]),

        start_time: Some(10),
        initial_stake_duration: Some(30),
        initial_stake_duration_offset: Some(5),
        initial_staked_funds: Some(vec![String::from("a")]),
        initial_stakers: Some(vec![Staker {
            node_id: Some(String::from("a")),
            reward_address: Some(String::from("b")),
            delegation_fee: Some(10),
        }]),

        c_chain_genesis: Some(String::from("{}")),

        message: Some(String::from("hello")),
    };

    let ret = genesis.to_string();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("genesis: {}", s);

    let p = random::tmp_path(10, Some(".json")).unwrap();
    let ret = genesis.sync(&p);
    assert!(ret.is_ok());

    let genesis_loaded = AvalancheGo::load(&p).unwrap();
    assert_eq!(genesis, genesis_loaded);
}
