use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

/// Represents Avalanche network genesis configuration.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#Config
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Genesis {
    #[serde(rename = "networkID")]
    pub network_id: u32,

    #[serde(rename = "allocations", skip_serializing_if = "Option::is_none")]
    pub allocations: Option<Vec<Allocation>>,

    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
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
    #[serde(rename = "initialStakedFunds", skip_serializing_if = "Option::is_none")]
    pub initial_staked_funds: Option<Vec<String>>,
    #[serde(rename = "initialStakers", skip_serializing_if = "Option::is_none")]
    pub initial_stakers: Option<Vec<Staker>>,

    #[serde(rename = "cChainGenesis", skip_serializing_if = "Option::is_none")]
    pub c_chain_genesis: Option<String>,

    #[serde(rename = "message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#Allocation
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Allocation {
    #[serde(rename = "ethAddr", skip_serializing_if = "Option::is_none")]
    pub eth_addr: Option<String>,
    #[serde(rename = "avaxAddr", skip_serializing_if = "Option::is_none")]
    pub avax_addr: Option<String>,
    #[serde(rename = "initialAmount", skip_serializing_if = "Option::is_none")]
    pub initial_amount: Option<u64>,
    #[serde(rename = "unlockSchedule", skip_serializing_if = "Option::is_none")]
    pub unlock_schedule: Option<Vec<LockedAmount>>,
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/genesis#LockedAmount
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct LockedAmount {
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(rename = "locktime", skip_serializing_if = "Option::is_none")]
    pub locktime: Option<u64>,
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

impl Genesis {
    /// Converts to string.
    pub fn to_string(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current configuration to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing network Config to '{}'", file_path);

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

#[test]
fn test_config() {
    let _ = env_logger::builder().is_test(true).try_init();

    let config = Genesis {
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

    let ret = config.to_string();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = crate::random::tmp_path(10).unwrap();
    let ret = config.sync(&p);
    assert!(ret.is_ok());
}

pub fn load(file_path: &str) -> io::Result<Genesis> {
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
