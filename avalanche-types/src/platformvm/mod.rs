pub mod add_subnet_validator;
pub mod add_validator;
pub mod create_chain;
pub mod create_subnet;
pub mod export;
pub mod import;

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{avax, codec, ids, secp256k1fx};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants#pkg-variables
pub fn chain_id() -> ids::Id {
    ids::Id::empty()
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Validator
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Validator {
    pub node_id: ids::ShortId,
    pub start: u64,
    pub end: u64,
    pub weight: u64,
}

impl Default for Validator {
    fn default() -> Self {
        Self::default()
    }
}

impl Validator {
    pub fn default() -> Self {
        Self {
            node_id: ids::ShortId::empty(),
            start: 0,
            end: 0,
            weight: 0,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockIn
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct StakeableLockIn {
    pub locktime: u64,
    pub transfer_input: secp256k1fx::TransferInput,
}

impl Default for StakeableLockIn {
    fn default() -> Self {
        Self::default()
    }
}

impl StakeableLockIn {
    pub fn default() -> Self {
        Self {
            locktime: 0,
            transfer_input: secp256k1fx::TransferInput::default(),
        }
    }

    pub fn type_name() -> String {
        "platformvm.StakeableLockIn".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::P_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for StakeableLockIn {
    fn cmp(&self, other: &StakeableLockIn) -> Ordering {
        self.locktime
            .cmp(&(other.locktime)) // returns when "locktime"s are not Equal
            .then_with(
                || self.transfer_input.cmp(&other.transfer_input), // if "locktime"s are Equal, compare "transfer_input"
            )
    }
}

impl PartialOrd for StakeableLockIn {
    fn partial_cmp(&self, other: &StakeableLockIn) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for StakeableLockIn {
    fn eq(&self, other: &StakeableLockIn) -> bool {
        (self.locktime == other.locktime) || (self.transfer_input == other.transfer_input)
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct StakeableLockOut {
    pub locktime: u64,
    pub transfer_output: secp256k1fx::TransferOutput,
}

impl Default for StakeableLockOut {
    fn default() -> Self {
        Self::default()
    }
}

impl StakeableLockOut {
    pub fn default() -> Self {
        Self {
            locktime: 0,
            transfer_output: secp256k1fx::TransferOutput::default(),
        }
    }

    pub fn type_name() -> String {
        "platformvm.StakeableLockOut".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::P_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for StakeableLockOut {
    fn cmp(&self, other: &StakeableLockOut) -> Ordering {
        self.locktime
            .cmp(&(other.locktime)) // returns when "locktime"s are not Equal
            .then_with(
                || self.transfer_output.cmp(&other.transfer_output), // if "locktime"s are Equal, compare "transfer_output"
            )
    }
}

impl PartialOrd for StakeableLockOut {
    fn partial_cmp(&self, other: &StakeableLockOut) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for StakeableLockOut {
    fn eq(&self, other: &StakeableLockOut) -> bool {
        (self.locktime == other.locktime) || (self.transfer_output == other.transfer_output)
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Utxo {
    pub utxo_id: avax::UtxoId,
    pub asset_id: ids::Id,
}

impl Default for Utxo {
    fn default() -> Self {
        Self::default()
    }
}

impl Utxo {
    pub fn default() -> Self {
        Self {
            utxo_id: avax::UtxoId::default(),
            asset_id: ids::Id::empty(),
        }
    }
}
