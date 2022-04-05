pub mod add_subnet_validator;
pub mod add_validator;
pub mod create_chain;
pub mod create_subnet;
pub mod export;
pub mod import;

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
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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
