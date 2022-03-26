pub mod add_subnet_validator;
pub mod add_validator;
pub mod create_chain;
pub mod create_subnet;
pub mod export;
pub mod import;

use crate::avalanche::types::{avax, ids, secp256k1fx};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Validator
#[derive(Debug, Eq, PartialEq, Clone)]
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
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct StakeableLockOut {
    pub locktime: u64,
    pub out: secp256k1fx::TransferOutput,
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
            out: secp256k1fx::TransferOutput::default(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
#[derive(Debug, Eq, PartialEq, Clone)]
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
