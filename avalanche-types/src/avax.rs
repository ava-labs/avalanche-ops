use std::{cmp::Ordering, io, str::FromStr};

use crate::ids;
use serde::{Deserialize, Serialize};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXOID
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct UtxoId {
    pub tx_id: ids::Id,
    pub output_index: u32,
    pub symbol: bool,
    pub id: ids::Id,
}

impl Default for UtxoId {
    fn default() -> Self {
        Self::default()
    }
}

impl UtxoId {
    pub fn default() -> Self {
        Self {
            tx_id: ids::Id::empty(),
            output_index: 0,
            symbol: false,
            id: ids::Id::empty(),
        }
    }

    pub fn new(tx_id: &[u8], output_index: u32, symbol: bool) -> Self {
        let tx_id = ids::Id::from_slice(tx_id);
        let prefixes: Vec<u64> = vec![output_index as u64];
        let id = tx_id.prefix(&prefixes);
        Self {
            tx_id,
            output_index,
            symbol,
            id,
        }
    }
}

impl Ord for UtxoId {
    fn cmp(&self, other: &UtxoId) -> Ordering {
        self.tx_id
            .cmp(&(other.tx_id)) // returns when "tx_id"s are not Equal
            .then_with(
                || self.output_index.cmp(&other.output_index), // if "tx_id"s are Equal, compare "output_index"
            )
    }
}

impl PartialOrd for UtxoId {
    fn partial_cmp(&self, other: &UtxoId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UtxoId {
    fn eq(&self, other: &UtxoId) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#SortUTXOIDs
/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_sort_utxo_ids --exact --show-output
#[test]
fn test_sort_utxo_ids() {
    use avalanche_utils::cmp;

    let mut utxos: Vec<UtxoId> = Vec::new();
    for i in (0..10).rev() {
        utxos.push(UtxoId {
            tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            output_index: (i + 1) as u32,
            ..UtxoId::default()
        });
        utxos.push(UtxoId {
            tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            output_index: i as u32,
            ..UtxoId::default()
        });
    }
    assert!(!cmp::is_sorted_and_unique(&utxos));
    utxos.sort();

    let mut sorted_utxos: Vec<UtxoId> = Vec::new();
    for i in 0..10 {
        sorted_utxos.push(UtxoId {
            tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            output_index: i as u32,
            ..UtxoId::default()
        });
        sorted_utxos.push(UtxoId {
            tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            output_index: (i + 1) as u32,
            ..UtxoId::default()
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_utxos));
    assert_eq!(utxos, sorted_utxos);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawUtxoId {
    #[serde(rename = "txID")]
    pub tx_id: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
}

impl RawUtxoId {
    pub fn convert(&self) -> io::Result<UtxoId> {
        let tx_id = ids::Id::from_str(&self.tx_id)?;
        Ok(UtxoId {
            tx_id,
            output_index: self.output_index,
            ..UtxoId::default()
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_utxo_id --exact --show-output
/// ref. "avalanchego/vms/components/avax.TestUTXOID"
#[test]
fn test_utxo_id() {
    let tx_id: Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let utxo_id = UtxoId::new(&tx_id, 0x20212223, false);

    let expected_id: Vec<u8> = vec![
        42, 202, 101, 108, 44, 18, 156, 140, 88, 220, 97, 33, 177, 172, 79, 57, 207, 131, 41, 102,
        29, 103, 184, 89, 239, 38, 187, 183, 167, 216, 160, 212,
    ];
    let expected_id = ids::Id::from_slice(&expected_id);
    assert_eq!(utxo_id.id, expected_id);
}
