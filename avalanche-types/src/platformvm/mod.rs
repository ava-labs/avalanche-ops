pub mod add_subnet_validator;
pub mod add_validator;
pub mod create_chain;
pub mod create_subnet;
pub mod export;
pub mod import;

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{codec, ids, secp256k1fx};

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
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::test_sort_stakeable_lock_ins --exact --show-output
#[test]
fn test_sort_stakeable_lock_ins() {
    use utils::cmp;

    let mut ins: Vec<StakeableLockIn> = Vec::new();
    for i in (0..10).rev() {
        ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 10,
                sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
        ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9, 9],
            },
        });
        ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
        ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
    }
    assert!(!cmp::is_sorted_and_unique(&ins));
    ins.sort();

    let mut sorted_ins: Vec<StakeableLockIn> = Vec::new();
    for i in 0..10 {
        sorted_ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
        sorted_ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
        sorted_ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 5,
                sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9, 9],
            },
        });
        sorted_ins.push(StakeableLockIn {
            locktime: i as u64,
            transfer_input: secp256k1fx::TransferInput {
                amount: 10,
                sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            },
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_ins));
    assert_eq!(ins, sorted_ins);
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
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::test_sort_stakeable_lock_outs --exact --show-output
#[test]
fn test_sort_stakeable_lock_outs() {
    use utils::cmp;

    let mut outs: Vec<StakeableLockOut> = Vec::new();
    for i in (0..10).rev() {
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                        ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3, 4, 5]),
                    ],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: i as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: i as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: i as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
    }
    assert!(!cmp::is_sorted_and_unique(&outs));
    outs.sort();

    let mut sorted_outs: Vec<StakeableLockOut> = Vec::new();
    for i in 0..10 {
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: i as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: i as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: i as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: i as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
        sorted_outs.push(StakeableLockOut {
            locktime: i as u64,
            transfer_output: secp256k1fx::TransferOutput {
                amount: (i + 1) as u64,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: (i + 1) as u64,
                    threshold: (i + 1) as u32,
                    addrs: vec![
                        ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                        ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3, 4, 5]),
                    ],
                    ..secp256k1fx::OutputOwners::default()
                },
            },
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_outs));
    assert_eq!(outs, sorted_outs);
}
