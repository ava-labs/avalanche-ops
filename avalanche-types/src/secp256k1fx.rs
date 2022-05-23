use std::{
    cmp::Ordering,
    io::{self, Error, ErrorKind},
};

use serde::{Deserialize, Serialize};

use crate::{codec, ids};
use avalanche_utils::cmp;

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#FxCredential
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/verify#Verifiable
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Credential
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct Credential {
    /// Signatures, each must be length of 65.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#SECP256K1RSigLen
    pub signatures: Vec<Vec<u8>>,
}

impl Default for Credential {
    fn default() -> Self {
        Self::default()
    }
}

impl Credential {
    pub fn default() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    pub fn new(sigs: Vec<Vec<u8>>) -> Self {
        Self { signatures: sigs }
    }

    pub fn type_name() -> String {
        "secp256k1fx.Credential".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::X_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for Credential {
    fn cmp(&self, other: &Credential) -> Ordering {
        Signatures::new(&self.signatures).cmp(&Signatures::new(&other.signatures))
    }
}

impl PartialOrd for Credential {
    fn partial_cmp(&self, other: &Credential) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Credential) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[derive(Eq)]
pub struct Signatures(Vec<Vec<u8>>);

impl Signatures {
    pub fn new(sigs: &[Vec<u8>]) -> Self {
        Signatures(Vec::from(sigs))
    }
}

impl Ord for Signatures {
    fn cmp(&self, other: &Signatures) -> Ordering {
        // packer encodes the array length first
        // so if the lengths differ, the ordering is decided
        let l1 = self.0.len();
        let l2 = other.0.len();
        l1.cmp(&l2) // returns when lengths are not Equal
            .then_with(
                || self.0.cmp(&other.0), // if lengths are Equal, compare the signatures
            )
    }
}

impl PartialOrd for Signatures {
    fn partial_cmp(&self, other: &Signatures) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Signatures {
    fn eq(&self, other: &Signatures) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

// NOTE: all signatures are fixed length
/// RUST_LOG=debug cargo test --package avalanche-types --lib -- secp256k1fx::test_sort_credentials --exact --show-output
#[test]
fn test_sort_credentials() {
    use avalanche_utils::cmp;

    let mut credentials: Vec<Credential> = Vec::new();
    for i in (0..10).rev() {
        credentials.push(Credential {
            signatures: vec![
                vec![i as u8, 1, 2, 3],
                vec![i as u8, 2, 2, 3],
                vec![i as u8, 4, 2, 3],
            ],
        });
        credentials.push(Credential {
            signatures: vec![
                vec![i as u8, 1, 2, 3],
                vec![i as u8, 2, 2, 3],
                vec![i as u8, 3, 2, 3],
            ],
        });
        credentials.push(Credential {
            signatures: vec![vec![i as u8, 1, 2, 3], vec![i as u8, 2, 2, 3]],
        });
        credentials.push(Credential {
            signatures: vec![vec![i as u8, 2, 2, 3]],
        });
        credentials.push(Credential {
            signatures: vec![vec![i as u8, 1, 2, 3]],
        });
    }
    assert!(!cmp::is_sorted_and_unique(&credentials));
    credentials.sort();

    let mut sorted_credentials: Vec<Credential> = Vec::new();
    for i in 0..10 {
        sorted_credentials.push(Credential {
            signatures: vec![vec![i as u8, 1, 2, 3]],
        });
        sorted_credentials.push(Credential {
            signatures: vec![vec![i as u8, 2, 2, 3]],
        });
    }
    for i in 0..10 {
        sorted_credentials.push(Credential {
            signatures: vec![vec![i as u8, 1, 2, 3], vec![i as u8, 2, 2, 3]],
        });
    }
    for i in 0..10 {
        sorted_credentials.push(Credential {
            signatures: vec![
                vec![i as u8, 1, 2, 3],
                vec![i as u8, 2, 2, 3],
                vec![i as u8, 3, 2, 3],
            ],
        });
        sorted_credentials.push(Credential {
            signatures: vec![
                vec![i as u8, 1, 2, 3],
                vec![i as u8, 2, 2, 3],
                vec![i as u8, 4, 2, 3],
            ],
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_credentials));
    assert_eq!(credentials, sorted_credentials);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#OutputOwners
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct OutputOwners {
    pub locktime: u64,
    pub threshold: u32,
    pub addrs: Vec<ids::ShortId>,
}

impl Default for OutputOwners {
    fn default() -> Self {
        Self::default()
    }
}

impl OutputOwners {
    pub fn default() -> Self {
        Self {
            locktime: 0,
            threshold: 0,
            addrs: Vec::new(),
        }
    }

    pub fn new(locktime: u64, threshold: u32, addrs: &[ids::ShortId]) -> Self {
        Self {
            locktime,
            threshold,
            addrs: Vec::from(addrs),
        }
    }

    pub fn type_name() -> String {
        "secp256k1fx.OutputOwners".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::P_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for OutputOwners {
    fn cmp(&self, other: &OutputOwners) -> Ordering {
        self.locktime
            .cmp(&(other.locktime)) // returns when "locktime"s are not Equal
            .then_with(
                || self.threshold.cmp(&other.threshold), // if "locktime"s are Equal, compare "threshold"
            )
            .then_with(
                || ids::ShortIds::new(&self.addrs).cmp(&ids::ShortIds::new(&other.addrs)), // if "locktime"s and "threshold"s are Equal, compare "addrs"
            )
    }
}

impl PartialOrd for OutputOwners {
    fn partial_cmp(&self, other: &OutputOwners) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OutputOwners {
    fn eq(&self, other: &OutputOwners) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- secp256k1fx::test_sort_output_owners --exact --show-output
#[test]
fn test_sort_output_owners() {
    use avalanche_utils::cmp;

    let mut owners: Vec<OutputOwners> = Vec::new();
    for i in (0..10).rev() {
        owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
                ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3]),
            ],
        });
        owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
            ],
        });
        owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3])],
        });
        owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3])],
        });
    }
    assert!(!cmp::is_sorted_and_unique(&owners));
    owners.sort();

    let mut sorted_owners: Vec<OutputOwners> = Vec::new();
    for i in 0..10 {
        sorted_owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3])],
        });
        sorted_owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3])],
        });
        sorted_owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
            ],
        });
        sorted_owners.push(OutputOwners {
            locktime: i as u64,
            threshold: i as u32,
            addrs: vec![
                ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3]),
                ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3]),
            ],
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_owners));
    assert_eq!(owners, sorted_owners);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOut
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct TransferOutput {
    pub amount: u64,
    pub output_owners: OutputOwners,
}

impl Default for TransferOutput {
    fn default() -> Self {
        Self::default()
    }
}

impl TransferOutput {
    pub fn default() -> Self {
        Self {
            amount: 0,
            output_owners: OutputOwners::default(),
        }
    }

    pub fn new(amount: u64, output_owners: OutputOwners) -> Self {
        Self {
            amount,
            output_owners,
        }
    }

    pub fn type_name() -> String {
        "secp256k1fx.TransferOutput".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::X_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for TransferOutput {
    fn cmp(&self, other: &TransferOutput) -> Ordering {
        self.amount
            .cmp(&(other.amount)) // returns when "amount"s are not Equal
            .then_with(
                || self.output_owners.cmp(&(other.output_owners)), // if "amount"s are Equal, compare "output_owners"
            )
    }
}

impl PartialOrd for TransferOutput {
    fn partial_cmp(&self, other: &TransferOutput) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TransferOutput {
    fn eq(&self, other: &TransferOutput) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- secp256k1fx::test_sort_transfer_outputs --exact --show-output
#[test]
fn test_sort_transfer_outputs() {
    use avalanche_utils::cmp;

    let mut outputs: Vec<TransferOutput> = Vec::new();
    for i in (0..10).rev() {
        outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3, 4, 5]),
                ],
                ..OutputOwners::default()
            },
        });
        outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                ],
                ..OutputOwners::default()
            },
        });
        outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
        outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: i as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
        outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: i as u64,
                threshold: i as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
    }
    assert!(!cmp::is_sorted_and_unique(&outputs));
    outputs.sort();

    let mut sorted_outputs: Vec<TransferOutput> = Vec::new();
    for i in 0..10 {
        sorted_outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: i as u64,
                threshold: i as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
        sorted_outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: i as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
        sorted_outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5])],
                ..OutputOwners::default()
            },
        });
        sorted_outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                ],
                ..OutputOwners::default()
            },
        });
        sorted_outputs.push(TransferOutput {
            amount: i as u64,
            output_owners: OutputOwners {
                locktime: (i + 1) as u64,
                threshold: (i + 1) as u32,
                addrs: vec![
                    ids::ShortId::from_slice(&vec![i as u8, 1, 2, 3, 4, 5]),
                    ids::ShortId::from_slice(&vec![i as u8, 2, 2, 3, 4, 5]),
                ],
                ..OutputOwners::default()
            },
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_outputs));
    assert_eq!(outputs, sorted_outputs);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableIn
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct TransferInput {
    pub amount: u64,
    pub sig_indices: Vec<u32>,
}

impl Default for TransferInput {
    fn default() -> Self {
        Self::default()
    }
}

impl TransferInput {
    pub fn default() -> Self {
        Self {
            amount: 0,
            sig_indices: Vec::new(),
        }
    }

    pub fn new(amount: u64, sig_indices: Vec<u32>) -> Self {
        Self {
            amount,
            sig_indices,
        }
    }

    pub fn type_name() -> String {
        "secp256k1fx.TransferInput".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::X_TYPES.get(&Self::type_name()).unwrap()) as u32
    }

    pub fn verify(&self) -> io::Result<()> {
        if self.amount == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "input has no value", // ref. "errNoValueInput"
            ));
        }
        if !cmp::is_sorted_and_unique(&self.sig_indices) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "signatures not sorted and unique", // ref. "errNotSortedUnique"
            ));
        }
        Ok(())
    }

    /// ref. "vms/secp256k1fx.Input.Cost"
    pub fn sig_costs(&self) -> u64 {
        let sigs = self.sig_indices.len();
        (sigs as u64) * 1000
    }
}

impl Ord for TransferInput {
    fn cmp(&self, other: &TransferInput) -> Ordering {
        self.amount
            .cmp(&(other.amount)) // returns when "amount"s are not Equal
            .then_with(
                || SigIndices::new(&self.sig_indices).cmp(&SigIndices::new(&other.sig_indices)), // if "amount"s are Equal, compare "sig_indices"
            )
    }
}

impl PartialOrd for TransferInput {
    fn partial_cmp(&self, other: &TransferInput) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TransferInput {
    fn eq(&self, other: &TransferInput) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[derive(Eq)]
pub struct SigIndices(Vec<u32>);

impl SigIndices {
    pub fn new(ids: &[u32]) -> Self {
        SigIndices(Vec::from(ids))
    }
}

impl Ord for SigIndices {
    fn cmp(&self, other: &SigIndices) -> Ordering {
        // packer encodes the array length first
        // so if the lengths differ, the ordering is decided
        let l1 = self.0.len();
        let l2 = other.0.len();
        l1.cmp(&l2) // returns when lengths are not Equal
            .then_with(
                || self.0.cmp(&other.0), // if lengths are Equal, compare the ids
            )
    }
}

impl PartialOrd for SigIndices {
    fn partial_cmp(&self, other: &SigIndices) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SigIndices {
    fn eq(&self, other: &SigIndices) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- secp256k1fx::test_sort_transfer_inputs --exact --show-output
#[test]
fn test_sort_transfer_inputs() {
    use avalanche_utils::cmp;

    let mut inputs: Vec<TransferInput> = Vec::new();
    for i in (0..10).rev() {
        inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        inputs.push(TransferInput {
            amount: 50,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
        inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
        inputs.push(TransferInput {
            amount: 1,
            sig_indices: vec![(i + 100) as u32, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
        });
    }
    assert!(!cmp::is_sorted_and_unique(&inputs));
    inputs.sort();

    let mut sorted_inputs: Vec<TransferInput> = Vec::new();
    for i in 0..10 {
        sorted_inputs.push(TransferInput {
            amount: 1,
            sig_indices: vec![(i + 100) as u32, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9],
        });
    }
    for i in 0..10 {
        sorted_inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
    }
    for i in 0..10 {
        sorted_inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        sorted_inputs.push(TransferInput {
            amount: 5,
            sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
        });
    }
    for i in 0..10 {
        sorted_inputs.push(TransferInput {
            amount: 50,
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_inputs));
    assert_eq!(inputs, sorted_inputs);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct Input {
    pub sig_indices: Vec<u32>,
}

impl Default for Input {
    fn default() -> Self {
        Self::default()
    }
}

impl Input {
    pub fn default() -> Self {
        Self {
            sig_indices: Vec::new(),
        }
    }

    pub fn new(sig_indices: Vec<u32>) -> Self {
        Self { sig_indices }
    }

    pub fn type_name() -> String {
        "secp256k1fx.Input".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::P_TYPES.get(&Self::type_name()).unwrap()) as u32
    }
}

impl Ord for Input {
    fn cmp(&self, other: &Input) -> Ordering {
        SigIndices::new(&self.sig_indices).cmp(&SigIndices::new(&other.sig_indices))
    }
}

impl PartialOrd for Input {
    fn partial_cmp(&self, other: &Input) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Input {
    fn eq(&self, other: &Input) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- secp256k1fx::test_sort_inputs --exact --show-output
#[test]
fn test_sort_inputs() {
    use avalanche_utils::cmp;

    let mut inputs: Vec<Input> = Vec::new();
    for i in (0..10).rev() {
        inputs.push(Input {
            sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        inputs.push(Input {
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        inputs.push(Input {
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
    }
    assert!(!cmp::is_sorted_and_unique(&inputs));
    inputs.sort();

    let mut sorted_inputs: Vec<Input> = Vec::new();
    for i in 0..10 {
        sorted_inputs.push(Input {
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5],
        });
    }
    for i in 0..10 {
        sorted_inputs.push(Input {
            sig_indices: vec![i as u32, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        sorted_inputs.push(Input {
            sig_indices: vec![i as u32, 2, 2, 3, 4, 5, 6, 7, 8, 9],
        });
    }
    assert!(cmp::is_sorted_and_unique(&sorted_inputs));
    assert_eq!(inputs, sorted_inputs);
}
