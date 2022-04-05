use std::{
    cmp,
    io::{self, Error, ErrorKind},
    str::FromStr,
};

use crate::{codec, formatting, ids, packer, platformvm, secp256k1fx};
use serde::{Deserialize, Serialize};
use utils::{hash, prefix};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOut
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct TransferableOutput {
    pub asset_id: ids::Id,
    pub fx_id: ids::Id, // skip serialization due to serialize:"false"

    /// The underlying type is one of the following:
    ///
    /// "*secp256k1fx.TransferOutput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
    ///
    /// "*platformvm.StakeableLockOut" which embeds "*secp256k1fx.TransferOutput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
    ///
    /// MUST: only one of the following can be "Some".
    pub transfer_output: Option<secp256k1fx::TransferOutput>,
    pub stakeable_lock_out: Option<platformvm::StakeableLockOut>,
}

impl Default for TransferableOutput {
    fn default() -> Self {
        Self::default()
    }
}

impl TransferableOutput {
    pub fn default() -> Self {
        Self {
            asset_id: ids::Id::empty(),
            fx_id: ids::Id::empty(),
            transfer_output: None,
            stakeable_lock_out: None,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableIn
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
#[derive(Debug, Serialize, Deserialize, Eq, Clone)]
pub struct TransferableInput {
    pub utxo_id: UtxoId,
    pub asset_id: ids::Id,
    pub fx_id: ids::Id, // skip serialization due to serialize:"false"

    /// The underlying type is one of the following:
    ///
    /// "*secp256k1fx.TransferInput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
    ///
    /// "*platformvm.StakeableLockIn" which embeds "*secp256k1fx.TransferInput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockIn
    ///
    /// MUST: only one of the following can be "Some".
    pub transfer_input: Option<secp256k1fx::TransferInput>,
    pub stakeable_lock_in: Option<platformvm::StakeableLockIn>,
}

impl Default for TransferableInput {
    fn default() -> Self {
        Self::default()
    }
}

impl TransferableInput {
    pub fn default() -> Self {
        Self {
            utxo_id: UtxoId::default(),
            asset_id: ids::Id::empty(),
            fx_id: ids::Id::empty(),
            transfer_input: None,
            stakeable_lock_in: None,
        }
    }
}

impl Ord for TransferableInput {
    fn cmp(&self, other: &TransferableInput) -> cmp::Ordering {
        self.utxo_id
            .tx_id
            .d
            .cmp(&(other.utxo_id.tx_id.d)) // returns when "utxo_id.tx_id"s are not Equal
            .then_with(
                || self.utxo_id.output_index.cmp(&other.utxo_id.output_index), // if "utxo_id.tx_id"s are Equal, compare "output_index"
            )
    }
}

impl PartialOrd for TransferableInput {
    fn partial_cmp(&self, other: &TransferableInput) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TransferableInput {
    fn eq(&self, other: &TransferableInput) -> bool {
        (self.utxo_id.tx_id == other.utxo_id.tx_id)
            || (self.utxo_id.output_index == other.utxo_id.output_index)
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#SortTransferableInputs
/// ref. "avalanchego/vms/components/avax.TestTransferableInputSorting"
/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_sort_transferable_inputs --exact --show-output
#[test]
fn test_sort_transferable_inputs() {
    let mut inputs: Vec<TransferableInput> = Vec::new();
    for i in (0..10).rev() {
        inputs.push(TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                output_index: (i + 1) as u32,
                ..UtxoId::default()
            },
            ..TransferableInput::default()
        });
        inputs.push(TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                output_index: i as u32,
                ..UtxoId::default()
            },
            ..TransferableInput::default()
        });
    }
    inputs.sort();

    let mut sorted_inputs: Vec<TransferableInput> = Vec::new();
    for i in 0..10 {
        sorted_inputs.push(TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                output_index: i as u32,
                ..UtxoId::default()
            },
            ..TransferableInput::default()
        });
        sorted_inputs.push(TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::from_slice(&vec![i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                output_index: (i + 1) as u32,
                ..UtxoId::default()
            },
            ..TransferableInput::default()
        });
    }

    assert_eq!(inputs, sorted_inputs);
}

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
    fn cmp(&self, other: &UtxoId) -> cmp::Ordering {
        self.tx_id
            .d
            .cmp(&(other.tx_id.d)) // returns when "tx_id"s are not Equal
            .then_with(
                || self.output_index.cmp(&other.output_index), // if "tx_id"s are Equal, compare "output_index"
            )
    }
}

impl PartialOrd for UtxoId {
    fn partial_cmp(&self, other: &UtxoId) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for UtxoId {
    fn eq(&self, other: &UtxoId) -> bool {
        (self.tx_id == other.tx_id) || (self.output_index == other.output_index)
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#SortUTXOIDs
/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_sort_utxo_ids --exact --show-output
#[test]
fn test_sort_utxo_ids() {
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

/// Do not parse the internal tests.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Utxo {
    pub utxo_id: UtxoId,
    pub asset_id: ids::Id,

    /// AvalancheGo loads "avax.UTXO" object from the db and
    /// defines the "out" field as an interface "Out verify.State".
    ///
    /// The underlying type is one of the following:
    ///
    /// "*secp256k1fx.TransferOutput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
    ///
    /// "*platformvm.StakeableLockOut" which embeds "*secp256k1fx.TransferOutput"
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
    ///
    /// MUST: only one of the following can be "Some".
    pub transfer_output: Option<secp256k1fx::TransferOutput>,
    pub stakeable_lock_out: Option<platformvm::StakeableLockOut>,
}

impl Default for Utxo {
    fn default() -> Self {
        Self::default()
    }
}

impl Utxo {
    pub fn default() -> Self {
        Self {
            utxo_id: UtxoId::default(),
            asset_id: ids::Id::empty(),
            transfer_output: None,
            stakeable_lock_out: None,
        }
    }

    /// Parses the raw hex-encoded data from the "getUTXOs" API.
    pub fn unpack_hex(d: &str) -> io::Result<Self> {
        // ref. "utils/formatting.encode" prepends "0x" for "Hex" encoding
        let d = prefix::strip_0x(d);
        let decoded = formatting::decode_hex_with_checksum(d.as_bytes())?;
        Self::unpack(&decoded)
    }

    /// Parses raw bytes to "Utxo".
    /// It assumes the data are already decoded from "hex".
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
    pub fn unpack(d: &[u8]) -> io::Result<Self> {
        let packer = packer::Packer::load_bytes_for_unpack(d.len() + 1024, d);

        let _codec_version = packer.unpack_u16();

        // must unpack in the order of struct
        let tx_id_bytes = match packer.unpack_bytes(ids::ID_LEN) {
            Some(b) => b,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "failed to unpack bytes (None)",
                ));
            }
        };
        let tx_id = ids::Id::from_slice(&tx_id_bytes);

        let output_index = packer.unpack_u32();

        let asset_id_bytes = match packer.unpack_bytes(ids::ID_LEN) {
            Some(b) => b,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "failed to unpack bytes for asset_id (None)",
                ));
            }
        };
        let asset_id = ids::Id::from_slice(&asset_id_bytes);

        // "Out verify.State" is an interface
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
        //
        // "*secp256k1fx.TransferOutput" -- type ID 7
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
        //
        // "*platformvm.StakeableLockOut" which embeds "*secp256k1fx.TransferOutput"-- type ID 22
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
        let type_id_verify_state = packer.unpack_u32();
        match type_id_verify_state {
            7 => {}
            22 => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown type ID for verify.State {}", type_id_verify_state),
                ));
            }
        }

        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
        let stakeable_lock_out = {
            if type_id_verify_state == 22 {
                let stakeable_lock_out_locktime = packer.unpack_u64();

                // "*secp256k1fx.TransferOutput" -- type ID 7
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
                let _type_id_secp256k1fx_transfer_output = packer.unpack_u32();

                let mut so = platformvm::StakeableLockOut::default();
                so.locktime = stakeable_lock_out_locktime;

                Some(so)
            } else {
                None
            }
        };

        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
        let amount = packer.unpack_u64();
        let locktime = packer.unpack_u64();
        let threshold = packer.unpack_u32();
        let addr_len = packer.unpack_u32();
        let mut addrs: Vec<ids::ShortId> = Vec::new();
        for _ in 0..addr_len {
            let addr = match packer.unpack_bytes(ids::SHORT_ID_LEN) {
                Some(b) => ids::ShortId::from_slice(&b),
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "failed to unpack bytes for address (None)",
                    ));
                }
            };
            addrs.push(addr);
        }
        let output_owners = secp256k1fx::OutputOwners {
            locktime,
            threshold,
            addrs,
        };
        let transfer_output = secp256k1fx::TransferOutput {
            amount,
            output_owners,
        };

        let utxo = {
            if let Some(mut stakeable_lock_out) = stakeable_lock_out {
                stakeable_lock_out.transfer_output = transfer_output;
                Utxo {
                    utxo_id: UtxoId {
                        tx_id,
                        output_index,
                        ..UtxoId::default()
                    },
                    asset_id,
                    stakeable_lock_out: Some(stakeable_lock_out),
                    ..Utxo::default()
                }
            } else {
                Utxo {
                    utxo_id: UtxoId {
                        tx_id,
                        output_index,
                        ..UtxoId::default()
                    },
                    asset_id,
                    transfer_output: Some(transfer_output),
                    ..Utxo::default()
                }
            }
        };
        Ok(utxo)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_utxo_unpack_hex --exact --show-output
#[test]
fn test_utxo_unpack_hex() {
    let d = "0x000000000000000000000000000000000000000000000000000000000000000000000000000088eec2e099c6a528e689618e8721e04ae85ea574c7a15a7968644d14d54780140000000702c68af0bb1400000000000000000000000000010000000165844a05405f3662c1928142c6c2a783ef871de939b564db";
    let addr = ids::ShortId::from_slice(&<Vec<u8>>::from([
        101, 132, 74, 5, 64, 95, 54, 98, 193, 146, 129, 66, 198, 194, 167, 131, 239, 135, 29, 233,
    ]));
    let utxo = Utxo::unpack_hex(d).unwrap();
    let expected = Utxo {
        utxo_id: UtxoId::default(),
        asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
            136, 238, 194, 224, 153, 198, 165, 40, 230, 137, 97, 142, 135, 33, 224, 74, 232, 94,
            165, 116, 199, 161, 90, 121, 104, 100, 77, 20, 213, 71, 128, 20,
        ])),
        transfer_output: Some(secp256k1fx::TransferOutput {
            amount: 200000000000000000,
            output_owners: secp256k1fx::OutputOwners {
                locktime: 0,
                threshold: 1,
                addrs: vec![addr],
            },
        }),
        ..Utxo::default()
    };
    assert_eq!(utxo, expected);
    println!("{:?}", utxo);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Metadata
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Metadata {
    pub id: ids::Id,
    pub unsigned_bytes: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self::default()
    }
}

impl Metadata {
    pub fn default() -> Self {
        Self {
            id: ids::Id::empty(),
            unsigned_bytes: Vec::new(),
            bytes: Vec::new(),
        }
    }

    pub fn new(unsigned_bytes: &[u8], bytes: &[u8]) -> Self {
        let id = hash::compute_sha256(bytes);
        let id = ids::Id::from_slice(&id);
        Self {
            id,
            unsigned_bytes: Vec::from(unsigned_bytes),
            bytes: Vec::from(bytes),
        }
    }

    pub fn verify(&self) -> io::Result<()> {
        if self.id.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "metadata was never initialized and is not valid", // ref. "errMetadataNotInitialize"
            ));
        }
        Ok(())
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#BaseTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#BaseTx
/// TODO: use serde custom serializer
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct BaseTx {
    pub metadata: Option<Metadata>, // skip serialization due to serialize:"false"
    pub network_id: u32,
    pub blockchain_id: ids::Id,
    pub transferable_outputs: Option<Vec<TransferableOutput>>,
    pub transferable_inputs: Option<Vec<TransferableInput>>,
    pub memo: Option<Vec<u8>>,
}

impl Default for BaseTx {
    fn default() -> Self {
        Self::default()
    }
}

impl BaseTx {
    pub fn default() -> Self {
        Self {
            metadata: None,
            network_id: 0,
            blockchain_id: ids::Id::empty(),
            transferable_outputs: None,
            transferable_inputs: None,
            memo: None,
        }
    }

    pub fn type_name() -> String {
        "avm.BaseTx".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::X_TYPES.get(&Self::type_name()).unwrap()) as u32
    }

    /// "Tx.Unsigned" is implemented by "avax.BaseTx"
    /// but for marshal, it's passed as an interface.
    /// Then marshaled via "avalanchego/codec/linearcodec.linearCodec"
    /// which then calls "genericCodec.marshal".
    /// ref. "avalanchego/vms/avm.Tx.SignSECP256K1Fx"
    /// ref. "avalanchego/codec.manager.Marshal"
    /// ref. "avalanchego/codec.manager.Marshal(codecVersion, &t.UnsignedTx)"
    /// ref. "avalanchego/codec/linearcodec.linearCodec.MarshalInto"
    /// ref. "avalanchego/codec/reflectcodec.genericCodec.MarshalInto"
    /// ref. "avalanchego/codec/reflectcodec.genericCodec.marshal"
    ///
    /// Returns the packer itself so that the following marshals can reuse.
    ///
    /// "BaseTx" is an interface in Go (reflect.Interface)
    /// thus the underlying type must be specified by the caller
    /// TODO: can we do better in Rust? Go does so with reflect...
    /// e.g., pack prefix with the type ID for "avm.BaseTx" (linearCodec.PackPrefix)
    /// ref. "avalanchego/codec/linearcodec.linearCodec.MarshalInto"
    /// ref. "avalanchego/codec/reflectcodec.genericCodec.MarshalInto"
    pub fn pack(&self, codec_version: u16, type_id: u32) -> io::Result<packer::Packer> {
        // ref. "avalanchego/codec.manager.Marshal", "vms/avm.newCustomCodecs"
        let packer = packer::Packer::new((1 << 31) - 1, 128);

        // codec version
        // ref. "avalanchego/codec.manager.Marshal"
        packer.pack_u16(codec_version);
        if packer.errored() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "couldn't pack codec version", // ref. "errCantPackVersion"
            ));
        }
        packer.pack_u32(type_id);

        // marshal the actual struct "avm.BaseTx"
        // "BaseTx.Metadata" is not serialize:"true" thus skipping serialization!!!
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#BaseTx
        // ref. "avalanchego/codec/reflectcodec.structFielder"
        packer.pack_u32(self.network_id);
        packer.pack_bytes(&self.blockchain_id.d);

        // "transferable_outputs" field; pack the number of slice elements
        if self.transferable_outputs.is_some() {
            let transferable_outputs = self.transferable_outputs.as_ref().unwrap();
            packer.pack_u32(transferable_outputs.len() as u32);

            for transferable_output in transferable_outputs.iter() {
                // "TransferableOutput.Asset" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableOutput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Asset
                packer.pack_bytes(&transferable_output.asset_id.d);

                // fx_id is serialize:"false" thus skipping serialization

                // decide the type
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
                if transferable_output.transfer_output.is_none()
                    && transferable_output.stakeable_lock_out.is_none()
                {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "unexpected Nones in TransferableOutput transfer_output and stakeable_lock_out",
                    ));
                }
                let type_id_transferable_out = {
                    if transferable_output.transfer_output.is_some() {
                        secp256k1fx::TransferOutput::type_id()
                    } else {
                        platformvm::StakeableLockOut::type_id()
                    }
                };
                // marshal type ID for "secp256k1fx::TransferOutput" or "platformvm::StakeableLockOut"
                packer.pack_u32(type_id_transferable_out);

                match type_id_transferable_out {
                    7 => {
                        // "secp256k1fx::TransferOutput"
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
                        let transfer_output = transferable_output.transfer_output.clone().unwrap();

                        // marshal "secp256k1fx.TransferOutput.Amt" field
                        packer.pack_u64(transfer_output.amount);

                        // "secp256k1fx.TransferOutput.OutputOwners" is struct and serialize:"true"
                        // but embedded inline in the struct "TransferOutput"
                        // so no need to encode type ID
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#OutputOwners
                        packer.pack_u64(transfer_output.output_owners.locktime);
                        packer.pack_u32(transfer_output.output_owners.threshold);
                        packer.pack_u32(transfer_output.output_owners.addrs.len() as u32);
                        for addr in transfer_output.output_owners.addrs.iter() {
                            packer.pack_bytes(&addr.d);
                        }
                    }
                    22 => {
                        // "platformvm::StakeableLockOut"
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
                        let stakeable_lock_out =
                            transferable_output.stakeable_lock_out.clone().unwrap();

                        // marshal "platformvm::StakeableLockOut.locktime" field
                        packer.pack_u64(stakeable_lock_out.locktime);

                        // "platformvm.StakeableLockOut.TransferOutput" is struct and serialize:"true"
                        // but embedded inline in the struct "StakeableLockOut"
                        // so no need to encode type ID
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockOut
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#OutputOwners
                        //
                        // marshal "secp256k1fx.TransferOutput.Amt" field
                        packer.pack_u64(stakeable_lock_out.transfer_output.amount);
                        packer.pack_u64(stakeable_lock_out.transfer_output.output_owners.locktime);
                        packer.pack_u32(stakeable_lock_out.transfer_output.output_owners.threshold);
                        packer.pack_u32(
                            stakeable_lock_out.transfer_output.output_owners.addrs.len() as u32,
                        );
                        for addr in stakeable_lock_out
                            .transfer_output
                            .output_owners
                            .addrs
                            .iter()
                        {
                            packer.pack_bytes(&addr.d);
                        }
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "unexpected type ID {} for TransferableOutput",
                                type_id_transferable_out
                            ),
                        ));
                    }
                }
            }
        } else {
            packer.pack_u32(0_u32);
        }

        // "transferable_inputs" field; pack the number of slice elements
        if self.transferable_inputs.is_some() {
            let transferable_inputs = self.transferable_inputs.as_ref().unwrap();
            packer.pack_u32(transferable_inputs.len() as u32);

            for transferable_input in transferable_inputs.iter() {
                // "TransferableInput.UTXOID" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableInput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXOID
                packer.pack_bytes(&transferable_input.utxo_id.tx_id.d);
                packer.pack_u32(transferable_input.utxo_id.output_index);

                // "TransferableInput.Asset" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableInput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Asset
                packer.pack_bytes(&transferable_input.asset_id.d);

                // fx_id is serialize:"false" thus skipping serialization

                // decide the type
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
                if transferable_input.transfer_input.is_none()
                    && transferable_input.stakeable_lock_in.is_none()
                {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "unexpected Nones in TransferableInput transfer_input and stakeable_lock_in",
                    ));
                }
                let type_id_transferable_in = {
                    if transferable_input.transfer_input.is_some() {
                        secp256k1fx::TransferInput::type_id()
                    } else {
                        platformvm::StakeableLockIn::type_id()
                    }
                };
                // marshal type ID for "secp256k1fx::TransferInput" or "platformvm::StakeableLockIn"
                packer.pack_u32(type_id_transferable_in);

                match type_id_transferable_in {
                    5 => {
                        // "secp256k1fx::TransferInput"
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
                        let transfer_input = transferable_input.transfer_input.clone().unwrap();

                        // marshal "secp256k1fx.TransferInput.Amt" field
                        packer.pack_u64(transfer_input.amount);

                        // "secp256k1fx.TransferInput.Input" is struct and serialize:"true"
                        // but embedded inline in the struct "TransferInput"
                        // so no need to encode type ID
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
                        packer.pack_u32(transfer_input.sig_indices.len() as u32);
                        for idx in transfer_input.sig_indices.iter() {
                            packer.pack_u32(*idx);
                        }
                    }
                    21 => {
                        // "platformvm::StakeableLockIn"
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockIn
                        let stakeable_lock_in =
                            transferable_input.stakeable_lock_in.clone().unwrap();

                        // marshal "platformvm::StakeableLockIn.locktime" field
                        packer.pack_u64(stakeable_lock_in.locktime);

                        // "platformvm.StakeableLockIn.TransferableIn" is struct and serialize:"true"
                        // but embedded inline in the struct "StakeableLockIn"
                        // so no need to encode type ID
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#StakeableLockIn
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
                        //
                        // marshal "secp256k1fx.TransferInput.Amt" field
                        packer.pack_u64(stakeable_lock_in.transfer_input.amount);
                        //
                        // "secp256k1fx.TransferInput.Input" is struct and serialize:"true"
                        // but embedded inline in the struct "TransferInput"
                        // so no need to encode type ID
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
                        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
                        packer.pack_u32(stakeable_lock_in.transfer_input.sig_indices.len() as u32);
                        for idx in stakeable_lock_in.transfer_input.sig_indices.iter() {
                            packer.pack_u32(*idx);
                        }
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "unexpected type ID {} for TransferableInpu",
                                type_id_transferable_in
                            ),
                        ));
                    }
                }
            }
        } else {
            packer.pack_u32(0_u32);
        }

        // marshal "BaseTx.memo"
        if self.memo.is_some() {
            let memo = self.memo.as_ref().unwrap();
            packer.pack_u32(memo.len() as u32);
            packer.pack_bytes(memo);
        } else {
            packer.pack_u32(0_u32);
        }

        Ok(packer)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avax::test_base_tx_serialization --exact --show-output
/// ref. "avalanchego/vms/avm.TestBaseTxSerialization"
#[test]
fn test_base_tx_serialization() {
    use crate::soft_key;
    use utils::cmp;

    // ref. "avalanchego/vms/avm/vm_test.go"
    let test_key = soft_key::Key::from_private_key(
        "PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5",
    )
    .expect("failed to load private key");
    let test_key_short_addr = test_key
        .short_address_bytes()
        .expect("failed short_address_bytes");
    let test_key_short_addr = ids::ShortId::from_slice(&test_key_short_addr);

    let unsigned_tx = BaseTx {
        network_id: 10,
        blockchain_id: ids::Id::from_slice(&<Vec<u8>>::from([5, 4, 3, 2, 1])),
        transferable_outputs: Some(vec![TransferableOutput {
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            transfer_output: Some(secp256k1fx::TransferOutput {
                amount: 12345,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![test_key_short_addr],
                },
            }),
            ..TransferableOutput::default()
        }]),
        transferable_inputs: Some(vec![TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, //
                    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, //
                    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, //
                    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, //
                ])),
                output_index: 1,
                ..UtxoId::default()
            },
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            transfer_input: Some(secp256k1fx::TransferInput {
                amount: 54321,
                sig_indices: vec![2],
            }),
            ..TransferableInput::default()
        }]),
        memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
        ..BaseTx::default()
    };
    let unsigned_tx_packer = unsigned_tx
        .pack(0, BaseTx::type_id())
        .expect("failed to pack unsigned_tx");
    let unsigned_tx_bytes = unsigned_tx_packer.take_bytes();

    let expected_unsigned_tx_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // avm.BaseTx type ID
        0x00, 0x00, 0x00, 0x00, //
        //
        // network id
        0x00, 0x00, 0x00, 0x0a, //
        //
        // blockchain id
        0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // outs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "outs[0]" TransferableOutput.asset_id
        0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // "outs[0]" secp256k1fx.TransferOutput type ID
        0x00, 0x00, 0x00, 0x07, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.locktime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.threshold
        0x00, 0x00, 0x00, 0x01, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs[0]
        0xfc, 0xed, 0xa8, 0xf9, 0x0f, 0xcb, 0x5d, 0x30, //
        0x61, 0x4b, 0x99, 0xd7, 0x9f, 0xc4, 0xba, 0xa2, //
        0x93, 0x07, 0x76, 0x26, //
        //
        // ins.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "ins[0]" TransferableInput.utxo_id.tx_id
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, //
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, //
        0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, //
        0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, //
        //
        // "ins[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x01, //
        //
        // "ins[0]" TransferableInput.asset_id
        0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "ins[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x02, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x04, //
        //
        // memo
        0x00, 0x01, 0x02, 0x03, //
    ];
    assert!(cmp::eq_vectors(
        &expected_unsigned_tx_bytes,
        &unsigned_tx_bytes
    ));
}
