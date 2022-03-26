use std::io::{self, Error, ErrorKind};

use crate::{
    avalanche::types::{codec, formatting, ids, packer, secp256k1fx},
    utils::{hash, prefix},
};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOut
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TransferableOutput {
    pub asset_id: ids::Id,
    pub fx_id: ids::Id, // skip serialization due to serialize:"false"
    pub out: secp256k1fx::TransferOutput,
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
            out: secp256k1fx::TransferOutput::default(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXOID
#[derive(Debug, Eq, PartialEq, Clone)]
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
        let tx_id = ids::Id::new(tx_id);
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

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::avax::test_utxo_id --exact --show-output
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
    let expected_id = ids::Id::new(&expected_id);
    assert_eq!(utxo_id.id, expected_id);
}

/// Do not parse the internal tests.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXO
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Utxo {
    pub tx_id: ids::Id,
    pub output_index: u32,
    pub asset_id: ids::Id,
    pub out: secp256k1fx::TransferOutput,
}

impl Default for Utxo {
    fn default() -> Self {
        Self::default()
    }
}

impl Utxo {
    pub fn default() -> Self {
        Self {
            tx_id: ids::Id::empty(),
            output_index: 0,
            asset_id: ids::Id::empty(),
            out: secp256k1fx::TransferOutput::default(),
        }
    }

    /// Parses the raw hex-encoded data from the "getUTXOs" API.
    pub fn unpack_hex(d: &str) -> io::Result<Self> {
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
        let tx_id = ids::Id::new(&tx_id_bytes);

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
        let asset_id = ids::Id::new(&asset_id_bytes);

        let type_id_secp256k1fx_transfer_output = packer.unpack_u32();
        assert_eq!(type_id_secp256k1fx_transfer_output, 7);

        let output_amount = packer.unpack_u64();
        let locktime = packer.unpack_u64();
        let threshold = packer.unpack_u32();

        // parse output owners for address lists
        let addr_len = packer.unpack_u32();
        let mut addrs: Vec<ids::ShortId> = Vec::new();
        for _ in 0..addr_len {
            let addr = match packer.unpack_bytes(ids::SHORT_ID_LEN) {
                Some(b) => ids::ShortId::new(&b),
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
        let utxo = Utxo {
            tx_id,
            output_index,
            asset_id,
            out: secp256k1fx::TransferOutput {
                amount: output_amount,
                output_owners,
            },
        };
        Ok(utxo)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::avax::test_utxo_unpack_hex --exact --show-output
#[test]
fn test_utxo_unpack_hex() {
    let d = "0x000000000000000000000000000000000000000000000000000000000000000000000000000088eec2e099c6a528e689618e8721e04ae85ea574c7a15a7968644d14d54780140000000702c68af0bb1400000000000000000000000000010000000165844a05405f3662c1928142c6c2a783ef871de939b564db";
    let addr = ids::ShortId::new(&<Vec<u8>>::from([
        101, 132, 74, 5, 64, 95, 54, 98, 193, 146, 129, 66, 198, 194, 167, 131, 239, 135, 29, 233,
    ]));
    let utxo = Utxo::unpack_hex(d).unwrap();
    let expected = Utxo {
        tx_id: ids::Id::empty(),
        output_index: 0,
        asset_id: ids::Id::new(&<Vec<u8>>::from([
            136, 238, 194, 224, 153, 198, 165, 40, 230, 137, 97, 142, 135, 33, 224, 74, 232, 94,
            165, 116, 199, 161, 90, 121, 104, 100, 77, 20, 213, 71, 128, 20,
        ])),
        out: secp256k1fx::TransferOutput {
            amount: 200000000000000000,
            output_owners: secp256k1fx::OutputOwners {
                locktime: 0,
                threshold: 1,
                addrs: vec![addr],
            },
        },
    };
    assert_eq!(utxo, expected);
    println!("{:?}", utxo);
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableIn
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TransferableInput {
    pub utxo_id: UtxoId,
    pub asset_id: ids::Id,
    pub fx_id: ids::Id, // skip serialization due to serialize:"false"
    pub input: secp256k1fx::TransferInput,
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
            input: secp256k1fx::TransferInput::default(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Metadata
#[derive(Debug, Eq, PartialEq, Clone)]
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
        let id = ids::Id::new(&id);
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
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BaseTx {
    pub metadata: Option<Metadata>, // skip serialization due to serialize:"false"
    pub network_id: u32,
    pub blockchain_id: ids::Id,
    pub outs: Option<Vec<TransferableOutput>>,
    pub ins: Option<Vec<TransferableInput>>,
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
            outs: None,
            ins: None,
            memo: None,
        }
    }

    pub fn type_name() -> String {
        "avm.BaseTx".to_string()
    }

    pub fn type_id() -> io::Result<u32> {
        if let Some(type_id) = codec::WALLET_X_TYPES.get("avm.BaseTx") {
            Ok((*type_id) as u32)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("type_id not found for {}", Self::type_name()),
            ));
        }
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

        // "outs" field; pack the number of slice elements
        if self.outs.is_some() {
            let outs = self.outs.as_ref().unwrap();
            packer.pack_u32(outs.len() as u32);
            let transfer_output_type_id = secp256k1fx::TransferOutput::type_id()?;
            for o in outs.iter() {
                // "TransferableOutput.Asset" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableOutput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableOutput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Asset
                packer.pack_bytes(&o.asset_id.d);

                // fx_id is serialize:"false" thus skipping serialization

                // marshal type ID for "secp256k1fx.TransferOutput"
                packer.pack_u32(transfer_output_type_id);

                // marshal "secp256k1fx.TransferOutput.Amt" field
                packer.pack_u64(o.out.amount);

                // "secp256k1fx.TransferOutput.OutputOwners" is struct and serialize:"true"
                // but embedded inline in the struct "TransferOutput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferOutput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#OutputOwners
                packer.pack_u64(o.out.output_owners.locktime);
                packer.pack_u32(o.out.output_owners.threshold);
                packer.pack_u32(o.out.output_owners.addrs.len() as u32);
                for addr in o.out.output_owners.addrs.iter() {
                    packer.pack_bytes(&addr.d);
                }
            }
        } else {
            packer.pack_u32(0_u32);
        }

        // "ins" field; pack the number of slice elements
        if self.ins.is_some() {
            let ins = self.ins.as_ref().unwrap();
            packer.pack_u32(ins.len() as u32);
            let transfer_input_type_id = secp256k1fx::TransferInput::type_id()?;
            for i in ins.iter() {
                // "TransferableInput.UTXOID" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableInput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#UTXOID
                packer.pack_bytes(&i.utxo_id.tx_id.d);
                packer.pack_u32(i.utxo_id.output_index);

                // "TransferableInput.Asset" is struct and serialize:"true"
                // but embedded inline in the struct "TransferableInput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#TransferableInput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/components/avax#Asset
                packer.pack_bytes(&i.asset_id.d);

                // fx_id is serialize:"false" thus skipping serialization

                // marshal type ID for "secp256k1fx.TransferInput"
                packer.pack_u32(transfer_input_type_id);

                // marshal "secp256k1fx.TransferInput.Amt" field
                packer.pack_u64(i.input.amount);

                // "secp256k1fx.TransferInput.Input" is struct and serialize:"true"
                // but embedded inline in the struct "TransferInput"
                // so no need to encode type ID
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#TransferInput
                // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Input
                packer.pack_u32(i.input.sig_indices.len() as u32);
                for idx in i.input.sig_indices.iter() {
                    packer.pack_u32(*idx);
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

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::avax::test_base_tx_serialization --exact --show-output
/// ref. "avalanchego/vms/avm.TestBaseTxSerialization"
#[test]
fn test_base_tx_serialization() {
    use crate::{avalanche::types::key, utils::vector};

    // ref. "avalanchego/vms/avm/vm_test.go"
    let test_key =
        key::Key::from_private_key("PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5")
            .expect("failed to load private key");
    let test_key_short_addr = test_key
        .short_address_bytes()
        .expect("failed short_address_bytes");
    let test_key_short_addr = ids::ShortId::new(&test_key_short_addr);

    let unsigned_tx = BaseTx {
        network_id: 10,
        blockchain_id: ids::Id::new(&<Vec<u8>>::from([5, 4, 3, 2, 1])),
        outs: Some(vec![TransferableOutput {
            asset_id: ids::Id::new(&<Vec<u8>>::from([1, 2, 3])),
            out: secp256k1fx::TransferOutput {
                amount: 12345,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![test_key_short_addr],
                },
            },
            ..TransferableOutput::default()
        }]),
        ins: Some(vec![TransferableInput {
            utxo_id: UtxoId {
                tx_id: ids::Id::new(&<Vec<u8>>::from([
                    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, //
                    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, //
                    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, //
                    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, //
                ])),
                output_index: 1,
                ..UtxoId::default()
            },
            asset_id: ids::Id::new(&<Vec<u8>>::from([1, 2, 3])),
            input: secp256k1fx::TransferInput {
                amount: 54321,
                sig_indices: vec![2],
            },
            ..TransferableInput::default()
        }]),
        memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
        ..BaseTx::default()
    };
    let unsigned_tx_packer = unsigned_tx
        .pack(0, BaseTx::type_id().unwrap())
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
    assert!(vector::eq_u8_vectors(
        &expected_unsigned_tx_bytes,
        &unsigned_tx_bytes
    ));
}
