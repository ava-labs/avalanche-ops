use std::io::{self, Error, ErrorKind};

use serde::{Deserialize, Serialize};

use crate::{avax, codec, ids, platformvm, secp256k1fx, soft_key};
use utils::{hash, secp256k1r};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#ImportTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedTx
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
    pub source_chain_id: ids::Id,
    pub source_chain_transferable_inputs: Option<Vec<avax::TransferableInput>>,
    pub creds: Vec<secp256k1fx::Credential>,
}

impl Default for Tx {
    fn default() -> Self {
        Self::default()
    }
}

impl Tx {
    pub fn default() -> Self {
        Self {
            unsigned_tx: avax::BaseTx::default(),
            source_chain_id: ids::Id::default(),
            source_chain_transferable_inputs: None,
            creds: Vec::new(),
        }
    }

    pub fn new(unsigned_tx: avax::BaseTx) -> Self {
        Self {
            unsigned_tx,
            ..Self::default()
        }
    }

    /// Returns the transaction ID.
    /// Only non-empty if the embedded metadata is updated
    /// with the signing process.
    pub fn tx_id(&self) -> ids::Id {
        if self.unsigned_tx.metadata.is_some() {
            let m = self.unsigned_tx.metadata.clone().unwrap();
            m.id
        } else {
            ids::Id::default()
        }
    }

    pub fn type_name() -> String {
        "platformvm.UnsignedImportTx".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::P_TYPES.get(&Self::type_name()).unwrap()) as u32
    }

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx.Sign
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#PrivateKeyED25519.SignHash
    /// TODO: support ledger signing
    pub fn sign(&mut self, signers: Option<Vec<Vec<soft_key::Key>>>) -> io::Result<()> {
        // marshal "unsigned tx" with the codec version
        let type_id = Self::type_id();
        let packer = self.unsigned_tx.pack(codec::VERSION, type_id)?;

        // "avalanchego" marshals the whole struct again for signed bytes
        // even when the underlying "unsigned_tx" is already once marshaled
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx.Sign
        //
        // reuse the underlying packer to avoid marshaling the unsigned tx twice
        // just marshal the next fields in the struct and pack them all together
        // in the existing packer
        let unsigned_tx_bytes = packer.take_bytes();

        // pack the first field in the struct
        packer.set_bytes(&unsigned_tx_bytes);

        // pack the second field in the struct
        packer.pack_bytes(&self.source_chain_id.d);

        // pack the third field in the struct
        if self.source_chain_transferable_inputs.is_some() {
            let source_chain_ins = self.source_chain_transferable_inputs.as_ref().unwrap();
            packer.pack_u32(source_chain_ins.len() as u32);

            for transferable_input in source_chain_ins.iter() {
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

        // take bytes just for hashing computation
        let unsigned_tx_bytes = packer.take_bytes();
        packer.set_bytes(&unsigned_tx_bytes);
        // compute sha256 for marshaled "unsigned tx" bytes
        // IMPORTANT: take the hash only for the type "platformvm.UnsignedImportTx" unsigned tx
        // not other fields -- only hash "platformvm.UnsignedImportTx.*" but not "platformvm.Tx.Creds"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedImportTx
        let hash = hash::compute_sha256(&unsigned_tx_bytes);

        // number of of credentials
        let (creds_len, signers) = {
            if let Some(ss) = signers {
                (ss.len() as u32, ss)
            } else {
                (0, Vec::new())
            }
        };
        // pack the fourth field in the struct
        packer.pack_u32(creds_len);

        // sign the hash with the signers (in case of multi-sig)
        // and combine all signatures into a secp256k1fx credential
        self.creds = Vec::new();
        for keys in signers.iter() {
            let mut sigs: Vec<Vec<u8>> = Vec::new();
            for k in keys.iter() {
                let secp = k.secret_key.expect("unexpected empty secret_key");
                let sig = secp256k1r::sign_ecdsa_recoverable(&secp, &hash);
                sigs.push(sig);
            }

            let mut cred = secp256k1fx::Credential::default();
            cred.sigs = sigs;

            // add a new credential to "Tx"
            self.creds.push(cred);
        }
        if creds_len > 0 {
            // pack each "cred" which is "secp256k1fx.Credential"
            // marshal type ID for "secp256k1fx.Credential"
            let cred_type_id = secp256k1fx::Credential::type_id();
            for cred in self.creds.iter() {
                packer.pack_u32(cred_type_id);
                packer.pack_u32(cred.sigs.len() as u32);
                for sig in cred.sigs.iter() {
                    packer.pack_bytes(sig);
                }
            }
        }
        let signed_tx_bytes = packer.take_bytes();
        let tx_id = hash::compute_sha256(&signed_tx_bytes);

        // update "BaseTx.Metadata" with id/unsigned bytes/bytes
        // ref. "avalanchego/vms/platformvm.Tx.SignSECP256K1Fx"
        // ref. "avalanchego/vms/components/avax.BaseTx.Metadata.Initialize"
        self.unsigned_tx.metadata = Some(avax::Metadata {
            id: ids::Id::from_slice(&tx_id),
            unsigned_bytes: unsigned_tx_bytes.to_vec(),
            bytes: signed_tx_bytes.to_vec(),
        });

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::import::test_import_tx_serialization_with_no_signer --exact --show-output
/// ref. "avalanchego/vms/platformvm.TestNewImportTx"
#[test]
fn test_import_tx_serialization_with_no_signer() {
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 10,
            ..avax::BaseTx::default()
        },
        source_chain_id: ids::Id::from_slice(&<Vec<u8>>::from([
            0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
            0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
            0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
            0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        ])),
        source_chain_transferable_inputs: Some(vec![avax::TransferableInput {
            utxo_id: avax::UtxoId {
                tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, //
                    0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, //
                    0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, //
                    0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, //
                ])),
                output_index: 1,
                ..avax::UtxoId::default()
            },
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            ])),
            transfer_input: Some(secp256k1fx::TransferInput {
                amount: 100,
                sig_indices: vec![0],
            }),
            ..avax::TransferableInput::default()
        }]),
        ..Tx::default()
    };

    tx.sign(None).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().to_string(),
        "2Yx2dzD5ACsyiQd9t4invR99FU9k3vQDcSimnLfG87u9V2zq7"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedImportTx type ID
        0x00, 0x00, 0x00, 0x11, //
        //
        // network id
        0x00, 0x00, 0x00, 0x0a, //
        //
        // blockchain id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // outs.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // ins.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // Tx.source_chain
        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
        0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
        0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
        0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        //
        // Tx.source_chain_ins.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.utxo_id.tx_id
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, //
        0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, //
        0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, //
        0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.source_chain_ins[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        //
        // number of of credentials (avax.Tx.creds.len())
        0x00, 0x00, 0x00, 0x00, //
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::import::test_import_tx_serialization_with_one_signer --exact --show-output
/// ref. "avalanchego/vms/platformvm.TestNewImportTx"
#[test]
fn test_import_tx_serialization_with_one_signer() {
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 10,
            ..avax::BaseTx::default()
        },
        source_chain_id: ids::Id::from_slice(&<Vec<u8>>::from([
            0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
            0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
            0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
            0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        ])),
        source_chain_transferable_inputs: Some(vec![avax::TransferableInput {
            utxo_id: avax::UtxoId {
                tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, //
                    0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, //
                    0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, //
                    0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, //
                ])),
                output_index: 1,
                ..avax::UtxoId::default()
            },
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            ])),
            transfer_input: Some(secp256k1fx::TransferInput {
                amount: 100,
                sig_indices: vec![0],
            }),
            ..avax::TransferableInput::default()
        }]),
        ..Tx::default()
    };

    // ref. "avalanchego/vms/platformvm/vm_test.go"
    let test_key = soft_key::Key::from_private_key(
        "PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5",
    )
    .expect("failed to load private key");
    let keys1: Vec<soft_key::Key> = vec![test_key];
    let signers: Vec<Vec<soft_key::Key>> = vec![keys1];
    tx.sign(Some(signers)).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().to_string(),
        "ZzEtfXr19a76z9UwV4fBDeDvSpzsNb7KkA3nNUGqX8X8BJsML"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedImportTx type ID
        0x00, 0x00, 0x00, 0x11, //
        //
        // network id
        0x00, 0x00, 0x00, 0x0a, //
        //
        // blockchain id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // outs.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // ins.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // Tx.source_chain
        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
        0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
        0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
        0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        //
        // Tx.source_chain_ins.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.utxo_id.tx_id
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, //
        0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, //
        0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, //
        0x6d, 0xec, 0x47, 0x2b, 0x25, 0xcf, 0x59, 0xa7, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.source_chain_ins[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.source_chain_ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        //
        // number of of credentials (avax.Tx.creds.len())
        0x00, 0x00, 0x00, 0x01, //
        //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // struct field type ID "fx::Credential.cred"
        // "secp256k1fx.Credential" type ID
        0x00, 0x00, 0x00, 0x09, //
        //
        // number of signers ("fx::Credential.cred.sigs.len()")
        0x00, 0x00, 0x00, 0x01, //
        //
        // first 65-byte signature
        0xe1, 0x8b, 0xeb, 0x85, 0xd5, 0x6b, 0xd1, 0xe1, 0xb5, 0xcb, //
        0x4f, 0x90, 0xa4, 0x98, 0x51, 0xd1, 0xa6, 0x52, 0xf0, 0xf1, //
        0x2b, 0x78, 0x41, 0x3e, 0x8a, 0xa5, 0x6b, 0xef, 0x32, 0xd9, //
        0x7a, 0x45, 0x40, 0xda, 0xe3, 0x58, 0x0c, 0xc4, 0x68, 0x9c, //
        0x8b, 0x21, 0x34, 0x7f, 0x4b, 0xea, 0x46, 0xe4, 0x31, 0x4f, //
        0x14, 0xa0, 0x3e, 0x94, 0x70, 0x55, 0x26, 0x0f, 0xe0, 0x6c, //
        0x95, 0x44, 0x82, 0x3b, 0x01,
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}
