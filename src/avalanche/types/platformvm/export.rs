use std::io::{self, Error, ErrorKind};

use crate::{
    avalanche::types::{avax, codec, ids, key, secp256k1fx},
    utils::{hash, secp256k1r},
};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#ExportTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedTx
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
    pub destination_chain: ids::Id,
    pub destination_chain_outs: Option<Vec<avax::TransferableOutput>>,
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
            destination_chain: ids::Id::default(),
            destination_chain_outs: None,
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
        "platformvm.UnsignedExportTx".to_string()
    }

    pub fn type_id() -> io::Result<u32> {
        if let Some(type_id) = codec::WALLET_P_TYPES.get("platformvm.UnsignedExportTx") {
            Ok((*type_id) as u32)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("type_id not found for {}", Self::type_name()),
            ));
        }
    }

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx.Sign
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#PrivateKeyED25519.SignHash
    /// TODO: support ledger signing
    pub fn sign(&mut self, signers: Option<Vec<Vec<key::Key>>>) -> io::Result<()> {
        // marshal "unsigned tx" with the codec version
        let type_id = Self::type_id()?;
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
        packer.pack_bytes(&self.destination_chain.d);

        // pack the third field in the struct
        if self.destination_chain_outs.is_some() {
            let destination_chain_outs = self.destination_chain_outs.as_ref().unwrap();
            packer.pack_u32(destination_chain_outs.len() as u32);
            let transfer_output_type_id = secp256k1fx::TransferOutput::type_id()?;
            for o in destination_chain_outs.iter() {
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

        // take bytes just for hashing computation
        let unsigned_tx_bytes = packer.take_bytes();
        packer.set_bytes(&unsigned_tx_bytes);
        // compute sha256 for marshaled "unsigned tx" bytes
        // IMPORTANT: take the hash only for the type "platformvm.UnsignedExportTx" unsigned tx
        // not other fields -- only hash "platformvm.UnsignedExportTx.*" but not "platformvm.Tx.Creds"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedExportTx
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
            let cred_type_id = secp256k1fx::Credential::type_id()?;
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
        // ref. "avalanchego/vms/platformvm.Tx.Sign"
        // ref. "avalanchego/vms/components/avax.BaseTx.Metadata.Initialize"
        self.unsigned_tx.metadata = Some(avax::Metadata {
            id: ids::Id::new(&tx_id),
            unsigned_bytes: unsigned_tx_bytes.to_vec(),
            bytes: signed_tx_bytes.to_vec(),
        });

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::platformvm::export::test_export_tx_serialization_with_no_signer --exact --show-output
/// ref. "avalanchego/vms/platformvm.TestNewExportTx"
#[test]
fn test_export_tx_serialization_with_no_signer() {
    use crate::utils::vector;

    // ref. "avalanchego/vms/platformvm/vm_test.go"
    let target_short_addr = ids::ShortId::new(&<Vec<u8>>::from([
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
    ]));

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 10,
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    id: ids::Id::new(&<Vec<u8>>::from([
                        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, 0x5a, 0xbf, //
                        0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, 0xd3, 0x06, 0x7e, 0xd5, //
                        0x09, 0xff, 0x25, 0xf1, 0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, //
                        0x51, 0xeb,
                    ])),
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::new(&<Vec<u8>>::from([0x79, 0x65, 0x65, 0x74])),
                input: secp256k1fx::TransferInput {
                    amount: 500000000,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            ..avax::BaseTx::default()
        },
        destination_chain: ids::Id::new(&<Vec<u8>>::from([
            0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
            0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
            0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
            0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        ])),
        destination_chain_outs: Some(vec![avax::TransferableOutput {
            asset_id: ids::Id::new(&<Vec<u8>>::from([0x79, 0x65, 0x65, 0x74])),
            out: secp256k1fx::TransferOutput {
                amount: 499999900,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![target_short_addr.clone()],
                },
            },
            ..avax::TransferableOutput::default()
        }]),
        ..Tx::default()
    };

    tx.sign(None).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "HjudJSkC39woaVLD6mKyLJeWfXZkiQQ64pUceHcfRRa6m4dRK"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedExportTx type ID
        0x00, 0x00, 0x00, 0x12, //
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
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.tx_id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xcd, 0x65, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // Tx.destination_chain
        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
        0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
        0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
        0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        //
        // Tx.destination_chain_outs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferOutput type ID
        0x00, 0x00, 0x00, 0x07, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.amount
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xcd, 0x64, 0x9c, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.locktime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.threshold
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs[0]
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
        //
        //
        // number of of credentials (avax.Tx.creds.len())
        0x00, 0x00, 0x00, 0x00, //
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(vector::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- avalanche::types::platformvm::export::test_export_tx_serialization_with_one_signer --exact --show-output
/// ref. "avalanchego/vms/platformvm.TestNewExportTx"
#[test]
fn test_export_tx_serialization_with_one_signer() {
    use crate::utils::vector;

    // ref. "avalanchego/vms/platformvm/vm_test.go"
    let target_short_addr = ids::ShortId::new(&<Vec<u8>>::from([
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
    ]));

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 10,
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    id: ids::Id::new(&<Vec<u8>>::from([
                        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, 0x5a, 0xbf, //
                        0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, 0xd3, 0x06, 0x7e, 0xd5, //
                        0x09, 0xff, 0x25, 0xf1, 0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, //
                        0x51, 0xeb,
                    ])),
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::new(&<Vec<u8>>::from([0x79, 0x65, 0x65, 0x74])),
                input: secp256k1fx::TransferInput {
                    amount: 500000000,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            ..avax::BaseTx::default()
        },
        destination_chain: ids::Id::new(&<Vec<u8>>::from([
            0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
            0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
            0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
            0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        ])),
        destination_chain_outs: Some(vec![avax::TransferableOutput {
            asset_id: ids::Id::new(&<Vec<u8>>::from([0x79, 0x65, 0x65, 0x74])),
            out: secp256k1fx::TransferOutput {
                amount: 499999900,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![target_short_addr.clone()],
                },
            },
            ..avax::TransferableOutput::default()
        }]),
        ..Tx::default()
    };

    // ref. "avalanchego/vms/platformvm/vm_test.go"
    let test_key =
        key::Key::from_private_key("PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5")
            .expect("failed to load private key");
    let keys1: Vec<key::Key> = vec![test_key];
    let signers: Vec<Vec<key::Key>> = vec![keys1];
    tx.sign(Some(signers)).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "xjRjs4pcDFBwJR4kAKMtVHNLQEdhswojNPqXKVgwsjCDsn4rE"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedExportTx type ID
        0x00, 0x00, 0x00, 0x12, //
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
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.tx_id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xcd, 0x65, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // Tx.destination_chain
        0x2c, 0x34, 0xce, 0x1d, 0xf2, 0x3b, 0x83, 0x8c, //
        0x5a, 0xbf, 0x2a, 0x7f, 0x64, 0x37, 0xcc, 0xa3, //
        0xd3, 0x06, 0x7e, 0xd5, 0x09, 0xff, 0x25, 0xf1, //
        0x1d, 0xf6, 0xb1, 0x1b, 0x58, 0x2b, 0x51, 0xeb, //
        //
        // Tx.destination_chain_outs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.asset_id
        0x79, 0x65, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferOutput type ID
        0x00, 0x00, 0x00, 0x07, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.amount
        0x00, 0x00, 0x00, 0x00, 0x1d, 0xcd, 0x64, 0x9c, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.locktime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.threshold
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.output_owners.addrs[0]
        0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, //
        0x8c, 0xa9, 0x1c, 0xa5, 0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, //
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
        0xe2, 0x61, 0x5a, 0xfb, 0x7a, 0xde, 0xc6, 0xf0, 0xa6, 0xba, //
        0x4e, 0x6e, 0x23, 0x51, 0x81, 0xea, 0x3d, 0x82, 0x11, 0xd9, //
        0xc8, 0x89, 0x0d, 0x03, 0x1f, 0xf2, 0x41, 0xe7, 0x4c, 0xb1, //
        0xcd, 0xda, 0x25, 0xa1, 0x87, 0xd8, 0x9a, 0x8f, 0xc8, 0x38, //
        0xcf, 0x82, 0x55, 0xe7, 0xb3, 0x42, 0x90, 0x97, 0xaa, 0xdd, //
        0x2e, 0x5f, 0x1a, 0xfa, 0x67, 0x23, 0xe5, 0xab, 0x37, 0x3c, //
        0x7d, 0x94, 0xca, 0xb8, 0x01,
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(vector::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}
