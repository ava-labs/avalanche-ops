use std::io::{self, Error, ErrorKind};

use crate::{avax, avm::fx, codec, ids, secp256k1fx, soft_key};
use utils::{hash, secp256k1r};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#ExportTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#UnsignedTx
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
    pub destination_chain: ids::Id,
    pub destination_chain_outs: Option<Vec<avax::TransferableOutput>>,
    pub fx_creds: Vec<fx::Credential>,
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
            fx_creds: Vec::new(),
        }
    }

    pub fn new(unsigned_tx: avax::BaseTx) -> Self {
        Self {
            unsigned_tx,
            ..Self::default()
        }
    }

    pub fn type_name() -> String {
        "avm.ExportTx".to_string()
    }

    pub fn type_id() -> io::Result<u32> {
        if let Some(type_id) = codec::X_TYPES.get("avm.ExportTx") {
            Ok((*type_id) as u32)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("type_id not found for {}", Self::type_name()),
            ));
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

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx.SignSECP256K1Fx
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#PrivateKeyED25519.SignHash
    /// TODO: support ledger signing
    pub fn sign(&mut self, signers: Option<Vec<Vec<soft_key::Key>>>) -> io::Result<()> {
        // marshal "unsigned tx" with the codec version
        let type_id = Self::type_id()?;
        let packer = self.unsigned_tx.pack(codec::VERSION, type_id)?;

        // "avalanchego" marshals the whole struct again for signed bytes
        // even when the underlying "unsigned_tx" is already once marshaled
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx.SignSECP256K1Fx
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
        // IMPORTANT: take the hash only for the type "avm.ExportTx" unsigned tx
        // not other fields -- only hash "avm.ExportTx.*" but not "avm.Tx.Creds"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#ExportTx
        let hash = hash::compute_sha256(&unsigned_tx_bytes);

        // number of of credentials
        let (fx_creds_len, signers) = {
            if let Some(ss) = signers {
                (ss.len() as u32, ss)
            } else {
                (0, Vec::new())
            }
        };
        // pack the fourth field in the struct
        packer.pack_u32(fx_creds_len);

        // sign the hash with the signers (in case of multi-sig)
        // and combine all signatures into a secp256k1fx credential
        self.fx_creds = Vec::new();
        for keys in signers.iter() {
            let mut sigs: Vec<Vec<u8>> = Vec::new();
            for k in keys.iter() {
                let secp = k.secret_key.expect("unexpected empty secret_key");
                let sig = secp256k1r::sign_ecdsa_recoverable(&secp, &hash);
                sigs.push(sig);
            }

            let mut cred = secp256k1fx::Credential::default();
            cred.sigs = sigs;

            let mut fx_cred = fx::Credential::default();
            fx_cred.cred = cred;

            // add a new credential to "Tx"
            self.fx_creds.push(fx_cred);
        }
        if fx_creds_len > 0 {
            // pack each "fx_cred" which is "secp256k1fx.Credential"
            // marshal type ID for "secp256k1fx.Credential"
            let cred_type_id = secp256k1fx::Credential::type_id()?;
            for fx_cred in self.fx_creds.iter() {
                packer.pack_u32(cred_type_id);
                packer.pack_u32(fx_cred.cred.sigs.len() as u32);
                for sig in fx_cred.cred.sigs.iter() {
                    packer.pack_bytes(sig);
                }
            }
        }
        let signed_tx_bytes = packer.take_bytes();
        let tx_id = hash::compute_sha256(&signed_tx_bytes);

        // update "BaseTx.Metadata" with id/unsigned bytes/bytes
        // ref. "avalanchego/vms/avm.Tx.SignSECP256K1Fx"
        // ref. "avalanchego/vms/components/avax.BaseTx.Metadata.Initialize"
        self.unsigned_tx.metadata = Some(avax::Metadata {
            id: ids::Id::from_slice(&tx_id),
            unsigned_bytes: unsigned_tx_bytes.to_vec(),
            bytes: signed_tx_bytes.to_vec(),
        });

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avm::export::test_export_tx_serialization_with_no_signer --exact --show-output
/// ref. "avalanchego/vms/avm.TestExportTxSerialization"
#[test]
fn test_export_tx_serialization_with_no_signer() {
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 2,
            blockchain_id: ids::Id::from_slice(&<Vec<u8>>::from([
                0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, //
                0xdd, 0xdd, 0xdd, 0xdd, 0xcc, 0xcc, 0xcc, 0xcc, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, //
                0x99, 0x99, 0x99, 0x99, 0x88, 0x88, 0x88, 0x88, //
            ])),
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                        0x0f, 0x2f, 0x4f, 0x6f, 0x8e, 0xae, 0xce, 0xee, //
                        0x0d, 0x2d, 0x4d, 0x6d, 0x8c, 0xac, 0xcc, 0xec, //
                        0x0b, 0x2b, 0x4b, 0x6b, 0x8a, 0xaa, 0xca, 0xea, //
                        0x09, 0x29, 0x49, 0x69, 0x88, 0xa8, 0xc8, 0xe8, //
                    ])),
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x1f, 0x3f, 0x5f, 0x7f, 0x9e, 0xbe, 0xde, 0xfe, //
                    0x1d, 0x3d, 0x5d, 0x7d, 0x9c, 0xbc, 0xdc, 0xfc, //
                    0x1b, 0x3b, 0x5b, 0x7b, 0x9a, 0xba, 0xda, 0xfa, //
                    0x19, 0x39, 0x59, 0x79, 0x98, 0xb8, 0xd8, 0xf8, //
                ])),
                input: secp256k1fx::TransferInput {
                    amount: 1000,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
            ..avax::BaseTx::default()
        },
        destination_chain: ids::Id::from_slice(&<Vec<u8>>::from([
            0x1f, 0x8f, 0x9f, 0x0f, 0x1e, 0x8e, 0x9e, 0x0e, //
            0x2d, 0x7d, 0xad, 0xfd, 0x2c, 0x7c, 0xac, 0xfc, //
            0x3b, 0x6b, 0xbb, 0xeb, 0x3a, 0x6a, 0xba, 0xea, //
            0x49, 0x59, 0xc9, 0xd9, 0x48, 0x58, 0xc8, 0xd8, //
        ])),
        ..Tx::default()
    };

    tx.sign(None).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "2PKJE4TrKYpgynBFCpNPpV3GHK7d9QTgrL5mpYG6abHKDvNBG3"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // avm.ExportTx type ID
        0x00, 0x00, 0x00, 0x04, //
        //
        // network id
        0x00, 0x00, 0x00, 0x02, //
        //
        // blockchain id
        0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, //
        0xdd, 0xdd, 0xdd, 0xdd, 0xcc, 0xcc, 0xcc, 0xcc, //
        0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, //
        0x99, 0x99, 0x99, 0x99, 0x88, 0x88, 0x88, 0x88, //
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
        0x0f, 0x2f, 0x4f, 0x6f, 0x8e, 0xae, 0xce, 0xee, //
        0x0d, 0x2d, 0x4d, 0x6d, 0x8c, 0xac, 0xcc, 0xec, //
        0x0b, 0x2b, 0x4b, 0x6b, 0x8a, 0xaa, 0xca, 0xea, //
        0x09, 0x29, 0x49, 0x69, 0x88, 0xa8, 0xc8, 0xe8, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.asset_id
        0x1f, 0x3f, 0x5f, 0x7f, 0x9e, 0xbe, 0xde, 0xfe, //
        0x1d, 0x3d, 0x5d, 0x7d, 0x9c, 0xbc, 0xdc, 0xfc, //
        0x1b, 0x3b, 0x5b, 0x7b, 0x9a, 0xba, 0xda, 0xfa, //
        0x19, 0x39, 0x59, 0x79, 0x98, 0xb8, 0xd8, 0xf8, //
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x04, //
        //
        // memo
        0x00, 0x01, 0x02, 0x03, //
        //
        // Tx.destination_chain
        0x1f, 0x8f, 0x9f, 0x0f, 0x1e, 0x8e, 0x9e, 0x0e, //
        0x2d, 0x7d, 0xad, 0xfd, 0x2c, 0x7c, 0xac, 0xfc, //
        0x3b, 0x6b, 0xbb, 0xeb, 0x3a, 0x6a, 0xba, 0xea, //
        0x49, 0x59, 0xc9, 0xd9, 0x48, 0x58, 0xc8, 0xd8, //
        //
        // Tx.destination_chain_outs.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // number of of credentials (avax.Tx.fx_creds.len())
        0x00, 0x00, 0x00, 0x00, //
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avm::export::test_export_tx_serialization_with_two_signers --exact --show-output
/// ref. "avalanchego/vms/avm.TestExportTxSerialization"
#[test]
fn test_export_tx_serialization_with_two_signers() {
    use crate::soft_key;
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 2,
            blockchain_id: ids::Id::from_slice(&<Vec<u8>>::from([
                0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, //
                0xdd, 0xdd, 0xdd, 0xdd, 0xcc, 0xcc, 0xcc, 0xcc, //
                0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, //
                0x99, 0x99, 0x99, 0x99, 0x88, 0x88, 0x88, 0x88, //
            ])),
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                        0x0f, 0x2f, 0x4f, 0x6f, 0x8e, 0xae, 0xce, 0xee, //
                        0x0d, 0x2d, 0x4d, 0x6d, 0x8c, 0xac, 0xcc, 0xec, //
                        0x0b, 0x2b, 0x4b, 0x6b, 0x8a, 0xaa, 0xca, 0xea, //
                        0x09, 0x29, 0x49, 0x69, 0x88, 0xa8, 0xc8, 0xe8, //
                    ])),
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x1f, 0x3f, 0x5f, 0x7f, 0x9e, 0xbe, 0xde, 0xfe, //
                    0x1d, 0x3d, 0x5d, 0x7d, 0x9c, 0xbc, 0xdc, 0xfc, //
                    0x1b, 0x3b, 0x5b, 0x7b, 0x9a, 0xba, 0xda, 0xfa, //
                    0x19, 0x39, 0x59, 0x79, 0x98, 0xb8, 0xd8, 0xf8, //
                ])),
                input: secp256k1fx::TransferInput {
                    amount: 1000,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
            ..avax::BaseTx::default()
        },
        destination_chain: ids::Id::from_slice(&<Vec<u8>>::from([
            0x1f, 0x8f, 0x9f, 0x0f, 0x1e, 0x8e, 0x9e, 0x0e, //
            0x2d, 0x7d, 0xad, 0xfd, 0x2c, 0x7c, 0xac, 0xfc, //
            0x3b, 0x6b, 0xbb, 0xeb, 0x3a, 0x6a, 0xba, 0xea, //
            0x49, 0x59, 0xc9, 0xd9, 0x48, 0x58, 0xc8, 0xd8, //
        ])),
        ..Tx::default()
    };

    // ref. "avalanchego/vms/avm/vm_test.go"
    let test_key = soft_key::Key::from_private_key(
        "PrivateKey-24jUJ9vZexUM6expyMcT48LBx27k1m7xpraoV62oSQAHdziao5",
    )
    .expect("failed to load private key");
    let keys1: Vec<soft_key::Key> = vec![test_key.clone(), test_key.clone()];
    let keys2: Vec<soft_key::Key> = vec![test_key.clone(), test_key.clone()];
    let signers: Vec<Vec<soft_key::Key>> = vec![keys1, keys2];
    tx.sign(Some(signers)).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "2oG52e7Cb7XF1yUzv3pRFndAypgbpswWRcSAKD5SH5VgaiTm5D"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // avm.ExportTx type ID
        0x00, 0x00, 0x00, 0x04, //
        //
        // network id
        0x00, 0x00, 0x00, 0x02, //
        //
        // blockchain id
        0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, //
        0xdd, 0xdd, 0xdd, 0xdd, 0xcc, 0xcc, 0xcc, 0xcc, //
        0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, //
        0x99, 0x99, 0x99, 0x99, 0x88, 0x88, 0x88, 0x88, //
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
        0x0f, 0x2f, 0x4f, 0x6f, 0x8e, 0xae, 0xce, 0xee, //
        0x0d, 0x2d, 0x4d, 0x6d, 0x8c, 0xac, 0xcc, 0xec, //
        0x0b, 0x2b, 0x4b, 0x6b, 0x8a, 0xaa, 0xca, 0xea, //
        0x09, 0x29, 0x49, 0x69, 0x88, 0xa8, 0xc8, 0xe8, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x00, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.asset_id
        0x1f, 0x3f, 0x5f, 0x7f, 0x9e, 0xbe, 0xde, 0xfe, //
        0x1d, 0x3d, 0x5d, 0x7d, 0x9c, 0xbc, 0xdc, 0xfc, //
        0x1b, 0x3b, 0x5b, 0x7b, 0x9a, 0xba, 0xda, 0xfa, //
        0x19, 0x39, 0x59, 0x79, 0x98, 0xb8, 0xd8, 0xf8, //
        //
        // "Tx.destination_chain_outs[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "Tx.destination_chain_outs[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x04, //
        //
        // memo
        0x00, 0x01, 0x02, 0x03, //
        //
        // Tx.destination_chain
        0x1f, 0x8f, 0x9f, 0x0f, 0x1e, 0x8e, 0x9e, 0x0e, //
        0x2d, 0x7d, 0xad, 0xfd, 0x2c, 0x7c, 0xac, 0xfc, //
        0x3b, 0x6b, 0xbb, 0xeb, 0x3a, 0x6a, 0xba, 0xea, //
        0x49, 0x59, 0xc9, 0xd9, 0x48, 0x58, 0xc8, 0xd8, //
        //
        // Tx.destination_chain_outs.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // number of of credentials (avax.Tx.fx_creds.len())
        0x00, 0x00, 0x00, 0x02, //
        //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // struct field type ID "fx::Credential.cred"
        // "secp256k1fx.Credential" type ID
        0x00, 0x00, 0x00, 0x09, //
        //
        // number of signers ("fx::Credential.cred.sigs.len()")
        0x00, 0x00, 0x00, 0x02, //
        //
        // first 65-byte signature
        0x61, 0xdd, 0x9b, 0xff, 0xc0, 0x49, 0x95, 0x6e, 0xd7, 0xf8, //
        0xcd, 0x92, 0xec, 0xda, 0x03, 0x6e, 0xac, 0xb8, 0x16, 0x9e, //
        0x53, 0x83, 0xc0, 0x3a, 0x2e, 0x88, 0x5b, 0x5f, 0xc6, 0xef, //
        0x2e, 0xbe, 0x50, 0x59, 0x72, 0x8d, 0x0f, 0xa6, 0x59, 0x66, //
        0x93, 0x28, 0x88, 0xb4, 0x56, 0x3b, 0x77, 0x7c, 0x59, 0xa5, //
        0x8f, 0xe0, 0x2a, 0xf3, 0xcc, 0x31, 0x32, 0xef, 0xfe, 0x7d, //
        0x3d, 0x9f, 0x14, 0x94, 0x01, //
        //
        // second 65-byte signature
        0x61, 0xdd, 0x9b, 0xff, 0xc0, 0x49, 0x95, 0x6e, 0xd7, 0xf8, //
        0xcd, 0x92, 0xec, 0xda, 0x03, 0x6e, 0xac, 0xb8, 0x16, 0x9e, //
        0x53, 0x83, 0xc0, 0x3a, 0x2e, 0x88, 0x5b, 0x5f, 0xc6, 0xef, //
        0x2e, 0xbe, 0x50, 0x59, 0x72, 0x8d, 0x0f, 0xa6, 0x59, 0x66, //
        0x93, 0x28, 0x88, 0xb4, 0x56, 0x3b, 0x77, 0x7c, 0x59, 0xa5, //
        0x8f, 0xe0, 0x2a, 0xf3, 0xcc, 0x31, 0x32, 0xef, 0xfe, 0x7d, //
        0x3d, 0x9f, 0x14, 0x94, 0x01, //
        //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // struct field type ID "fx::Credential.cred"
        // "secp256k1fx.Credential" type ID
        0x00, 0x00, 0x00, 0x09, //
        //
        // number of signers ("fx::Credential.cred.sigs.len()")
        0x00, 0x00, 0x00, 0x02, //
        //
        // first 65-byte signature
        0x61, 0xdd, 0x9b, 0xff, 0xc0, 0x49, 0x95, 0x6e, 0xd7, 0xf8, //
        0xcd, 0x92, 0xec, 0xda, 0x03, 0x6e, 0xac, 0xb8, 0x16, 0x9e, //
        0x53, 0x83, 0xc0, 0x3a, 0x2e, 0x88, 0x5b, 0x5f, 0xc6, 0xef, //
        0x2e, 0xbe, 0x50, 0x59, 0x72, 0x8d, 0x0f, 0xa6, 0x59, 0x66, //
        0x93, 0x28, 0x88, 0xb4, 0x56, 0x3b, 0x77, 0x7c, 0x59, 0xa5, //
        0x8f, 0xe0, 0x2a, 0xf3, 0xcc, 0x31, 0x32, 0xef, 0xfe, 0x7d, //
        0x3d, 0x9f, 0x14, 0x94, 0x01, //
        //
        // second 65-byte signature
        0x61, 0xdd, 0x9b, 0xff, 0xc0, 0x49, 0x95, 0x6e, 0xd7, 0xf8, //
        0xcd, 0x92, 0xec, 0xda, 0x03, 0x6e, 0xac, 0xb8, 0x16, 0x9e, //
        0x53, 0x83, 0xc0, 0x3a, 0x2e, 0x88, 0x5b, 0x5f, 0xc6, 0xef, //
        0x2e, 0xbe, 0x50, 0x59, 0x72, 0x8d, 0x0f, 0xa6, 0x59, 0x66, //
        0x93, 0x28, 0x88, 0xb4, 0x56, 0x3b, 0x77, 0x7c, 0x59, 0xa5, //
        0x8f, 0xe0, 0x2a, 0xf3, 0xcc, 0x31, 0x32, 0xef, 0xfe, 0x7d, //
        0x3d, 0x9f, 0x14, 0x94, 0x01, //
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}
