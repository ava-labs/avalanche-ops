use std::io;

use serde::{Deserialize, Serialize};

use crate::{avax, avm::fx, codec, ids, secp256k1fx, soft_key};
use utils::{hash, secp256k1r};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#UnsignedTx
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
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
            fx_creds: Vec::new(),
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
        "avm.BaseTx".to_string()
    }

    pub fn type_id() -> u32 {
        *(codec::X_TYPES.get(&Self::type_name()).unwrap()) as u32
    }

    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx.SignSECP256K1Fx
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#PrivateKeyED25519.SignHash
    /// TODO: support ledger signing
    pub fn sign(&mut self, signers: Option<Vec<Vec<soft_key::Key>>>) -> io::Result<()> {
        // marshal "unsigned tx" with the codec version
        let type_id = Self::type_id();
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

        // compute sha256 for marshaled "unsigned tx" bytes
        // IMPORTANT: take the hash only for the type "avm.Tx" unsigned tx
        // not other fields -- only hash "avm.Tx.UnsignedTx" but not "avm.Tx.Creds"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/avm#Tx
        let hash = hash::compute_sha256(&unsigned_tx_bytes);

        // number of of credentials
        let (fx_creds_len, signers) = {
            if let Some(ss) = signers {
                (ss.len() as u32, ss)
            } else {
                (0, Vec::new())
            }
        };
        // pack the second field in the struct
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
            let cred_type_id = secp256k1fx::Credential::type_id();
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avm::tx::test_tx_serialization_with_no_signer --exact --show-output
/// ref. "avalanchego/vms/avm.TestBaseTxSerialization"
#[test]
fn test_tx_serialization_with_no_signer() {
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

    let unsigned_tx = avax::BaseTx {
        network_id: 10,
        blockchain_id: ids::Id::from_slice(&<Vec<u8>>::from([5, 4, 3, 2, 1])),
        transferable_outputs: Some(vec![avax::TransferableOutput {
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            transfer_output: Some(secp256k1fx::TransferOutput {
                amount: 12345,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![test_key_short_addr.clone()],
                },
            }),
            ..avax::TransferableOutput::default()
        }]),
        transferable_inputs: Some(vec![avax::TransferableInput {
            utxo_id: avax::UtxoId {
                tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, //
                    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, //
                    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, //
                    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, //
                ])),
                output_index: 1,
                symbol: false,
                id: ids::Id::empty(),
            },
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            fx_id: ids::Id::empty(),
            transfer_input: Some(secp256k1fx::TransferInput {
                amount: 54321,
                sig_indices: vec![2],
            }),
            ..avax::TransferableInput::default()
        }]),
        memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
        ..avax::BaseTx::default()
    };

    let mut tx = Tx::new(unsigned_tx);
    tx.sign(None).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().to_string(),
        "zeqT8FTnRAxes7QQQYkaWhNkHavd9d6aCdH8TQu2Mx5KEydEz"
    );

    let expected_signed_bytes: Vec<u8> = vec![
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
        //
        // number of of credentials (avax.Tx.fx_creds.len())
        0x00, 0x00, 0x00, 0x00, //
    ];
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes,));
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- avm::tx::test_tx_serialization_with_two_signers --exact --show-output
/// ref. "avalanchego/vms/avm.TestBaseTxSerialization"
#[test]
fn test_tx_serialization_with_two_signers() {
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

    let unsigned_tx = avax::BaseTx {
        network_id: 10,
        blockchain_id: ids::Id::from_slice(&<Vec<u8>>::from([5, 4, 3, 2, 1])),
        transferable_outputs: Some(vec![avax::TransferableOutput {
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            transfer_output: Some(secp256k1fx::TransferOutput {
                amount: 12345,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0,
                    threshold: 1,
                    addrs: vec![test_key_short_addr.clone()],
                },
            }),
            ..avax::TransferableOutput::default()
        }]),
        transferable_inputs: Some(vec![avax::TransferableInput {
            utxo_id: avax::UtxoId {
                tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, //
                    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, //
                    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, //
                    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0, //
                ])),
                output_index: 1,
                symbol: false,
                id: ids::Id::empty(),
            },
            asset_id: ids::Id::from_slice(&<Vec<u8>>::from([1, 2, 3])),
            transfer_input: Some(secp256k1fx::TransferInput {
                amount: 54321,
                sig_indices: vec![2],
            }),
            ..avax::TransferableInput::default()
        }]),
        memo: Some(vec![0x00, 0x01, 0x02, 0x03]),
        ..avax::BaseTx::default()
    };

    let keys1: Vec<soft_key::Key> = vec![test_key.clone(), test_key.clone()];
    let keys2: Vec<soft_key::Key> = vec![test_key.clone(), test_key.clone()];
    let signers: Vec<Vec<soft_key::Key>> = vec![keys1, keys2];
    let mut tx_with_two_signers = Tx::new(unsigned_tx);
    tx_with_two_signers
        .sign(Some(signers))
        .expect("failed to sign");
    let tx_with_two_signers_metadata = tx_with_two_signers.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_with_two_signers_metadata.bytes;
    // for c in &signed_bytes_2[expected_signed_bytes_1.len()..] {
    //     println!("{:#02x},", *c);
    // }
    assert_eq!(
        tx_with_two_signers.tx_id().to_string(),
        "QnTUuie2qe6BKyYrC2jqd73bJ828QNhYnZbdA2HWsnVRPjBfV"
    );

    let expected_signed_bytes: Vec<u8> = vec![
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
        0x7d, 0x89, 0x8e, 0xe9, 0x8a, 0xf8, 0x33, 0x5d, 0x37, 0xe6, //
        0xfa, 0xda, 0x0c, 0xbb, 0x44, 0xa1, 0x44, 0x05, 0xd3, 0xbb, //
        0x94, 0x0d, 0xfc, 0x0d, 0x99, 0xa6, 0xd3, 0xff, 0x5c, 0x71, //
        0x5a, 0xff, 0x26, 0xd1, 0x84, 0x84, 0xf2, 0x9b, 0x28, 0x96, //
        0x44, 0x96, 0x8f, 0xed, 0xff, 0xeb, 0x23, 0xe0, 0x30, 0x66, //
        0x5d, 0x73, 0x6d, 0x94, 0xfc, 0x80, 0xbc, 0x73, 0x5f, 0x51, //
        0xc8, 0x06, 0xd7, 0x43, 0x00, //
        //
        // second 65-byte signature
        0x7d, 0x89, 0x8e, 0xe9, 0x8a, 0xf8, 0x33, 0x5d, 0x37, 0xe6, //
        0xfa, 0xda, 0x0c, 0xbb, 0x44, 0xa1, 0x44, 0x05, 0xd3, 0xbb, //
        0x94, 0x0d, 0xfc, 0x0d, 0x99, 0xa6, 0xd3, 0xff, 0x5c, 0x71, //
        0x5a, 0xff, 0x26, 0xd1, 0x84, 0x84, 0xf2, 0x9b, 0x28, 0x96, //
        0x44, 0x96, 0x8f, 0xed, 0xff, 0xeb, 0x23, 0xe0, 0x30, 0x66, //
        0x5d, 0x73, 0x6d, 0x94, 0xfc, 0x80, 0xbc, 0x73, 0x5f, 0x51, //
        0xc8, 0x06, 0xd7, 0x43, 0x00, //
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
        0x7d, 0x89, 0x8e, 0xe9, 0x8a, 0xf8, 0x33, 0x5d, 0x37, 0xe6, //
        0xfa, 0xda, 0x0c, 0xbb, 0x44, 0xa1, 0x44, 0x05, 0xd3, 0xbb, //
        0x94, 0x0d, 0xfc, 0x0d, 0x99, 0xa6, 0xd3, 0xff, 0x5c, 0x71, //
        0x5a, 0xff, 0x26, 0xd1, 0x84, 0x84, 0xf2, 0x9b, 0x28, 0x96, //
        0x44, 0x96, 0x8f, 0xed, 0xff, 0xeb, 0x23, 0xe0, 0x30, 0x66, //
        0x5d, 0x73, 0x6d, 0x94, 0xfc, 0x80, 0xbc, 0x73, 0x5f, 0x51, //
        0xc8, 0x06, 0xd7, 0x43, 0x00, //
        //
        // second 65-byte signature
        0x7d, 0x89, 0x8e, 0xe9, 0x8a, 0xf8, 0x33, 0x5d, 0x37, 0xe6, //
        0xfa, 0xda, 0x0c, 0xbb, 0x44, 0xa1, 0x44, 0x05, 0xd3, 0xbb, //
        0x94, 0x0d, 0xfc, 0x0d, 0x99, 0xa6, 0xd3, 0xff, 0x5c, 0x71, //
        0x5a, 0xff, 0x26, 0xd1, 0x84, 0x84, 0xf2, 0x9b, 0x28, 0x96, //
        0x44, 0x96, 0x8f, 0xed, 0xff, 0xeb, 0x23, 0xe0, 0x30, 0x66, //
        0x5d, 0x73, 0x6d, 0x94, 0xfc, 0x80, 0xbc, 0x73, 0x5f, 0x51, //
        0xc8, 0x06, 0xd7, 0x43, 0x00, //
    ];
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes,));
}
