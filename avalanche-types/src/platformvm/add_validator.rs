use std::io::{self, Error, ErrorKind};

use crate::{avax, codec, ids, key, platformvm, secp256k1fx};
use utils::{hash, secp256k1r};

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedAddValidatorTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedTx
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
    pub validator: platformvm::Validator,
    pub stake_outputs: Option<Vec<avax::TransferableOutput>>,
    pub rewards_owner: secp256k1fx::OutputOwners,
    pub shares: u32,
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
            validator: platformvm::Validator::default(),
            stake_outputs: None,
            rewards_owner: secp256k1fx::OutputOwners::default(),
            shares: 0,
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
        "platformvm.UnsignedAddValidatorTx".to_string()
    }

    pub fn type_id() -> io::Result<u32> {
        if let Some(type_id) = codec::WALLET_P_TYPES.get("platformvm.UnsignedAddValidatorTx") {
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

        // pack the second field "validator" in the struct
        packer.pack_bytes(&self.validator.node_id.d);
        packer.pack_u64(self.validator.start);
        packer.pack_u64(self.validator.end);
        packer.pack_u64(self.validator.weight);

        // pack the third field "stake" in the struct
        if self.stake_outputs.is_some() {
            let stake = self.stake_outputs.as_ref().unwrap();
            packer.pack_u32(stake.len() as u32);
            let transfer_output_type_id = secp256k1fx::TransferOutput::type_id()?;
            for o in stake.iter() {
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

        // pack the fourth field "reward_owner" in the struct
        // not embedded thus encode struct type id
        let output_owners_type_id = secp256k1fx::OutputOwners::type_id()?;
        packer.pack_u32(output_owners_type_id);
        packer.pack_u64(self.rewards_owner.locktime);
        packer.pack_u32(self.rewards_owner.threshold);
        packer.pack_u32(self.rewards_owner.addrs.len() as u32);
        for addr in self.rewards_owner.addrs.iter() {
            packer.pack_bytes(&addr.d);
        }

        // pack the fifth field "shares" in the struct
        packer.pack_u32(self.shares);

        // take bytes just for hashing computation
        let unsigned_tx_bytes = packer.take_bytes();
        packer.set_bytes(&unsigned_tx_bytes);
        // compute sha256 for marshaled "unsigned tx" bytes
        // IMPORTANT: take the hash only for the type "platformvm.UnsignedAddValidatorTx" unsigned tx
        // not other fields -- only hash "platformvm.UnsignedAddValidatorTx.*" but not "platformvm.Tx.Creds"
        // ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedAddValidatorTx
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::add_validator::test_add_validator_tx_serialization_with_one_signer --exact --show-output
#[test]
fn test_add_validator_tx_serialization_with_one_signer() {
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 1000000,
            outs: Some(vec![avax::TransferableOutput {
                asset_id: ids::Id::new(&<Vec<u8>>::from([
                    0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, //
                    0xe6, 0x89, 0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, //
                    0xe8, 0x5e, 0xa5, 0x74, 0xc7, 0xa1, 0x5a, 0x79, //
                    0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, 0x80, 0x14, //
                ])),
                out: secp256k1fx::TransferOutput {
                    amount: 0x2c6874d687fc000,
                    output_owners: secp256k1fx::OutputOwners {
                        locktime: 0x00,
                        threshold: 0x01,
                        addrs: vec![ids::ShortId::new(&<Vec<u8>>::from([
                            0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
                            0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
                        ]))],
                    },
                },
                ..avax::TransferableOutput::default()
            }]),
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    tx_id: ids::Id::new(&<Vec<u8>>::from([
                        0x78, 0x3b, 0x22, 0xc6, 0xa8, 0xd6, 0x83, 0x4c, 0x89, 0x30, //
                        0xae, 0xac, 0x3d, 0xb6, 0x02, 0x63, 0xc1, 0x2e, 0x98, 0x16, //
                        0x0e, 0xf7, 0x22, 0x1b, 0x4d, 0x5e, 0x62, 0x2e, 0x87, 0x0f, //
                        0x92, 0xd9,
                    ])),
                    output_index: 0,
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::new(&<Vec<u8>>::from([
                    0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, //
                    0xe6, 0x89, 0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, //
                    0xe8, 0x5e, 0xa5, 0x74, 0xc7, 0xa1, 0x5a, 0x79, //
                    0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, 0x80, 0x14, //
                ])),
                input: secp256k1fx::TransferInput {
                    amount: 0x2c6891f11c9e000,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            ..avax::BaseTx::default()
        },
        validator: platformvm::Validator {
            node_id: ids::ShortId::new(&<Vec<u8>>::from([
                0x9c, 0xd7, 0xb3, 0xe4, 0x79, 0x04, 0xf6, 0x7c, 0xc4, 0x8e, //
                0xb5, 0xb9, 0xaf, 0xdb, 0x03, 0xe6, 0xd1, 0x8a, 0xcf, 0x6c, //
            ])),
            start: 0x623d7267,
            end: 0x63c91062,
            weight: 0x1d1a94a2000,
        },
        stake_outputs: Some(vec![avax::TransferableOutput {
            asset_id: ids::Id::new(&<Vec<u8>>::from([
                0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, //
                0xe6, 0x89, 0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, //
                0xe8, 0x5e, 0xa5, 0x74, 0xc7, 0xa1, 0x5a, 0x79, //
                0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, 0x80, 0x14, //
            ])),
            out: secp256k1fx::TransferOutput {
                amount: 0x1d1a94a2000,
                output_owners: secp256k1fx::OutputOwners {
                    locktime: 0x00,
                    threshold: 0x01,
                    addrs: vec![ids::ShortId::new(&<Vec<u8>>::from([
                        0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
                        0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
                    ]))],
                },
            },
            ..avax::TransferableOutput::default()
        }]),
        rewards_owner: secp256k1fx::OutputOwners {
            locktime: 0x00,
            threshold: 0x01,
            addrs: vec![ids::ShortId::new(&<Vec<u8>>::from([
                0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
                0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
            ]))],
        },
        shares: 0x4e20,
        ..Tx::default()
    };

    let test_key =
        key::Key::from_private_key("PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67")
            .expect("failed to load private key");
    let keys1: Vec<key::Key> = vec![test_key];
    let signers: Vec<Vec<key::Key>> = vec![keys1];
    tx.sign(Some(signers)).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "SPG7CSVMSkXSxnCWQnaENXFHKuzxuCYDGBSKVqsQtqx7WvwJ8"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedAddValidatorTx type ID
        0x00, 0x00, 0x00, 0x0c, //
        //
        // network id
        0x00, 0x0f, 0x42, 0x40, //
        //
        // blockchain id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, //
        //
        // outs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "outs[0]" TransferableOutput.asset_id
        0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, 0xe6, 0x89, //
        0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, 0xe8, 0x5e, 0xa5, 0x74, //
        0xc7, 0xa1, 0x5a, 0x79, 0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, //
        0x80, 0x14, //
        //
        // NOTE: fx_id is serialize:"false"
        //
        // "outs[0]" secp256k1fx.TransferOutput type ID
        0x00, 0x00, 0x00, 0x07, //
        //
        // "outs[0]" TransferableOutput.out.secp256k1fx::TransferOutput.amount
        0x02, 0xc6, 0x87, 0x4d, 0x68, 0x7f, 0xc0, 0x00, //
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
        0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
        0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
        //
        // ins.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "ins[0]" TransferableInput.utxo_id.tx_id
        0x78, 0x3b, 0x22, 0xc6, 0xa8, 0xd6, 0x83, 0x4c, 0x89, 0x30, //
        0xae, 0xac, 0x3d, 0xb6, 0x02, 0x63, 0xc1, 0x2e, 0x98, 0x16, //
        0x0e, 0xf7, 0x22, 0x1b, 0x4d, 0x5e, 0x62, 0x2e, 0x87, 0x0f, //
        0x92, 0xd9, //
        //
        // "ins[0]" TransferableInput.utxo_id.output_index
        0x00, 0x00, 0x00, 0x00, //
        //
        // "ins[0]" TransferableInput.asset_id
        0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, 0xe6, 0x89, //
        0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, 0xe8, 0x5e, 0xa5, 0x74, //
        0xc7, 0xa1, 0x5a, 0x79, 0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, //
        0x80, 0x14, //
        //
        // "ins[0]" secp256k1fx.TransferInput type ID
        0x00, 0x00, 0x00, 0x05, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.amount
        0x02, 0xc6, 0x89, 0x1f, 0x11, 0xc9, 0xe0, 0x00, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // "ins[0]" TransferableInput.input.secp256k1fx::TransferInput.sig_indices[0]
        0x00, 0x00, 0x00, 0x00, //
        //
        // memo.len()
        0x00, 0x00, 0x00, 0x00, //
        //
        // Validator.validator.node_id
        0x9c, 0xd7, 0xb3, 0xe4, 0x79, 0x04, 0xf6, 0x7c, 0xc4, 0x8e, //
        0xb5, 0xb9, 0xaf, 0xdb, 0x03, 0xe6, 0xd1, 0x8a, 0xcf, 0x6c, //
        //
        // Validator.validator.start
        0x00, 0x00, 0x00, 0x00, 0x62, 0x3d, 0x72, 0x67, //
        //
        // Validator.validator.end
        0x00, 0x00, 0x00, 0x00, 0x63, 0xc9, 0x10, 0x62, //
        //
        // Validator.validator.weight
        0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, //
        //
        // stake_outputs.len
        0x00, 0x00, 0x00, 0x01, //
        //
        // stake_outputs[0].asset_id
        0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, 0xe6, 0x89, //
        0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, 0xe8, 0x5e, 0xa5, 0x74, //
        0xc7, 0xa1, 0x5a, 0x79, 0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, //
        0x80, 0x14, //
        //
        // secp256k1fx.TransferOutput type ID
        0x00, 0x00, 0x00, 0x07, //
        //
        // stake_outputs[0].amount
        0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, //
        //
        // locktime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // threshold
        0x00, 0x00, 0x00, 0x01, //
        //
        // addrs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // addrs[0]
        0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
        0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
        //
        // secp256k1fx.OutputOwners type id
        0x00, 0x00, 0x00, 0x0b, //
        //
        // locktime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        //
        // threshold
        0x00, 0x00, 0x00, 0x01, //
        //
        // addrs.len()
        0x00, 0x00, 0x00, 0x01, //
        //
        // addrs[0]
        0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
        0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
        //
        // reward shares
        0x00, 0x00, 0x4e, 0x20, //
        //
        // number of credentials
        0x00, 0x00, 0x00, 0x01, //
        //
        // struct field type ID "fx::Credential.cred"
        // "secp256k1fx.Credential" type ID
        0x00, 0x00, 0x00, 0x09, //
        //
        // number of signers ("fx::Credential.cred.sigs.len()")
        0x00, 0x00, 0x00, 0x01, //
        //
        // first 65-byte signature
        0x83, 0xa8, 0x63, 0xc8, 0x90, 0x02, 0xab, 0x70, 0xa1, 0x2c, //
        0x37, 0x80, 0x22, 0x84, 0xb7, 0x03, 0xc1, 0x65, 0x3a, 0x93, //
        0xa0, 0xa2, 0x5e, 0x04, 0x51, 0xf0, 0xda, 0xa0, 0x79, 0x16, //
        0xa3, 0x24, 0x71, 0xb1, 0x65, 0xbb, 0x4b, 0x1b, 0xd1, 0xb6, //
        0xed, 0xc6, 0xb4, 0x94, 0xbc, 0x6a, 0xac, 0x63, 0xc2, 0x4f, //
        0xcc, 0xfd, 0x9a, 0x54, 0x7b, 0x5f, 0x03, 0xa6, 0x02, 0x52, //
        0xd4, 0x5c, 0x24, 0x80, 0x00,
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}