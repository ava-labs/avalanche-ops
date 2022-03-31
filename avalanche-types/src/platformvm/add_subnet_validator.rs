use std::io::{self, Error, ErrorKind};

use crate::{avax, codec, ids, platformvm, secp256k1fx, soft_key};
use utils::{hash, secp256k1r};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Validator {
    pub validator: platformvm::Validator,
    pub subnet_id: ids::Id,
}

impl Default for Validator {
    fn default() -> Self {
        Self::default()
    }
}

impl Validator {
    pub fn default() -> Self {
        Self {
            validator: platformvm::Validator::default(),
            subnet_id: ids::Id::empty(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#Tx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedAddSubnetValidatorTx
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#UnsignedTx
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Tx {
    /// The transaction ID is empty for unsigned tx
    /// as long as "avax.BaseTx.Metadata" is "None".
    /// Once Metadata is updated with signing and "Tx.Initialize",
    /// Tx.ID() is non-empty.
    pub unsigned_tx: avax::BaseTx,
    pub validator: Validator,
    pub subnet_auth: secp256k1fx::Input,
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
            validator: Validator::default(),
            subnet_auth: secp256k1fx::Input::default(),
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
        "platformvm.UnsignedAddSubnetValidatorTx".to_string()
    }

    pub fn type_id() -> io::Result<u32> {
        if let Some(type_id) = codec::P_TYPES.get("platformvm.UnsignedAddSubnetValidatorTx") {
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
    pub fn sign(&mut self, signers: Option<Vec<Vec<soft_key::Key>>>) -> io::Result<()> {
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
        packer.pack_bytes(&self.validator.validator.node_id.d);
        packer.pack_u64(self.validator.validator.start);
        packer.pack_u64(self.validator.validator.end);
        packer.pack_u64(self.validator.validator.weight);
        packer.pack_bytes(&self.validator.subnet_id.d);

        // pack the third field "subnet_auth" in the struct
        let subnet_auth_type_id = secp256k1fx::Input::type_id()?;
        packer.pack_u32(subnet_auth_type_id);
        packer.pack_u32(self.subnet_auth.sig_indices.len() as u32);
        for sig_idx in self.subnet_auth.sig_indices.iter() {
            packer.pack_u32(*sig_idx);
        }

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
            id: ids::Id::from_slice(&tx_id),
            unsigned_bytes: unsigned_tx_bytes.to_vec(),
            bytes: signed_tx_bytes.to_vec(),
        });

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- platformvm::add_subnet_validator::test_add_subnet_validator_tx_serialization_with_one_signer --exact --show-output
#[test]
fn test_add_subnet_validator_tx_serialization_with_one_signer() {
    use utils::cmp;

    let mut tx = Tx {
        unsigned_tx: avax::BaseTx {
            network_id: 1000000,
            outs: Some(vec![avax::TransferableOutput {
                asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, //
                    0xe6, 0x89, 0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, //
                    0xe8, 0x5e, 0xa5, 0x74, 0xc7, 0xa1, 0x5a, 0x79, //
                    0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, 0x80, 0x14, //
                ])),
                out: secp256k1fx::TransferOutput {
                    amount: 0x2c6874d5c56f500,
                    output_owners: secp256k1fx::OutputOwners {
                        locktime: 0x00,
                        threshold: 0x01,
                        addrs: vec![ids::ShortId::from_slice(&<Vec<u8>>::from([
                            0x65, 0x84, 0x4a, 0x05, 0x40, 0x5f, 0x36, 0x62, 0xc1, 0x92, //
                            0x81, 0x42, 0xc6, 0xc2, 0xa7, 0x83, 0xef, 0x87, 0x1d, 0xe9, //
                        ]))],
                    },
                },
                ..avax::TransferableOutput::default()
            }]),
            ins: Some(vec![avax::TransferableInput {
                utxo_id: avax::UtxoId {
                    output_index: 0,
                    tx_id: ids::Id::from_slice(&<Vec<u8>>::from([
                        0xdd, 0x91, 0x70, 0x54, 0x1a, 0xf4, 0x4b, 0x08, //
                        0x54, 0x4d, 0xae, 0x2c, 0x5e, 0x6f, 0x2b, 0xd9, //
                        0x1e, 0xd4, 0x1e, 0x72, 0x22, 0x44, 0x73, 0x56, //
                        0x1f, 0x50, 0xe8, 0xeb, 0xfc, 0xba, 0x59, 0xb9, //
                    ])),
                    ..avax::UtxoId::default()
                },
                asset_id: ids::Id::from_slice(&<Vec<u8>>::from([
                    0x88, 0xee, 0xc2, 0xe0, 0x99, 0xc6, 0xa5, 0x28, //
                    0xe6, 0x89, 0x61, 0x8e, 0x87, 0x21, 0xe0, 0x4a, //
                    0xe8, 0x5e, 0xa5, 0x74, 0xc7, 0xa1, 0x5a, 0x79, //
                    0x68, 0x64, 0x4d, 0x14, 0xd5, 0x47, 0x80, 0x14, //
                ])),
                input: secp256k1fx::TransferInput {
                    amount: 0x2c6874d5c663740,
                    sig_indices: vec![0],
                },
                ..avax::TransferableInput::default()
            }]),
            ..avax::BaseTx::default()
        },
        validator: Validator {
            validator: platformvm::Validator {
                node_id: ids::ShortId::from_slice(&<Vec<u8>>::from([
                    0xca, 0xc3, 0x1b, 0x23, 0x7f, 0x96, 0x40, 0xd5, 0x01, 0x11, //
                    0xbe, 0x86, 0xb9, 0x58, 0x73, 0x0a, 0xfb, 0x70, 0x5e, 0x0f, //
                ])),
                start: 0x623d424b,
                end: 0x641e6651,
                weight: 0x3e8,
            },
            subnet_id: ids::Id::from_slice(&<Vec<u8>>::from([
                0xdd, 0x91, 0x70, 0x54, 0x1a, 0xf4, 0x4b, 0x08, 0x54, 0x4d, //
                0xae, 0x2c, 0x5e, 0x6f, 0x2b, 0xd9, 0x1e, 0xd4, 0x1e, 0x72, //
                0x22, 0x44, 0x73, 0x56, 0x1f, 0x50, 0xe8, 0xeb, 0xfc, 0xba, //
                0x59, 0xb9,
            ])),
        },
        subnet_auth: secp256k1fx::Input {
            sig_indices: vec![0_u32],
        },
        ..Tx::default()
    };

    let test_key = soft_key::Key::from_private_key(
        "PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67",
    )
    .expect("failed to load private key");
    let keys1: Vec<soft_key::Key> = vec![test_key.clone()];
    let keys2: Vec<soft_key::Key> = vec![test_key];
    let signers: Vec<Vec<soft_key::Key>> = vec![keys1, keys2];
    tx.sign(Some(signers)).expect("failed to sign");
    let tx_metadata = tx.unsigned_tx.metadata.clone().unwrap();
    let signed_bytes = tx_metadata.bytes;
    assert_eq!(
        tx.tx_id().string(),
        "2bAuXK8TGqehHQCSaFkg4tSf7BX91aXM4qP3vX2Y62d4hg22T5"
    );

    let expected_signed_bytes: Vec<u8> = vec![
        // codec version
        0x00, 0x00, //
        //
        // platformvm.UnsignedAddSubnetValidatorTx type ID
        0x00, 0x00, 0x00, 0x0d, //
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
        0x02, 0xc6, 0x87, 0x4d, 0x5c, 0x56, 0xf5, 0x00, //
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
        0xdd, 0x91, 0x70, 0x54, 0x1a, 0xf4, 0x4b, 0x08, 0x54, 0x4d, //
        0xae, 0x2c, 0x5e, 0x6f, 0x2b, 0xd9, 0x1e, 0xd4, 0x1e, 0x72, //
        0x22, 0x44, 0x73, 0x56, 0x1f, 0x50, 0xe8, 0xeb, 0xfc, 0xba, //
        0x59, 0xb9, //
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
        0x02, 0xc6, 0x87, 0x4d, 0x5c, 0x66, 0x37, 0x40, //
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
        0xca, 0xc3, 0x1b, 0x23, 0x7f, 0x96, 0x40, 0xd5, 0x01, 0x11, //
        0xbe, 0x86, 0xb9, 0x58, 0x73, 0x0a, 0xfb, 0x70, 0x5e, 0x0f, //
        //
        // Validator.validator.start
        0x00, 0x00, 0x00, 0x00, 0x62, 0x3d, 0x42, 0x4b, //
        //
        // Validator.validator.end
        0x00, 0x00, 0x00, 0x00, 0x64, 0x1e, 0x66, 0x51, //
        //
        // Validator.validator.weight
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, //
        //
        // Validator.subnet_id
        0xdd, 0x91, 0x70, 0x54, 0x1a, 0xf4, 0x4b, 0x08, //
        0x54, 0x4d, 0xae, 0x2c, 0x5e, 0x6f, 0x2b, 0xd9, //
        0x1e, 0xd4, 0x1e, 0x72, 0x22, 0x44, 0x73, 0x56, //
        0x1f, 0x50, 0xe8, 0xeb, 0xfc, 0xba, 0x59, 0xb9, //
        //
        // "secp256k1fx.Input" type ID
        0x00, 0x00, 0x00, 0x0a, //
        //
        // "secp256k1fx.Input.sig_indices.len()"
        0x00, 0x00, 0x00, 0x01, //
        //
        // "secp256k1fx.Input.sig_indices[0]"
        0x00, 0x00, 0x00, 0x00,
        //
        //
        // number of of credentials (avax.Tx.creds.len())
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
        0x00, 0x00, 0x00, 0x01, //
        //
        // first 65-byte signature
        0x12, 0x51, 0x43, 0xaf, 0xa0, 0xd1, 0x5b, 0xe6, 0x06, 0xe2, //
        0xc5, 0x50, 0xe1, 0x09, 0xac, 0x86, 0xcd, 0x55, 0x45, 0xeb, //
        0x86, 0x5d, 0x8e, 0x19, 0xf0, 0x37, 0x28, 0x62, 0x8e, 0xaf, //
        0xac, 0x52, 0x3a, 0x2c, 0xe3, 0xde, 0x22, 0xa1, 0x3d, 0x3b, //
        0xfb, 0x67, 0x2b, 0x03, 0xa8, 0x29, 0xd7, 0xbd, 0x1d, 0x10, //
        0x06, 0x34, 0xbd, 0x2b, 0x4a, 0xf5, 0x3d, 0xb9, 0x0d, 0x2a, //
        0x63, 0x71, 0x38, 0x5a, 0x00, //
        //
        // struct field type ID "fx::Credential.cred"
        // "secp256k1fx.Credential" type ID
        0x00, 0x00, 0x00, 0x09, //
        //
        // number of signers ("fx::Credential.cred.sigs.len()")
        0x00, 0x00, 0x00, 0x01, //
        //
        // second 65-byte signature
        0x12, 0x51, 0x43, 0xaf, 0xa0, 0xd1, 0x5b, 0xe6, 0x06, 0xe2, //
        0xc5, 0x50, 0xe1, 0x09, 0xac, 0x86, 0xcd, 0x55, 0x45, 0xeb, //
        0x86, 0x5d, 0x8e, 0x19, 0xf0, 0x37, 0x28, 0x62, 0x8e, 0xaf, //
        0xac, 0x52, 0x3a, 0x2c, 0xe3, 0xde, 0x22, 0xa1, 0x3d, 0x3b, //
        0xfb, 0x67, 0x2b, 0x03, 0xa8, 0x29, 0xd7, 0xbd, 0x1d, 0x10, //
        0x06, 0x34, 0xbd, 0x2b, 0x4a, 0xf5, 0x3d, 0xb9, 0x0d, 0x2a, //
        0x63, 0x71, 0x38, 0x5a, 0x00, //
    ];
    // for c in &signed_bytes {
    //     println!("{:#02x},", *c);
    // }
    assert!(cmp::eq_u8_vectors(&expected_signed_bytes, &signed_bytes));
}
