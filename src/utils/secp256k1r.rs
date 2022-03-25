use secp256k1::{self, Message, Secp256k1, SecretKey};

/// "github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa.SignCompact" outputs 65-byte signature
/// with a trailing "0x00" byte -- see "compactSigSize"
/// ref. "avalanchego/utils/crypto.PrivateKeySECP256K1R.SignHash"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#SECP256K1RSigLen
const SIG_LEN: usize = 65;

/// Signs the message with the ECDSA secret key and appends the recovery code to the signature.
/// ref. https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/ecdsa/recovery.rs
/// ref. https://docs.rs/secp256k1/latest/secp256k1/struct.SecretKey.html#method.sign_ecdsa
/// ref. https://docs.rs/secp256k1/latest/secp256k1/struct.Message.html
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#PrivateKeyED25519.SignHash
pub fn sign_ecdsa_recoverable(secret_key: &SecretKey, msg: &[u8]) -> Vec<u8> {
    let sk = Secp256k1::new();
    let m = Message::from_slice(msg).expect("failed to create Message");

    // "github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa.SignCompact" outputs 65-byte signature
    // ref. "avalanchego/utils/crypto.PrivateKeySECP256K1R.SignHash"
    // ref. https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/ecdsa/recovery.rs
    let sig = sk.sign_ecdsa_recoverable(&m, secret_key);
    let (rec_id, sig) = sig.serialize_compact();

    let mut sig = Vec::from(sig);
    sig.push(rec_id.to_i32() as u8);

    assert_eq!(sig.len(), SIG_LEN);
    sig
}
