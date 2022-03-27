use crate::avalanche::types::key;

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain
/// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.8/wallet/chain/p/builder.go
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Keychain {
    pub key: key::Key,
}

impl Keychain {
    pub fn new(key: key::Key) -> Self {
        Self { key }
    }
}
