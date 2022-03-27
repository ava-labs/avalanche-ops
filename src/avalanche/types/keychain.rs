use crate::avalanche::types::key;

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/secp256k1fx#Keychain
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Keychain {
    pub key: key::Key,
}

impl Keychain {
    pub fn new(key: key::Key) -> Self {
        Self { key }
    }
}
