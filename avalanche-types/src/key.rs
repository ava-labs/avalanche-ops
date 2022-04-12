use std::io;

use crate::ids;

pub trait ReadOnly {
    /// Implements "crypto.PublicKeySECP256K1R.Address()" and "formatting.FormatAddress".
    /// "human readable part" (hrp) must be valid output from "constants.GetHRP(networkID)".
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants
    fn get_address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String>;
    fn get_short_address(&self) -> ids::ShortId;
    fn get_eth_address(&self) -> String;
}

/// The length of recoverable ECDSA signature.
/// "github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa.SignCompact" outputs
/// 65-byte signature -- see "compactSigSize"
/// ref. "avalanchego/utils/crypto.PrivateKeySECP256K1R.SignHash"
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/crypto#SECP256K1RSigLen
pub const ECDSA_RECOVERABLE_SIG_LEN: usize = 65;
