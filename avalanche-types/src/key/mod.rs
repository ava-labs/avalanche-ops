pub mod address;
pub mod cert;
pub mod hot;

use std::io;

use serde::{Deserialize, Serialize};

use crate::ids;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct NetworkAddressEntry {
    pub x_address: String,
    pub p_address: String,
    pub c_address: String,
}

/// Key interface that "only" allows "read" operations.
pub trait ReadOnly {
    /// Implements "crypto.PublicKeySECP256K1R.Address()" and "formatting.FormatAddress".
    /// "human readable part" (hrp) must be valid output from "constants.GetHRP(networkID)".
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants
    fn get_address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String>;
    fn get_short_address(&self) -> ids::ShortId;
    fn get_eth_address(&self) -> String;
}
