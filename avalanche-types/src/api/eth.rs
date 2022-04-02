use std::string::String;

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use utils::big_int;

/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(with = "big_int::serde_hex_format")]
    pub result: BigInt,
}
