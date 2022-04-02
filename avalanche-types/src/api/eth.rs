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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::eth::test_get_balance_response --exact --show-output
#[test]
fn test_get_balance_response() {
    // ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
    let resp: GetBalanceResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": \"0x1388\",
    \"id\": 1
}

",
    )
    .unwrap();
    let expected = GetBalanceResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: big_int::from_hex("0x1388").unwrap(),
    };
    assert_eq!(resp, expected);
}
