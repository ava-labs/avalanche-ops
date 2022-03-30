use std::{
    io::{self, Error, ErrorKind},
    string::String,
};

use log::info;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use crate::jsonrpc;
use utils::{big_int, http};

/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(with = "big_int::serde_hex_format")]
    pub result: BigInt,
}

/// e.g., "eth_getBalance" on "http://[ADDR]:9650" and "/ext/bc/C/rpc" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
pub async fn get_balance(url: &str, eth_addr: &str) -> io::Result<GetBalanceResponse> {
    let joined = http::join_uri(url, "/ext/bc/C/rpc")?;
    info!("getting balances for {} via {:?}", eth_addr, joined);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("eth_getBalance");

    let params = vec![String::from(eth_addr), "latest".to_string()];
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::insecure_post(url, "/ext/bc/C/rpc", &d).await?;
    let resp: GetBalanceResponse = match serde_json::from_slice(&rb) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
        }
    };
    Ok(resp)
}
