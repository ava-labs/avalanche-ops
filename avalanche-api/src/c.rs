use std::{
    io::{self, Error, ErrorKind},
    string::String,
};

use avalanche_types::api::{eth, jsonrpc};
use avalanche_utils::http;
use log::info;

/// e.g., "eth_getBalance" on "http://[ADDR]:9650" and "/ext/bc/C/rpc" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
pub async fn get_balance(url: &str, eth_addr: &str) -> io::Result<eth::GetBalanceResponse> {
    let joined = http::join_uri(url, "/ext/bc/C/rpc")?;
    info!("getting balances for {} via {:?}", eth_addr, joined);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("eth_getBalance");

    let params = vec![String::from(eth_addr), "latest".to_string()];
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "/ext/bc/C/rpc", &d).await?;
    let resp: eth::GetBalanceResponse = match serde_json::from_slice(&rb) {
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
