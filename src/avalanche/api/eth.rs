use std::{
    io::{self, Error, ErrorKind},
    process::Command,
    string::String,
    time::Duration,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::{avalanche::api::jsonrpc, utils::http};

/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<u64>,
}

/// e.g., "eth_getBalance" on "http://[ADDR]:9650" and "/ext/bc/C/rpc" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
pub async fn get_balance(url: &str, path: &str, paddr: &str) -> io::Result<GetBalanceResponse> {
    info!("getting balance for {} via {} {}", paddr, url, path);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("eth_getBalance");

    let params = vec![String::from(paddr), "latest".to_string()];
    data.params = Some(params);

    let d = data.encode_json()?;

    let resp: _GetBalanceResponse = {
        if url.starts_with("https") {
            let joined = http::join_uri(url, path)?;

            // TODO: implement this with native Rust
            info!("sending via curl --insecure");
            let mut cmd = Command::new("curl");
            cmd.arg("--insecure");
            cmd.arg("-X POST");
            cmd.arg("--header 'content-type:application/json;'");
            cmd.arg(format!("--data '{}'", d));
            cmd.arg(joined.as_str());

            let output = cmd.output()?;
            match serde_json::from_slice(&output.stdout) {
                Ok(p) => p,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed to decode {}", e),
                    ));
                }
            }
        } else {
            let req = http::create_json_post(url, path, &d)?;
            let buf = match http::read_bytes(
                req,
                Duration::from_secs(5),
                url.starts_with("https"),
                false,
            )
            .await
            {
                Ok(u) => u,
                Err(e) => return Err(e),
            };
            match serde_json::from_slice(&buf) {
                Ok(p) => p,
                Err(e) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("failed to decode {}", e),
                    ));
                }
            }
        }
    };

    let parsed = resp.convert()?;
    Ok(parsed)
}

/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetBalanceResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
}

impl _GetBalanceResponse {
    fn convert(&self) -> io::Result<GetBalanceResponse> {
        let result = match &self.result {
            Some(v) => {
                let result = v.parse::<u64>().unwrap();
                Some(result)
            }
            None => None,
        };
        Ok(GetBalanceResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result,
        })
    }
}
