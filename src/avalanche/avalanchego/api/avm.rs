use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    process::Command,
    string::String,
    time::Duration,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::{
    avalanche::avalanchego::api::{avax, jsonrpc},
    utils::http,
};

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<u64>,
    #[serde(rename = "utxoIDs", skip_serializing_if = "Option::is_none")]
    pub utxo_ids: Option<Vec<avax::UtxoId>>,
}

impl Default for GetBalanceResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetBalanceResult {
    pub fn default() -> Self {
        Self {
            balance: None,
            utxo_ids: None,
        }
    }
}

/// e.g., "avm.getBalance" on "http://[ADDR]:9650" and "/ext/bc/X" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
pub async fn get_balance(url: &str, path: &str, xaddr: &str) -> io::Result<GetBalanceResponse> {
    info!("getting balance for {} via {} {}", xaddr, url, path);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("avm.getBalance");

    let mut params = HashMap::new();
    params.insert(String::from("assetID"), String::from("AVAX"));
    params.insert(String::from("address"), xaddr.to_string());
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

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetBalanceResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<_GetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetBalanceResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "utxoIDs", skip_serializing_if = "Option::is_none")]
    utxo_ids: Option<Vec<avax::UtxoId>>,
}

impl _GetBalanceResponse {
    fn convert(&self) -> io::Result<GetBalanceResponse> {
        let mut result = GetBalanceResult::default();
        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .balance
                .is_some()
        {
            let balance = self
                .result
                .clone()
                .expect("unexpected None result")
                .balance
                .expect("unexpected None balance");
            let balance = balance.parse::<u64>().unwrap();
            result.balance = Some(balance);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .utxo_ids
                .is_some()
        {
            let utxo_ids = self
                .result
                .clone()
                .expect("unexpected None result")
                .utxo_ids
                .expect("unexpected None utxo_ids");
            result.utxo_ids = Some(utxo_ids);
        }

        Ok(GetBalanceResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

#[test]
fn test_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
    let resp: _GetBalanceResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"balance\": \"299999999999900\",
        \"utxoIDs\": [
            {
                \"txID\": \"WPQdyLNqHfiEKp4zcCpayRHYDVYuh1hqs9c1RqgZXS4VPgdvo\",
                \"outputIndex\": 1
            }
        ]
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetBalanceResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetBalanceResult {
            balance: Some(299999999999900),
            utxo_ids: Some(vec![avax::UtxoId {
                tx_id: Some(String::from(
                    "WPQdyLNqHfiEKp4zcCpayRHYDVYuh1hqs9c1RqgZXS4VPgdvo",
                )),
                output_index: Some(1),
            }]),
        }),
    };
    assert_eq!(parsed, expected);
}
