use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::{avax, jsonrpc};
use avalanche_types::ids;
use utils::http;

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
pub async fn get_balance(url: &str, xaddr: &str) -> io::Result<GetBalanceResponse> {
    let joined = http::join_uri(url, "/ext/bc/X")?;
    info!("getting balances for {} via {:?}", xaddr, joined);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("avm.getBalance");

    let mut params = HashMap::new();
    params.insert(String::from("assetID"), String::from("AVAX"));
    params.insert(String::from("address"), xaddr.to_string());
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::insecure_post(url, "/ext/bc/X", &d).await?;
    let resp: _GetBalanceResponse = match serde_json::from_slice(&rb) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
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

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GetAssetDescriptionResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetAssetDescriptionResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GetAssetDescriptionResult {
    /// TODO: implement serializer/deserializer for "ids::Id"
    /// #[serde(default, deserialize_with = "ids::format_id_de")]
    pub asset_id: ids::Id,
    pub name: String,
    pub symbol: String,
    pub denomination: usize,
}

impl Default for GetAssetDescriptionResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetAssetDescriptionResult {
    pub fn default() -> Self {
        Self {
            asset_id: ids::Id::default(),
            name: String::new(),
            symbol: String::new(),
            denomination: 0,
        }
    }
}

/// e.g., "avm.getAssetDescription".
/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
pub async fn get_asset_description(
    url: &str,
    asset_id: &str,
) -> io::Result<GetAssetDescriptionResponse> {
    info!("getting asset description from {} for {}", url, asset_id);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("avm.getAssetDescription");

    let mut params = HashMap::new();
    params.insert(String::from("assetID"), String::from(asset_id));
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::insecure_post(url, "ext/bc/X", &d).await?;
    let resp: _GetAssetDescriptionResponse = match serde_json::from_slice(&rb) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
        }
    };
    let converted = resp.convert()?;
    Ok(converted)
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetAssetDescriptionResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<_GetAssetDescriptionResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetAssetDescriptionResult {
    #[serde(rename = "assetID")]
    asset_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denomination: Option<String>,
}

// https://serde.rs/field-attrs.html
// #[serde(default, deserialize_with = "ids::format_id_de")]

impl _GetAssetDescriptionResponse {
    fn convert(&self) -> io::Result<GetAssetDescriptionResponse> {
        let mut result = GetAssetDescriptionResult::default();
        if self.result.is_some() {
            let asset_id = self
                .result
                .clone()
                .expect("unexpected None result")
                .asset_id;
            result.asset_id = {
                if asset_id.is_empty() {
                    ids::Id::empty()
                } else {
                    ids::Id::from_string(&asset_id).unwrap()
                }
            };

            let name = self
                .result
                .clone()
                .expect("unexpected None result")
                .name
                .unwrap_or_default();
            result.name = name;

            let symbol = self
                .result
                .clone()
                .expect("unexpected None result")
                .symbol
                .unwrap_or_default();
            result.symbol = symbol;

            let denomination = self
                .result
                .clone()
                .expect("unexpected None result")
                .denomination;
            result.denomination = {
                if let Some(d) = denomination {
                    d.parse::<usize>().unwrap()
                } else {
                    0_usize
                }
            };
        }

        Ok(GetAssetDescriptionResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-api --lib -- avm::test_asset_description_response_convert --exact --show-output
#[test]
fn test_asset_description_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
    let resp: _GetAssetDescriptionResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"assetID\": \"2fombhL7aGPwj3KH4bfrmJwW6PVnMobf9Y2fn9GwxiAAJyFDbe\",
        \"name\": \"Avalanche\",
        \"symbol\": \"AVAX\",
        \"denomination\": \"9\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetAssetDescriptionResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetAssetDescriptionResult {
            asset_id: ids::Id::from_string("2fombhL7aGPwj3KH4bfrmJwW6PVnMobf9Y2fn9GwxiAAJyFDbe")
                .unwrap(),
            name: String::from("Avalanche"),
            symbol: String::from("AVAX"),
            denomination: 9,
        }),
    };
    assert_eq!(parsed, expected);
}
