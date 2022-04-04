use std::{io, str::FromStr, string::String};

use serde::{Deserialize, Serialize};

use crate::{avax, ids};

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBalanceResult {
    pub balance: u64,
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
            balance: 0,
            utxo_ids: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBalanceResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBalanceResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "utxoIDs", skip_serializing_if = "Option::is_none")]
    utxo_ids: Option<Vec<avax::RawUtxoId>>,
}

impl RawGetBalanceResponse {
    pub fn convert(&self) -> io::Result<GetBalanceResponse> {
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
            result.balance = balance.parse::<u64>().unwrap();
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
            let mut converts: Vec<avax::UtxoId> = Vec::new();
            for v in utxo_ids.iter() {
                let converted = v.convert()?;
                converts.push(converted);
            }
            result.utxo_ids = Some(converts);
        }

        Ok(GetBalanceResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::avm::test_get_balance_response_convert --exact --show-output
#[test]
fn test_get_balance_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
    let resp: RawGetBalanceResponse = serde_json::from_str(
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
            balance: 299999999999900,
            utxo_ids: Some(vec![avax::UtxoId {
                tx_id: ids::Id::from_str("WPQdyLNqHfiEKp4zcCpayRHYDVYuh1hqs9c1RqgZXS4VPgdvo")
                    .unwrap(),
                output_index: 1,
                ..avax::UtxoId::default()
            }]),
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetAssetDescriptionResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetAssetDescriptionResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetAssetDescriptionResult {
    #[serde(deserialize_with = "ids::must_deserialize_id")]
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

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetAssetDescriptionResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetAssetDescriptionResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetAssetDescriptionResult {
    #[serde(rename = "assetID")]
    asset_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denomination: Option<String>,
}

impl RawGetAssetDescriptionResponse {
    pub fn convert(&self) -> io::Result<GetAssetDescriptionResponse> {
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
                    ids::Id::from_str(&asset_id).unwrap()
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

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::avm::test_get_asset_description_response_convert --exact --show-output
#[test]
fn test_get_asset_description_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
    let resp: RawGetAssetDescriptionResponse = serde_json::from_str(
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
            asset_id: ids::Id::from_str("2fombhL7aGPwj3KH4bfrmJwW6PVnMobf9Y2fn9GwxiAAJyFDbe")
                .unwrap(),
            name: String::from("Avalanche"),
            symbol: String::from("AVAX"),
            denomination: 9,
        }),
    };
    assert_eq!(parsed, expected);
}
