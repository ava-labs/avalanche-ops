use std::{
    io::{self, Error, ErrorKind},
    string::String,
};

use serde::{Deserialize, Serialize};

use crate::{api::jsonrpc, avax};

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetHeightResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetHeightResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetHeightResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
}

impl Default for GetHeightResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetHeightResult {
    pub fn default() -> Self {
        Self { height: None }
    }
}

impl RawGetHeightResponse {
    pub fn convert(&self) -> GetHeightResponse {
        let mut result = GetHeightResult::default();
        if self.result.is_some() {
            let raw_result = self.result.clone().expect("unexpected None result");
            result = raw_result.convert();
        }

        GetHeightResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetHeightResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<RawGetHeightResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetHeightResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<String>,
}

impl Default for RawGetHeightResult {
    fn default() -> Self {
        Self::default()
    }
}

impl RawGetHeightResult {
    pub fn default() -> Self {
        Self { height: None }
    }

    pub fn convert(&self) -> GetHeightResult {
        let height = match self.height.clone() {
            Some(v) => v,
            None => String::from("0"),
        };
        let height = height.parse::<u64>().unwrap();
        GetHeightResult {
            height: Some(height),
        }
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::platformvm::test_get_height --exact --show-output
#[test]
fn test_get_height() {
    // ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
    let resp: RawGetHeightResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"height\": \"0\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let converted = resp.convert();

    let expected = GetHeightResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetHeightResult { height: Some(0) }),
    };
    assert_eq!(converted, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GetBalanceResult {
    pub balance: Option<u64>,
    pub unlocked: Option<u64>,
    pub locked_stakeable: Option<u64>,
    pub locked_not_stakeable: Option<u64>,
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
            unlocked: None,
            locked_stakeable: None,
            locked_not_stakeable: None,
            utxo_ids: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBalanceResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetBalanceResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBalanceResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<String>,
    #[serde(rename = "lockedStakeable", skip_serializing_if = "Option::is_none")]
    pub locked_stakeable: Option<String>,
    #[serde(rename = "lockedNotStakeable", skip_serializing_if = "Option::is_none")]
    pub locked_not_stakeable: Option<String>,
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
            let balance = balance.parse::<u64>().unwrap();
            result.balance = Some(balance);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .unlocked
                .is_some()
        {
            let unlocked = self
                .result
                .clone()
                .expect("unexpected None result")
                .unlocked
                .expect("unexpected None unlocked");
            let unlocked = unlocked.parse::<u64>().unwrap();
            result.unlocked = Some(unlocked);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .locked_stakeable
                .is_some()
        {
            let locked_stakeable = self
                .result
                .clone()
                .expect("unexpected None result")
                .locked_stakeable
                .expect("unexpected None locked_stakeable");
            let locked_stakeable = locked_stakeable.parse::<u64>().unwrap();
            result.locked_stakeable = Some(locked_stakeable);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .locked_not_stakeable
                .is_some()
        {
            let locked_not_stakeable = self
                .result
                .clone()
                .expect("unexpected None result")
                .locked_not_stakeable
                .expect("unexpected None locked_not_stakeable");
            let locked_not_stakeable = locked_not_stakeable.parse::<u64>().unwrap();
            result.locked_not_stakeable = Some(locked_not_stakeable);
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

#[test]
fn test_convert_get_balance() {
    use crate::ids;
    use std::str::FromStr;

    // ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
    let resp: RawGetBalanceResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"balance\": \"20000000000000000\",
        \"unlocked\": \"10000000000000000\",
        \"lockedStakeable\": \"10000000000000000\",
        \"lockedNotStakeable\": \"0\",
        \"utxoIDs\": [
            {
                \"txID\": \"11111111111111111111111111111111LpoYY\",
                \"outputIndex\": 1
            },
            {
                \"txID\": \"11111111111111111111111111111111LpoYY\",
                \"outputIndex\": 0
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
            balance: Some(20000000000000000),
            unlocked: Some(10000000000000000),
            locked_stakeable: Some(10000000000000000),
            locked_not_stakeable: Some(0),
            utxo_ids: Some(vec![
                avax::UtxoId {
                    tx_id: ids::Id::from_str("11111111111111111111111111111111LpoYY").unwrap(),
                    output_index: 1,
                    ..avax::UtxoId::default()
                },
                avax::UtxoId {
                    tx_id: ids::Id::from_str("11111111111111111111111111111111LpoYY").unwrap(),
                    output_index: 0,
                    ..avax::UtxoId::default()
                },
            ]),
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct GetUtxosRequest {
    pub addresses: Vec<String>,
    pub limit: u32,
    pub encoding: String,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetUtxosResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetUtxosResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetUtxosResult {
    #[serde(rename = "numFetched", skip_serializing_if = "Option::is_none")]
    pub num_fetched: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxos: Option<Vec<String>>,
    #[serde(rename = "endIndex", skip_serializing_if = "Option::is_none")]
    pub end_index: Option<EndIndex>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl Default for GetUtxosResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetUtxosResult {
    pub fn default() -> Self {
        Self {
            num_fetched: None,
            utxos: None,
            end_index: None,
            encoding: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct EndIndex {
    pub address: String,
    pub utxo: String,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetUtxosResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<RawGetUtxosResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetUtxosResult {
    #[serde(rename = "numFetched", skip_serializing_if = "Option::is_none")]
    pub num_fetched: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxos: Option<Vec<String>>,
    #[serde(rename = "endIndex", skip_serializing_if = "Option::is_none")]
    pub end_index: Option<EndIndex>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/issuing-api-calls
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DataForGetUtxos {
    pub jsonrpc: String,
    pub id: u32,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<GetUtxosRequest>,
}

impl Default for DataForGetUtxos {
    fn default() -> Self {
        Self::default()
    }
}

impl DataForGetUtxos {
    pub fn default() -> Self {
        Self {
            jsonrpc: String::from(jsonrpc::DEFAULT_VERSION),
            id: jsonrpc::DEFAULT_ID,
            method: String::new(),
            params: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to JSON {}", e),
                ));
            }
        }
    }
}

impl RawGetUtxosResponse {
    pub fn convert(&self) -> io::Result<GetUtxosResponse> {
        let mut result = GetUtxosResult::default();
        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .num_fetched
                .is_some()
        {
            let num_fetched = self
                .result
                .clone()
                .expect("unexpected None result")
                .num_fetched
                .expect("unexpected None num_fetched");
            let num_fetched = num_fetched.parse::<u32>().unwrap();
            result.num_fetched = Some(num_fetched);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .utxos
                .is_some()
        {
            let utxos = self
                .result
                .clone()
                .expect("unexpected None result")
                .utxos
                .expect("unexpected None utxos");
            result.utxos = Some(utxos);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .end_index
                .is_some()
        {
            let end_index = self
                .result
                .clone()
                .expect("unexpected None result")
                .end_index
                .expect("unexpected None end_index");
            result.end_index = Some(end_index);
        }

        if self.result.is_some()
            && self
                .result
                .clone()
                .expect("unexpected None result")
                .encoding
                .is_some()
        {
            let encoding = self
                .result
                .clone()
                .expect("unexpected None result")
                .encoding
                .expect("unexpected None encoding");
            result.encoding = Some(encoding);
        }

        Ok(GetUtxosResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::platformvm::test_convert_get_utxos_empty --exact --show-output
#[test]
fn test_convert_get_utxos_empty() {
    // ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
    let resp: RawGetUtxosResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"numFetched\": \"0\",
        \"utxos\": [],
        \"endIndex\": {
            \"address\": \"P-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5\",
            \"utxo\": \"11111111111111111111111111111111LpoYY\"
        },
        \"encoding\":\"hex\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetUtxosResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetUtxosResult {
            num_fetched: Some(0),
            utxos: Some(Vec::new()),
            end_index: Some(EndIndex {
                address: String::from("P-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5"),
                utxo: String::from("11111111111111111111111111111111LpoYY"),
            }),
            encoding: Some(String::from("hex")),
        }),
    };
    assert_eq!(parsed, expected);
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::platformvm::test_convert_get_utxos_non_empty --exact --show-output
#[test]
fn test_convert_get_utxos_non_empty() {
    // ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
    let resp: RawGetUtxosResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"numFetched\": \"1\",
        \"utxos\": [
            \"0x000000000000000000000000000000000000000000000000000000000000000000000000000088eec2e099c6a528e689618e8721e04ae85ea574c7a15a7968644d14d54780140000000702c68af0bb1400000000000000000000000000010000000165844a05405f3662c1928142c6c2a783ef871de939b564db\"
        ],
        \"endIndex\": {
            \"address\": \"P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs\",
            \"utxo\": \"LUC1cmcxnfNR9LdkACS2ccGKLEK7SYqB4gLLTycQfg1koyfSq\"
        },
        \"encoding\": \"hex\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetUtxosResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetUtxosResult {
            num_fetched: Some(1),
            utxos: Some(vec![
                String::from("0x000000000000000000000000000000000000000000000000000000000000000000000000000088eec2e099c6a528e689618e8721e04ae85ea574c7a15a7968644d14d54780140000000702c68af0bb1400000000000000000000000000010000000165844a05405f3662c1928142c6c2a783ef871de939b564db"),
            ]),
            end_index: Some(EndIndex {
                address: String::from("P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs"),
                utxo: String::from("LUC1cmcxnfNR9LdkACS2ccGKLEK7SYqB4gLLTycQfg1koyfSq"),
            }),
            encoding: Some(String::from("hex")),
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct GetCurrentValidatorsResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetCurrentValidatorsResult>,
}

impl Default for GetCurrentValidatorsResponse {
    fn default() -> Self {
        Self::default()
    }
}

impl GetCurrentValidatorsResponse {
    pub fn default() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: 1,
            result: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct GetCurrentValidatorsResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators: Option<Vec<ApiPrimaryValidator>>,
}

impl Default for GetCurrentValidatorsResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetCurrentValidatorsResult {
    pub fn default() -> Self {
        Self { validators: None }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIStaker
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ApiPrimaryValidator {
    #[serde(rename = "txID", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,
    #[serde(rename = "stakeAmount", skip_serializing_if = "Option::is_none")]
    pub stake_amount: Option<u64>,
    #[serde(rename = "nodeID", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(rename = "rewardOwner", skip_serializing_if = "Option::is_none")]
    pub reward_owner: Option<ApiOwner>,
    #[serde(rename = "potentialReward", skip_serializing_if = "Option::is_none")]
    pub potential_reward: Option<u64>,
    #[serde(rename = "delegationFee", skip_serializing_if = "Option::is_none")]
    pub delegation_fee: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staked: Option<Vec<ApiUtxo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegators: Option<Vec<ApiPrimaryDelegator>>,
}

impl Default for ApiPrimaryValidator {
    fn default() -> Self {
        Self::default()
    }
}

impl ApiPrimaryValidator {
    pub fn default() -> Self {
        Self {
            tx_id: None,
            start_time: None,
            end_time: None,
            weight: None,
            stake_amount: None,
            node_id: None,
            reward_owner: None,
            potential_reward: None,
            delegation_fee: None,
            uptime: None,
            connected: None,
            staked: None,
            delegators: None,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIStaker
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ApiPrimaryDelegator {
    #[serde(rename = "txID", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,
    #[serde(rename = "stakeAmount", skip_serializing_if = "Option::is_none")]
    pub stake_amount: Option<u64>,
    #[serde(rename = "nodeID", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(rename = "rewardOwner", skip_serializing_if = "Option::is_none")]
    pub reward_owner: Option<ApiOwner>,
    #[serde(rename = "potentialReward", skip_serializing_if = "Option::is_none")]
    pub potential_reward: Option<u64>,
    #[serde(rename = "delegationFee", skip_serializing_if = "Option::is_none")]
    pub delegation_fee: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staked: Option<Vec<ApiUtxo>>,
}

impl Default for ApiPrimaryDelegator {
    fn default() -> Self {
        Self::default()
    }
}

impl ApiPrimaryDelegator {
    pub fn default() -> Self {
        Self {
            tx_id: None,
            start_time: None,
            end_time: None,
            weight: None,
            stake_amount: None,
            node_id: None,
            reward_owner: None,
            potential_reward: None,
            delegation_fee: None,
            uptime: None,
            connected: None,
            staked: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawApiPrimaryValidator {
    #[serde(rename = "txID", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(rename = "weight", skip_serializing_if = "Option::is_none")]
    pub weight: Option<String>,
    #[serde(rename = "stakeAmount", skip_serializing_if = "Option::is_none")]
    pub stake_amount: Option<String>,
    #[serde(rename = "nodeID", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(rename = "rewardOwner", skip_serializing_if = "Option::is_none")]
    pub reward_owner: Option<RawApiOwner>,
    #[serde(rename = "potentialReward", skip_serializing_if = "Option::is_none")]
    pub potential_reward: Option<String>,
    #[serde(rename = "delegationFee", skip_serializing_if = "Option::is_none")]
    pub delegation_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staked: Option<Vec<RawApiUtxo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegators: Option<Vec<RawApiPrimaryDelegator>>,
}

impl Default for RawApiPrimaryValidator {
    fn default() -> Self {
        Self::default()
    }
}

impl RawApiPrimaryValidator {
    pub fn default() -> Self {
        Self {
            tx_id: None,
            start_time: None,
            end_time: None,
            weight: None,
            stake_amount: None,
            node_id: None,
            reward_owner: None,
            potential_reward: None,
            delegation_fee: None,
            uptime: None,
            connected: None,
            staked: None,
            delegators: None,
        }
    }

    pub fn convert(&self) -> ApiPrimaryValidator {
        let start_time = self.start_time.clone().unwrap_or_else(|| String::from("0"));
        let start_time = start_time.parse::<u64>().unwrap();

        let end_time = self.end_time.clone().unwrap_or_else(|| String::from("0"));
        let end_time = end_time.parse::<u64>().unwrap();

        let weight = self.weight.clone().unwrap_or_else(|| String::from("0"));
        let weight = weight.parse::<u64>().unwrap();

        let stake_amount = self
            .stake_amount
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let stake_amount = stake_amount.parse::<u64>().unwrap();

        let reward_owner = {
            if self.reward_owner.is_none() {
                None
            } else {
                let reward_owner = self.reward_owner.clone().unwrap();
                let reward_owner = reward_owner.convert();
                Some(reward_owner)
            }
        };

        let potential_reward = self
            .potential_reward
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let potential_reward = potential_reward.parse::<u64>().unwrap();

        let delegation_fee = self
            .delegation_fee
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let delegation_fee = delegation_fee.parse::<f32>().unwrap();

        let uptime = self.uptime.clone().unwrap_or_else(|| String::from("0"));
        let uptime = uptime.parse::<f32>().unwrap();

        let staked = {
            if self.staked.is_none() {
                None
            } else {
                let raw_staked = self.staked.clone().unwrap();
                let mut staked: Vec<ApiUtxo> = Vec::new();
                for st in raw_staked.iter() {
                    let converted = st.convert();
                    staked.push(converted);
                }
                Some(staked)
            }
        };

        let delegators = {
            if self.delegators.is_none() {
                None
            } else {
                let raw_delegators = self.delegators.clone().unwrap();
                let mut delegators: Vec<ApiPrimaryDelegator> = Vec::new();
                for st in raw_delegators.iter() {
                    let converted = st.convert();
                    delegators.push(converted);
                }
                Some(delegators)
            }
        };

        ApiPrimaryValidator {
            tx_id: self.tx_id.clone(),
            start_time: Some(start_time),
            end_time: Some(end_time),
            weight: Some(weight),
            stake_amount: Some(stake_amount),
            node_id: self.node_id.clone(),
            reward_owner,
            potential_reward: Some(potential_reward),
            delegation_fee: Some(delegation_fee),
            uptime: Some(uptime),
            connected: self.connected,
            staked,
            delegators,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawApiPrimaryDelegator {
    #[serde(rename = "txID", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "startTime", skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(rename = "weight", skip_serializing_if = "Option::is_none")]
    pub weight: Option<String>,
    #[serde(rename = "stakeAmount", skip_serializing_if = "Option::is_none")]
    pub stake_amount: Option<String>,
    #[serde(rename = "nodeID", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(rename = "rewardOwner", skip_serializing_if = "Option::is_none")]
    pub reward_owner: Option<RawApiOwner>,
    #[serde(rename = "potentialReward", skip_serializing_if = "Option::is_none")]
    pub potential_reward: Option<String>,
    #[serde(rename = "delegationFee", skip_serializing_if = "Option::is_none")]
    pub delegation_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staked: Option<Vec<RawApiUtxo>>,
}

impl Default for RawApiPrimaryDelegator {
    fn default() -> Self {
        Self::default()
    }
}

impl RawApiPrimaryDelegator {
    pub fn default() -> Self {
        Self {
            tx_id: None,
            start_time: None,
            end_time: None,
            weight: None,
            stake_amount: None,
            node_id: None,
            reward_owner: None,
            potential_reward: None,
            delegation_fee: None,
            uptime: None,
            connected: None,
            staked: None,
        }
    }

    pub fn convert(&self) -> ApiPrimaryDelegator {
        let start_time = self.start_time.clone().unwrap_or_else(|| String::from("0"));
        let start_time = start_time.parse::<u64>().unwrap();

        let end_time = self.end_time.clone().unwrap_or_else(|| String::from("0"));
        let end_time = end_time.parse::<u64>().unwrap();

        let weight = self.weight.clone().unwrap_or_else(|| String::from("0"));
        let weight = weight.parse::<u64>().unwrap();

        let stake_amount = self
            .stake_amount
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let stake_amount = stake_amount.parse::<u64>().unwrap();

        let reward_owner = {
            if self.reward_owner.is_none() {
                None
            } else {
                let reward_owner = self.reward_owner.clone().unwrap();
                let reward_owner = reward_owner.convert();
                Some(reward_owner)
            }
        };

        let potential_reward = self
            .potential_reward
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let potential_reward = potential_reward.parse::<u64>().unwrap();

        let delegation_fee = self
            .delegation_fee
            .clone()
            .unwrap_or_else(|| String::from("0"));
        let delegation_fee = delegation_fee.parse::<f32>().unwrap();

        let uptime = self.uptime.clone().unwrap_or_else(|| String::from("0"));
        let uptime = uptime.parse::<f32>().unwrap();

        let staked = {
            if self.staked.is_none() {
                None
            } else {
                let raw_staked = self.staked.clone().unwrap();
                let mut staked: Vec<ApiUtxo> = Vec::new();
                for st in raw_staked.iter() {
                    let converted = st.convert();
                    staked.push(converted);
                }
                Some(staked)
            }
        };

        ApiPrimaryDelegator {
            tx_id: self.tx_id.clone(),
            start_time: Some(start_time),
            end_time: Some(end_time),
            weight: Some(weight),
            stake_amount: Some(stake_amount),
            node_id: self.node_id.clone(),
            reward_owner,
            potential_reward: Some(potential_reward),
            delegation_fee: Some(delegation_fee),
            uptime: Some(uptime),
            connected: self.connected,
            staked,
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIOwner
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawApiOwner {
    pub locktime: String,
    pub threshold: String,
    pub addresses: Vec<String>,
}

impl Default for RawApiOwner {
    fn default() -> Self {
        Self::default()
    }
}

impl RawApiOwner {
    pub fn default() -> Self {
        Self {
            locktime: String::new(),
            threshold: String::new(),
            addresses: Vec::new(),
        }
    }

    pub fn convert(&self) -> ApiOwner {
        let locktime = self.locktime.parse::<u64>().unwrap();
        let threshold = self.threshold.parse::<u32>().unwrap();
        ApiOwner {
            locktime,
            threshold,
            addresses: self.addresses.clone(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIOwner
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ApiOwner {
    pub locktime: u64,
    pub threshold: u32,
    pub addresses: Vec<String>,
}

impl Default for ApiOwner {
    fn default() -> Self {
        Self::default()
    }
}

impl ApiOwner {
    pub fn default() -> Self {
        Self {
            locktime: 0,
            threshold: 0,
            addresses: Vec::new(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIUTXO
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawApiUtxo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locktime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Default for RawApiUtxo {
    fn default() -> Self {
        Self::default()
    }
}

impl RawApiUtxo {
    pub fn default() -> Self {
        Self {
            locktime: None,
            amount: None,
            address: None,
            message: None,
        }
    }

    pub fn convert(&self) -> ApiUtxo {
        let locktime = {
            if self.locktime.is_some() {
                let locktime = self.locktime.clone().unwrap();
                locktime.parse::<u64>().unwrap()
            } else {
                0_u64
            }
        };
        let amount = {
            if self.amount.is_some() {
                let amount = self.amount.clone().unwrap();
                amount.parse::<u64>().unwrap()
            } else {
                0_u64
            }
        };
        let address = self.address.clone().unwrap();
        ApiUtxo {
            locktime,
            amount,
            address,
            message: self.message.clone(),
        }
    }
}

/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIUTXO
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ApiUtxo {
    pub locktime: u64,
    pub amount: u64,
    pub address: String,
    pub message: Option<String>,
}

impl Default for ApiUtxo {
    fn default() -> Self {
        Self::default()
    }
}

impl ApiUtxo {
    pub fn default() -> Self {
        Self {
            locktime: 0,
            amount: 0,
            address: String::new(),
            message: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetCurrentValidatorsResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetCurrentValidatorsResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetCurrentValidatorsResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators: Option<Vec<RawApiPrimaryValidator>>,
}

impl RawGetCurrentValidatorsResponse {
    pub fn convert(&self) -> io::Result<GetCurrentValidatorsResponse> {
        if self.result.as_ref().is_none() {
            return Ok(GetCurrentValidatorsResponse::default());
        };

        let rs = self.result.as_ref().unwrap();
        if rs.validators.is_none() {
            return Ok(GetCurrentValidatorsResponse::default());
        }

        let mut validators: Vec<ApiPrimaryValidator> = Vec::new();
        let raw_validators = rs.validators.clone().unwrap();
        for raw_validator in raw_validators.iter() {
            let validator = raw_validator.convert();
            validators.push(validator);
        }

        Ok(GetCurrentValidatorsResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(GetCurrentValidatorsResult {
                validators: Some(validators),
            }),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::platformvm::test_convert_get_current_validators --exact --show-output
#[test]
fn test_convert_get_current_validators() {
    // ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
    let resp: RawGetCurrentValidatorsResponse = serde_json::from_str(
        "
{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"validators\": [
            {
                \"txID\": \"KPkPo9EerKZhSwrA8NfLTVWsgr16Ntu8Ei4ci7GF7t75szrcQ\",
                \"startTime\": \"1648312635\",
                \"endTime\": \"1679843235\",
                \"stakeAmount\": \"100000000000000000\",
                \"nodeID\": \"NodeID-5wVq6KkSK3p4wQFmiVHCDq2zdg8unchaE\",
                \"rewardOwner\": {
                    \"locktime\": \"0\",
                    \"threshold\": \"1\",
                    \"addresses\": [
                        \"P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs\"
                    ]
                },
                \"potentialReward\": \"79984390135364555\",
                \"delegationFee\": \"6.2500\",
                \"uptime\": \"1.0000\",
                \"connected\": true,
                \"delegators\": null
            },
            {
                \"txID\": \"EjKZm5eEajWu151cfPms7PvMjyaQk36qTSz1MfnZRU5x5bNxz\",
                \"startTime\": \"1648312635\",
                \"endTime\": \"1679848635\",
                \"stakeAmount\": \"100000000000000000\",
                \"nodeID\": \"NodeID-JLR7d6z9cwCbkoPcPsnjkm6gq4xz7c4oT\",
                \"rewardOwner\": {
                    \"locktime\": \"0\",
                    \"threshold\": \"1\",
                    \"addresses\": [
                        \"P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs\"
                    ]
                },
                \"potentialReward\": \"77148186230865960\",
                \"delegationFee\": \"6.2500\",
                \"uptime\": \"1.0000\",
                \"connected\": true,
                \"delegators\": null
            }
        ]
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    println!("{:?}", parsed);

    let expected = GetCurrentValidatorsResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetCurrentValidatorsResult {
            validators: Some(<Vec<ApiPrimaryValidator>>::from([
                ApiPrimaryValidator {
                    tx_id: Some(String::from(
                        "KPkPo9EerKZhSwrA8NfLTVWsgr16Ntu8Ei4ci7GF7t75szrcQ",
                    )),
                    start_time: Some(1648312635),
                    end_time: Some(1679843235),
                    weight: Some(0),
                    stake_amount: Some(100000000000000000),
                    node_id: Some("NodeID-5wVq6KkSK3p4wQFmiVHCDq2zdg8unchaE".to_string()),
                    reward_owner: Some(ApiOwner {
                        locktime: 0,
                        threshold: 1,
                        addresses: vec![
                            "P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs".to_string()
                        ],
                    }),
                    potential_reward: Some(79984390135364555),
                    delegation_fee: Some(6.25),
                    uptime: Some(1.0),
                    connected: Some(true),
                    ..ApiPrimaryValidator::default()
                },
                ApiPrimaryValidator {
                    tx_id: Some(String::from(
                        "EjKZm5eEajWu151cfPms7PvMjyaQk36qTSz1MfnZRU5x5bNxz",
                    )),
                    start_time: Some(1648312635),
                    end_time: Some(1679848635),
                    weight: Some(0),
                    stake_amount: Some(100000000000000000),
                    node_id: Some("NodeID-JLR7d6z9cwCbkoPcPsnjkm6gq4xz7c4oT".to_string()),
                    reward_owner: Some(ApiOwner {
                        locktime: 0,
                        threshold: 1,
                        addresses: vec![
                            "P-custom1vkzy5p2qtumx9svjs9pvds48s0hcw80f962vrs".to_string()
                        ],
                    }),
                    potential_reward: Some(77148186230865960),
                    delegation_fee: Some(6.25),
                    uptime: Some(1.0),
                    connected: Some(true),
                    ..ApiPrimaryValidator::default()
                },
            ])),
        }),
    };
    assert_eq!(parsed, expected);
}
