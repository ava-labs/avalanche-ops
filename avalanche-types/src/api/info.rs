use std::{collections::HashMap, io, str::FromStr, string::String};

use serde::{Deserialize, Serialize};

use crate::ids;

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkname
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNetworkNameResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetNetworkNameResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkname
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetNetworkNameResult {
    pub network_name: String,
}

impl Default for GetNetworkNameResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetNetworkNameResult {
    pub fn default() -> Self {
        Self {
            network_name: String::new(),
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNetworkIdResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetNetworkIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNetworkIdResult {
    #[serde(rename = "networkID")]
    pub network_id: u32,
}

impl Default for GetNetworkIdResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetNetworkIdResult {
    pub fn default() -> Self {
        Self { network_id: 1 }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetNetworkIdResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetNetworkIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetNetworkIdResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "networkID")]
    network_id: String,
}

impl RawGetNetworkIdResponse {
    pub fn convert(&self) -> io::Result<GetNetworkIdResponse> {
        let mut result = GetNetworkIdResult::default();
        if self.result.is_some() {
            let network_id = self
                .result
                .clone()
                .expect("unexpected None result")
                .network_id;
            result.network_id = {
                if network_id.is_empty() {
                    0_u32
                } else {
                    network_id.parse::<u32>().unwrap()
                }
            };
        }

        Ok(GetNetworkIdResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::info::test_network_id_response_convert --exact --show-output
#[test]
fn test_network_id_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
    let resp: RawGetNetworkIdResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"networkID\": \"9999999\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetNetworkIdResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetNetworkIdResult {
            network_id: 9999999_u32,
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBlockchainIdResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetBlockchainIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBlockchainIdResult {
    /// TODO: implement serializer/deserializer for "ids::Id"
    /// #[serde(default, deserialize_with = "ids::deserialize_id")]
    pub blockchain_id: ids::Id,
}

impl Default for GetBlockchainIdResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetBlockchainIdResult {
    pub fn default() -> Self {
        Self {
            blockchain_id: ids::Id::default(),
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBlockchainIdResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetBlockchainIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetBlockchainIdResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "blockchainID")]
    blockchain_id: String,
}

impl RawGetBlockchainIdResponse {
    pub fn convert(&self) -> io::Result<GetBlockchainIdResponse> {
        let mut result = GetBlockchainIdResult::default();
        if self.result.is_some() {
            let blockchain_id = self
                .result
                .clone()
                .expect("unexpected None result")
                .blockchain_id;
            result.blockchain_id = {
                if blockchain_id.is_empty() {
                    ids::Id::empty()
                } else {
                    ids::Id::from_str(&blockchain_id).unwrap()
                }
            };
        }

        Ok(GetBlockchainIdResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::info::test_blockchain_id_response_convert --exact --show-output
#[test]
fn test_blockchain_id_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
    let resp: RawGetBlockchainIdResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"blockchainID\": \"sV6o671RtkGBcno1FiaDbVcFv2sG5aVXMZYzKdP4VQAWmJQnM\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetBlockchainIdResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetBlockchainIdResult {
            blockchain_id: ids::Id::from_str("sV6o671RtkGBcno1FiaDbVcFv2sG5aVXMZYzKdP4VQAWmJQnM")
                .unwrap(),
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNodeIdResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetNodeIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNodeIdResult {
    pub node_id: ids::NodeId,
}

impl Default for GetNodeIdResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetNodeIdResult {
    pub fn default() -> Self {
        Self {
            node_id: ids::NodeId::default(),
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetNodeIdResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetNodeIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetNodeIdResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "nodeID")]
    node_id: String,
}

impl RawGetNodeIdResponse {
    pub fn convert(&self) -> io::Result<GetNodeIdResponse> {
        let mut result = GetNodeIdResult::default();
        if self.result.is_some() {
            let node_id = self.result.clone().expect("unexpected None result").node_id;
            result.node_id = {
                if node_id.is_empty() {
                    ids::NodeId::empty()
                } else {
                    ids::NodeId::from_str(&node_id).unwrap()
                }
            };
        }

        Ok(GetNodeIdResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::info::test_node_id_response_convert --exact --show-output
#[test]
fn test_node_id_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
    let resp: RawGetNodeIdResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"nodeID\": \"NodeID-5mb46qkSBj81k9g9e4VFjGGSbaaSLFRzD\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetNodeIdResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetNodeIdResult {
            node_id: ids::NodeId::from_str("NodeID-5mb46qkSBj81k9g9e4VFjGGSbaaSLFRzD").unwrap(),
        }),
    };
    assert_eq!(parsed, expected);
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeversion
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetNodeVersionResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetNodeVersionResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeversion
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetNodeVersionResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_versions: Option<VmVersions>,
}

impl Default for GetNodeVersionResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetNodeVersionResult {
    pub fn default() -> Self {
        Self {
            version: None,
            database_version: None,
            git_commit: None,
            vm_versions: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeversion
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VmVersions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl Default for VmVersions {
    fn default() -> Self {
        Self::default()
    }
}

impl VmVersions {
    pub fn default() -> Self {
        Self {
            avm: None,
            evm: None,
            platform: None,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetvms
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetVmsResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetVmsResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetvms
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetVmsResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vms: Option<HashMap<String, Vec<String>>>,
}

impl Default for GetVmsResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetVmsResult {
    pub fn default() -> Self {
        Self { vms: None }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infoisbootstrapped
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetBootstrappedResponse {
    pub jsonrpc: String,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GetBootstrappedResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infoisbootstrapped
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetBootstrappedResult {
    #[serde(rename = "isBootstrapped")]
    pub bootstrapped: bool,
}

impl Default for GetBootstrappedResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetBootstrappedResult {
    pub fn default() -> Self {
        Self {
            bootstrapped: false,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetTxFeeResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetTxFeeResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GetTxFeeResult {
    pub creation_tx_fee: u64,
    pub tx_fee: u64,
}

impl Default for GetTxFeeResult {
    fn default() -> Self {
        Self::default()
    }
}

impl GetTxFeeResult {
    pub fn default() -> Self {
        Self {
            creation_tx_fee: 0,
            tx_fee: 0,
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetTxFeeResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<RawGetTxFeeResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RawGetTxFeeResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "creationTxFee")]
    creation_tx_fee: String,
    #[serde(rename = "txFee")]
    tx_fee: String,
}

impl RawGetTxFeeResponse {
    pub fn convert(&self) -> io::Result<GetTxFeeResponse> {
        let mut result = GetTxFeeResult::default();
        if self.result.is_some() {
            let creation_tx_fee = self
                .result
                .clone()
                .expect("unexpected None result")
                .creation_tx_fee;
            result.creation_tx_fee = {
                if creation_tx_fee.is_empty() {
                    0_u64
                } else {
                    creation_tx_fee.parse::<u64>().unwrap()
                }
            };

            let tx_fee = self.result.clone().expect("unexpected None result").tx_fee;
            result.tx_fee = {
                if tx_fee.is_empty() {
                    0_u64
                } else {
                    tx_fee.parse::<u64>().unwrap()
                }
            };
        }

        Ok(GetTxFeeResponse {
            jsonrpc: self.jsonrpc.clone(),
            id: self.id,
            result: Some(result),
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::info::test_get_tx_fee_response_convert --exact --show-output
#[test]
fn test_get_tx_fee_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
    let resp: RawGetTxFeeResponse = serde_json::from_str(
        "

{
    \"jsonrpc\": \"2.0\",
    \"result\": {
        \"creationTxFee\": \"10000000\",
        \"txFee\": \"1000000\"
    },
    \"id\": 1
}

",
    )
    .unwrap();
    let parsed = resp.convert().unwrap();
    let expected = GetTxFeeResponse {
        jsonrpc: "2.0".to_string(),
        id: 1,
        result: Some(GetTxFeeResult {
            creation_tx_fee: 10000000_u64,
            tx_fee: 1000000_u64,
        }),
    };
    assert_eq!(parsed, expected);
}
