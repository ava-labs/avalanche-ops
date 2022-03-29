use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    process::Command,
    string::String,
    time::Duration,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::jsonrpc;
use avalanche_types::ids;
use utils::http;

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

/// e.g., "info.getNetworkName".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkname
pub async fn get_network_name(url: &str) -> io::Result<GetNetworkNameResponse> {
    info!("getting network name for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNetworkName");

    let d = data.encode_json()?;

    let resp: GetNetworkNameResponse = {
        if url.starts_with("https") {
            let joined = http::join_uri(url, "ext/info")?;

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
            let req = http::create_json_post(url, "ext/info", &d)?;
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
    Ok(resp)
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

/// e.g., "info.getNetworkID".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
pub async fn get_network_id(url: &str) -> io::Result<GetNetworkIdResponse> {
    info!("getting network ID for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNetworkID");

    let d = data.encode_json()?;

    let resp: _GetNetworkIdResponse = {
        if url.starts_with("https") {
            let joined = http::join_uri(url, "ext/info")?;

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
            let req = http::create_json_post(url, "ext/info", &d)?;
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

    let converted = resp.convert()?;
    Ok(converted)
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetNetworkIdResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<_GetNetworkIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetNetworkIdResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "networkID")]
    network_id: String,
}

impl _GetNetworkIdResponse {
    fn convert(&self) -> io::Result<GetNetworkIdResponse> {
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

/// RUST_LOG=debug cargo test --package avalanche-api --lib -- info::test_network_id_response_convert --exact --show-output
#[test]
fn test_network_id_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
    let resp: _GetNetworkIdResponse = serde_json::from_str(
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

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct GetNodeIdResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<GetNodeIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Eq, PartialEq, Clone)]
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

/// e.g., "info.getNodeID".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
pub async fn get_node_id(url: &str) -> io::Result<GetNodeIdResponse> {
    info!("getting node ID for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNodeID");

    let d = data.encode_json()?;

    let resp: _GetNodeIdResponse = {
        if url.starts_with("https") {
            let joined = http::join_uri(url, "ext/info")?;

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
            let req = http::create_json_post(url, "ext/info", &d)?;
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

    let converted = resp.convert()?;
    Ok(converted)
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetNodeIdResponse {
    jsonrpc: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<_GetNodeIdResult>,
}

/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
struct _GetNodeIdResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(rename = "nodeID")]
    node_id: String,
}

impl _GetNodeIdResponse {
    fn convert(&self) -> io::Result<GetNodeIdResponse> {
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

/// RUST_LOG=debug cargo test --package avalanche-api --lib -- info::test_node_id_response_convert --exact --show-output
#[test]
fn test_node_id_response_convert() {
    // ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
    let resp: _GetNodeIdResponse = serde_json::from_str(
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

/// e.g., "info.getNodeVersion".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeversion
pub async fn get_node_version(url: &str) -> io::Result<GetNodeVersionResponse> {
    let joined = http::join_uri(url, "ext/info")?;
    info!("getting node version for {:?}", joined);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNodeVersion");

    let d = data.encode_json()?;

    let resp: GetNodeVersionResponse = {
        if url.starts_with("https") {
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
            let req = http::create_json_post(url, "ext/info", &d)?;
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
    Ok(resp)
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

/// e.g., "info.getVMs".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetvms
pub async fn get_vms(url: &str) -> io::Result<GetVmsResponse> {
    info!("getting VMs for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getVMs");

    let d = data.encode_json()?;

    let resp: GetVmsResponse = {
        if url.starts_with("https") {
            let joined = http::join_uri(url, "ext/info")?;

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
            let req = http::create_json_post(url, "ext/info", &d)?;
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
    Ok(resp)
}
