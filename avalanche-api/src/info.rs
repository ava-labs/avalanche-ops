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
use utils::http;

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
