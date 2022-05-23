use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    string::String,
};

use log::info;

use avalanche_types::api::{info, jsonrpc};
use avalanche_utils::http;

/// e.g., "info.getNetworkName".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkname
pub async fn get_network_name(url: &str) -> io::Result<info::GetNetworkNameResponse> {
    info!("getting network name for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNetworkName");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::GetNetworkNameResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getNetworkID".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnetworkid
pub async fn get_network_id(url: &str) -> io::Result<info::GetNetworkIdResponse> {
    info!("getting network ID for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNetworkID");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::RawGetNetworkIdResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getBlockchainID".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetblockchainid
pub async fn get_blockchain_id(
    url: &str,
    chain_alias: &str,
) -> io::Result<info::GetBlockchainIdResponse> {
    info!("getting blockchain ID for {} and {}", url, chain_alias);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("info.getBlockchainID");

    let mut params = HashMap::new();
    params.insert(String::from("alias"), String::from(chain_alias));
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::RawGetBlockchainIdResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getNodeID".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeid
pub async fn get_node_id(url: &str) -> io::Result<info::GetNodeIdResponse> {
    info!("getting node ID for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNodeID");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::RawGetNodeIdResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getNodeVersion".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetnodeversion
pub async fn get_node_version(url: &str) -> io::Result<info::GetNodeVersionResponse> {
    let joined = http::join_uri(url, "ext/info")?;
    info!("getting node version for {:?}", joined);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getNodeVersion");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::GetNodeVersionResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getVMs".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogetvms
pub async fn get_vms(url: &str) -> io::Result<info::GetVmsResponse> {
    info!("getting VMs for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getVMs");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::GetVmsResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.isBootstrapped".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infoisbootstrapped
pub async fn get_bootstrapped(url: &str) -> io::Result<info::GetBootstrappedResponse> {
    info!("getting bootstrapped for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.isBootstrapped");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::GetBootstrappedResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "info.getTxFee".
/// ref. https://docs.avax.network/build/avalanchego-apis/info/#infogettxfee
pub async fn get_tx_fee(url: &str) -> io::Result<info::GetTxFeeResponse> {
    info!("getting node ID for {}", url);

    let mut data = jsonrpc::DataWithParamsArray::default();
    data.method = String::from("info.getTxFee");

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "ext/info", &d).await?;
    let resp: info::RawGetTxFeeResponse = match serde_json::from_slice(&rb) {
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
