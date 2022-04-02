use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    string::String,
};

use log::info;

use avalanche_types::api::{avm, jsonrpc};
use utils::http;

/// e.g., "avm.getBalance" on "http://[ADDR]:9650" and "/ext/bc/X" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain#avmgetbalance
pub async fn get_balance(url: &str, xaddr: &str) -> io::Result<avm::GetBalanceResponse> {
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
    let resp: avm::RawGetBalanceResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "avm.getAssetDescription".
/// ref. https://docs.avax.network/build/avalanchego-apis/x-chain/#avmgetassetdescription
pub async fn get_asset_description(
    url: &str,
    asset_id: &str,
) -> io::Result<avm::GetAssetDescriptionResponse> {
    info!("getting asset description from {} for {}", url, asset_id);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("avm.getAssetDescription");

    let mut params = HashMap::new();
    params.insert(String::from("assetID"), String::from(asset_id));
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::insecure_post(url, "ext/bc/X", &d).await?;
    let resp: avm::RawGetAssetDescriptionResponse = match serde_json::from_slice(&rb) {
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
