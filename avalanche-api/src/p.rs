use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    string::String,
};

use log::info;

use avalanche_types::api::{jsonrpc, platformvm};
use utils::http;

/// e.g., "platform.getHeight" on "http://[ADDR]:9650" and "/ext/bc/P" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetheight
pub async fn get_height(url: &str) -> io::Result<platformvm::GetHeightResponse> {
    let joined = http::join_uri(url, "/ext/bc/P")?;
    info!("getting height for {:?}", joined);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("platform.getHeight");

    let params = HashMap::new();
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "/ext/bc/P", &d).await?;
    let resp: platformvm::RawGetHeightResponse = match serde_json::from_slice(&rb) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
        }
    };
    let converted = resp.convert();
    Ok(converted)
}

/// e.g., "platform.getBalance" on "http://[ADDR]:9650" and "/ext/bc/P" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetbalance
pub async fn get_balance(url: &str, paddr: &str) -> io::Result<platformvm::GetBalanceResponse> {
    let joined = http::join_uri(url, "/ext/bc/P")?;
    info!("getting balances for {} via {:?}", paddr, joined);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("platform.getBalance");

    let mut params = HashMap::new();
    params.insert(String::from("address"), paddr.to_string());
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "/ext/bc/P", &d).await?;
    let resp: platformvm::RawGetBalanceResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "platform.getUTXOs" on "http://[ADDR]:9650" and "/ext/bc/P" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetutxos
pub async fn get_utxos(url: &str, paddr: &str) -> io::Result<platformvm::GetUtxosResponse> {
    let joined = http::join_uri(url, "/ext/bc/P")?;
    info!("getting UTXOs for {} via {:?}", paddr, joined);

    let mut data = platformvm::DataForGetUtxos::default();
    data.method = String::from("platform.getUTXOs");

    let params = platformvm::GetUtxosRequest {
        addresses: vec![paddr.to_string()],
        limit: 100,
        encoding: String::from("hex"), // don't use "cb58"
    };
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "/ext/bc/P", &d).await?;
    let resp: platformvm::RawGetUtxosResponse = match serde_json::from_slice(&rb) {
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

/// e.g., "platform.getBalance" on "http://[ADDR]:9650" and "/ext/bc/P" path.
/// ref. https://docs.avax.network/build/avalanchego-apis/p-chain/#platformgetcurrentvalidators
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/vms/platformvm#APIPrimaryValidator
pub async fn get_current_validators(
    url: &str,
) -> io::Result<platformvm::GetCurrentValidatorsResponse> {
    let joined = http::join_uri(url, "/ext/bc/P")?;
    info!("getting current validators via {:?}", joined);

    let mut data = jsonrpc::Data::default();
    data.method = String::from("platform.getCurrentValidators");

    let params = HashMap::new();
    data.params = Some(params);

    let d = data.encode_json()?;
    let rb = http::post_non_tls(url, "/ext/bc/P", &d).await?;
    let resp: platformvm::RawGetCurrentValidatorsResponse = match serde_json::from_slice(&rb) {
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

// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/p/builder.go

// TODO: create subnet tx
// TODO: check p-chain tx
// TODO: add subnet validator tx
// TODO: create blockchain tx with genesis
// TODO: add wallet
