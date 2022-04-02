use std::{
    io::{self, Error, ErrorKind},
    string::String,
    sync::Arc,
};

use log::info;

use avalanche_types::api::health;
use utils::http;

/// "If a single piece of data must be accessible from more than one task
/// concurrently, then it must be shared using synchronization primitives such as Arc."
/// ref. https://tokio.rs/tokio/tutorial/spawning
pub async fn check(url: Arc<String>, liveness: bool) -> io::Result<health::Response> {
    let url_path = {
        if liveness {
            "ext/health/liveness"
        } else {
            "ext/health"
        }
    };
    let joined = http::join_uri(url.as_str(), url_path)?;
    info!("checking for {:?}", joined);

    let rb = http::get_non_tls(url.as_str(), url_path).await?;
    let resp: health::Response = match serde_json::from_slice(&rb) {
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

pub async fn spawn_check(u: &str, liveness: bool) -> io::Result<health::Response> {
    let ep_arc = Arc::new(u.to_string());
    tokio::spawn(async move { check(ep_arc, liveness).await })
        .await
        .expect("failed spawn await")
}
