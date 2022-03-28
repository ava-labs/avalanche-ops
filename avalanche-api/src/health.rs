use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    process::Command,
    string::String,
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use log::info;
use serde::Deserialize;

use utils::{http, rfc3339};

/// Represents AvalancheGo health status.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/api/health#APIHealthReply
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<HashMap<String, CheckResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthy: Option<bool>,
}

/// Represents AvalancheGo health status.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/api/health#Result
#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(with = "rfc3339::serde_format")]
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contiguous_failures: Option<i64>,
    #[serde(default, deserialize_with = "rfc3339::format_date")]
    pub time_of_first_failure: Option<DateTime<Utc>>,
}

impl Response {
    pub fn parse_from_str(s: &str) -> io::Result<Self> {
        serde_json::from_str(s).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
        })
    }
}

#[test]
fn test_api_health() {
    let _ = env_logger::builder().is_test(true).try_init();

    let data = "{\"checks\":{\"C\":{\"message\":{\"consensus\":{\"longestRunningBlock\":\"0s\",\"outstandingBlocks\":0},\"vm\":null},\"timestamp\":\"2022-02-16T08:15:01.766696642Z\",\"duration\":5861},\"P\":{\"message\":{\"consensus\":{\"longestRunningBlock\":\"0s\",\"outstandingBlocks\":0},\"vm\":{\"percentConnected\":1}},\"timestamp\":\"2022-02-16T08:15:01.766695342Z\",\"duration\":19790},\"X\":{\"message\":{\"consensus\":{\"outstandingVertices\":0,\"snowstorm\":{\"outstandingTransactions\":0}},\"vm\":null},\"timestamp\":\"2022-02-16T08:15:01.766712432Z\",\"duration\":8731},\"bootstrapped\":{\"message\":[],\"timestamp\":\"2022-02-16T08:15:01.766704522Z\",\"duration\":8120},\"network\":{\"message\":{\"connectedPeers\":4,\"sendFailRate\":0.016543146704195332,\"timeSinceLastMsgReceived\":\"1.766701162s\",\"timeSinceLastMsgSent\":\"3.766701162s\"},\"timestamp\":\"2022-02-16T08:15:01.766702722Z\",\"duration\":5600},\"router\":{\"message\":{\"longestRunningRequest\":\"0s\",\"outstandingRequests\":0},\"timestamp\":\"2022-02-16T08:15:01.766689781Z\",\"duration\":11210}},\"healthy\":true}";
    let parsed = Response::parse_from_str(data).unwrap();
    info!("parsed: {:?}", parsed);
    assert!(parsed.healthy.unwrap());
}

/// "If a single piece of data must be accessible from more than one task
/// concurrently, then it must be shared using synchronization primitives such as Arc."
/// ref. https://tokio.rs/tokio/tutorial/spawning
pub async fn check(u: Arc<String>, liveness: bool) -> io::Result<Response> {
    let url_path = {
        if liveness {
            "ext/health/liveness"
        } else {
            "ext/health"
        }
    };
    let joined = http::join_uri(u.as_str(), url_path)?;
    info!("checking for {:?}", joined);

    let resp = {
        if u.starts_with("https") {
            // TODO: implement this with native Rust
            info!("sending via curl --insecure");
            let mut cmd = Command::new("curl");
            cmd.arg("--insecure");
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
            let req = http::create_get(u.as_str(), url_path)?;
            let buf =
                match http::read_bytes(req, Duration::from_secs(5), u.starts_with("https"), false)
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

pub async fn spawn_check(u: &str, liveness: bool) -> io::Result<Response> {
    let ep_arc = Arc::new(u.to_string());
    tokio::spawn(async move { check(ep_arc, liveness).await })
        .await
        .expect("failed spawn await")
}
