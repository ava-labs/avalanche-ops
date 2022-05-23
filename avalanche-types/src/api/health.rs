use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    str::FromStr,
    string::String,
};

use chrono::{DateTime, Utc};
use serde::Deserialize;

use avalanche_utils::rfc3339;

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
    #[serde(default, deserialize_with = "rfc3339::deserialize")]
    pub time_of_first_failure: Option<DateTime<Utc>>,
}

/// ref. https://doc.rust-lang.org/std/str/trait.FromStr.html
impl FromStr for Response {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed serde_json::from_str '{}'", e),
            )
        })
    }
}

/// RUST_LOG=debug cargo test --package avalanche-types --lib -- api::health::test_parse --exact --show-output
#[test]
fn test_parse() {
    use log::info;
    let _ = env_logger::builder().is_test(true).try_init();

    let data = "

{
    \"checks\": {
        \"C\": {
            \"message\": {
                \"consensus\": {
                    \"longestRunningBlock\": \"0s\",
                    \"outstandingBlocks\": 0
                },
                \"vm\": null
            },
            \"timestamp\": \"2022-02-16T08:15:01.766696642Z\",
            \"duration\": 5861
        },
        \"P\": {
            \"message\": {
                \"consensus\": {
                    \"longestRunningBlock\": \"0s\",
                    \"outstandingBlocks\": 0
                },
                \"vm\": {
                    \"percentConnected\": 1
                }
            },
            \"timestamp\": \"2022-02-16T08:15:01.766695342Z\",
            \"duration\": 19790
        },
        \"X\": {
            \"message\": {
                \"consensus\": {
                    \"outstandingVertices\": 0,
                    \"snowstorm\": {
                        \"outstandingTransactions\": 0
                    }
                },
                \"vm\": null
            },
            \"timestamp\": \"2022-02-16T08:15:01.766712432Z\",
            \"duration\": 8731
        },
        \"bootstrapped\": {
            \"message\": [],
            \"timestamp\": \"2022-02-16T08:15:01.766704522Z\",
            \"duration\": 8120
        },
        \"network\": {
            \"message\": {
                \"connectedPeers\": 4,
                \"sendFailRate\": 0.016543146704195332,
                \"timeSinceLastMsgReceived\": \"1.766701162s\",
                \"timeSinceLastMsgSent\": \"3.766701162s\"
            },
            \"timestamp\": \"2022-02-16T08:15:01.766702722Z\",
            \"duration\": 5600
        },
        \"router\": {
            \"message\": {
                \"longestRunningRequest\": \"0s\",
                \"outstandingRequests\": 0
            },
            \"timestamp\": \"2022-02-16T08:15:01.766689781Z\",
            \"duration\": 11210
        }
    },
    \"healthy\": true
}

";
    let parsed = Response::from_str(data).unwrap();
    info!("parsed: {:?}", parsed);
    assert!(parsed.healthy.unwrap());
}
