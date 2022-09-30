use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Flags {
    pub log_level: String,
    pub metrics_push_interval_seconds: u64,
}

impl Flags {
    pub fn to_flags(&self) -> String {
        let mut s = format!("--log-level={}", self.log_level);
        s.push_str(
            format!(
                " --metrics-push-interval-seconds={}",
                self.metrics_push_interval_seconds
            )
            .as_str(),
        );
        s
    }
}
