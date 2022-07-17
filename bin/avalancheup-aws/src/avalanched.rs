use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Flags {
    pub log_level: String,
    pub lite_mode: bool,
}

impl Flags {
    pub fn to_flags(&self) -> String {
        let mut s = format!("--log-level={}", self.log_level);
        if self.lite_mode {
            s.push_str(" --lite-mode");
        }
        s
    }
}
