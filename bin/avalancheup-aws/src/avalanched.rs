use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Flags {
    pub log_level: String,
    pub use_default_config: bool,
    pub skip_publish_node_info: bool,
}

impl Flags {
    pub fn to_flags(&self) -> String {
        let mut s = format!("--log-level={}", self.log_level);
        if self.use_default_config {
            s.push_str(" --use-default-config");
        }
        if self.skip_publish_node_info {
            s.push_str(" --skip-publish-node-info");
        }
        s
    }
}
