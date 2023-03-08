use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Flags {
    pub log_level: String,
    pub use_default_config: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_periodic_node_info: Option<bool>,
}

impl Flags {
    pub fn to_flags(&self) -> String {
        let mut s = format!("--log-level={}", self.log_level);
        if self.use_default_config {
            s.push_str(" --use-default-config");
        }
        if let Some(v) = &self.publish_periodic_node_info {
            if *v {
                s.push_str(" --publish-periodic-node-info");
            }
        }
        s
    }
}
