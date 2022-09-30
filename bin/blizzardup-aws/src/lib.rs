mod blizzard;
mod aws;

use serde::{Deserialize, Serialize};

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,

    pub key_files_dir: String,
    pub keys_to_generate: usize,

    pub region: String,
    pub use_spot_instance: bool,

    pub install_artifacts_blizzard_bin: String,

    pub blizzard_log_level: String,
    pub blizzard_metrics_push_interval_seconds: u64,

    pub spec_file_path: String,
}
