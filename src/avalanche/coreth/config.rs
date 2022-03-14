use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

/// To be persisted in "chain_config_dir".
/// ref. https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config
/// ref. https://github.com/ava-labs/coreth/blob/v0.8.6/plugin/evm/config.go
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snowman_api_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coreth_admin_api_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coreth_admin_api_dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_apis: Option<Vec<String>>,

    /// If not empty, it enables the profiler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuous_profiler_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuous_profiler_frequency: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuous_profiler_max_files: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_gas_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_tx_fee_cap: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimages_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruning_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_async: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_verification_enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_expensive_enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_txs_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_max_duration: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_cpu_refill_rate: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_cpu_max_stored: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_max_blocks_per_request: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_unfinalized_queries: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_unprotected_txs: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_external_signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_insecure_unlock_allowed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_tx_gossip_only_enabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_regossip_frequency: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_regossip_max_size: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_bloom_filter_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_data_directory: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_outbound_active_requests: Option<i64>,
}

pub const DEFAULT_CORETH_ADMIN_API_ENABLED: bool = true;

/// MUST BE a valid path in remote host machine.
pub const DEFAULT_PROFILE_DIR: &str = "/var/log/avalanche-profile/coreth";
pub const DEFAULT_PROFILE_FREQUENCY: i64 = 15 * 60 * 1000 * 1000 * 1000; // 15-min
pub const DEFAULT_PROFILE_MAX_FILES: i64 = 5;

pub const DEFAULT_METRICS_ENABLED: bool = true;
pub const DEFAULT_LOG_LEVEL: &str = "info";

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl Config {
    pub fn default() -> Self {
        Self {
            snowman_api_enabled: None,
            coreth_admin_api_enabled: Some(DEFAULT_CORETH_ADMIN_API_ENABLED),
            coreth_admin_api_dir: None,

            eth_apis: None,

            continuous_profiler_dir: None,
            continuous_profiler_frequency: None,
            continuous_profiler_max_files: None,

            rpc_gas_cap: None,
            rpc_tx_fee_cap: None,

            preimages_enabled: None,
            pruning_enabled: None,
            snapshot_async: None,
            snapshot_verification_enabled: None,

            metrics_enabled: Some(DEFAULT_METRICS_ENABLED),
            metrics_expensive_enabled: None,

            local_txs_enabled: None,
            api_max_duration: None,
            ws_cpu_refill_rate: None,
            ws_cpu_max_stored: None,
            api_max_blocks_per_request: None,
            allow_unfinalized_queries: None,
            allow_unprotected_txs: None,

            keystore_directory: None,
            keystore_external_signer: None,
            keystore_insecure_unlock_allowed: None,

            remote_tx_gossip_only_enabled: None,
            tx_regossip_frequency: None,
            tx_regossip_max_size: None,

            log_level: Some(String::from(DEFAULT_LOG_LEVEL)),

            offline_pruning_enabled: None,
            offline_pruning_bloom_filter_size: None,
            offline_pruning_data_directory: None,

            max_outbound_active_requests: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to JSON {}", e),
                ));
            }
        }
    }

    /// Saves the current beacon node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Config to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}
