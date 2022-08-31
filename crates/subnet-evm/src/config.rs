use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

/// To be persisted in "chain_config_dir".
/// ref. https://pkg.go.dev/github.com/ava-labs/subnet-evm/plugin/evm#Config
/// ref. https://github.com/ava-labs/subnet-evm/blob/v0.2.9/plugin/evm/config.go
/// ref. https://serde.rs/container-attrs.html
///
/// If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
/// the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json
/// ref. https://docs.avax.network/subnets/customize-a-subnet#chain-configs
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snowman_api_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_api_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_api_dir: Option<String>,

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
    pub snapshot_async: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_verification_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruning_enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_expensive_enabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_txs_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_max_duration: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_cpu_refill_rate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_cpu_max_stored: Option<String>,
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
    pub remote_gossip_only_enabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regossip_frequency: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regossip_max_txs: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regossip_txs_per_address: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_regossip_frequency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_regossip_max_txs: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_regossip_txs_per_address: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_regossip_addresses: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_json_format: Option<bool>,

    #[serde(rename = "feeRecipient", skip_serializing_if = "Option::is_none")]
    pub fee_recipient: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_bloom_filter_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_pruning_data_directory: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_outbound_active_requests: Option<i64>,
}

pub const DEFAULT_ADMIN_API_ENABLED: bool = true;

/// MUST BE a valid path in remote host machine.
pub const DEFAULT_PROFILE_DIR: &str = "/var/log/avalanche-profile/coreth";
pub const DEFAULT_PROFILE_FREQUENCY: i64 = 15 * 60 * 1000 * 1000 * 1000; // 15-min
pub const DEFAULT_PROFILE_MAX_FILES: i64 = 5;

pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_LOG_JSON_FORMAT: bool = true;

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl Config {
    pub fn default() -> Self {
        Self {
            snowman_api_enabled: None,
            admin_api_enabled: Some(DEFAULT_ADMIN_API_ENABLED),
            admin_api_dir: None,

            // "subnet-evm" will adopt the changes from "coreth"
            // that removes "public-*" to be consistent with geth
            // TODO: once "subnet-evm" updates, follow the same
            eth_apis: Some(vec![
                "public-eth".to_string(),
                "public-eth-filter".to_string(),
                "net".to_string(),
                "web3".to_string(),
                "internal-public-eth".to_string(),
                "internal-public-blockchain".to_string(),
                "internal-public-transaction-pool".to_string(),
                "internal-public-tx-pool".to_string(),
                "debug-tracer".to_string(),
                // "internal-public-debug".to_string(),
            ]),

            continuous_profiler_dir: None,
            continuous_profiler_frequency: None,
            continuous_profiler_max_files: None,

            rpc_gas_cap: None,
            rpc_tx_fee_cap: None,

            preimages_enabled: None,
            snapshot_async: None,
            snapshot_verification_enabled: None,
            pruning_enabled: Some(true),

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

            remote_gossip_only_enabled: None,
            regossip_frequency: None,
            regossip_max_txs: None,
            regossip_txs_per_address: None,
            priority_regossip_frequency: Some("1s".to_string()),
            priority_regossip_max_txs: Some(32),
            priority_regossip_txs_per_address: Some(16),
            priority_regossip_addresses: Some(vec![
                "0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC".to_string(), // ewoq key address
            ]),

            log_level: Some(String::from(DEFAULT_LOG_LEVEL)),
            log_json_format: Some(DEFAULT_LOG_JSON_FORMAT),

            fee_recipient: None,

            offline_pruning_enabled: None,
            offline_pruning_bloom_filter_size: None,
            offline_pruning_data_directory: None,

            max_outbound_active_requests: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize to JSON {}", e),
            )),
        }
    }

    /// Saves the current anchor node to disk
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

/// RUST_LOG=debug cargo test --package subnet-evm --lib -- config::test_config --exact --show-output
#[test]
fn test_config() {
    let _ = env_logger::builder().is_test(true).try_init();

    let tmp_path = random_manager::tmp_path(10, Some(".json")).unwrap();
    let cfg = Config::default();
    cfg.sync(&tmp_path).unwrap();
}
