use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use avalanche_types::{constants, genesis};
use log::info;
use serde::{Deserialize, Serialize};

/// Represents AvalancheGo configuration.
/// All file paths must be valid on the remote machines.
/// For example, you may configure cert paths on your local laptop
/// but the actual Avalanche nodes run on the remote machines
/// so the paths will be invalid.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/config
/// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.10/config/flags.go
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// File path to persist all fields below.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<String>,

    /// Genesis file path.
    /// MUST BE NON-EMPTY for custom network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<String>,

    /// Network ID. Default to custom network ID.
    /// Set it to 1 for mainnet.
    /// e.g., "mainnet" is 1, "fuji" is 4, "local" is 12345.
    /// "utils/constants/NetworkID" only accepts string for known networks.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants#pkg-constants
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants#NetworkName
    pub network_id: u32,

    pub db_type: String,
    /// Database directory, must be a valid path in remote host machine.
    pub db_dir: String,
    /// Logging directory, must be a valid path in remote host machine.
    pub log_dir: String,
    /// "avalanchego" logging level.
    /// See "utils/logging/level.go".
    /// e.g., "INFO", "FATAL", "DEBUG", "VERBO", etc..
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_display_level: Option<String>,

    /// HTTP port.
    pub http_port: u32,
    /// HTTP host, which avalanchego defaults to 127.0.0.1.
    /// Set it to 0.0.0.0 to expose the HTTP API to all incoming traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_enabled: Option<bool>,
    /// MUST BE a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_key_file: Option<String>,
    /// MUST BE a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_cert_file: Option<String>,
    /// Public IP of this node for P2P communication.
    /// If empty, try to discover with NAT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_enabled: Option<bool>,
    /// Staking port.
    pub staking_port: u32,
    /// MUST BE a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_key_file: Option<String>,
    /// MUST BE a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_cert_file: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ips: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ids: Option<String>,

    /// The sample size k, snowball.Parameters.K.
    /// If zero, use the default value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_sample_size: Option<u32>,
    /// The quorum size α, snowball.Parameters.Alpha.
    /// If zero, use the default value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_quorum_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_concurrent_repolls: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_max_time_processing: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_rogue_commit_threshold: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_virtuous_commit_threshold: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_peer_list_gossip_frequency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_max_reconnect_delay: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_allow_incomplete: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_admin_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_info_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_keystore_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_metrics_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_health_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_ipcs_enabled: Option<bool>,

    /// A list of whitelisted subnet IDs (comma-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelisted_subnets: Option<String>,

    /// Chain configuration directory for all chains.
    /// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.6/config/flags.go#L25-L44
    pub chain_config_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_config_dir: Option<String>,

    /// A comma seperated string of explicit nodeID and IPs
    /// to contact for starting state sync. Useful for testing.
    /// NOTE: Actual state data will be downloaded from nodes
    /// specified in the C-Chain config, or the entire network
    /// if no list specified there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_ids: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_ips: Option<String>,

    /// Continous profile flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_continuous_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_continuous_freq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_continuous_max_files: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_inbound_at_large_alloc_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_inbound_validator_alloc_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_inbound_node_max_at_large_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_outbound_at_large_alloc_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_outbound_validator_alloc_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttler_outbound_node_max_at_large_bytes: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_minimum_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_require_validator_to_connect: Option<bool>,
}

/// Default "config-file" path on the remote linux machines.
/// MUST BE a valid path in remote host machine.
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/avalanche.config.json";
/// Default "genesis" path on the remote linux machines.
/// MUST BE a valid path in remote host machine.
pub const DEFAULT_GENESIS_PATH: &str = "/etc/avalanche.genesis.json";

pub const DEFAULT_DB_TYPE: &str = "leveldb";
/// Default "db-dir" directory path for remote linux machines.
/// MUST BE matched with the attached physical storage volume path.
/// MUST BE a valid path in remote host machine.
/// ref. See "src/aws/cfn-templates/avalanche-node/asg_amd64_ubuntu.yaml" "ASGLaunchTemplate"
pub const DEFAULT_DB_DIR: &str = "/data";
/// Default "log-dir" directory path for remote linux machines.
/// MUST BE a valid path in remote host machine.
/// ref. See "src/aws/cfn-templates/avalanche-node/asg_amd64_ubuntu.yaml" "ASGLaunchTemplate"
pub const DEFAULT_LOG_DIR: &str = "/var/log/avalanche";
pub const DEFAULT_LOG_LEVEL: &str = "INFO";

/// Default HTTP port.
/// NOTE: keep default value in sync with "avalanchego/config/flags.go".
pub const DEFAULT_HTTP_PORT: u32 = 9650;
/// Default HTTP host.
/// Open listener to "0.0.0.0" to allow all incoming traffic.
/// e.g., If set to default "127.0.0.1", the external client
/// cannot access "/ext/metrics". Set different values to
/// make this more restrictive.
pub const DEFAULT_HTTP_HOST: &str = "0.0.0.0";
pub const DEFAULT_HTTP_TLS_ENABLED: bool = false;

pub const DEFAULT_STAKING_ENABLED: bool = true;
/// Default staking port.
/// NOTE: keep default value in sync with "avalanchego/config/flags.go".
pub const DEFAULT_STAKING_PORT: u32 = 9651;
/// MUST BE a valid path in remote host machine.
pub const DEFAULT_STAKING_TLS_KEY_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.key";
/// MUST BE a valid path in remote host machine.
pub const DEFAULT_STAKING_TLS_CERT_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.crt";

/// Default snow sample size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_SAMPLE_SIZE: u32 = 20;
/// Default snow quorum size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_QUORUM_SIZE: u32 = 15;

pub const DEFAULT_INDEX_ENABLED: bool = false;
pub const DEFAULT_INDEX_ALLOW_INCOMPLETE: bool = false;

pub const DEFAULT_API_ADMIN_ENABLED: bool = true;
pub const DEFAULT_API_INFO_ENABLED: bool = true;
pub const DEFAULT_API_KEYSTORE_ENABLED: bool = true;
pub const DEFAULT_API_METRICS_ENABLED: bool = true;
pub const DEFAULT_API_HEALTH_ENABLED: bool = true;
pub const DEFAULT_API_IPCS_ENABLED: bool = true;

/// ref. https://github.com/ava-labs/avalanchego/blob/v1.7.6/config/flags.go#L25-L44
pub const DEFAULT_CHAIN_CONFIG_DIR: &str = "/etc/avalanche/configs/chains";
pub const DEFAULT_SUBNET_CONFIG_DIR: &str = "/etc/avalanche/configs/subnets";

/// MUST BE a valid path in remote host machine.
pub const DEFAULT_PROFILE_DIR: &str = "/var/log/avalanche-profile/avalanche";

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl Config {
    pub fn default() -> Self {
        Self {
            config_file: Some(String::from(DEFAULT_CONFIG_FILE_PATH)),
            genesis: Some(String::from(DEFAULT_GENESIS_PATH)),

            network_id: constants::DEFAULT_CUSTOM_NETWORK_ID,

            db_type: String::from(DEFAULT_DB_TYPE),
            db_dir: String::from(DEFAULT_DB_DIR),
            log_dir: String::from(DEFAULT_LOG_DIR),
            log_level: Some(String::from(DEFAULT_LOG_LEVEL)),
            log_display_level: None,

            http_port: DEFAULT_HTTP_PORT,
            http_host: Some(String::from(DEFAULT_HTTP_HOST)),
            http_tls_enabled: Some(DEFAULT_HTTP_TLS_ENABLED),
            http_tls_key_file: None,
            http_tls_cert_file: None,
            public_ip: None,

            staking_enabled: Some(DEFAULT_STAKING_ENABLED),
            staking_port: DEFAULT_STAKING_PORT,
            staking_tls_key_file: Some(String::from(DEFAULT_STAKING_TLS_KEY_FILE)),
            staking_tls_cert_file: Some(String::from(DEFAULT_STAKING_TLS_CERT_FILE)),

            bootstrap_ips: None,
            bootstrap_ids: None,

            snow_sample_size: Some(DEFAULT_SNOW_SAMPLE_SIZE),
            snow_quorum_size: Some(DEFAULT_SNOW_QUORUM_SIZE),
            snow_concurrent_repolls: None,
            snow_max_time_processing: None,
            snow_rogue_commit_threshold: None,
            snow_virtuous_commit_threshold: None,

            network_peer_list_gossip_frequency: None,
            network_max_reconnect_delay: None,

            index_enabled: Some(DEFAULT_INDEX_ENABLED),
            index_allow_incomplete: Some(DEFAULT_INDEX_ALLOW_INCOMPLETE),

            api_admin_enabled: Some(DEFAULT_API_ADMIN_ENABLED),
            api_info_enabled: Some(DEFAULT_API_INFO_ENABLED),
            api_keystore_enabled: Some(DEFAULT_API_KEYSTORE_ENABLED),
            api_metrics_enabled: Some(DEFAULT_API_METRICS_ENABLED),
            api_health_enabled: Some(DEFAULT_API_HEALTH_ENABLED),
            api_ipcs_enabled: Some(DEFAULT_API_IPCS_ENABLED),

            whitelisted_subnets: None,

            chain_config_dir: String::from(DEFAULT_CHAIN_CONFIG_DIR),
            subnet_config_dir: Some(String::from(DEFAULT_SUBNET_CONFIG_DIR)),

            state_sync_ids: None,
            state_sync_ips: None,

            profile_dir: Some(String::from(DEFAULT_PROFILE_DIR)),
            profile_continuous_enabled: None,
            profile_continuous_freq: None,
            profile_continuous_max_files: None,

            throttler_inbound_at_large_alloc_size: None,
            throttler_inbound_validator_alloc_size: None,
            throttler_inbound_node_max_at_large_bytes: None,

            throttler_outbound_at_large_alloc_size: None,
            throttler_outbound_validator_alloc_size: None,
            throttler_outbound_node_max_at_large_bytes: None,

            network_minimum_timeout: None,
            network_require_validator_to_connect: None,
        }
    }

    /// Returns true if the configuration is mainnet.
    pub fn is_mainnet(&self) -> bool {
        self.network_id == 1
    }

    /// Returns true if the configuration is a custom network
    /// thus requires a custom genesis file.
    pub fn is_custom_network(&self) -> bool {
        !self.is_mainnet() && (self.network_id == 0 || self.network_id > 5)
    }

    /// Converts to string with JSON encoder.
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

    /// Saves the current configuration to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: Option<String>) -> io::Result<()> {
        if file_path.is_none() && self.config_file.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "empty config-file path",
            ));
        }
        let p = file_path.unwrap_or_else(|| {
            self.config_file
                .clone()
                .expect("unexpected None config_file")
        });

        info!("syncing avalanchego Config to '{}'", p);
        let path = Path::new(&p);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to JSON {}", e),
                ));
            }
        };
        let mut f = File::create(p)?;
        f.write_all(&d)?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading config from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(&file_path).map_err(|e| {
            return Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            );
        })?;
        serde_json::from_reader(f).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
        })
    }

    /// Validates the configuration.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating the avalanchego configuration");

        // mainnet does not need genesis file
        if !self.is_custom_network() && self.genesis.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--genesis={}' for network_id {}",
                    self.genesis.clone().expect("unexpected None genesis"),
                    self.network_id,
                ),
            ));
        }

        // custom network requires genesis file
        if self.is_custom_network() && self.genesis.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--network-id={}' but empty '--genesis'",
                    self.network_id
                ),
            ));
        }

        // custom network requires genesis file
        if self.genesis.is_some()
            && !Path::new(&self.genesis.clone().expect("unexpected None genesis")).exists()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--genesis={}' but genesis file does not exist",
                    self.genesis.clone().expect("unexpected None genesis")
                ),
            ));
        }

        // network ID must match with the one in genesis file
        if self.genesis.is_some() {
            let genesis_file_path = self.genesis.clone().expect("unexpected None genesis");
            let genesis_config =
                genesis::Genesis::load(&genesis_file_path).expect("unexpected None genesis config");
            if genesis_config.network_id.ne(&self.network_id) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'genesis' network ID {} != avalanchego::Config.network_id {}",
                        genesis_config.network_id, self.network_id
                    ),
                ));
            }
        }

        // staking
        if self.staking_enabled.is_some() && !self.staking_enabled.unwrap() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'staking-enabled' must be true",
            ));
        }
        if self.staking_tls_cert_file.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'staking-tls-cert-file' not defined",
            ));
        }
        if self.staking_tls_key_file.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'staking-tls-key-file' not defined",
            ));
        }

        // state sync
        if self.state_sync_ids.is_some() && self.state_sync_ips.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "non-empty 'state-sync-ids' but empty 'state-sync-ips'",
            ));
        }
        if self.state_sync_ids.is_none() && self.state_sync_ips.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "non-empty 'state-sync-ips' but empty 'state-sync-ids'",
            ));
        }

        // continuous profiles
        if self.profile_continuous_enabled.is_some() && !self.profile_continuous_enabled.unwrap() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'profile-continuous-enabled' must be true",
            ));
        }
        if self.profile_continuous_freq.is_some() && self.profile_continuous_enabled.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "non-empty 'profile-continuous-freq' but empty 'profile-continuous-enabled'",
            ));
        }
        if self.profile_continuous_max_files.is_some() && self.profile_continuous_enabled.is_none()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "non-empty 'profile-continuous-max-files' but empty 'profile-continuous-enabled'",
            ));
        }

        Ok(())
    }
}

#[test]
fn test_config() {
    use avalanche_utils::random;
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = Config::default();
    config.network_id = 1337;

    let ret = config.encode_json();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = random::tmp_path(10, Some(".yaml")).unwrap();
    let ret = config.sync(Some(p.clone()));
    assert!(ret.is_ok());

    let config_loaded = Config::load(&p).unwrap();
    assert_eq!(config, config_loaded);

    fs::remove_file(p).unwrap();
}
