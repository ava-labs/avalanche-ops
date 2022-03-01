use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::avalanche::genesis;

/// Default "config-file" path on the remote linux machines.
/// Must be a valid path in remote host machine.
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/avalanche.config.json";
/// Default "genesis" path on the remote linux machines.
/// Must be a valid path in remote host machine.
pub const DEFAULT_GENESIS_PATH: &str = "/etc/avalanche.genesis.json";

/// Default "db-dir" directory path for remote linux machines.
/// Must be matched with the attached physical storage volume path.
/// Must be a valid path in remote host machine.
/// ref. See "cloudformation/avalanche-node/asg_amd64_ubuntu.yaml" "ASGLaunchTemplate"
pub const DEFAULT_DB_DIR: &str = "/avalanche-data";
/// Default "log-dir" directory path for remote linux machines.
/// Must be a valid path in remote host machine.
/// ref. See "cloudformation/avalanche-node/asg_amd64_ubuntu.yaml" "ASGLaunchTemplate"
pub const DEFAULT_LOG_DIR: &str = "/var/log/avalanche";
pub const DEFAULT_LOG_LEVEL: &str = "INFO";

pub const DEFAULT_STAKING_ENABLED: bool = true;
/// Default staking port.
/// NOTE: keep default value in sync with "avalanchego/config/flags.go".
pub const DEFAULT_STAKING_PORT: u32 = 9651;
/// Must be a valid path in remote host machine.
pub const DEFAULT_STAKING_TLS_KEY_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.key";
/// Must be a valid path in remote host machine.
pub const DEFAULT_STAKING_TLS_CERT_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.crt";

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

pub const DEFAULT_CHAIN_CONFIG_DIR: &str = "/etc/avalanchego/configs/chains";

/// Represents AvalancheGo configuration.
/// All file paths must be valid on the remote machines.
/// For example, you may configure cert paths on your local laptop
/// but the actual Avalanche nodes run on the remote machines
/// so the paths will be invalid.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/config
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AvalancheGo {
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

    /// Database directory, must be a valid path in remote host machine.
    pub db_dir: String,
    /// Logging directory, must be a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<String>,
    /// "avalanchego" logging level.
    /// See "utils/logging/level.go".
    /// e.g., "INFO", "FATAL", "DEBUG", "VERBO", etc..
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_display_level: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_enabled: Option<bool>,
    /// Staking port.
    /// If none, default to the value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_port: Option<u32>,
    /// Must be a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_key_file: Option<String>,
    /// Must be a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_cert_file: Option<String>,

    /// HTTP port.
    /// If none, default to the value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_port: Option<u32>,
    /// HTTP host, which avalanchego defaults to 127.0.0.1.
    /// Set it to 0.0.0.0 to expose the HTTP API to all incoming traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_enabled: Option<bool>,
    /// Must be a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_key_file: Option<String>,
    /// Must be a valid path in remote host machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_tls_cert_file: Option<String>,
    /// Public IP of this node for P2P communication.
    /// If empty, try to discover with NAT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

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

    // TODO: support https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_config_dir: Option<String>,
}

impl Default for AvalancheGo {
    fn default() -> Self {
        Self::default()
    }
}

impl AvalancheGo {
    pub fn new() -> Self {
        Self {
            config_file: None,
            genesis: None,

            network_id: genesis::DEFAULT_CUSTOM_NETWORK_ID,

            db_dir: String::from(DEFAULT_DB_DIR),
            log_dir: None,
            log_level: None,
            log_display_level: None,

            staking_enabled: None,
            staking_port: None,
            staking_tls_key_file: None,
            staking_tls_cert_file: None,

            http_port: None,
            http_host: None,
            http_tls_enabled: None,
            http_tls_key_file: None,
            http_tls_cert_file: None,
            public_ip: None,

            bootstrap_ips: None,
            bootstrap_ids: None,

            snow_sample_size: None,
            snow_quorum_size: None,

            network_peer_list_gossip_frequency: None,
            network_max_reconnect_delay: None,

            index_enabled: None,
            index_allow_incomplete: None,

            api_admin_enabled: None,
            api_info_enabled: None,
            api_keystore_enabled: None,
            api_metrics_enabled: None,
            api_health_enabled: None,
            api_ipcs_enabled: None,

            whitelisted_subnets: None,

            chain_config_dir: None,
        }
    }

    pub fn default() -> Self {
        let mut config = Self::new();

        config.network_id = genesis::DEFAULT_CUSTOM_NETWORK_ID;
        config.config_file = Some(String::from(DEFAULT_CONFIG_FILE_PATH));
        config.genesis = Some(String::from(DEFAULT_GENESIS_PATH));

        config.db_dir = String::from(DEFAULT_DB_DIR);
        config.log_dir = Some(String::from(DEFAULT_LOG_DIR));
        config.log_level = Some(String::from(DEFAULT_LOG_LEVEL));

        config.staking_enabled = Some(DEFAULT_STAKING_ENABLED);
        config.staking_port = Some(DEFAULT_STAKING_PORT);
        config.staking_tls_key_file = Some(String::from(DEFAULT_STAKING_TLS_KEY_FILE));
        config.staking_tls_cert_file = Some(String::from(DEFAULT_STAKING_TLS_CERT_FILE));

        config.http_port = Some(DEFAULT_HTTP_PORT);
        config.http_host = Some(String::from(DEFAULT_HTTP_HOST));
        config.http_tls_enabled = Some(DEFAULT_HTTP_TLS_ENABLED);

        config.snow_sample_size = Some(DEFAULT_SNOW_SAMPLE_SIZE);
        config.snow_quorum_size = Some(DEFAULT_SNOW_QUORUM_SIZE);

        config.index_enabled = Some(DEFAULT_INDEX_ENABLED);
        config.index_allow_incomplete = Some(DEFAULT_INDEX_ALLOW_INCOMPLETE);

        config.api_admin_enabled = Some(DEFAULT_API_ADMIN_ENABLED);
        config.api_info_enabled = Some(DEFAULT_API_INFO_ENABLED);
        config.api_keystore_enabled = Some(DEFAULT_API_KEYSTORE_ENABLED);
        config.api_metrics_enabled = Some(DEFAULT_API_METRICS_ENABLED);
        config.api_health_enabled = Some(DEFAULT_API_HEALTH_ENABLED);
        config.api_ipcs_enabled = Some(DEFAULT_API_IPCS_ENABLED);

        config.chain_config_dir = Some(String::from(DEFAULT_CHAIN_CONFIG_DIR));
        config
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

        let f = match File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to open {} ({})", file_path, e),
                ));
            }
        };
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
            let genesis_config = genesis::AvalancheGo::load(&genesis_file_path)
                .expect("unexpected None genesis config");
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

        Ok(())
    }
}

#[test]
fn test_config() {
    use crate::random;
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = AvalancheGo::new();
    config.network_id = 1337;

    let ret = config.encode_json();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = random::tmp_path(10, Some(".yaml")).unwrap();
    let ret = config.sync(Some(p.clone()));
    assert!(ret.is_ok());

    let config_loaded = AvalancheGo::load(&p).unwrap();
    assert_eq!(config, config_loaded);

    fs::remove_file(p).unwrap();
}
