use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

/// Default "config-file" path for remote linux machines.
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/avalanche.config.json";
/// Default "genesis" path for remote linux machines.
pub const DEFAULT_GENESIS_PATH: &str = "/etc/avalanche.genesis.json";

/// Default snow sample size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_SAMPLE_SIZE: u32 = 20;
/// Default snow quorum size.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_SNOW_QUORUM_SIZE: u32 = 15;

/// Default HTTP host.
/// Open listener to "0.0.0.0" to allow all incoming traffic.
/// e.g., If set to default "127.0.0.1", the external client
/// cannot access "/ext/metrics". Set different values to
/// make this more restrictive.
pub const DEFAULT_HTTP_HOST: &str = "0.0.0.0";
/// Default HTTP port.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_HTTP_PORT: u32 = 9650;
/// Default staking port.
/// NOTE: keep this in sync with "avalanchego/config/flags.go".
pub const DEFAULT_STAKING_PORT: u32 = 9651;

/// Default "db-dir" directory path for remote linux machines.
/// Must be matched with the attached physical storage volume path.
/// ref. See "cloudformation/asg_ubuntu_amd64.yaml" "ASGLaunchTemplate"
pub const DEFAULT_DB_DIR: &str = "/avalanche-data";
/// Default "log-dir" directory path for remote linux machines.
/// ref. See "cloudformation/asg_ubuntu_amd64.yaml" "ASGLaunchTemplate"
pub const DEFAULT_LOG_DIR: &str = "/var/log/avalanche";

pub const DEFAULT_STAKING_ENABLED: bool = true;
pub const DEFAULT_STAKING_TLS_KEY_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.key";
pub const DEFAULT_STAKING_TLS_CERT_FILE: &str = "/etc/pki/tls/certs/avalanched.pki.crt";

pub const DEFAULT_INDEX_ENABLED: bool = true;
pub const DEFAULT_API_ADMIN_ENABLED: bool = true;
pub const DEFAULT_API_IPCS_ENABLED: bool = true;

/// Represents AvalancheGo genesis configuration.
/// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/config
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

    /// Network ID.
    /// MUST NOT BE EMPTY.
    /// e.g., "mainnet" is 1, "fuji" is 4, "local" is 12345.
    /// "utils/constants/NetworkID" only accepts string for known networks.
    /// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/utils/constants#NetworkName
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// HTTP port.
    /// If none, default to the value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_port: Option<u32>,
    /// Staking port.
    /// If none, default to the value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_port: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_dir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<String>,
    /// "avalanchego" logging level.
    /// See "utils/logging/level.go".
    /// e.g., "INFO", "FATAL", "DEBUG", "VERBO", etc..
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_display_level: Option<String>,

    /// A list of whitelisted subnet IDs (comma-separated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelisted_subnets: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_key_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_cert_file: Option<String>,

    /// The sample size k, snowball.Parameters.K.
    /// If zero, use the default value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_sample_size: Option<u32>,
    /// The quorum size α, snowball.Parameters.Alpha.
    /// If zero, use the default value set via avalanche node code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snow_quorum_size: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ips: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ids: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_peer_list_gossip_frequency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_max_reconnect_delay: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_admin_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_ipcs_enabled: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            config_file: None,
            genesis: None,

            network_id: None,

            public_ip: None,

            http_host: None,
            http_port: None,
            staking_port: None,

            db_dir: None,

            log_dir: None,
            log_level: None,
            log_display_level: None,

            whitelisted_subnets: None,

            staking_enabled: None,
            staking_tls_key_file: None,
            staking_tls_cert_file: None,

            snow_sample_size: None,
            snow_quorum_size: None,

            bootstrap_ips: None,
            bootstrap_ids: None,

            network_peer_list_gossip_frequency: None,
            network_max_reconnect_delay: None,

            index_enabled: None,
            api_admin_enabled: None,
            api_ipcs_enabled: None,
        }
    }

    pub fn default() -> Self {
        let mut config = Self::new();
        config.config_file = Some(String::from(DEFAULT_CONFIG_FILE_PATH));
        config.genesis = Some(String::from(DEFAULT_GENESIS_PATH));

        config.staking_enabled = Some(DEFAULT_STAKING_ENABLED);
        config.staking_tls_key_file = Some(String::from(DEFAULT_STAKING_TLS_KEY_FILE));
        config.staking_tls_cert_file = Some(String::from(DEFAULT_STAKING_TLS_CERT_FILE));

        config.snow_sample_size = Some(DEFAULT_SNOW_SAMPLE_SIZE);
        config.snow_quorum_size = Some(DEFAULT_SNOW_QUORUM_SIZE);

        config.http_host = Some(String::from(DEFAULT_HTTP_HOST));
        config.http_port = Some(DEFAULT_HTTP_PORT);
        config.staking_port = Some(DEFAULT_STAKING_PORT);

        config.db_dir = Some(String::from(DEFAULT_DB_DIR));
        config.log_dir = Some(String::from(DEFAULT_LOG_DIR));

        config.index_enabled = Some(DEFAULT_INDEX_ENABLED);
        config.api_admin_enabled = Some(DEFAULT_API_ADMIN_ENABLED);
        config.api_ipcs_enabled = Some(DEFAULT_API_IPCS_ENABLED);
        config
    }

    /// Returns true if the topology is mainnet.
    pub fn is_mainnet(&self) -> bool {
        self.network_id.is_none() || self.network_id.unwrap() == 1
    }

    /// Converts to string with JSON encoder.
    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to YAML {}", e),
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
        let p = file_path.unwrap_or_else(|| self.config_file.clone().unwrap());

        info!("syncing avalanchego Config to '{}'", p);
        let path = Path::new(&p);
        let parent_dir = path.parent().unwrap();
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
        if self.network_id.is_none() && self.genesis.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--genesis={}' but empty '--network-id'",
                    self.genesis.clone().unwrap()
                ),
            ));
        }

        // custom network requires genesis file
        if self.network_id.is_some() && self.genesis.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--network-id={}' but empty '--genesis'",
                    self.network_id.unwrap()
                ),
            ));
        }

        // custom network requires genesis file
        if self.genesis.is_some() && !Path::new(&self.genesis.clone().unwrap()).exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "non-empty '--genesis={}' but genesis file does not exist",
                    self.genesis.clone().unwrap()
                ),
            ));
        }

        // network ID must match with the one in genesis file
        if self.genesis.is_some() {
            let genesis_file_path = self.genesis.clone().unwrap();
            let genesis_config = crate::genesis::Config::load(&genesis_file_path).unwrap();
            let genesis_network_id = self.network_id.unwrap();
            if genesis_config.network_id.ne(&genesis_network_id) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'genesis' network ID {} != avalanchego::Config.network_id {}",
                        genesis_network_id,
                        self.network_id.unwrap()
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
    use std::fs;

    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = Config::new();
    config.network_id = Some(1337);

    let ret = config.encode_json();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = crate::random::tmp_path(10).unwrap();
    let ret = config.sync(Some(p.clone()));
    assert!(ret.is_ok());

    let config_loaded = Config::load(&p).unwrap();
    assert_eq!(config, config_loaded);

    fs::remove_file(p).unwrap();
}
