use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/opt/aws/amazon-cloudwatch-agent/bin/config.json";

pub const DEFAULT_METRICS_COLLECTION_INTERVAL: u32 = 60;
pub const DEFAULT_LOGFILE: &str =
    "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log";

/// Represents CloudWatch configuration.
/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
/// ref. https://serde.rs/container-attrs.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Agent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<Logs>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Agent {
    pub metrics_collection_interval: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub logfile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Logs {
    /// Specifies the default log stream name to be used for any logs.
    /// e.g., Use test "Id" to publish all logs under one stream.
    pub log_stream_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_collected: Option<LogsCollected>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_flush_interval: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct LogsCollected {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Files>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Files {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collect_list: Option<Vec<Collect>>,
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Collect {
    /// Specifies what to use as the log group name in CloudWatch Logs.
    pub log_group_name: String,
    /// Specifies the path of the log file to upload to CloudWatch Logs.
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_format: Option<String>,
    /// The valid values are UTC and Local.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_removal: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            agent: None,
            logs: None,
        }
    }

    pub fn default() -> Self {
        let mut config = Self::new();
        config.agent = Some(Agent {
            metrics_collection_interval: DEFAULT_METRICS_COLLECTION_INTERVAL,
            region: None,
            logfile: String::from(DEFAULT_LOGFILE),
            debug: Some(false),
        });
        config
    }

    /// Converts to string.
    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current configuration to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing CloudWatch config to '{}'", file_path);
        let path = Path::new(file_path);
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
        let mut f = File::create(file_path)?;
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
        info!("validating the CloudWatch configuration");

        Ok(())
    }
}

#[test]
fn test_config() {
    use std::fs;

    let _ = env_logger::builder().is_test(true).try_init();

    let config = Config::default();
    let ret = config.encode_json();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = crate::random::tmp_path(10).unwrap();
    let ret = config.sync(&p);
    assert!(ret.is_ok());
    fs::remove_file(p).unwrap();
}
