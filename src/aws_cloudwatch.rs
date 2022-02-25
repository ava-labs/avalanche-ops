use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use aws_sdk_cloudwatchlogs::{
    error::{
        CreateLogGroupError, CreateLogGroupErrorKind, DeleteLogGroupError, DeleteLogGroupErrorKind,
    },
    types::SdkError,
    Client,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::errors::{Error::API, Result};

/// Implements AWS CloudWatch manager.
pub struct Manager {
    #[allow(dead_code)]
    shared_config: aws_config::Config,
    cli: Client,
}

impl Manager {
    pub fn new(shared_config: &aws_config::Config) -> Self {
        let cloned = shared_config.clone();
        let cli = Client::new(shared_config);
        Self {
            shared_config: cloned,
            cli,
        }
    }

    /// Creates a CloudWatch log group.
    pub async fn create_log_group(&self, log_group_name: &str) -> Result<()> {
        // ref. https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
        info!("creating CloudWatch log group '{}'", log_group_name);
        let ret = self
            .cli
            .create_log_group()
            .log_group_name(log_group_name)
            .send()
            .await;
        let already_created = match ret {
            Ok(_) => false,
            Err(e) => {
                if !is_error_create_log_group_already_exists(&e) {
                    return Err(API {
                        message: format!("failed create_log_group {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                warn!("log_group already exists ({})", e);
                true
            }
        };
        if !already_created {
            info!("created CloudWatch log group");
        }
        Ok(())
    }

    /// Deletes a CloudWatch log group.
    pub async fn delete_log_group(&self, log_group_name: &str) -> Result<()> {
        // ref. https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
        info!("deleting CloudWatch log group '{}'", log_group_name);
        let ret = self
            .cli
            .delete_log_group()
            .log_group_name(log_group_name)
            .send()
            .await;
        let deleted = match ret {
            Ok(_) => true,
            Err(e) => {
                let mut ignore_err: bool = false;
                if is_error_delete_log_group_does_not_exist(&e) {
                    warn!(
                        "delete_log_group failed; '{}' does not exist ({}",
                        log_group_name, e
                    );
                    ignore_err = true
                }
                if !ignore_err {
                    return Err(API {
                        message: format!("failed delete_log_group {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                false
            }
        };
        if deleted {
            info!("deleted CloudWatch log group");
        };
        Ok(())
    }
}

#[inline]
pub fn is_error_retryable<E>(e: &SdkError<E>) -> bool {
    match e {
        SdkError::TimeoutError(_) | SdkError::ResponseError { .. } => true,
        SdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
fn is_error_create_log_group_already_exists(e: &SdkError<CreateLogGroupError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                CreateLogGroupErrorKind::ResourceAlreadyExistsException(_)
            )
        }
        _ => false,
    }
}

#[inline]
fn is_error_delete_log_group_does_not_exist(e: &SdkError<DeleteLogGroupError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                DeleteLogGroupErrorKind::ResourceNotFoundException(_)
            )
        }
        _ => false,
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
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

impl Default for Agent {
    fn default() -> Self {
        Self {
            metrics_collection_interval: DEFAULT_METRICS_COLLECTION_INTERVAL,
            region: None,
            logfile: String::from(DEFAULT_LOGFILE),
            debug: Some(false),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Logs {
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
    pub log_stream_name: String,
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

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Metrics {
    pub namespace: String,
    pub metrics_collected: MetricsCollected,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append_dimensions: Option<HashMap<String, String>>,
    pub force_flush_interval: u32,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut m = HashMap::new();
        // m.insert("InstanceId".to_string(), "${aws:InstanceId}".to_string());
        // m.insert(
        //     "InstanceType".to_string(),
        //     "${aws:InstanceType}".to_string(),
        // );
        m.insert(
            "AutoScalingGroupName".to_string(),
            "${aws:AutoScalingGroupName}".to_string(),
        );
        Self {
            namespace: String::new(),
            metrics_collected: MetricsCollected::default(),
            append_dimensions: Some(m),
            force_flush_interval: 30,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct MetricsCollected {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<Disk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diskio: Option<DiskIo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<Mem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netstat: Option<Netstat>,
}

impl Default for MetricsCollected {
    fn default() -> Self {
        Self {
            disk: Some(Disk::default()),
            diskio: Some(DiskIo::default()),
            mem: Some(Mem::default()),
            netstat: Some(Netstat::default()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Disk {
    pub resources: Vec<String>,
    pub measurement: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_file_system_types: Option<Vec<String>>,
    pub metrics_collection_interval: u32,
}

impl Default for Disk {
    fn default() -> Self {
        Self {
            resources: vec!["/".to_string()],
            measurement: vec!["free".to_string(), "total".to_string(), "used".to_string()],
            ignore_file_system_types: Some(vec!["sysfs".to_string(), "devtmpfs".to_string()]),
            metrics_collection_interval: 60,
        }
    }
}

impl Disk {
    pub fn new(resources: Vec<String>) -> Self {
        Self {
            resources,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DiskIo {
    pub resources: Vec<String>,
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for DiskIo {
    fn default() -> Self {
        Self {
            resources: vec!["*".to_string()],
            measurement: vec![
                "reads".to_string(),
                "writes".to_string(),
                "read_time".to_string(),
                "write_time".to_string(),
                "io_time".to_string(),
            ],
            metrics_collection_interval: 60,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Mem {
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for Mem {
    fn default() -> Self {
        Self {
            measurement: vec!["mem_used".to_string(), "mem_total".to_string()],
            metrics_collection_interval: 60,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Netstat {
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for Netstat {
    fn default() -> Self {
        Self {
            measurement: vec![
                "tcp_established".to_string(),
                "tcp_syn_sent".to_string(),
                "tcp_close".to_string(),
            ],
            metrics_collection_interval: 60,
        }
    }
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
            metrics: None,
        }
    }

    pub fn default() -> Self {
        let mut config = Self::new();
        config.agent = Some(Agent::default());
        config.metrics = Some(Metrics::default());
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
    use crate::random;
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    let config = Config::default();
    let ret = config.encode_json();
    assert!(ret.is_ok());
    let s = ret.unwrap();
    info!("config: {}", s);

    let p = random::tmp_path(10, Some(".json")).unwrap();
    let ret = config.sync(&p);
    assert!(ret.is_ok());
    fs::remove_file(p).unwrap();
}
