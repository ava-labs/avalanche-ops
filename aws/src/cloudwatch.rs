use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
    sync::Arc,
    thread, time,
};

use aws_sdk_cloudwatch::{
    model::MetricDatum, types::SdkError as MetricsSdkError, Client as MetricsClient,
};
use aws_sdk_cloudwatchlogs::{
    error::{
        CreateLogGroupError, CreateLogGroupErrorKind, DeleteLogGroupError, DeleteLogGroupErrorKind,
    },
    types::SdkError as LogsSdkError,
    Client as LogsClient,
};
use aws_types::SdkConfig as AwsSdkConfig;
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::errors::{Error::API, Result};

/// Implements AWS CloudWatch manager.
#[derive(Debug, Clone)]
pub struct Manager {
    #[allow(dead_code)]
    shared_config: AwsSdkConfig,
    metrics_cli: MetricsClient,
    logs_cli: LogsClient,
}

impl Manager {
    pub fn new(shared_config: &AwsSdkConfig) -> Self {
        let cloned = shared_config.clone();
        let metrics_cli = MetricsClient::new(shared_config);
        let logs_cli = LogsClient::new(shared_config);
        Self {
            shared_config: cloned,
            metrics_cli,
            logs_cli,
        }
    }

    /// Posts CloudWatch metrics.
    ///
    /// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html
    /// ref. https://docs.rs/aws-sdk-cloudwatch/latest/aws_sdk_cloudwatch/struct.Client.html#method.put_metric_data
    ///
    /// "If a single piece of data must be accessible from more than one task
    /// concurrently, then it must be shared using synchronization primitives such as Arc."
    /// ref. https://tokio.rs/tokio/tutorial/spawning
    pub async fn put_metric_data(
        &self,
        namespace: Arc<String>,
        data: Arc<Vec<MetricDatum>>,
    ) -> Result<()> {
        let n = data.len();
        info!("posting CloudWatch {} metrics in '{}'", n, namespace);
        if n <= 20 {
            let ret = self
                .metrics_cli
                .put_metric_data()
                .namespace(namespace.clone().to_string())
                .set_metric_data(Some(data.to_vec()))
                .send()
                .await;
            match ret {
                Ok(_) => {
                    info!("successfully post metrics");
                }
                Err(e) => {
                    return Err(API {
                        message: format!("failed put_metric_data {:?}", e),
                        is_retryable: is_metrics_error_retryable(&e),
                    });
                }
            };
        } else {
            warn!("put_metric_data limit is 20, got {}; batching by 20...", n);
            for batch in data.chunks(20) {
                let batch_n = batch.len();
                let ret = self
                    .metrics_cli
                    .put_metric_data()
                    .namespace(namespace.to_string())
                    .set_metric_data(Some(batch.to_vec()))
                    .send()
                    .await;
                match ret {
                    Ok(_) => {
                        info!("successfully post {} metrics in batch", batch_n);
                    }
                    Err(e) => {
                        return Err(API {
                            message: format!("failed put_metric_data {:?}", e),
                            is_retryable: is_metrics_error_retryable(&e),
                        });
                    }
                }
                thread::sleep(time::Duration::from_secs(1));
            }
        }

        Ok(())
    }

    /// Creates a CloudWatch log group.
    /// ref. https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    pub async fn create_log_group(&self, log_group_name: &str) -> Result<()> {
        info!("creating CloudWatch log group '{}'", log_group_name);
        let ret = self
            .logs_cli
            .create_log_group()
            .log_group_name(log_group_name)
            .send()
            .await;
        let already_created = match ret {
            Ok(_) => false,
            Err(e) => {
                if !is_logs_error_create_log_group_already_exists(&e) {
                    return Err(API {
                        message: format!("failed create_log_group {:?}", e),
                        is_retryable: is_logs_error_retryable(&e),
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
    /// ref. https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    pub async fn delete_log_group(&self, log_group_name: &str) -> Result<()> {
        info!("deleting CloudWatch log group '{}'", log_group_name);
        let ret = self
            .logs_cli
            .delete_log_group()
            .log_group_name(log_group_name)
            .send()
            .await;
        let deleted = match ret {
            Ok(_) => true,
            Err(e) => {
                let mut ignore_err: bool = false;
                if is_logs_error_delete_log_group_does_not_exist(&e) {
                    warn!(
                        "delete_log_group failed; '{}' does not exist ({}",
                        log_group_name, e
                    );
                    ignore_err = true
                }
                if !ignore_err {
                    return Err(API {
                        message: format!("failed delete_log_group {:?}", e),
                        is_retryable: is_logs_error_retryable(&e),
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
pub fn is_metrics_error_retryable<E>(e: &MetricsSdkError<E>) -> bool {
    match e {
        MetricsSdkError::TimeoutError(_) | MetricsSdkError::ResponseError { .. } => true,
        MetricsSdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
pub fn is_logs_error_retryable<E>(e: &LogsSdkError<E>) -> bool {
    match e {
        LogsSdkError::TimeoutError(_) | LogsSdkError::ResponseError { .. } => true,
        LogsSdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
fn is_logs_error_create_log_group_already_exists(e: &LogsSdkError<CreateLogGroupError>) -> bool {
    match e {
        LogsSdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                CreateLogGroupErrorKind::ResourceAlreadyExistsException(_)
            )
        }
        _ => false,
    }
}

#[inline]
fn is_logs_error_delete_log_group_does_not_exist(e: &LogsSdkError<DeleteLogGroupError>) -> bool {
    match e {
        LogsSdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                DeleteLogGroupErrorKind::ResourceNotFoundException(_)
            )
        }
        _ => false,
    }
}

pub async fn spawn_put_metric_data(
    cw_manager: Manager,
    namespace: &str,
    data: Vec<MetricDatum>,
) -> Result<()> {
    let cw_manager_arc = Arc::new(cw_manager);
    let namespace_arc = Arc::new(namespace.to_string());
    tokio::spawn(async move {
        cw_manager_arc
            .put_metric_data(namespace_arc, Arc::new(data))
            .await
    })
    .await
    .expect("failed spawn await")
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_in_days: Option<u16>,
}

impl Default for Collect {
    fn default() -> Self {
        Self {
            log_group_name: String::from(""),
            log_stream_name: String::from(""),
            file_path: String::from(""),
            timestamp_format: None,
            timezone: None,
            auto_removal: None,
            retention_in_days: None,
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Metrics {
    pub namespace: String,
    pub metrics_collected: MetricsCollected,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append_dimensions: Option<HashMap<String, String>>,
    /// Specifies the dimensions that collected metrics are to be aggregated on.
    /// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation_dimensions: Option<Vec<Vec<String>>>,
    pub force_flush_interval: u32,
}

impl Default for Metrics {
    fn default() -> Self {
        // ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
        let mut m = HashMap::new();
        m.insert("InstanceId".to_string(), "${aws:InstanceId}".to_string());
        m.insert(
            "InstanceType".to_string(),
            "${aws:InstanceType}".to_string(),
        );
        m.insert(
            "AutoScalingGroupName".to_string(),
            "${aws:AutoScalingGroupName}".to_string(),
        );
        Self {
            namespace: String::new(),
            metrics_collected: MetricsCollected::default(),
            append_dimensions: Some(m),
            aggregation_dimensions: Some(vec![
                vec!["AutoScalingGroupName".to_string()],
                vec!["InstanceId".to_string(), "InstanceType".to_string()],
            ]),
            force_flush_interval: 30,
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct MetricsCollected {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Cpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<Mem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<Disk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diskio: Option<DiskIo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<Net>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netstat: Option<Netstat>,
}

impl Default for MetricsCollected {
    fn default() -> Self {
        Self {
            cpu: Some(Cpu::default()),
            mem: Some(Mem::default()),
            disk: Some(Disk::default()),
            diskio: Some(DiskIo::default()),
            net: Some(Net::default()),
            netstat: Some(Netstat::default()),
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Cpu {
    pub resources: Vec<String>,
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for Cpu {
    fn default() -> Self {
        Self {
            resources: vec!["*".to_string()],
            measurement: vec![
                "usage_active".to_string(), // cpu_usage_* metrics is Percent
                "usage_system".to_string(), // cpu_usage_* metrics is Percent
            ],
            metrics_collection_interval: 60,
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
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

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
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
            measurement: vec![
                "used".to_string(),
                "total".to_string(),
                "inodes_used".to_string(),
                "inodes_total".to_string(),
            ],
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

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
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
            // "nvme0n1" for boot volume (AWS)
            // "nvme0n1p1" for boot volume (AWS)
            // "nvme1n1" for mounted EBS (AWS)
            // (run "lsblk" to find out which devices)
            resources: vec!["nvme1n1".to_string()],
            measurement: vec![
                "reads".to_string(),
                "writes".to_string(),
                "read_time".to_string(),
                "write_time".to_string(),
            ],
            metrics_collection_interval: 60,
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Net {
    pub resources: Vec<String>,
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for Net {
    fn default() -> Self {
        Self {
            resources: vec!["*".to_string()],
            measurement: vec![
                "bytes_sent".to_string(),
                "bytes_recv".to_string(),
                "packets_sent".to_string(),
                "packets_recv".to_string(),
            ],
            metrics_collection_interval: 60,
        }
    }
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Netstat {
    pub measurement: Vec<String>,
    pub metrics_collection_interval: u32,
}

impl Default for Netstat {
    fn default() -> Self {
        Self {
            measurement: vec!["tcp_listen".to_string(), "tcp_established".to_string()],
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
        info!("validating the CloudWatch configuration");

        Ok(())
    }
}

#[test]
fn test_config() {
    use std::fs;
    use avalanche_utils::random;
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
