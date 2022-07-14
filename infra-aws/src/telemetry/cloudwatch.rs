use std::{io, path::Path};

use avalanche_types::node;
use aws_manager::cloudwatch;

/// Sets up log collection agent (e.g., cloudwatch agent)
/// using the systemd service.
pub struct ConfigManager {
    /// Used for "log_group_name" and metrics "namespace".
    pub id: String,

    /// Used for naming CloudWatch log name.
    pub node_kind: node::Kind,

    /// Directory where avalanche outputs chain logs.
    pub log_dir: String,

    /// Set "true" to collect instance-level system logs.
    /// Useful to check OOMs via "oom-kill" or "Out of memory: Killed process 8266 (...)"
    pub instance_system_logs: bool,
    /// Set "true" to collect instance-level system metrics.
    pub instance_system_metrics: bool,
    /// Required if "instance_system_metrics" is set "true".
    pub data_volume_path: Option<String>,

    /// CloudWatch agent configuration file path.
    pub config_file_path: String,
}

/// ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
impl ConfigManager {
    /// Set "log_files" to track extra log files via CloudWatch.
    /// e.g., "/var/log/avalanched.log"
    pub fn sync(&self, log_files: Option<Vec<String>>) -> io::Result<()> {
        log::info!("syncing CloudWatch configuration JSON file");

        let mut log_collect_list = vec![
            // e.g., collect all .log files in the /var/log/avalanche tree
            cloudwatch::Collect {
                log_group_name: self.id.clone(),
                log_stream_name: format!("{{instance_id}}-{}-all-logs", self.node_kind.as_str()),
                file_path: format!("{}/**.log", self.log_dir),

                // TODO: replace this with log rotation
                auto_removal: Some(false),

                retention_in_days: Some(7),
                ..cloudwatch::Collect::default()
            },
        ];

        if let Some(v) = log_files {
            for f in v {
                // "/var/log/avalanched.log" becomes "avalanched.log"
                let fname = Path::new(&f)
                    .file_name()
                    .unwrap()
                    .to_os_string()
                    .into_string()
                    .unwrap();

                log_collect_list.push(cloudwatch::Collect {
                    log_group_name: self.id.clone(),
                    log_stream_name: format!(
                        "{{instance_id}}-{}-{}",
                        self.node_kind.as_str(),
                        fname
                    ),

                    file_path: f,

                    auto_removal: Some(true),
                    retention_in_days: Some(7),
                    ..cloudwatch::Collect::default()
                });
            }
        }

        if self.instance_system_logs {
            // to check OOMs via "oom-kill" or "Out of memory: Killed process 8266 (srEXiWaHuhNyGwP)"
            log_collect_list.push(cloudwatch::Collect {
                log_group_name: self.id.clone(),
                log_stream_name: format!("{{instance_id}}-{}-syslog", self.node_kind.as_str()),
                file_path: String::from("/var/log/syslog"),
                auto_removal: Some(true),
                retention_in_days: Some(7),
                ..cloudwatch::Collect::default()
            });
            // to check device layer logs
            log_collect_list.push(cloudwatch::Collect {
                log_group_name: self.id.clone(),
                log_stream_name: format!("{{instance_id}}-{}-dmesg", self.node_kind.as_str()),
                file_path: String::from("/var/log/dmesg"),
                auto_removal: Some(true),
                retention_in_days: Some(7),
                ..cloudwatch::Collect::default()
            });
        }

        let mut cloudwatch_config = cloudwatch::Config::default();
        cloudwatch_config.logs = Some(cloudwatch::Logs {
            force_flush_interval: Some(60),
            logs_collected: Some(cloudwatch::LogsCollected {
                files: Some(cloudwatch::Files {
                    collect_list: Some(log_collect_list),
                }),
            }),
        });

        if self.instance_system_metrics {
            let mut cw_metrics = cloudwatch::Metrics {
                namespace: self.id.clone(),
                ..Default::default()
            };
            cw_metrics.metrics_collected.disk = Some(cloudwatch::Disk::new(vec![self
                .data_volume_path
                .clone()
                .unwrap()]));

            cloudwatch_config.metrics = Some(cw_metrics);
        }

        cloudwatch_config.sync(&self.config_file_path)
    }
}
