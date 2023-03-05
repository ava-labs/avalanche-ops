use std::{
    fs,
    io::{self, Error, ErrorKind},
};

use avalanche_installer;
use avalanche_telemetry_cloudwatch_installer;
use aws_ip_provisioner_installer;
use aws_manager::{self, s3};
use aws_volume_provisioner_installer;
use clap::{Arg, Command};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "install";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Installs components")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_S3_KEY")
                .long("avalanchego-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_TARGET_FILE_PATH")
                .long("avalanchego-target-file-path")
                .help("Non-empty to download avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_PLUGIN_S3_PREFIX")
                .long("avalanchego-plugin-s3-prefix")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_PLUGIN_TARGET_DIR")
                .long("avalanchego-plugin-target-dir")
                .help("Non-empty to download avalanchego plugins from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("RUST_OS_TYPE")
                .long("rust-os-type")
                .help("Sets Rust OS type")
                .required(false)
                .num_args(1)
                .value_parser(["ubuntu20.04"])
                .default_value("ubuntu20.04"),
        )
        .arg(
            Arg::new("AVALANCHE_CONFIG_S3_KEY")
                .long("avalanche-config-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHE_CONFIG_TARGET_FILE_PATH")
                .long("avalanche-config-target-file-path")
                .help("Non-empty to download avalanche-config")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AWS_VOLUME_PROVISIONER_S3_KEY")
                .long("aws-volume-provisioner-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AWS_VOLUME_PROVISIONER_TARGET_FILE_PATH")
                .long("aws-volume-provisioner-target-file-path")
                .help("Non-empty to download aws-volume-provisioner")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AWS_IP_PROVISIONER_S3_KEY")
                .long("aws-ip-provisioner-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AWS_IP_PROVISIONER_TARGET_FILE_PATH")
                .long("aws-ip-provisioner-target-file-path")
                .help("Non-empty to download aws-ip-provisioner")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHE_TELEMETRY_CLOUDWATCH_S3_KEY")
                .long("avalanche-telemetry-cloudwatch-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHE_TELEMETRY_CLOUDWATCH_TARGET_FILE_PATH")
                .long("avalanche-telemetry-cloudwatch-target-file-path")
                .help("Non-empty to download avalanche-telemetry-cloudwatch")
                .required(false)
                .num_args(1),
        )
}

/// 1. If the S3 key is not empty, download from S3.
/// 2. If the S3 object does not exist, download from github.
/// 3. If the S3 download fails, fall back to github downloads.
pub async fn execute(
    log_level: &str,
    region: &str,
    s3_bucket: &str,
    avalanchego_s3_key: &str,
    avalanchego_target_file_path: &str,
    avalanchego_plugin_s3_prefix: &str,
    avalanchego_plugin_target_dir: &str,
    rust_os_type: &str,
    avalanche_config_s3_key: &str,
    avalanche_config_target_file_path: &str,
    aws_volume_provisioner_s3_key: &str,
    aws_volume_provisioner_target_file_path: &str,
    aws_ip_provisioner_s3_key: &str,
    aws_ip_provisioner_target_file_path: &str,
    avalanche_telemetry_cloudwatch_s3_key: &str,
    avalanche_telemetry_cloudwatch_target_file_path: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let shared_config = aws_manager::load_config(Some(region.to_string())).await?;
    let s3_manager = s3::Manager::new(&shared_config);

    let need_github_download = if !avalanchego_s3_key.is_empty() {
        log::info!("downloading avalanche from s3");

        let (mut success, mut exists) = (false, false);
        for round in 0..20 {
            log::info!("[ROUND {round}] checking if {avalanchego_s3_key} exists");

            let res = s3_manager.exists(&s3_bucket, &avalanchego_s3_key).await;

            if res.is_ok() {
                success = true;
                exists = res.unwrap();
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("s3 exists retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("s3 exists failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "s3 exists check failed with retries",
            ));
        }
        if !exists {
            log::info!("{avalanchego_s3_key} does not exist, falling back to github downloads");
            true
        } else {
            log::info!("{avalanchego_s3_key} exists {exists}");
            avalanche_installer::avalanchego::s3::download_avalanche_and_plugins(
                false, // not overwrite
                &s3_manager,
                s3_bucket,
                avalanchego_s3_key,
                avalanchego_target_file_path,
                avalanchego_plugin_s3_prefix,
                avalanchego_plugin_target_dir,
            )
            .await?;
            false
        }
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading avalanchego from github");
        let tmp_path = avalanche_installer::avalanchego::github::download(None, None, None).await?;
        fs::copy(&tmp_path, &avalanchego_target_file_path)?;
        fs::remove_file(&tmp_path)?;
    }

    let need_github_download = if !avalanche_config_s3_key.is_empty() {
        log::info!("downloading avalanche-config from s3");

        let (mut success, mut exists) = (false, false);
        for round in 0..20 {
            log::info!("[ROUND {round}] checking if {avalanche_config_s3_key} exists");

            let res = s3_manager
                .exists(&s3_bucket, &avalanche_config_s3_key)
                .await;

            if res.is_ok() {
                success = true;
                exists = res.unwrap();
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("s3 exists retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("s3 exists failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "s3 exists check failed with retries",
            ));
        }
        if !exists {
            log::info!(
                "{avalanche_config_s3_key} does not exist, falling back to github downloads"
            );
            true
        } else {
            log::info!("{avalanche_config_s3_key} exists {exists}");
            avalanche_config_installer::s3::download(
                true, // overwrite
                &s3_manager,
                s3_bucket,
                avalanche_config_s3_key,
                avalanche_config_target_file_path,
            )
            .await?;
            false
        }
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading avalanche-config from github");
        let ot = if rust_os_type.is_empty() {
            None
        } else {
            Some(avalanche_config_installer::github::Os::new(rust_os_type).unwrap())
        };
        avalanche_config_installer::github::download(
            None,
            ot,
            None,
            avalanche_config_target_file_path,
        )
        .await?;
    }

    let need_github_download = if !aws_volume_provisioner_s3_key.is_empty() {
        log::info!("downloading aws-volume-provisioner from s3");

        let (mut success, mut exists) = (false, false);
        for round in 0..20 {
            log::info!("[ROUND {round}] checking if {aws_volume_provisioner_s3_key} exists");

            let res = s3_manager
                .exists(&s3_bucket, &aws_volume_provisioner_s3_key)
                .await;

            if res.is_ok() {
                success = true;
                exists = res.unwrap();
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("s3 exists retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("s3 exists failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "s3 exists check failed with retries",
            ));
        }
        if !exists {
            log::info!(
                "{aws_volume_provisioner_s3_key} does not exist, falling back to github downloads"
            );
            true
        } else {
            log::info!("{aws_volume_provisioner_s3_key} exists {exists}");
            aws_volume_provisioner_installer::s3::download(
                true, // overwrite
                &s3_manager,
                s3_bucket,
                aws_volume_provisioner_s3_key,
                aws_volume_provisioner_target_file_path,
            )
            .await?;
            false
        }
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading aws-volume-provisioner from github");
        let ot = if rust_os_type.is_empty() {
            None
        } else {
            Some(aws_volume_provisioner_installer::github::Os::new(rust_os_type).unwrap())
        };
        aws_volume_provisioner_installer::github::download(
            None,
            ot,
            None,
            aws_volume_provisioner_target_file_path,
        )
        .await?;
    }

    let need_github_download = if !aws_ip_provisioner_s3_key.is_empty() {
        log::info!("downloading aws-ip-provisioner from s3");

        let (mut success, mut exists) = (false, false);
        for round in 0..20 {
            log::info!("[ROUND {round}] checking if {aws_ip_provisioner_s3_key} exists");

            let res = s3_manager
                .exists(&s3_bucket, &aws_ip_provisioner_s3_key)
                .await;

            if res.is_ok() {
                success = true;
                exists = res.unwrap();
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("s3 exists retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("s3 exists failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "s3 exists check failed with retries",
            ));
        }
        if !exists {
            log::info!(
                "{aws_ip_provisioner_s3_key} does not exist, falling back to github downloads"
            );
            true
        } else {
            log::info!("{aws_ip_provisioner_s3_key} exists {exists}");
            aws_ip_provisioner_installer::s3::download(
                true, // overwrite
                &s3_manager,
                s3_bucket,
                aws_ip_provisioner_s3_key,
                aws_ip_provisioner_target_file_path,
            )
            .await?;
            false
        }
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading aws-ip-provisioner from github");
        let ot = if rust_os_type.is_empty() {
            None
        } else {
            Some(aws_ip_provisioner_installer::github::Os::new(rust_os_type).unwrap())
        };
        aws_ip_provisioner_installer::github::download(
            None,
            ot,
            None,
            aws_ip_provisioner_target_file_path,
        )
        .await?;
    }

    let need_github_download = if !avalanche_telemetry_cloudwatch_s3_key.is_empty() {
        log::info!("downloading avalanche-telemetry-cloudwatch from s3");

        let (mut success, mut exists) = (false, false);
        for round in 0..20 {
            log::info!(
                "[ROUND {round}] checking if {avalanche_telemetry_cloudwatch_s3_key} exists"
            );

            let res = s3_manager
                .exists(&s3_bucket, &avalanche_telemetry_cloudwatch_s3_key)
                .await;

            if res.is_ok() {
                success = true;
                exists = res.unwrap();
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("s3 exists retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("s3 exists failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "s3 exists check failed with retries",
            ));
        }
        if !exists {
            log::info!(
                "{avalanche_telemetry_cloudwatch_s3_key} does not exist, falling back to github downloads"
            );
            true
        } else {
            log::info!("{avalanche_telemetry_cloudwatch_s3_key} exists {exists}");
            avalanche_telemetry_cloudwatch_installer::s3::download(
                true, // overwrite
                &s3_manager,
                s3_bucket,
                avalanche_telemetry_cloudwatch_s3_key,
                avalanche_telemetry_cloudwatch_target_file_path,
            )
            .await?;
            false
        }
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading avalanche-telemetry-cloudwatch from github");
        let ot = if rust_os_type.is_empty() {
            None
        } else {
            Some(avalanche_telemetry_cloudwatch_installer::github::Os::new(rust_os_type).unwrap())
        };
        avalanche_telemetry_cloudwatch_installer::github::download(
            None,
            ot,
            None,
            avalanche_telemetry_cloudwatch_target_file_path,
        )
        .await?;
    }

    Ok(())
}
