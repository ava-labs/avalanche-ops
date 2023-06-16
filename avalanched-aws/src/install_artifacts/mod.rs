use std::{fs, io};

use aws_manager::{self, s3};

use clap::{Arg, Command};
use tokio::time::Duration;

pub const NAME: &str = "install-artifacts";

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
            Arg::new("S3_REGION")
                .long("s3-region")
                .help("Sets the AWS S3 region")
                .required(true)
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
                .help("Non-empty to download from S3 (overwrites --avalanchego-release-tag)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_LOCAL_PATH")
                .long("avalanchego-local-path")
                .help("Non-empty to download avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_RELEASE_TAG")
                .long("avalanchego-release-tag")
                .help("Non-empty to specify avalanchego release tag to download (ignored if --avalanchego-s3-key is not empty)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("OS_TYPE")
                .long("os-type")
                .help("Sets the OS type")
                .required(false)
                .num_args(1)
                .value_parser(["ubuntu20.04"])
                .default_value("ubuntu20.04"),
        )
        .arg(
            Arg::new("AWS_VOLUME_PROVISIONER_S3_KEY")
                .long("aws-volume-provisioner-s3-key")
                .help("Non-empty to download from S3")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AWS_VOLUME_PROVISIONER_LOCAL_PATH")
                .long("aws-volume-provisioner-local-path")
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
            Arg::new("AWS_IP_PROVISIONER_LOCAL_PATH")
                .long("aws-ip-provisioner-local-path")
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
            Arg::new("AVALANCHE_TELEMETRY_CLOUDWATCH_LOCAL_PATH")
                .long("avalanche-telemetry-cloudwatch-local-path")
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
    s3_region: &str,
    s3_bucket: &str,
    avalanchego_s3_key: &str,
    avalanchego_local_path: &str,
    avalanchego_release_tag: Option<String>,
    os_type: &str,
    aws_volume_provisioner_s3_key: &str,
    aws_volume_provisioner_local_path: &str,
    aws_ip_provisioner_s3_key: &str,
    aws_ip_provisioner_local_path: &str,
    avalanche_telemetry_cloudwatch_s3_key: &str,
    avalanche_telemetry_cloudwatch_local_path: &str,
) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let shared_config = aws_manager::load_config(
        Some(s3_region.to_string()),
        None,
        Some(Duration::from_secs(30)),
    )
    .await;
    let s3_manager = s3::Manager::new(&shared_config);

    let need_github_download = if !avalanchego_s3_key.is_empty() {
        log::info!("downloading avalanche from s3");
        let successfully_downloaded = s3_manager
            .download_executable_with_retries(
                s3_bucket,
                avalanchego_s3_key,
                avalanchego_local_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        !successfully_downloaded
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading avalanchego from github");
        let tmp_path =
            avalanche_installer::avalanchego::github::download(None, None, avalanchego_release_tag)
                .await?;
        fs::copy(&tmp_path, avalanchego_local_path)?;
        fs::remove_file(&tmp_path)?;
    }

    let need_github_download = if !aws_volume_provisioner_s3_key.is_empty() {
        log::info!("downloading aws-volume-provisioner from s3");
        let successfully_downloaded = s3_manager
            .download_executable_with_retries(
                s3_bucket,
                aws_volume_provisioner_s3_key,
                aws_volume_provisioner_local_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        !successfully_downloaded
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading aws-volume-provisioner from github");
        let ot = if os_type.is_empty() {
            None
        } else {
            Some(aws_volume_provisioner_installer::github::Os::new(os_type).unwrap())
        };
        aws_volume_provisioner_installer::github::download(
            None,
            ot,
            Some("latest".to_string()),
            aws_volume_provisioner_local_path,
        )
        .await?;
    }

    let need_github_download = if !aws_ip_provisioner_s3_key.is_empty() {
        log::info!("downloading aws-ip-provisioner from s3");
        let successfully_downloaded = s3_manager
            .download_executable_with_retries(
                s3_bucket,
                aws_ip_provisioner_s3_key,
                aws_ip_provisioner_local_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        !successfully_downloaded
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading aws-ip-provisioner from github");
        let ot = if os_type.is_empty() {
            None
        } else {
            Some(aws_ip_provisioner_installer::github::Os::new(os_type).unwrap())
        };
        aws_ip_provisioner_installer::github::download(
            None,
            ot,
            Some("latest".to_string()),
            aws_ip_provisioner_local_path,
        )
        .await?;
    }

    let need_github_download = if !avalanche_telemetry_cloudwatch_s3_key.is_empty() {
        log::info!("downloading avalanche-telemetry-cloudwatch from s3");
        let successfully_downloaded = s3_manager
            .download_executable_with_retries(
                s3_bucket,
                avalanche_telemetry_cloudwatch_s3_key,
                avalanche_telemetry_cloudwatch_local_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        !successfully_downloaded
    } else {
        true
    };
    if need_github_download {
        log::info!("downloading avalanche-telemetry-cloudwatch from github");
        let ot = if os_type.is_empty() {
            None
        } else {
            Some(avalanche_telemetry_cloudwatch_installer::github::Os::new(os_type).unwrap())
        };
        avalanche_telemetry_cloudwatch_installer::github::download(
            None,
            ot,
            Some("latest".to_string()),
            avalanche_telemetry_cloudwatch_local_path,
        )
        .await?;
    }

    Ok(())
}
