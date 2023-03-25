use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
};

use avalanche_types::{avalanchego::config as avalanchego_config, ids};
use aws_manager::{self, s3};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "install-subnet";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub region: String,
    pub s3_bucket: String,

    pub subnet_config_s3_key: String,
    pub subnet_config_local_path: String,

    pub vm_binary_s3_key: String,
    pub vm_binary_local_path: String,

    pub subnet_id_to_track: String,
    pub avalanchego_config_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about(
            "Download Vm binary, track subnet Id, update subnet config (WARN: ALWAYS OVERWRITES)",
        )
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
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_S3_KEY")
                .long("subnet-config-s3-key")
                .help("Sets the S3 key for the subnet config (if empty, do not download)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_LOCAL_PATH")
                .long("subnet-config-local-path")
                .help("Subnet configuration local file path (if empty, do not download)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_S3_KEY")
                .long("vm-binary-s3-key")
                .help("Download VM binary from S3")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_LOCAL_PATH")
                .long("vm-binary-local-path")
                .help("VM binary local file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_ID_TO_TRACK")
                .long("subnet-id-to-track")
                .help("Subnet Id to track via avalanchego config file")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_CONFIG_PATH")
                .long("avalanchego-config-path")
                .help("avalanchego config file path")
                .required(true)
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let shared_config =
        aws_manager::load_config(Some(opts.region.clone()), Some(Duration::from_secs(30))).await?;
    let s3_manager = s3::Manager::new(&shared_config);

    if !opts.subnet_config_s3_key.is_empty() && !opts.subnet_config_s3_key.is_empty() {
        let path = Path::new(&opts.subnet_config_local_path);
        if path.exists() {
            log::warn!(
                "about to overwrite subnet config path {}",
                opts.subnet_config_local_path
            );
        }
        if let Some(parent_dir) = path.parent() {
            log::info!(
                "creating parent dir '{}' for subnet config",
                parent_dir.display()
            );
            fs::create_dir_all(parent_dir)?;
        }

        let tmp_path = random_manager::tmp_path(15, None)?;
        let mut success = false;
        for round in 0..20 {
            log::info!(
                "[ROUND {round}] get_object for {}",
                opts.subnet_config_s3_key
            );

            let res = s3_manager
                .get_object(&opts.s3_bucket, &opts.subnet_config_s3_key, &tmp_path)
                .await;

            if res.is_ok() {
                success = true;
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("get_object retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("get_object failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "get_object failed to download with retries",
            ));
        }
        log::info!("successfully downloaded to {tmp_path}");
        {
            let f = File::open(&tmp_path)?;
            f.set_permissions(PermissionsExt::from_mode(0o777))?;
        }
        log::info!(
            "copying subnet-config file {tmp_path} to {}",
            opts.subnet_config_local_path
        );
        fs::copy(&tmp_path, &opts.subnet_config_local_path)?;
        fs::remove_file(&tmp_path)?;
    } else {
        log::info!("skipping downloading subnet config since empty");
    }

    {
        let path = Path::new(&opts.vm_binary_local_path);
        if path.exists() {
            log::warn!(
                "about to overwrite VM binary path {}",
                opts.vm_binary_local_path
            );
        }
        if let Some(parent_dir) = path.parent() {
            log::info!(
                "creating parent dir '{}' for vm binary",
                parent_dir.display()
            );
            fs::create_dir_all(parent_dir)?;
        }

        let tmp_path = random_manager::tmp_path(15, None)?;
        let mut success = false;
        for round in 0..20 {
            log::info!("[ROUND {round}] get_object for {}", opts.vm_binary_s3_key);

            let res = s3_manager
                .get_object(&opts.s3_bucket, &opts.vm_binary_s3_key, &tmp_path)
                .await;

            if res.is_ok() {
                success = true;
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("get_object retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("get_object failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "get_object failed to download with retries",
            ));
        }
        log::info!("successfully downloaded to {tmp_path}");
        {
            let f = File::open(&tmp_path)?;
            f.set_permissions(PermissionsExt::from_mode(0o777))?;
        }

        log::info!(
            "copying Vm binary file {tmp_path} to {}",
            opts.vm_binary_local_path
        );
        match fs::copy(&tmp_path, &opts.vm_binary_local_path) {
            Ok(_) => log::info!("successfully copied file"),
            Err(e) => {
                log::warn!("failed to copy file {}", e);

                // mask the error
                // Os { code: 26, kind: ExecutableFileBusy, message: "Text file busy" }
                if !e.to_string().to_lowercase().contains("text file busy") {
                    return Err(e);
                }
            }
        }
        fs::remove_file(&tmp_path)?;
    }

    {
        log::info!(
            "adding a subnet-id '{}' to track-subnets flag in {}",
            opts.subnet_id_to_track,
            opts.avalanchego_config_path,
        );
        let converted = ids::Id::from_str(&opts.subnet_id_to_track)?;
        log::info!("validated a subnet-id '{}'", converted);

        let mut config = avalanchego_config::Config::load(&opts.avalanchego_config_path)?;
        if let Some(existing_config_path) = &config.config_file {
            if existing_config_path.ne(&opts.avalanchego_config_path) {
                log::warn!(
                    "overwriting existing config-file {} to {}",
                    existing_config_path,
                    opts.avalanchego_config_path
                );
                config.config_file = Some(opts.avalanchego_config_path.clone());
            }
        }
        config.add_track_subnets(Some(converted.to_string()));

        config.sync(None)?;
    }

    Ok(())
}
