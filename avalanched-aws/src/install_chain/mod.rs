use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use aws_manager::{self, s3};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "install-chain";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub region: String,
    pub s3_bucket: String,

    pub chain_config_s3_key: String,
    pub chain_config_local_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Update chain config (WARN: ALWAYS OVERWRITES)")
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
            Arg::new("CHAIN_CONFIG_S3_KEY")
                .long("chain-config-s3-key")
                .help("Sets the S3 key for the chain config")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_LOCAL_PATH")
                .long("chain-config-local-path")
                .help("Chain configuration local file path")
                .required(true)
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let shared_config =
        aws_manager::load_config(Some(opts.region.clone()), Some(Duration::from_secs(30))).await?;
    let s3_manager = s3::Manager::new(&shared_config);

    {
        let path = Path::new(&opts.chain_config_local_path);
        if path.exists() {
            log::warn!(
                "about to overwrite subnet chain config path {}",
                opts.chain_config_local_path
            );
        }
        if let Some(parent_dir) = path.parent() {
            log::info!(
                "creating parent dir '{}' for subnet chain config",
                parent_dir.display()
            );
            fs::create_dir_all(parent_dir)?;
        }

        let tmp_path = random_manager::tmp_path(15, None)?;
        let mut success = false;
        for round in 0..20 {
            log::info!(
                "[ROUND {round}] get_object for {}",
                opts.chain_config_s3_key
            );

            let res = s3_manager
                .get_object(&opts.s3_bucket, &opts.chain_config_s3_key, &tmp_path)
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
            "copying subnet chain config file {tmp_path} to {}",
            opts.chain_config_local_path
        );
        fs::copy(&tmp_path, &opts.chain_config_local_path)?;
        fs::remove_file(&tmp_path)?;
    }

    Ok(())
}
