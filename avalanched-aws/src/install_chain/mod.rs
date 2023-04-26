use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
};

use aws_manager::{self, s3};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

pub const NAME: &str = "install-chain";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub s3_region: String,
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
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let shared_config =
        aws_manager::load_config(Some(opts.s3_region.clone()), Some(Duration::from_secs(30))).await;
    let s3_manager = s3::Manager::new(&shared_config);

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

    let exists = s3_manager
        .download_executable_with_retries(
            &opts.s3_bucket,
            &opts.chain_config_s3_key,
            &opts.chain_config_local_path,
            true,
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    if !exists {
        return Err(Error::new(
            ErrorKind::Other,
            "chain config s3 file not found",
        ));
    }

    Ok(())
}
