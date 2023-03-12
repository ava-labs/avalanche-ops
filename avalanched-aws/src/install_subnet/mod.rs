use std::{
    fs,
    io::{self, Error, ErrorKind},
};

use aws_manager::{self, s3};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "install-subnet";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub region: String,
    pub s3_bucket: String,

    pub subnet_config_s3_key: String,
    pub subnet_config_path: String,

    pub vm_binary_s3_key: String,
    pub vm_binary_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Download Vm binary, track subnet Id, update subnet config")
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
                .help("Sets the S3 key for the subnet config")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_PATH")
                .long("subnet-config-path")
                .help("Subnet configuration file path")
                .required(true)
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
            Arg::new("VM_BINARY_PATH")
                .long("vm-binary-path")
                .help("VM binary file path")
                .required(true)
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let shared_config = aws_manager::load_config(Some(opts.region.clone())).await?;
    let s3_manager = s3::Manager::new(&shared_config);

    Ok(())
}
