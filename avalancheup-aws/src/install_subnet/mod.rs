use std::{
    collections::HashMap,
    io::{self, stdout},
};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "install-subnet";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub chain_rpc_url: String,
    pub key: String,

    pub subnet_config_path: String,
    pub vm_binary_path: String,
    pub chain_genesis_path: String,
    pub chain_config_path: String,

    pub region: String,
    pub s3_bucket: String,
    pub node_ids_to_instance_ids: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct HashMapParser;

impl clap::builder::TypedValueParser for HashMapParser {
    type Value = HashMap<String, String>;

    fn parse_ref(
        &self,
        _cmd: &Command,
        _arg: Option<&Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let str = value.to_str().unwrap_or_default();
        let m: HashMap<String, String> = serde_json::from_str(str).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("HashMap parsing failed ({})", e),
            )
        })?;
        Ok(m)
    }
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Installs a subnet to target nodes")
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
            Arg::new("CHAIN_RPC_URL")
                .long("chain-rpc-url")
                .help("Sets the P-chain or Avalanche RPC endpoint")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KEY")
                .long("key")
                .help("Sets the key Id (if hotkey, use private key in hex format)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_PATH")
                .long("subnet-config-path")
                .help("Subnet configuration file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_PATH")
                .long("vm-binary-path")
                .help("VM binary file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_GENESIS_PATH")
                .long("chain-genesis-path")
                .help("Chain genesis file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_PATH")
                .long("chain-config-path")
                .help("Chain configuration file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("NODE_IDS_TO_INSTANCE_IDS")
                .long("node-ids-to-instance-ids")
                .help("Sets the hash map of node Id to instance Id in JSON format")
                .required(true)
                .value_parser(HashMapParser {})
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nInstalling subnet with chain rpc url '{}', subnet config '{}', VM binary '{}', chain genesis '{}', chain config '{}', node ids to instance ids '{:?}'\n",
            opts.chain_rpc_url, opts.subnet_config_path, opts.vm_binary_path, opts.chain_genesis_path, opts.chain_config_path, opts.node_ids_to_instance_ids,
        )),
        ResetColor
    )?;
    // TODO: upload VM binary to S3

    // TODO: load wallet

    // TODO: add nodes as primary network validator if not yet

    // TODO: create subnet

    // TODO: track subnet by restarting nodes

    if !opts.subnet_config_path.is_empty() {
        // TODO: write subnet config if not empty on remote machines
        log::info!("subnet config not empty -- sending SSM commands to write subnet config on remote machines");
    }

    // TODO: add nodes as subnet network validator if not yet

    // TODO: create blockchain with genesis

    if !opts.chain_config_path.is_empty() {
        // TODO: write chain config if not empty on remote machines
        log::info!("chain config not empty -- sending SSM commands to write chain config on remote machines");
    }

    Ok(())
}
