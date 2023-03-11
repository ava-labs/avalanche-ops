use std::{
    collections::HashMap,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "install-subnet";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub skip_prompt: bool,

    pub chain_rpc_url: String,
    pub key: String,

    pub subnet_config_path: String,
    pub vm_binary_path: String,
    pub chain_config_path: String,
    pub chain_genesis_path: String,

    pub region: String,
    pub s3_bucket: String,
    pub s3_key_vm_binary: String,
    pub ssm_doc: String,

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
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
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
            Arg::new("CHAIN_CONFIG_PATH")
                .long("chain-config-path")
                .help("Chain configuration file path")
                .required(false)
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
            Arg::new("S3_KEY_VM_BINARY")
                .long("s3-key-vm-binary")
                .help("Sets the S3 key for the Vm binary")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("SSM_DOC")
                .long("ssm-doc")
                .help("Sets the SSM document name for subnet install")
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
            "\nInstalling subnet with chain rpc url '{}', subnet config '{}', VM binary '{}', chain config '{}', chain genesis '{}', node ids to instance ids '{:?}'\n",
            opts.chain_rpc_url, opts.subnet_config_path, opts.vm_binary_path, opts.chain_config_path, opts.chain_genesis_path, opts.node_ids_to_instance_ids,
        )),
        ResetColor
    )?;

    if !opts.skip_prompt {
        let options = &[
            "No, I am not ready to install a subnet.",
            "Yes, let's install a subnet.",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'install-subnet' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: uploading VM binary to S3\n\n"),
        ResetColor
    )?;
    if !Path::new(&opts.vm_binary_path).exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("vm binary '{}' not found", opts.vm_binary_path),
        ));
    }
    let s3_key_vm_binary = if !opts.s3_key_vm_binary.is_empty() {
        opts.s3_key_vm_binary.clone()
    } else {
        let file_stem = Path::new(&opts.vm_binary_path).file_stem().unwrap();
        file_stem.to_str().unwrap().to_string()
    };
    log::info!(
        "uploading vm binary '{}' to {} {s3_key_vm_binary}",
        opts.vm_binary_path,
        opts.s3_bucket
    );
    // TODO: upload VM binary to S3

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: loading wallets to install subnets\n\n"),
        ResetColor
    )?;
    // TODO: load wallet

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as primary network validators if not yet\n\n"),
        ResetColor
    )?;
    // TODO: add nodes as primary network validator if not yet

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating a subnet\n\n"),
        ResetColor
    )?;
    // TODO: create subnet

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: track the subnet in remote nodes\n\n"),
        ResetColor
    )?;
    // TODO: track subnet by restarting nodes

    if !opts.subnet_config_path.is_empty() {
        //
        //
        //
        //
        //
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(
                "\n\n\nSTEP: update subnet config by sending SSM commands to remote machines\n\n"
            ),
            ResetColor
        )?;
        // TODO: write subnet config if not empty on remote machines
    }

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as subnet validators\n\n"),
        ResetColor
    )?;
    // TODO: add nodes as subnet network validator if not yet

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating a blockchain with the genesis\n\n"),
        ResetColor
    )?;
    // TODO: create blockchain with genesis

    if !opts.chain_config_path.is_empty() {
        //
        //
        //
        //
        //
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(
                "\n\n\nSTEP: update subnet chain config by sending SSM commands to remote machines\n\n"
            ),
            ResetColor
        )?;
        // TODO: write chain config if not empty on remote machines
    }

    Ok(())
}
