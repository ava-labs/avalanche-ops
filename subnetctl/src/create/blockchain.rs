use std::io::{self, stdout};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

use avalanche_types::ids;

pub const NAME: &str = "blockchain";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Creates a blockchain")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("HTTP_RPC_ENDPOINT")
                .long("http-rpc-endpoint")
                .short('e')
                .help("HTTP RPC endpoint")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SUBNET_ID")
                .long("subnet-id")
                .short('s')
                .help("subnet ID (must be formatted in ids.Id)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CHAIN_NAME")
                .long("chain-name")
                .short('c')
                .help("chain name (must not include special characters)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VM_ID")
                .long("vm-id")
                .short('i')
                .help("VM ID (must be formatted in ids.Id)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VM_GENESIS_PATH")
                .long("vm-genesis-path")
                .short('g')
                .help("VM genesis file path")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

pub struct Option {
    pub log_level: String,
    pub http_rpc_ep: String,
    pub subnet_id: ids::Id,
    pub chain_name: String,
    pub vm_id: ids::Id,
    pub vm_genesis_path: String,
}

pub fn execute(opt: Option) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("Connecting to '{}'\n", opt.http_rpc_ep)),
        ResetColor
    )?;

    Ok(())
}
