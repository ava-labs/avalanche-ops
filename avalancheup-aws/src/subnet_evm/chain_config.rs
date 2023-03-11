use std::io::{self, stdout};

use avalanche_types::subnet_evm::chain_config as subnet_evm_chain_config;
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "chain-config";

/// Defines "subnet-evm chain-config" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub tx_pool_account_slots: u64,
    pub tx_pool_global_slots: u64,
    pub tx_pool_account_queue: u64,
    pub tx_pool_global_queue: u64,
    pub local_txs_enabled: bool,
    pub priority_regossip_frequency: i64,
    pub priority_regossip_max_txs: i32,
    pub priority_regossip_txs_per_address: i32,
    pub priority_regossip_addresses: Vec<String>,

    pub file_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default chain configuration for subnet-evm")
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
            Arg::new("TX_POOL_ACCOUNT_SLOTS")
                .long("tx-pool-account-slots")
                .help("Sets non-zero to set tx-pool-account-slots (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("TX_POOL_GLOBAL_SLOTS")
                .long("tx-pool-global-slots")
                .help("Sets non-zero to set tx-pool-global-slots (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("TX_POOL_ACCOUNT_QUEUE")
                .long("tx-pool-account-queue")
                .help("Sets non-zero to set tx-pool-account-queue (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("TX_POOL_GLOBAL_QUEUE")
                .long("tx-pool-global-queue")
                .help("Sets non-zero to set tx-pool-global-queue (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("LOCAL_TXS_ENABLED")
                .long("local-txs-enabled")
                .help("Sets to enable local txs for subnet-evm")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("PRIORITY_REGOSSIP_FREQUENCY")
                .long("priority-regossip-frequency")
                .help("Sets non-zero to set priority-regossip-frequency (in nano-seconds, in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(i64))
                .default_value("0"),
        )
        .arg(
            Arg::new("PRIORITY_REGOSSIP_MAX_TXS")
                .long("priority-regossip-max-txs")
                .help("Sets non-zero to set priority-regossip-max-txs (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(i32))
                .default_value("0"),
        )
        .arg(
            Arg::new("PRIORITY_REGOSSIP_TXS_PER_ADDRESS")
                .long("priority-regossip-txs-per-address")
                .help("Sets non-zero to set priority-regossip-txs-per-address (in chain config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(i32))
                .default_value("0"),
        )
        .arg(
            Arg::new("PRIORITY_REGOSSIP_ADDRESSES")
                .long("priority-regossip-addresses")
                .help("Sets the comma-separated priority regossip addresses (in addition to pre-funded test keys, in chain config)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("FILE_PATH")
                .long("file-path")
                .short('s')
                .help("The config file to create")
                .required(false)
                .num_args(1),
        )
}

pub fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaving chain config to '{}'\n", opts.file_path)),
        ResetColor
    )?;
    let mut chain_config = subnet_evm_chain_config::Config::default();

    if opts.tx_pool_account_slots > 0 {
        chain_config.tx_pool_account_slots = Some(opts.tx_pool_account_slots);
    }
    if opts.tx_pool_global_slots > 0 {
        chain_config.tx_pool_global_slots = Some(opts.tx_pool_global_slots);
    }
    if opts.tx_pool_account_queue > 0 {
        chain_config.tx_pool_account_queue = Some(opts.tx_pool_account_queue);
    }
    if opts.tx_pool_global_queue > 0 {
        chain_config.tx_pool_global_queue = Some(opts.tx_pool_global_queue);
    }
    if opts.local_txs_enabled {
        chain_config.local_txs_enabled = Some(true);
    }
    if opts.priority_regossip_frequency > 0 {
        chain_config.priority_regossip_frequency = Some(opts.priority_regossip_frequency);
    }
    if opts.priority_regossip_max_txs > 0 {
        chain_config.priority_regossip_max_txs = Some(opts.priority_regossip_max_txs);
    }
    if opts.priority_regossip_txs_per_address > 0 {
        chain_config.priority_regossip_txs_per_address =
            Some(opts.priority_regossip_txs_per_address);
    }
    if !opts.priority_regossip_addresses.is_empty() {
        chain_config.priority_regossip_addresses = Some(opts.priority_regossip_addresses.clone());
    }

    chain_config.sync(&opts.file_path)?;
    let d = chain_config.encode_json().expect("failed encode_json");
    println!("{d}");

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved chain config to '{}'\n", opts.file_path)),
        ResetColor
    )?;

    Ok(())
}
