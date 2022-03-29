use std::{
    fs,
    io::{self, stdout},
    time::SystemTime,
};

use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use lazy_static::lazy_static;
use log::info;

use avalanche_types::key;
use utils::rfc3339;

lazy_static! {
    pub static ref DEFAULT_VALIATE_END: &'static str = {
        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();
        let default_validate_end = now_unix + 365 * 24 * 60 * 60;
        let default_validate_end =
            rfc3339::to_str(default_validate_end).expect("failed to convert rfc3339");
        leak_string_to_static_str(default_validate_end)
    };
}

fn leak_string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

pub const NAME: &str = "validator";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Adds a validator")
        .long_about("

e.g.,

$ subnetctl add validator \
--http-rpc-endpoint=http://localhost:52250 \
--private-key-path=.insecure.ewoq.key \
--node-id=\"NodeID-4B4rc5vdD1758JSBYL1xyvE5NHGzz6xzH\" \
--stake-amount=2000000000000 \
--validate-reward-fee-percent=2

See https://github.com/ava-labs/subnet-cli.


")
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
                .default_value("info")
        )
        .arg(
            Arg::new("HTTP_RPC_ENDPOINT")
                .long("http-rpc-endpoint")
                .short('e')
                .help("HTTP RPC endpoint")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
        )
        .arg(
            // TODO: support ledger
            Arg::new("PRIVATE_KEY_PATH")
                .long("private-key-path")
                .short('p')
                .help("private key file path that contains hex string")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
        )
        .arg(
            Arg::new("NODE_ID")
                .long("node-id")
                .short('n')
                .help("node ID (must be formatted in ids.Id")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("STAKE_AMOUNT")
                .long("stake-amount")
                .short('s')
                .help("stake amount denominated in nano AVAX (minimum amount that a validator must stake is 2,000 AVAX)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("2000000000000")
        )
        .arg(
            Arg::new("VALIDATE_END")
                .long("validate-end")
                .short('v')
                .help("validate start timestamp in RFC3339 format")
                .required(true)
                .takes_value(true)
                .default_value(*DEFAULT_VALIATE_END)
                .allow_invalid_utf8(false)
        )
        .arg(
            Arg::new("VALIDATE_REWARD_FEE_PERCENT")
                .long("validate-reward-fee-percent")
                .short('f')
                .help("percentage of fee that the validator will take rewards from its delegators")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("2")
        )
}

pub struct CmdOption {
    pub log_level: String,
    pub http_rpc_ep: String,
    pub private_key_path: Option<String>,
    pub node_id: String,
    pub stake_amount: u64,
    pub validate_end: DateTime<Utc>,
    pub validate_reward_fee_percent: u32,
}

pub fn execute(opt: CmdOption) -> io::Result<()> {
    assert_eq!(opt.node_id.len(), 1);

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    let keys = {
        if let Some(private_key_path) = opt.private_key_path {
            let contents = fs::read_to_string(private_key_path).expect("failed to read file");
            let keys = key::load_keys(&contents.as_bytes())?;
            keys
        } else {
            panic!("unexpected None opt.private_key_path -- hardware wallet not supported yet");
        }
    };
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    info!("loaded key at ETH address {}", key.eth_address);

    // TODO: get reward address

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("Connecting to '{}'\n", opt.http_rpc_ep)),
        ResetColor
    )?;

    // TODO: get current network ID

    // TODO: get P-chain ID

    info!("getting current validators...");
    // TODO: error if a nodeID is already a validator

    // TODO: check current balance and required spending
    // ref. https://docs.avax.network/learn/platform-overview/transaction-fees/#fee-schedule

    // TODO: get inputs

    // TODO: get outputs

    let now = SystemTime::now();
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unexpected None duration_since")
        .as_secs();
    let _validate_start = now_unix + 30;

    let _reward_shares = opt.validate_reward_fee_percent * 10000;

    // TODO: prompt for confirmation

    // TODO: sign transaction

    // TODO: send transaction

    // TODO: poll to confirm transaction

    // TODO: check current validators

    Ok(())
}
