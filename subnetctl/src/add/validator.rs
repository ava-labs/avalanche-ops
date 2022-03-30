use std::{
    fs,
    io::{self, stdout, Error, ErrorKind},
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
use tokio::runtime::Runtime;

use avalanche_api::{info as api_info, platform as api_platform};
use avalanche_types::{constants, key, platformvm};
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
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );
    let rt = Runtime::new().unwrap();

    /////
    println!();
    println!();
    println!();
    let keys = {
        if let Some(private_key_path) = opt.private_key_path {
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("loading private key file '{}'\n", private_key_path)),
                ResetColor
            )?;
            let contents = fs::read_to_string(private_key_path).expect("failed to read file");
            let keys = key::load_keys(&contents.as_bytes())?;
            keys
        } else {
            panic!("unexpected None opt.private_key_path -- hardware wallet not supported yet");
        }
    };
    assert_eq!(keys.len(), 1);
    let key = &keys[0];

    let reward_short_address = key.short_address.clone();
    info!(
        "loaded key at ETH address {} (reward short address {})",
        key.eth_address, reward_short_address
    );

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "connecting to '{}' for network information\n",
            opt.http_rpc_ep
        )),
        ResetColor
    )?;
    let resp = rt
        .block_on(api_info::get_network_id(&opt.http_rpc_ep))
        .expect("failed get_network_id");
    let network_id = resp.result.unwrap().network_id;
    if let Some(name) = constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
        if *name == "mainnet" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "mainnet is not supported yet!",
            ));
        }
    }
    let resp = rt
        .block_on(api_info::get_network_name(&opt.http_rpc_ep))
        .expect("failed get_network_name");
    let network_name = resp.result.unwrap().network_name;
    if network_name == "mainnet" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "mainnet is not supported yet!",
        ));
    }
    info!("network id {} and name {}", network_id, network_name);

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print("getting P-chain ID\n"),
        ResetColor
    )?;
    let p_chain_id = platformvm::chain_id();
    info!("P-chain ID is {}", p_chain_id.string());

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "getting current validators via '{}' to check node '{}' is already a validator\n",
            opt.http_rpc_ep, opt.node_id
        )),
        ResetColor
    )?;
    let resp = rt
        .block_on(api_platform::get_current_validators(&opt.http_rpc_ep))
        .expect("failed get_current_validators");
    let validators = resp.result.unwrap().validators.unwrap();
    for validator in validators.iter() {
        let node_id = validator.node_id.clone().unwrap();
        if node_id == opt.node_id {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("node ID {} is already a validator", node_id),
            ));
        }
        info!("listing current validator {}", node_id);
    }

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
