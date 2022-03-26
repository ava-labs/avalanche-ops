use std::{
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

use avalanche_ops::utils::rfc3339;

pub const NAME: &str = "validator";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Adds a validator")
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

pub struct Option {
    pub log_level: String,
    pub http_rpc_ep: String,
    pub stake_amount: u64,
    pub validate_end: DateTime<Utc>,
    pub valiate_reward_fee_percent: u32,
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
