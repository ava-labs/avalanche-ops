use std::io::{self, stdout};

use avalanche_types::subnet;
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "subnet-config";

/// Defines "subnet-evm subnet-config" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,
    pub proposer_min_block_delay: u64,
    pub file_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default configuration")
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
            Arg::new("PROPOSER_MIN_BLOCK_DELAY")
                .long("proposer-min-block-delay")
                .help("Sets to subnet-evm proposer-min-block-delay in nano seconds (in subnet config)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("1000000000"), // 1-second
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
        Print(format!("\nSaving subnet config to '{}'\n", opts.file_path)),
        ResetColor
    )?;
    let mut subnet_config = subnet::config::Config::default();
    if opts.proposer_min_block_delay > 0 {
        subnet_config.proposer_min_block_delay = opts.proposer_min_block_delay;
    }

    subnet_config.sync(&opts.file_path)?;
    let d = subnet_config.encode_json().expect("failed encode_json");
    println!("{d}");

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved subnet config to '{}'\n", opts.file_path)),
        ResetColor
    )?;

    Ok(())
}
