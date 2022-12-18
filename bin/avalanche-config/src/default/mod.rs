use std::io::{self, stdout, Error, ErrorKind};

use avalanche_types::avalanchego::config as avalanchego_config;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

pub const NAME: &str = "default";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default configuration file")
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
            Arg::new("CONFIG_FILE_PATH")
                .long("config-file-path")
                .short('f')
                .help("Avalanche configuration file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("NETWORK_NAME")
                .long("network-name")
                .short('n')
                .help("Sets the type of network by name (e.g., mainnet, fuji, custom)")
                .required(false)
                .num_args(1)
                .value_parser(["mainnet", "fuji", "custom"])
                .default_value("custom"),
        )
}

pub fn execute(log_level: &str, config_file_path: &str, network_name: &str) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nWriting configuration for '{}' to '{}'\n",
            network_name, config_file_path
        )),
        ResetColor
    )?;
    let config = match network_name {
        "mainnet" => avalanchego_config::Config::default_main(),
        "fuji" => avalanchego_config::Config::default_fuji(),
        "custom" => avalanchego_config::Config::default_custom(),
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("unknown network name {}", network_name),
            ))
        }
    };
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nCreated configuration:\n'{}'\n",
            config.encode_json()?
        )),
        ResetColor
    )?;

    config.sync(Some(config_file_path.to_string()))?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!("\nSaved configuration to '{}'\n", config_file_path)),
        ResetColor
    )?;

    Ok(())
}
