use std::{
    collections::BTreeSet,
    io::{self, stdout},
    str::FromStr,
};

use avalanche_types::{avalanchego::config as avalanchego_config, ids};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};

pub const NAME: &str = "add-track-subnet";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Adds a tracked subnet")
        .long_about(
            "

Requires configuration file that's compatible to avalanche_types::avalanchego::config.

",
        )
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
                .help("Avalanche configuration file path to update")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_ID")
                .long("subnet-id")
                .help("Sets the subnet Id to add/track")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
}

pub fn execute(
    log_level: &str,
    config_file_path: &str,
    subnet_id: &str,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("adding a subnet-id '{}' to tracked-subnets flag", subnet_id);
    let converted = ids::Id::from_str(subnet_id)?;
    log::info!("validated a subnet-id '{}'", converted);

    println!();
    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to update configuration with a tracked subnet Id '{}'.",
                converted
            ),
            format!(
                "Yes, let's update configuration with a tracked subnet Id '{}'.",
                converted
            ),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'add-track-subnet' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    } else {
        log::info!("skipping prompt...")
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!("\nLoading configuration: '{}'\n", config_file_path)),
        ResetColor
    )?;

    let mut config = avalanchego_config::Config::load(config_file_path)?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nLoaded configuration:\n'{}'\n",
            config.encode_json()?
        )),
        ResetColor
    )?;

    let mut new_track_subnets = BTreeSet::new();
    new_track_subnets.insert(subnet_id.to_string());

    let existing_track_subnets = config.track_subnets.clone().unwrap_or(String::new());
    for existing_subnet_id in existing_track_subnets.split(',').into_iter() {
        if existing_subnet_id.is_empty() {
            continue;
        }
        new_track_subnets.insert(existing_subnet_id.to_string());
    }

    let mut track_subnets = Vec::new();
    for new_subnet_id in new_track_subnets {
        track_subnets.push(new_subnet_id);
    }
    if !track_subnets.is_empty() {
        config.track_subnets = Some(track_subnets.join(","));
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nUpdated configuration:\n'{}'\n",
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
