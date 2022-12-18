use std::{
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

pub const NAME: &str = "add-whitelist-subnet";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Adds a whitelisted subnet (no overwrite)")
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
            Arg::new("ORIGINAL_CONFIG_FILE_PATH")
                .long("original-config-file-path")
                .help("Original avalanche configuration file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("NEW_CONFIG_FILE_PATH")
                .long("new-config-file-path")
                .help("New avalanche configuration file path to save")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_ID")
                .long("subnet-id")
                .help("Sets the subnet Id to add")
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
    orig_config_file_path: &str,
    new_config_file_path: &str,
    subnet_id: &str,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!(
        "adding subnet-id '{}' to whitelisted-subnets flag",
        subnet_id
    );
    let converted = ids::Id::from_str(subnet_id)?;
    log::info!("validated subnet-id '{}'", converted);

    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to update configuration with whitelisted subnet Id '{}'!",
                converted
            ),
            format!(
                "Yes, let's update configuration with whitelisted subnet Id '{}'!",
                converted
            ),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'apply' option")
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
        Print(format!(
            "\nLoading configuration: '{}'\n",
            orig_config_file_path
        )),
        ResetColor
    )?;

    let mut config = avalanchego_config::Config::load(orig_config_file_path)?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nLoaded configuration: '{}'\n",
            config.encode_json()?
        )),
        ResetColor
    )?;

    let mut new_whitelisted_subnets = config.whitelisted_subnets.unwrap_or(String::new());
    if !new_whitelisted_subnets.is_empty() {
        new_whitelisted_subnets.push(',');
    }
    new_whitelisted_subnets.push_str(subnet_id);
    config.whitelisted_subnets = Some(new_whitelisted_subnets);

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nUpdated configuration: '{}'\n",
            config.encode_json()?
        )),
        ResetColor
    )?;

    config.sync(Some(new_config_file_path.to_string()))?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nSaved configuration to '{}'\n",
            new_config_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
