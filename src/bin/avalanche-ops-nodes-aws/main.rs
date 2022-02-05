#![feature(path_file_prefix)]
use std::{io::stdout, path::Path};

use clap::{arg, App, AppSettings};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_CONFIG: &str = "default-config";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

mod status;

fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowInvalidUtf8ForExternalSubcommands)
        .subcommands(vec![
            create_default_config_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_CONFIG, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            // ref. https://github.com/env-logger-rs/env_logger/issues/47
            env_logger::init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
            );

            let network_id = sub_matches.value_of("NETWORK_ID").unwrap_or("custom");
            let cfg = avalanche_ops::network::Config::default(network_id);
            let config_path = sub_matches.value_of("config").unwrap();
            cfg.sync(config_path).unwrap();

            let status = status::Status { config: cfg };
            let status_path = get_status_path(config_path);
            status.sync(status_path.as_str()).unwrap();

            info!("saved to '{}' for network '{}'", config_path, network_id);
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            // ref. https://github.com/env-logger-rs/env_logger/issues/47
            env_logger::init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
            );

            let config_path = sub_matches.value_of("config").unwrap();
            let cfg = avalanche_ops::network::load_config(config_path).unwrap();

            println!("\n\n");
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("Loaded configuration: '{}'", config_path)),
                ResetColor
            )
            .unwrap();

            let d = serde_yaml::to_string(&cfg).unwrap();
            println!("\n{}\n", d);

            let enable_prompt = sub_matches.value_of("prompt").unwrap_or("true");

            if enable_prompt == "true" {
                let options = &[
                    "No, I am not ready to create resources!",
                    "Yes, let's create resources!",
                ];
                let selected = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select your option")
                    .items(&options[..])
                    .default(0)
                    .interact()
                    .unwrap();
                if selected == 0 {
                    return;
                }
            }

            info!("creating resources...")
            // TODO
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            // ref. https://github.com/env-logger-rs/env_logger/issues/47
            env_logger::init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
            );

            let status_path = sub_matches.value_of("status").unwrap();
            let status = status::load_status(status_path).unwrap();

            println!("\n\n");
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("Loaded status: '{}'", status_path)),
                ResetColor
            )
            .unwrap();

            let d = serde_yaml::to_string(&status).unwrap();
            println!("\n{}\n", d);

            let enable_prompt = sub_matches.value_of("prompt").unwrap_or("true");

            if enable_prompt == "true" {
                let options = &[
                    "No, I am not ready to delete resources!",
                    "Yes, let's delete resources!",
                ];
                let selected = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select your option")
                    .items(&options[..])
                    .default(0)
                    .interact()
                    .unwrap();
                if selected == 0 {
                    return;
                }
            }

            info!("deleting resources...")
            // TODO
        }

        _ => unreachable!("unknown subcommand"),
    }
}

fn create_default_config_command() -> App<'static> {
    App::new(SUBCOMMAND_DEFAULT_CONFIG)
        .about("Writes a default configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-c --config <FILE> "Sets a config file to write")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(arg!(<NETWORK_ID>).required(true).allow_invalid_utf8(false))
}

fn get_status_path(p: &str) -> String {
    let path = Path::new(p);
    let parent_dir = path.parent().unwrap();
    let name = path.file_prefix().unwrap();
    let ext = path.extension().unwrap();
    let new_name = format!(
        "{}-status.{}",
        name.to_str().unwrap(),
        ext.to_str().unwrap()
    );
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

fn create_apply_command() -> App<'static> {
    App::new(SUBCOMMAND_APPLY)
        .about("Applies/creates resources based on configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-p --prompt <PROMPT> "Enables prompt mode")
                .required(false)
                .possible_value("true")
                .possible_value("false")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-c --config <FILE> "The config file to load")
                .required(true)
                .allow_invalid_utf8(false),
        )
}

fn create_delete_command() -> App<'static> {
    App::new(SUBCOMMAND_DELETE)
        .about("Deletes resources based on configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-p --prompt <PROMPT> "Enables prompt mode")
                .required(false)
                .possible_value("true")
                .possible_value("false")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-s --status <FILE> "The status file to load")
                .required(true)
                .allow_invalid_utf8(false),
        )
}
