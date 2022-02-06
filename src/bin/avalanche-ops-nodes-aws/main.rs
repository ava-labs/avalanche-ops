use std::{io::stdout, path::Path};

use clap::{arg, App, AppSettings};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{aws, aws_sts, network};

mod status;

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_CONFIG: &str = "default-config";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

fn main() {
    let rt = Runtime::new().unwrap();

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
            let cfg = network::Config::default(network_id);
            let config_path = sub_matches.value_of("config").unwrap();
            cfg.sync(config_path).unwrap();

            info!("saved to '{}' for network '{}'", config_path, network_id);
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            // ref. https://github.com/env-logger-rs/env_logger/issues/47
            env_logger::init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
            );

            let config_path = sub_matches.value_of("config").unwrap();
            let cfg = network::load_config(config_path).unwrap();

            let ret = rt.block_on(aws::load_config(Some(cfg.topology.region.clone())));
            assert!(ret.is_ok());
            let shared_config = ret.unwrap();
            let sts_manager = aws_sts::Manager::new(&shared_config);

            let ret = rt.block_on(sts_manager.get_identity());
            assert!(ret.is_ok());
            let current_identity = ret.unwrap();

            let mut status = status::Status::default(&cfg, &current_identity);

            let default_status_path = get_status_path(config_path);
            let status_path = sub_matches
                .value_of("status")
                .unwrap_or(&default_status_path);
            if Path::new(status_path).exists() {
                let ret = status::load_status(status_path);
                status = ret.unwrap();
                // always overwrite with original config
                // in case we suppport update and reconcile
                status.config = cfg.clone();
            }
            status.sync(status_path).unwrap();

            let config_contents = cfg.to_string().unwrap();
            let status_contents = status.to_string().unwrap();

            println!("\n");
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("Loaded configuration: '{}'", config_path)),
                ResetColor
            )
            .unwrap();
            println!("\n{}\n", config_contents);
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("Loaded status: '{}'", status_path)),
                ResetColor
            )
            .unwrap();
            println!("\n{}\n", status_contents);

            // configuration must be valid
            cfg.validate().unwrap();
            println!("\n");

            // AWS calls must be made from the same caller
            if status.identity != current_identity {
                panic!(
                    "status identity {:?} != currently loaded identity {:?}",
                    status.identity, current_identity
                );
            }

            if sub_matches.value_of("prompt").unwrap_or("true") == "true" {
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

            info!("creating resources (with status path {})", status_path);
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

            let ret = rt.block_on(aws::load_config(Some(
                status.config.topology.region.clone(),
            )));
            assert!(ret.is_ok());
            let shared_config = ret.unwrap();
            let sts_manager = aws_sts::Manager::new(&shared_config);
            let ret = rt.block_on(sts_manager.get_identity());
            assert!(ret.is_ok());
            let current_identity = ret.unwrap();

            println!("\n");
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("Loaded status: '{}'", status_path)),
                ResetColor
            )
            .unwrap();
            let status_contents = status.to_string().unwrap();
            println!("\n{}\n", status_contents);

            if sub_matches.value_of("prompt").unwrap_or("true") == "true" {
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

            // AWS calls must be made from the same caller
            if status.identity != current_identity {
                panic!(
                    "status identity {:?} != currently loaded identity {:?}",
                    status.identity, current_identity
                );
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
        .arg(
            arg!(-s --status <FILE> "The status file to write (always overwrites)")
                .required(false)
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

fn get_status_path(p: &str) -> String {
    let path = Path::new(p);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
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
