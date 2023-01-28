use std::{
    collections::HashMap,
    io::{self, stdout},
};

use avalanche_types::key;
use aws_manager::{self, kms, sts};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};

pub const NAME: &str = "create";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Creates an AWS KMS CMK")
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
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("KEY_NAME")
                .long("key-name")
                .short('n')
                .help("KMS CMK name")
                .required(false)
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

pub async fn execute(
    log_level: &str,
    region: &str,
    key_name: &str,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("requesting to create a new KMS CMK {key_name} ({region})");

    let shared_config = aws_manager::load_config(Some(region.to_string()))
        .await
        .unwrap();
    let kms_manager = kms::Manager::new(&shared_config);

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();
    log::info!("current identity {:?}", current_identity);
    println!();

    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to create a new KMS CMK '{}' '{}'.",
                region, key_name
            ),
            format!(
                "Yes, let's create a new KMS CMK '{}' '{}'.",
                region, key_name
            ),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'create' option")
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
            "\nCreating a new KMS CMK {} in region {}\n",
            key_name, region
        )),
        ResetColor
    )?;
    let mut tags = HashMap::new();
    tags.insert(String::from("Name"), key_name.to_string());
    let cmk = key::secp256k1::kms::aws::Cmk::create(kms_manager.clone(), tags)
        .await
        .unwrap();
    let cmk_info = cmk.to_info(1).unwrap();

    println!();
    println!("loaded CMK\n\n{}\n(mainnet)\n", cmk_info);
    println!();

    Ok(())
}
