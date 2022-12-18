use std::io::{self, stdout};

use avalanche_types::key;
use aws_manager::{self, kms, sts};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use tokio::runtime::Runtime;

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

pub fn execute(log_level: &str, region: &str, key_name: &str, skip_prompt: bool) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("requesting to create a new KMS CMK {key_name} ({region})");

    let rt = Runtime::new().unwrap();

    let shared_config = rt
        .block_on(aws_manager::load_config(Some(region.to_string())))
        .expect("failed to aws_manager::load_config");
    let kms_manager = kms::Manager::new(&shared_config);

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();
    log::info!("current identity {:?}", current_identity);

    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to create a new KMS CMK '{}' '{}'!",
                region, key_name
            ),
            format!(
                "Yes, let's create a new KMS CMK '{}' '{}'!",
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
    let cmk_signer = rt
        .block_on(key::secp256k1::kms::aws::Signer::create(
            kms_manager.clone(),
            key_name,
        ))
        .expect("failed to key::secp256k1::kms::aws::Signer::create");
    let cmk_signer_info = cmk_signer.to_info(1).unwrap();
    log::info!("created CMK signer (info for mainnet: {})", cmk_signer_info);

    Ok(())
}
