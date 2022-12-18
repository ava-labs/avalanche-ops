use std::io::{self, stdout};

use avalanche_types::key;
use aws_manager::{self, kms, sts};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use tokio::runtime::Runtime;

pub const NAME: &str = "delete";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Deletes an AWS KMS CMK")
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
            Arg::new("KEY_ARN")
                .long("key-arn")
                .short('a')
                .help("KMS CMK ARN")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("PENDING_WINDOWS_IN_DAYS")
                .long("pending-windows-in-days")
                .help("Sets the schedule delete pending days")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(i32))
                .default_value("7"),
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
    region: &str,
    key_arn: &str,
    pending_windows_in_days: i32,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("requesting to delete {key_arn} ({region}) in {pending_windows_in_days} days");

    let rt = Runtime::new().unwrap();

    let shared_config = rt
        .block_on(aws_manager::load_config(Some(region.to_string())))
        .expect("failed to aws_manager::load_config");
    let kms_manager = kms::Manager::new(&shared_config);

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();
    log::info!("current identity {:?}", current_identity);

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nLoading the KMS CMK {} in region {}\n",
            key_arn, region
        )),
        ResetColor
    )?;
    let cmk_signer = rt
        .block_on(key::secp256k1::kms::aws::Signer::create(
            kms_manager.clone(),
            key_arn,
        ))
        .expect("failed to key::secp256k1::kms::aws::Signer::create");
    let cmk_signer_info = cmk_signer.to_info(1).unwrap();
    log::info!("loaded CMK signer (info for mainnet: {})", cmk_signer_info);

    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to delete a new KMS CMK '{}' '{}' in {} days!",
                region, key_arn, pending_windows_in_days
            ),
            format!(
                "Yes, let's delete a new KMS CMK '{}' '{}' in {} days!",
                region, key_arn, pending_windows_in_days
            ),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'delete' option")
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

    rt.block_on(cmk_signer.delete(pending_windows_in_days))
        .unwrap();

    log::info!("successfully delete CMK signer");
    Ok(())
}
