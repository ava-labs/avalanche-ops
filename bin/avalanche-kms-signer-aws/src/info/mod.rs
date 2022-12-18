use std::io::{self, stdout};

use avalanche_types::key;
use aws_manager::{self, kms, sts};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use tokio::runtime::Runtime;

pub const NAME: &str = "info";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Fetches the info of an AWS KMS CMK")
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
            Arg::new("NETWORK_ID")
                .long("network-id")
                .help("Sets the network Id")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("1"),
        )
}

pub fn execute(log_level: &str, region: &str, key_arn: &str, network_id: u32) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("requesting info for KMS CMK {key_arn} ({region}) with network Id {network_id}");

    let rt = Runtime::new().unwrap();

    let shared_config = rt
        .block_on(aws_manager::load_config(Some(region.to_string())))
        .expect("failed to aws_manager::load_config");
    let kms_manager = kms::Manager::new(&shared_config);

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();
    log::info!("current identity {:?}", current_identity);
    println!();

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nLoading the KMS CMK {} in region {}\n",
            key_arn, region
        )),
        ResetColor
    )?;
    let cmk = rt
        .block_on(key::secp256k1::kms::aws::Cmk::from_arn(
            kms_manager.clone(),
            key_arn,
        ))
        .expect("failed to key::secp256k1::kms::aws::Cmk::create");
    let cmk_info = cmk.to_info(network_id).unwrap();

    println!();
    println!("loaded CMK\n\n{}\n(network Id {network_id})\n", cmk_info);
    println!();

    Ok(())
}
