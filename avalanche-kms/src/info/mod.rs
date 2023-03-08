use std::{
    io::{self, stdout},
    str::FromStr,
};

use avalanche_types::{
    jsonrpc::client::{evm as avalanche_sdk_evm, info as json_client_info},
    key::secp256k1::{self, KeyType},
    units, utils,
};
use aws_manager::{self, kms, sts};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

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
            Arg::new("KEY_TYPE")
                .long("key-type")
                .help("Sets the key type")
                .required(true)
                .value_parser(["aws-kms", "hot"])
                .num_args(1),
        )
        .arg(
            Arg::new("KEY")
                .long("key")
                .help("Hex-encoded hot key or KMS CMK ARN")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_RPC_URL")
                .long("chain-rpc-url")
                .help("Sets to fetch other information from the RPC endpoints (e.g., balances)")
                .required(false)
                .num_args(1),
        )
}

pub async fn execute(
    log_level: &str,
    region: &str,
    key_type: &str,
    key: &str,
    chain_rpc_url: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!(
        "requesting info for KMS CMK {key_type} ({region}) with chain RPC URL '{chain_rpc_url}'"
    );
    let network_id = if chain_rpc_url.is_empty() {
        1
    } else {
        let (scheme, host, port, _, _) =
            utils::urls::extract_scheme_host_port_path_chain_alias(chain_rpc_url).unwrap();
        let scheme = if let Some(s) = scheme {
            format!("{s}://")
        } else {
            String::new()
        };
        let rpc_ep = format!("{scheme}{host}");
        let rpc_url = if let Some(port) = port {
            format!("{rpc_ep}:{port}")
        } else {
            rpc_ep.clone() // e.g., DNS
        };

        let resp = json_client_info::get_network_id(&rpc_url).await.unwrap();
        resp.result.unwrap().network_id
    };
    log::info!("network Id: {network_id}");

    let shared_config = aws_manager::load_config(Some(region.to_string()))
        .await
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();
    log::info!("current identity {:?}", current_identity);
    println!();

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nLoading the hotkey or KMS CMK {} in region {}\n",
            key, region
        )),
        ResetColor
    )?;
    let converted_key_type = KeyType::from_str(key_type).unwrap();
    match converted_key_type {
        KeyType::AwsKms => {
            let kms_manager = kms::Manager::new(&shared_config);
            let cmk = secp256k1::kms::aws::Cmk::from_arn(kms_manager.clone(), key)
                .await
                .unwrap();
            let cmk_info = cmk.to_info(network_id).unwrap();

            println!();
            println!("loaded CMK\n\n{}\n(network Id {network_id})\n", cmk_info);
            println!();

            if !chain_rpc_url.is_empty() {
                let balance =
                    avalanche_sdk_evm::get_balance(chain_rpc_url, cmk_info.h160_address).await?;
                println!(
                    "{} balance: {} ({} ETH/AVAX)",
                    cmk_info.eth_address,
                    balance,
                    units::cast_navax_to_avax_i64(balance)
                );
            }
        }
        KeyType::Hot => {
            let k = secp256k1::private_key::Key::from_hex(key).unwrap();

            if !chain_rpc_url.is_empty() {
                let balance =
                    avalanche_sdk_evm::get_balance(chain_rpc_url, k.to_public_key().to_h160())
                        .await?;
                println!(
                    "{} balance: {} ({} ETH/AVAX)",
                    k.to_public_key().to_eth_address(),
                    balance,
                    units::cast_navax_to_avax_i64(balance)
                );
            }
        }
        KeyType::Unknown(s) => panic!("unknown key type {s}"),
    }

    Ok(())
}
