use std::{
    collections::HashMap,
    env,
    io::{self, stdout},
};

use avalanche_types::{
    jsonrpc::client::{evm as json_client_evm, info as json_client_info},
    key, units, wallet,
};
use aws_manager::{self, kms, sts};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use primitive_types::U256;
use tokio::time::{sleep, Duration};

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
            Arg::new("KEY_NAME_PREFIX")
                .long("key-name-prefix")
                .help("KMS CMK name prefix")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("KEYS")
                .long("keys")
                .help("Sets the number of keys to create")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("EVM_CHAIN_RPC_URL")
                .long("evm-chain-rpc-url")
                .help("Sets EVM chain RPC endpoint")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_HOTKEY")
                .long("evm-funding-hotkey")
                .help("Sets the private key in hex format to fund the created key (leave empty to skip funding)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_AMOUNT_IN_NANO_AVAX")
                .long("evm-funding-amount-in-nano-avax")
                .help("Sets the funding amount in nAVAX (cannot be overlapped with --funding-amount-in-avax)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_AMOUNT_IN_AVAX")
                .long("evm-funding-amount-in-avax")
                .help("Sets the funding amount in AVAX (cannot be overlapped with --funding-amount-in-nano-avax)")
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
    key_name_prefix: &str,
    keys: usize,
    evm_chain_rpc_url: &str,
    evm_funding_hotkey: &str,
    evm_funding_amount_navax: U256,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!(
        "requesting to create new {keys} KMS CMK(s) with prefix '{key_name_prefix}' (in the {region})"
    );

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
                "No, I am not ready to create new {keys} KMS CMK(s) with '{key_name_prefix}' in '{region}'."
            ),
            format!(
                "Yes, let's create new {keys} KMS CMK(s) with '{key_name_prefix}' in '{region}'."
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
            "\nCreating new KMS CMKs with '{key_name_prefix}' in region {region}\n",
        )),
        ResetColor
    )?;
    let mut cmks = Vec::new();
    for i in 0..keys {
        // to prevent rate limit errors
        // e.g.,
        // { source: CreateKeyError { kind: Unhandled(Unhandled { source: Error { code: Some(\\\"ThrottlingException\\\"), message: Some(\\\"You have exceeded the rate at which you may call KMS. Reduce the frequency of your calls.\\\"
        sleep(Duration::from_secs(2)).await;

        println!("");
        log::info!("[{i}] creating CMk");
        let mut tags = HashMap::new();
        tags.insert(
            String::from("Name"),
            format!("{key_name_prefix}-{:03}", i + 1),
        );
        let cmk = key::secp256k1::kms::aws::Cmk::create(kms_manager.clone(), tags)
            .await
            .unwrap();

        let cmk_info = cmk.to_info(1).unwrap();
        cmks.push(cmk_info.clone());

        println!();
        println!("loaded CMK\n\n{}\n", cmk_info);
        println!();

        if evm_funding_hotkey.is_empty() {
            log::info!("no evm-funding-hotkey given, skipping...");
            continue;
        }

        let resp = json_client_info::get_network_id(evm_chain_rpc_url)
            .await
            .unwrap();
        let network_id = resp.result.unwrap().network_id;

        let chain_id = json_client_evm::chain_id(evm_chain_rpc_url).await.unwrap();
        log::info!(
            "running against {evm_chain_rpc_url}, network Id {network_id}, chain Id {chain_id}"
        );

        let funding_key = key::secp256k1::private_key::Key::from_hex(evm_funding_hotkey).unwrap();
        let funding_key_info = funding_key.to_info(network_id).unwrap();
        log::info!("loaded funding key: {}", funding_key_info.eth_address);

        let transferee_addr = cmk_info.h160_address;
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\ntransfering {evm_funding_amount_navax} ({} ETH/AVAX) from {} to {transferee_addr} via {evm_chain_rpc_url}\n",
                units::cast_navax_to_avax_i64(evm_funding_amount_navax), funding_key_info.eth_address
        )),
            ResetColor
        )?;
        let funding_key_signer: ethers_signers::LocalWallet =
            funding_key.to_ethers_core_signing_key().into();

        let w = wallet::Builder::new(&funding_key)
            .base_http_url(evm_chain_rpc_url.to_string())
            .build()
            .await?;
        let funding_evm_wallet =
            w.evm(&funding_key_signer, evm_chain_rpc_url, U256::from(chain_id))?;

        let transferer_balance = funding_evm_wallet.balance().await?;
        println!(
            "transferrer {} current balance: {} ({} ETH/AVAX)",
            funding_key_info.eth_address,
            transferer_balance,
            units::cast_navax_to_avax_i64(transferer_balance)
        );
        let transferee_balance =
            json_client_evm::get_balance(evm_chain_rpc_url, transferee_addr).await?;
        println!(
            "transferee 0x{:x} current balance: {} ({} ETH/AVAX)",
            transferee_addr,
            transferee_balance,
            units::cast_navax_to_avax_i64(transferee_balance)
        );

        let tx_id = funding_evm_wallet
            .eip1559()
            .recipient(transferee_addr)
            .value(evm_funding_amount_navax)
            .urgent()
            .check_acceptance(true)
            .submit()
            .await?;
        log::info!("evm ethers wallet SUCCESS with transaction id {}", tx_id);
    }

    for cmk in cmks.iter() {
        println!("{},{}", cmk.id.clone().unwrap(), cmk.eth_address)
    }

    let exec_path = env::current_exe().expect("unexpected None current_exe");
    println!("\n# [UNSAFE] to delete the keys");
    for cmk in cmks.iter() {
        println!("{} delete --region={region} --pending-windows-in-days 7 --unsafe-skip-prompt --key-arn {}", exec_path.display(), cmk.id.clone().unwrap());
    }

    println!("\n# [UNSAFE] to fund the keys");
    let mut addresses = Vec::new();
    for cmk in cmks.iter() {
        addresses.push(cmk.eth_address.clone());
    }
    println!("{} evm-transfer-from-hotkey --chain-rpc-url={evm_chain_rpc_url} --transferer-key=[FUNDING_HOTKEY] --transfer-amount-in-avax \"30000000\" --transferee-addresses {}", exec_path.display(), addresses.join(","));

    Ok(())
}
