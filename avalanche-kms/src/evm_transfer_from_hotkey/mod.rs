use std::io::{self, stdout};

use avalanche_types::{
    jsonrpc::client::{evm as json_client_evm, info as json_client_info},
    key, units, wallet,
};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use primitive_types::{H160, U256};

pub const NAME: &str = "evm-transfer-from-hotkey";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Transfers the EVM native tokens 'from' hotkey to the 'to' address")
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
            Arg::new("CHAIN_RPC_URL")
                .long("chain-rpc-url")
                .help("Sets the EVM chain RPC endpoint")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("TRANSFERER_KEY")
                .long("transferer-key")
                .help("Sets the from private key (in hex format)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("TRANSFER_AMOUNT_IN_NANO_AVAX")
                .long("transfer-amount-in-nano-avax")
                .help("Sets the transfer amount in nAVAX (cannot be overlapped with --transfer-amount-in-avax)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("TRANSFER_AMOUNT_IN_AVAX")
                .long("transfer-amount-in-avax")
                .help("Sets the transfer amount in AVAX (cannot be overlapped with --transfer-amount-in-nano-avax)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("TRANSFEREE_ADDRESSES")
                .long("transferee-addresses")
                .help("Sets the comma-separated transferee EVM addresses")
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

pub async fn execute(
    log_level: &str,
    chain_rpc_url: &str,
    transferer_key: &str,
    transfer_amount_navax: U256,
    transferee_addrs: Vec<H160>,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let resp = json_client_info::get_network_id(chain_rpc_url)
        .await
        .unwrap();
    let network_id = resp.result.unwrap().network_id;

    let chain_id = json_client_evm::chain_id(chain_rpc_url).await.unwrap();
    log::info!("running against {chain_rpc_url}, network Id {network_id}, chain Id {chain_id}");

    let transferer_key = key::secp256k1::private_key::Key::from_hex(transferer_key).unwrap();
    let transferer_key_info = transferer_key.to_info(network_id).unwrap();
    log::info!("loaded hot key: {}", transferer_key_info.eth_address);

    if !skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to transfer {transfer_amount_navax} ({} ETH/AVX) from {} to total {} addresses: {:?}",
                units::cast_navax_to_avax_i64(transfer_amount_navax), transferer_key_info.eth_address, transferee_addrs.len(), transferee_addrs
            ),
            format!(
                "Yes, let's transfer {transfer_amount_navax} ({} ETH/AVX) from {} to total {} addresses: {:?}",
                units::cast_navax_to_avax_i64(transfer_amount_navax), transferer_key_info.eth_address, transferee_addrs.len(), transferee_addrs
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

    for transferee_addr in transferee_addrs.iter() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\ntransfering {transfer_amount_navax} ({} ETH/AVAX) from {} to {transferee_addr} via {chain_rpc_url}\n",
                units::cast_navax_to_avax_i64(transfer_amount_navax), transferer_key_info.eth_address
            )),
            ResetColor
        )?;
        let transferer_key_signer: ethers_signers::LocalWallet =
            transferer_key.to_ethers_core_signing_key().into();

        let w = wallet::Builder::new(&transferer_key)
            .base_http_url(chain_rpc_url.to_string())
            .build()
            .await?;
        let transferer_evm_wallet =
            w.evm(&transferer_key_signer, chain_rpc_url, U256::from(chain_id))?;

        let transferer_balance = transferer_evm_wallet.balance().await?;
        println!(
            "transferrer {} current balance: {} ({} ETH/AVAX)",
            transferer_key_info.eth_address,
            transferer_balance,
            units::cast_navax_to_avax_i64(transferer_balance)
        );
        let transferee_balance =
            json_client_evm::get_balance(chain_rpc_url, *transferee_addr).await?;
        println!(
            "transferee 0x{:x} current balance: {} ({} ETH/AVAX)",
            transferee_addr,
            transferee_balance,
            units::cast_navax_to_avax_i64(transferee_balance)
        );

        let tx_id = transferer_evm_wallet
            .eip1559()
            .recipient(*transferee_addr)
            .value(transfer_amount_navax)
            .urgent()
            .check_acceptance(true)
            .submit()
            .await?;
        log::info!("evm ethers wallet SUCCESS with transaction id {}", tx_id);
    }

    Ok(())
}
