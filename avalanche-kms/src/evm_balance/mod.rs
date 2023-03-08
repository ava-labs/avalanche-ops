use std::io;

use avalanche_types::{jsonrpc::client::evm as avalanche_sdk_evm, units};
use clap::{Arg, Command};
use primitive_types::H160;

pub const NAME: &str = "evm-balance";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Fetches the balance of an address")
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
                .help("Sets to fetch other information from the RPC endpoints (e.g., balances)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("ADDRESS")
                .long("address")
                .help("Sets the address")
                .required(true)
                .num_args(1),
        )
}

pub async fn execute(log_level: &str, chain_rpc_url: &str, addr: H160) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("fetching the balance of {addr} via {chain_rpc_url}");

    let balance = avalanche_sdk_evm::get_balance(chain_rpc_url, addr).await?;
    println!(
        "{} balance: {} ({} ETH/AVAX)",
        addr,
        balance,
        units::cast_navax_to_avax_i64(balance)
    );

    Ok(())
}
