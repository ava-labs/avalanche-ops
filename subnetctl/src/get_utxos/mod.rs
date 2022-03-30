use std::io::{self};

use clap::{Arg, Command};
use log::info;
use tokio::runtime::Runtime;

use avalanche_api::platform;

pub const NAME: &str = "get-utxos";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Reads the spec file and outputs all the balances for the generated keys")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("HTTP_RPC_ENDPOINT")
                .long("http-rpc-endpoint")
                .short('e')
                .help("HTTP RPC endpoint")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("P_CHAIN_ADDRESS")
                .long("p-chain-address")
                .short('a')
                .help("P-chain address to fetch UTXOs from")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}
pub struct Option {
    pub log_level: String,
    pub http_rpc_ep: String,
    pub paddr: String,
}

pub fn execute(opt: Option) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    let rt = Runtime::new().unwrap();

    let resp = rt
        .block_on(platform::get_utxos(&opt.http_rpc_ep, &opt.paddr))
        .expect("failed to get UTXOs");
    info!("get_utxos response: {:?}", resp);

    Ok(())
}
