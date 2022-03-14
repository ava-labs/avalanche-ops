use std::env::args;

use log::info;
use tokio::runtime::Runtime;

extern crate avalanche_ops;
use avalanche_ops::avalanche::api::eth;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let url = args().nth(1).expect("no url given");
    let paddr = args().nth(2).expect("no x-chain address given");

    let rt = Runtime::new().unwrap();
    let resp = rt
        .block_on(eth::get_balance(&url, "/ext/bc/C/rpc", &paddr))
        .expect("failed to get balance");
    info!("response: {:?}", resp);
}
