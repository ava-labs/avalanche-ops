use std::env::args;

use log::info;
use tokio::runtime::Runtime;

use avalanche_api::platform;

/// cargo run --example platform -- [HTTP RPC ENDPOINT] P-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5
///
/// ```
/// # or run this
/// subnetctl get-utxos \
/// --http-rpc-endpoint [HTTP RPC ENDPOINT] \
/// --p-chain-address P-custom152qlr6zunz7nw2kc4lfej3cn3wk46u3002k4w5
/// ```
///
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let url = args().nth(1).expect("no url given");
    let paddr = args().nth(2).expect("no x-chain address given");

    let rt = Runtime::new().unwrap();

    let resp = rt
        .block_on(platform::get_balance(&url, "/ext/bc/P", &paddr))
        .expect("failed to get balance");
    info!("get_balance response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_utxos(&url, "/ext/bc/P", &paddr))
        .expect("failed to get UTXOs");
    info!("get_utxos response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_height(&url, "/ext/bc/P"))
        .expect("failed to get height");
    info!("get_height response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_current_validators(&url, "/ext/bc/P"))
        .expect("failed to get current validators");
    info!("get_current_validators response: {:?}", resp);
}
