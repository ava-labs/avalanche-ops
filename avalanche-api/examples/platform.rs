use std::env::args;

use log::info;
use tokio::runtime::Runtime;

use avalanche_api::platform;

/// cargo run --example platform -- [HTTP RPC ENDPOINT] P-custom1qwmslrrqdv4slxvynhy9csq069l0u8mqwjzmcd
///
/// ```
/// # or run this
/// subnetctl get-utxos \
/// --http-rpc-endpoint [HTTP RPC ENDPOINT] \
/// --p-chain-address P-custom1qwmslrrqdv4slxvynhy9csq069l0u8mqwjzmcd
/// ```
///
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let rt = Runtime::new().unwrap();

    let url = args().nth(1).expect("no url given");
    let paddr = args().nth(2).expect("no p-chain address given");

    println!("{}", url);
    println!("{}", paddr);
    let resp = rt
        .block_on(platform::get_balance(&url, &paddr))
        .expect("failed to get balance");
    info!("get_balance response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_utxos(&url, &paddr))
        .expect("failed to get UTXOs");
    info!("get_utxos response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_height(&url))
        .expect("failed to get height");
    info!("get_height response: {:?}", resp);

    let resp = rt
        .block_on(platform::get_current_validators(&url))
        .expect("failed to get current validators");
    info!("get_current_validators response: {:?}", resp);
}
