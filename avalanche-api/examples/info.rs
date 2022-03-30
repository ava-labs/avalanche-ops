use std::env::args;

use log::info;
use tokio::runtime::Runtime;

use avalanche_api::info;

/// cargo run --example info -- [HTTP RPC ENDPOINT]
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let url = args().nth(1).expect("no url given");
    let rt = Runtime::new().unwrap();

    let resp = rt
        .block_on(info::get_network_name(&url))
        .expect("failed get_network_name");
    info!("get_network_name response: {:?}", resp);

    let resp = rt
        .block_on(info::get_network_id(&url))
        .expect("failed get_network_id");
    info!("get_network_id response: {:?}", resp);

    let resp = rt
        .block_on(info::get_blockchain_id(&url, "X"))
        .expect("failed get_blockchain_id");
    info!("get_blockchain_id for X response: {:?}", resp);

    let resp = rt
        .block_on(info::get_blockchain_id(&url, "P"))
        .expect("failed get_blockchain_id");
    info!("get_blockchain_id for P response: {:?}", resp);

    let resp = rt
        .block_on(info::get_blockchain_id(&url, "C"))
        .expect("failed get_blockchain_id");
    info!("get_blockchain_id for C response: {:?}", resp);

    let resp = rt
        .block_on(info::get_node_id(&url))
        .expect("failed get_node_id");
    info!("get_node_id response: {:?}", resp);

    let resp = rt
        .block_on(info::get_node_version(&url))
        .expect("failed get_node_version");
    info!("get_node_version response: {:?}", resp);

    let resp = rt.block_on(info::get_vms(&url)).expect("failed get_vms");
    info!("get_vms response: {:?}", resp);

    let resp = rt
        .block_on(info::get_bootstrapped(&url))
        .expect("failed get_bootstrapped");
    info!("get_bootstrapped response: {:?}", resp);

    let resp = rt
        .block_on(info::get_tx_fee(&url))
        .expect("failed get_tx_fee");
    info!("get_tx_fee response: {:?}", resp);
}
