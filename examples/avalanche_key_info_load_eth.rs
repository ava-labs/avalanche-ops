use std::env::args;

use log::info;

extern crate avalanche_ops;
use avalanche_ops::avalanche::types::key;

/// cargo run --example avalanche_key_info_load_eth -- 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 1
/// cargo run --example avalanche_key_info_load_eth -- 56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027 9999
/// cargo run --example avalanche_key_info_load_eth -- e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 1
/// cargo run --example avalanche_key_info_load_eth -- e73b5812225f2e1c62de93fb6ec35a9338882991577f9a6d5651dce61cecd852 9999
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let private_key = args().nth(1).expect("no private key given");

    let network_id = args().nth(2).expect("no network ID given");
    let network_id = network_id.parse::<u32>().unwrap();

    info!("loading key");
    let k = key::Key::from_private_key_eth(&private_key).unwrap();
    let info = k.to_info(network_id).unwrap();
    assert_eq!(private_key, k.private_key_hex);
    assert_eq!(info.x_address, k.address("X", network_id).unwrap());
    assert_eq!(info.p_address, k.address("P", network_id).unwrap());
    assert_eq!(info.c_address, k.address("C", network_id).unwrap());
    assert_eq!(info.short_address, k.short_address);
    assert_eq!(info.eth_address, k.eth_address);

    print!("{}", info.to_string().unwrap());
}
