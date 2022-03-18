use std::env::args;

use log::info;

extern crate avalanche_ops;
use avalanche_ops::avalanche::key;

/// cargo run --example avalanche_key_info_validate -- 9999 ./artifacts/ewoq.key.json
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let network_id = args().nth(1).expect("no network ID given");
    let network_id = network_id.parse::<u32>().unwrap();

    info!("loading key");
    let key_path = args().nth(2).expect("no key path given");
    let info = key::PrivateKeyInfo::load(&key_path).unwrap();
    println!("{}", info.to_string().unwrap());

    let k = key::Key::from_private_key(&info.private_key).unwrap();
    assert_eq!(info.private_key, k.private_key);
    assert_eq!(info.x_address, k.address("X", network_id).unwrap());
    assert_eq!(info.p_address, k.address("P", network_id).unwrap());
    assert_eq!(info.c_address, k.address("C", network_id).unwrap());
    assert_eq!(info.short_address, k.short_address);
    assert_eq!(info.eth_address, k.eth_address);

    info!("SUCCESS");
}
