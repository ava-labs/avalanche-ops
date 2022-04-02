use std::env::args;

use log::info;

use avalanche_types::soft_key;

/// cargo run --example soft_key_info_validate -- ./artifacts/ewoq.key.json 9999
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let network_id = args().nth(2).expect("no network ID given");
    let network_id = network_id.parse::<u32>().unwrap();

    info!("loading key");
    let key_path = args().nth(1).expect("no key path given");
    let info = soft_key::PrivateKeyInfo::load(&key_path).unwrap();
    println!("{}", info);

    let k = soft_key::Key::from_private_key(&info.private_key).unwrap();
    assert_eq!(info.private_key, k.private_key);
    assert_eq!(info.x_address, k.address("X", network_id).unwrap());
    assert_eq!(info.p_address, k.address("P", network_id).unwrap());
    assert_eq!(info.c_address, k.address("C", network_id).unwrap());
    assert_eq!(info.short_address, k.short_address);
    assert_eq!(info.eth_address, k.eth_address);

    info!("SUCCESS");
}
