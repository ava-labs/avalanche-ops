use std::env::args;

use log::info;

use avalanche_types::soft_key;

/// cargo run --example soft_key_info_load_avax -- PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN 1
/// cargo run --example soft_key_info_load_avax -- PrivateKey-ewoqjP7PxY4yr3iLTpLisriqt94hdyDFNgchSxGGztUrTXtNN 9999
/// cargo run --example soft_key_info_load_avax -- PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67 1
/// cargo run --example soft_key_info_load_avax -- PrivateKey-2kqWNDaqUKQyE4ZsV5GLCGeizE6sHAJVyjnfjXoXrtcZpK9M67 9999
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let private_key = args().nth(1).expect("no private key given");

    let network_id = args().nth(2).expect("no network ID given");
    let network_id = network_id.parse::<u32>().unwrap();

    info!("loading key");
    let k = soft_key::Key::from_private_key(&private_key).unwrap();
    let info = k.info(network_id).unwrap();
    assert_eq!(private_key, k.private_key);
    assert_eq!(info.x_address, k.address("X", network_id).unwrap());
    assert_eq!(info.p_address, k.address("P", network_id).unwrap());
    assert_eq!(info.c_address, k.address("C", network_id).unwrap());
    assert_eq!(info.short_address, k.short_address);
    assert_eq!(info.eth_address, k.eth_address);

    print!("{}", info.to_string().unwrap());
}
