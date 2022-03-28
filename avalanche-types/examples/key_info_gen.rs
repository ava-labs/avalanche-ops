use std::env::args;

use avalanche_types::key;

/// cargo run --example key_info_gen -- 9999 /tmp/key.json
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let network_id = args().nth(1).expect("no network ID given");
    let network_id = network_id.parse::<u32>().unwrap();

    let file_path = args().nth(2).expect("no file path given");

    let key = key::Key::generate().expect("unexpected key generate failure");
    let info = key.info(network_id).expect("failed to_info");
    print!("{}", info.to_string().unwrap());

    info.sync(file_path).unwrap();
}
