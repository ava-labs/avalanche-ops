use log::info;

use avalanche_types::soft_key;

/// cargo run --example soft_key_mnemonic_gen
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // ref. https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
    // ref. https://iancoleman.io/bip39/
    let phrase = soft_key::generate_mnemonic_phrase_24_word();
    info!("mnemonic phrase: {}", phrase);

    let key = soft_key::Key::from_mnemonic_phrase(phrase).unwrap();

    let info = key.private_key_info(1).expect("failed to_info");
    info!("network ID 1:\n{}", info);

    let info = key.private_key_info(9999).expect("failed to_info");
    info!("network ID 9999:\n{}", info);
}
