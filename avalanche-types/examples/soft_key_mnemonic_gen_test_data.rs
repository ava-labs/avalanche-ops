use std::{collections::HashMap, env::args, fs::File, io::Write};

use log::info;

use avalanche_types::soft_key;

/// cargo run --example soft_key_mnemonic_gen_test_data -- 30 /tmp/test.key.infos.json
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let n = args().nth(1).expect("no n given");
    let n = n.parse::<u32>().unwrap();

    let output_path = args().nth(2).expect("no output path given");

    let mut key_infos: Vec<soft_key::PrivateKeyInfoEntry> = Vec::new();
    for i in 0..n {
        info!("generating {}", i + 1);
        let phrase = soft_key::generate_mnemonic_phrase_24_word();
        let key = soft_key::Key::from_mnemonic_phrase(phrase.clone()).unwrap();

        let mut addresses: HashMap<String, soft_key::PrivateKeyInfoEntryAddress> = HashMap::new();

        let info1 = key.info(1).unwrap();
        addresses.insert(
            "1".to_string(),
            soft_key::PrivateKeyInfoEntryAddress {
                x_address: info1.x_address,
                p_address: info1.p_address,
                c_address: info1.c_address,
            },
        );
        let info9999 = key.info(9999).unwrap();
        addresses.insert(
            "9999".to_string(),
            soft_key::PrivateKeyInfoEntryAddress {
                x_address: info9999.x_address,
                p_address: info9999.p_address,
                c_address: info9999.c_address,
            },
        );

        key_infos.push(soft_key::PrivateKeyInfoEntry {
            mnemonic_phrase: Some(phrase),

            private_key: key.private_key,
            private_key_hex: key.private_key_hex,

            addresses,

            short_address: key.short_address,
            eth_address: key.eth_address,
        })
    }

    let d = serde_json::to_vec(&key_infos).unwrap();
    let mut f = File::create(&output_path).unwrap();
    f.write_all(&d).unwrap();

    info!("wrote to {}", output_path);
}
