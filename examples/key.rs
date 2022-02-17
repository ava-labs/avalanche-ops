use std::{
    env::args,
    fs::File,
    io::{self, Error, ErrorKind},
    path::Path,
    string::String,
};

use log::info;
use serde::{Deserialize, Serialize};

extern crate avalanche_ops;
use avalanche_ops::key;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!("loading key");
    let key_path = args().nth(1).expect("no key path given");
    let keys = Keys::load(&key_path).unwrap();
    info!("{:?}", keys);

    let k = key::Key::from_private_key(&keys.encoded_private_key).unwrap();
    assert_eq!(keys.encoded_private_key, k.encoded_private_key);
    assert_eq!(keys.short_address, k.short_address);
    assert_eq!(keys.x_chain_address, k.address("X", 9999).unwrap());
    assert_eq!(keys.p_chain_address, k.address("P", 9999).unwrap());
    assert_eq!(keys.c_chain_address, k.address("C", 9999).unwrap());
    // assert_eq!(keys.eth_address, k.eth_address);
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Keys {
    pub encoded_private_key: String,
    pub x_chain_address: String,
    pub p_chain_address: String,
    pub c_chain_address: String,
    pub short_address: String,
    pub eth_address: String,
}

impl Keys {
    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading Keys from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = match File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to open {} ({})", file_path, e),
                ));
            }
        };
        serde_yaml::from_reader(f).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e));
        })
    }
}
