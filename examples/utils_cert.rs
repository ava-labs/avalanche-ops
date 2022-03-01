use std::env::args;

use log::info;

extern crate avalanche_ops;
use avalanche_ops::{node, utils::cert};

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!("generating certs");

    let key_path = args().nth(1).expect("no key path given");
    let cert_path = args().nth(2).expect("no cert path given");

    let ret = cert::generate(key_path.as_str(), cert_path.as_str());
    assert!(ret.is_ok());
    // openssl x509 -in artifacts/staker1.insecure.crt -text -noout
    // openssl x509 -in artifacts/test.insecure.crt -text -noout

    println!("Node ID: {}", node::load_id(cert_path.as_str()).unwrap());
}
