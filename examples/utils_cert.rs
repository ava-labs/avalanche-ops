use std::{env::args, fs, path::Path};

extern crate avalanche_ops;
use avalanche_ops::{avalanche::node, utils::cert};

/// cargo run --example utils_cert -- /tmp/test.insecure.key /tmp/test.insecure.cert
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let key_path = args().nth(1).expect("no key path given");
    let cert_path = args().nth(2).expect("no cert path given");

    if Path::new(&key_path).exists() {
        fs::remove_file(&key_path).expect("failed remove_file");
    }
    if Path::new(&cert_path).exists() {
        fs::remove_file(&cert_path).expect("failed remove_file");
    }

    cert::generate(key_path.as_str(), cert_path.as_str()).expect("failed to generate certs");
    // openssl x509 -in artifacts/staker1.insecure.crt -text -noout
    // openssl x509 -in artifacts/test.insecure.crt -text -noout

    println!("Node ID: {}", node::load_id(cert_path.as_str()).unwrap());
}
