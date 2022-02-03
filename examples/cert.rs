use log::info;

extern crate avalanche_ops;
use avalanche_ops::cert;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!("generating certs");

    let ret = cert::generate("artifacts/test.insecure.key", "artifacts/test.insecure.crt");
    assert!(ret.is_ok());

    // openssl x509 -in artifacts/staker1.insecure.crt -text -noout
    // openssl x509 -in artifacts/test.insecure.crt -text -noout
}
