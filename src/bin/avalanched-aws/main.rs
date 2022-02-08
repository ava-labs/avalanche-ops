use std::path::Path;

use clap::{App, Arg};
use log::info;

use avalanche_ops::{cert, compress};

const APP_NAME: &str = "avalanched-aws";

fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche agent (daemon) on AWS")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_KEY_PATH")
                .long("tls-key-path")
                .short('k')
                .help("TLS key path to save the generated key")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_CERT_PATH")
                .long("tls-cert-path")
                .short('c')
                .help("TLS cert path to save the generated cert")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    let log_level = matches.value_of("LOG_LEVEL").unwrap_or("info");
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    // TODO: load aws config

    // TODO: get instance ID

    // TODO: get public IP

    // TODO: get public hostname

    let tls_key_path = matches.value_of("TLS_KEY_PATH").unwrap();
    if tls_key_path.is_empty() {
        panic!("empty tls_key_path")
    }
    let tls_cert_path = matches.value_of("TLS_CERT_PATH").unwrap();
    if tls_cert_path.is_empty() {
        panic!("empty tls_cert_path")
    }
    if !Path::new(tls_key_path).exists() {
        info!(
            "TLS key path {} does not exist yet, generating one",
            tls_key_path
        );
        cert::generate(tls_key_path, tls_cert_path).unwrap();

        let tempf = tempfile::NamedTempFile::new().unwrap();
        let tempf_path = tempf.path().to_str().unwrap();
        compress::to_zstd(tls_key_path, tempf_path, None).unwrap();

        // TODO: encrypt with KMS

        // TODO: upload to S3
    }

    // TODO: download network config from S3

    // TODO: download avalanchego config from S3

    // TODO: download plugins config from S3

    // TODO: run avalanche node in systemd

    // TODO: periodically upload beacon information to S3 as health check

    info!("Hello, world!");
}
