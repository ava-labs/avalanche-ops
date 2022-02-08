use std::path::Path;

use clap::{App, Arg};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{aws, aws_ec2, aws_kms, aws_s3, cert, compress};

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
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("AWS region")
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

    let rt = Runtime::new().unwrap();

    let az = rt.block_on(aws_ec2::fetch_availability_zone()).unwrap();
    info!("fetched availability zone {}", az);
    let reg = rt.block_on(aws_ec2::fetch_region()).unwrap();
    info!("fetched region {}", reg);
    let instance_id = rt.block_on(aws_ec2::fetch_instance_id()).unwrap();
    info!("fetched instance ID {}", instance_id);
    let public_ipv4 = rt.block_on(aws_ec2::fetch_public_ipv4()).unwrap();
    info!("fetched public ipv4 {}", public_ipv4);

    let region = matches.value_of("REGION").unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(region.to_string())))
        .unwrap();

    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let s3_manager = aws_s3::Manager::new(&shared_config);

    let tags = rt.block_on(ec2_manager.fetch_tags(&instance_id)).unwrap();
    let mut id: String = String::new();
    let mut node_type: String = String::new();
    let mut kms_cmk_arn: String = String::new();
    let mut s3_bucket_name: String = String::new();
    for c in tags {
        let k = c.key().unwrap();
        let v = c.value().unwrap();
        info!("tag key='{}', value='{}'", k, v);
        match k {
            "ID" => {
                id = v.to_string();
            }
            "NODE_TYPE" => {
                node_type = v.to_string();
            }
            "KMS_CMK_ARN" => {
                kms_cmk_arn = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                s3_bucket_name = v.to_string();
            }
            _ => {}
        }
    }
    if id.is_empty() {
        panic!("'ID' tag not found")
    }
    if node_type.is_empty() {
        panic!("'NODE_TYPE' tag not found")
    }
    if kms_cmk_arn.is_empty() {
        panic!("'KMS_CMK_ARN' tag not found")
    }
    if s3_bucket_name.is_empty() {
        panic!("'S3_BUCKET_NAME' tag not found")
    }

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

        let tmpf_compressed = tempfile::NamedTempFile::new().unwrap();
        let tmpf_compressed_path = tmpf_compressed.path().to_str().unwrap();
        compress::to_zstd(tls_key_path, tmpf_compressed_path, None).unwrap();

        let tmpf_encrypted = tempfile::NamedTempFile::new().unwrap();
        let tmpf_encrypted_path = tmpf_encrypted.path().to_str().unwrap();
        rt.block_on(kms_manager.encrypt_file(
            &kms_cmk_arn,
            None,
            tmpf_compressed_path,
            tmpf_encrypted_path,
        ))
        .unwrap();

        rt.block_on(s3_manager.put_object(
            &s3_bucket_name,
            tmpf_encrypted_path,
            format!("{}/pki/{}.key.zstd.encrypted", id, instance_id).as_str(),
        ))
        .unwrap();
    }

    // TODO: download network config from S3

    // TODO: download avalanchego config from S3

    // TODO: download plugins config from S3

    // TODO: run avalanche node in systemd

    // TODO: periodically upload beacon information to S3 as health check

    info!("Hello, world!");
}
