mod command;
mod flags;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "staking-key-cert-s3-downloader";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Staking certs downloader from S3")
        .long_about(
            "

Downloads the avalanched-aws generated certificates from S3.

$ staking-key-cert-s3-downloader \
--log-level=info \
--aws-region=us-west-2 \
--s3-bucket=info \
--s3-key-tls-key=pki/NodeABCDE.key.zstd.encrypted \
--s3-key-tls-cert=pki/NodeABCDE.crt.zstd.encrypted \
--kms-cmk-id=abc-abc-abc \
--tls-key-path=pki/NodeABCDE.key \
--tls-cert-path=pki/NodeABCDE.crt

",
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("AWS_REGION")
                .long("aws-region")
                .help("Sets the AWS region")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_KEY_TLS_KEY")
                .long("s3-key-tls-key")
                .help("Sets the S3 key for TLS key")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_KEY_TLS_CERT")
                .long("s3-key-tls-cert")
                .help("Sets the S3 key for TLS cert")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("KMS_CMK_ID")
                .long("kms-cmk-id")
                .help("Sets the KMS CMK Id to envelope-decrypt the files from S3")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_KEY_PATH")
                .long("tls-key-path")
                .help("Sets the local file path to save TLS key")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_CERT_PATH")
                .long("tls-cert-path")
                .help("Sets the local file path to save TLS cert")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    let opts = flags::Options {
        log_level: matches.value_of("LOG_LEVEL").unwrap_or("info").to_string(),
        aws_region: matches.value_of("AWS_REGION").unwrap().to_string(),
        s3_bucket: matches.value_of("S3_BUCKET").unwrap().to_string(),
        s3_key_tls_key: matches.value_of("S3_KEY_TLS_KEY").unwrap().to_string(),
        s3_key_tls_cert: matches.value_of("S3_KEY_TLS_CERT").unwrap().to_string(),
        kms_cmk_id: matches.value_of("KMS_CMK_ID").unwrap().to_string(),
        tls_key_path: matches.value_of("TLS_KEY_PATH").unwrap().to_string(),
        tls_cert_path: matches.value_of("TLS_CERT_PATH").unwrap().to_string(),
    };
    command::execute(opts).await.unwrap();
}
