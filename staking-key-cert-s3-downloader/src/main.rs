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

staking-key-cert-s3-downloader \
--log-level=info \
--aws-region=us-west-2 \
--s3-bucket=info \
--s3-key-tls-key=pki/NodeABCDE.key.zstd.encrypted \
--s3-key-tls-cert=pki/NodeABCDE.crt.zstd.encrypted \
--kms-cmk-id=abc-abc-abc \
--aad-tag=mytag \
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
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_KEY_TLS_KEY")
                .long("s3-key-tls-key")
                .help("Sets the S3 key for TLS key")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_KEY_TLS_CERT")
                .long("s3-key-tls-cert")
                .help("Sets the S3 key for TLS cert")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KMS_CMK_ID")
                .long("kms-cmk-id")
                .help("Sets the KMS CMK Id to envelope-decrypt the files from S3")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("AAD_TAG")
                .long("aad-tag")
                .help("Sets the AAD tag for envelope encryption")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("TLS_KEY_PATH")
                .long("tls-key-path")
                .help("Sets the local file path to save TLS key")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("TLS_CERT_PATH")
                .long("tls-cert-path")
                .help("Sets the local file path to save TLS cert")
                .required(true)
                .num_args(1),
        )
        .get_matches();

    let opts = flags::Options {
        log_level: matches
            .get_one::<String>("LOG_LEVEL")
            .unwrap_or(&String::from("info"))
            .clone(),
        region: matches.get_one::<String>("REGION").unwrap().clone(),
        s3_bucket: matches.get_one::<String>("S3_BUCKET").unwrap().clone(),
        s3_key_tls_key: matches.get_one::<String>("S3_KEY_TLS_KEY").unwrap().clone(),
        s3_key_tls_cert: matches
            .get_one::<String>("S3_KEY_TLS_CERT")
            .unwrap()
            .clone(),
        kms_cmk_id: matches.get_one::<String>("KMS_CMK_ID").unwrap().clone(),
        aad_tag: matches.get_one::<String>("AAD_TAG").unwrap().clone(),
        tls_key_path: matches.get_one::<String>("TLS_KEY_PATH").unwrap().clone(),
        tls_cert_path: matches.get_one::<String>("TLS_CERT_PATH").unwrap().clone(),
    };
    command::execute(opts).await.unwrap();
}
