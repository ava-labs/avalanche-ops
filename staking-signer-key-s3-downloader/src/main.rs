mod command;
mod flags;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "staking-signer-key-s3-downloader";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Staking certs downloader from S3")
        .long_about(
            "

Downloads the avalanched-aws generated staking signer key from S3.

staking-signer-key-s3-downloader \
--log-level=info \
--aws-region=us-west-2 \
--s3-bucket=info \
--s3-key=pki/NodeABCDE.key.zstd.encrypted \
--kms-key-id=abc-abc-abc \
--aad-tag=mytag \
--key-path=pki/NodeABCDE.key

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
            Arg::new("S3_KEY")
                .long("s3-key")
                .help("Sets the S3 key")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KMS_KEY_ID")
                .long("kms-key-id")
                .help("Sets the KMS key Id to envelope-decrypt the files from S3")
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
            Arg::new("KEY_PATH")
                .long("key-path")
                .help("Sets the local file path to save key")
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
        s3_key: matches.get_one::<String>("S3_KEY").unwrap().clone(),
        kms_key_id: matches.get_one::<String>("KMS_KEY_ID").unwrap().clone(),
        aad_tag: matches.get_one::<String>("AAD_TAG").unwrap().clone(),
        key_path: matches.get_one::<String>("KEY_PATH").unwrap().clone(),
    };
    command::execute(opts).await.unwrap();
}
