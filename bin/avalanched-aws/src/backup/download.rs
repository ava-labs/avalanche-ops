use std::{fs, io, path::Path, sync::Arc};

use avalanche_utils::{compress, random};
use aws_sdk_manager::{self, s3};
use clap::{Arg, Command};
use log::info;
use tokio::runtime::Runtime;

pub const NAME: &str = "download";

pub fn subcommand() -> Command<'static> {
    Command::new(NAME)
        .about("Downloads compressed/archived backup file from remote storage")
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("us-west-2"),
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
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("UNARCHIVE_DECOMPRESSION_METHOD")
                .long("unarchive-decompression-method")
                .short('c')
                .help("Sets the decompression and unarchive method")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .possible_value(compress::DirDecoder::TarGzip.id())
                .possible_value(compress::DirDecoder::ZipGzip.id())
                .possible_value(compress::DirDecoder::TarZstd.id())
                .possible_value(compress::DirDecoder::ZipZstd.id())
                .default_value(compress::DirDecoder::TarGzip.id()),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .short('b')
                .help("Sets the S3 bucket name to upload to")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_KEY")
                .long("s3-key")
                .short('k')
                .help("Sets the S3 key name for uploading")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("UNPACK_DIR")
                .long("unpack-dir")
                .short('u')
                .help("Sets the destition db directory path to unpack")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

pub fn execute(
    reg: &str,
    log_level: &str,
    decompression_unarchive_method: &str,
    s3_bucket: &str,
    s3_key: &str,
    unpack_dir: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let rt = Runtime::new().unwrap();

    // let reg = rt.block_on(ec2::fetch_region()).unwrap();
    // info!("fetched region {}", reg);
    // let instance_id = rt.block_on(ec2::fetch_instance_id()).unwrap();
    // info!("fetched instance ID {}", instance_id);

    info!("STEP: loading AWS config");
    let shared_config = rt
        .block_on(aws_sdk_manager::load_config(Some(reg.to_string())))
        .unwrap();
    let s3_manager = s3::Manager::new(&shared_config);

    let dec = compress::DirDecoder::new(decompression_unarchive_method)?;

    let parent_dir = Path::new(&unpack_dir)
        .parent()
        .expect("unexpected None parent dir");
    let tmp_file_path = parent_dir.join(random::string(10));
    let tmp_file_path = tmp_file_path.as_path().as_os_str().to_str().unwrap();
    info!(
        "STEP: downloading from S3 {} {} to {}",
        s3_bucket, s3_key, tmp_file_path
    );
    rt.block_on(s3_manager.get_object(
        Arc::new(s3_bucket.to_string()),
        Arc::new(s3_key.to_string()),
        Arc::new(tmp_file_path.to_string()),
    ))
    .expect("failed get_object backup");

    info!(
        "STEP: unpack backup {} to {} with {}",
        tmp_file_path,
        unpack_dir,
        dec.to_string()
    );
    compress::unpack_directory(tmp_file_path, unpack_dir, dec)?;
    fs::remove_file(tmp_file_path)?;

    info!("'avalanched backup download' all success!");
    Ok(())
}
