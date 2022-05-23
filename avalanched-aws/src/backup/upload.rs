use std::{fs, io, path::Path, sync::Arc};

use avalanche_utils::{compress, random};
use aws::{self, s3};
use clap::{Arg, Command};
use log::info;
use tokio::runtime::Runtime;

pub const NAME: &str = "upload";

// TODO: make this periodic
pub fn subcommand() -> Command<'static> {
    Command::new(NAME)
        .about("Uploads the local data directory to remote storage")
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
            Arg::new("ARCHIVE_COMPRESSION_METHOD")
                .long("archive-compression-method")
                .short('c')
                .help("Sets the archive and compression method")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .possible_value(compress::DirEncoder::TarGzip.id())
                .possible_value(compress::DirEncoder::ZipGzip.id())
                .possible_value(compress::DirEncoder::TarZstd(1).id())
                .possible_value(compress::DirEncoder::TarZstd(2).id())
                .possible_value(compress::DirEncoder::TarZstd(3).id())
                .possible_value(compress::DirEncoder::ZipZstd(1).id())
                .possible_value(compress::DirEncoder::ZipZstd(2).id())
                .possible_value(compress::DirEncoder::ZipZstd(3).id())
                .default_value(compress::DirEncoder::TarGzip.id()),
        )
        .arg(
            Arg::new("PACK_DIR")
                .long("pack-dir")
                .short('p')
                .help("Sets the source directory path to compress/archive")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
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
}

pub fn execute(
    reg: &str,
    log_level: &str,
    archive_compression_method: &str,
    pack_dir: &str,
    s3_bucket: &str,
    s3_key: &str,
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
        .block_on(aws::load_config(Some(reg.to_string())))
        .unwrap();
    let s3_manager = s3::Manager::new(&shared_config);

    let enc = compress::DirEncoder::new(archive_compression_method)?;
    info!("STEP: backup {} with {}", pack_dir, enc.to_string());
    let parent_dir = Path::new(&pack_dir)
        .parent()
        .expect("unexpected None parent dir");
    let tmp_file_path = parent_dir.join(random::string(10));
    let tmp_file_path = tmp_file_path.as_path().as_os_str().to_str().unwrap();
    compress::pack_directory(pack_dir, tmp_file_path, enc)?;

    info!("STEP: upload output {} to S3", tmp_file_path);
    rt.block_on(s3_manager.put_object(
        Arc::new(tmp_file_path.to_string()),
        Arc::new(s3_bucket.to_string()),
        Arc::new(s3_key.to_string()),
    ))
    .unwrap();
    fs::remove_file(tmp_file_path)?;

    info!("'avalanched backup upload' all success!");
    Ok(())
}
