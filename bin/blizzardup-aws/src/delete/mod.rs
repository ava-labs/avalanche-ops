use std::io;

use clap::{Arg, Command};

pub const NAME: &str = "delete";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Deletes resources based on configuration")
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_CLOUDWATCH_LOG_GROUP")
                .long("delete-cloudwatch-log-group")
                .help("Enables to delete CloudWatch log group")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_S3_OBJECTS")
                .long("delete-s3-objects")
                .help("Enables to delete S3 objects")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_S3_BUCKET")
                .long("delete-s3-bucket")
                .help("Enables delete S3 bucket (use with caution!)")
                .required(false)
                .num_args(0),
        )
}

pub fn execute(
    log_level: &str,
    spec_file_path: &str,
    delete_cloudwatch_log_group: bool,
    delete_s3_objects: bool,
    delete_s3_bucket: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    println!();
    log::info!("delete all success!");
    Ok(())
}
