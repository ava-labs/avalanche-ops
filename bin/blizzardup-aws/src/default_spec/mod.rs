use std::io::{self};

use clap::{value_parser, Arg, Command};

pub const NAME: &str = "default-spec";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default configuration")
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
            Arg::new("KEY_FILES_DIR")
                .long("key-files-dir")
                .help("Directory to write key files to")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("KEYS_TO_GENERATE") 
                .long("keys-to-generate")
                .help("Sets the number of keys to generate")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("50"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("USE_SPOT_INSTANCE")
                .long("use-spot-instance")
                .help("Sets to use EC2 spot instance")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("NETWORK_ID") 
                .long("network-id")
                .help("Sets the network Id")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("2000777"),
        )
        .arg(
            Arg::new("NODES") 
                .long("nodes")
                .help("Sets the number of blizzards nodes to create")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("2"),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_BLIZZARD_BIN") 
                .long("install-artifacts-blizzard-bin")
                .help("Sets the Blizzard binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("BLIZZARD_LOG_LEVEL") 
                .long("blizzard-log-level")
                .help("Sets the log level for 'blizzard'")
                .required(false)
                .num_args(1)
                 .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("BLIZZARD_METRICS_PUSH_INTERVAL_SECONDS")
                .long("blizzard-metrics-push-interval-seconds")
                .help("Sets 'blizzard' metrics push interval in seconds")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("60"),
        )
        .arg(
            Arg::new("BLIZZARD_HTTP_RPCS")
                .long("blizzard-http-rpcs")
                .help("Comma-separated 'blizzard' HTTP RPC endpoints (e.g., http://[HOST]:[PORT])")
                .required(false)
                .num_args(1)
                .default_value("http://localhost:9650"),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(false)
                .num_args(1),
        )
}

pub fn execute(opts: blizzardup_aws::DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    Ok(())
}
