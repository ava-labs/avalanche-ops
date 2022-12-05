use std::io::{self, stdout};

use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

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
            Arg::new("FUNDED_KEYS") 
                .long("funded-keys")
                .help("Sets the number of pre-funded keys to load from avalanche-types TEST_KEYS")
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
            Arg::new("INSTANCE_MODE")
                .long("instance-mode")
                .help("Sets instance mode")
                .required(false)
                .num_args(1)
                .value_parser(["spot", "on-demand"])
                .default_value("spot"),
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
                .default_value("10"),
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
            Arg::new("BLIZZARD_HTTP_RPCS")
                .long("blizzard-http-rpcs")
                .help("Comma-separated 'blizzard' HTTP RPC endpoints (e.g., http://[HOST]:[PORT])")
                .required(false)
                .num_args(1)
                .default_value("http://localhost:9650"),
        )
        .arg(
            Arg::new("BLIZZARD_SUBNET_EVM_BLOCKCHAIN_ID")
                .long("blizzard-subnet-evm-blockchain-id")
                .help("Blockchain Id for subnet-evm")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("BLIZZARD_LOAD_KINDS")
                .long("blizzard-load-kinds")
                .help("Comma-separated 'blizzard' load kinds (e.g., x-transfers,c-transfers)")
                .required(false)
                .num_args(1)
                .default_value("x-transfers,c-transfers"),
        )
        .arg(
            Arg::new("BLIZZARD_KEYS_TO_GENERATE")
                .long("blizzard-keys-to-generate")
                .help("Number of keys to generate per each blizzard agent")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("100"),
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
            Arg::new("BLIZZARD_WORKERS")
                .long("blizzard-workers")
                .help("Sets the number of concurrent blizzard workers to launch on the host")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("30"),
        )
        .arg(
            Arg::new("BLIZZARD_GAS") 
                .long("blizzard-gas")
                .help("Sets the gas for EVM transactions")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("BLIZZARD_GAS_PRICE") 
                .long("blizzard-gas-price")
                .help("Sets the gas price for EVM transactions")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64)),
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

    let spec = blizzardup_aws::Spec::default_aws(opts.clone());
    spec.validate()?;

    let spec_file_path = {
        if opts.spec_file_path.is_empty() {
            dir_manager::home::named(&spec.id, Some(".yaml"))
        } else {
            opts.spec_file_path
        }
    };
    spec.sync(&spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().expect("failed spec.encode_yaml");
    println!("{}", spec_contents);

    println!();
    println!("# run the following to create resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Magenta),
        Print(format!("cat {}\n", spec_file_path)),
        ResetColor
    )?;
    let exec_path = std::env::current_exe().expect("unexpected None current_exe");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{} apply \\\n--spec-file-path {}\n",
            exec_path.display(),
            spec_file_path
        )),
        ResetColor
    )?;
    println!();
    println!("# run the following to delete resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
                    "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--spec-file-path {}\n",
                    exec_path.display(),
                    spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
