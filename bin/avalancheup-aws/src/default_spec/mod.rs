use std::io::{self, stdout, Error, ErrorKind};

use avalanche_types::avalanchego::config as avalanchego_config;
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
            Arg::new("KEY_FILES_DIR")
                .long("key-files-dir")
                .help("Directory to write key files to")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("KEYS_TO_GENERATE") 
                .long("keys-to-generate")
                .help("Sets the number of keys to generate (only requires for custom network)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("0"),
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
            Arg::new("PREFERRED_AZ_INDEX")
                .long("preferred-az-index")
                .short('x')
                .help("Sets the index to choose the preferred AZ (only use it to launch an instance other than first AZ for custom network, or second avalancheup cluster)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
        .arg(
            Arg::new("USE_SPOT_INSTANCE")
                .long("use-spot-instance")
                .help("Sets to use EC2 spot instance")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("USE_ELASTIC_IPS")
                .long("use-elastic-ips")
                .help("Sets to provision EC2 elastic IPs for all nodes")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DISABLE_SPOT_INSTANCE_FOR_ANCHOR_NODES")
                .long("disable-spot-instance-for-anchor-nodes")
                .help("Sets to disable spot instance for anchor nodes")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DISABLE_NLB")
                .long("disable-nlb")
                .help("Sets to disable NLB")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DISABLE_LOGS_AUTO_REMOVAL")
                .long("disable-logs-auto-removal")
                .help("Sets to disable CloudWatch logs auto removal")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("METRICS_FETCH_INTERVAL_SECONDS")
                .long("metrics-fetch-interval-seconds")
                .help("Sets the avalanche-telemetry-cloudwatch fetch interval in seconds")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("3600"),
        )
        .arg(
            Arg::new("AAD_TAG")
                .long("aad-tag")
                .short('a')
                .help("Sets the AAD tag for envelope encryption with KMS")
                .required(false)
                .num_args(1)
                .default_value("avalanche-ops-aad-tag"),
        )
        .arg(
            Arg::new("NLB_ACM_CERTIFICATE_ARN") 
                .long("nlb-acm-certificate-arn")
                .help("Sets ACM ARN to enable NLB HTTPS")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AWS_VOLUME_PROVISIONER_BIN") 
                .long("install-artifacts-aws-volume-provisioner-bin")
                .help("Sets the aws-volume-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AWS_IP_PROVISIONER_BIN") 
                .long("install-artifacts-aws-ip-provisioner-bin")
                .help("Sets the aws-ip-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_TELEMETRY_CLOUDWATCH_BIN") 
                .long("install-artifacts-avalanche-telemetry-cloudwatch-bin")
                .help("Sets the avalanche-telemetry-cloudwatch binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHED_BIN") 
                .long("install-artifacts-avalanched-bin")
                .help("Sets the Avalanched binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_BIN") 
                .long("install-artifacts-avalanche-bin")
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGINS_DIR") 
                .long("install-artifacts-plugins-dir")
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("NETWORK_NAME") 
                .long("network-name")
                .help("Sets the type of network by name (e.g., mainnet, fuji, custom)")
                .required(false)
                .num_args(1)
                .default_value("custom"),
        )
        .arg(
            Arg::new("VOLUME_SIZE_IN_GB")
                .long("volume-size-in-gb")
                .help("Sets initial volume size in GB")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("300"),
        )
        .arg(
            Arg::new("AVALANCHED_LOG_LEVEL") 
                .long("avalanched-log-level")
                .help("Sets the log level for 'avalanched'")
                .required(false)
                .num_args(1)
                 .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("AVALANCHED_USE_DEFAULT_CONFIG") 
                .long("avalanched-use-default-config")
                .help("Sets to use default config (for CDK)")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AVALANCHED_PUBLISH_PERIODIC_NODE_INFO") 
                .long("avalanched-publish-periodic-node-info")
                .help("Sets to periodically publish node info to S3")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AVALANCHEGO_LOG_LEVEL") 
                .long("avalanchego-log-level")
                .help("Sets log-level for avalanchego")
                .required(false)
                .num_args(1)
                .default_value(avalanchego_config::DEFAULT_LOG_LEVEL),
        )
        .arg(
            Arg::new("AVALANCHEGO_WHITELISTED_SUBNETS") 
                .long("avalanchego-whitelisted-subnets")
                .help("Sets the whitelisted-subnets value for avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_HTTP_TLS_ENABLED") 
                .long("avalanchego-http-tls-enabled")
                .help("Sets to enable HTTP TLS")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AVALANCHEGO_STATE_SYNC_IDS") 
                .long("avalanchego-state-sync-ids")
                .help("Sets explicit state-sync-ids for avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_STATE_SYNC_IPS") 
                .long("avalanchego-state-sync-ips")
                .help("Sets explicit state-sync-ips for avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_ENABLED")
                .long("avalanchego-profile-continuous-enabled")
                .help("Sets profile-continuous-enabled for avalanchego")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_FREQ")
                .long("avalanchego-profile-continuous-freq")
                .help("Sets profile-continuous-freq for avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_MAX_FILES")
                .long("avalanchego-profile-continuous-max-files")
                .help("Sets profile-continuous-max-files for avalanchego")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("CORETH_METRICS_ENABLED")
                .long("coreth-metrics-enabled")
                .help("Sets metrics-enabled for coreth")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("CORETH_CONTINUOUS_PROFILER_ENABLED")
                .long("coreth-continuous-profiler-enabled")
                .help("Sets to enable coreth profiler with default values")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("CORETH_OFFLINE_PRUNING_ENABLED")
                .long("coreth-offline-pruning-enabled")
                .help("Sets offline-pruning-enabled for coreth")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("CORETH_STATE_SYNC_ENABLED")
                .long("coreth-state-sync-enabled")
                .help("Sets state-sync-enabled for coreth")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("CORETH_STATE_SYNC_METRICS_ENABLED")
                .long("coreth-state-sync-metrics-enabled")
                .help("Sets state-sync-metrics-enabled for coreth")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("ENABLE_SUBNET_EVM")
                .long("enable-subnet-evm")
                .help("Sets to enable subnet-evm")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("SUBNET_EVM_GAS_LIMIT")
                .long("subnet-evm-gas-limit")
                .help("Sets subnet-evm gas limit")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("8000000"),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG")
                .long("subnet-evm-auto-contract-deployer-allow-list-config")
                .help("Sets to auto-populate subnet-evm allow list config")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_CONTRACT_NATIVE_MINTER_CONFIG")
                .long("subnet-evm-auto-contract-native-minter-config")
                .help("Sets to auto-populate subnet-evm native minter config")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_FEE_MANAGER_CONFIG")
                .long("subnet-evm-auto-fee-manager-config")
                .help("Sets to auto-populate subnet-evm fee manager config")
                .required(false)
                .num_args(0),
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

pub fn execute(opts: avalancheup_aws::DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    if opts.network_name == "custom" && opts.keys_to_generate == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            "can't --keys-to-generate=0 for custom network",
        ));
    }
    if opts.network_name != "custom" && opts.keys_to_generate > 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "can't --keys-to-generate={} (>0) for {} network",
                opts.keys_to_generate, opts.network_name
            ),
        ));
    }

    let spec = avalancheup_aws::Spec::default_aws(opts.clone());
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
                    "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-eips \\\n--spec-file-path {}\n",
                    exec_path.display(),
                    spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
