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
            Arg::new("ANCHOR_NODES")
                .long("anchor-nodes")
                .help("Sets the number of anchor nodes (only used when non-zero value)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("0"),
        )
        .arg(
            Arg::new("NON_ANCHOR_NODES")
                .long("non-anchor-nodes")
                .help("Sets the number of non-anchor nodes (only used when non-zero value)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("0"),
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
                .help("Sets the number of keys to generate (only requires for custom network, default if not specified)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
        .arg(
            Arg::new("KEYS_TO_GENERATE_TYPE") 
                .long("keys-to-generate-type")
                .help("Sets the key type for generated keys")
                .required(false)
                .num_args(1)
                .value_parser(["hot", "aws-kms"])
                .default_value("hot"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(false)
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
            Arg::new("IP_MODE")
                .long("ip-mode")
                .help("Sets IP mode to provision EC2 elastic IPs for all nodes")
                .required(false)
                .num_args(1)
                .value_parser(["elastic", "ephemeral"])
                .default_value("elastic"),
        )
        .arg(
            Arg::new("ENABLE_NLB")
                .long("enable-nlb")
                .help("Sets to enable NLB")
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
                .help("Sets the avalanche-telemetry-cloudwatch fetch interval and other system metrics push interval in seconds (0 to disable by default)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
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
            Arg::new("INSTALL_ARTIFACTS_AWS_VOLUME_PROVISIONER_LOCAL_BIN") 
                .long("install-artifacts-aws-volume-provisioner-local-bin")
                .help("Sets the aws-volume-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AWS_IP_PROVISIONER_LOCAL_BIN") 
                .long("install-artifacts-aws-ip-provisioner-local-bin")
                .help("Sets the aws-ip-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_TELEMETRY_CLOUDWATCH_LOCAL_BIN") 
                .long("install-artifacts-avalanche-telemetry-cloudwatch-local-bin")
                .help("Sets the avalanche-telemetry-cloudwatch binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_CONFIG_LOCAL_BIN") 
                .long("install-artifacts-avalanche-config-local-bin")
                .help("Sets the avalanche-config binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHED_LOCAL_BIN") 
                .long("install-artifacts-avalanched-local-bin")
                .help("Sets the avalanched binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_LOCAL_BIN") 
                .long("install-artifacts-avalanche-local-bin")
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGIN_LOCAL_DIR") 
                .long("install-artifacts-plugin-local-dir")
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
                .value_parser(["mainnet", "fuji", "custom"])
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
            Arg::new("SUBNET_EVMS")
                .long("subnet-evms")
                .help("Sets the number of subnet-evms")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_GAS_LIMIT")
                .long("subnet-evm-gas-limit")
                .help("Sets subnet-evm gas limit (zero then use defaults)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_TARGET_BLOCK_RATE")
                .long("subnet-evm-target-block-rate")
                .help("Sets non-zero to set subnet-evm target block rate (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_MIN_BASE_FEE")
                .long("subnet-evm-min-base-fee")
                .help("Sets non-zero to set subnet-evm min base fee (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_TARGET_GAS")
                .long("subnet-evm-target-gas")
                .help("Sets non-zero to set subnet-evm target gas (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_BASE_FEE_CHANGE_DENOMINATOR")
                .long("subnet-evm-base-fee-change-denominator")
                .help("Sets non-zero to set subnet-evm base fee change denominator (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_MIN_BLOCK_GAS_COST")
                .long("subnet-evm-min-block-gas-cost")
                .help("Sets non-zero to set subnet-evm min block gas cost (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_MAX_BLOCK_GAS_COST")
                .long("subnet-evm-max-block-gas-cost")
                .help("Sets non-zero to set subnet-evm max block gas cost (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("SUBNET_EVM_BLOCK_GAS_COST_STEP")
                .long("subnet-evm-block-gas-cost-step")
                .help("Sets non-zero to set subnet-evm block gas cost step (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
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
            Arg::new("SUBNET_EVM_CONFIG_PROPOSER_MIN_BLOCK_DELAY_SECONDS")
                .long("subnet-evm-config-proposer-min-block-delay-seconds")
                .help("Sets to subnet-evm config proposer-min-block-delay in seconds")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("1"),
        )
        .arg(
            Arg::new("XSVMS")
                .long("xsvms")
                .help("Sets the number of XSVMs")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("0"),
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

pub async fn execute(opts: avalancheup_aws::spec::DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    let mut cloned_opts = opts.clone();

    if cloned_opts.network_name == "custom" && cloned_opts.keys_to_generate == 0 {
        log::warn!("can't --keys-to-generate=0 for custom network -- defaulting to 2");
        cloned_opts.keys_to_generate = 2;
    }

    if cloned_opts.network_name != "custom" && cloned_opts.keys_to_generate > 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "can't --keys-to-generate={} (>0) for {} network",
                cloned_opts.keys_to_generate, cloned_opts.network_name
            ),
        ));
    }

    let spec = avalancheup_aws::spec::Spec::default_aws(cloned_opts.clone()).await;
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
        Print(format!("vi {}\n\n", spec_file_path)),
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
                    "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-elastic-ips \\\n--spec-file-path {}\n\n",
                    exec_path.display(),
                    spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
