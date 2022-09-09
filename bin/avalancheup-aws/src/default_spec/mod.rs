use std::io::{self, stdout};

use avalanchego::config as avalanchego_config;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

pub const NAME: &str = "default-spec";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Writes a default configuration")
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
            Arg::new("PREFERRED_AZ_INDEX")
                .long("preferred-az-index")
                .short('x')
                .help("Sets the index to choose the preferred AZ (only use it to launch an instance other than first AZ for custom network, or second avalancheup cluster)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("0"),
        )
        .arg(
            Arg::new("KEY_FILES_DIR")
                .long("key-files-dir")
                .help("Directory to write key files to")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("USE_SPOT_INSTANCE")
                .long("use-spot-instance")
                .help("Sets to use EC2 spot instance")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DISABLE_NLB")
                .long("disable-nlb")
                .help("Sets to disable NLB")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AAD_TAG")
                .long("aad-tag")
                .short('a')
                .help("Sets the AAD tag for envelope encryption with KMS")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("avalanche-ops-aad-tag"),
        )
        .arg(
            Arg::new("NLB_ACM_CERTIFICATE_ARN") 
                .long("nlb-acm-certificate-arn")
                .help("Sets ACM ARN to enable NLB HTTPS")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHED_BIN") 
                .long("install-artifacts-avalanched-bin")
                .help("Sets the Avalanched binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_BIN") 
                .long("install-artifacts-avalanche-bin")
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGINS_DIR") 
                .long("install-artifacts-plugins-dir")
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("NETWORK_NAME") 
                .long("network-name")
                .help("Sets the type of network by name (e.g., mainnet, fuji, custom)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("custom"),
        )
        .arg(
            Arg::new("KEYS_TO_GENERATE") 
                .long("keys-to-generate")
                .help("Sets the number of keys to generate")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("5"), // ref. "avalancheup_aws::DEFAULT_KEYS_TO_GENERATE"
        )
        .arg(
            Arg::new("VOLUME_SIZE_IN_GB")
                .long("volume-size-in-gb")
                .help("Sets initial volume size in GB")
                .required(false)
                .takes_value(true)
                .default_value("500")
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHED_LOG_LEVEL") 
                .long("avalanched-log-level")
                .help("Sets the log level for 'avalanched'")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .possible_value("debug")
                .possible_value("info")
                .default_value("info"),
        )
        .arg(
            Arg::new("AVALANCHED_USE_DEFAULT_CONFIG") 
                .long("avalanched-use-default-config")
                .help("Sets to use default config (for CDK)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHED_SKIP_PUBLISH_NODE_INFO") 
                .long("avalanched-skip-publish-node-info")
                .help("Sets to skip publishing node info(for CDK)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_LOG_LEVEL") 
                .long("avalanchego-log-level")
                .help("Sets log-level for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value(avalanchego_config::DEFAULT_LOG_LEVEL),
        )
        .arg(
            Arg::new("AVALANCHEGO_WHITELISTED_SUBNETS") 
                .long("avalanchego-whitelisted-subnets")
                .help("Sets the whitelisted-subnets value for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_HTTP_TLS_ENABLED") 
                .long("avalanchego-http-tls-enabled")
                .help("Sets to enable HTTP TLS")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_STATE_SYNC_IDS") 
                .long("avalanchego-state-sync-ids")
                .help("Sets explicit state-sync-ids for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_STATE_SYNC_IPS") 
                .long("avalanchego-state-sync-ips")
                .help("Sets explicit state-sync-ips for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_ENABLED")
                .long("avalanchego-profile-continuous-enabled")
                .help("Sets profile-continuous-enabled for avalanchego")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_FREQ")
                .long("avalanchego-profile-continuous-freq")
                .help("Sets profile-continuous-freq for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_PROFILE_CONTINUOUS_MAX_FILES")
                .long("avalanchego-profile-continuous-max-files")
                .help("Sets profile-continuous-max-files for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CORETH_METRICS_ENABLED")
                .long("coreth-metrics-enabled")
                .help("Sets metrics-enabled for coreth")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CORETH_CONTINUOUS_PROFILER_ENABLED")
                .long("coreth-continuous-profiler-enabled")
                .help("Sets to enable coreth profiler with default values")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CORETH_OFFLINE_PRUNING_ENABLED")
                .long("coreth-offline-pruning-enabled")
                .help("Sets offline-pruning-enabled for coreth")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CORETH_STATE_SYNC_ENABLED")
                .long("coreth-state-sync-enabled")
                .help("Sets state-sync-enabled for coreth")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CORETH_STATE_SYNC_METRICS_ENABLED")
                .long("coreth-state-sync-metrics-enabled")
                .help("Sets state-sync-metrics-enabled for coreth")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("ENABLE_SUBNET_EVM")
                .long("enable-subnet-evm")
                .help("Sets to enable subnet-evm")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SUBNET_EVM_GAS_LIMIT")
                .long("subnet-evm-gas-limit")
                .help("Sets subnet-evm gas limit")
                .required(false)
                .takes_value(true)
                .default_value("8000000")
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG")
                .long("subnet-evm-auto-contract-deployer-allow-list-config")
                .help("Sets to auto-populate subnet-evm allow list config")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_CONTRACT_NATIVE_MINTER_CONFIG")
                .long("subnet-evm-auto-contract-native-minter-config")
                .help("Sets to auto-populate subnet-evm native minter config")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SUBNET_EVM_AUTO_FEE_MANAGER_CONFIG")
                .long("subnet-evm-auto-fee-manager-config")
                .help("Sets to auto-populate subnet-evm fee manager config")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

pub fn execute(opt: avalancheup_aws::DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.clone().log_level),
    );

    let spec = avalancheup_aws::Spec::default_aws(opt.clone());
    spec.validate()?;

    let spec_file_path = {
        if opt.spec_file_path.is_empty() {
            dir_manager::home::named(&spec.id, Some(".yaml"))
        } else {
            opt.spec_file_path
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
                    "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--spec-file-path {}\n",
                    exec_path.display(),
                    spec_file_path
        )),
        ResetColor
    )?;

    if spec.subnet_evm_genesis.is_some() {
        let subnet_evm_genesis_file_path =
            dir_manager::home::named(&spec.id, Some(".subnet-evm.genesis.json"));
        let subnet_evm_genesis = spec
            .subnet_evm_genesis
            .expect("unexpected None subnet_evm_genesis");
        println!();
        subnet_evm_genesis
            .sync(&subnet_evm_genesis_file_path)
            .expect("failed subnet_evm_genesis.sync");

        println!();
        println!("# [optional] after 'apply', run the following to create subnet-evm resources");
        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!("cat {} | grep private_key_hex:\n", spec_file_path)),
            ResetColor
        )?;
        let keys = spec
            .generated_seed_private_keys
            .expect("unexpected None generated_seed_private_keys");
        execute!(
            stdout(),
            SetForegroundColor(Color::Cyan),
            Print(format!(
                "cat <<EOF > /tmp/test.key\n{}\nEOF\ncat /tmp/test.key\n",
                keys[0].private_key_hex
            )),
            ResetColor
        )?;
        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!("cat {}\n", subnet_evm_genesis_file_path)),
            ResetColor
        )?;

        println!();
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("subnet-cli add validator \\\n--enable-prompt \\\n--private-key-path=/tmp/test.key \\\n--public-uri=... \\\n--stake-amount=2000000000000 \\\n--validate-reward-fee-percent=2 \\\n--node-ids=\"...\"\n"),
            ResetColor
        )?;

        println!();
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "subnet-cli wizard \\\n--enable-prompt \\\n--private-key-path=/tmp/test.key \\\n--public-uri=... \\\n--vm-genesis-path={} \\\n--vm-id=srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy \\\n--chain-name=subnetevm \\\n--node-ids=\"...\"\n",
                subnet_evm_genesis_file_path
            )),
            ResetColor
        )?;
    }

    Ok(())
}
