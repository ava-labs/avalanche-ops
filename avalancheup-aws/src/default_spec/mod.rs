use std::{
    collections::HashMap,
    io::{self, stdout},
    path::Path,
};

use avalanche_types::avalanchego::config as avalanchego_config;
use aws_manager::ec2;
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

pub const NAME: &str = "default-spec";

#[derive(Clone, Debug)]
pub struct HashMapStringToStringParser;

impl clap::builder::TypedValueParser for HashMapStringToStringParser {
    type Value = HashMap<String, String>;

    fn parse_ref(
        &self,
        _cmd: &Command,
        _arg: Option<&Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let s = value.to_str().unwrap_or_default();
        let m: HashMap<String, String> = serde_json::from_str(s).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("HashMap parsing '{}' failed ({})", s, e),
            )
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug)]
pub struct HashMapStringToStringsParser;

impl clap::builder::TypedValueParser for HashMapStringToStringsParser {
    type Value = HashMap<String, Vec<String>>;

    fn parse_ref(
        &self,
        _cmd: &Command,
        _arg: Option<&Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let s = value.to_str().unwrap_or_default();
        let m: HashMap<String, Vec<String>> = serde_json::from_str(s).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("HashMap parsing '{}' failed ({})", s, e),
            )
        })?;
        Ok(m)
    }
}

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
            Arg::new("ARCH_TYPE")
                .long("arch-type")
                .help("Sets the machine architecture")
                .required(true)
                .num_args(1)
                .value_parser([
                    ec2::ArchType::Amd64.as_str(),
                    ec2::ArchType::Arm64.as_str(),
                ])
                .default_value(ec2::ArchType::Amd64.as_str()),
        )
        .arg(
            Arg::new("OS_TYPE")
                .long("os-type")
                .help("Sets the OS type")
                .required(true)
                .num_args(1)
                .value_parser([
                    ec2::OsType::Ubuntu2004.as_str(),
                ])
                .default_value(ec2::OsType::Ubuntu2004.as_str()),
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
            Arg::new("REGIONS")
                .long("regions")
                .help("Sets the comma-separated instance types (to be discarded by --auto-regions)")
                .required(false)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("AUTO_REGIONS")
                .long("auto-regions")
                .help("Sets the number of regions to auto-populate (overwrites --region)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("0"),
        )
        .arg(
            Arg::new("KEEP_RESOURCES_EXCEPT_ASG_SSM")
                .long("keep-resources-except-asg-ssm")
                .help("Sets to keep resources except ASG/SSM (useful for reusing IAM Role/VPC/KMS)")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("CREATE_DEV_MACHINE")
                .long("create-dev-machine")
                .help("Sets to create a dev-machine")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DEV_MACHINE_SSH_KEY_EMAIL")
                .long("dev-machine-ssh-key-email")
                .help("Sets the email address for an SSH key")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("INGRESS_IPV4_CIDR")
                .long("ingress-ipv4-cidr")
                .help("Sets the IPv4 CIDR range for ingress traffic HTTP/SSH (leave empty to default to public IP on the local host)")
                .required(false)
                .num_args(1),
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
            Arg::new("INSTANCE_SIZE")
                .long("instance-size")
                .help("Sets instance size")
                .required(false)
                .num_args(1)
                .value_parser(["large", "xlarge", "2xlarge", "4xlarge", "8xlarge"])
                .default_value("xlarge"),
        )
        .arg(
            Arg::new("INSTANCE_TYPES")
                .long("instance-types")
                .help("Sets the hash map from a region to a comma-separated instance types (overwrites --instance-size)")
                .required(false)
                .value_parser(HashMapStringToStringsParser {})
                .num_args(1),
        )
        .arg(
            Arg::new("IMAGE_IDS")
                .long("image-ids")
                .help("Sets the hash map from a region to the EC2 image ID to overwrite SSM parameter")
                .required(false)
                .value_parser(HashMapStringToStringParser {})
                .num_args(1),
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
            Arg::new("ENABLE_SSH")
                .long("enable-ssh")
                .help("Sets to enable SSH")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("ENABLE_NLB")
                .long("enable-nlb")
                .help("Sets to enable NLB")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("NLB_ACM_CERTIFICATE_ARNS") 
                .long("nlb-acm-certificate-arns")
                .help("Sets the hash map from a region to an ACM ARN to enable NLB HTTPS")
                .required(false)
                .value_parser(HashMapStringToStringParser {})
                .num_args(1),
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
            Arg::new("UPLOAD_ARTIFACTS_AWS_VOLUME_PROVISIONER_LOCAL_BIN") 
                .long("upload-artifacts-aws-volume-provisioner-local-bin")
                .help("Sets the aws-volume-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("UPLOAD_ARTIFACTS_AWS_IP_PROVISIONER_LOCAL_BIN") 
                .long("upload-artifacts-aws-ip-provisioner-local-bin")
                .help("Sets the aws-ip-provisioner binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("UPLOAD_ARTIFACTS_AVALANCHE_TELEMETRY_CLOUDWATCH_LOCAL_BIN") 
                .long("upload-artifacts-avalanche-telemetry-cloudwatch-local-bin")
                .help("Sets the avalanche-telemetry-cloudwatch binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("UPLOAD_ARTIFACTS_AVALANCHED_AWS_LOCAL_BIN") 
                .long("upload-artifacts-avalanched-aws-local-bin")
                .help("Sets the avalanched binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("UPLOAD_ARTIFACTS_AVALANCHEGO_LOCAL_BIN") 
                .long("upload-artifacts-avalanchego-local-bin")
                .help("Sets the AvalancheGo node binary path in the local machine to be shared with remote machines (if empty, it downloads the latest from github)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("UPLOAD_ARTIFACTS_PROMETHEUS_METRICS_RULES_FILE_PATH") 
                .long("upload-artifacts-prometheus-metrics-rules-file-path")
                .help("Sets prometheus rules file path in the local machine to be shared with remote machines")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_RELEASE_TAG")
                .long("avalanchego-release-tag")
                .help("Non-empty to specify avalanchego release tag to download (ignored if --upload-artifacts-avalanchego-local-bin is not empty)")
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
            Arg::new("PRIMARY_NETWORK_VALIDATE_PERIOD_IN_DAYS") 
                .long("primary-network-validate-period-in-days")
                .help("Sets the number of days to validate primary network")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("16"),
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("PROFILE_NAME")
                .long("profile-name")
                .help("Sets the AWS credential profile name for API calls/endpoints")
                .required(false)
                .default_value("default")
                .num_args(1),
        )
}

pub async fn execute(opts: avalanche_ops::aws::spec::DefaultSpecOption) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    let (spec, spec_file_path) = avalanche_ops::aws::spec::Spec::default_aws(opts)
        .await
        .unwrap();
    spec.validate()?;
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
        Print(format!("vi {}\n", spec_file_path)),
        ResetColor
    )?;

    println!();
    println!("# run the following to see all nodes after successful 'apply' command runs");
    execute!(
        stdout(),
        SetForegroundColor(Color::Magenta),
        Print(format!(
            "vi {}\n\n",
            get_all_nodes_yaml_path(&spec_file_path)
        )),
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
            "{} delete \\
--delete-cloudwatch-log-group \\
--delete-s3-objects \\
--delete-ebs-volumes \\
--delete-elastic-ips \\
--spec-file-path {spec_file_path}
",
            exec_path.display(),
        )),
        ResetColor
    )?;

    println!();
    println!("# delete resources with override option");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{} delete \\
--override-keep-resources-except-asg-ssm \\
--delete-cloudwatch-log-group \\
--delete-s3-objects \\
--delete-ebs-volumes \\
--delete-elastic-ips \\
--spec-file-path {spec_file_path}

",
            exec_path.display(),
        )),
        ResetColor
    )?;

    Ok(())
}

fn get_all_nodes_yaml_path(spec_file_path: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-all-nodes.yaml", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}
