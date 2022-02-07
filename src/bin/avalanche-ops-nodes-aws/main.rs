use std::{
    fs,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
    thread,
    time::{self, Duration},
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use clap::{arg, App, AppSettings, Arg};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

use avalanche_ops::{
    aws, aws_cloudformation, aws_ec2, aws_kms, aws_s3, aws_sts, compress, network,
};

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_CONFIG: &str = "default-config";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowInvalidUtf8ForExternalSubcommands)
        .subcommands(vec![
            create_default_config_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_CONFIG, sub_matches)) => {
            let bin_path = sub_matches.value_of("AVALANCHEGO_BIN").unwrap();
            let plugins_dir = sub_matches.value_of("PLUGINS_DIR").unwrap_or("");
            let log_level = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            let config_path = sub_matches.value_of("CONFIG_FILE_PATH").unwrap();
            let network_id = sub_matches.value_of("NETWORK_ID").unwrap_or("custom");
            run_default_config(bin_path, plugins_dir, log_level, config_path, network_id).unwrap();
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            let log_level = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            let config_path = sub_matches.value_of("CONFIG_FILE_PATH").unwrap();
            let skip_prompt = sub_matches.is_present("SKIP_PROMPT");
            run_apply(log_level, config_path, skip_prompt).unwrap();
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            let log_level = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            let config_path = sub_matches.value_of("CONFIG_FILE_PATH").unwrap();
            let delete_all = sub_matches.is_present("DELETE_ALL");
            let skip_prompt = sub_matches.is_present("SKIP_PROMPT");
            run_delete(log_level, config_path, delete_all, skip_prompt).unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

fn create_default_config_command() -> App<'static> {
    App::new(SUBCOMMAND_DEFAULT_CONFIG)
        .about("Writes a default configuration")
        .arg(
            Arg::new("AVALANCHEGO_BIN") 
                .long("avalanchego-bin")
                .short('b')
                .help("Sets the Avalanche node binary path to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("PLUGINS_DIR") 
                .long("plugins-dir")
                .short('p')
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
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
            Arg::new("CONFIG_FILE_PATH")
                .long("config")
                .short('c')
                .help("The config file to create")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(arg!(<NETWORK_ID>).required(true).allow_invalid_utf8(false))
}

fn create_apply_command() -> App<'static> {
    App::new(SUBCOMMAND_APPLY)
        .about("Applies/creates resources based on configuration")
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
            Arg::new("CONFIG_FILE_PATH")
                .long("config")
                .short('c')
                .help("The config file to load and update")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

fn create_delete_command() -> App<'static> {
    App::new(SUBCOMMAND_DELETE)
        .about("Deletes resources based on configuration")
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
            Arg::new("CONFIG_FILE_PATH")
                .long("config")
                .short('c')
                .help("The config file to load")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DELETE_ALL")
                .long("delete-all")
                .short('a')
                .help("Enables delete all mode (e.g., delete S3 bucket)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

/// TODO: better error handling rather than just panic with "unwrap"
fn run_default_config(
    bin_path: &str,
    plugins_dir: &str,
    log_level: &str,
    config_path: &str,
    network_id: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut pdir = Some(String::from(plugins_dir));
    if plugins_dir.is_empty() {
        pdir = None;
    }
    let config = network::Config::default_aws(bin_path, pdir, network_id);
    config.sync(config_path).unwrap();

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}", config_contents);

    Ok(())
}

/// TODO: better error handling rather than just panic with "unwrap"
fn run_apply(log_level: &str, config_path: &str, skip_prompt: bool) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    #[derive(RustEmbed)]
    #[folder = "cloudformation/"]
    #[prefix = "cloudformation/"]
    struct Asset;

    let mut config = network::load_config(config_path).unwrap();
    let mut aws_resources = config.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = aws_sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // configuration must be valid
    config.validate().unwrap();

    // validate identity
    match aws_resources.clone().identity {
        Some(identity) => {
            // AWS calls must be made from the same caller
            if identity != current_identity {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "config identity {:?} != currently loaded identity {:?}",
                        identity, current_identity
                    ),
                ));
            }
        }
        None => {
            aws_resources.identity = Some(current_identity);
        }
    }

    // set defaults
    if aws_resources.ec2_key_name.is_none() {
        aws_resources.ec2_key_name = Some(format!("{}-ec2-key", config.id));
    }
    if aws_resources.cloudformation_ec2_instance_role.is_none() {
        aws_resources.cloudformation_ec2_instance_role =
            Some(format!("{}-ec2-instance-role", config.id));
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc = Some(format!("{}-vpc", config.id));
    }
    if !config.is_mainnet() && aws_resources.cloudformation_asg_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_beacon_nodes =
            Some(format!("{}-asg-beacon-nodes", config.id));
    }
    if aws_resources.cloudformation_asg_non_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_non_beacon_nodes =
            Some(format!("{}-asg-non-beacon-nodes", config.id));
    }
    config.aws_resources = Some(aws_resources.clone());
    config.sync(config_path).unwrap();

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}\n", config_contents);

    if !skip_prompt {
        let options = &[
            "No, I am not ready to create resources!",
            "Yes, let's create resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("creating resources (with config path {})", config_path);
    let s3_manager = aws_s3::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 bucket\n"),
        ResetColor
    )
    .unwrap();
    rt.block_on(s3_manager.create_bucket(&aws_resources.bucket))
        .unwrap();

    thread::sleep(time::Duration::from_secs(1));
    let tempf = tempfile::NamedTempFile::new().unwrap();
    let tempf_path = tempf.path().to_str().unwrap();
    crate::compress::compress_zstd(&config.avalanchego_bin, tempf_path, None).unwrap();
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        tempf_path,
        format!("{}/installation/avalanchego.zstd", config.id).as_str(),
    ))
    .unwrap();

    if config.plugins_dir.is_some() {
        let plugins_dir = config.plugins_dir.clone().unwrap();
        for entry in fs::read_dir(plugins_dir.as_str()).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            let tempf = tempfile::NamedTempFile::new().unwrap();
            let tempf_path = tempf.path().to_str().unwrap();
            crate::compress::compress_zstd(file_path, tempf_path, None).unwrap();

            info!(
                "uploading {} (compressed from {}) from plugins directory {}",
                tempf_path, file_path, plugins_dir,
            );
            rt.block_on(s3_manager.put_object(
                &aws_resources.bucket,
                tempf_path,
                format!("{}/installation/plugins/{}.zstd", config.id, file_name).as_str(),
            ))
            .unwrap();
        }
    }
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        config_path,
        format!("{}/config.yaml", config.id).as_str(),
    ))
    .unwrap();

    if aws_resources.kms_cmk_id.is_none() && aws_resources.kms_cmk_arn.is_none() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )
        .unwrap();
        let key = rt
            .block_on(kms_manager.create_key(format!("{}-cmk", config.id).as_str()))
            .unwrap();

        aws_resources.kms_cmk_id = Some(key.id);
        aws_resources.kms_cmk_arn = Some(key.arn);
        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    if aws_resources.ec2_key_path.is_none() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )
        .unwrap();
        let ec2_key_path = get_ec2_key_path(config_path);
        rt.block_on(ec2_manager.create_key_pair(
            aws_resources.ec2_key_name.clone().unwrap().as_str(),
            ec2_key_path.as_str(),
        ))
        .unwrap();

        let ec2_key_path_compressed = format!("{}.zstd", ec2_key_path);
        compress::compress_zstd(
            ec2_key_path.as_str(),
            ec2_key_path_compressed.as_str(),
            None,
        )
        .unwrap();
        let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
        rt.block_on(kms_manager.encrypt_file(
            aws_resources.kms_cmk_id.clone().unwrap().as_str(),
            None,
            ec2_key_path_compressed.as_str(),
            ec2_key_path_compressed_encrypted.as_str(),
        ))
        .unwrap();
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            ec2_key_path_compressed_encrypted.as_str(),
            format!("{}/ec2-key.zstd.encrypted", config.id).as_str(),
        ))
        .unwrap();

        aws_resources.ec2_key_path = Some(ec2_key_path);
        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )
        .unwrap();

        let ec2_instance_role_yaml = Asset::get("cloudformation/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        rt.block_on(
            cloudformation_manager.create_stack(
                ec2_instance_role_stack_name.as_str(),
                Some(vec![Capability::CapabilityNamedIam]),
                OnFailure::Delete,
                ec2_instance_role_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("kind")
                    .value("avalanche-ops")
                    .build()])),
                Some(Vec::from([
                    Parameter::builder()
                        .parameter_key("Id")
                        .parameter_value(&config.id)
                        .build(),
                    Parameter::builder()
                        .parameter_key("KmsKeyArn")
                        .parameter_value(aws_resources.kms_cmk_arn.clone().unwrap())
                        .build(),
                    Parameter::builder()
                        .parameter_key("S3BucketName")
                        .parameter_value(aws_resources.bucket.clone())
                        .build(),
                ])),
            ),
        )
        .unwrap();

        thread::sleep(time::Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                ec2_instance_role_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(20),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("InstanceProfileArn") {
                aws_resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_none()
        && aws_resources.cloudformation_vpc_security_group_id.is_none()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )
        .unwrap();

        let vpc_yaml = Asset::get("cloudformation/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();

        let mut parameters = Vec::from([
            Parameter::builder()
                .parameter_key("Id")
                .parameter_value(&config.id)
                .build(),
            Parameter::builder()
                .parameter_key("VpcCidr")
                .parameter_value("10.0.0.0/16")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr1")
                .parameter_value("10.0.64.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr2")
                .parameter_value("10.0.128.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetCidr3")
                .parameter_value("10.0.192.0/19")
                .build(),
            Parameter::builder()
                .parameter_key("IngressEgressIPv4Range")
                .parameter_value("0.0.0.0/0")
                .build(),
        ]);
        if config.http_port.is_some() {
            let http_port = config.http_port.unwrap();
            let param = Parameter::builder()
                .parameter_key("HttpPort")
                .parameter_value(format!("{}", http_port))
                .build();
            parameters.push(param);
        }
        if config.staking_port.is_some() {
            let staking_port = config.staking_port.unwrap();
            let param = Parameter::builder()
                .parameter_key("StakingPort")
                .parameter_value(format!("{}", staking_port))
                .build();
            parameters.push(param);
        }

        rt.block_on(cloudformation_manager.create_stack(
            vpc_stack_name.as_str(),
            None,
            OnFailure::Delete,
            vpc_tmpl,
            Some(Vec::from([
                Tag::builder().key("kind").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        thread::sleep(time::Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(20),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("VpcId") {
                aws_resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                aws_resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                aws_resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    if config.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_none()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for beacon nodes\n"),
            ResetColor
        )
        .unwrap();

        let cloudformation_asg_beacon_nodes_yaml =
            Asset::get("cloudformation/ec2_asg_amd64.yaml").unwrap();
        let cloudformation_asg_beacon_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_beacon_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_beacon_nodes
            .clone()
            .unwrap();

        let mut parameters = Vec::from([
            Parameter::builder()
                .parameter_key("Id")
                .parameter_value(&config.id)
                .build(),
            Parameter::builder()
                .parameter_key("NodeType")
                .parameter_value("beacon")
                .build(),
            Parameter::builder()
                .parameter_key("S3BucketName")
                .parameter_value(aws_resources.bucket.clone())
                .build(),
            Parameter::builder()
                .parameter_key("Ec2KeyPairName")
                .parameter_value(aws_resources.ec2_key_name.clone().unwrap())
                .build(),
            Parameter::builder()
                .parameter_key("InstanceProfileArn")
                .parameter_value(
                    aws_resources
                        .cloudformation_ec2_instance_profile_arn
                        .clone()
                        .unwrap(),
                )
                .build(),
            Parameter::builder()
                .parameter_key("PublicSubnetIds")
                .parameter_value(
                    aws_resources
                        .cloudformation_vpc_public_subnet_ids
                        .clone()
                        .unwrap()
                        .join(","),
                )
                .build(),
            Parameter::builder()
                .parameter_key("SecurityGroupId")
                .parameter_value(
                    aws_resources
                        .cloudformation_vpc_security_group_id
                        .clone()
                        .unwrap(),
                )
                .build(),
            Parameter::builder()
                .parameter_key("AsgDesiredCapacity")
                .parameter_value(format!("{}", config.machine.beacon_nodes.unwrap()))
                .build(),
        ]);
        if config.machine.instance_types.is_some() {
            let instance_types = config.machine.instance_types.clone().unwrap();
            parameters.push(
                Parameter::builder()
                    .parameter_key("InstanceTypes")
                    .parameter_value(instance_types.join(","))
                    .build(),
            );
            parameters.push(
                Parameter::builder()
                    .parameter_key("InstanceTypesCount")
                    .parameter_value(format!("{}", instance_types.len()))
                    .build(),
            );
        }

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_beacon_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_beacon_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("kind").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        // TODO: adjust timeouts based on the capacity
        thread::sleep(time::Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_beacon_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(20),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_beacon_nodes_logical_id = Some(v);
            }
        }

        // TODO
        // get all IPs and IDs, update config path
        // e.g.,
        // chmod 400 /tmp/test-ec2-access-key
        // ssh -o "StrictHostKeyChecking no" -i /tmp/test-ec2-access-key ubuntu@34.209.244.108
        // ssh -o "StrictHostKeyChecking no" -i /tmp/test-ec2-access-key ubuntu@ec2-34-209-244-108.us-west-2.compute.amazonaws.com
        // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]

        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_none()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for non-beacon nodes\n"),
            ResetColor
        )
        .unwrap();

        // TODO
        info!("not implemented...");

        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            config_path,
            format!("{}/config.yaml", config.id).as_str(),
        ))
        .unwrap();
    }

    Ok(())
}

/// TODO: better error handling rather than just panic with "unwrap"
fn run_delete(
    log_level: &str,
    config_path: &str,
    delete_all: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let config = network::load_config(config_path).unwrap();
    let aws_resources = config.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = aws_sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
    match aws_resources.identity {
        Some(identity) => {
            // AWS calls must be made from the same caller
            if identity != current_identity {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "config identity {:?} != currently loaded identity {:?}",
                        identity, current_identity
                    ),
                ));
            }
        }
        None => {
            return Err(Error::new(ErrorKind::Other, "unknown identity"));
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}\n", config_contents);

    if !skip_prompt {
        let options = &[
            "No, I am not ready to delete resources!",
            "Yes, let's delete resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("deleting resources...");
    let s3_manager = aws_s3::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_some()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete ASG for non-beacon nodes\n"),
            ResetColor
        )
        .unwrap();

        let asg_non_beacon_nodes_stack_name =
            aws_resources.cloudformation_asg_non_beacon_nodes.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_non_beacon_nodes_stack_name.as_str()))
            .unwrap();
        thread::sleep(time::Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            asg_non_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(300),
            Duration::from_secs(20),
        ))
        .unwrap();
    }

    if config.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_some()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete ASG for beacon nodes\n"),
            ResetColor
        )
        .unwrap();

        let asg_beacon_nodes_stack_name = aws_resources.cloudformation_asg_beacon_nodes.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_beacon_nodes_stack_name.as_str()))
            .unwrap();
        thread::sleep(time::Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            asg_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(300),
            Duration::from_secs(20),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_some()
        && aws_resources.cloudformation_vpc_security_group_id.is_some()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_some()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )
        .unwrap();

        let vpc_stack_name = aws_resources.cloudformation_vpc.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(vpc_stack_name.as_str()))
            .unwrap();
        thread::sleep(time::Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            vpc_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(300),
            Duration::from_secs(20),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 instance role\n"),
            ResetColor
        )
        .unwrap();

        let ec2_instance_role_stack_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_stack_name.as_str()))
            .unwrap();
        thread::sleep(time::Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            ec2_instance_role_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(300),
            Duration::from_secs(20),
        ))
        .unwrap();
    }

    if aws_resources.ec2_key_name.is_some() && aws_resources.ec2_key_path.is_some() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 key pair\n"),
            ResetColor
        )
        .unwrap();

        let ec2_key_path = aws_resources.ec2_key_path.unwrap();
        if Path::new(ec2_key_path.as_str()).exists() {
            fs::remove_file(ec2_key_path.as_str()).unwrap();
        }
        let ec2_key_path_compressed = format!("{}.zstd", ec2_key_path);
        if Path::new(ec2_key_path_compressed.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed.as_str()).unwrap();
        }
        let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
        if Path::new(ec2_key_path_compressed_encrypted.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed_encrypted.as_str()).unwrap();
        }
        rt.block_on(ec2_manager.delete_key_pair(aws_resources.ec2_key_name.unwrap().as_str()))
            .unwrap();
    }

    if aws_resources.kms_cmk_id.is_some() && aws_resources.kms_cmk_arn.is_some() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete KMS key\n"),
            ResetColor
        )
        .unwrap();

        let cmk_id = aws_resources.kms_cmk_id.unwrap();
        rt.block_on(kms_manager.schedule_to_delete(cmk_id.as_str()))
            .unwrap();
    }

    if delete_all {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 bucket\n"),
            ResetColor
        )
        .unwrap();

        rt.block_on(s3_manager.delete_objects(&aws_resources.bucket, None))
            .unwrap();
        rt.block_on(s3_manager.delete_bucket(&aws_resources.bucket))
            .unwrap();
    }

    Ok(())
}

fn get_ec2_key_path(config_path: &str) -> String {
    let path = Path::new(config_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ec2-access-key", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}
