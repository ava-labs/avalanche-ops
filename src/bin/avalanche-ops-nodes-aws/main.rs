use std::{
    fs::{self, File},
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_s3::model::Object;
use clap::{App, AppSettings, Arg};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::{info, warn};
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

use avalanche_ops::{
    self, avalanchego, aws, aws_cloudformation, aws_cloudwatch, aws_ec2, aws_kms, aws_s3, aws_sts,
    compress, envelope, http, node, random,
};

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_SPEC: &str = "default-spec";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowInvalidUtf8ForExternalSubcommands)
        .subcommands(vec![
            create_default_spec_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_SPEC, sub_matches)) => {
            run_default_spec(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHED_BIN")
                    .unwrap(),
                sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                    .unwrap(),
                sub_matches
                    .value_of("INSTALL_ARTIFACTS_PLUGINS_DIR")
                    .unwrap_or(""),
                sub_matches
                    .value_of("INSTALL_ARTIFACTS_GENESIS_DRAFT_FILE_PATH")
                    .unwrap(),
                sub_matches.value_of("AVALANCHEGO_LOG_LEVEL").unwrap(),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
            )
            .unwrap();
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            run_apply(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            run_delete(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("DELETE_ALL"),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

fn create_default_spec_command() -> App<'static> {
    App::new(SUBCOMMAND_DEFAULT_SPEC)
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
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHED_BIN") 
                .long("install-artifacts-avalanched-bin")
                .short('d')
                .help("Sets the Avalanched binary path in the local machine to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_BIN") 
                .long("install-artifacts-avalanche-bin")
                .short('b')
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGINS_DIR") 
                .long("install-artifacts-plugins-dir")
                .short('p')
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_GENESIS_DRAFT_FILE_PATH") 
                .long("install-artifacts-genesis-draft-file-path")
                .short('g')
                .help("Sets the genesis draft file path in the local machine to load and share with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("AVALANCHEGO_LOG_LEVEL") 
                .long("avalanchego-log-level")
                .help("Sets log-level for avalanchego")
                .default_value(avalanchego::DEFAULT_LOG_LEVEL)
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load and update")
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
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
        .arg(
            Arg::new("DELETE_ALL")
                .long("delete-all")
                .short('a')
                .help("Enables delete all mode (e.g., delete S3 bucket)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

fn run_default_spec(
    log_level: &str,
    install_artifacts_avalanched_bin: &str,
    install_artifacts_avalanche_bin: &str,
    install_artifacts_plugins_dir: &str,
    install_artifacts_genesis_draft_file_path: &str,
    avalanchego_log_level: &str,
    spec_file_path: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut _install_artifacts_plugins_dir = Some(String::from(install_artifacts_plugins_dir));
    if install_artifacts_plugins_dir.is_empty() {
        _install_artifacts_plugins_dir = None;
    }
    let mut _install_artifacts_genesis_draft_file_path =
        Some(String::from(install_artifacts_genesis_draft_file_path));
    if install_artifacts_genesis_draft_file_path.is_empty() {
        _install_artifacts_genesis_draft_file_path = None;
    }

    let mut avalanchego_config = avalanchego::Config::default();

    let genesis = avalanchego::Genesis::load(install_artifacts_genesis_draft_file_path)?;
    avalanchego_config.network_id = Some(genesis.network_id);
    avalanchego_config.log_level = Some(String::from(avalanchego_log_level));

    let spec = avalanche_ops::Spec::default_aws(
        install_artifacts_avalanched_bin,
        install_artifacts_avalanche_bin,
        _install_artifacts_plugins_dir,
        _install_artifacts_genesis_draft_file_path,
        avalanchego_config,
    );
    spec.validate()?;
    spec.sync(spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    Ok(())
}

fn run_apply(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    #[derive(RustEmbed)]
    #[folder = "cloudformation/"]
    #[prefix = "cloudformation/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = avalanche_ops::Spec::load(spec_file_path).unwrap();
    spec.validate()?;

    let rt = Runtime::new().unwrap();

    let mut aws_resources = spec.aws_resources.clone().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = aws_sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

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

    // set defaults based on ID
    if aws_resources.ec2_key_name.is_none() {
        aws_resources.ec2_key_name = Some(format!("{}-ec2-key", spec.id));
    }
    if aws_resources.cloudformation_ec2_instance_role.is_none() {
        aws_resources.cloudformation_ec2_instance_role =
            Some(format!("{}-ec2-instance-role", spec.id));
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc = Some(format!("{}-vpc", spec.id));
    }
    if !spec.avalanchego_config.is_mainnet()
        && aws_resources.cloudformation_asg_beacon_nodes.is_none()
    {
        aws_resources.cloudformation_asg_beacon_nodes =
            Some(format!("{}-asg-beacon-nodes", spec.id));
    }
    if aws_resources.cloudformation_asg_non_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_non_beacon_nodes =
            Some(format!("{}-asg-non-beacon-nodes", spec.id));
    }
    spec.aws_resources = Some(aws_resources.clone());
    spec.sync(spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded Spec: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml()?;
    println!("{}\n", spec_contents);

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

    info!("creating resources (with spec path {})", spec_file_path);
    let s3_manager = aws_s3::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    thread::sleep(Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 bucket\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.create_bucket(&aws_resources.bucket))
        .unwrap();

    thread::sleep(Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: upload artifacts to S3 bucket\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        &spec.install_artifacts.avalanched_bin,
        &aws_s3::KeyPath::AvalanchedBin(spec.id.clone()).encode(),
    ))
    .unwrap();
    let tmp_avalanche_bin_compressed_path = random::tmp_path(15).unwrap();
    crate::compress::to_zstd_file(
        &spec.install_artifacts.avalanchego_bin,
        &tmp_avalanche_bin_compressed_path,
        None,
    )
    .unwrap();
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        &tmp_avalanche_bin_compressed_path,
        &aws_s3::KeyPath::AvalancheBinCompressed(spec.id.clone()).encode(),
    ))
    .unwrap();
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        &spec.install_artifacts.avalanchego_bin,
        &aws_s3::KeyPath::AvalancheBin(spec.id.clone()).encode(),
    ))
    .unwrap();
    if spec.install_artifacts.plugins_dir.is_some() {
        let plugins_dir = spec.install_artifacts.plugins_dir.clone().unwrap();
        for entry in fs::read_dir(plugins_dir.as_str()).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            let tmp_plugin_compressed_path = random::tmp_path(15).unwrap();
            crate::compress::to_zstd_file(file_path, &tmp_plugin_compressed_path, None).unwrap();

            info!(
                "uploading {} (compressed from {}) from plugins directory {}",
                tmp_plugin_compressed_path, file_path, plugins_dir,
            );
            rt.block_on(
                s3_manager.put_object(
                    &aws_resources.bucket,
                    &tmp_plugin_compressed_path,
                    format!(
                        "{}/{}.zstd",
                        &aws_s3::KeyPath::PluginsDir(spec.id.clone()).encode(),
                        file_name
                    )
                    .as_str(),
                ),
            )
            .unwrap();
        }
    }
    if spec.install_artifacts.genesis_draft_file_path.is_some() {
        let genesis_draft_file_path = spec
            .install_artifacts
            .genesis_draft_file_path
            .clone()
            .unwrap();
        if Path::new(&genesis_draft_file_path).exists() {
            rt.block_on(s3_manager.put_object(
                &aws_resources.bucket,
                &genesis_draft_file_path,
                &aws_s3::KeyPath::GenesisDraftFile(spec.id.clone()).encode(),
            ))
            .unwrap();
        }
    }
    rt.block_on(s3_manager.put_object(
        &aws_resources.bucket,
        spec_file_path,
        &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
    ))
    .unwrap();

    if aws_resources.kms_cmk_id.is_none() && aws_resources.kms_cmk_arn.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )?;
        let key = rt
            .block_on(kms_manager.create_key(format!("{}-cmk", spec.id).as_str()))
            .unwrap();

        aws_resources.kms_cmk_id = Some(key.id);
        aws_resources.kms_cmk_arn = Some(key.arn);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }
    let envelope = envelope::Envelope::new(Some(kms_manager), aws_resources.kms_cmk_id.clone());

    if aws_resources.ec2_key_path.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )
        .unwrap();
        let ec2_key_path = get_ec2_key_path(spec_file_path);
        rt.block_on(ec2_manager.create_key_pair(
            aws_resources.ec2_key_name.clone().unwrap().as_str(),
            ec2_key_path.as_str(),
        ))
        .unwrap();

        let tmp_compressed_path = random::tmp_path(15).unwrap();
        compress::to_zstd_file(ec2_key_path.as_str(), &tmp_compressed_path, None).unwrap();

        let tmp_encrypted_path = random::tmp_path(15).unwrap();
        rt.block_on(envelope.seal_aes_256_file(&tmp_compressed_path, &tmp_encrypted_path))
            .unwrap();
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            &tmp_encrypted_path,
            &aws_s3::KeyPath::Ec2AccessKeyCompressedEncrypted(spec.id.clone()).encode(),
        ))
        .unwrap();

        aws_resources.ec2_key_path = Some(ec2_key_path);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_yaml = Asset::get("cloudformation/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        rt.block_on(cloudformation_manager.create_stack(
            ec2_instance_role_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ec2_instance_role_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(Vec::from([
                build_param("Id", &spec.id),
                build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
                build_param("S3BucketName", &aws_resources.bucket),
            ])),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                ec2_instance_role_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
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
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_none()
        && aws_resources.cloudformation_vpc_security_group_id.is_none()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cloudformation/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();

        let mut parameters = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("IngressEgressIpv4Range", "0.0.0.0/0"),
        ]);
        if spec.avalanchego_config.http_port.is_some() {
            let http_port = spec.avalanchego_config.http_port.unwrap();
            let param = build_param("HttpPort", format!("{}", http_port).as_str());
            parameters.push(param);
        }
        if spec.avalanchego_config.staking_port.is_some() {
            let staking_port = spec.avalanchego_config.staking_port.unwrap();
            let param = build_param("StakingPort", format!("{}", staking_port).as_str());
            parameters.push(param);
        }
        rt.block_on(cloudformation_manager.create_stack(
            vpc_stack_name.as_str(),
            None,
            OnFailure::Delete,
            vpc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(30),
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
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    let mut asg_parameters = Vec::from([
        build_param("Id", &spec.id),
        build_param(
            "NetworkId",
            format!("{}", &spec.avalanchego_config.network_id.unwrap_or(1)).as_str(),
        ),
        build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
        build_param("S3BucketName", &aws_resources.bucket),
        build_param(
            "Ec2KeyPairName",
            &aws_resources.ec2_key_name.clone().unwrap(),
        ),
        build_param(
            "InstanceProfileArn",
            &aws_resources
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        ),
        build_param(
            "PublicSubnetIds",
            &aws_resources
                .cloudformation_vpc_public_subnet_ids
                .clone()
                .unwrap()
                .join(","),
        ),
        build_param(
            "SecurityGroupId",
            &aws_resources
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        ),
        build_param(
            "NlbVpcId",
            &aws_resources.cloudformation_vpc_id.clone().unwrap(),
        ),
    ]);
    if spec.avalanchego_config.http_port.is_some() {
        let http_port = spec.avalanchego_config.http_port.unwrap();
        let param = build_param("NlbHttpPort", format!("{}", http_port).as_str());
        asg_parameters.push(param);
    }
    if spec.machine.instance_types.is_some() {
        let instance_types = spec.machine.instance_types.clone().unwrap();
        asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
        asg_parameters.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    let mut all_nodes: Vec<node::Node> = Vec::new();
    if spec.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for beacon nodes\n"),
            ResetColor
        )?;

        let cloudformation_asg_beacon_nodes_yaml =
            Asset::get("cloudformation/asg_ubuntu_amd64.yaml").unwrap();
        let cloudformation_asg_beacon_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_beacon_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_beacon_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.beacon_nodes.unwrap();

        // must deep-copy as shared with other node kind
        let mut parameters = asg_parameters.clone();
        parameters.push(build_param("NodeKind", "beacon"));
        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_beacon_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_beacon_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        // add 5-minute for ELB creation
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_beacon_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_beacon_nodes_logical_id = Some(v);
                continue;
            }
            if k.eq("NlbArn") {
                aws_resources.cloudformation_asg_nlb_arn = Some(v);
                continue;
            }
            if k.eq("NlbTargetGroupArn") {
                aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                continue;
            }
            if k.eq("NlbDnsName") {
                aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                continue;
            }
        }
        if aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_beacon_nodes_logical_id not found",
            ));
        }
        if aws_resources.cloudformation_asg_nlb_arn.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_arn not found",
            ));
        }
        if aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
            ));
        }
        if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_dns_name not found",
            ));
        }

        let asg_name = aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .clone()
            .unwrap();
        let droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!("\nchmod 400 {}", ec2_key_path);
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            println!(
                "# instance '{}' ({}, {})\nssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}",
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ec2_key_path,
                d.public_ipv4
            );
        }
        println!();

        // wait for beacon nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let target_nodes = spec.machine.beacon_nodes.unwrap();
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &aws_resources.bucket,
                    Some(aws_s3::KeyPath::DiscoverReadyBeaconNodesDir(spec.id.clone()).encode()),
                ))
                .unwrap();
            info!(
                "{} beacon nodes are bootstrapped and ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        let mut nodes: Vec<node::Node> = Vec::new();
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let beacon_node = aws_s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();
            all_nodes.push(beacon_node.clone());
            nodes.push(beacon_node);
        }
        info!("waiting for beacon nodes bootstrap and ready (to be safe)");
        let http_port = spec
            .avalanchego_config
            .http_port
            .unwrap_or(avalanchego::DEFAULT_HTTP_PORT);
        for node in nodes.iter() {
            let mut success = false;
            for _ in 0..7_u8 {
                thread::sleep(Duration::from_secs(5));
                let ret = rt.block_on(get_health(
                    format!("http://{}:{}", node.ip, http_port).as_str(),
                ));
                success = match ret {
                    Ok(res) => res.healthy.is_some() && res.healthy.unwrap(),
                    Err(e) => {
                        warn!("health check failed for {} ({})", node.machine_id, e);
                        false
                    }
                };
                if success {
                    info!("health check success for {}", node.machine_id);
                    break;
                }
            }
            if !success {
                return Err(Error::new(ErrorKind::Other, "health check failed"));
            }
        }

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
    }

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_none()
    {
        thread::sleep(Duration::from_secs(5));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for non-beacon nodes\n"),
            ResetColor
        )?;

        let cloudformation_asg_non_beacon_nodes_yaml =
            Asset::get("cloudformation/asg_ubuntu_amd64.yaml").unwrap();
        let cloudformation_asg_non_beacon_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_non_beacon_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_non_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_non_beacon_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.non_beacon_nodes;

        // we don't create beacon nodes for mainnet nodes
        // so no nlb creation before
        // we create here for non-beacon nodes
        let need_to_create_nlb = aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none();

        // must deep-copy as shared with other node kind
        let mut parameters = asg_parameters.clone();
        parameters.push(build_param("NodeKind", "non-beacon"));
        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));
        if !need_to_create_nlb {
            // already created for beacon nodes
            parameters.push(build_param(
                "NlbTargetGroupArn",
                &aws_resources
                    .cloudformation_asg_nlb_target_group_arn
                    .clone()
                    .unwrap(),
            ));
        }

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_non_beacon_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_non_beacon_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_non_beacon_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_non_beacon_nodes_logical_id = Some(v);
                continue;
            }
            if need_to_create_nlb {
                if k.eq("NlbArn") {
                    aws_resources.cloudformation_asg_nlb_arn = Some(v);
                    continue;
                }
                if k.eq("NlbTargetGroupArn") {
                    aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                    continue;
                }
                if k.eq("NlbDnsName") {
                    aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                    continue;
                }
            }
        }
        if aws_resources
            .cloudformation_asg_non_beacon_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_non_beacon_nodes_logical_id not found",
            ));
        }
        if need_to_create_nlb {
            if aws_resources.cloudformation_asg_nlb_arn.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_arn not found",
                ));
            }
            if aws_resources
                .cloudformation_asg_nlb_target_group_arn
                .is_none()
            {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
            if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        let asg_name = aws_resources
            .cloudformation_asg_non_beacon_nodes_logical_id
            .clone()
            .unwrap();
        let droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();

        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!("\nchmod 400 {}", ec2_key_path);
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            println!(
                "# instance '{}' ({}, {})\nssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}",
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ec2_key_path,
                d.public_ipv4
            );
        }
        println!();

        // wait for non-beacon nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let target_nodes = spec.machine.non_beacon_nodes;
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &aws_resources.bucket,
                    Some(aws_s3::KeyPath::DiscoverReadyNonBeaconNodesDir(spec.id.clone()).encode()),
                ))
                .unwrap();
            info!(
                "{} non-beacon nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        let mut nodes: Vec<node::Node> = Vec::new();
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let non_beacon_node = aws_s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();
            all_nodes.push(non_beacon_node.clone());
            nodes.push(non_beacon_node);
        }
        info!("waiting for non-beacon nodes bootstrap and ready (to be safe)");
        let http_port = spec
            .avalanchego_config
            .http_port
            .unwrap_or(avalanchego::DEFAULT_HTTP_PORT);
        for node in nodes.iter() {
            let mut success = false;
            for _ in 0..7_u8 {
                thread::sleep(Duration::from_secs(5));
                let ret = rt.block_on(get_health(
                    format!("http://{}:{}", node.ip, http_port).as_str(),
                ));
                success = match ret {
                    Ok(res) => res.healthy.is_some() && res.healthy.unwrap(),
                    Err(e) => {
                        warn!("health check failed for {} ({})", node.machine_id, e);
                        false
                    }
                };
                if success {
                    info!("health check success for {}", node.machine_id);
                    break;
                }
            }
            if !success {
                return Err(Error::new(ErrorKind::Other, "health check failed"));
            }
        }

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id).encode(),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: listing all nodes based on S3 keys...\n"),
        ResetColor
    )?;
    for node in all_nodes.iter() {
        println!("{}", node.encode_yaml().unwrap());
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: nodes are ready -- check the following endpoints!\n"),
        ResetColor
    )?;
    let dns_name = aws_resources.cloudformation_asg_nlb_dns_name.unwrap();
    let http_port = spec
        .avalanchego_config
        .http_port
        .unwrap_or(avalanchego::DEFAULT_HTTP_PORT);
    println!("http://{}:{}/ext/metrics", dns_name, http_port);
    println!("http://{}:{}/ext/health", dns_name, http_port);
    let mut uris: Vec<String> = vec![];
    for n in all_nodes.iter() {
        println!("http://{}:{}/ext/metrics", n.ip, http_port);
        println!("http://{}:{}/ext/health", n.ip, http_port);
        uris.push(format!("http://{}:{}", n.ip, http_port))
    }
    println!("URIs: {}", uris.join(","));

    println!();
    info!("apply all success!");
    Ok(())
}

fn run_delete(
    log_level: &str,
    spec_file_path: &str,
    delete_all: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = avalanche_ops::Spec::load(spec_file_path).unwrap();
    let aws_resources = spec.aws_resources.clone().unwrap();

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
        Print(format!("\nLoaded configuration: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

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
    let cw_manager = aws_cloudwatch::Manager::new(&shared_config);

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete ASG for non-beacon nodes\n"),
            ResetColor
        )?;

        let desired_capacity = spec.machine.beacon_nodes.unwrap();
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        let asg_non_beacon_nodes_stack_name =
            aws_resources.cloudformation_asg_non_beacon_nodes.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_non_beacon_nodes_stack_name.as_str()))
            .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            asg_non_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if spec.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete ASG for beacon nodes\n"),
            ResetColor
        )?;

        let desired_capacity = spec.machine.beacon_nodes.unwrap();
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        let asg_beacon_nodes_stack_name = aws_resources.cloudformation_asg_beacon_nodes.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_beacon_nodes_stack_name.as_str()))
            .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            asg_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_some()
        && aws_resources.cloudformation_vpc_security_group_id.is_some()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )?;

        let vpc_stack_name = aws_resources.cloudformation_vpc.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(vpc_stack_name.as_str()))
            .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            vpc_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_stack_name.as_str()))
            .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            ec2_instance_role_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if aws_resources.ec2_key_name.is_some() && aws_resources.ec2_key_path.is_some() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 key pair\n"),
            ResetColor
        )?;

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
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete KMS key\n"),
            ResetColor
        )?;

        let cmk_id = aws_resources.kms_cmk_id.unwrap();
        rt.block_on(kms_manager.schedule_to_delete(cmk_id.as_str()))
            .unwrap();
    }

    if delete_all {
        // deletes the one auto-created by nodes
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: cloudwatch log groups\n"),
            ResetColor
        )?;
        rt.block_on(cw_manager.delete_log_group(&spec.id)).unwrap();

        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 bucket\n"),
            ResetColor
        )?;

        rt.block_on(s3_manager.delete_objects(&aws_resources.bucket, None))
            .unwrap();
        rt.block_on(s3_manager.delete_bucket(&aws_resources.bucket))
            .unwrap();
    }

    println!();
    info!("delete all success!");
    Ok(())
}

fn build_param(k: &str, v: &str) -> Parameter {
    Parameter::builder()
        .parameter_key(k)
        .parameter_value(v)
        .build()
}

fn get_ec2_key_path(spec_file_path: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ec2-access.key", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

async fn get_health(u: &str) -> io::Result<avalanchego::APIHealthReply> {
    info!("checking /ext/health for {}", u);
    let req = http::create_get(u, "ext/health")?;

    // TODO: fix this; avalanchego /ext/health returns 503...
    let buf = match http::read_bytes(req, Duration::from_secs(5), false).await {
        Ok(u) => u,
        Err(e) => return Err(e),
    };

    let resp = match serde_json::from_slice(&buf) {
        Ok(p) => p,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to decode {}", e),
            ));
        }
    };

    Ok(resp)
}
