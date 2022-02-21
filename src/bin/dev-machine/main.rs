use std::{
    fs::{self, File},
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

use avalanche_ops::{
    self, aws, aws_cloudformation, aws_ec2, aws_kms, aws_s3, aws_sts, compress, dev_machine,
    envelope, random,
};

const APP_NAME: &str = "dev-machine";
const SUBCOMMAND_DEFAULT_SPEC: &str = "default-spec";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

fn create_default_spec_command() -> Command<'static> {
    Command::new(SUBCOMMAND_DEFAULT_SPEC)
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
            Arg::new("ARCH")
                .long("arch")
                .short('a')
                .help("Sets the machine architecture")
                .required(true)
                .takes_value(true)
                .possible_value("arm64")
                .allow_invalid_utf8(false)
                .default_value(dev_machine::DEFAULT_ARCH),
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

fn create_apply_command() -> Command<'static> {
    Command::new(SUBCOMMAND_APPLY)
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
                .allow_invalid_utf8(false)
                .default_value("info"),
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

fn create_delete_command() -> Command<'static> {
    Command::new(SUBCOMMAND_DELETE)
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
                .allow_invalid_utf8(false)
                .default_value("info"),
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

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .subcommands(vec![
            create_default_spec_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_SPEC, sub_matches)) => {
            let opt = DefaultSpecOption {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                arch: sub_matches.value_of("ARCH").unwrap().to_string(),
                spec_file_path: sub_matches.value_of("SPEC_FILE_PATH").unwrap().to_string(),
            };
            execute_default_spec(opt).unwrap();
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            execute_apply(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            execute_delete(
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

struct DefaultSpecOption {
    log_level: String,
    arch: String,
    spec_file_path: String,
}

fn execute_default_spec(opt: DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    let spec = dev_machine::Spec::default(&opt.arch).unwrap();
    spec.validate()?;
    spec.sync(&opt.spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", opt.spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    Ok(())
}

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

fn execute_apply(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    #[derive(RustEmbed)]
    #[folder = "cloudformation/dev-machine/"]
    #[prefix = "cloudformation/dev-machine/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = dev_machine::Spec::load(spec_file_path).unwrap();
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
            Some(dev_machine::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc =
            Some(dev_machine::StackName::Vpc(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_asg.is_none() {
        aws_resources.cloudformation_asg =
            Some(dev_machine::StackName::Asg(spec.id.clone()).encode());
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

        let ec2_instance_role_yaml =
            Asset::get("cloudformation/dev-machine/ec2_instance_role.yaml").unwrap();
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
                    .key("KIND")
                    .value("avalanche-ops/dev-machine")
                    .build()])),
                Some(Vec::from([
                    build_param("Id", &spec.id),
                    build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
                    build_param("S3BucketName", &aws_resources.bucket),
                ])),
            ),
        )
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

        let vpc_yaml = Asset::get("cloudformation/dev-machine/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();

        let parameters = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("IngressIpv4Range", "0.0.0.0/0"),
        ]);
        rt.block_on(
            cloudformation_manager.create_stack(
                vpc_stack_name.as_str(),
                None,
                OnFailure::Delete,
                vpc_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("avalanche-ops/dev-machine")
                    .build()])),
                Some(parameters),
            ),
        )
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
    ]);
    if spec.machine.instance_types.is_some() {
        let instance_types = spec.machine.instance_types.clone().unwrap();
        asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
        asg_parameters.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    if spec.machine.machines > 0 && aws_resources.cloudformation_asg_logical_id.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG\n"),
            ResetColor
        )?;

        // TODO: support other platforms
        let cloudformation_asg_yaml =
            Asset::get("cloudformation/dev-machine/asg_arm64_al2.yaml").unwrap();
        let cloudformation_asg_tmpl =
            std::str::from_utf8(cloudformation_asg_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_stack_name = aws_resources.cloudformation_asg.clone().unwrap();

        let desired_capacity = spec.machine.machines;

        // must deep-copy as shared with other machine kind
        let mut parameters = asg_parameters.clone();

        // TODO: remove this... doesn't work for amd64 and other regions
        if aws_resources.region == "us-west-2" && spec.machine.arch == "arm64" {
            // 64-bit Arm with Kernel 5.10
            // "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-arm64-gp2" returns Kernel 4.14
            parameters.push(build_param("ImageId", "ami-021e15f46d293ec60"));
        }
        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        rt.block_on(
            cloudformation_manager.create_stack(
                cloudformation_asg_stack_name.as_str(),
                None,
                OnFailure::Delete,
                cloudformation_asg_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("avalanche-ops/dev-machine")
                    .build()])),
                Some(parameters),
            ),
        )
        .unwrap();

        // add 5-minute for ELB creation
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_stack_name.as_str(),
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
                aws_resources.cloudformation_asg_logical_id = Some(v);
                continue;
            }
        }
        if aws_resources.cloudformation_asg_logical_id.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_logical_id not found",
            ));
        }

        let asg_name = aws_resources.cloudformation_asg_logical_id.clone().unwrap();
        let droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!("\nchmod 400 {}", ec2_key_path);
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // TODO: support other user name?
            println!(
                "# instance '{}' ({}, {})\nssh -o \"StrictHostKeyChecking no\" -i {} ec2-user@{}",
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ec2_key_path,
                d.public_ipv4
            );
        }
        println!();

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            &aws_resources.bucket,
            spec_file_path,
            &aws_s3::KeyPath::ConfigFile(spec.id).encode(),
        ))
        .unwrap();

        info!("waiting for bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }

    println!();
    info!("apply all success!");
    Ok(())
}

fn execute_delete(
    log_level: &str,
    spec_file_path: &str,
    delete_all: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = dev_machine::Spec::load(spec_file_path).unwrap();
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

    // delete this first since EC2 key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
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

    // delete this first since KMS key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
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

    // IAM roles can be deleted without being blocked on ASG/VPC
    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: trigger delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_stack_name.as_str()))
            .unwrap();
    }

    if spec.machine.machines > 0 && aws_resources.cloudformation_asg_logical_id.is_some() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete ASG\n"),
            ResetColor
        )?;

        let asg_stack_name = aws_resources.cloudformation_asg.clone().unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_stack_name.as_str()))
            .unwrap();
    }

    if spec.machine.machines > 0 && aws_resources.cloudformation_asg_logical_id.is_some() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete ASG\n"),
            ResetColor
        )?;

        let asg_stack_name = aws_resources.cloudformation_asg.unwrap();

        let desired_capacity = spec.machine.machines;
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        rt.block_on(cloudformation_manager.poll_stack(
            asg_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    // VPC delete must run after associated EC2 instances are terminated due to dependencies
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
            Print("\n\n\nSTEP: confirming delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
        rt.block_on(cloudformation_manager.poll_stack(
            ec2_instance_role_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if delete_all {
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
