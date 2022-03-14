use std::{
    fs::{self},
    io::{self, stdout, Error, ErrorKind},
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_cloudformation::model::StackStatus;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{
    self,
    aws::{self, cloudformation, ec2, kms, s3, sts},
    dev,
};

pub const NAME: &str = "delete";

pub fn command() -> Command<'static> {
    Command::new(NAME)
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

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

pub fn execute(
    log_level: &str,
    spec_file_path: &str,
    delete_all: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = dev::Spec::load(spec_file_path).unwrap();
    let aws_resources = spec.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
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
    let s3_manager = s3::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);

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
