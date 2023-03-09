use std::{
    fs,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
};

use aws_manager::{self, cloudformation, cloudwatch, ec2, s3, sts};
use aws_sdk_cloudformation::model::StackStatus;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "delete";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Deletes resources based on configuration")
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_CLOUDWATCH_LOG_GROUP")
                .long("delete-cloudwatch-log-group")
                .help("Enables to delete CloudWatch log group")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_S3_OBJECTS")
                .long("delete-s3-objects")
                .help("Enables to delete S3 objects")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_S3_BUCKET")
                .long("delete-s3-bucket")
                .help("Enables delete S3 bucket (use with caution!)")
                .required(false)
                .num_args(0),
        )
}

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

pub async fn execute(
    log_level: &str,
    spec_file_path: &str,
    delete_cloudwatch_log_group: bool,
    delete_s3_objects: bool,
    delete_s3_bucket: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = blizzardup_aws::Spec::load(spec_file_path).expect("failed to load spec");
    let resources = spec.resources.clone().unwrap();

    let shared_config = aws_manager::load_config(Some(resources.region.clone()))
        .await
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    // validate identity
    match resources.identity {
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
            "No, I am not ready to delete resources.",
            "Yes, let's delete resources.",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'delete' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    log::info!("deleting resources...");
    let s3_manager = s3::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    // delete this first since EC2 key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    if resources.ec2_key_name.is_some() && resources.ec2_key_path.is_some() {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = resources.ec2_key_path.unwrap();
        if Path::new(ec2_key_path.as_str()).exists() {
            fs::remove_file(ec2_key_path.as_str()).unwrap();
        }
        ec2_manager
            .delete_key_pair(resources.ec2_key_name.unwrap().as_str())
            .await
            .unwrap();
    }

    // IAM roles can be deleted without being blocked on ASG/VPC
    if resources.cloudformation_ec2_instance_profile_arn.is_some() {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: trigger delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name =
            resources.cloudformation_ec2_instance_role.clone().unwrap();
        cloudformation_manager
            .delete_stack(ec2_instance_role_stack_name.as_str())
            .await
            .unwrap();
    }

    // delete no matter what, in case node provision failed
    sleep(Duration::from_secs(1)).await;

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: triggering delete ASG for blizzard nodes\n"),
        ResetColor
    )?;
    let asg_blizzards_stack_name = resources.cloudformation_asg_blizzards.clone().unwrap();
    cloudformation_manager
        .delete_stack(asg_blizzards_stack_name.as_str())
        .await
        .unwrap();

    sleep(Duration::from_secs(1)).await;

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: confirming delete ASG for blizzard nodes\n"),
        ResetColor
    )?;
    let desired_capacity = spec.machine.nodes;
    let mut wait_secs = 300 + 60 * desired_capacity as u64;
    if wait_secs > MAX_WAIT_SECONDS {
        wait_secs = MAX_WAIT_SECONDS;
    }
    cloudformation_manager
        .poll_stack(
            asg_blizzards_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

    // VPC delete must run after associated EC2 instances are terminated due to dependencies
    if resources.cloudformation_vpc_id.is_some()
        && resources.cloudformation_vpc_security_group_id.is_some()
        && resources.cloudformation_vpc_public_subnet_ids.is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )?;
        let vpc_stack_name = resources.cloudformation_vpc.unwrap();
        cloudformation_manager
            .delete_stack(vpc_stack_name.as_str())
            .await
            .unwrap();
        sleep(Duration::from_secs(10)).await;
        cloudformation_manager
            .poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::DeleteComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
    }

    if resources.cloudformation_ec2_instance_profile_arn.is_some() {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete EC2 instance role\n"),
            ResetColor
        )?;
        let ec2_instance_role_stack_name = resources.cloudformation_ec2_instance_role.unwrap();
        cloudformation_manager
            .poll_stack(
                ec2_instance_role_stack_name.as_str(),
                StackStatus::DeleteComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
    }

    if delete_cloudwatch_log_group {
        // deletes the one auto-created by nodes
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: cloudwatch log groups\n"),
            ResetColor
        )?;
        cw_manager.delete_log_group(&spec.id).await.unwrap();
    }

    if delete_s3_objects {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 objects\n"),
            ResetColor
        )?;
        sleep(Duration::from_secs(5)).await;
        s3_manager
            .delete_objects(&resources.s3_bucket, Some(&spec.id))
            .await
            .unwrap();
    }

    if delete_s3_bucket {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 bucket\n"),
            ResetColor
        )?;
        sleep(Duration::from_secs(5)).await;
        s3_manager
            .delete_bucket(&resources.s3_bucket)
            .await
            .unwrap();
    }

    println!();
    log::info!("delete all success!");
    Ok(())
}
