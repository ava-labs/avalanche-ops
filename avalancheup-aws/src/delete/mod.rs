use std::{
    collections::HashMap,
    fs,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
};

use aws_manager::{self, cloudformation, cloudwatch, ec2, kms, s3, sts};
use aws_sdk_cloudformation::model::StackStatus;
use aws_sdk_ec2::model::Filter;
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
        .arg(
            Arg::new("DELETE_EBS_VOLUMES")
                .long("delete-ebs-volumes")
                .help("Enables delete orphaned EBS volumes (use with caution!)")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("DELETE_ELASTIC_IPS")
                .long("delete-elastic-ips")
                .help("Enables delete orphaned elastic IPs (use with caution!)")
                .required(false)
                .num_args(0),
        )
}

pub async fn execute(
    log_level: &str,
    spec_file_path: &str,
    delete_cloudwatch_log_group: bool,
    delete_s3_objects: bool,
    delete_s3_bucket: bool,
    delete_ebs_volumes: bool,
    delete_elastic_ips: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = avalanche_ops::aws::spec::Spec::load(spec_file_path).expect("failed to load spec");

    let shared_config = aws_manager::load_config(Some(spec.resources.region.clone()))
        .await
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    if let Some(identity) = &spec.resources.identity {
        // AWS calls must be made from the same caller
        if !identity.eq(&current_identity) {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "config identity {:?} != currently loaded identity {:?}",
                    identity, current_identity
                ),
            ));
        }
    } else {
        return Err(Error::new(ErrorKind::Other, "unknown identity"));
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
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    // delete this first since EC2 key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: delete EC2 key pair\n"),
        ResetColor
    )?;

    let ec2_key_path = spec.resources.ec2_key_path.clone();
    if Path::new(ec2_key_path.as_str()).exists() {
        fs::remove_file(ec2_key_path.as_str()).unwrap();
    }
    let ec2_key_path_compressed = format!(
        "{}{}",
        ec2_key_path,
        compress_manager::Encoder::Zstd(3).ext()
    );
    if Path::new(ec2_key_path_compressed.as_str()).exists() {
        fs::remove_file(ec2_key_path_compressed.as_str()).unwrap();
    }
    let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
    if Path::new(ec2_key_path_compressed_encrypted.as_str()).exists() {
        fs::remove_file(ec2_key_path_compressed_encrypted.as_str()).unwrap();
    }
    ec2_manager
        .delete_key_pair(&spec.resources.ec2_key_name)
        .await
        .unwrap();

    // delete this first since KMS key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    if spec
        .resources
        .kms_cmk_symmetric_default_encrypt_key
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete KMS key for encryption\n"),
            ResetColor
        )?;

        let k = spec
            .resources
            .kms_cmk_symmetric_default_encrypt_key
            .unwrap();
        kms_manager
            .schedule_to_delete(k.id.as_str(), 7)
            .await
            .unwrap();
    }

    // IAM roles can be deleted without being blocked on ASG/VPC
    if spec
        .resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: trigger delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = spec
            .resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();
        cloudformation_manager
            .delete_stack(ec2_instance_role_stack_name.as_str())
            .await
            .unwrap();
    }

    sleep(Duration::from_secs(1)).await;
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: triggering delete SSM document for restart avalanche node with subnet-evm track\n"),
        ResetColor
    )?;
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm
        .clone()
        .unwrap();
    cloudformation_manager
        .delete_stack(ssm_doc_stack_name.as_str())
        .await
        .unwrap();

    execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete SSM document for restart avalanche node to reload chain config\n"),
            ResetColor
        )?;
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm
        .clone()
        .unwrap();
    cloudformation_manager
        .delete_stack(ssm_doc_stack_name.as_str())
        .await
        .unwrap();

    sleep(Duration::from_secs(1)).await;
    execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete SSM document for restart avalanche node with xsvm track\n"),
            ResetColor
        )?;
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm
        .clone()
        .unwrap();
    cloudformation_manager
        .delete_stack(ssm_doc_stack_name.as_str())
        .await
        .unwrap();

    // delete no matter what, in case node provision failed
    sleep(Duration::from_secs(1)).await;
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: triggering delete ASG for non-anchor nodes\n"),
        ResetColor
    )?;
    if let Some(stack_names) = &spec.resources.cloudformation_asg_non_anchor_nodes {
        for stack_name in stack_names.iter() {
            cloudformation_manager
                .delete_stack(stack_name)
                .await
                .unwrap();
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: triggering delete ASG for anchor nodes\n"),
        ResetColor
    )?;
    if let Some(stack_names) = &spec.resources.cloudformation_asg_anchor_nodes {
        for stack_name in stack_names.iter() {
            cloudformation_manager
                .delete_stack(stack_name)
                .await
                .unwrap();
        }
    }

    // delete no matter what, in case node provision failed
    sleep(Duration::from_secs(1)).await;

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: confirming delete ASG for non-anchor nodes\n"),
        ResetColor
    )?;
    if let Some(stack_names) = &spec.resources.cloudformation_asg_non_anchor_nodes {
        for stack_name in stack_names.iter() {
            cloudformation_manager
                .poll_stack(
                    stack_name,
                    StackStatus::DeleteComplete,
                    Duration::from_secs(600),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: confirming delete ASG for anchor nodes\n"),
        ResetColor
    )?;
    if let Some(stack_names) = spec.resources.cloudformation_asg_anchor_nodes {
        for stack_name in stack_names.iter() {
            cloudformation_manager
                .poll_stack(
                    stack_name,
                    StackStatus::DeleteComplete,
                    Duration::from_secs(600),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();
        }
    }

    // VPC delete must run after associated EC2 instances are terminated due to dependencies
    if spec.resources.cloudformation_vpc_id.is_some()
        && spec
            .resources
            .cloudformation_vpc_security_group_id
            .is_some()
        && spec
            .resources
            .cloudformation_vpc_public_subnet_ids
            .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )?;

        let vpc_stack_name = spec.resources.cloudformation_vpc.unwrap();
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

    if spec
        .resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = spec.resources.cloudformation_ec2_instance_role.unwrap();
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

    if spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete SSM document for node restart subnet track subnet-evm\n"),
            ResetColor
        )?;

        let ssm_doc_stack_name = spec
            .resources
            .cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm
            .unwrap();
        cloudformation_manager
            .poll_stack(
                ssm_doc_stack_name.as_str(),
                StackStatus::DeleteComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
    }

    if spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(
                "\n\n\nSTEP: confirming delete SSM document for node restart subnet track xsvm\n"
            ),
            ResetColor
        )?;

        let ssm_doc_stack_name = spec
            .resources
            .cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm
            .unwrap();
        cloudformation_manager
            .poll_stack(
                ssm_doc_stack_name.as_str(),
                StackStatus::DeleteComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
    }

    if spec
        .resources
        .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm
        .is_some()
    {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(
                "\n\n\nSTEP: confirming delete SSM document for node restart chain configuration subnet-evm\n"
            ),
            ResetColor
        )?;

        let ssm_doc_stack_name = spec
            .resources
            .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm
            .unwrap();
        cloudformation_manager
            .poll_stack(
                ssm_doc_stack_name.as_str(),
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
            .delete_objects(&spec.resources.s3_bucket, Some(&spec.id))
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
            .delete_bucket(&spec.resources.s3_bucket)
            .await
            .unwrap();
    }

    if delete_ebs_volumes {
        sleep(Duration::from_secs(1)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: deleting orphaned EBS volumes\n"),
            ResetColor
        )?;
        // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
        let filters: Vec<Filter> = vec![
            Filter::builder()
                .set_name(Some(String::from("tag:Kind")))
                .set_values(Some(vec![String::from("aws-volume-provisioner")]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("tag:Id")))
                .set_values(Some(vec![spec.id.clone()]))
                .build(),
        ];
        let volumes = ec2_manager.describe_volumes(Some(filters)).await.unwrap();
        log::info!("found {} volumes", volumes.len());
        if !volumes.is_empty() {
            log::info!("deleting {} volumes", volumes.len());
            for v in volumes {
                let volume_id = v.volume_id().unwrap().to_string();
                log::info!("deleting EBS volume '{}'", volume_id);
                ec2_manager
                    .cli
                    .delete_volume()
                    .volume_id(volume_id)
                    .send()
                    .await
                    .unwrap();
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    if delete_elastic_ips {
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: releasing orphaned elastic IPs\n"),
            ResetColor
        )?;
        let eips = ec2_manager
            .describe_eips_by_tags(HashMap::from([(String::from("Id"), spec.id.clone())]))
            .await
            .unwrap();
        log::info!("found {} elastic IP addresses", eips.len());
        for eip_addr in eips.iter() {
            let allocation_id = eip_addr.allocation_id.to_owned().unwrap();

            log::info!("releasing elastic IP via allocation Id {}", allocation_id);

            ec2_manager
                .cli
                .release_address()
                .allocation_id(allocation_id)
                .send()
                .await
                .unwrap();
            sleep(Duration::from_secs(2)).await;
        }
    }

    println!();
    log::info!("delete all success!");
    Ok(())
}
