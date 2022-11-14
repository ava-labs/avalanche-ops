use std::{
    collections::HashMap,
    fs,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
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
use tokio::runtime::Runtime;

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

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

pub fn execute(
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

    let spec = avalancheup_aws::Spec::load(spec_file_path).expect("failed to load spec");

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws_manager::load_config(Some(
            spec.aws_resources.region.clone(),
        )))
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    if let Some(identity) = &spec.aws_resources.identity {
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
            "No, I am not ready to delete resources!",
            "Yes, let's delete resources!",
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
    if spec.aws_resources.ec2_key_name.is_some() && spec.aws_resources.ec2_key_path.is_some() {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = spec.aws_resources.ec2_key_path.unwrap();
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
        rt.block_on(ec2_manager.delete_key_pair(spec.aws_resources.ec2_key_name.unwrap().as_str()))
            .unwrap();
    }

    // delete this first since KMS key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    if spec
        .aws_resources
        .kms_cmk_symmetric_default_encrypt_key
        .is_some()
    {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete KMS key\n"),
            ResetColor
        )?;

        let k = spec
            .aws_resources
            .kms_cmk_symmetric_default_encrypt_key
            .unwrap();
        rt.block_on(kms_manager.schedule_to_delete(k.id.as_str()))
            .unwrap();
    }

    // IAM roles can be deleted without being blocked on ASG/VPC
    if spec
        .aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: trigger delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = spec
            .aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_stack_name.as_str()))
            .unwrap();
    }

    if spec.subnet_evm_genesis.is_some() && spec.avalanchego_config.is_custom_network() {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete SSM document for restart avalanche node with subnet-evm whitelist\n"),
            ResetColor
        )?;

        let ssm_doc_stack_name = spec
            .aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ssm_doc_stack_name.as_str()))
            .unwrap();
    }

    // delete no matter what, in case node provision failed
    thread::sleep(Duration::from_secs(1));

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: triggering delete ASG for non-anchor nodes\n"),
        ResetColor
    )?;
    let asg_non_anchor_nodes_stack_name = spec
        .aws_resources
        .cloudformation_asg_non_anchor_nodes
        .clone()
        .unwrap();
    rt.block_on(cloudformation_manager.delete_stack(asg_non_anchor_nodes_stack_name.as_str()))
        .unwrap();

    if spec.machine.anchor_nodes.unwrap_or(0) > 0 {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete ASG for anchor nodes\n"),
            ResetColor
        )?;
        let asg_anchor_nodes_stack_name = spec
            .aws_resources
            .cloudformation_asg_anchor_nodes
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_anchor_nodes_stack_name.as_str()))
            .unwrap();
    }

    // delete no matter what, in case node provision failed
    thread::sleep(Duration::from_secs(1));

    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\n\nSTEP: confirming delete ASG for non-anchor nodes\n"),
        ResetColor
    )?;
    let desired_capacity = spec.machine.non_anchor_nodes;
    let mut wait_secs = 300 + 60 * desired_capacity as u64;
    if wait_secs > MAX_WAIT_SECONDS {
        wait_secs = MAX_WAIT_SECONDS;
    }
    rt.block_on(cloudformation_manager.poll_stack(
        asg_non_anchor_nodes_stack_name.as_str(),
        StackStatus::DeleteComplete,
        Duration::from_secs(wait_secs),
        Duration::from_secs(30),
    ))
    .unwrap();

    if spec.machine.anchor_nodes.unwrap_or(0) > 0 {
        // delete no matter what, in case node provision failed
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete ASG for anchor nodes\n"),
            ResetColor
        )?;
        let asg_anchor_nodes_stack_name =
            spec.aws_resources.cloudformation_asg_anchor_nodes.unwrap();
        let desired_capacity = spec.machine.anchor_nodes.unwrap();
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        rt.block_on(cloudformation_manager.poll_stack(
            asg_anchor_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    // VPC delete must run after associated EC2 instances are terminated due to dependencies
    if spec.aws_resources.cloudformation_vpc_id.is_some()
        && spec
            .aws_resources
            .cloudformation_vpc_security_group_id
            .is_some()
        && spec
            .aws_resources
            .cloudformation_vpc_public_subnet_ids
            .is_some()
    {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )?;

        let vpc_stack_name = spec.aws_resources.cloudformation_vpc.unwrap();
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

    if spec
        .aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name =
            spec.aws_resources.cloudformation_ec2_instance_role.unwrap();
        rt.block_on(cloudformation_manager.poll_stack(
            ec2_instance_role_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if spec
        .aws_resources
        .cloudformation_ssm_doc_restart_node_whitelist_subnet
        .is_some()
    {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete SSM document for node restart subnet whitelist\n"),
            ResetColor
        )?;

        let ssm_doc_stack_name = spec
            .aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet
            .unwrap();
        rt.block_on(cloudformation_manager.poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if delete_cloudwatch_log_group {
        // deletes the one auto-created by nodes
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: cloudwatch log groups\n"),
            ResetColor
        )?;
        rt.block_on(cw_manager.delete_log_group(&spec.id)).unwrap();
    }

    if delete_s3_objects {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 objects\n"),
            ResetColor
        )?;
        thread::sleep(Duration::from_secs(5));
        rt.block_on(s3_manager.delete_objects(
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Some(Arc::new(spec.id.clone())),
        ))
        .unwrap();
    }

    if delete_s3_bucket {
        thread::sleep(Duration::from_secs(1));

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 bucket\n"),
            ResetColor
        )?;
        thread::sleep(Duration::from_secs(5));
        rt.block_on(s3_manager.delete_bucket(&spec.aws_resources.s3_bucket))
            .unwrap();
    }

    if delete_ebs_volumes {
        thread::sleep(Duration::from_secs(1));

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
        let volumes = rt
            .block_on(ec2_manager.describe_volumes(Some(filters)))
            .unwrap();
        log::info!("found {} volumes", volumes.len());
        if !volumes.is_empty() {
            log::info!("deleting {} volumes", volumes.len());
            let ec2_cli = ec2_manager.client();
            for v in volumes {
                let volume_id = v.volume_id().unwrap().to_string();
                log::info!("deleting EBS volume '{}'", volume_id);
                rt.block_on(ec2_cli.delete_volume().volume_id(volume_id).send())
                    .unwrap();
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    if delete_elastic_ips {
        thread::sleep(Duration::from_secs(1));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: releasing orphaned elastic IPs\n"),
            ResetColor
        )?;
        let eips = rt
            .block_on(
                ec2_manager
                    .describe_eips_by_tags(HashMap::from([(String::from("Id"), spec.id.clone())])),
            )
            .unwrap();
        log::info!("found {} elastic IP addresses", eips.len());
        for eip_addr in eips.iter() {
            let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
            let ec2_cli = ec2_manager.client();

            log::info!("releasing elastic IP via allocation Id {}", allocation_id);
            rt.block_on(
                ec2_cli
                    .release_address()
                    .allocation_id(allocation_id)
                    .send(),
            )
            .unwrap();
            thread::sleep(Duration::from_secs(2));
        }
    }

    println!();
    log::info!("delete all success!");
    Ok(())
}
