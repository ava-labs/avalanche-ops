use std::{
    collections::HashMap,
    fs,
    io::{self, stdout},
    path::Path,
};

use aws_manager::{self, cloudformation, cloudwatch, ec2, kms, s3, sts};
use aws_sdk_cloudformation::types::StackStatus;
use aws_sdk_ec2::types::Filter;
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
            Arg::new("OVERRIDE_KEEP_RESOURCES_EXCEPT_ASG_SSM")
                .long("override-keep-resources-except-asg-ssm")
                .help("Ignore --keep-resources-except-asg-ssm option to delete all")
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
    override_keep_resources_except_asg_ssm: bool,
    delete_cloudwatch_log_group: bool,
    delete_s3_objects: bool,
    delete_s3_bucket: bool,
    delete_ebs_volumes: bool,
    delete_elastic_ips: bool,
    skip_prompt: bool,
    profile_name: String,
) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec =
        avalanche_ops::aws::spec::Spec::load(spec_file_path).expect("failed to load spec");

    let shared_config = aws_manager::load_config(
        Some(spec.resource.regions[0].clone()),
        Some(profile_name.clone()),
        Some(Duration::from_secs(30)),
    )
    .await;

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    // validate identity
    if !spec.resource.identity.user_id.is_empty() {
        // AWS calls must be made from the same caller
        if spec.resource.identity.user_id != current_identity.user_id {
            log::warn!(
                "config identity {:?} != currently loaded identity {:?}",
                spec.resource.identity,
                current_identity
            );
        }
    } else {
        spec.resource.identity = current_identity;
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
    let default_s3_manager = s3::Manager::new(&shared_config);

    let mut keep_resources_except_asg_ssm = spec.keep_resources_except_asg_ssm;
    if override_keep_resources_except_asg_ssm {
        // don't keep if override
        keep_resources_except_asg_ssm = false;
    }

    if !keep_resources_except_asg_ssm {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);
            let regional_kms_manager = kms::Manager::new(&regional_shared_config);

            // delete this first since EC2 key delete does not depend on ASG/VPC
            // (mainly to speed up delete operation)
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: delete EC2 key pair in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let ec2_key_path = regional_resource.ec2_key_path.clone();
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
            let ec2_key_path_compressed_encrypted =
                format!("{}.encrypted", ec2_key_path_compressed);
            if Path::new(ec2_key_path_compressed_encrypted.as_str()).exists() {
                fs::remove_file(ec2_key_path_compressed_encrypted.as_str()).unwrap();
            }
            regional_ec2_manager
                .delete_key_pair(&regional_resource.ec2_key_name)
                .await
                .unwrap();

            // delete this first since KMS key delete does not depend on ASG/VPC
            // (mainly to speed up delete operation)
            if regional_resource
                .kms_symmetric_default_encrypt_key
                .is_some()
            {
                sleep(Duration::from_secs(1)).await;

                execute!(
                    stdout(),
                    SetForegroundColor(Color::Red),
                    Print(format!(
                        "\n\n\nSTEP: delete KMS key for encryption in the region '{region}'\n"
                    )),
                    ResetColor
                )?;

                let k = regional_resource
                    .kms_symmetric_default_encrypt_key
                    .clone()
                    .unwrap();
                regional_kms_manager
                    .schedule_to_delete(k.id.as_str(), 7)
                    .await
                    .unwrap();
            }
        }
    } else {
        log::info!("skipping deleting EC2 key pairs and KMS keys");
    }

    if !keep_resources_except_asg_ssm {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_cloudformation_manager =
                cloudformation::Manager::new(&regional_shared_config);

            // IAM roles can be deleted without being blocked on ASG/VPC
            if regional_resource
                .cloudformation_ec2_instance_profile_arn
                .is_some()
            {
                sleep(Duration::from_secs(1)).await;
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Red),
                    Print(format!(
                        "\n\n\nSTEP: trigger delete IAM EC2 instance role in the region '{region}'\n"
                    )),
                    ResetColor
                )?;

                let ec2_instance_role_stack_name = regional_resource
                    .cloudformation_ec2_instance_role
                    .clone()
                    .unwrap();
                regional_cloudformation_manager
                    .delete_stack(ec2_instance_role_stack_name.as_str())
                    .await
                    .unwrap();
            }
        }
    } else {
        log::info!("skipping deleting IAM EC2 instance role");
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;

        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if let Some(ssm_doc_stack_name) = &regional_resource.cloudformation_ssm_install_subnet_chain
        {
            execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!("\n\n\nSTEP: triggering delete SSM document for installing subnet in the region '{region}'\n")),
            ResetColor
        )?;
            regional_cloudformation_manager
                .delete_stack(ssm_doc_stack_name)
                .await
                .unwrap();
        }
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;

        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource
            .cloudformation_asg_dev_machine_logical_id
            .is_some()
        {
            sleep(Duration::from_secs(2)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: triggering delete dev-machine ASG in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let asg_stack_name = regional_resource
                .cloudformation_asg_dev_machine_logical_id
                .clone()
                .unwrap();
            regional_cloudformation_manager
                .delete_stack(&asg_stack_name)
                .await
                .unwrap();
        }

        // delete no matter what, in case node provision failed
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!(
                "\n\n\nSTEP: triggering delete ASG for non-anchor nodes in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if let Some(stack_names) = &regional_resource.cloudformation_asg_non_anchor_nodes {
            let interval = if stack_names.len() > 20 {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(200)
            };
            for stack_name in stack_names.iter() {
                sleep(interval).await;

                regional_cloudformation_manager
                    .delete_stack(stack_name)
                    .await
                    .unwrap();
            }
        }

        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!(
                "\n\n\nSTEP: triggering delete ASG for anchor nodes in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if let Some(stack_names) = &regional_resource.cloudformation_asg_anchor_nodes {
            let interval = if stack_names.len() > 20 {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(200)
            };
            for stack_name in stack_names.iter() {
                sleep(interval).await;

                regional_cloudformation_manager
                    .delete_stack(stack_name)
                    .await
                    .unwrap();
            }
        }
    }

    for (region, rr) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = rr.clone();
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;

        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        // delete no matter what, in case node provision failed
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!(
                "\n\n\nSTEP: confirming delete ASG for non-anchor nodes in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if let Some(stack_names) = &regional_resource.cloudformation_asg_non_anchor_nodes {
            for stack_name in stack_names.iter() {
                regional_cloudformation_manager
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
            Print(format!(
                "\n\n\nSTEP: confirming delete ASG for anchor nodes in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if let Some(stack_names) = &regional_resource.cloudformation_asg_anchor_nodes {
            for stack_name in stack_names {
                regional_cloudformation_manager
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

        // now that all ASG stacks are deleted, reset launch template
        // that was defined in the same CFN template
        log::warn!(
            "resetting '{region}' cloudformation_asg_launch_template_id '{:?}' in the spec file",
            regional_resource.cloudformation_asg_launch_template_id
        );
        regional_resource.cloudformation_asg_launch_template_id = None;
        regional_resource.cloudformation_asg_launch_template_version = None;

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");
    }

    if !keep_resources_except_asg_ssm {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_cloudformation_manager =
                cloudformation::Manager::new(&regional_shared_config);

            // VPC delete must run after associated EC2 instances are terminated due to dependencies
            if regional_resource.cloudformation_vpc_id.is_some()
                && regional_resource
                    .cloudformation_vpc_security_group_id
                    .is_some()
                && regional_resource
                    .cloudformation_vpc_public_subnet_ids
                    .is_some()
            {
                sleep(Duration::from_secs(1)).await;
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Red),
                    Print(format!(
                        "\n\n\nSTEP: deleting VPC in the region '{region}'\n"
                    )),
                    ResetColor
                )?;
                let vpc_stack_name = regional_resource.cloudformation_vpc.clone().unwrap();
                regional_cloudformation_manager
                    .delete_stack(vpc_stack_name.as_str())
                    .await
                    .unwrap();
                sleep(Duration::from_secs(10)).await;
                regional_cloudformation_manager
                    .poll_stack(
                        vpc_stack_name.as_str(),
                        StackStatus::DeleteComplete,
                        Duration::from_secs(500),
                        Duration::from_secs(30),
                    )
                    .await
                    .unwrap();
            }
        }
    } else {
        log::info!("skipping deleting VPC")
    }

    if !keep_resources_except_asg_ssm {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_cloudformation_manager =
                cloudformation::Manager::new(&regional_shared_config);

            if regional_resource
                .cloudformation_ec2_instance_profile_arn
                .is_some()
            {
                sleep(Duration::from_secs(1)).await;
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Red),
                    Print(format!(
                    "\n\n\nSTEP: confirming delete IAM EC2 instance role in the region '{region}'\n"
                )),
                    ResetColor
                )?;

                let ec2_instance_role_stack_name = regional_resource
                    .cloudformation_ec2_instance_role
                    .clone()
                    .unwrap();
                regional_cloudformation_manager
                    .poll_stack(
                        ec2_instance_role_stack_name.as_str(),
                        StackStatus::DeleteComplete,
                        Duration::from_secs(500),
                        Duration::from_secs(30),
                    )
                    .await
                    .unwrap();
            }
        }
    } else {
        log::info!("skipping confirming IAM EC2 instance role deletion")
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;

        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource
            .cloudformation_asg_dev_machine_logical_id
            .is_some()
        {
            sleep(Duration::from_secs(2)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print("\n\n\nSTEP: confirming delete dev-machine ASG\n"),
                ResetColor
            )?;

            let asg_stack_name = regional_resource
                .cloudformation_asg_dev_machine_logical_id
                .clone()
                .unwrap();
            regional_cloudformation_manager
                .poll_stack(
                    asg_stack_name.as_str(),
                    StackStatus::DeleteComplete,
                    Duration::from_secs(300),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();
        }

        if let Some(ssm_doc_stack_name) = &regional_resource.cloudformation_ssm_install_subnet_chain
        {
            sleep(Duration::from_secs(1)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!("\n\n\nSTEP: confirming delete SSM document for installing subnet in the region '{region}'\n")),
                ResetColor
            )?;
            regional_cloudformation_manager
                .poll_stack(
                    ssm_doc_stack_name.as_str(),
                    StackStatus::DeleteComplete,
                    Duration::from_secs(500),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();
        } else {
            log::warn!("regional_resource.cloudformation_ssm_install_subnet_chain not found");
        }
    }

    if delete_cloudwatch_log_group {
        for (region, _) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_cloudwatch_manager = cloudwatch::Manager::new(&regional_shared_config);

            // deletes the one auto-created by nodes
            sleep(Duration::from_secs(1)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: deleting cloudwatch log groups in the region '{region}'\n"
                )),
                ResetColor
            )?;
            regional_cloudwatch_manager
                .delete_log_group(&spec.id)
                .await
                .unwrap();
        }
    }

    if delete_s3_objects {
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!(
                "\n\n\nSTEP: deleting S3 objects in the region '{}'\n",
                spec.resource.regions[0]
            )),
            ResetColor
        )?;
        sleep(Duration::from_secs(5)).await;
        default_s3_manager
            .delete_objects(&spec.resource.s3_bucket, Some(&spec.id))
            .await
            .unwrap();
    }

    if delete_s3_bucket {
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print(format!(
                "\n\n\nSTEP: deleting S3 bucket in the region '{}'\n",
                spec.resource.regions[0]
            )),
            ResetColor
        )?;
        sleep(Duration::from_secs(5)).await;
        default_s3_manager
            .delete_bucket(&spec.resource.s3_bucket)
            .await
            .unwrap();
    }

    if delete_ebs_volumes {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

            if regional_resource
                .cloudformation_asg_dev_machine_logical_id
                .is_some()
            {
                sleep(Duration::from_secs(1)).await;
                execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: deleting orphaned dev-machine EBS volumes in the region '{region}'\n"
                )),
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
                        .set_values(Some(vec![format!("{}-dev-machine", spec.id)]))
                        .build(),
                ];
                let volumes = regional_ec2_manager
                    .describe_volumes(Some(filters))
                    .await
                    .unwrap();
                log::info!("found {} volumes for dev-machine", volumes.len());
                if !volumes.is_empty() {
                    log::info!("deleting {} volumes for dev-machine", volumes.len());
                    for v in volumes {
                        let volume_id = v.volume_id().unwrap().to_string();
                        log::info!("deleting EBS volume '{}'", volume_id);
                        regional_ec2_manager
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

            sleep(Duration::from_secs(1)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: deleting orphaned EBS volumes in the region '{region}'\n"
                )),
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
            let volumes = regional_ec2_manager
                .describe_volumes(Some(filters))
                .await
                .unwrap();
            log::info!("found {} volumes", volumes.len());
            if !volumes.is_empty() {
                log::info!("deleting {} volumes", volumes.len());
                for v in volumes {
                    let volume_id = v.volume_id().unwrap().to_string();
                    log::info!("deleting EBS volume '{}'", volume_id);
                    regional_ec2_manager
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
    }

    if delete_elastic_ips {
        for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
            let regional_shared_config = aws_manager::load_config(
                Some(region.clone()),
                Some(profile_name.clone()),
                Some(Duration::from_secs(30)),
            )
            .await;

            let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

            if regional_resource
                .cloudformation_asg_dev_machine_logical_id
                .is_some()
            {
                sleep(Duration::from_secs(1)).await;
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Red),
                    Print(format!(
                        "\n\n\nSTEP: releasing orphaned dev-machine elastic IPs in the region '{region}'\n"
                    )),
                    ResetColor
                )?;
                let eips = regional_ec2_manager
                    .describe_eips_by_tags(HashMap::from([(
                        String::from("Id"),
                        format!("{}-dev-machine", spec.id),
                    )]))
                    .await
                    .unwrap();
                log::info!("found {} elastic IP addresses for dev machine", eips.len());
                for eip_addr in eips.iter() {
                    let allocation_id = eip_addr.allocation_id.to_owned().unwrap();

                    log::info!("releasing elastic IP via allocation Id {}", allocation_id);

                    regional_ec2_manager
                        .cli
                        .release_address()
                        .allocation_id(allocation_id)
                        .send()
                        .await
                        .unwrap();
                    sleep(Duration::from_secs(2)).await;
                }
            }

            sleep(Duration::from_secs(1)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Red),
                Print(format!(
                    "\n\n\nSTEP: releasing orphaned elastic IPs in the region '{region}'\n"
                )),
                ResetColor
            )?;
            let eips = regional_ec2_manager
                .describe_eips_by_tags(HashMap::from([(String::from("Id"), spec.id.clone())]))
                .await
                .unwrap();
            log::info!("found {} elastic IP addresses", eips.len());
            for eip_addr in eips.iter() {
                let allocation_id = eip_addr.allocation_id.to_owned().unwrap();

                log::info!("releasing elastic IP via allocation Id {}", allocation_id);

                regional_ec2_manager
                    .cli
                    .release_address()
                    .allocation_id(allocation_id)
                    .send()
                    .await
                    .unwrap();
                sleep(Duration::from_secs(2)).await;
            }
        }
    }

    println!();
    log::info!("delete all success!");
    Ok(())
}
