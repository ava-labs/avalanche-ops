use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use avalanche_types::{
    ids, jsonrpc::client::health as jsonrpc_client_health,
    jsonrpc::client::info as jsonrpc_client_info, key, units, wallet,
};
use aws_manager::{
    self, cloudformation, ec2,
    kms::{self, envelope},
    s3, sts,
};
use aws_sdk_cloudformation::types::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_ec2::types::Address;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "apply";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Applies/creates resources based on configuration")
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
                .help("The spec file to load and update")
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
}

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

pub async fn execute(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec =
        avalanche_ops::aws::spec::Spec::load(spec_file_path).expect("failed to load spec");
    spec.validate()?;

    let shared_config = aws_manager::load_config(
        Some(spec.resource.regions[0].clone()),
        Some(Duration::from_secs(30)),
    )
    .await;

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    // validate identity
    if let Some(identity) = &spec.resource.identity {
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
        spec.resource.identity = Some(current_identity);
    }

    // set defaults based on ID
    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        if regional_resource.ec2_key_name.is_empty() {
            regional_resource.ec2_key_name = format!("{}-ec2-key", spec.id);
        }
        if regional_resource.cloudformation_ec2_instance_role.is_none() {
            regional_resource.cloudformation_ec2_instance_role = Some(
                avalanche_ops::aws::spec::StackName::Ec2InstanceRole(
                    spec.id.clone(),
                    region.clone(),
                )
                .encode(),
            );
        }
        if regional_resource.cloudformation_vpc.is_none() {
            regional_resource.cloudformation_vpc =
                Some(avalanche_ops::aws::spec::StackName::Vpc(spec.id.clone()).encode());
        }

        let regional_machine = spec.machine.regional_machines.get(region).clone().unwrap();

        // DON'T "spec.regional_resource.cloudformation_asg_anchor_nodes.is_none()"
        // in case we edit anchor node size after default spec generation
        if spec.avalanchego_config.is_custom_network() {
            let anchor_nodes = regional_machine.anchor_nodes.unwrap_or(0);
            let mut asg_names = Vec::new();
            for i in 0..anchor_nodes {
                let asg_name =
                    format!("{}-anchor-{}-{:02}", spec.id, spec.machine.arch_type, i + 1);
                asg_names.push(asg_name);
            }
            regional_resource.cloudformation_asg_anchor_nodes = Some(asg_names);
        }

        // DON'T "spec.regional_resource.cloudformation_asg_non_anchor_nodes.is_none()"
        // in case we edit non-anchor node size after default spec generation
        let non_anchor_nodes = regional_machine.non_anchor_nodes;
        let mut asg_names = Vec::new();
        for i in 0..non_anchor_nodes {
            let asg_name = format!(
                "{}-non-anchor-{}-{:02}",
                spec.id,
                spec.machine.arch_type,
                i + 1
            );
            asg_names.push(asg_name);
        }
        regional_resource.cloudformation_asg_non_anchor_nodes = Some(asg_names);

        // just create these no matter what for simplification
        regional_resource.cloudformation_ssm_install_subnet_chain = Some(
            avalanche_ops::aws::spec::StackName::SsmInstallSubnetChain(spec.id.clone()).encode(),
        );

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
        spec.sync(spec_file_path)?;
    }

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
            "No, I am not ready to create resources.",
            "Yes, let's create resources.",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'apply' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    let exec_path = env::current_exe().expect("unexpected None current_exe");
    let exec_parent_dir = exec_path.parent().expect("unexpected None parent");
    let exec_parent_dir = exec_parent_dir.display().to_string();

    log::info!("creating resources (with spec path {})", spec_file_path);
    let default_s3_manager = s3::Manager::new(&shared_config);

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))
        .expect("failed to register os signal");

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 buckets\n"),
        ResetColor
    )?;
    default_s3_manager
        .create_bucket(&spec.resource.s3_bucket)
        .await
        .unwrap();
    let mut days_to_prefixes = HashMap::new();
    days_to_prefixes.insert(
        3,
        vec![format!("{}/install-subnet-chain/ssm-output-logs", spec.id)],
    );
    default_s3_manager
        .put_bucket_object_expire_configuration(&spec.resource.s3_bucket, days_to_prefixes)
        .await
        .unwrap();

    // set before we update "upload_artifacts"
    let avalanched_download_source = if let Some(v) = &spec.upload_artifacts {
        if v.avalanched_local_bin.is_empty() {
            "github"
        } else {
            "s3"
        }
    } else {
        "github"
    };
    if let Some(v) = &spec.upload_artifacts {
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: upload artifacts to S3 bucket\n"),
            ResetColor
        )?;

        if !v.avalanched_local_bin.is_empty() && Path::new(&v.avalanched_local_bin).exists() {
            // don't compress since we need to download this in user data
            // while instance bootstrapping
            default_s3_manager
                .put_object(
                    &v.avalanched_local_bin,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalanchedAwsBin(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.avalanched_bin");
        } else {
            log::info!(
                "skipping uploading avalanched_bin, will be downloaded on remote machines..."
            );
        }

        if !v.aws_volume_provisioner_local_bin.is_empty()
            && Path::new(&v.aws_volume_provisioner_local_bin).exists()
        {
            // don't compress since we need to download this in user data
            // while instance bootstrapping

            default_s3_manager
                .put_object(
                    &v.aws_volume_provisioner_local_bin,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AwsVolumeProvisionerBin(
                        spec.id.clone(),
                    )
                    .encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.aws_volume_provisioner_bin");
        } else {
            log::info!("skipping uploading aws_volume_provisioner_bin, will be downloaded on remote machines...");
        }

        if !v.aws_ip_provisioner_local_bin.is_empty()
            && Path::new(&v.aws_ip_provisioner_local_bin).exists()
        {
            // don't compress since we need to download this in user data
            // while instance bootstrapping

            default_s3_manager
                .put_object(
                    &v.aws_ip_provisioner_local_bin,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AwsIpProvisionerBin(
                        spec.id.clone(),
                    )
                    .encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.aws_ip_provisioner_bin");
        } else {
            log::info!(
                "skipping uploading aws_ip_provisioner_bin, will be downloaded on remote machines..."
            );
        }

        if !v.avalanche_telemetry_cloudwatch_local_bin.is_empty()
            && Path::new(&v.avalanche_telemetry_cloudwatch_local_bin).exists()
        {
            // don't compress since we need to download this in user data
            // while instance bootstrapping

            default_s3_manager
                .put_object(
                    &v.avalanche_telemetry_cloudwatch_local_bin,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalancheTelemetryCloudwatchBin(
                        spec.id.clone(),
                    )
                    .encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.avalanche_telemetry_cloudwatch_bin");
        } else {
            log::info!(
                "skipping uploading avalanche_telemetry_cloudwatch_bin, will be downloaded on remote machines..."
            );
        }

        if !v.avalanchego_local_bin.is_empty() && Path::new(&v.avalanchego_local_bin).exists() {
            // upload without compression first
            default_s3_manager
                .put_object(
                    &v.avalanchego_local_bin,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalancheGoBin(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object avalanchego_bin");
        } else {
            log::info!(
                "skipping uploading avalanchego_bin, will be downloaded on remote machines..."
            );
        }

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: uploading metrics rules\n"),
            ResetColor
        )?;
        default_s3_manager
            .put_object(
                &v.prometheus_metrics_rules_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::MetricsRules(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        log::info!("done with uploading artifacts, thus reset!");
        spec.upload_artifacts = None;
        spec.sync(spec_file_path)?;

        log::info!("uploading avalancheup spec file...");
        default_s3_manager
            .put_object(
                &spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    } else {
        log::info!("skipping uploading artifacts...");
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;

        let regional_kms_manager = kms::Manager::new(&regional_shared_config);
        if regional_resource
            .kms_symmetric_default_encrypt_key
            .is_none()
        {
            sleep(Duration::from_secs(1)).await;
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: create encryption KMS key in '{region}'\n"
                )),
                ResetColor
            )?;
            let key = regional_kms_manager
                .create_symmetric_default_key(format!("{}-kms-key", spec.id).as_str(), false)
                .await
                .unwrap();

            regional_resource.kms_symmetric_default_encrypt_key =
                Some(avalanche_ops::aws::spec::KmsKey {
                    id: key.id,
                    arn: key.arn,
                });
            spec.sync(spec_file_path)?;
        }

        default_s3_manager
            .put_object(
                &spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        let regional_envelope_manager = envelope::Manager::new(
            &regional_kms_manager,
            regional_resource
                .kms_symmetric_default_encrypt_key
                .clone()
                .unwrap()
                .id,
            "avalanche-ops".to_string(),
        );

        if !Path::new(&regional_resource.ec2_key_path).exists() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!("\n\n\nSTEP: create EC2 key pair in '{region}'\n")),
                ResetColor
            )?;

            let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);
            let ec2_key_path = regional_resource.ec2_key_path.clone();
            regional_ec2_manager
                .create_key_pair(&regional_resource.ec2_key_name, ec2_key_path.as_str())
                .await
                .unwrap();

            let tmp_compressed_path =
                random_manager::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext()))
                    .unwrap();
            compress_manager::pack_file(
                ec2_key_path.as_str(),
                &tmp_compressed_path,
                compress_manager::Encoder::Zstd(3),
            )
            .unwrap();

            let tmp_encrypted_path = random_manager::tmp_path(15, Some(".zstd.encrypted")).unwrap();
            regional_envelope_manager
                .seal_aes_256_file(&tmp_compressed_path, &tmp_encrypted_path)
                .await
                .unwrap();

            default_s3_manager
                .put_object(
                    &tmp_encrypted_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
                        spec.id.clone(),
                    )
                    .encode(),
                )
                .await
                .unwrap();

            default_s3_manager
                .put_object(
                    &spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
        }

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let regional_resource = r.clone();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource
            .cloudformation_ec2_instance_profile_arn
            .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating EC2 instance role in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let ec2_instance_role_tmpl =
                avalanche_ops::aws::artifacts::ec2_instance_role_yaml().unwrap();
            let ec2_instance_role_stack_name = regional_resource
                .cloudformation_ec2_instance_role
                .clone()
                .unwrap();

            let role_params = Vec::from([
                build_param("RoleName", format!("{}-{region}-role", &spec.id).as_str()),
                build_param(
                    "RoleProfileName",
                    format!("{}-{region}-role-profile", &spec.id).as_str(),
                ),
                build_param("Id", &spec.id),
                build_param(
                    "KmsKeyArn",
                    &regional_resource
                        .kms_symmetric_default_encrypt_key
                        .clone()
                        .unwrap()
                        .arn,
                ),
                build_param("S3BucketName", &spec.resource.s3_bucket),
            ]);
            regional_cloudformation_manager
                .create_stack(
                    ec2_instance_role_stack_name.as_str(),
                    Some(vec![Capability::CapabilityNamedIam]),
                    OnFailure::Delete,
                    &ec2_instance_role_tmpl,
                    Some(Vec::from([Tag::builder()
                        .key("KIND")
                        .value("avalanche-ops")
                        .build()])),
                    Some(role_params),
                )
                .await
                .unwrap();
        }
    }
    log::info!("waiting for IAM creation...");
    sleep(Duration::from_secs(10)).await;
    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource
            .cloudformation_ec2_instance_profile_arn
            .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: polling EC2 instance role in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let ec2_instance_role_stack_name = regional_resource
                .cloudformation_ec2_instance_role
                .clone()
                .unwrap();

            let stack = regional_cloudformation_manager
                .poll_stack(
                    ec2_instance_role_stack_name.as_str(),
                    StackStatus::CreateComplete,
                    Duration::from_secs(500),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();

            for o in stack.outputs.unwrap() {
                let k = o.output_key.unwrap();
                let v = o.output_value.unwrap();
                log::info!("stack output key=[{}], value=[{}]", k, v,);
                if k.eq("InstanceProfileArn") {
                    regional_resource.cloudformation_ec2_instance_profile_arn = Some(v)
                }
            }
        }

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                &spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let regional_resource = r.clone();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource.cloudformation_vpc_id.is_none()
            && regional_resource
                .cloudformation_vpc_security_group_id
                .is_none()
            && regional_resource
                .cloudformation_vpc_public_subnet_ids
                .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a VPC in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let vpc_tmpl = avalanche_ops::aws::artifacts::vpc_yaml().unwrap();
            let vpc_stack_name = regional_resource.cloudformation_vpc.clone().unwrap();
            let vpc_params = Vec::from([
                build_param("Id", &spec.id),
                build_param("VpcCidr", "10.0.0.0/16"),
                build_param("PublicSubnetCidr1", "10.0.64.0/19"),
                build_param("PublicSubnetCidr2", "10.0.128.0/19"),
                build_param("PublicSubnetCidr3", "10.0.192.0/19"),
                build_param("SshPortIngressIpv4Range", &spec.resource.ingress_ipv4_cidr),
                build_param("HttpPortIngressIpv4Range", &spec.resource.ingress_ipv4_cidr),
                build_param("StakingPortIngressIpv4Range", "0.0.0.0/0"),
                build_param(
                    "StakingPort",
                    format!("{}", spec.avalanchego_config.staking_port).as_str(),
                ),
                build_param(
                    "HttpPort",
                    format!("{}", spec.avalanchego_config.http_port).as_str(),
                ),
            ]);
            regional_cloudformation_manager
                .create_stack(
                    vpc_stack_name.as_str(),
                    None,
                    OnFailure::Delete,
                    &vpc_tmpl,
                    Some(Vec::from([Tag::builder()
                        .key("KIND")
                        .value("avalanche-ops")
                        .build()])),
                    Some(vpc_params),
                )
                .await
                .expect("failed create_stack for VPC");
        }
    }
    log::info!("waiting for VPC creation...");
    sleep(Duration::from_secs(10)).await;
    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        if regional_resource.cloudformation_vpc_id.is_none()
            && regional_resource
                .cloudformation_vpc_security_group_id
                .is_none()
            && regional_resource
                .cloudformation_vpc_public_subnet_ids
                .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: polling a VPC in the region '{region}'\n"
                )),
                ResetColor
            )?;

            let vpc_stack_name = regional_resource.cloudformation_vpc.clone().unwrap();
            let stack = regional_cloudformation_manager
                .poll_stack(
                    vpc_stack_name.as_str(),
                    StackStatus::CreateComplete,
                    Duration::from_secs(300),
                    Duration::from_secs(30),
                )
                .await
                .expect("failed poll_stack for VPC");

            for o in stack.outputs.unwrap() {
                let k = o.output_key.unwrap();
                let v = o.output_value.unwrap();
                log::info!("stack output key=[{}], value=[{}]", k, v,);
                if k.eq("VpcId") {
                    regional_resource.cloudformation_vpc_id = Some(v);
                    continue;
                }
                if k.eq("SecurityGroupId") {
                    regional_resource.cloudformation_vpc_security_group_id = Some(v);
                    continue;
                }
                if k.eq("PublicSubnetIds") {
                    let splits: Vec<&str> = v.split(',').collect();
                    let mut pub_subnets: Vec<String> = vec![];
                    for s in splits {
                        log::info!("public subnet {}", s);
                        pub_subnets.push(String::from(s));
                    }
                    regional_resource.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
                }
            }
        }

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                &spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    let mut created_nodes: Vec<avalanche_ops::aws::spec::Node> = Vec::new();
    let mut region_to_common_asg_params = HashMap::new();
    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_machine = spec.machine.regional_machines.get(region).clone().unwrap();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        let mut common_asg_params = Vec::from([
            build_param("Id", &spec.id),
            build_param(
                "NetworkId",
                format!("{}", &spec.avalanchego_config.network_id).as_str(),
            ),
            build_param(
                "KmsKeyArn",
                &regional_resource
                    .kms_symmetric_default_encrypt_key
                    .clone()
                    .unwrap()
                    .arn,
            ),
            build_param("AadTag", &spec.aad_tag),
            build_param("S3Region", &spec.resource.regions[0]),
            build_param("S3BucketName", &spec.resource.s3_bucket),
            build_param("Ec2KeyPairName", &regional_resource.ec2_key_name),
            build_param(
                "InstanceProfileArn",
                &regional_resource
                    .cloudformation_ec2_instance_profile_arn
                    .clone()
                    .unwrap(),
            ),
            build_param(
                "SecurityGroupId",
                &regional_resource
                    .cloudformation_vpc_security_group_id
                    .clone()
                    .unwrap(),
            ),
            build_param(
                "NlbVpcId",
                &regional_resource.cloudformation_vpc_id.clone().unwrap(),
            ),
            build_param(
                "NlbHttpPort",
                format!("{}", spec.avalanchego_config.http_port).as_str(),
            ),
            build_param("AsgDesiredCapacity", "1"),
            // for CFN template updates
            // ref. "Temporarily setting autoscaling group MinSize and DesiredCapacity to 2."
            // ref. "Rolling update initiated. Terminating 1 obsolete instance(s) in batches of 1, while keeping at least 1 instance(s) in service."
            build_param("AsgMaxSize", "2"),
            build_param(
                "VolumeSize",
                format!("{}", spec.machine.volume_size_in_gb).as_str(),
            ),
            build_param("ArchType", &spec.machine.arch_type),
            build_param(
                "ImageIdSsmParameter",
                &format!(
                "/aws/service/canonical/ubuntu/server/20.04/stable/current/{}/hvm/ebs-gp2/ami-id",
                spec.machine.arch_type
            ),
            ),
            build_param("RustOsType", &spec.machine.rust_os_type),
            build_param(
                "AvalanchedAwsArgs",
                &format!("agent {}", spec.avalanched_config.to_flags()),
            ),
            build_param("VolumeProvisionerInitialWaitRandomSeconds", "10"),
        ]);

        if let Some(avalanchego_release_tag) = &spec.avalanchego_release_tag {
            common_asg_params.push(build_param(
                "AvalancheGoReleaseTag",
                &avalanchego_release_tag.clone(),
            ));
        }

        if !regional_machine.instance_types.is_empty() {
            let instance_types = regional_machine.instance_types.clone();
            common_asg_params.push(build_param("InstanceTypes", &instance_types.join(",")));
            common_asg_params.push(build_param(
                "InstanceTypesCount",
                format!("{}", instance_types.len()).as_str(),
            ));
        }

        common_asg_params.push(build_param(
            "AvalanchedAwsDownloadSource",
            avalanched_download_source,
        ));

        let is_spot_instance = spec.machine.instance_mode == String::from("spot");
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        common_asg_params.push(build_param(
            "InstanceMode",
            if is_spot_instance {
                "spot"
            } else {
                "on-demand"
            },
        ));
        common_asg_params.push(build_param("IpMode", &spec.machine.ip_mode));
        common_asg_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        if let Some(arn) = &regional_resource.nlb_acm_certificate_arn {
            common_asg_params.push(build_param("NlbAcmCertificateArn", arn));
        };
        if spec.enable_nlb {
            common_asg_params.push(build_param("NlbEnabled", "true"));
        } else {
            common_asg_params.push(build_param("NlbEnabled", "false"));
        }

        region_to_common_asg_params.insert(region.to_string(), common_asg_params.clone());

        let public_subnet_ids = regional_resource
            .cloudformation_vpc_public_subnet_ids
            .clone()
            .unwrap();

        let mut anchor_asg_logical_ids = Vec::new();
        if regional_machine.anchor_nodes.unwrap_or(0) > 0
            && regional_resource
                .cloudformation_asg_anchor_nodes_logical_ids
                .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: create ASG for anchor nodes for network Id {} in the region '{region}'\n",
                    spec.avalanchego_config.network_id
                )),
                ResetColor
            )?;

            let cloudformation_asg_anchor_nodes_tmpl =
                avalanche_ops::aws::artifacts::asg_ubuntu_yaml().unwrap();
            let stack_names = regional_resource
                .cloudformation_asg_anchor_nodes
                .clone()
                .unwrap();

            let regional_anchor_nodes = regional_machine.anchor_nodes.unwrap();

            // must deep-copy as shared with other node kind
            let mut common_asg_params_anchor = common_asg_params.clone();
            common_asg_params_anchor.push(build_param("NodeKind", "anchor"));

            for i in 0..regional_anchor_nodes as usize {
                let mut anchor_asg_params = common_asg_params_anchor.clone();
                anchor_asg_params.push(build_param(
                    "PublicSubnetIds",
                    // since we only launch one node per ASG
                    &public_subnet_ids[random_manager::usize() % public_subnet_ids.len()].clone(),
                ));

                // AutoScalingGroupName: !Join ["-", [!Ref Id, !Ref NodeKind, !Ref ArchType]]
                let anchor_asg_name =
                    format!("{}-anchor-{}-{:02}", spec.id, spec.machine.arch_type, i + 1);
                anchor_asg_params.push(build_param("AsgName", &anchor_asg_name));

                if let Some(asg_launch_template_id) =
                    &regional_resource.cloudformation_asg_launch_template_id
                {
                    // reuse ASG template from previous run
                    anchor_asg_params
                        .push(build_param("AsgLaunchTemplateId", asg_launch_template_id));
                }
                if let Some(asg_launch_template_version) =
                    &regional_resource.cloudformation_asg_launch_template_version
                {
                    // reuse ASG template from previous run
                    anchor_asg_params.push(build_param(
                        "AsgLaunchTemplateVersion",
                        &asg_launch_template_version,
                    ));
                }

                if let Some(arn) = &regional_resource.cloudformation_asg_nlb_target_group_arn {
                    // NLB already created
                    anchor_asg_params.push(build_param("NlbTargetGroupArn", arn));
                }

                // rate limit
                sleep(Duration::from_secs(1)).await;
                regional_cloudformation_manager
                    .create_stack(
                        &stack_names[i],
                        None,
                        OnFailure::Delete,
                        &cloudformation_asg_anchor_nodes_tmpl,
                        Some(Vec::from([Tag::builder()
                            .key("KIND")
                            .value("avalanche-ops")
                            .build()])),
                        Some(anchor_asg_params),
                    )
                    .await
                    .unwrap();

                if i == 0 {
                    // add 5-minute for ELB creation + volume provisioner
                    let mut wait_secs = 800;
                    if wait_secs > MAX_WAIT_SECONDS {
                        wait_secs = MAX_WAIT_SECONDS;
                    }
                    sleep(Duration::from_secs(60)).await;

                    let stack = regional_cloudformation_manager
                        .poll_stack(
                            &stack_names[i],
                            StackStatus::CreateComplete,
                            Duration::from_secs(wait_secs),
                            Duration::from_secs(30),
                        )
                        .await
                        .unwrap();

                    for o in stack.outputs.unwrap() {
                        let k = o.output_key.unwrap();
                        let v = o.output_value.unwrap();
                        log::info!("stack output key=[{}], value=[{}]", k, v,);
                        if k.eq("AsgLogicalId") {
                            anchor_asg_logical_ids.push(v);
                            continue;
                        }
                        if k.eq("NlbArn") {
                            regional_resource.cloudformation_asg_nlb_arn = Some(v);
                            continue;
                        }
                        if k.eq("NlbTargetGroupArn") {
                            regional_resource.cloudformation_asg_nlb_target_group_arn = Some(v);
                            continue;
                        }
                        if k.eq("NlbDnsName") {
                            regional_resource.cloudformation_asg_nlb_dns_name = Some(v);
                            continue;
                        }
                        if k.eq("AsgLaunchTemplateId") {
                            regional_resource.cloudformation_asg_launch_template_id = Some(v);
                            continue;
                        }
                        if k.eq("AsgLaunchTemplateVersion") {
                            regional_resource.cloudformation_asg_launch_template_version = Some(v);
                            continue;
                        }
                    }
                }
            }
            for i in 1..regional_anchor_nodes as usize {
                let mut wait_secs = 800;
                if wait_secs > MAX_WAIT_SECONDS {
                    wait_secs = MAX_WAIT_SECONDS;
                }

                let stack = regional_cloudformation_manager
                    .poll_stack(
                        &stack_names[i],
                        StackStatus::CreateComplete,
                        Duration::from_secs(wait_secs),
                        Duration::from_secs(30),
                    )
                    .await
                    .unwrap();

                for o in stack.outputs.unwrap() {
                    let k = o.output_key.unwrap();
                    let v = o.output_value.unwrap();
                    log::info!("stack output key=[{}], value=[{}]", k, v,);
                    if k.eq("AsgLogicalId") {
                        anchor_asg_logical_ids.push(v);
                        continue;
                    }
                    if k.eq("NlbArn") {
                        regional_resource.cloudformation_asg_nlb_arn = Some(v);
                        continue;
                    }
                    if k.eq("NlbTargetGroupArn") {
                        regional_resource.cloudformation_asg_nlb_target_group_arn = Some(v);
                        continue;
                    }
                    if k.eq("NlbDnsName") {
                        regional_resource.cloudformation_asg_nlb_dns_name = Some(v);
                        continue;
                    }
                    if k.eq("AsgLaunchTemplateId") {
                        regional_resource.cloudformation_asg_launch_template_id = Some(v);
                        continue;
                    }
                    if k.eq("AsgLaunchTemplateVersion") {
                        regional_resource.cloudformation_asg_launch_template_version = Some(v);
                        continue;
                    }
                }
            }
            if anchor_asg_logical_ids.is_empty() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "regional_resource.cloudformation_asg_anchor_nodes_logical_ids not found",
                ));
            }
            anchor_asg_logical_ids.sort();

            regional_resource.cloudformation_asg_anchor_nodes_logical_ids =
                Some(anchor_asg_logical_ids.clone());
            spec.sync(spec_file_path)?;
        }

        if regional_resource.cloudformation_asg_nlb_arn.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "regional_resource.cloudformation_asg_nlb_arn not found",
                ));
            }
        }
        if regional_resource
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "regional_resource.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if regional_resource.cloudformation_asg_nlb_dns_name.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB DNS name...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "regional_resource.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
        spec.sync(spec_file_path)?;
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_machine = spec.machine.regional_machines.get(region).clone().unwrap();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

        if let Some(anchor_asg_logical_ids) =
            &regional_resource.cloudformation_asg_anchor_nodes_logical_ids
        {
            let mut droplets: Vec<ec2::Droplet> = Vec::new();
            let mut eips = Vec::new();
            let mut instance_id_to_public_ip = HashMap::new();
            for anchor_asg_name in anchor_asg_logical_ids.iter() {
                let mut dss: Vec<ec2::Droplet> = Vec::new();
                for _ in 0..20 {
                    // TODO: better retries
                    log::info!("fetching all droplets for anchor-node SSH access");
                    let ds = regional_ec2_manager
                        .list_asg(anchor_asg_name)
                        .await
                        .unwrap();
                    if ds.len() >= 1 {
                        dss = ds;
                        break;
                    }
                    log::info!("retrying fetching all droplets (only got {})", ds.len());
                    sleep(Duration::from_secs(30)).await;
                }
                droplets.extend(dss);

                if spec.machine.ip_mode == String::from("elastic") {
                    log::info!("using elastic IPs... wait more");
                    let mut outs: Vec<Address>;
                    loop {
                        outs = regional_ec2_manager
                            .describe_eips_by_tags(HashMap::from([
                                (String::from("Id"), spec.id.clone()),
                                (
                                    String::from("autoscaling:groupName"),
                                    anchor_asg_name.clone(),
                                ),
                            ]))
                            .await
                            .unwrap();

                        log::info!("got {} EIP addresses", outs.len());

                        let mut ready = true;
                        for eip_addr in outs.iter() {
                            ready = ready && eip_addr.instance_id.is_some();
                        }
                        if ready && outs.len() == 1 {
                            break;
                        }

                        sleep(Duration::from_secs(30)).await;
                    }
                    eips.extend(outs.clone());

                    for eip_addr in outs.iter() {
                        let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
                        let instance_id = eip_addr.instance_id.to_owned().unwrap();
                        let public_ip = eip_addr.public_ip.to_owned().unwrap();
                        log::info!("EIP found {allocation_id} for {instance_id} and {public_ip}");
                        instance_id_to_public_ip.insert(instance_id, public_ip);
                    }
                }
            }

            let f = File::open(&regional_resource.ec2_key_path).unwrap();
            f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();

            println!();
            for d in droplets {
                let (instance_ip, ip_kind) =
                    if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                        (public_ip.clone(), "elastic")
                    } else {
                        (d.public_ipv4.clone(), "ephemeral")
                    };
                // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
                // aws ssm start-session --region [region] --target [instance ID]
                println!(
                    "# change SSH key permission
chmod 400 {}
# instance '{}' ({}, {}) -- IP kind {}
ssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}
# download to local machine
scp -i {} ubuntu@{}:REMOTE_FILE_PATH LOCAL_FILE_PATH
scp -i {} -r ubuntu@{}:REMOTE_DIRECTORY_PATH LOCAL_DIRECTORY_PATH
# upload to remote machine
scp -i {} LOCAL_FILE_PATH ubuntu@{}:REMOTE_FILE_PATH
scp -i {} -r LOCAL_DIRECTORY_PATH ubuntu@{}:REMOTE_DIRECTORY_PATH
# SSM session (requires SSM agent)
aws ssm start-session --region {} --target {}
",
                    regional_resource.ec2_key_path,
                    //
                    d.instance_id,
                    d.instance_state_name,
                    d.availability_zone,
                    ip_kind,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    region,
                    d.instance_id,
                );
            }
            println!();

            // wait for anchor nodes to generate certs and node ID and post to remote storage
            // TODO: set timeouts
            let mut regional_anchor_nodes = Vec::new();
            let total_target_anchor_nodes = spec.machine.total_anchor_nodes.unwrap_or(0);
            let regional_target_anchor_nodes = regional_machine.anchor_nodes.unwrap_or(0);
            loop {
                sleep(Duration::from_secs(30)).await;

                // listing anchor nodes here is safe
                // because we only do this once during network creation
                // and avalanched-aws agent only discovers when there's no existing genesis file!
                // (won't poll the stale members to rewrite genesis file)
                let objects = default_s3_manager
                .list_objects(
                    &spec.resource.s3_bucket,
                    Some(&s3::append_slash(
                        &avalanche_ops::aws::spec::StorageNamespace::DiscoverReadyAnchorNodesDir(
                            spec.id.clone(),
                        )
                        .encode(),
                    )),
                )
                .await
                .unwrap();
                log::info!(
                    "{} anchor nodes are bootstrapped and ready (expecting total {total_target_anchor_nodes} nodes, regional {regional_target_anchor_nodes} nodes)",
                    objects.len()
                );

                regional_anchor_nodes.clear();
                for obj in objects.iter() {
                    let s3_key = obj.key().unwrap();
                    let anchor_node =
                        avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key)
                            .unwrap();

                    if anchor_node.region.eq(region) {
                        regional_anchor_nodes.push(anchor_node);
                    }
                }
                if regional_anchor_nodes.len() as u32 >= regional_target_anchor_nodes {
                    break;
                }

                if term.load(Ordering::Relaxed) {
                    log::warn!("received signal {}", signal_hook::consts::SIGINT);
                    println!();
                    println!("# delete resources");
                    execute!(
                        stdout(),
                        SetForegroundColor(Color::Green),
                        Print(format!(
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-elastic-ips \\\n--spec-file-path {}\n\n",
                            exec_path.display(),
                            spec_file_path
                        )),
                        ResetColor
                    )?;
                    println!();
                };
            }

            for anchor_node in regional_anchor_nodes.iter() {
                created_nodes.push(anchor_node.clone());
            }
            spec.resource.created_nodes = Some(created_nodes.clone());
            spec.sync(spec_file_path)?;

            default_s3_manager
                .put_object(
                    &spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();

            log::info!("waiting for anchor nodes bootstrap and ready (to be safe)");
            sleep(Duration::from_secs(15)).await;
        }
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();
        let regional_machine = spec.machine.regional_machines.get(region).clone().unwrap();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        let common_asg_params = region_to_common_asg_params.get(region).unwrap();

        if regional_resource
            .cloudformation_asg_non_anchor_nodes_logical_ids
            .is_none()
        {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating ASG for non-anchor nodes for network Id {} in the region '{region}'\n",
                    spec.avalanchego_config.network_id
                )),
                ResetColor
            )?;

            let cloudformation_asg_non_anchor_nodes_tmpl =
                avalanche_ops::aws::artifacts::asg_ubuntu_yaml().unwrap();
            let stack_names = regional_resource
                .cloudformation_asg_non_anchor_nodes
                .clone()
                .unwrap();

            let regional_non_anchor_nodes = regional_machine.non_anchor_nodes;

            // must deep-copy as shared with other node kind
            let mut common_asg_params_non_anchor = common_asg_params.clone();
            common_asg_params_non_anchor.push(build_param("NodeKind", "non-anchor"));

            let public_subnet_ids = regional_resource
                .cloudformation_vpc_public_subnet_ids
                .clone()
                .unwrap();

            let mut non_anchor_asg_logical_ids = Vec::new();
            for i in 0..regional_non_anchor_nodes as usize {
                let mut non_anchor_asg_params = common_asg_params_non_anchor.clone();
                non_anchor_asg_params.push(build_param(
                    "PublicSubnetIds",
                    // since we only launch one node per ASG
                    &public_subnet_ids[random_manager::usize() % public_subnet_ids.len()].clone(),
                ));

                // AutoScalingGroupName: !Join ["-", [!Ref Id, !Ref NodeKind, !Ref ArchType]]
                let non_anchor_asg_name = format!(
                    "{}-non-anchor-{}-{:02}",
                    spec.id,
                    spec.machine.arch_type,
                    i + 1
                );
                non_anchor_asg_params.push(build_param("AsgName", &non_anchor_asg_name));

                if let Some(asg_launch_template_id) =
                    &regional_resource.cloudformation_asg_launch_template_id
                {
                    // reuse ASG template from previous run
                    non_anchor_asg_params
                        .push(build_param("AsgLaunchTemplateId", asg_launch_template_id));
                }
                if let Some(asg_launch_template_version) =
                    &regional_resource.cloudformation_asg_launch_template_version
                {
                    // reuse ASG template from previous run
                    non_anchor_asg_params.push(build_param(
                        "AsgLaunchTemplateVersion",
                        &asg_launch_template_version,
                    ));
                }

                if let Some(arn) = &regional_resource.cloudformation_asg_nlb_target_group_arn {
                    // NLB already created
                    non_anchor_asg_params.push(build_param("NlbTargetGroupArn", arn));
                }

                // rate limit
                sleep(Duration::from_secs(1)).await;
                regional_cloudformation_manager
                    .create_stack(
                        &stack_names[i],
                        None,
                        OnFailure::Delete,
                        &cloudformation_asg_non_anchor_nodes_tmpl,
                        Some(Vec::from([Tag::builder()
                            .key("KIND")
                            .value("avalanche-ops")
                            .build()])),
                        Some(non_anchor_asg_params),
                    )
                    .await
                    .unwrap();

                if i == 0 {
                    // add 5-minute for ELB creation + volume provisioner
                    let mut wait_secs = 800;
                    if wait_secs > MAX_WAIT_SECONDS {
                        wait_secs = MAX_WAIT_SECONDS;
                    }
                    sleep(Duration::from_secs(60)).await;

                    let stack = regional_cloudformation_manager
                        .poll_stack(
                            &stack_names[i],
                            StackStatus::CreateComplete,
                            Duration::from_secs(wait_secs),
                            Duration::from_secs(30),
                        )
                        .await
                        .unwrap();

                    for o in stack.outputs.unwrap() {
                        let k = o.output_key.unwrap();
                        let v = o.output_value.unwrap();
                        log::info!("stack output key=[{}], value=[{}]", k, v,);
                        if k.eq("AsgLogicalId") {
                            non_anchor_asg_logical_ids.push(v);
                            continue;
                        }
                        if k.eq("NlbArn") {
                            regional_resource.cloudformation_asg_nlb_arn = Some(v);
                            continue;
                        }
                        if k.eq("NlbTargetGroupArn") {
                            regional_resource.cloudformation_asg_nlb_target_group_arn = Some(v);
                            continue;
                        }
                        if k.eq("NlbDnsName") {
                            regional_resource.cloudformation_asg_nlb_dns_name = Some(v);
                            continue;
                        }
                        if k.eq("AsgLaunchTemplateId") {
                            regional_resource.cloudformation_asg_launch_template_id = Some(v);
                            continue;
                        }
                        if k.eq("AsgLaunchTemplateVersion") {
                            regional_resource.cloudformation_asg_launch_template_version = Some(v);
                            continue;
                        }
                    }
                }
            }
            for i in 1..regional_non_anchor_nodes as usize {
                let mut wait_secs = 800;
                if wait_secs > MAX_WAIT_SECONDS {
                    wait_secs = MAX_WAIT_SECONDS;
                }

                let stack = regional_cloudformation_manager
                    .poll_stack(
                        &stack_names[i],
                        StackStatus::CreateComplete,
                        Duration::from_secs(wait_secs),
                        Duration::from_secs(30),
                    )
                    .await
                    .unwrap();

                for o in stack.outputs.unwrap() {
                    let k = o.output_key.unwrap();
                    let v = o.output_value.unwrap();
                    log::info!("stack output key=[{}], value=[{}]", k, v,);
                    if k.eq("AsgLogicalId") {
                        non_anchor_asg_logical_ids.push(v);
                        continue;
                    }
                    if k.eq("NlbArn") {
                        regional_resource.cloudformation_asg_nlb_arn = Some(v);
                        continue;
                    }
                    if k.eq("NlbTargetGroupArn") {
                        regional_resource.cloudformation_asg_nlb_target_group_arn = Some(v);
                        continue;
                    }
                    if k.eq("NlbDnsName") {
                        regional_resource.cloudformation_asg_nlb_dns_name = Some(v);
                        continue;
                    }
                    if k.eq("AsgLaunchTemplateId") {
                        regional_resource.cloudformation_asg_launch_template_id = Some(v);
                        continue;
                    }
                    if k.eq("AsgLaunchTemplateVersion") {
                        regional_resource.cloudformation_asg_launch_template_version = Some(v);
                        continue;
                    }
                }
            }
            if non_anchor_asg_logical_ids.is_empty() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "regional_resource.cloudformation_asg_non_anchor_nodes_logical_ids not found",
                ));
            }
            non_anchor_asg_logical_ids.sort();

            regional_resource.cloudformation_asg_non_anchor_nodes_logical_ids =
                Some(non_anchor_asg_logical_ids.clone());
            spec.sync(spec_file_path)?;

            if regional_resource.cloudformation_asg_nlb_arn.is_none() {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "regional_resource.cloudformation_asg_nlb_arn not found",
                    ));
                }
            }
            if regional_resource
                .cloudformation_asg_nlb_target_group_arn
                .is_none()
            {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB target group ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "regional_resource.cloudformation_asg_nlb_target_group_arn not found",
                    ));
                }
            }
            if regional_resource.cloudformation_asg_nlb_dns_name.is_none() {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB DNS name...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "regional_resource.cloudformation_asg_nlb_dns_name not found",
                    ));
                }
            }
        }

        spec.resource
            .regional_resources
            .insert(region.clone(), regional_resource);
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_machine = spec.machine.regional_machines.get(region).clone().unwrap();

        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

        if let Some(non_anchor_asg_logical_ids) =
            &regional_resource.cloudformation_asg_non_anchor_nodes_logical_ids
        {
            let mut droplets: Vec<ec2::Droplet> = Vec::new();
            let mut eips = Vec::new();
            let mut instance_id_to_public_ip = HashMap::new();
            for non_anchor_asg_name in non_anchor_asg_logical_ids {
                let mut dss = Vec::new();
                for _ in 0..20 {
                    // TODO: better retries
                    log::info!("fetching all droplets for non-anchor-node SSH access");
                    let ds = regional_ec2_manager
                        .list_asg(non_anchor_asg_name)
                        .await
                        .unwrap();
                    if ds.len() >= 1 {
                        dss = ds;
                        break;
                    }
                    log::info!("retrying fetching all droplets (only got {})", ds.len());
                    sleep(Duration::from_secs(30)).await;
                }
                droplets.extend(dss);

                if spec.machine.ip_mode == String::from("elastic") {
                    log::info!("using elastic IPs... wait more");
                    let mut outs: Vec<Address>;
                    loop {
                        outs = regional_ec2_manager
                            .describe_eips_by_tags(HashMap::from([
                                (String::from("Id"), spec.id.clone()),
                                (
                                    String::from("autoscaling:groupName"),
                                    non_anchor_asg_name.clone(),
                                ),
                            ]))
                            .await
                            .unwrap();

                        log::info!("got {} EIP addresses", outs.len());

                        let mut ready = true;
                        for eip_addr in outs.iter() {
                            ready = ready && eip_addr.instance_id.is_some();
                        }
                        if ready && outs.len() == 1 {
                            break;
                        }

                        sleep(Duration::from_secs(30)).await;
                    }
                    eips.extend(outs.clone());

                    for eip_addr in outs.iter() {
                        let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
                        let instance_id = eip_addr.instance_id.to_owned().unwrap();
                        let public_ip = eip_addr.public_ip.to_owned().unwrap();
                        log::info!("EIP found {allocation_id} for {instance_id} and {public_ip}");
                        instance_id_to_public_ip.insert(instance_id, public_ip);
                    }
                }
            }

            println!();
            let f = File::open(&regional_resource.ec2_key_path).unwrap();
            f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
            for d in droplets {
                let (instance_ip, ip_kind) =
                    if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                        (public_ip.clone(), "elastic")
                    } else {
                        (d.public_ipv4.clone(), "ephemeral")
                    };
                // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
                // aws ssm start-session --region [region] --target [instance ID]
                println!(
                    "# change SSH key permission
chmod 400 {}
# instance '{}' ({}, {}) -- IP kind {}
ssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}
# download to local machine
scp -i {} ubuntu@{}:REMOTE_FILE_PATH LOCAL_FILE_PATH
scp -i {} -r ubuntu@{}:REMOTE_DIRECTORY_PATH LOCAL_DIRECTORY_PATH
# upload to remote machine
scp -i {} LOCAL_FILE_PATH ubuntu@{}:REMOTE_FILE_PATH
scp -i {} -r LOCAL_DIRECTORY_PATH ubuntu@{}:REMOTE_DIRECTORY_PATH
# SSM session (requires SSM agent)
aws ssm start-session --region {} --target {}
",
                    regional_resource.ec2_key_path,
                    //
                    d.instance_id,
                    d.instance_state_name,
                    d.availability_zone,
                    ip_kind,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.ec2_key_path,
                    instance_ip,
                    //
                    regional_resource.region,
                    d.instance_id,
                );
            }
            println!();

            // wait for non anchor nodes to generate certs and node ID and post to remote storage
            // TODO: set timeouts
            let mut regional_non_anchor_nodes = Vec::new();
            let total_target_non_anchor_nodes = spec.machine.total_non_anchor_nodes;
            let regional_target_non_anchor_nodes = regional_machine.non_anchor_nodes;
            loop {
                sleep(Duration::from_secs(30)).await;

                let objects = default_s3_manager
                .list_objects(
                    &spec.resource.s3_bucket,
                    Some(&s3::append_slash(
                        &avalanche_ops::aws::spec::StorageNamespace::DiscoverReadyNonAnchorNodesDir(
                            spec.id.clone(),
                        )
                        .encode(),
                    )),
                )
                .await
                .unwrap();
                log::info!(
                    "{} non-anchor nodes are bootstrapped and ready (expecting total {total_target_non_anchor_nodes} nodes, regional {regional_target_non_anchor_nodes} nodes)",
                    objects.len()
                );

                regional_non_anchor_nodes.clear();
                for obj in objects.iter() {
                    let s3_key = obj.key().unwrap();
                    let non_anchor_node =
                        avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key)
                            .unwrap();

                    if non_anchor_node.region.eq(region) {
                        regional_non_anchor_nodes.push(non_anchor_node);
                    }
                }
                if regional_non_anchor_nodes.len() as u32 >= regional_target_non_anchor_nodes {
                    break;
                }

                if term.load(Ordering::Relaxed) {
                    log::warn!("received signal {}", signal_hook::consts::SIGINT);
                    println!();
                    println!("# delete resources");
                    execute!(
                        stdout(),
                        SetForegroundColor(Color::Green),
                        Print(format!(
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-elastic-ips \\\n--spec-file-path {}\n\n",
                            exec_path.display(),
                            spec_file_path
                        )),
                        ResetColor
                    )?;
                    println!();
                };
            }

            for non_anchor_node in regional_non_anchor_nodes.iter() {
                created_nodes.push(non_anchor_node.clone());
            }
            spec.resource.created_nodes = Some(created_nodes.clone());
            spec.sync(spec_file_path)?;
            default_s3_manager
                .put_object(
                    &spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object ConfigFile");

            log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
            sleep(Duration::from_secs(20)).await;
        }
    }

    spec.resource.created_nodes = Some(created_nodes.clone());
    spec.sync(spec_file_path)?;
    default_s3_manager
        .put_object(
            &spec_file_path,
            &spec.resource.s3_bucket,
            &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
        )
        .await
        .expect("failed put_object ConfigFile");

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: showing all node objects based on S3 keys for all regions...\n\n"),
        ResetColor
    )?;
    for node in created_nodes.iter() {
        println!("{}", node.encode_yaml().unwrap());
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: nodes are ready -- check the following endpoints for all regions!\n\n"),
        ResetColor
    )?;
    let mut rpc_hosts = Vec::new();
    let mut rpc_host_to_node = HashMap::new();
    let mut nlb_https_enabled = false;
    for (_, regional_resource) in spec.resource.regional_resources.clone().iter() {
        nlb_https_enabled = regional_resource.nlb_acm_certificate_arn.is_some();

        if let Some(dns_name) = &regional_resource.cloudformation_asg_nlb_dns_name {
            rpc_hosts.push(dns_name.clone());
        }
    }
    for node in created_nodes.iter() {
        rpc_host_to_node.insert(node.public_ip.clone(), node.clone());
        rpc_hosts.push(node.public_ip.clone())
    }
    let http_port: u32 = spec.avalanchego_config.http_port;
    let https_enabled = spec.avalanchego_config.http_tls_enabled.is_some()
        && spec.avalanchego_config.http_tls_enabled.unwrap();
    let (scheme_for_dns, port_for_dns) = {
        if nlb_https_enabled || https_enabled {
            ("https", 443)
        } else {
            ("http", http_port)
        }
    };
    // TODO: check "/ext/info"
    // TODO: check "/ext/bc/C/rpc"
    // TODO: subnet-evm endpoint with "/ext/bc/[BLOCKCHAIN TX ID]/rpc"
    // ref. https://github.com/ava-labs/subnet-evm/blob/505f03904736ee9f8de7b862c06d0ae18062cc80/runner/main.go#L671
    //
    // NOTE: metamask endpoints will be "http://[NLB_DNS]:9650/ext/bc/[CHAIN ID]/rpc"
    // NOTE: metamask endpoints will be "http://[NLB_DNS]:9650/ext/bc/C/rpc"
    // NOTE: metamask chain ID is "43112" as in coreth "DEFAULT_GENESIS"
    let mut all_nodes_http_rpcs = Vec::new();
    let mut all_nodes_c_chain_rpc_urls = Vec::new();
    for host in rpc_hosts.iter() {
        let http_rpc = format!("{scheme_for_dns}://{host}:{port_for_dns}").to_string();

        let mut success = false;
        for _ in 0..3_u8 {
            let ret = jsonrpc_client_info::get_node_id(&http_rpc).await;
            match ret {
                Ok(res) => {
                    log::info!(
                        "get node id response for {http_rpc}: {}",
                        serde_json::to_string_pretty(&res).unwrap()
                    );
                }
                Err(e) => {
                    log::warn!(
                        "get node id check failed for {} ({:?}, could be IP range not allowed)",
                        http_rpc,
                        e
                    );
                }
            };

            let ret = jsonrpc_client_health::check(Arc::new(http_rpc.clone()), true).await;
            match ret {
                Ok(res) => {
                    if res.healthy {
                        success = true;
                        log::info!("health/liveness check success for {}", http_rpc);
                        break;
                    }
                }
                Err(e) => {
                    log::warn!(
                        "health/liveness check failed for {} ({:?}, could be IP range not allowed)",
                        http_rpc,
                        e
                    );
                }
            };

            sleep(Duration::from_secs(5)).await;
        }
        if !success {
            log::warn!(
                "health/liveness check failed on {} for network id {} (could be IP range not allowed)",
                http_rpc,
                &spec.avalanchego_config.network_id
            );
        }

        let mut endpoints = avalanche_ops::aws::spec::Endpoints::default();
        endpoints.http_rpc = Some(http_rpc.clone());
        endpoints.http_rpc_x = Some(format!("{http_rpc}/ext/bc/X"));
        endpoints.http_rpc_p = Some(format!("{http_rpc}/ext/bc/P"));
        endpoints.http_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.metrics = Some(format!("{http_rpc}/ext/metrics"));
        endpoints.health = Some(format!("{http_rpc}/ext/health"));
        endpoints.liveness = Some(format!("{http_rpc}/ext/health/liveness"));
        endpoints.metamask_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.websocket_rpc_c = Some(format!("ws://{host}:{port_for_dns}/ext/bc/C/ws"));
        println!("{}", endpoints.encode_yaml().unwrap());

        all_nodes_http_rpcs.push(http_rpc.clone());
        all_nodes_c_chain_rpc_urls.push(format!("{http_rpc}/ext/bc/C/rpc"));
    }
    println!("\nall nodes HTTP RPCs: {}", all_nodes_http_rpcs.join(","));

    let mut all_node_ids = Vec::new();
    let mut all_instance_ids = Vec::new();
    let mut node_id_to_region_machine_id = HashMap::new();
    for node in created_nodes.iter() {
        let node_id = node.node_id.clone();
        let instance_id = node.machine_id.clone();

        all_node_ids.push(node_id.clone());
        all_instance_ids.push(instance_id.clone());

        node_id_to_region_machine_id.insert(
            node_id,
            avalanche_ops::aws::spec::RegionMachineId {
                region: node.region.clone(),
                machine_id: instance_id,
            },
        );
    }

    //
    //
    //
    //
    //
    println!();
    log::info!(
        "apply all success with node Ids {:?} and instance Ids {:?}",
        all_node_ids,
        all_instance_ids
    );

    println!();
    println!("# delete resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{} delete \\
--delete-cloudwatch-log-group \\
--delete-s3-objects \\
--delete-ebs-volumes \\
--delete-elastic-ips \\
--spec-file-path {}

",
            exec_path.display(),
            spec_file_path
        )),
        ResetColor
    )?;

    //
    //
    //
    //
    //
    println!();
    println!("# download the generated certificates");
    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!(
                "aws --region {} s3 ls s3://{}/{}/pki/ --human-readable\n",
                region, spec.resource.s3_bucket, spec.id
            )),
            ResetColor
        )?;
        let kms_key_id = regional_resource
            .kms_symmetric_default_encrypt_key
            .clone()
            .unwrap()
            .id;
        for n in created_nodes.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "
{exec_parent_dir}/staking-key-cert-s3-downloader \\
--log-level=info \\
--s3-region={s3_region} \\
--s3-bucket={s3_buckeet} \\
--s3-key-tls-key={id}/pki/{node_id}.key.zstd.encrypted \\
--s3-key-tls-cert={id}/pki/{node_id}.crt.zstd.encrypted \\
--kms-region={kms_region} \\
--kms-key-id={kms_key_id} \\
--aad-tag='{aad_tag}' \\
--tls-key-path=/tmp/{node_id}.key \\
--tls-cert-path=/tmp/{node_id}.crt

cat /tmp/{node_id}.crt

{exec_parent_dir}/staking-signer-key-s3-downloader \\
--log-level=info \\
--s3-region={s3_region} \\
--s3-bucket={s3_buckeet} \\
--s3-key={id}/staking-signer-keys/{node_id}.staking-signer.bls.key.zstd.encrypted \\
--kms-region={kms_region} \\
--kms-key-id={kms_key_id} \\
--aad-tag='{aad_tag}' \\
--key-path=/tmp/{node_id}.bls.key

",
                    exec_parent_dir = exec_parent_dir,
                    s3_region = spec.resource.regions[0],
                    s3_buckeet = spec.resource.s3_bucket,
                    id = spec.id,
                    kms_region = region,
                    kms_key_id = kms_key_id,
                    aad_tag = spec.aad_tag,
                    node_id = n.node_id,
                )),
                ResetColor
            )?;
        }
    }

    //
    //
    //
    //
    //
    let mut region_to_ssm_doc_name = HashMap::new();
    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!("\n\n\nSTEP: creating an SSM document for installing subnet in the region '{region}'\n\n")),
            ResetColor
        )?;
        let ssm_doc_tmpl = avalanche_ops::aws::artifacts::ssm_install_subnet_chain_yaml().unwrap();
        let ssm_doc_stack_name = regional_resource
            .cloudformation_ssm_install_subnet_chain
            .clone()
            .unwrap();
        let ssm_install_subnet_chain_doc_name =
            avalanche_ops::aws::spec::StackName::SsmInstallSubnetChain(spec.id.clone()).encode();
        region_to_ssm_doc_name.insert(
            region.to_string(),
            ssm_install_subnet_chain_doc_name.clone(),
        );

        let cfn_params = Vec::from([build_param(
            "DocumentName",
            &ssm_install_subnet_chain_doc_name,
        )]);
        regional_cloudformation_manager
            .create_stack(
                ssm_doc_stack_name.as_str(),
                Some(vec![Capability::CapabilityNamedIam]),
                OnFailure::Delete,
                &ssm_doc_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("avalanche-ops")
                    .build()])),
                Some(cfn_params),
            )
            .await
            .unwrap();
    }
    log::info!("waiting for SSM creation...");
    sleep(Duration::from_secs(10)).await;
    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config =
            aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30))).await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!("\n\n\nSTEP: polling an SSM document for installing subnet in the region '{region}'\n\n")),
            ResetColor
        )?;
        let ssm_doc_stack_name = regional_resource
            .cloudformation_ssm_install_subnet_chain
            .clone()
            .unwrap();
        regional_cloudformation_manager
            .poll_stack(
                ssm_doc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        log::info!("created ssm document for installing subnet in the region '{region}'");
    }

    // TODO: support Fuji
    if spec.avalanchego_config.is_custom_network() {
        let ki = spec.prefunded_keys.clone().unwrap()[0].clone();
        let priv_key =
            key::secp256k1::private_key::Key::from_cb58(ki.private_key_cb58.clone().unwrap())
                .unwrap();

        let wallet_to_spend = wallet::Builder::new(&priv_key)
            .base_http_urls(all_nodes_http_rpcs.clone())
            .build()
            .await
            .unwrap();
        let balance = wallet_to_spend.p().balance().await.unwrap();
        log::info!(
            "adding primary network validators with the wallet {} of balance {} nAVAX ({} AVAX)",
            ki.eth_address,
            balance,
            units::cast_xp_navax_to_avax(primitive_types::U256::from(balance))
        );

        // add nodes as validators for the primary network
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: adding all nodes as primary network validators...\n\n"),
            ResetColor
        )?;
        log::info!("adding all nodes as primary network permissionless validator");
        let mut handles = Vec::new();
        for (i, node) in created_nodes.iter().enumerate() {
            // randomly wait to prevent UTXO double spends from the same wallet
            let initial_wait_sec = if i == 0 {
                0
            } else {
                if created_nodes.len() > 50 {
                    2 + i as u64
                } else {
                    1 + i as u64
                }
            };
            let random_wait = Duration::from_secs(initial_wait_sec)
                .checked_add(Duration::from_millis(500 + random_manager::u64() % 100))
                .unwrap();

            handles.push(tokio::spawn(add_primary_network_permissionless_validator(
                Arc::new(random_wait),
                Arc::new(wallet_to_spend.clone()),
                Arc::new(ids::node::Id::from_str(&node.node_id).unwrap()),
                Arc::new(node.proof_of_possession.to_owned()),
                Arc::new(2 * units::KILO_AVAX),
                Arc::new(spec.primary_network_validate_period_in_days),
            )));
        }
        log::info!("STEP: blocking on add_permissionless_validator handles via JoinHandle");
        for handle in handles {
            match handle.await {
                Ok(_) => {}
                Err(e) => {
                    log::warn!("failed add_permissionless_validator with {} -- please try again with 'add-primary-network-validators' command",e)
                }
            }
        }
    }

    //
    //
    //
    //
    //
    println!("\n# EXAMPLE: write subnet config");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "# 250000000 ns == 0.25 s
# 1000000000 ns == 1.00 s
{exec_path} subnet-config \\
--log-level=info \\
--proposer-min-block-delay 1000000000 \\
--file-path /tmp/subnet-config.json
",
            exec_path = exec_path.display(),
        )),
        ResetColor
    )?;

    println!("\n# EXAMPLE: write subnet-evm chain config");
    let priority_regossip_addresses_flag = if let Some(keys) = &spec.prefunded_keys {
        let mut ss = Vec::new();
        for k in keys.iter() {
            ss.push(k.eth_address.clone());
        }
        format!(" --priority-regossip-addresses {}", ss.join(","))
    } else {
        String::new()
    };
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{exec_path} subnet-evm chain-config \\
--log-level=info \\
--tx-pool-account-slots 1000000 \\
--tx-pool-global-slots 10000000000 \\
--tx-pool-account-queue 300000 \\
--tx-pool-global-queue 10000000 \\
--local-txs-enabled \\
--priority-regossip-frequency 30000000000 \\
--priority-regossip-max-txs 1000 \\
--priority-regossip-txs-per-address 100{priority_regossip_addresses_flag} \\
--file-path /tmp/subnet-evm-chain-config.json
",
            exec_path = exec_path.display(),
            priority_regossip_addresses_flag = priority_regossip_addresses_flag,
        )),
        ResetColor
    )?;

    println!("\n# EXAMPLE: write subnet-evm genesis");
    let seed_eth_addresses = if let Some(keys) = &spec.prefunded_keys {
        let mut addresses = Vec::new();
        for k in keys.iter() {
            addresses.push(k.eth_address.clone());
        }
        addresses.join(",")
    } else {
        let mut addresses = Vec::new();
        for i in 0..5 {
            let eth_addr = if i < key::secp256k1::TEST_KEYS.len() {
                key::secp256k1::TEST_KEYS[i]
                    .to_public_key()
                    .to_eth_address()
            } else {
                let k = key::secp256k1::private_key::Key::generate().unwrap();
                k.to_public_key().to_eth_address()
            };
            addresses.push(eth_addr);
        }
        addresses.join(",")
    };
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{exec_path} subnet-evm genesis \\
--log-level=info \\
--seed-eth-addresses {seed_eth_addresses} \\
--gas-limit 300000000 \\
--target-block-rate 1 \\
--min-base-fee 10000000 \\
--target-gas 999999999999999999 \\
--base-fee-change-denominator 4800000 \\
--min-block-gas-cost 0 \\
--max-block-gas-cost 10000000 \\
--block-gas-cost-step 500000 \\
--file-path /tmp/subnet-evm-genesis.json
",
            exec_path = exec_path.display(),
            seed_eth_addresses = seed_eth_addresses,
        )),
        ResetColor
    )?;

    println!(
        "\n# EXAMPLE: ONLY add nodes as primary network validators WITHOUT subnet installation"
    );
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{exec_path} add-primary-network-validators \\
--log-level info \\
--chain-rpc-url {chain_rpc_url} \\
--key {priv_key_hex} \\
--primary-network-validate-period-in-days 16 \\
--staking-amount-in-avax 2000 \\
--spec-file-path {spec_file_path}

# or
# --target-node-ids '{target_node_ids}'

",
            exec_path = exec_path.display(),
            chain_rpc_url =
                format!("{}://{}:{}", scheme_for_dns, rpc_hosts[0], port_for_dns).to_string(),
            priv_key_hex = key::secp256k1::TEST_KEYS[0].to_hex(),
            spec_file_path = spec_file_path,
            target_node_ids = all_node_ids.join(","),
        )),
        ResetColor
    )?;

    println!("\n# EXAMPLE: install subnet-evm in all nodes (including adding all nodes as primary network validators, works for any VM)");
    let region_to_ssm_doc_name = serde_json::to_string(&region_to_ssm_doc_name).unwrap();
    let node_id_to_region_machine_id =
        serde_json::to_string(&node_id_to_region_machine_id).unwrap();
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{exec_path} install-subnet-chain \\
--log-level info \\
--s3-region {s3_region} \\
--s3-bucket {s3_bucket} \\
--s3-key-prefix {id}/install-subnet-chain \\
--chain-rpc-url {chain_rpc_url} \\
--key {priv_key_hex} \\
--primary-network-validate-period-in-days 16 \\
--subnet-validate-period-in-days 14 \\
--subnet-config-local-path /tmp/subnet-config.json \\
--subnet-config-remote-dir {subnet_config_remote_dir} \\
--vm-binary-local-path REPLACE_ME \\
--vm-binary-remote-dir {vm_plugin_remote_dir} \\
--chain-name subnetevm \\
--chain-genesis-path /tmp/subnet-evm-genesis.json \\
--chain-config-local-path /tmp/subnet-evm-chain-config.json \\
--chain-config-remote-dir {chain_config_remote_dir} \\
--avalanchego-config-remote-path {avalanchego_config_remote_path} \\
--staking-amount-in-avax 2000 \\
--ssm-docs '{region_to_ssm_doc_name}' \\
--target-nodes '{node_id_to_region_machine_id}'

# or use to add all nodes as subnet validators
# --spec-file-path {spec_file_path}
",
            exec_path = exec_path.display(),
            s3_region = spec.resource.regions[0],
            s3_bucket = spec.resource.s3_bucket,
            chain_rpc_url =
                format!("{}://{}:{}", scheme_for_dns, rpc_hosts[0], port_for_dns).to_string(),
            priv_key_hex = key::secp256k1::TEST_KEYS[0].to_hex(),
            id = spec.id,
            subnet_config_remote_dir = spec.avalanchego_config.subnet_config_dir,
            vm_plugin_remote_dir = spec.avalanchego_config.plugin_dir,
            chain_config_remote_dir = spec.avalanchego_config.chain_config_dir,
            avalanchego_config_remote_path = spec.avalanchego_config.config_file.clone().unwrap(),
            region_to_ssm_doc_name = region_to_ssm_doc_name,
            node_id_to_region_machine_id = node_id_to_region_machine_id,
            spec_file_path = spec_file_path,
        )),
        ResetColor
    )?;

    println!("\n# EXAMPLE: start distributed load generator");
    execute!(
        stdout(),
        SetForegroundColor(Color::DarkGreen),
        Print(format!(
            "{exec_parent_dir}/blizzardup-aws \\
default-spec --log-level=info --funded-keys={funded_keys} --region={region} --upload-artifacts-blizzard-bin={exec_parent_dir}/blizzard-aws --instance-mode=spot \\
--nodes=10 \\
--blizzard-log-level=info --blizzard-chain-rpc-urls={chain_rpc_urls} --blizzard-keys-to-generate=100 --blizzard-workers=10 --blizzard-load-kinds=x-transfers,evm-transfers

",
            exec_parent_dir = exec_parent_dir,
            funded_keys = if let Some(keys) = &spec.prefunded_keys {
                keys.len()
            } else {
                1
            },
            region = spec.resource.regions[0],
            chain_rpc_urls = all_nodes_c_chain_rpc_urls.clone().join(","),
        )),
        ResetColor
    )?;

    println!("\n# EXAMPLE: query all endpoints");
    execute!(
        stdout(),
        SetForegroundColor(Color::DarkGreen),
        Print(format!(
            "{exec_path} endpoints \\
--log-level=info \\
--chain-rpc-urls={chain_rpc_urls}

",
            exec_path = exec_path.display(),
            chain_rpc_urls = all_nodes_http_rpcs.clone().join(","),
        )),
        ResetColor
    )?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: nodes are ready -- check the following endpoints!\n\n"),
        ResetColor
    )?;
    // TODO: check "/ext/info"
    // TODO: check "/ext/bc/C/rpc"
    // TODO: subnet-evm endpoint with "/ext/bc/[BLOCKCHAIN TX ID]/rpc"
    // ref. https://github.com/ava-labs/subnet-evm/blob/505f03904736ee9f8de7b862c06d0ae18062cc80/runner/main.go#L671
    //
    // NOTE: metamask endpoints will be "http://[NLB_DNS]:9650/ext/bc/[CHAIN ID]/rpc"
    // NOTE: metamask endpoints will be "http://[NLB_DNS]:9650/ext/bc/C/rpc"
    // NOTE: metamask chain ID is "43112" as in coreth "DEFAULT_GENESIS"
    for host in rpc_hosts.iter() {
        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();

        let mut endpoints = avalanche_ops::aws::spec::Endpoints::default();
        endpoints.http_rpc = Some(http_rpc.clone());
        endpoints.http_rpc_x = Some(format!("{http_rpc}/ext/bc/X"));
        endpoints.http_rpc_p = Some(format!("{http_rpc}/ext/bc/P"));
        endpoints.http_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.metrics = Some(format!("{http_rpc}/ext/metrics"));
        endpoints.health = Some(format!("{http_rpc}/ext/health"));
        endpoints.liveness = Some(format!("{http_rpc}/ext/health/liveness"));
        endpoints.metamask_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.websocket_rpc_c = Some(format!("ws://{host}:{port_for_dns}/ext/bc/C/ws"));
        println!("{}", endpoints.encode_yaml().unwrap());
    }

    Ok(())
}

fn build_param(k: &str, v: &str) -> Parameter {
    Parameter::builder()
        .parameter_key(k)
        .parameter_value(v)
        .build()
}

/// randomly wait to prevent UTXO double spends from the same wallet
async fn add_primary_network_permissionless_validator(
    random_wait_dur: Arc<Duration>,
    wallet_to_spend: Arc<wallet::Wallet<key::secp256k1::private_key::Key>>,
    node_id: Arc<ids::node::Id>,
    pop: Arc<key::bls::ProofOfPossession>,
    stake_amount_in_navax: Arc<u64>,
    primary_network_validate_period_in_days: Arc<u64>,
) {
    let random_wait_dur = random_wait_dur.as_ref();
    log::info!(
        "adding '{node_id}' as a primary network permissionless validator after waiting random {:?}",
        *random_wait_dur
    );
    sleep(*random_wait_dur).await;

    let node_id = node_id.as_ref();
    let pop = pop.as_ref();
    let stake_amount_in_navax = stake_amount_in_navax.as_ref();
    let primary_network_validate_period_in_days = primary_network_validate_period_in_days.as_ref();

    let (tx_id, added) = wallet_to_spend
        .p()
        .add_permissionless_validator()
        .node_id(node_id.clone())
        .proof_of_possession(pop.clone())
        .stake_amount(*stake_amount_in_navax)
        .validate_period_in_days(*primary_network_validate_period_in_days, 60)
        .check_acceptance(true)
        .issue()
        .await
        .unwrap();

    log::info!("primary network validator tx id {}, added {}", tx_id, added);
}
