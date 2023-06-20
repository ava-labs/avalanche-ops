use std::{
    collections::{BTreeMap, HashMap},
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

    let default_shared_config = aws_manager::load_config(
        Some(spec.resource.regions[0].clone()),
        Some(spec.profile_name.clone()),
        Some(Duration::from_secs(30)),
    )
    .await;

    let sts_manager = sts::Manager::new(&default_shared_config);
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

        let regional_machine = spec.machine.regional_machines.get(region).unwrap();

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
    let default_s3_manager = s3::Manager::new(&default_shared_config);

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

        // do not reset, we need this in case we need rerun
        // spec.upload_artifacts = None;

        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");
    } else {
        log::info!("skipping uploading artifacts...");
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_kms_manager = kms::Manager::new(&regional_shared_config);

        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: create KMS encrypt key in '{region}'\n"
            )),
            ResetColor
        )?;
        if regional_resource
            .kms_symmetric_default_encrypt_key
            .is_none()
        {
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
            default_s3_manager
                .put_object(
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
        } else {
            log::info!("skipping creating KMS default encrypt key");
        }

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
                    spec_file_path,
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

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: creating EC2 instance role in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if regional_resource
            .cloudformation_ec2_instance_profile_arn
            .is_none()
        {
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

            log::info!("waiting for IAM creation...");
            sleep(Duration::from_secs(10)).await;
        } else {
            log::info!("skipping creating IAM EC2 instance role (already exists)")
        }
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
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

            spec.resource
                .regional_resources
                .insert(region.clone(), regional_resource);
            spec.sync(spec_file_path)?;
            default_s3_manager
                .put_object(
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
        } else {
            log::info!("skipping polling IAM EC2 instance role status (already exists)")
        }
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let regional_resource = r.clone();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: creating a VPC in the region '{region}'\n"
            )),
            ResetColor
        )?;
        if regional_resource.cloudformation_vpc_id.is_none()
            && regional_resource
                .cloudformation_vpc_security_group_id
                .is_none()
            && regional_resource
                .cloudformation_vpc_public_subnet_ids
                .is_none()
        {
            let vpc_tmpl = avalanche_ops::aws::artifacts::vpc_yaml().unwrap();
            let vpc_stack_name = regional_resource.cloudformation_vpc.clone().unwrap();
            let vpc_params = Vec::from([
                build_param("Id", &spec.id),
                build_param("UserId", &spec.resource.identity.user_id),
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

            log::info!("waiting for VPC creation...");
            sleep(Duration::from_secs(10)).await;
        } else {
            log::info!("skipping creating VPC (already exists)")
        }
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
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

            spec.resource
                .regional_resources
                .insert(region.clone(), regional_resource);
            spec.sync(spec_file_path)?;
            default_s3_manager
                .put_object(
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
        } else {
            log::info!("skipping polling VPC")
        }
    }

    let mut created_nodes: Vec<avalanche_ops::aws::spec::Node> = Vec::new();
    let mut region_to_common_asg_params = HashMap::new();
    let mut region_to_common_dev_machine_asg_params = HashMap::new();
    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();

        let regional_machine = spec.machine.regional_machines.get(region).unwrap();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        let mut common_asg_params = vec![
            build_param("Id", &spec.id),
            build_param("UserId", &spec.resource.identity.user_id),
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
            build_param("OsType", &spec.machine.os_type),
            build_param(
                "ImageIdSsmParameter",
                &ec2::default_image_id_ssm_parameter(
                    &spec.machine.arch_type,
                    &spec.machine.os_type,
                )
                .unwrap(),
            ),
            build_param(
                "AvalanchedAwsArgs",
                &format!("agent {}", spec.avalanched_config.to_flags()),
            ),
            build_param("ProvisionerInitialWaitRandomSeconds", "15"),
        ];

        // just copy the regional machine params, and later overwrite if 'create-dev-machine' is true
        let mut common_dev_machine_params = BTreeMap::new();
        common_dev_machine_params.insert("Id".to_string(), format!("{}-dev-machine", spec.id));
        common_dev_machine_params
            .insert("UserId".to_string(), spec.resource.identity.user_id.clone());
        common_dev_machine_params.insert("AsgName".to_string(), format!("{}-dev-machine", spec.id));
        common_dev_machine_params.insert(
            "KmsKeyArn".to_string(),
            regional_resource
                .kms_symmetric_default_encrypt_key
                .clone()
                .unwrap()
                .arn
                .clone(),
        );
        common_dev_machine_params.insert("AadTag".to_string(), spec.aad_tag.clone());
        common_dev_machine_params
            .insert("S3BucketName".to_string(), spec.resource.s3_bucket.clone());
        common_dev_machine_params.insert(
            "Ec2KeyPairName".to_string(),
            regional_resource.ec2_key_name.clone(),
        );
        common_dev_machine_params.insert(
            "InstanceProfileArn".to_string(),
            regional_resource
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        );
        common_dev_machine_params.insert(
            "SecurityGroupId".to_string(),
            regional_resource
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        );
        common_dev_machine_params.insert("AsgDesiredCapacity".to_string(), "1".to_string());
        // for CFN template updates
        // ref. "Temporarily setting autoscaling group MinSize and DesiredCapacity to 2."
        // ref. "Rolling update initiated. Terminating 1 obsolete instance(s) in batches of 1, while keeping at least 1 instance(s) in service."
        common_dev_machine_params.insert("AsgMaxSize".to_string(), "2".to_string());
        common_dev_machine_params.insert(
            "VolumeSize".to_string(),
            format!("{}", spec.machine.volume_size_in_gb),
        );
        common_dev_machine_params.insert("ArchType".to_string(), spec.machine.arch_type.clone());
        common_dev_machine_params.insert("OsType".to_string(), spec.machine.os_type.clone());
        common_dev_machine_params.insert(
            "ImageIdSsmParameter".to_string(),
            ec2::default_image_id_ssm_parameter(&spec.machine.arch_type, &spec.machine.os_type)
                .unwrap(),
        );
        common_dev_machine_params.insert(
            "ProvisionerInitialWaitRandomSeconds".to_string(),
            "15".to_string(), // we poll asg tag anyways
        );

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

            common_dev_machine_params.insert("InstanceTypes".to_string(), instance_types.join(","));
            common_dev_machine_params.insert(
                "InstanceTypesCount".to_string(),
                format!("{}", instance_types.len()),
            );
        }

        common_asg_params.push(build_param(
            "AvalanchedAwsDownloadSource",
            avalanched_download_source,
        ));

        let is_spot_instance = spec.machine.instance_mode == *"spot";
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        common_asg_params.push(build_param(
            "InstanceMode",
            if is_spot_instance {
                "spot"
            } else {
                "on-demand"
            },
        ));
        common_dev_machine_params.insert(
            "InstanceMode".to_string(),
            if is_spot_instance {
                "spot".to_string()
            } else {
                "on-demand".to_string()
            },
        );

        common_asg_params.push(build_param("IpMode", &spec.machine.ip_mode));
        common_dev_machine_params.insert("IpMode".to_string(), spec.machine.ip_mode.clone());

        common_asg_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));
        common_dev_machine_params.insert(
            "OnDemandPercentageAboveBaseCapacity".to_string(),
            format!("{}", on_demand_pct),
        );

        if let Some(arn) = &regional_resource.nlb_acm_certificate_arn {
            common_asg_params.push(build_param("NlbAcmCertificateArn", arn));
        };
        if spec.enable_nlb {
            common_asg_params.push(build_param("NlbEnabled", "true"));
        } else {
            common_asg_params.push(build_param("NlbEnabled", "false"));
        }

        let public_subnet_ids = regional_resource
            .cloudformation_vpc_public_subnet_ids
            .clone()
            .unwrap();
        common_dev_machine_params
            .insert("PublicSubnetIds".to_string(), public_subnet_ids.join(","));

        region_to_common_asg_params.insert(region.to_string(), common_asg_params.clone());
        region_to_common_dev_machine_asg_params
            .insert(region.to_string(), common_dev_machine_params);

        let mut anchor_asg_logical_ids = Vec::new();
        if regional_machine.anchor_nodes.unwrap_or(0) > 0 {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: create ASG for anchor nodes for network Id {} in the region '{region}'\n",
                    spec.avalanchego_config.network_id
                )),
                ResetColor
            )?;

            if regional_resource
                .cloudformation_asg_anchor_nodes_logical_ids
                .is_some()
            {
                log::warn!("'{region}' already has cloudformation_asg_anchor_nodes_logical_ids, it may fail due to conflict, continue anyways (keep_resources_except_asg_ssm: {})", spec.keep_resources_except_asg_ssm);
            }

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
                        asg_launch_template_version,
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
                        Some(Vec::from([
                            Tag::builder().key("KIND").value("avalanche-ops").build(),
                            Tag::builder()
                                .key("UserId")
                                .value(spec.resource.identity.user_id.clone())
                                .build(),
                        ])),
                        Some(anchor_asg_params),
                    )
                    .await
                    .unwrap();

                if i == 0 {
                    log::info!(
                        "waiting 1-minute for initial node creation to reuse NLB/ASG launch templates"
                    );
                    sleep(Duration::from_secs(100)).await;

                    // add 5-minute for ELB creation + volume provisioner + ip provisioner
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
            default_s3_manager
                .put_object(
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object ConfigFile");
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
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_machine = spec.machine.regional_machines.get(region).unwrap();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

        if let Some(anchor_asg_logical_ids) =
            &regional_resource.cloudformation_asg_anchor_nodes_logical_ids
        {
            let mut droplets: Vec<ec2::Droplet> = Vec::new();
            let mut eips = Vec::new();
            let mut instance_id_to_public_ip = HashMap::new();
            for anchor_asg_name in anchor_asg_logical_ids.iter() {
                let mut local_droplets: Vec<ec2::Droplet> = Vec::new();
                for _ in 0..20 {
                    // TODO: better retries
                    log::info!("fetching all droplets for anchor-node SSH access");
                    let ds = regional_ec2_manager
                        .list_asg(anchor_asg_name)
                        .await
                        .unwrap();
                    if !ds.is_empty() {
                        local_droplets = ds;
                        break;
                    }
                    log::info!("retrying fetching all droplets (only got {})", ds.len());
                    sleep(Duration::from_secs(30)).await;
                }
                droplets.extend(local_droplets);

                if spec.machine.ip_mode == *"elastic" {
                    log::info!("using elastic IPs... wait more");
                    let mut outs: Vec<Address>;
                    let mut cnt = 0;
                    loop {
                        cnt = cnt + 1;

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

                        log::info!("[retries {cnt}] got {} EIP addresses", outs.len());

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
            let mut ssh_commands = Vec::new();
            for d in droplets {
                let (public_ip, ip_mode) =
                    if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                        (public_ip.clone(), "elastic")
                    } else {
                        (d.public_ipv4.clone(), "ephemeral")
                    };

                let ssh_command = ec2::SshCommand {
                    ec2_key_path: regional_resource.ec2_key_path.clone(),
                    user_name: String::from("ubuntu"),

                    region: region.clone(),
                    availability_zone: d.availability_zone,

                    instance_id: d.instance_id,
                    instance_state_name: d.instance_state_name,

                    ip_mode: ip_mode.to_string(),
                    public_ip: public_ip,
                };
                println!("\n{}\n", ssh_command.to_string());
                ssh_commands.push(ssh_command);
            }
            println!();

            ec2::SshCommands(ssh_commands.clone())
                .sync(&regional_resource.ssh_commands_path_anchor_nodes)
                .unwrap();

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
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();

            log::info!("waiting for anchor nodes bootstrap and ready (to be safe)");
            sleep(Duration::from_secs(15)).await;

            for ssh_command in ssh_commands.iter() {
                match ssh_command.run("tail -10 /var/log/cloud-init-output.log") {
                    Ok(output) => {
                        println!(
                            "{} (anchor node) init script std output:\n{}\n",
                            ssh_command.instance_id, output.stdout
                        );
                        println!(
                            "{} (anchor node) init script std err:\n{}\n",
                            ssh_command.instance_id, output.stderr
                        );
                    }
                    Err(e) => log::warn!("failed to run ssh command {}", e),
                }
            }
        }
    }

    for (region, r) in spec.resource.regional_resources.clone().iter() {
        let mut regional_resource = r.clone();
        let regional_machine = spec.machine.regional_machines.get(region).unwrap();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);

        let common_asg_params = region_to_common_asg_params.get(region).unwrap();

        if regional_resource
            .cloudformation_asg_non_anchor_nodes_logical_ids
            .is_some()
        {
            log::warn!("'{region}' already has cloudformation_asg_non_anchor_nodes_logical_ids, it may fail due to conflict, continue anyways (keep_resources_except_asg_ssm: {})", spec.keep_resources_except_asg_ssm);
        }

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
                    asg_launch_template_version,
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
                    Some(Vec::from([
                        Tag::builder().key("KIND").value("avalanche-ops").build(),
                        Tag::builder()
                            .key("UserId")
                            .value(spec.resource.identity.user_id.clone())
                            .build(),
                    ])),
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
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");

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
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_machine = spec.machine.regional_machines.get(region).unwrap();

        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
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
                    if !ds.is_empty() {
                        dss = ds;
                        break;
                    }
                    log::info!("retrying fetching all droplets (only got {})", ds.len());
                    sleep(Duration::from_secs(30)).await;
                }
                droplets.extend(dss);

                if spec.machine.ip_mode == *"elastic" {
                    log::info!("using elastic IPs... wait more");
                    #[allow(unused_assignments)]
                    let mut eips_out: Vec<Address> = Vec::new();
                    let max_retry = 10;
                    loop {
                        let mut retry_count = 0;
                        let outs = match regional_ec2_manager
                            .describe_eips_by_tags(HashMap::from([
                                (String::from("Id"), spec.id.clone()),
                                (
                                    String::from("autoscaling:groupName"),
                                    non_anchor_asg_name.clone(),
                                ),
                            ]))
                            .await
                        {
                            Ok(o) => o,
                            Err(e) => {
                                retry_count += 1;
                                if retry_count == max_retry {
                                    return Err(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        format!(
                                            "could not find elastic ip for node {}",
                                            spec.id.clone()
                                        ),
                                    ));
                                }

                                log::error!(
                                    "error finding elastic ip for node {}: {e}",
                                    spec.id.clone()
                                );
                                continue;
                            }
                        };

                        log::info!("got {} EIP addresses", outs.len());

                        let mut ready = true;
                        for eip_addr in outs.iter() {
                            ready = ready && eip_addr.instance_id.is_some();
                        }
                        if ready && outs.len() == 1 {
                            eips_out = outs.clone();
                            break;
                        }

                        sleep(Duration::from_secs(30)).await;
                    }
                    eips.extend(eips_out.clone());

                    for eip_addr in eips_out.iter() {
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
            let mut ssh_commands = Vec::new();
            for d in droplets {
                let (public_ip, ip_mode) =
                    if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                        (public_ip.clone(), "elastic")
                    } else {
                        (d.public_ipv4.clone(), "ephemeral")
                    };

                let ssh_command = ec2::SshCommand {
                    ec2_key_path: regional_resource.ec2_key_path.clone(),
                    user_name: String::from("ubuntu"),

                    region: region.clone(),
                    availability_zone: d.availability_zone,

                    instance_id: d.instance_id,
                    instance_state_name: d.instance_state_name,

                    ip_mode: ip_mode.to_string(),
                    public_ip: public_ip,
                };
                println!("\n{}\n", ssh_command.to_string());
                ssh_commands.push(ssh_command);
            }
            println!();

            ec2::SshCommands(ssh_commands.clone())
                .sync(&regional_resource.ssh_commands_path_non_anchor_nodes)
                .unwrap();

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
                    spec_file_path,
                    &spec.resource.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object ConfigFile");

            log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
            sleep(Duration::from_secs(20)).await;

            for ssh_command in ssh_commands.iter() {
                match ssh_command.run("tail -10 /var/log/cloud-init-output.log") {
                    Ok(output) => {
                        println!(
                            "{} (non-anchor node) init script std output:\n{}\n",
                            ssh_command.instance_id, output.stdout
                        );
                        println!(
                            "{} (non-anchor node) init script std err:\n{}\n",
                            ssh_command.instance_id, output.stderr
                        );
                    }
                    Err(e) => log::warn!("failed to run ssh command {}", e),
                }
            }
        }
    }

    spec.resource.created_nodes = Some(created_nodes.clone());
    spec.sync(spec_file_path)?;
    default_s3_manager
        .put_object(
            spec_file_path,
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
    let all_nodes_yaml_path = get_all_nodes_yaml_path(spec_file_path);
    let f = File::create(&all_nodes_yaml_path).unwrap();
    serde_yaml::to_writer(f, &created_nodes.clone()).unwrap();
    println!("# for all nodes\ncat {all_nodes_yaml_path}");

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
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
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
                Some(Vec::from([
                    Tag::builder().key("KIND").value("avalanche-ops").build(),
                    Tag::builder()
                        .key("UserId")
                        .value(spec.resource.identity.user_id.clone())
                        .build(),
                ])),
                Some(cfn_params),
            )
            .await
            .unwrap();
    }
    log::info!("waiting for SSM creation...");
    sleep(Duration::from_secs(10)).await;
    for (region, regional_resource) in spec.resource.regional_resources.clone().iter() {
        let regional_shared_config = aws_manager::load_config(
            Some(region.clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
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

    // adding validators is only supported for custom network
    // because fuji + mainnet requires state sync with exiting chain state
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
            } else if created_nodes.len() > 50 {
                2 + i as u64
            } else {
                1 + i as u64
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

# or --target-node-ids '{target_node_ids}'

",
            exec_path = exec_path.display(),
            chain_rpc_url = if spec.avalanchego_config.is_custom_network() {
                format!("{}://{}:{}", scheme_for_dns, rpc_hosts[0], port_for_dns)
            } else {
                "https://api.avax-test.network".to_string()
            },
            priv_key_hex = key::secp256k1::TEST_KEYS[0].to_hex(),
            spec_file_path = spec_file_path,
            target_node_ids = all_node_ids.join(","),
        )),
        ResetColor
    )?;

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
            chain_rpc_url = if spec.avalanchego_config.is_custom_network() {
                format!("{}://{}:{}", scheme_for_dns, rpc_hosts[0], port_for_dns)
            } else {
                "https://api.avax-test.network".to_string()
            },
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

    if spec.create_dev_machine {
        //
        //
        //
        //
        //
        println!();
        log::info!("creating a dev machine");

        let mut regional_resource = spec
            .resource
            .regional_resources
            .get(&spec.resource.regions[0])
            .unwrap()
            .clone();
        let stack_name = if let Some(v) = &regional_resource.cloudformation_asg_dev_machine {
            v.clone()
        } else {
            let s = avalanche_ops::aws::spec::StackName::DevMachine(spec.id.clone()).encode();
            regional_resource.cloudformation_asg_dev_machine = Some(s.clone());
            s
        };
        spec.resource
            .regional_resources
            .insert(spec.resource.regions[0].clone(), regional_resource.clone());
        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");

        let mut regional_common_dev_machine_asg_params = region_to_common_dev_machine_asg_params
            .get(&spec.resource.regions[0])
            .unwrap()
            .clone();
        let dev_machine = spec.dev_machine.clone().unwrap();
        regional_common_dev_machine_asg_params
            .insert("IpMode".to_string(), dev_machine.ip_mode.clone());

        if let Some(email) = &dev_machine.ssh_key_email {
            regional_common_dev_machine_asg_params.insert("SshKeyEmail".to_string(), email.clone());
        };

        if !dev_machine.instance_types.is_empty() {
            let instance_types = dev_machine.instance_types.clone();
            regional_common_dev_machine_asg_params
                .insert("InstanceTypes".to_string(), instance_types.join(","));
            regional_common_dev_machine_asg_params.insert(
                "InstanceTypesCount".to_string(),
                format!("{}", instance_types.len()),
            );
        }

        let is_spot_instance = dev_machine.instance_mode == *"spot";
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        regional_common_dev_machine_asg_params.insert(
            "InstanceMode".to_string(),
            if is_spot_instance {
                "spot".to_string()
            } else {
                "on-demand".to_string()
            },
        );
        regional_common_dev_machine_asg_params.insert(
            "OnDemandPercentageAboveBaseCapacity".to_string(),
            format!("{}", on_demand_pct),
        );
        regional_common_dev_machine_asg_params
            .insert("ArchType".to_string(), dev_machine.arch_type.clone());
        regional_common_dev_machine_asg_params
            .insert("OsType".to_string(), "ubuntu20.04".to_string());
        regional_common_dev_machine_asg_params.insert(
            "ImageIdSsmParameter".to_string(),
            ec2::default_image_id_ssm_parameter(&spec.machine.arch_type, &spec.machine.os_type)
                .unwrap(),
        );

        let regional_shared_config = aws_manager::load_config(
            Some(spec.resource.regions[0].clone()),
            Some(spec.profile_name.clone()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let regional_cloudformation_manager = cloudformation::Manager::new(&regional_shared_config);
        let regional_ec2_manager = ec2::Manager::new(&regional_shared_config);

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: creating dev machine ASG in '{}'\n\n",
                spec.resource.regions[0]
            )),
            ResetColor
        )?;
        let asg_tmpl = aws_dev_machine::artifacts::asg_ubuntu_yaml().unwrap();

        let mut cfn_params = Vec::new();
        for (k, v) in regional_common_dev_machine_asg_params.iter() {
            log::info!("dev-machine CFN parameter: '{k}'='{v}'");
            cfn_params.push(build_param(k, v));
        }

        regional_cloudformation_manager
            .create_stack(
                &stack_name,
                None,
                OnFailure::Delete,
                &asg_tmpl,
                Some(Vec::from([
                    Tag::builder().key("KIND").value("avalanche-ops").build(),
                    Tag::builder()
                        .key("UserId")
                        .value(spec.resource.identity.user_id.clone())
                        .build(),
                ])),
                Some(cfn_params),
            )
            .await
            .unwrap();

        let stack = regional_cloudformation_manager
            .poll_stack(
                &stack_name,
                StackStatus::CreateComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        log::info!(
            "created a dev machine in the region '{}'",
            spec.resource.regions[0]
        );

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                regional_resource.cloudformation_asg_dev_machine_logical_id = Some(v);
                continue;
            }
        }
        if regional_resource
            .cloudformation_asg_dev_machine_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "dev-machine regional_resource.cloudformation_asg_dev_machine_logical_id not found",
            ));
        }

        let asg_name = regional_resource
            .cloudformation_asg_dev_machine_logical_id
            .clone()
            .unwrap();

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        for _ in 0..10 {
            // TODO: better retries
            log::info!("fetching all droplets for dev-machine SSH access (target node 1)",);
            droplets = regional_ec2_manager.list_asg(&asg_name).await.unwrap();
            if (droplets.len() as u32) >= 1 {
                break;
            }
            log::info!(
                "retrying fetching all droplets (only got {})",
                droplets.len()
            );
            sleep(Duration::from_secs(30)).await;
        }

        let mut eips = Vec::new();
        if spec.machine.ip_mode == *"elastic" {
            log::info!("using elastic IPs... wait more");
            loop {
                eips = regional_ec2_manager
                    .describe_eips_by_tags(HashMap::from([(
                        String::from("Id"),
                        format!("{}-dev-machine", spec.id),
                    )]))
                    .await
                    .unwrap();

                log::info!("got {} EIP addresses", eips.len());

                let mut ready = true;
                for eip_addr in eips.iter() {
                    ready = ready && eip_addr.instance_id.is_some();
                }
                if ready && eips.len() == 1 {
                    break;
                }

                sleep(Duration::from_secs(30)).await;
            }
        }

        let mut instance_id_to_public_ip = HashMap::new();
        for eip_addr in eips.iter() {
            let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
            let instance_id = eip_addr.instance_id.to_owned().unwrap();
            let public_ip = eip_addr.public_ip.to_owned().unwrap();
            log::info!("EIP found {allocation_id} for {instance_id} and {public_ip}");
            instance_id_to_public_ip.insert(instance_id, public_ip);
        }

        let user_name = {
            if dev_machine.os_type == "al2" {
                "ec2-user"
            } else {
                "ubuntu"
            }
        };

        let mut ssh_commands = Vec::new();
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            // TODO: support other user name?
            let public_ip = if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                public_ip.clone()
            } else {
                d.public_ipv4.clone()
            };

            let ssh_command = ec2::SshCommand {
                ec2_key_path: regional_resource.ec2_key_path.clone(),
                user_name: user_name.to_string(),

                region: spec.resource.regions[0].clone(),
                availability_zone: d.availability_zone,

                instance_id: d.instance_id,
                instance_state_name: d.instance_state_name,

                ip_mode: spec.machine.ip_mode.clone(),
                public_ip: public_ip,
            };
            println!("\n{}\n", ssh_command.to_string());
            ssh_commands.push(ssh_command);
        }
        println!();

        ec2::SshCommands(ssh_commands.clone())
            .sync(&regional_resource.ssh_commands_path_dev_machine)
            .unwrap();

        spec.resource
            .regional_resources
            .insert(spec.resource.regions[0].clone(), regional_resource);
        spec.sync(spec_file_path)?;
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");

        sleep(Duration::from_secs(1)).await;
        log::info!("uploading avalancheup spec file...");
        default_s3_manager
            .put_object(
                spec_file_path,
                &spec.resource.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        sleep(Duration::from_secs(10)).await;
        for ssh_command in ssh_commands.iter() {
            match ssh_command.run("tail -10 /var/log/cloud-init-output.log") {
                Ok(output) => {
                    println!(
                        "{} (dev machine) init script std output:\n{}\n",
                        ssh_command.instance_id, output.stdout
                    );
                    println!(
                        "{} (dev machine) init script std err:\n{}\n",
                        ssh_command.instance_id, output.stderr
                    );
                }
                Err(e) => log::warn!("failed to run ssh command {}", e),
            }
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

    match wallet_to_spend
        .p()
        .add_permissionless_validator()
        .node_id(*node_id)
        .proof_of_possession(pop.clone())
        .stake_amount(*stake_amount_in_navax)
        .validate_period_in_days(*primary_network_validate_period_in_days, 60)
        .check_acceptance(true)
        .poll_timeout(Duration::from_secs(150))
        .issue()
        .await
    {
        Ok((tx_id, added)) => {
            log::info!("primary network validator tx id {}, added {}", tx_id, added);
        }
        Err(e) => {
            log::warn!("failed add_permissionless_validator {}", e);
        }
    }
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
