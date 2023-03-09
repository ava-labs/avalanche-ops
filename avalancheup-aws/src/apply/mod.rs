use std::{
    collections::{BTreeMap, HashMap},
    env,
    fs::{self, File},
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
    ids::{self, node},
    jsonrpc::client::health as client_health,
    key, wallet,
};
use aws_manager::{
    self, cloudformation, ec2,
    kms::{self, envelope},
    s3, ssm, sts,
};
use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_ec2::model::Address;
use aws_sdk_s3::model::Object;
use aws_sdk_ssm::model::CommandInvocationStatus;
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
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec =
        avalanche_ops::aws::spec::Spec::load(spec_file_path).expect("failed to load spec");
    spec.validate()?;

    let shared_config = aws_manager::load_config(Some(spec.resources.region.clone()))
        .await
        .expect("failed to aws_manager::load_config");

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    // validate identity
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
        spec.resources.identity = Some(current_identity);
    }

    // set defaults based on ID
    if spec.resources.ec2_key_name.is_empty() {
        spec.resources.ec2_key_name = format!("{}-ec2-key", spec.id);
    }
    if spec.resources.cloudformation_ec2_instance_role.is_none() {
        spec.resources.cloudformation_ec2_instance_role =
            Some(avalanche_ops::aws::spec::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if spec.resources.cloudformation_vpc.is_none() {
        spec.resources.cloudformation_vpc =
            Some(avalanche_ops::aws::spec::StackName::Vpc(spec.id.clone()).encode());
    }

    // DON'T "spec.resources.cloudformation_asg_anchor_nodes.is_none()"
    // in case we edit anchor node size after default spec generation
    if spec.avalanchego_config.is_custom_network() {
        let anchor_nodes = spec.machine.anchor_nodes.unwrap_or(0);
        let mut asg_names = Vec::new();
        for i in 0..anchor_nodes {
            let asg_name = format!("{}-anchor-{}-{:02}", spec.id, spec.machine.arch_type, i + 1);
            asg_names.push(asg_name);
        }
        spec.resources.cloudformation_asg_anchor_nodes = Some(asg_names);
    }

    // DON'T "spec.resources.cloudformation_asg_non_anchor_nodes.is_none()"
    // in case we edit non-anchor node size after default spec generation
    let non_anchor_nodes = spec.machine.non_anchor_nodes;
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
    spec.resources.cloudformation_asg_non_anchor_nodes = Some(asg_names);

    if spec
        .resources
        .cloudwatch_avalanche_metrics_namespace
        .is_none()
    {
        spec.resources.cloudwatch_avalanche_metrics_namespace =
            Some(format!("{}-avalanche", spec.id));
    }

    // just create these no matter what for simplification
    spec.resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm = Some(
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeTrackedSubnetSubnetEvm(
            spec.id.clone(),
        )
        .encode(),
    );
    spec.resources
        .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm = Some(
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeChainConfigSubnetEvm(spec.id.clone())
            .encode(),
    );
    spec.resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm = Some(
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeTrackedSubnetXsvm(spec.id.clone())
            .encode(),
    );
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
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);
    let ssm_manager = ssm::Manager::new(&shared_config);

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))
        .expect("failed to register os signal");

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 buckets\n"),
        ResetColor
    )?;
    s3_manager
        .create_bucket(&spec.resources.s3_bucket)
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
            s3_manager
                .put_object(
                    &v.avalanched_local_bin,
                    &spec.resources.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalanchedBin(spec.id.clone())
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

            s3_manager
                .put_object(
                    &v.aws_volume_provisioner_local_bin,
                    &spec.resources.s3_bucket,
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

            s3_manager
                .put_object(
                    &v.aws_ip_provisioner_local_bin,
                    &spec.resources.s3_bucket,
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

            s3_manager
                .put_object(
                    &v.avalanche_telemetry_cloudwatch_local_bin,
                    &spec.resources.s3_bucket,
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

        if !v.avalanche_config_local_bin.is_empty()
            && Path::new(&v.avalanche_config_local_bin).exists()
        {
            // don't compress since we need to download this in user data
            // while instance bootstrapping

            s3_manager
                .put_object(
                    &v.avalanche_config_local_bin,
                    &spec.resources.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalancheConfigBin(
                        spec.id.clone(),
                    )
                    .encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.avalanche_config_bin");
        } else {
            log::info!(
                "skipping uploading avalanche_config_bin, will be downloaded on remote machines..."
            );
        }

        if !v.avalanchego_local_bin.is_empty() && Path::new(&v.avalanchego_local_bin).exists() {
            // upload without compression first
            s3_manager
                .put_object(
                    &v.avalanchego_local_bin,
                    &spec.resources.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::AvalancheBin(spec.id.clone())
                        .encode(),
                )
                .await
                .expect("failed put_object avalanchego_bin");
        } else {
            log::info!(
                "skipping uploading avalanchego_bin, will be downloaded on remote machines..."
            );
        }

        if !v.plugin_local_dir.is_empty() && Path::new(&v.plugin_local_dir).exists() {
            for entry in fs::read_dir(&v.plugin_local_dir).unwrap() {
                let entry = entry.unwrap();
                let entry_path = entry.path();

                let file_path = entry_path.to_str().unwrap();
                let file_name = entry.file_name();
                let file_name = file_name.as_os_str().to_str().unwrap();

                log::info!(
                    "uploading {} from plugins directory {}",
                    file_path,
                    v.plugin_local_dir,
                );
                s3_manager
                    .put_object(
                        &file_path,
                        &spec.resources.s3_bucket,
                        &format!(
                            "{}/{}",
                            &avalanche_ops::aws::spec::StorageNamespace::PluginDir(spec.id.clone())
                                .encode(),
                            file_name,
                        ),
                    )
                    .await
                    .expect("failed put_object file_path");
            }
        } else {
            log::info!("skipping uploading plugin dir...");
        }

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: uploading metrics rules\n"),
            ResetColor
        )?;
        s3_manager
            .put_object(
                &v.prometheus_metrics_rules_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::MetricsRules(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        log::info!("done with uploading artifacts, thus reset!");
        spec.upload_artifacts = None;
        spec.sync(spec_file_path)?;

        log::info!("uploading avalancheup spec file...");
        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    } else {
        log::info!("skipping uploading artifacts...");
    }

    if spec
        .resources
        .kms_cmk_symmetric_default_encrypt_key
        .is_none()
    {
        sleep(Duration::from_secs(1)).await;
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )?;

        let key = kms_manager
            .create_symmetric_default_key(format!("{}-cmk", spec.id).as_str())
            .await
            .unwrap();

        spec.resources.kms_cmk_symmetric_default_encrypt_key =
            Some(avalanche_ops::aws::spec::KmsCmk {
                id: key.id,
                arn: key.arn,
            });
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }
    let envelope_manager = envelope::Manager::new(
        &kms_manager,
        spec.resources
            .kms_cmk_symmetric_default_encrypt_key
            .clone()
            .unwrap()
            .id,
        "avalanche-ops".to_string(),
    );

    if !Path::new(&spec.resources.ec2_key_path).exists() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = spec.resources.ec2_key_path.clone();
        ec2_manager
            .create_key_pair(&spec.resources.ec2_key_name, ec2_key_path.as_str())
            .await
            .unwrap();

        let tmp_compressed_path =
            random_manager::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext())).unwrap();
        compress_manager::pack_file(
            ec2_key_path.as_str(),
            &tmp_compressed_path,
            compress_manager::Encoder::Zstd(3),
        )
        .unwrap();

        let tmp_encrypted_path = random_manager::tmp_path(15, Some(".zstd.encrypted")).unwrap();
        envelope_manager
            .seal_aes_256_file(&tmp_compressed_path, &tmp_encrypted_path)
            .await
            .unwrap();

        s3_manager
            .put_object(
                &tmp_encrypted_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
                    spec.id.clone(),
                )
                .encode(),
            )
            .await
            .unwrap();

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    if spec
        .resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_tmpl =
            avalanche_ops::aws::artifacts::ec2_instance_role_yaml().unwrap();
        let ec2_instance_role_stack_name = spec
            .resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        let role_params = Vec::from([
            build_param("Id", &spec.id),
            build_param(
                "KmsCmkArn",
                &spec
                    .resources
                    .kms_cmk_symmetric_default_encrypt_key
                    .clone()
                    .unwrap()
                    .arn,
            ),
            build_param("S3BucketName", &spec.resources.s3_bucket),
        ]);
        cloudformation_manager
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

        sleep(Duration::from_secs(10)).await;
        let stack = cloudformation_manager
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
                spec.resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    if spec.resources.cloudformation_vpc_id.is_none()
        && spec
            .resources
            .cloudformation_vpc_security_group_id
            .is_none()
        && spec
            .resources
            .cloudformation_vpc_public_subnet_ids
            .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_tmpl = avalanche_ops::aws::artifacts::vpc_yaml().unwrap();
        let vpc_stack_name = spec.resources.cloudformation_vpc.clone().unwrap();
        let vpc_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            // TODO: restrict IP
            build_param("SshPortIngressIpv4Range", "0.0.0.0/0"),
            build_param("HttpPortIngressIpv4Range", "0.0.0.0/0"),
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
        cloudformation_manager
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

        sleep(Duration::from_secs(10)).await;
        let stack = cloudformation_manager
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
                spec.resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                spec.resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    log::info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                spec.resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    let mut common_asg_params = Vec::from([
        build_param("Id", &spec.id),
        build_param(
            "NetworkId",
            format!("{}", &spec.avalanchego_config.network_id).as_str(),
        ),
        build_param(
            "KmsCmkArn",
            &spec
                .resources
                .kms_cmk_symmetric_default_encrypt_key
                .clone()
                .unwrap()
                .arn,
        ),
        build_param("AadTag", &spec.aad_tag),
        build_param("S3BucketName", &spec.resources.s3_bucket),
        build_param("Ec2KeyPairName", &spec.resources.ec2_key_name),
        build_param(
            "InstanceProfileArn",
            &spec
                .resources
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        ),
        build_param(
            "SecurityGroupId",
            &spec
                .resources
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        ),
        build_param(
            "NlbVpcId",
            &spec.resources.cloudformation_vpc_id.clone().unwrap(),
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
        build_param("AvalanchedFlag", &spec.avalanched_config.to_flags()),
        build_param("VolumeProvisionerInitialWaitRandomSeconds", "10"),
    ]);

    if !spec.machine.instance_types.is_empty() {
        let instance_types = spec.machine.instance_types.clone();
        common_asg_params.push(build_param("InstanceTypes", &instance_types.join(",")));
        common_asg_params.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    common_asg_params.push(build_param(
        "AvalanchedDownloadSource",
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

    if let Some(arn) = &spec.resources.nlb_acm_certificate_arn {
        common_asg_params.push(build_param("NlbAcmCertificateArn", arn));
    };
    if spec.enable_nlb {
        common_asg_params.push(build_param("NlbEnabled", "true"));
    } else {
        common_asg_params.push(build_param("NlbEnabled", "false"));
    }

    let public_subnet_ids = spec
        .resources
        .cloudformation_vpc_public_subnet_ids
        .clone()
        .unwrap();

    // TODO: support bootstrap from existing DB for anchor nodes
    let mut created_nodes: Vec<avalanche_ops::aws::spec::Node> = Vec::new();

    let mut asg_launch_template_id = String::new();
    let mut asg_launch_template_version = String::new();

    if spec.machine.anchor_nodes.unwrap_or(0) > 0
        && spec
            .resources
            .cloudformation_asg_anchor_nodes_logical_ids
            .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: create ASG for anchor nodes for network Id {}\n",
                spec.avalanchego_config.network_id
            )),
            ResetColor
        )?;

        let cloudformation_asg_anchor_nodes_tmpl =
            avalanche_ops::aws::artifacts::asg_ubuntu_yaml().unwrap();
        let stack_names = spec
            .resources
            .cloudformation_asg_anchor_nodes
            .clone()
            .unwrap();

        let anchor_nodes = spec.machine.anchor_nodes.unwrap();

        // must deep-copy as shared with other node kind
        let mut common_asg_params_anchor = common_asg_params.clone();
        common_asg_params_anchor.push(build_param("NodeKind", "anchor"));

        let mut asg_logical_ids = Vec::new();
        for i in 0..anchor_nodes as usize {
            let mut asg_params = common_asg_params_anchor.clone();
            asg_params.push(build_param(
                "PublicSubnetIds",
                // since we only launch one node per ASG
                &public_subnet_ids[random_manager::usize() % public_subnet_ids.len()].clone(),
            ));

            // AutoScalingGroupName: !Join ["-", [!Ref Id, !Ref NodeKind, !Ref ArchType]]
            let asg_name = format!("{}-anchor-{}-{:02}", spec.id, spec.machine.arch_type, i + 1);
            asg_params.push(build_param("AsgName", &asg_name));

            if !asg_launch_template_id.is_empty() {
                // reuse ASG template
                asg_params.push(build_param("AsgLaunchTemplateId", &asg_launch_template_id));
            }
            if !asg_launch_template_version.is_empty() {
                asg_params.push(build_param(
                    "AsgLaunchTemplateVersion",
                    &asg_launch_template_version,
                ));
            }

            if let Some(arn) = &spec.resources.cloudformation_asg_nlb_target_group_arn {
                // NLB already created
                asg_params.push(build_param("NlbTargetGroupArn", arn));
            }

            cloudformation_manager
                .create_stack(
                    &stack_names[i],
                    None,
                    OnFailure::Delete,
                    &cloudformation_asg_anchor_nodes_tmpl,
                    Some(Vec::from([Tag::builder()
                        .key("KIND")
                        .value("avalanche-ops")
                        .build()])),
                    Some(asg_params),
                )
                .await
                .unwrap();

            // add 5-minute for ELB creation + volume provisioner
            let mut wait_secs = 800;
            if wait_secs > MAX_WAIT_SECONDS {
                wait_secs = MAX_WAIT_SECONDS;
            }
            sleep(Duration::from_secs(60)).await;
            let stack = cloudformation_manager
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
                    asg_logical_ids.push(v);
                    continue;
                }
                if k.eq("NlbArn") {
                    spec.resources.cloudformation_asg_nlb_arn = Some(v);
                    continue;
                }
                if k.eq("NlbTargetGroupArn") {
                    spec.resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                    continue;
                }
                if k.eq("NlbDnsName") {
                    spec.resources.cloudformation_asg_nlb_dns_name = Some(v);
                    continue;
                }
                if k.eq("AsgLaunchTemplateId") {
                    asg_launch_template_id = v;
                    continue;
                }
                if k.eq("AsgLaunchTemplateVersion") {
                    asg_launch_template_version = v;
                    continue;
                }
            }
        }

        spec.resources.cloudformation_asg_anchor_nodes_logical_ids = Some(asg_logical_ids.clone());
        spec.sync(spec_file_path)?;

        if spec.resources.cloudformation_asg_nlb_arn.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_arn not found",
                ));
            }
        }
        if spec
            .resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if spec.resources.cloudformation_asg_nlb_dns_name.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB DNS name...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let mut eips = Vec::new();
        let mut instance_id_to_public_ip = HashMap::new();
        for asg_name in asg_logical_ids.iter() {
            let mut dss = Vec::new();
            for _ in 0..20 {
                // TODO: better retries
                log::info!("fetching all droplets for anchor-node SSH access");
                let ds = ec2_manager.list_asg(asg_name).await.unwrap();
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
                    outs = ec2_manager
                        .describe_eips_by_tags(HashMap::from([
                            (String::from("Id"), spec.id.clone()),
                            (String::from("autoscaling:groupName"), asg_name.clone()),
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

        let f = File::open(&spec.resources.ec2_key_path).unwrap();
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
                spec.resources.ec2_key_path,
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ip_kind,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.region,
                d.instance_id,
            );
        }
        println!();

        // wait for anchor nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let mut objects: Vec<Object>;
        let target_nodes = spec.machine.anchor_nodes.unwrap_or(0);
        loop {
            sleep(Duration::from_secs(30)).await;

            objects = s3_manager
                .list_objects(
                    &spec.resources.s3_bucket,
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
                "{} anchor nodes are bootstrapped and ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }

            if term.load(Ordering::Relaxed) {
                log::warn!("received signal {}", signal_hook::consts::SIGINT);
                println!();
                println!("# run the following to delete resources");
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

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let anchor_node =
                avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            created_nodes.push(anchor_node.clone());
        }

        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        log::info!("waiting for anchor nodes bootstrap and ready (to be safe)");
        sleep(Duration::from_secs(15)).await;
    }

    if spec
        .resources
        .cloudformation_asg_non_anchor_nodes_logical_ids
        .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "\n\n\nSTEP: create ASG for non-anchor nodes for network Id {}\n",
                spec.avalanchego_config.network_id
            )),
            ResetColor
        )?;

        let cloudformation_asg_non_anchor_nodes_tmpl =
            avalanche_ops::aws::artifacts::asg_ubuntu_yaml().unwrap();
        let stack_names = spec
            .resources
            .cloudformation_asg_non_anchor_nodes
            .clone()
            .unwrap();

        let non_anchor_nodes = spec.machine.non_anchor_nodes;

        // must deep-copy as shared with other node kind
        let mut common_asg_params_non_anchor = common_asg_params.clone();
        common_asg_params_non_anchor.push(build_param("NodeKind", "non-anchor"));

        let mut asg_logical_ids = Vec::new();
        for i in 0..non_anchor_nodes as usize {
            let mut asg_params = common_asg_params_non_anchor.clone();
            asg_params.push(build_param(
                "PublicSubnetIds",
                // since we only launch one node per ASG
                &public_subnet_ids[random_manager::usize() % public_subnet_ids.len()].clone(),
            ));

            // AutoScalingGroupName: !Join ["-", [!Ref Id, !Ref NodeKind, !Ref ArchType]]
            let asg_name = format!(
                "{}-non-anchor-{}-{:02}",
                spec.id,
                spec.machine.arch_type,
                i + 1
            );
            asg_params.push(build_param("AsgName", &asg_name));

            if !asg_launch_template_id.is_empty() {
                // reuse ASG template
                asg_params.push(build_param("AsgLaunchTemplateId", &asg_launch_template_id));
            }
            if !asg_launch_template_version.is_empty() {
                asg_params.push(build_param(
                    "AsgLaunchTemplateVersion",
                    &asg_launch_template_version,
                ));
            }

            if let Some(arn) = &spec.resources.cloudformation_asg_nlb_target_group_arn {
                // NLB already created
                asg_params.push(build_param("NlbTargetGroupArn", arn));
            }

            cloudformation_manager
                .create_stack(
                    &stack_names[i],
                    None,
                    OnFailure::Delete,
                    &cloudformation_asg_non_anchor_nodes_tmpl,
                    Some(Vec::from([Tag::builder()
                        .key("KIND")
                        .value("avalanche-ops")
                        .build()])),
                    Some(asg_params),
                )
                .await
                .unwrap();

            // add 5-minute for ELB creation + volume provisioner
            let mut wait_secs = 800;
            if wait_secs > MAX_WAIT_SECONDS {
                wait_secs = MAX_WAIT_SECONDS;
            }
            sleep(Duration::from_secs(60)).await;
            let stack = cloudformation_manager
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
                    asg_logical_ids.push(v);
                    continue;
                }
                if k.eq("NlbArn") {
                    spec.resources.cloudformation_asg_nlb_arn = Some(v);
                    continue;
                }
                if k.eq("NlbTargetGroupArn") {
                    spec.resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                    continue;
                }
                if k.eq("NlbDnsName") {
                    spec.resources.cloudformation_asg_nlb_dns_name = Some(v);
                    continue;
                }
                if k.eq("AsgLaunchTemplateId") {
                    asg_launch_template_id = v;
                    continue;
                }
                if k.eq("AsgLaunchTemplateVersion") {
                    asg_launch_template_version = v;
                    continue;
                }
            }
        }

        spec.resources
            .cloudformation_asg_non_anchor_nodes_logical_ids = Some(asg_logical_ids.clone());
        spec.sync(spec_file_path)?;

        if spec.resources.cloudformation_asg_nlb_arn.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_arn not found",
                ));
            }
        }
        if spec
            .resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if spec.resources.cloudformation_asg_nlb_dns_name.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB DNS name...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let mut eips = Vec::new();
        let mut instance_id_to_public_ip = HashMap::new();
        for asg_name in asg_logical_ids.iter() {
            let mut dss = Vec::new();
            for _ in 0..20 {
                // TODO: better retries
                log::info!("fetching all droplets for non-anchor-node SSH access");
                let ds = ec2_manager.list_asg(asg_name).await.unwrap();
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
                    outs = ec2_manager
                        .describe_eips_by_tags(HashMap::from([
                            (String::from("Id"), spec.id.clone()),
                            (String::from("autoscaling:groupName"), asg_name.clone()),
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
        let f = File::open(&spec.resources.ec2_key_path).unwrap();
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
                spec.resources.ec2_key_path,
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ip_kind,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.ec2_key_path,
                instance_ip,
                //
                spec.resources.region,
                d.instance_id,
            );
        }
        println!();

        // wait for non anchor nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let mut objects: Vec<Object>;
        let target_nodes = spec.machine.non_anchor_nodes;
        loop {
            sleep(Duration::from_secs(30)).await;

            objects = s3_manager
                .list_objects(
                    &spec.resources.s3_bucket,
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
                "{} non-anchor nodes are bootstrapped and ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }

            if term.load(Ordering::Relaxed) {
                log::warn!("received signal {}", signal_hook::consts::SIGINT);
                println!();
                println!("# run the following to delete resources");
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

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let non_anchor_node =
                avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            created_nodes.push(non_anchor_node.clone());
        }

        s3_manager
            .put_object(
                &spec_file_path,
                &spec.resources.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");

        log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
        sleep(Duration::from_secs(20)).await;
    }

    spec.resources.created_nodes = Some(created_nodes.clone());
    spec.sync(spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: listing all node objects based on S3 keys...\n\n"),
        ResetColor
    )?;
    for node in created_nodes.iter() {
        println!("{}", node.encode_yaml().unwrap());
    }

    let mut rpc_hosts = if let Some(dns_name) = &spec.resources.cloudformation_asg_nlb_dns_name {
        vec![dns_name.clone()]
    } else {
        Vec::new()
    };
    let mut rpc_host_to_node = HashMap::new();
    for node in created_nodes.iter() {
        rpc_host_to_node.insert(node.public_ip.clone(), node.clone());
        rpc_hosts.push(node.public_ip.clone())
    }

    let http_port = spec.avalanchego_config.http_port;
    let nlb_https_enabled = spec.resources.nlb_acm_certificate_arn.is_some();
    let https_enabled = spec.avalanchego_config.http_tls_enabled.is_some()
        && spec.avalanchego_config.http_tls_enabled.unwrap();
    let (scheme_for_dns, port_for_dns) = {
        if nlb_https_enabled || https_enabled {
            ("https", 443)
        } else {
            ("http", http_port)
        }
    };

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
    let mut http_rpcs = Vec::new();
    let mut chain_rpc_urls = Vec::new();
    for host in rpc_hosts.iter() {
        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();
        http_rpcs.push(http_rpc.clone());

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
        spec.resources.created_endpoints = Some(endpoints.clone());
        println!(
            "{}",
            spec.resources
                .created_endpoints
                .clone()
                .unwrap()
                .encode_yaml()
                .unwrap()
        );

        chain_rpc_urls.push(format!("{http_rpc}/ext/bc/C/rpc"));
    }

    spec.sync(spec_file_path)?;
    s3_manager
        .put_object(
            &spec_file_path,
            &spec.resources.s3_bucket,
            &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
        )
        .await
        .expect("failed put_object ConfigFile");

    for http_rpc in http_rpcs.iter() {
        let mut success = false;
        for _ in 0..10_u8 {
            let ret = client_health::check(Arc::new(http_rpc.clone()), true).await;
            match ret {
                Ok(res) => {
                    if res.healthy {
                        success = true;
                        log::info!("health/liveness check success for {}", http_rpc);
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("health/liveness check failed for {} ({:?})", http_rpc, e);
                }
            };
            sleep(Duration::from_secs(10)).await;
        }
        if !success {
            log::warn!(
                "health/liveness check failed on {} for network id {}",
                http_rpc,
                &spec.avalanchego_config.network_id
            );
            return Err(Error::new(ErrorKind::Other, "health/liveness check failed"));
        }
    }

    let mut uris: Vec<String> = vec![];
    for node in created_nodes.iter() {
        let mut success = false;
        for _ in 0..10_u8 {
            let ret = client_health::check(Arc::new(node.http_endpoint.clone()), true).await;
            match ret {
                Ok(res) => {
                    if res.healthy {
                        success = true;
                        log::info!("health/liveness check success for {}", node.machine_id);
                        break;
                    }
                }
                Err(e) => {
                    log::warn!(
                        "health/liveness check failed for {} ({:?})",
                        node.machine_id,
                        e
                    );
                }
            };

            sleep(Duration::from_secs(10)).await;
        }
        if !success {
            log::warn!(
                "health/liveness check failed for network id {}",
                &spec.avalanchego_config.network_id
            );
            return Err(Error::new(ErrorKind::Other, "health/liveness check failed"));
        }
        println!("{}/ext/metrics", node.http_endpoint);
        println!("{}/ext/health", node.http_endpoint);
        println!("{}/ext/health/liveness", node.http_endpoint);
        uris.push(node.http_endpoint.clone());
    }
    println!("\nURIs: {}", uris.join(","));

    let mut all_node_ids = Vec::new();
    let mut all_instance_ids = Vec::new();
    let mut node_ids_to_instance_ids = HashMap::new();
    for node in created_nodes.iter() {
        let node_id = node.node_id.clone();
        let instance_id = node.machine_id.clone();

        all_node_ids.push(node_id.clone());
        all_instance_ids.push(instance_id.clone());

        node_ids_to_instance_ids.insert(node_id, instance_id);
    }

    // mainnet/fuji should not be done this automatic, must be done in a separate command
    if !spec.avalanchego_config.is_custom_network() {
        log::info!(
            "skipping installing subnets for network Id {}",
            spec.avalanchego_config.network_id
        );

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
            spec.resources.created_endpoints = Some(endpoints.clone());

            println!(
                "{}",
                spec.resources
                    .created_endpoints
                    .clone()
                    .unwrap()
                    .encode_yaml()
                    .unwrap()
            );
        }

        return Ok(());
    }

    println!();
    log::info!(
        "apply all success with node Ids {:?} and instance Ids {:?}",
        all_node_ids,
        all_instance_ids
    );

    println!();
    println!("# run the following to delete resources");
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

    println!();
    println!("# run the following to download the generated certificates");
    execute!(
        stdout(),
        SetForegroundColor(Color::Magenta),
        Print(format!(
            "aws --region {} s3 ls s3://{}/{}/pki/ --human-readable\n",
            spec.resources.region, spec.resources.s3_bucket, spec.id
        )),
        ResetColor
    )?;
    let kms_cmk_id = spec
        .resources
        .kms_cmk_symmetric_default_encrypt_key
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
--region={region} \\
--s3-bucket={s3_buckeet} \\
--s3-key-tls-key={id}/pki/{node_id}.key.zstd.encrypted \\
--s3-key-tls-cert={id}/pki/{node_id}.crt.zstd.encrypted \\
--kms-cmk-id={kms_cmk_id} \\
--aad-tag='{aad_tag}' \\
--tls-key-path=/tmp/{node_id}.key \\
--tls-cert-path=/tmp/{node_id}.crt

cat /tmp/{node_id}.crt
",
                exec_parent_dir = exec_parent_dir,
                region = spec.resources.region,
                s3_buckeet = spec.resources.s3_bucket,
                id = spec.id,
                kms_cmk_id = kms_cmk_id,
                aad_tag = spec.aad_tag,
                node_id = n.node_id,
            )),
            ResetColor
        )?;
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::DarkGreen),
        Print(format!(
            "
{exec_parent_dir}/blizzardup-aws \\
default-spec \\
--log-level=info \\
--funded-keys={funded_keys} \\
--region={region} \\
--upload-artifacts-blizzard-bin={exec_parent_dir}/blizzard-aws \\
--instance-mode=spot \\
--nodes=10 \\
--blizzard-log-level=info \\
--blizzard-chain-rpc-urls={blizzard_chain_rpc_urls} \\
--blizzard-keys-to-generate=100 \\
--blizzard-workers=10 \\
--blizzard-load-kinds=x-transfers,evm-transfers

",
            exec_parent_dir = exec_parent_dir,
            funded_keys = if let Some(keys) = &spec.prefunded_keys {
                keys.len()
            } else {
                1
            },
            region = spec.resources.region,
            blizzard_chain_rpc_urls = chain_rpc_urls.clone().join(","),
        )),
        ResetColor
    )?;

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating an SSM document for restarting node with tracked subnet subnet-evm...\n\n"),
        ResetColor
    )?;
    let ssm_doc_tmpl =
        avalanche_ops::aws::artifacts::ssm_doc_restart_node_tracked_subnet_subnet_evm_yaml()
            .unwrap();
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm
        .clone()
        .unwrap();
    let ssm_document_name_restart_tracked_subnet =
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeTrackedSubnetSubnetEvm(
            spec.id.clone(),
        )
        .encode();
    let cfn_params = Vec::from([build_param(
        "DocumentName",
        &ssm_document_name_restart_tracked_subnet,
    )]);
    cloudformation_manager
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
    sleep(Duration::from_secs(10)).await;
    cloudformation_manager
        .poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    log::info!("created ssm document for restarting node with tracked subnet");

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating an SSM document for restarting node to load chain config subnet-evm...\n\n"),
        ResetColor
    )?;
    let ssm_doc_tmpl =
        avalanche_ops::aws::artifacts::ssm_doc_restart_node_chain_config_subnet_evm_yaml().unwrap();
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm
        .clone()
        .unwrap();
    let ssm_document_name_restart_node_chain_config =
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeChainConfigSubnetEvm(spec.id.clone())
            .encode();
    let cfn_params = Vec::from([build_param(
        "DocumentName",
        &ssm_document_name_restart_node_chain_config,
    )]);
    cloudformation_manager
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
    sleep(Duration::from_secs(10)).await;
    cloudformation_manager
        .poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    log::info!("created ssm document for restarting node to load chain config");

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating an SSM document for restarting node with tracked subnet xsvm...\n\n"),
        ResetColor
    )?;
    let ssm_doc_tmpl =
        avalanche_ops::aws::artifacts::ssm_doc_restart_node_tracked_subnet_xsvm_yaml().unwrap();
    let ssm_doc_stack_name = spec
        .resources
        .cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm
        .clone()
        .unwrap();
    let ssm_document_name_restart_tracked_subnet =
        avalanche_ops::aws::spec::StackName::SsmDocRestartNodeTrackedSubnetXsvm(spec.id.clone())
            .encode();
    let cfn_params = Vec::from([build_param(
        "DocumentName",
        &ssm_document_name_restart_tracked_subnet,
    )]);
    cloudformation_manager
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
    sleep(Duration::from_secs(10)).await;
    cloudformation_manager
        .poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    log::info!("created ssm document for restarting node with tracked subnet");

    //
    //
    //
    //
    //
    let ki = spec.prefunded_keys.clone().unwrap()[0].clone();
    let priv_key =
        key::secp256k1::private_key::Key::from_cb58(ki.private_key_cb58.clone().unwrap())?;

    let wallet_to_spend = wallet::Builder::new(&priv_key)
        .base_http_urls(http_rpcs.clone())
        .build()
        .await
        .unwrap();

    //
    //
    //
    //
    //
    // add nodes as validators for the primary network
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as primary network validators...\n\n"),
        ResetColor
    )?;
    log::info!("adding all nodes as primary network validator");
    for node_id in all_node_ids.iter() {
        let (tx_id, added) = wallet_to_spend
            .p()
            .add_validator()
            .node_id(node::Id::from_str(node_id.as_str()).unwrap())
            .check_acceptance(true)
            .issue()
            .await
            .unwrap();
        log::info!("validator tx id {}, added {}", tx_id, added);
    }

    // maps subnet-evm blockchain id to its validator node Ids
    let mut subnet_evm_blockchain_ids = BTreeMap::new();
    if let Some(subnet_evms) = &spec.subnet_evms {
        println!();
        log::info!("non-empty subnet_evms and custom network, so install with test keys");
        println!();

        let mut tracked_subnets = Vec::new();
        for (subnet_evm_name, subnet_evm) in subnet_evms.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new subnet for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            let subnet_id = wallet_to_spend
                .p()
                .create_subnet()
                .dry_mode(true)
                .issue()
                .await
                .unwrap();
            log::info!("[dry mode] subnet Id '{}'", subnet_id);

            let created_subnet_id = wallet_to_spend
                .p()
                .create_subnet()
                .check_acceptance(true)
                .issue()
                .await
                .unwrap();
            log::info!("created subnet '{}' (still need track)", created_subnet_id);
            tracked_subnets.push(created_subnet_id.to_string());

            // must upload before restarting with SSM doc
            log::info!(
                "uploading avalancheup spec file with subnet-evm tracked subnets {:?}",
                tracked_subnets
            );
            let ss = tracked_subnets.join(",");
            log::info!("updated spec.avalanchego_config.track_subnets with {ss}");
            spec.avalanchego_config.track_subnets = Some(ss);
            spec.sync(spec_file_path)?;
            s3_manager
                .put_object(
                    &spec_file_path,
                    &spec.resources.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
            sleep(Duration::from_secs(5)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with tracked subnet subnet-evm...\n\n"),
                ResetColor
            )?;
            // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
            let ssm_output = ssm_manager
                .cli
                .send_command()
                .document_name(ssm_document_name_restart_tracked_subnet.clone())
                .set_instance_ids(Some(all_instance_ids.clone()))
                .parameters(
                    "vmId",
                    vec![String::from(
                        "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                    )],
                )
                .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                .parameters("subnetEvmName", vec![subnet_evm_name.clone()])
                .parameters("newTrackedSubnetId", vec![created_subnet_id.to_string()])
                .output_s3_region(spec.resources.region.clone())
                .output_s3_bucket_name(spec.resources.s3_bucket.clone())
                .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                .send()
                .await
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            sleep(Duration::from_secs(30)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = ssm_manager
                    .poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
            sleep(Duration::from_secs(5)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: adding selected nodes as subnet validator for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            for node_id in all_node_ids.iter() {
                wallet_to_spend
                    .p()
                    .add_subnet_validator()
                    .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                    .subnet_id(created_subnet_id)
                    .check_acceptance(true)
                    .issue()
                    .await
                    .unwrap();
            }
            log::info!("added subnet validators for {}", created_subnet_id);
            sleep(Duration::from_secs(5)).await;

            let subnet_evm_genesis_bytes = subnet_evm.genesis.to_bytes().unwrap();
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new blockchain for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            let blockchain_id = wallet_to_spend
                .p()
                .create_chain()
                .subnet_id(created_subnet_id)
                .genesis_data(subnet_evm_genesis_bytes.clone())
                .vm_id(
                    ids::Id::from_str("srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy").unwrap(),
                )
                .chain_name(String::from("subnetevm"))
                .dry_mode(true)
                .issue()
                .await
                .unwrap();
            log::info!("[dry mode] blockchain Id {}", blockchain_id);

            let blockchain_id = wallet_to_spend
                .p()
                .create_chain()
                .subnet_id(created_subnet_id)
                .genesis_data(subnet_evm_genesis_bytes)
                .vm_id(
                    ids::Id::from_str("srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy").unwrap(),
                )
                .chain_name(String::from("subnetevm"))
                .check_acceptance(true)
                .issue()
                .await
                .unwrap();
            log::info!("created a blockchain {blockchain_id} for subnet {subnet_id}");

            subnet_evm_blockchain_ids.insert(blockchain_id.to_string(), all_node_ids.clone());

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with chain config...\n\n"),
                ResetColor
            )?;
            // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
            let ssm_output = ssm_manager
                .cli
                .send_command()
                .document_name(ssm_document_name_restart_node_chain_config.clone())
                .set_instance_ids(Some(all_instance_ids.clone()))
                .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                .parameters("subnetEvmName", vec![subnet_evm_name.clone()])
                .parameters("newBlockchainId", vec![blockchain_id.to_string()])
                .output_s3_region(spec.resources.region.clone())
                .output_s3_bucket_name(spec.resources.s3_bucket.clone())
                .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                .send()
                .await
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            sleep(Duration::from_secs(30)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = ssm_manager
                    .poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
        }
    }

    // maps xsvm blockchain id to its validator node Ids
    let mut xsvm_blockchain_ids = BTreeMap::new();
    if let Some(xsvms) = &spec.xsvms {
        println!();
        log::info!("non-empty xsvms and custom network, so install with test keys");
        println!();

        for (xsvm_name, xsvm) in xsvms.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new subnet for xsvm {xsvm_name}...\n\n"
                )),
                ResetColor
            )?;
            let subnet_id = wallet_to_spend
                .p()
                .create_subnet()
                .dry_mode(true)
                .issue()
                .await
                .unwrap();
            log::info!("[dry mode] subnet Id '{}'", subnet_id);

            let created_subnet_id = wallet_to_spend
                .p()
                .create_subnet()
                .check_acceptance(true)
                .issue()
                .await
                .unwrap();
            log::info!("created subnet '{}' (still need track)", created_subnet_id);

            // must upload before restarting with SSM doc
            log::info!(
                "uploading avalancheup spec file with subnet-evm tracked subnets {:?}",
                spec.avalanchego_config.track_subnets
            );
            if let Some(s) = &spec.avalanchego_config.track_subnets {
                let ss = format!("{s},{}", created_subnet_id.to_string());
                log::info!("updated spec.avalanchego_config.track_subnets with {ss}");
                spec.avalanchego_config.track_subnets = Some(ss);
            } else {
                let ss = created_subnet_id.to_string();
                log::info!("updated spec.avalanchego_config.track_subnets with {ss}");
                spec.avalanchego_config.track_subnets = Some(ss);
            }
            spec.sync(spec_file_path)?;
            s3_manager
                .put_object(
                    &spec_file_path,
                    &spec.resources.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(spec.id.clone())
                        .encode(),
                )
                .await
                .unwrap();
            sleep(Duration::from_secs(5)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with tracked subnet xsvm...\n\n"),
                ResetColor
            )?;
            // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
            let ssm_output = ssm_manager
                .cli
                .send_command()
                .document_name(ssm_document_name_restart_tracked_subnet.clone())
                .set_instance_ids(Some(all_instance_ids.clone()))
                .parameters(
                    "vmId",
                    vec![String::from(
                        "v3m4wPxaHpvGr8qfMeyK6PRW3idZrPHmYcMTt7oXdK47yurVH",
                    )],
                )
                .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                .parameters("xsvmName", vec![xsvm_name.clone()])
                .parameters("newTrackedSubnetId", vec![created_subnet_id.to_string()])
                .output_s3_region(spec.resources.region.clone())
                .output_s3_bucket_name(spec.resources.s3_bucket.clone())
                .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                .send()
                .await
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            sleep(Duration::from_secs(30)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = ssm_manager
                    .poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
            sleep(Duration::from_secs(5)).await;

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: adding selected nodes as subnet validator for xsvm {xsvm_name}...\n\n"
                )),
                ResetColor
            )?;
            for node_id in all_node_ids.iter() {
                wallet_to_spend
                    .p()
                    .add_subnet_validator()
                    .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                    .subnet_id(created_subnet_id)
                    .check_acceptance(true)
                    .issue()
                    .await
                    .unwrap();
            }
            log::info!("added subnet validators for {}", created_subnet_id);
            sleep(Duration::from_secs(5)).await;

            // do not use JSON bytes
            let xsvm_genesis_bytes = xsvm.genesis.to_packer_bytes().unwrap();
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new blockchain for xsvm {xsvm_name}...\n\n"
                )),
                ResetColor
            )?;
            let blockchain_id = wallet_to_spend
                .p()
                .create_chain()
                .subnet_id(created_subnet_id)
                .genesis_data(xsvm_genesis_bytes.clone())
                .vm_id(
                    ids::Id::from_str("v3m4wPxaHpvGr8qfMeyK6PRW3idZrPHmYcMTt7oXdK47yurVH").unwrap(),
                )
                .chain_name(String::from("xsvm"))
                .dry_mode(true)
                .issue()
                .await
                .unwrap();
            log::info!("[dry mode] blockchain Id {}", blockchain_id);

            let blockchain_id = wallet_to_spend
                .p()
                .create_chain()
                .subnet_id(created_subnet_id)
                .genesis_data(xsvm_genesis_bytes)
                .vm_id(
                    ids::Id::from_str("v3m4wPxaHpvGr8qfMeyK6PRW3idZrPHmYcMTt7oXdK47yurVH").unwrap(),
                )
                .chain_name(String::from("xsvm"))
                .check_acceptance(true)
                .issue()
                .await
                .unwrap();
            log::info!("created a blockchain {blockchain_id} for subnet {subnet_id}");

            xsvm_blockchain_ids.insert(blockchain_id.to_string(), all_node_ids.clone());
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::DarkGreen),
        Print("\n\n\n\nSTEP: nodes are ready -- check the following endpoints!\n\n"),
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
        let node_id = if let Some(node) = rpc_host_to_node.get(host) {
            node.node_id.clone()
        } else {
            String::from("NLB DNS")
        };
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
        spec.resources.created_endpoints = Some(endpoints.clone());
        println!(
            "\n---\n{node_id}\n{}",
            spec.resources
                .created_endpoints
                .clone()
                .unwrap()
                .encode_yaml()
                .unwrap()
        );

        if !subnet_evm_blockchain_ids.is_empty() {
            println!();
        }
        for (subnet_evm_blockchain_id, node_ids) in subnet_evm_blockchain_ids.iter() {
            log::info!(
                "subnet-evm chain {subnet_evm_blockchain_id} validators: {:?}:",
                node_ids
            );
            if let Some(node) = rpc_host_to_node.get(host) {
                println!(
                    "\nsubnet-evm RPC for node '{}':\n{http_rpc}/ext/bc/{subnet_evm_blockchain_id}/rpc\n",
                    node.node_id
                );
            } else {
                println!(
                    "\n[NLB DNS] subnet-evm RPC for nodes '{:?}':\n{http_rpc}/ext/bc/{subnet_evm_blockchain_id}/rpc\n",
                    node_ids
                );
            }
        }

        if !xsvm_blockchain_ids.is_empty() {
            println!();
        }
        for (xsvm_blockchain_id, node_ids) in xsvm_blockchain_ids.iter() {
            log::info!(
                "xsvm chain {xsvm_blockchain_id} validators: {:?}:",
                node_ids
            );
            if !node_ids.contains(&node_id) {
                log::info!("{node_id} is not validating subnet chain {xsvm_blockchain_id}");
                continue;
            }

            if let Some(node) = rpc_host_to_node.get(host) {
                println!(
                    "\nxsvm RPC for node '{}':\n{http_rpc}/ext/bc/{xsvm_blockchain_id}\n",
                    node.node_id
                );
            } else {
                println!(
                    "\n[NLB DNS] xsvm RPC for nodes '{:?}':\n{http_rpc}/ext/bc/{xsvm_blockchain_id}\n",
                    node_ids
                );
            }
        }
    }

    for (subnet_evm_blockchain_id, node_ids) in subnet_evm_blockchain_ids.iter() {
        log::info!(
            "created subnet-evm with blockchain Id {subnet_evm_blockchain_id} in nodes {:?}",
            node_ids
        );
        let mut chain_rpc_urls = Vec::new();
        for http_rpc in http_rpcs.iter() {
            chain_rpc_urls.push(format!(
                "{http_rpc}/ext/bc/{}/rpc",
                subnet_evm_blockchain_id
            ));
        }
        execute!(
            stdout(),
            SetForegroundColor(Color::DarkGreen),
            Print(format!(
                "
{exec_parent_dir}/blizzardup-aws \\
default-spec \\
--log-level=info \\
--funded-keys={funded_keys} \\
--region={region} \\
--upload-artifacts-blizzard-bin={exec_parent_dir}/blizzard-aws \\
--instance-mode=spot \\
--nodes=10 \\
--blizzard-log-level=info \\
--blizzard-chain-rpc-urls={blizzard_chain_rpc_urls} \\
--blizzard-keys-to-generate=100 \\
--blizzard-workers=10 \\
--blizzard-load-kinds=x-transfers,evm-transfers
",
                exec_parent_dir = exec_parent_dir,
                funded_keys = if let Some(keys) = &spec.prefunded_keys {
                    keys.len()
                } else {
                    1
                },
                region = spec.resources.region,
                blizzard_chain_rpc_urls = chain_rpc_urls.clone().join(","),
            )),
            ResetColor
        )?;
    }
    println!();
    println!();

    Ok(())
}

fn build_param(k: &str, v: &str) -> Parameter {
    Parameter::builder()
        .parameter_key(k)
        .parameter_value(v)
        .build()
}
