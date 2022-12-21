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
    thread,
    time::Duration,
};

use avalanche_types::{
    client::{health as client_health, wallet},
    ids::{self, node},
    key,
};
use aws_manager::{
    self, cloudformation, ec2,
    kms::{self, envelope},
    s3, ssm, sts,
};
use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_s3::model::Object;
use aws_sdk_ssm::model::CommandInvocationStatus;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

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

pub fn execute(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    #[derive(RustEmbed)]
    #[folder = "cfn-templates/"]
    #[prefix = "cfn-templates/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = avalancheup_aws::spec::Spec::load(spec_file_path).expect("failed to load spec");
    spec.validate()?;

    let rt = Runtime::new().unwrap();

    let shared_config = rt
        .block_on(aws_manager::load_config(Some(
            spec.aws_resources.region.clone(),
        )))
        .expect("failed to aws_manager::load_config");

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
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
        spec.aws_resources.identity = Some(current_identity);
    }

    // set defaults based on ID
    if spec.aws_resources.ec2_key_name.is_none() {
        spec.aws_resources.ec2_key_name = Some(format!("{}-ec2-key", spec.id));
    }
    if spec
        .aws_resources
        .cloudformation_ec2_instance_role
        .is_none()
    {
        spec.aws_resources.cloudformation_ec2_instance_role =
            Some(avalancheup_aws::spec::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if spec.aws_resources.cloudformation_vpc.is_none() {
        spec.aws_resources.cloudformation_vpc =
            Some(avalancheup_aws::spec::StackName::Vpc(spec.id.clone()).encode());
    }
    if spec.avalanchego_config.is_custom_network()
        && spec.aws_resources.cloudformation_asg_anchor_nodes.is_none()
    {
        spec.aws_resources.cloudformation_asg_anchor_nodes =
            Some(avalancheup_aws::spec::StackName::AsgAnchorNodes(spec.id.clone()).encode());
    }
    if spec
        .aws_resources
        .cloudformation_asg_non_anchor_nodes
        .is_none()
    {
        spec.aws_resources.cloudformation_asg_non_anchor_nodes =
            Some(avalancheup_aws::spec::StackName::AsgNonAnchorNodes(spec.id.clone()).encode());
    }
    if spec
        .aws_resources
        .cloudwatch_avalanche_metrics_namespace
        .is_none()
    {
        spec.aws_resources.cloudwatch_avalanche_metrics_namespace =
            Some(format!("{}-avalanche", spec.id));
    }
    if spec.subnet_evms.is_some() {
        spec.aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet_subnet_evm = Some(
            avalancheup_aws::spec::StackName::SsmDocRestartNodeWhitelistSubnetSubnetEvm(
                spec.id.clone(),
            )
            .encode(),
        );
        spec.aws_resources
            .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm = Some(
            avalancheup_aws::spec::StackName::SsmDocRestartNodeChanConfigSubnetEvm(spec.id.clone())
                .encode(),
        );
    }
    if spec.xsvms.is_some() {
        spec.aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet_xsvm = Some(
            avalancheup_aws::spec::StackName::SsmDocRestartNodeWhitelistSubnetXsvm(spec.id.clone())
                .encode(),
        );
    }
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
    let ssm_cli = ssm_manager.client();

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))
        .expect("failed to register os signal");

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 buckets\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.create_bucket(&spec.aws_resources.s3_bucket))
        .unwrap();

    thread::sleep(Duration::from_secs(1));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: upload artifacts to S3 bucket\n"),
        ResetColor
    )?;

    if let Some(v) = &spec.install_artifacts.aws_volume_provisioner_local_bin {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(
            s3_manager.put_object(
                Arc::new(v.to_string()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::spec::StorageNamespace::AwsVolumeProvisionerBin(
                        spec.id.clone(),
                    )
                    .encode(),
                ),
            ),
        )
        .expect("failed put_object install_artifacts.aws_volume_provisioner_bin");
    } else {
        log::info!("skipping uploading aws_volume_provisioner_bin, will be downloaded on remote machines...");
    }

    if let Some(v) = &spec.install_artifacts.aws_ip_provisioner_local_bin {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(
            s3_manager.put_object(
                Arc::new(v.to_string()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::spec::StorageNamespace::AwsIpProvisionerBin(spec.id.clone())
                        .encode(),
                ),
            ),
        )
        .expect("failed put_object install_artifacts.aws_ip_provisioner_bin");
    } else {
        log::info!(
            "skipping uploading aws_ip_provisioner_bin, will be downloaded on remote machines..."
        );
    }

    if let Some(v) = &spec
        .install_artifacts
        .avalanche_telemetry_cloudwatch_local_bin
    {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(
            s3_manager.put_object(
                Arc::new(v.to_string()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::spec::StorageNamespace::AvalancheTelemetryCloudwatchBin(
                        spec.id.clone(),
                    )
                    .encode(),
                ),
            ),
        )
        .expect("failed put_object install_artifacts.avalanche_telemetry_cloudwatch_bin");
    } else {
        log::info!(
            "skipping uploading avalanche_telemetry_cloudwatch_bin, will be downloaded on remote machines..."
        );
    }

    if let Some(v) = &spec.install_artifacts.avalanche_config_local_bin {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(
            s3_manager.put_object(
                Arc::new(v.to_string()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::spec::StorageNamespace::AvalancheConfigBin(spec.id.clone())
                        .encode(),
                ),
            ),
        )
        .expect("failed put_object install_artifacts.avalanche_config_bin");
    } else {
        log::info!(
            "skipping uploading avalanche_config_bin, will be downloaded on remote machines..."
        );
    }

    if let Some(v) = &spec.install_artifacts.avalanched_local_bin {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(s3_manager.put_object(
            Arc::new(v.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(
                avalancheup_aws::spec::StorageNamespace::AvalanchedBin(spec.id.clone()).encode(),
            ),
        ))
        .expect("failed put_object install_artifacts.avalanched_bin");
    } else {
        log::info!("skipping uploading avalanched_bin, will be downloaded on remote machines...");
    }

    if let Some(avalanchego_bin) = &spec.install_artifacts.avalanchego_local_bin {
        // upload without compression first
        rt.block_on(s3_manager.put_object(
            Arc::new(avalanchego_bin.clone()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(
                avalancheup_aws::spec::StorageNamespace::AvalancheBin(spec.id.clone()).encode(),
            ),
        ))
        .expect("failed put_object avalanchego_bin");
    } else {
        log::info!("skipping uploading avalanchego_bin, will be downloaded on remote machines...");
    }

    if spec.install_artifacts.plugins_local_dir.is_some() {
        let plugins_dir = spec.install_artifacts.plugins_local_dir.clone().unwrap();
        for entry in fs::read_dir(plugins_dir.as_str()).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            log::info!(
                "uploading {} from plugins directory {}",
                file_path,
                plugins_dir,
            );
            rt.block_on(s3_manager.put_object(
                Arc::new(file_path.to_string()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(format!(
                    "{}/{}",
                    &avalancheup_aws::spec::StorageNamespace::PluginsDir(spec.id.clone()).encode(),
                    file_name,
                )),
            ))
            .expect("failed put_object file_path");
        }
    } else {
        log::info!("skipping uploading plugin dir...");
    }

    log::info!("uploading avalancheup spec file...");
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(spec.aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
    ))
    .unwrap();

    if spec
        .aws_resources
        .kms_cmk_symmetric_default_encrypt_key
        .is_none()
    {
        thread::sleep(Duration::from_secs(1));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )?;

        let key = rt
            .block_on(kms_manager.create_symmetric_default_key(format!("{}-cmk", spec.id).as_str()))
            .unwrap();

        spec.aws_resources.kms_cmk_symmetric_default_encrypt_key =
            Some(avalancheup_aws::aws::KmsCmk {
                id: key.id,
                arn: key.arn,
            });
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }
    let envelope_manager = envelope::Manager::new(
        kms_manager,
        spec.aws_resources
            .kms_cmk_symmetric_default_encrypt_key
            .clone()
            .unwrap()
            .id,
        "avalanche-ops".to_string(),
    );

    if spec.aws_resources.ec2_key_path.is_none() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = get_ec2_key_path(spec_file_path);
        rt.block_on(ec2_manager.create_key_pair(
            spec.aws_resources.ec2_key_name.clone().unwrap().as_str(),
            ec2_key_path.as_str(),
        ))
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
        rt.block_on(envelope_manager.seal_aes_256_file(
            Arc::new(tmp_compressed_path),
            Arc::new(tmp_encrypted_path.clone()),
        ))
        .unwrap();
        rt.block_on(
            s3_manager.put_object(
                Arc::new(tmp_encrypted_path),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::spec::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
                        spec.id.clone(),
                    )
                    .encode(),
                ),
            ),
        )
        .unwrap();

        spec.aws_resources.ec2_key_path = Some(ec2_key_path);
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    if let Some(metrics_rules) = &spec.prometheus_metrics_rules {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: uploading metrics rules\n"),
            ResetColor
        )?;

        let metrics_rules_file_path = random_manager::tmp_path(10, None).unwrap();
        metrics_rules.sync(&metrics_rules_file_path).unwrap();
        rt.block_on(s3_manager.put_object(
            Arc::new(metrics_rules_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(
                avalancheup_aws::spec::StorageNamespace::MetricsRules(spec.id.clone()).encode(),
            ),
        ))
        .unwrap();
    }

    if spec
        .aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_yaml = Asset::get("cfn-templates/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name = spec
            .aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        let role_params = Vec::from([
            build_param("Id", &spec.id),
            build_param(
                "KmsCmkArn",
                &spec
                    .aws_resources
                    .kms_cmk_symmetric_default_encrypt_key
                    .clone()
                    .unwrap()
                    .arn,
            ),
            build_param("S3BucketName", &spec.aws_resources.s3_bucket),
        ]);
        rt.block_on(cloudformation_manager.create_stack(
            ec2_instance_role_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ec2_instance_role_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(role_params),
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
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("InstanceProfileArn") {
                spec.aws_resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    if spec.aws_resources.cloudformation_vpc_id.is_none()
        && spec
            .aws_resources
            .cloudformation_vpc_security_group_id
            .is_none()
        && spec
            .aws_resources
            .cloudformation_vpc_public_subnet_ids
            .is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cfn-templates/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = spec.aws_resources.cloudformation_vpc.clone().unwrap();
        let vpc_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("IngressIpv4Range", "0.0.0.0/0"),
            build_param(
                "StakingPort",
                format!("{}", spec.avalanchego_config.staking_port).as_str(),
            ),
            build_param(
                "HttpPort",
                format!("{}", spec.avalanchego_config.http_port).as_str(),
            ),
        ]);
        rt.block_on(cloudformation_manager.create_stack(
            vpc_stack_name.as_str(),
            None,
            OnFailure::Delete,
            vpc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(vpc_params),
        ))
        .expect("failed create_stack for VPC");

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ))
            .expect("failed poll_stack for VPC");

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("VpcId") {
                spec.aws_resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                spec.aws_resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    log::info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                spec.aws_resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    let mut asg_parameters = Vec::from([
        build_param("Id", &spec.id),
        build_param(
            "NetworkId",
            format!("{}", &spec.avalanchego_config.network_id).as_str(),
        ),
        build_param(
            "KmsCmkArn",
            &spec
                .aws_resources
                .kms_cmk_symmetric_default_encrypt_key
                .clone()
                .unwrap()
                .arn,
        ),
        build_param("AadTag", &spec.aad_tag),
        build_param("S3BucketName", &spec.aws_resources.s3_bucket),
        build_param(
            "Ec2KeyPairName",
            &spec.aws_resources.ec2_key_name.clone().unwrap(),
        ),
        build_param(
            "InstanceProfileArn",
            &spec
                .aws_resources
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        ),
        build_param(
            "SecurityGroupId",
            &spec
                .aws_resources
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        ),
        build_param(
            "NlbVpcId",
            &spec.aws_resources.cloudformation_vpc_id.clone().unwrap(),
        ),
        build_param(
            "NlbHttpPort",
            format!("{}", spec.avalanchego_config.http_port).as_str(),
        ),
    ]);

    asg_parameters.push(build_param(
        "VolumeSize",
        format!("{}", spec.machine.volume_size_in_gb).as_str(),
    ));

    asg_parameters.push(build_param("Arch", &spec.machine.arch));
    if !spec.machine.instance_types.is_empty() {
        let instance_types = spec.machine.instance_types.clone();
        asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
        asg_parameters.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    let aws_volume_provisioner_download_source = if spec
        .install_artifacts
        .aws_volume_provisioner_bin_install_from_s3
        .unwrap_or_default()
    {
        "s3"
    } else {
        "github"
    };
    asg_parameters.push(build_param(
        "VolumeProvisionerDownloadSource",
        aws_volume_provisioner_download_source,
    ));

    let aws_ip_provisioner_download_source = if spec
        .install_artifacts
        .aws_ip_provisioner_bin_install_from_s3
        .unwrap_or_default()
    {
        "s3"
    } else {
        "github"
    };
    asg_parameters.push(build_param(
        "IpProvisionerDownloadSource",
        aws_ip_provisioner_download_source,
    ));

    let avalanche_telemetry_cloudwatch_download_source = if spec
        .install_artifacts
        .avalanche_telemetry_cloudwatch_bin_install_from_s3
        .unwrap_or_default()
    {
        "s3"
    } else {
        "github"
    };
    asg_parameters.push(build_param(
        "AvalancheTelemetryCloudwatchDownloadSource",
        avalanche_telemetry_cloudwatch_download_source,
    ));

    let avalanche_config_download_source = if spec
        .install_artifacts
        .avalanche_config_bin_install_from_s3
        .unwrap_or_default()
    {
        "s3"
    } else {
        "github"
    };
    asg_parameters.push(build_param(
        "AvalancheConfigDownloadSource",
        avalanche_config_download_source,
    ));

    let avalanched_download_source = if spec
        .install_artifacts
        .avalanched_bin_install_from_s3
        .unwrap_or_default()
    {
        "s3"
    } else {
        "github"
    };
    asg_parameters.push(build_param(
        "AvalanchedDownloadSource",
        avalanched_download_source,
    ));

    asg_parameters.push(build_param(
        "AvalanchedFlag",
        &spec.avalanched_config.to_flags(),
    ));

    let public_subnet_ids = spec
        .aws_resources
        .cloudformation_vpc_public_subnet_ids
        .clone()
        .unwrap();

    // TODO: support bootstrap from existing DB for anchor nodes
    let mut created_nodes: Vec<avalancheup_aws::spec::Node> = Vec::new();

    if spec.machine.anchor_nodes.unwrap_or(0) > 0
        && spec
            .aws_resources
            .cloudformation_asg_anchor_nodes_logical_id
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

        // TODO: support other platforms
        let cloudformation_asg_anchor_nodes_yaml =
            Asset::get("cfn-templates/asg_amd64_ubuntu.yaml").unwrap();
        let cloudformation_asg_anchor_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_anchor_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_anchor_nodes_stack_name = spec
            .aws_resources
            .cloudformation_asg_anchor_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.anchor_nodes.unwrap();

        // must deep-copy as shared with other node kind
        let mut asg_anchor_params = asg_parameters.clone();
        asg_anchor_params.push(build_param("NodeKind", "anchor"));

        if let Some(anchor_nodes) = &spec.machine.anchor_nodes {
            if *anchor_nodes == 1 {
                asg_anchor_params.push(build_param(
                    "VolumeProvisionerInitialWaitRandomSeconds",
                    "10",
                ));

                log::info!(
                    "using single subnet {} for {} anchor node",
                    public_subnet_ids[spec.aws_resources.preferred_az_index],
                    *anchor_nodes
                );
                asg_anchor_params.push(build_param(
                    "PublicSubnetIds",
                    &public_subnet_ids[spec.aws_resources.preferred_az_index],
                ));
            } else if *anchor_nodes == 2 {
                asg_anchor_params.push(build_param(
                    "VolumeProvisionerInitialWaitRandomSeconds",
                    "20",
                ));

                log::info!(
                    "using two subnets {} and {} for {} anchor nodes",
                    public_subnet_ids[0],
                    public_subnet_ids[1],
                    *anchor_nodes
                );
                asg_anchor_params.push(build_param(
                    "PublicSubnetIds",
                    &public_subnet_ids[..2].join(","),
                ));
            } else {
                asg_anchor_params.push(build_param(
                    "VolumeProvisionerInitialWaitRandomSeconds",
                    "200",
                ));

                log::info!(
                    "using multiple subnets {:?} for {} anchor nodes",
                    public_subnet_ids,
                    *anchor_nodes
                );
                asg_anchor_params
                    .push(build_param("PublicSubnetIds", &public_subnet_ids.join(",")));
            }
        }

        let is_spot_instance = spec.machine.instance_mode == String::from("spot")
            && !spec.machine.disable_spot_instance_for_anchor_nodes;
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        asg_anchor_params.push(build_param(
            "InstanceMode",
            if is_spot_instance {
                "spot"
            } else {
                "on-demand"
            },
        ));
        asg_anchor_params.push(build_param("IpMode", &spec.machine.ip_mode));
        asg_anchor_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        asg_anchor_params.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        // for CFN template updates
        // ref. "Temporarily setting autoscaling group MinSize and DesiredCapacity to 2."
        // ref. "Rolling update initiated. Terminating 1 obsolete instance(s) in batches of 1, while keeping at least 1 instance(s) in service."
        asg_anchor_params.push(build_param(
            "AsgMaxSize",
            format!("{}", desired_capacity + 1).as_str(),
        ));

        if spec.aws_resources.nlb_acm_certificate_arn.is_some() {
            asg_anchor_params.push(build_param(
                "NlbAcmCertificateArn",
                &spec.aws_resources.nlb_acm_certificate_arn.clone().unwrap(),
            ));
        };

        if spec.enable_nlb {
            asg_anchor_params.push(build_param("NlbEnabled", "true"));
        } else {
            asg_anchor_params.push(build_param("NlbEnabled", "false"));
        }

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_anchor_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_anchor_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(asg_anchor_params),
        ))
        .unwrap();

        // add 5-minute for ELB creation + volume provisioner
        let mut wait_secs = 700 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(60));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_anchor_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                spec.aws_resources
                    .cloudformation_asg_anchor_nodes_logical_id = Some(v);
                continue;
            }
            if k.eq("NlbArn") {
                spec.aws_resources.cloudformation_asg_nlb_arn = Some(v);
                continue;
            }
            if k.eq("NlbTargetGroupArn") {
                spec.aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                continue;
            }
            if k.eq("NlbDnsName") {
                spec.aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                continue;
            }
        }
        if spec
            .aws_resources
            .cloudformation_asg_anchor_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_anchor_nodes_logical_id not found",
            ));
        }
        if spec.aws_resources.cloudformation_asg_nlb_arn.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_arn not found",
                ));
            }
        }
        if spec
            .aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if spec.aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
            if !spec.enable_nlb {
                log::info!("NLB is disabled so empty NLB DNS name...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }

        let asg_name = spec
            .aws_resources
            .cloudformation_asg_anchor_nodes_logical_id
            .clone()
            .unwrap();

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let target_nodes = spec.machine.anchor_nodes.unwrap();
        for _ in 0..20 {
            // TODO: better retries
            log::info!(
                "fetching all droplets for anchor-node SSH access (target nodes {})",
                target_nodes
            );
            droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
            if (droplets.len() as u32) >= target_nodes {
                break;
            }
            log::info!(
                "retrying fetching all droplets (only got {})",
                droplets.len()
            );
            thread::sleep(Duration::from_secs(30));
        }

        let mut eips = Vec::new();
        if spec.machine.ip_mode == String::from("elastic") {
            log::info!("using elastic IPs... wait more");
            loop {
                eips = rt
                    .block_on(ec2_manager.describe_eips_by_tags(HashMap::from([(
                        String::from("Id"),
                        spec.id.clone(),
                    )])))
                    .unwrap();

                log::info!("got {} EIP addresses", eips.len());

                let mut ready = true;
                for eip_addr in eips.iter() {
                    ready = ready && eip_addr.instance_id.is_some();
                }
                if ready && eips.len() == target_nodes as usize {
                    break;
                }

                thread::sleep(Duration::from_secs(30));
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

        let ec2_key_path = spec.aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
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
                ec2_key_path,
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ip_kind,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                spec.aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        // wait for anchor nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(
                    s3_manager.list_objects(
                        Arc::new(spec.aws_resources.s3_bucket.clone()),
                        Some(Arc::new(s3::append_slash(
                            &avalancheup_aws::spec::StorageNamespace::DiscoverReadyAnchorNodesDir(
                                spec.id.clone(),
                            )
                            .encode(),
                        ))),
                    ),
                )
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
                avalancheup_aws::spec::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            created_nodes.push(anchor_node.clone());
        }

        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();

        log::info!("waiting for anchor nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(15));
    }

    if spec
        .aws_resources
        .cloudformation_asg_non_anchor_nodes_logical_id
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

        let cloudformation_asg_non_anchor_nodes_yaml =
            Asset::get("cfn-templates/asg_amd64_ubuntu.yaml").unwrap();
        let cloudformation_asg_non_anchor_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_non_anchor_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_non_anchor_nodes_stack_name = spec
            .aws_resources
            .cloudformation_asg_non_anchor_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.non_anchor_nodes;

        // we did not create anchor nodes for mainnet/* nodes
        // so no nlb creation before
        // we create here for non-anchor nodes
        let need_to_create_nlb = spec
            .aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none();

        // must deep-copy as shared with other node kind
        let mut asg_non_anchor_params = asg_parameters.clone();
        asg_non_anchor_params.push(build_param("NodeKind", "non-anchor"));

        // no competing volume provisioner in the same zone
        // TODO: if one manually updates the capacity,
        // this value is not valid... may cause contentions in EBS volume provision
        if spec.machine.non_anchor_nodes == 1 {
            asg_non_anchor_params.push(build_param(
                "VolumeProvisionerInitialWaitRandomSeconds",
                "10",
            ));

            log::info!(
                "using single subnet {} for 1 non-anchor node",
                public_subnet_ids[spec.aws_resources.preferred_az_index],
            );
            asg_non_anchor_params.push(build_param(
                "PublicSubnetIds",
                &public_subnet_ids[spec.aws_resources.preferred_az_index],
            ));
        } else if spec.machine.non_anchor_nodes == 2 {
            asg_non_anchor_params.push(build_param(
                "VolumeProvisionerInitialWaitRandomSeconds",
                "20",
            ));

            log::info!(
                "using two subnets {} and {} for {} non-anchor nodes",
                public_subnet_ids[0],
                public_subnet_ids[1],
                spec.machine.non_anchor_nodes
            );
            asg_non_anchor_params.push(build_param(
                "PublicSubnetIds",
                &public_subnet_ids[..2].join(","),
            ));
        } else {
            asg_non_anchor_params.push(build_param(
                "VolumeProvisionerInitialWaitRandomSeconds",
                "200",
            ));

            log::info!(
                "using multiple subnets {:?} for {} non-anchor nodes",
                public_subnet_ids,
                spec.machine.non_anchor_nodes
            );
            asg_non_anchor_params
                .push(build_param("PublicSubnetIds", &public_subnet_ids.join(",")));
        }

        let is_spot_instance = spec.machine.instance_mode == String::from("spot");
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        asg_non_anchor_params.push(build_param("InstanceMode", &spec.machine.instance_mode));
        asg_non_anchor_params.push(build_param("IpMode", &spec.machine.ip_mode));
        asg_non_anchor_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        asg_non_anchor_params.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        // for CFN template updates
        // ref. "Temporarily setting autoscaling group MinSize and DesiredCapacity to 2."
        // ref. "Rolling update initiated. Terminating 1 obsolete instance(s) in batches of 1, while keeping at least 1 instance(s) in service."
        asg_non_anchor_params.push(build_param(
            "AsgMaxSize",
            format!("{}", desired_capacity + 1).as_str(),
        ));

        if !spec.enable_nlb {
            asg_non_anchor_params.push(build_param("NlbEnabled", "false"));
        } else {
            asg_non_anchor_params.push(build_param("NlbEnabled", "true"));
            if need_to_create_nlb {
                if spec.aws_resources.nlb_acm_certificate_arn.is_some() {
                    asg_non_anchor_params.push(build_param(
                        "NlbAcmCertificateArn",
                        &spec.aws_resources.nlb_acm_certificate_arn.clone().unwrap(),
                    ));
                };
            } else {
                // NLB already created for anchor nodes
                asg_non_anchor_params.push(build_param(
                    "NlbTargetGroupArn",
                    &spec
                        .aws_resources
                        .cloudformation_asg_nlb_target_group_arn
                        .clone()
                        .unwrap(),
                ));
            }
        }

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_non_anchor_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_non_anchor_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(asg_non_anchor_params),
        ))
        .unwrap();

        // add 5-minute for ELB creation + volume provisioner
        let mut wait_secs = 700 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(60));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_non_anchor_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                spec.aws_resources
                    .cloudformation_asg_non_anchor_nodes_logical_id = Some(v);
                continue;
            }
            if need_to_create_nlb {
                if k.eq("NlbArn") {
                    spec.aws_resources.cloudformation_asg_nlb_arn = Some(v);
                    continue;
                }
                if k.eq("NlbTargetGroupArn") {
                    spec.aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                    continue;
                }
                if k.eq("NlbDnsName") {
                    spec.aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                    continue;
                }
            }
        }
        if spec
            .aws_resources
            .cloudformation_asg_non_anchor_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_non_anchor_nodes_logical_id not found",
            ));
        }
        if need_to_create_nlb {
            if spec.aws_resources.cloudformation_asg_nlb_arn.is_none() {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_arn not found",
                    ));
                }
            }
            if spec
                .aws_resources
                .cloudformation_asg_nlb_target_group_arn
                .is_none()
            {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB target group ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                    ));
                }
            }
            if spec.aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
                if !spec.enable_nlb {
                    log::info!("NLB is disabled so empty NLB DNS name...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_dns_name not found",
                    ));
                }
            }
        }
        spec.sync(spec_file_path)?;

        let asg_name = spec
            .aws_resources
            .cloudformation_asg_non_anchor_nodes_logical_id
            .clone()
            .expect("unexpected None cloudformation_asg_non_anchor_nodes_logical_id");

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let target_nodes = spec.machine.non_anchor_nodes;
        for _ in 0..20 {
            // TODO: better retries
            log::info!(
                "fetching all droplets for non-anchor node SSH access (target nodes {})",
                target_nodes
            );
            droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
            if (droplets.len() as u32) >= target_nodes {
                break;
            }
            log::info!(
                "retrying fetching all droplets (only got {})",
                droplets.len()
            );
            thread::sleep(Duration::from_secs(30));
        }

        let mut eips = Vec::new();
        if spec.machine.ip_mode == String::from("elastic") {
            log::info!("using elastic IPs... wait more");
            loop {
                eips = rt
                    .block_on(ec2_manager.describe_eips_by_tags(HashMap::from([(
                        String::from("Id"),
                        spec.id.clone(),
                    )])))
                    .unwrap();

                log::info!("got {} EIP addresses", eips.len());

                let mut ready = true;
                for eip_addr in eips.iter() {
                    ready = ready && eip_addr.instance_id.is_some();
                }
                if ready
                    && eips.len()
                        >= spec.machine.anchor_nodes.unwrap_or(0) as usize
                            + spec.machine.non_anchor_nodes as usize
                {
                    break;
                }

                thread::sleep(Duration::from_secs(30));
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

        let ec2_key_path = spec.aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
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
                ec2_key_path,
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ip_kind,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                ec2_key_path,
                instance_ip,
                //
                spec.aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        let s3_dir = avalancheup_aws::spec::StorageNamespace::DiscoverReadyNonAnchorNodesDir(
            spec.id.clone(),
        );

        // wait for non-anchor nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(s3_manager.list_objects(
                    Arc::new(spec.aws_resources.s3_bucket.clone()),
                    Some(Arc::new(s3::append_slash(&s3_dir.encode()))),
                ))
                .unwrap();
            log::info!(
                "{} non-anchor nodes are ready (expecting {} nodes)",
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
                avalancheup_aws::spec::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            created_nodes.push(non_anchor_node.clone());
        }

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .expect("failed put_object ConfigFile");

        log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }

    spec.created_nodes = Some(created_nodes.clone());
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

    let mut rpc_hosts = if let Some(dns_name) = &spec.aws_resources.cloudformation_asg_nlb_dns_name
    {
        vec![dns_name.clone()]
    } else {
        Vec::new()
    };
    let mut rpc_hosts_to_nodes = HashMap::new();
    for node in created_nodes.iter() {
        rpc_hosts_to_nodes.insert(node.public_ip.clone(), node.clone());
        rpc_hosts.push(node.public_ip.clone())
    }

    let http_port = spec.avalanchego_config.http_port;
    let nlb_https_enabled = spec.aws_resources.nlb_acm_certificate_arn.is_some();
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
    for host in rpc_hosts.iter() {
        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();
        http_rpcs.push(http_rpc.clone());

        let mut endpoints = avalancheup_aws::spec::Endpoints::default();
        endpoints.http_rpc = Some(http_rpc.clone());
        endpoints.http_rpc_x = Some(format!("{http_rpc}/ext/bc/X"));
        endpoints.http_rpc_p = Some(format!("{http_rpc}/ext/bc/P"));
        endpoints.http_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.metrics = Some(format!("{http_rpc}/ext/metrics"));
        endpoints.health = Some(format!("{http_rpc}/ext/health"));
        endpoints.liveness = Some(format!("{http_rpc}/ext/health/liveness"));
        endpoints.metamask_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.websocket_rpc_c = Some(format!("ws://{host}:{port_for_dns}/ext/bc/C/ws"));
        spec.created_endpoints = Some(endpoints.clone());
        println!(
            "{}",
            spec.created_endpoints
                .clone()
                .unwrap()
                .encode_yaml()
                .unwrap()
        );
    }

    spec.sync(spec_file_path)?;
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(spec.aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::spec::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
    ))
    .expect("failed put_object ConfigFile");

    for http_rpc in http_rpcs.iter() {
        let mut success = false;
        for _ in 0..10_u8 {
            let ret = rt.block_on(client_health::check(Arc::new(http_rpc.clone()), true));
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
            thread::sleep(Duration::from_secs(10));
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
            let ret = rt.block_on(client_health::check(
                Arc::new(node.http_endpoint.clone()),
                true,
            ));
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

            thread::sleep(Duration::from_secs(10));
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
            spec.aws_resources.region, spec.aws_resources.s3_bucket, spec.id
        )),
        ResetColor
    )?;
    let kms_cmk_id = spec
        .aws_resources
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
                region = spec.aws_resources.region,
                s3_buckeet = spec.aws_resources.s3_bucket,
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
--install-artifacts-blizzard-bin={exec_parent_dir}/blizzard-aws \\
--instance-mode=spot \\
--network-id={network_id} \\
--nodes=10 \\
--blizzard-log-level=info \\
--blizzard-http-rpcs={blizzard_http_rpcs} \\
--blizzard-keys-to-generate=100 \\
--blizzard-workers=100 \\
--blizzard-load-kinds=x-transfers,c-transfers
",
            exec_parent_dir = exec_parent_dir,
            funded_keys = if let Some(keys) = &spec.test_key_infos {
                keys.len()
            } else {
                1
            },
            region = spec.aws_resources.region,
            network_id = spec.avalanchego_config.network_id,
            blizzard_http_rpcs = http_rpcs.clone().join(","),
        )),
        ResetColor
    )?;

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

            let mut endpoints = avalancheup_aws::spec::Endpoints::default();
            endpoints.http_rpc = Some(http_rpc.clone());
            endpoints.http_rpc_x = Some(format!("{http_rpc}/ext/bc/X"));
            endpoints.http_rpc_p = Some(format!("{http_rpc}/ext/bc/P"));
            endpoints.http_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
            endpoints.metrics = Some(format!("{http_rpc}/ext/metrics"));
            endpoints.health = Some(format!("{http_rpc}/ext/health"));
            endpoints.liveness = Some(format!("{http_rpc}/ext/health/liveness"));
            endpoints.metamask_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
            endpoints.websocket_rpc_c = Some(format!("ws://{host}:{port_for_dns}/ext/bc/C/ws"));
            spec.created_endpoints = Some(endpoints.clone());

            println!(
                "{}",
                spec.created_endpoints
                    .clone()
                    .unwrap()
                    .encode_yaml()
                    .unwrap()
            );
        }

        return Ok(());
    }

    // TODO: support KMS CMK
    assert!(spec.test_key_infos.is_some());
    let test_key_info = spec.test_key_infos.clone().unwrap()[0].clone();
    let test_key_pk = key::secp256k1::private_key::Key::from_cb58(
        test_key_info.private_key_cb58.clone().unwrap(),
    )?;

    let wallet_to_spend = rt
        .block_on(
            wallet::Builder::new(&test_key_pk)
                .http_rpcs(http_rpcs.clone())
                .build(),
        )
        .unwrap();

    // add nodes as validators for the primary network
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as primary network validators...\n\n"),
        ResetColor
    )?;
    log::info!("adding all nodes as primary network validator");
    for node_id in all_node_ids.iter() {
        let (tx_id, added) = rt
            .block_on(
                wallet_to_spend
                    .p()
                    .add_validator()
                    .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                    .check_acceptance(true)
                    .issue(),
            )
            .unwrap();
        log::info!("validator tx id {}, added {}", tx_id, added);
    }

    // maps subnet-evm blockchain id to its validator node Ids
    let mut subnet_evm_blockchain_ids = BTreeMap::new();
    if let Some(subnet_evms) = &spec.subnet_evms {
        println!();
        log::info!("non-empty subnet_evms and custom network, so install with test keys");
        println!();

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: creating an SSM document for restarting node with whitelisted subnet subnet-evm...\n\n"),
            ResetColor
        )?;
        let ssm_doc_yaml =
            Asset::get("cfn-templates/ssm_doc_restart_node_whitelist_subnet_subnet_evm.yaml")
                .unwrap();
        let ssm_doc_tmpl = std::str::from_utf8(ssm_doc_yaml.data.as_ref()).unwrap();
        let ssm_doc_stack_name = spec
            .aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet_subnet_evm
            .clone()
            .unwrap();
        let ssm_document_name_restart_whitelist_subnet =
            avalancheup_aws::spec::StackName::SsmDocRestartNodeWhitelistSubnetSubnetEvm(
                spec.id.clone(),
            )
            .encode();
        let cfn_params = Vec::from([build_param(
            "DocumentName",
            &ssm_document_name_restart_whitelist_subnet,
        )]);
        rt.block_on(cloudformation_manager.create_stack(
            ssm_doc_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ssm_doc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(cfn_params),
        ))
        .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
        log::info!("created ssm document for restarting node with whitelisted subnet");

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: creating an SSM document for restarting node to load chain config subnet-evm...\n\n"),
            ResetColor
        )?;
        let ssm_doc_yaml =
            Asset::get("cfn-templates/ssm_doc_restart_node_chain_config_subnet_evm.yaml").unwrap();
        let ssm_doc_tmpl = std::str::from_utf8(ssm_doc_yaml.data.as_ref()).unwrap();
        let ssm_doc_stack_name = spec
            .aws_resources
            .cloudformation_ssm_doc_restart_node_chain_config_subnet_evm
            .clone()
            .unwrap();
        let ssm_document_name_restart_node_chain_config =
            avalancheup_aws::spec::StackName::SsmDocRestartNodeChanConfigSubnetEvm(spec.id.clone())
                .encode();
        let cfn_params = Vec::from([build_param(
            "DocumentName",
            &ssm_document_name_restart_node_chain_config,
        )]);
        rt.block_on(cloudformation_manager.create_stack(
            ssm_doc_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ssm_doc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(cfn_params),
        ))
        .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
        log::info!("created ssm document for restarting node to load chain config");

        for (subnet_evm_name, subnet_evm) in subnet_evms.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new subnet for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            let subnet_id = rt
                .block_on(wallet_to_spend.p().create_subnet().dry_mode(true).issue())
                .unwrap();
            log::info!("[dry mode] subnet Id '{}'", subnet_id);

            let created_subnet_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_subnet()
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            log::info!(
                "created subnet '{}' (still need whitelist)",
                created_subnet_id
            );
            thread::sleep(Duration::from_secs(5));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with whitelisted subnet subnet-evm...\n\n"),
                ResetColor
            )?;
            // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
            let ssm_output = rt
                .block_on(
                    ssm_cli
                        .send_command()
                        .document_name(ssm_document_name_restart_whitelist_subnet.clone())
                        .set_instance_ids(Some(all_instance_ids.clone()))
                        .parameters(
                            "vmId",
                            vec![String::from(
                                "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                            )],
                        )
                        .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                        .parameters("subnetEvmName", vec![subnet_evm_name.clone()])
                        .parameters(
                            "newWhitelistedSubnetId",
                            vec![created_subnet_id.to_string()],
                        )
                        .output_s3_region(spec.aws_resources.region.clone())
                        .output_s3_bucket_name(spec.aws_resources.s3_bucket.clone())
                        .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                        .send(),
                )
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            thread::sleep(Duration::from_secs(30));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = rt
                    .block_on(ssm_manager.poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    ))
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
            thread::sleep(Duration::from_secs(5));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: adding selected nodes as subnet validator for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            for node_id in all_node_ids.iter() {
                rt.block_on(
                    wallet_to_spend
                        .p()
                        .add_subnet_validator()
                        .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                        .subnet_id(created_subnet_id)
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            }
            log::info!("added subnet validators for {}", created_subnet_id);
            thread::sleep(Duration::from_secs(5));

            let subnet_evm_genesis_bytes = subnet_evm.genesis.to_bytes().unwrap();
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new blockchain for subnet-evm {subnet_evm_name}...\n\n"
                )),
                ResetColor
            )?;
            let blockchain_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_chain()
                        .subnet_id(created_subnet_id)
                        .genesis_data(subnet_evm_genesis_bytes.clone())
                        .vm_id(
                            ids::Id::from_str("srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy")
                                .unwrap(),
                        )
                        .chain_name(String::from("subnetevm"))
                        .dry_mode(true)
                        .issue(),
                )
                .unwrap();
            log::info!("[dry mode] blockchain Id {}", blockchain_id);

            let blockchain_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_chain()
                        .subnet_id(created_subnet_id)
                        .genesis_data(subnet_evm_genesis_bytes)
                        .vm_id(
                            ids::Id::from_str("srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy")
                                .unwrap(),
                        )
                        .chain_name(String::from("subnetevm"))
                        .check_acceptance(true)
                        .issue(),
                )
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
            let ssm_output = rt
                .block_on(
                    ssm_cli
                        .send_command()
                        .document_name(ssm_document_name_restart_node_chain_config.clone())
                        .set_instance_ids(Some(all_instance_ids.clone()))
                        .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                        .parameters("subnetEvmName", vec![subnet_evm_name.clone()])
                        .parameters("newBlockchainId", vec![blockchain_id.to_string()])
                        .output_s3_region(spec.aws_resources.region.clone())
                        .output_s3_bucket_name(spec.aws_resources.s3_bucket.clone())
                        .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                        .send(),
                )
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            thread::sleep(Duration::from_secs(30));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = rt
                    .block_on(ssm_manager.poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    ))
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
        }

        for (subnet_evm_blockchain_id, node_ids) in subnet_evm_blockchain_ids.iter() {
            log::info!(
                "created subnet-evm with blockchain Id {subnet_evm_blockchain_id} in nodes {:?}",
                node_ids
            );
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
--install-artifacts-blizzard-bin={exec_parent_dir}/blizzard-aws \\
--instance-mode=spot \\
--network-id={network_id} \\
--nodes=10 \\
--blizzard-log-level=info \\
--blizzard-http-rpcs={blizzard_http_rpcs} \\
--blizzard-subnet-evm-blockchain-id={subnet_evm_blockchain_id} \\
--blizzard-keys-to-generate=100 \\
--blizzard-workers=100 \\
--blizzard-load-kinds=subnet-evm-transfers
",
                    exec_parent_dir = exec_parent_dir,
                    funded_keys = if let Some(keys) = &spec.test_key_infos {
                        keys.len()
                    } else {
                        1
                    },
                    region = spec.aws_resources.region,
                    network_id = spec.avalanchego_config.network_id,
                    blizzard_http_rpcs = http_rpcs.clone().join(","),
                    subnet_evm_blockchain_id = subnet_evm_blockchain_id,
                )),
                ResetColor
            )?;
        }
    }

    // maps xsvm blockchain id to its validator node Ids
    let mut xsvm_blockchain_ids = BTreeMap::new();
    if let Some(xsvms) = &spec.xsvms {
        println!();
        log::info!("non-empty xsvms and custom network, so install with test keys");
        println!();

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: creating an SSM document for restarting node with whitelisted subnet xsvm...\n\n"),
            ResetColor
        )?;
        let ssm_doc_yaml =
            Asset::get("cfn-templates/ssm_doc_restart_node_whitelist_subnet_xsvm.yaml").unwrap();
        let ssm_doc_tmpl = std::str::from_utf8(ssm_doc_yaml.data.as_ref()).unwrap();
        let ssm_doc_stack_name = spec
            .aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet_xsvm
            .clone()
            .unwrap();
        let ssm_document_name_restart_whitelist_subnet =
            avalancheup_aws::spec::StackName::SsmDocRestartNodeWhitelistSubnetXsvm(spec.id.clone())
                .encode();
        let cfn_params = Vec::from([build_param(
            "DocumentName",
            &ssm_document_name_restart_whitelist_subnet,
        )]);
        rt.block_on(cloudformation_manager.create_stack(
            ssm_doc_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ssm_doc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(cfn_params),
        ))
        .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            ssm_doc_stack_name.as_str(),
            StackStatus::CreateComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
        log::info!("created ssm document for restarting node with whitelisted subnet");

        // in case we need split subnet validator set
        // we want batch set to be 2, for 4 nodes + 2 subnets
        // we want batch set to be 2, for 3 nodes + 2 subnets
        // we don't want batch set 1, for 3 nodes + 2 subnets
        let mut batch_size = all_node_ids.len() / xsvms.len();
        if all_node_ids.len() % 2 == 1 {
            batch_size += 1;
        }

        let mut batch_cur = 0_usize;
        for (xsvm_name, xsvm) in xsvms.iter() {
            let selected_node_ids = if spec.xsvms_split_validators {
                let mut nodes = Vec::new();
                for (idx, chunks) in all_node_ids.chunks(batch_size).enumerate() {
                    if idx != batch_cur {
                        continue;
                    }
                    nodes = chunks.to_vec();
                    break;
                }
                nodes
            } else {
                all_node_ids.clone()
            };
            batch_cur += 1;
            log::info!(
                "selected XSVM nodes {:?} out of {:?} (split validators {})",
                selected_node_ids,
                all_node_ids,
                spec.xsvms_split_validators
            );

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: creating a new subnet for xsvm {xsvm_name}...\n\n"
                )),
                ResetColor
            )?;
            let subnet_id = rt
                .block_on(wallet_to_spend.p().create_subnet().dry_mode(true).issue())
                .unwrap();
            log::info!("[dry mode] subnet Id '{}'", subnet_id);

            let created_subnet_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_subnet()
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            log::info!(
                "created subnet '{}' (still need whitelist)",
                created_subnet_id
            );
            thread::sleep(Duration::from_secs(5));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with whitelisted subnet xsvm...\n\n"),
                ResetColor
            )?;
            // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
            let ssm_output = rt
                .block_on(
                    ssm_cli
                        .send_command()
                        .document_name(ssm_document_name_restart_whitelist_subnet.clone())
                        .set_instance_ids(Some(all_instance_ids.clone()))
                        .parameters(
                            "vmId",
                            vec![String::from(
                                "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                            )],
                        )
                        .parameters("specPath", vec![String::from("/data/avalancheup.yaml")])
                        .parameters("xsvmName", vec![xsvm_name.clone()])
                        .parameters(
                            "newWhitelistedSubnetId",
                            vec![created_subnet_id.to_string()],
                        )
                        .output_s3_region(spec.aws_resources.region.clone())
                        .output_s3_bucket_name(spec.aws_resources.s3_bucket.clone())
                        .output_s3_key_prefix(format!("{}/ssm-output-logs", spec.id))
                        .send(),
                )
                .unwrap();
            let ssm_output = ssm_output.command().unwrap();
            let ssm_command_id = ssm_output.command_id().unwrap();
            log::info!("sent SSM command {}", ssm_command_id);
            thread::sleep(Duration::from_secs(30));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
                ResetColor
            )?;
            for instance_id in all_instance_ids.iter() {
                let status = rt
                    .block_on(ssm_manager.poll_command(
                        ssm_command_id,
                        instance_id,
                        CommandInvocationStatus::Success,
                        Duration::from_secs(300),
                        Duration::from_secs(5),
                    ))
                    .unwrap();
                log::info!("status {:?} for instance id {}", status, instance_id);
            }
            thread::sleep(Duration::from_secs(5));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\n\n\nSTEP: adding selected nodes as subnet validator for xsvm {xsvm_name}...\n\n"
                )),
                ResetColor
            )?;
            for node_id in selected_node_ids.iter() {
                rt.block_on(
                    wallet_to_spend
                        .p()
                        .add_subnet_validator()
                        .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                        .subnet_id(created_subnet_id)
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            }
            log::info!("added subnet validators for {}", created_subnet_id);
            thread::sleep(Duration::from_secs(5));

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
            let blockchain_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_chain()
                        .subnet_id(created_subnet_id)
                        .genesis_data(xsvm_genesis_bytes.clone())
                        .vm_id(
                            ids::Id::from_str("v3m4wPxaHpvGr8qfMeyK6PRW3idZrPHmYcMTt7oXdK47yurVH")
                                .unwrap(),
                        )
                        .chain_name(String::from("xsvm"))
                        .dry_mode(true)
                        .issue(),
                )
                .unwrap();
            log::info!("[dry mode] blockchain Id {}", blockchain_id);

            let blockchain_id = rt
                .block_on(
                    wallet_to_spend
                        .p()
                        .create_chain()
                        .subnet_id(created_subnet_id)
                        .genesis_data(xsvm_genesis_bytes)
                        .vm_id(
                            ids::Id::from_str("v3m4wPxaHpvGr8qfMeyK6PRW3idZrPHmYcMTt7oXdK47yurVH")
                                .unwrap(),
                        )
                        .chain_name(String::from("xsvm"))
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            log::info!("created a blockchain {blockchain_id} for subnet {subnet_id}");
            xsvm_blockchain_ids.insert(blockchain_id.to_string(), selected_node_ids.clone());
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
        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();

        let mut endpoints = avalancheup_aws::spec::Endpoints::default();
        endpoints.http_rpc = Some(http_rpc.clone());
        endpoints.http_rpc_x = Some(format!("{http_rpc}/ext/bc/X"));
        endpoints.http_rpc_p = Some(format!("{http_rpc}/ext/bc/P"));
        endpoints.http_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.metrics = Some(format!("{http_rpc}/ext/metrics"));
        endpoints.health = Some(format!("{http_rpc}/ext/health"));
        endpoints.liveness = Some(format!("{http_rpc}/ext/health/liveness"));
        endpoints.metamask_rpc_c = Some(format!("{http_rpc}/ext/bc/C/rpc"));
        endpoints.websocket_rpc_c = Some(format!("ws://{host}:{port_for_dns}/ext/bc/C/ws"));
        spec.created_endpoints = Some(endpoints.clone());
        println!(
            "{}",
            spec.created_endpoints
                .clone()
                .unwrap()
                .encode_yaml()
                .unwrap()
        );

        if !subnet_evm_blockchain_ids.is_empty() {
            println!();
        }
        for (subnet_evm_blockchain_id, node_ids) in subnet_evm_blockchain_ids.iter() {
            if let Some(node) = rpc_hosts_to_nodes.get(host) {
                println!(
                    "subnet-evm RPC for node '{}': {http_rpc}/ext/bc/{subnet_evm_blockchain_id}/rpc",
                    node.node_id
                );
            } else {
                println!(
                    "[NLB DNS] subnet-evm RPC for nodes '{:?}': {http_rpc}/ext/bc/{subnet_evm_blockchain_id}/rpc",
                    node_ids
                );
            }
        }

        if !xsvm_blockchain_ids.is_empty() {
            println!();
        }
        for (xsvm_blockchain_id, node_ids) in xsvm_blockchain_ids.iter() {
            if let Some(node) = rpc_hosts_to_nodes.get(host) {
                println!(
                    "xsvm RPC for node '{}': {http_rpc}/ext/bc/{xsvm_blockchain_id}",
                    node.node_id
                );
            } else {
                println!(
                    "[NLB DNS] xsvm RPC for nodes '{:?}': {http_rpc}/ext/bc/{xsvm_blockchain_id}",
                    node_ids
                );
            }
        }
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
