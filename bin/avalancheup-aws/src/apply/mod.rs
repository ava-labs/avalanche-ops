use std::{
    collections::HashMap,
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

    let mut spec = avalancheup_aws::Spec::load(spec_file_path).expect("failed to load spec");
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
            Some(avalancheup_aws::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if spec.aws_resources.cloudformation_vpc.is_none() {
        spec.aws_resources.cloudformation_vpc =
            Some(avalancheup_aws::StackName::Vpc(spec.id.clone()).encode());
    }
    if spec.avalanchego_config.is_custom_network()
        && spec.aws_resources.cloudformation_asg_anchor_nodes.is_none()
    {
        spec.aws_resources.cloudformation_asg_anchor_nodes =
            Some(avalancheup_aws::StackName::AsgAnchorNodes(spec.id.clone()).encode());
    }
    if spec
        .aws_resources
        .cloudformation_asg_non_anchor_nodes
        .is_none()
    {
        spec.aws_resources.cloudformation_asg_non_anchor_nodes =
            Some(avalancheup_aws::StackName::AsgNonAnchorNodes(spec.id.clone()).encode());
    }
    if spec
        .aws_resources
        .cloudwatch_avalanche_metrics_namespace
        .is_none()
    {
        spec.aws_resources.cloudwatch_avalanche_metrics_namespace =
            Some(format!("{}-avalanche", spec.id));
    }
    if spec.subnet_evm_genesis.is_some() {
        spec.aws_resources
            .cloudformation_ssm_doc_restart_node_whitelist_subnet = Some(
            avalancheup_aws::StackName::SsmDocRestartNodeWhitelistSubnet(spec.id.clone()).encode(),
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

    if let Some(v) = &spec.install_artifacts.avalanched_bin {
        // don't compress since we need to download this in user data
        // while instance bootstrapping
        rt.block_on(s3_manager.put_object(
            Arc::new(v.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::AvalanchedBin(spec.id.clone()).encode()),
        ))
        .expect("failed put_object install_artifacts.avalanched_bin");
    } else {
        log::info!("skipping uploading avalanched_bin, will be downloaded on remote machines...");
    }

    if let Some(v) = &spec.install_artifacts.avalanchego_bin {
        // compress as these will be decompressed by "avalanched"
        let tmp_avalanche_bin_compressed_path =
            random_manager::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext())).unwrap();

        compress_manager::pack_file(
            v,
            &tmp_avalanche_bin_compressed_path,
            compress_manager::Encoder::Zstd(3),
        )
        .expect("failed pack_file install_artifacts.avalanched_bin");

        rt.block_on(s3_manager.put_object(
            Arc::new(tmp_avalanche_bin_compressed_path.clone()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(
                avalancheup_aws::StorageNamespace::AvalancheBinCompressed(spec.id.clone()).encode(),
            ),
        ))
        .expect("failed put_object compressed avalanchego_bin");

        fs::remove_file(tmp_avalanche_bin_compressed_path)?;
    } else {
        log::info!("skipping uploading avalanchego_bin, will be downloaded on remote machines...");
    }

    if spec.install_artifacts.plugins_dir.is_some() {
        let plugins_dir = spec.install_artifacts.plugins_dir.clone().unwrap();
        for entry in fs::read_dir(plugins_dir.as_str()).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            let tmp_plugin_compressed_path =
                random_manager::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext()))
                    .unwrap();
            compress_manager::pack_file(
                file_path,
                &tmp_plugin_compressed_path,
                compress_manager::Encoder::Zstd(3),
            )
            .unwrap();

            log::info!(
                "uploading {} (compressed from {}) from plugins directory {}",
                tmp_plugin_compressed_path,
                file_path,
                plugins_dir,
            );
            rt.block_on(s3_manager.put_object(
                Arc::new(tmp_plugin_compressed_path.clone()),
                Arc::new(spec.aws_resources.s3_bucket.clone()),
                Arc::new(format!(
                    "{}/{}{}",
                    &avalancheup_aws::StorageNamespace::PluginsDir(spec.id.clone()).encode(),
                    file_name,
                    compress_manager::Encoder::Zstd(3).ext()
                )),
            ))
            .expect("failed put_object tmp_plugin_compressed_path");
            fs::remove_file(tmp_plugin_compressed_path)?;
        }
    } else {
        log::info!("skipping uploading plugin dir...");
    }

    log::info!("uploading avalancheup spec file...");
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(spec.aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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
                    avalancheup_aws::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
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
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    if let Some(metrics_rules) = &spec.metrics_rules {
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
            Arc::new(avalancheup_aws::StorageNamespace::MetricsRules(spec.id.clone()).encode()),
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
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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

    let avalanched_download_source = if spec.install_artifacts.avalanched_bin.is_some() {
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
    let mut current_nodes: Vec<avalancheup_aws::Node> = Vec::new();
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

        let is_spot_instance =
            spec.machine.use_spot_instance && !spec.machine.disable_spot_instance_for_anchor_nodes;
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        let ip_mode = if spec.machine.use_elastic_ips {
            String::from("elastic")
        } else {
            String::from("ephemeral")
        };
        asg_anchor_params.push(build_param(
            "AsgSpotInstance",
            format!("{}", is_spot_instance).as_str(),
        ));
        asg_anchor_params.push(build_param("IpMode", &ip_mode));
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

        let disable_nlb = spec.disable_nlb;
        if disable_nlb {
            asg_anchor_params.push(build_param("NlbDisabled", "true"));
        } else {
            asg_anchor_params.push(build_param("NlbDisabled", "false"));
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
            if spec.disable_nlb {
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
            if spec.disable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if spec.aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
            if spec.disable_nlb {
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

        let eip_addresses = rt
            .block_on(
                ec2_manager
                    .describe_eips_by_tags(HashMap::from([(String::from("Id"), spec.id.clone())])),
            )
            .unwrap();
        let mut instance_id_to_public_ip = HashMap::new();
        for eip_addr in eip_addresses.iter() {
            let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
            let instance_id = eip_addr.instance_id.to_owned().unwrap();
            let public_ip = eip_addr.public_ip.to_owned().unwrap();
            log::info!("EIP found {allocation_id} for {instance_id} and {public_ip}");
            instance_id_to_public_ip.insert(instance_id, public_ip);
        }

        let ec2_key_path = spec.aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!(
            "
# change SSH key permission
chmod 400 {}",
            ec2_key_path
        );
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            println!(
                "# instance '{}' ({}, {})
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
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                spec.aws_resources.region,
                d.instance_id,
            );

            if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                println!(
                    "# instance '{}' ({}, {}) -- with elastic IP
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
                    //
                    d.instance_id,
                    d.instance_state_name,
                    d.availability_zone,
                    //
                    ec2_key_path,
                    public_ip,
                    //
                    ec2_key_path,
                    public_ip,
                    //
                    ec2_key_path,
                    public_ip,
                    //
                    ec2_key_path,
                    public_ip,
                    //
                    ec2_key_path,
                    public_ip,
                    //
                    spec.aws_resources.region,
                    d.instance_id,
                );
            }
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
                            &avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNodesDir(
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
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-eips \\\n--spec-file-path {}\n",
                            exec_path.display(),
                            spec_file_path
                        )),
                        ResetColor
                    )?;
            };
        }

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let anchor_node =
                avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            current_nodes.push(anchor_node.clone());
        }

        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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

        let is_spot_instance = spec.machine.use_spot_instance;
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        let ip_mode = if spec.machine.use_elastic_ips {
            String::from("elastic")
        } else {
            String::from("ephemeral")
        };
        asg_non_anchor_params.push(build_param(
            "AsgSpotInstance",
            format!("{}", is_spot_instance).as_str(),
        ));
        asg_non_anchor_params.push(build_param("IpMode", &ip_mode));
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

        let disable_nlb = spec.disable_nlb;
        if disable_nlb {
            asg_non_anchor_params.push(build_param("NlbDisabled", "true"));
        } else {
            asg_non_anchor_params.push(build_param("NlbDisabled", "false"));
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
                if spec.disable_nlb {
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
                if spec.disable_nlb {
                    log::info!("NLB is disabled so empty NLB target group ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                    ));
                }
            }
            if spec.aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
                if spec.disable_nlb {
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

        let ec2_key_path = spec.aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!(
            "
# change SSH key permission
chmod 400 {}",
            ec2_key_path
        );
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            println!(
                "# instance '{}' ({}, {})
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
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                ec2_key_path,
                d.public_ipv4,
                //
                spec.aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        let s3_dir =
            avalancheup_aws::StorageNamespace::DiscoverReadyNonAnchorNodesDir(spec.id.clone());

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
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--delete-eips \\\n--spec-file-path {}\n",
                            exec_path.display(),
                            spec_file_path
                        )),
                        ResetColor
                    )?;
            };
        }

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let non_anchor_node =
                avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key).unwrap();
            current_nodes.push(non_anchor_node.clone());
        }
        spec.current_nodes = Some(current_nodes.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(spec.aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .expect("failed put_object ConfigFile");

        log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }
    spec.current_nodes = Some(current_nodes.clone());
    spec.sync(spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: listing all node objects based on S3 keys...\n\n"),
        ResetColor
    )?;
    for node in current_nodes.iter() {
        println!("{}", node.encode_yaml().unwrap());
    }

    let mut rpc_hosts = if let Some(dns_name) = &spec.aws_resources.cloudformation_asg_nlb_dns_name
    {
        vec![dns_name.clone()]
    } else {
        Vec::new()
    };
    for node in current_nodes.iter() {
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
        let mut endpoints = avalancheup_aws::Endpoints::default();

        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();
        http_rpcs.push(http_rpc.clone());

        endpoints.http_rpc = Some(http_rpc.clone());
        endpoints.http_rpc_x = Some(format!("{}/ext/bc/X", http_rpc));
        endpoints.http_rpc_p = Some(format!("{}/ext/bc/P", http_rpc));
        endpoints.http_rpc_c = Some(format!("{}/ext/bc/C/rpc", http_rpc));
        endpoints.metrics = Some(format!("{}/ext/metrics", http_rpc));
        endpoints.health = Some(format!("{}/ext/health", http_rpc));
        endpoints.liveness = Some(format!("{}/ext/health/liveness", http_rpc));
        endpoints.metamask_rpc_c = Some(format!("{}/ext/bc/C/rpc", http_rpc));
        endpoints.websocket_rpc_c = Some(format!("ws://{}:{}/ext/bc/C/ws", host, port_for_dns));

        spec.endpoints = Some(endpoints.clone());

        println!("{}", spec.endpoints.clone().unwrap().encode_yaml().unwrap());
    }

    spec.sync(spec_file_path)?;
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(spec.aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
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
    for node in current_nodes.iter() {
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

    println!();
    log::info!("apply all success!");

    let nodes = spec
        .current_nodes
        .clone()
        .expect("unexpected None current_nodes");
    let mut all_node_ids: Vec<String> = Vec::new();
    let mut all_instance_ids: Vec<String> = Vec::new();
    for node in nodes.iter() {
        let node_id = node.node_id.clone();
        all_node_ids.push(node_id);
        all_instance_ids.push(node.machine_id.clone())
    }

    if let Some(keys_with_balances) = &spec.test_insecure_hot_key_infos {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: adding all nodes as validators...\n\n"),
            ResetColor
        )?;

        // create a wallet
        let pk = key::secp256k1::private_key::Key::from_cb58(
            keys_with_balances[0].private_key_cb58.clone(),
        )?;
        let w = rt
            .block_on(
                wallet::Builder::new(&pk)
                    .http_rpcs(http_rpcs.clone())
                    .build(),
            )
            .unwrap();

        log::info!("adding all nodes as primary network validator");
        for node_id in all_node_ids.iter() {
            let (tx_id, added) = rt
                .block_on(
                    w.p()
                        .add_validator()
                        .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                        .check_acceptance(true)
                        .issue(),
                )
                .unwrap();
            log::info!("validator tx id {}, added {}", tx_id, added);
        }
    }

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
--delete-eips \\
--spec-file-path {}
",
            exec_path.display(),
            spec_file_path
        )),
        ResetColor
    )?;

    if let Some(nodes) = &spec.current_nodes {
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
        for n in nodes.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "
$ ./scripts/build.release.sh
$ ./target/release/staking-key-cert-s3-downloader \\
--log-level=info \\
--region={region} \\
--s3-bucket={s3_buckeet} \\
--s3-key-tls-key={id}/pki/{node_id}.key.zstd.encrypted \\
--s3-key-tls-cert={id}/pki/{node_id}.crt.zstd.encrypted \\
--kms-cmk-id={kms_cmk_id} \\
--aad-tag='{aad_tag}' \\
--tls-key-path=/tmp/{node_id}.key \\
--tls-cert-path=/tmp/{node_id}.crt
$ cat /tmp/{node_id}.crt
",
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
    } else {
        log::warn!("no current nodes found in spec");
    }

    // need subnet-evm installation
    if let Some(subnet_evm_genesis) = &spec.subnet_evm_genesis {
        let subnet_evm_genesis_file_path =
            dir_manager::home::named(&spec.id, Some(".subnet-evm.genesis.json"));

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: writing subnet-evm genesis...\n\n"),
            ResetColor
        )?;
        subnet_evm_genesis
            .sync(&subnet_evm_genesis_file_path)
            .expect("failed subnet_evm_genesis.sync");

        if spec.avalanchego_config.is_custom_network() {
            if let Some(keys_with_balances) = &spec.test_insecure_hot_key_infos {
                // create a wallet
                let pk = key::secp256k1::private_key::Key::from_cb58(
                    keys_with_balances[0].private_key_cb58.clone(),
                )?;
                let w = rt
                    .block_on(
                        wallet::Builder::new(&pk)
                            .http_rpcs(http_rpcs.clone())
                            .build(),
                    )
                    .unwrap();

                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\n\n\nSTEP: creating a new subnet...\n\n"),
                    ResetColor
                )?;
                let subnet_id = rt
                    .block_on(w.p().create_subnet().dry_mode(true).issue())
                    .unwrap();
                log::info!("dry mode create_subnet Id {}", subnet_id);

                let subnet_id = rt
                    .block_on(w.p().create_subnet().check_acceptance(true).issue())
                    .unwrap();
                log::info!("created subnet {}", subnet_id);
                thread::sleep(Duration::from_secs(5));

                let whitelisted_subnet_id = if let Some(v) =
                    &spec.avalanchego_config.whitelisted_subnets
                {
                    v.clone()
                } else {
                    // TODO: would not work... because SSM doc does simple string replacement on config file
                    // TODO: parse avalanchego config JSON and in-place replace the config
                    log::warn!("spec.avalanchego_config.whitelisted_subnets is empty... using default... may not work!");
                    String::from("hac2sQTf29JJvveiJssb4tz8TNRQ3SyKSW7GgcwGTMk3xabgf")
                };

                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\n\n\nSTEP: creating an SSM document for restarting node with whitelisted subnet...\n\n"),
                    ResetColor
                )?;
                let ssm_doc_yaml =
                    Asset::get("cfn-templates/ssm_doc_restart_node_whitelist_subnet.yaml").unwrap();
                let ssm_doc_tmpl = std::str::from_utf8(ssm_doc_yaml.data.as_ref()).unwrap();
                let ssm_doc_stack_name = spec
                    .aws_resources
                    .cloudformation_ssm_doc_restart_node_whitelist_subnet
                    .clone()
                    .unwrap();
                let ssm_document_name =
                    avalancheup_aws::StackName::SsmDocRestartNodeWhitelistSubnet(spec.id.clone())
                        .encode();
                let cfn_params = Vec::from([
                    build_param("DocumentName", &ssm_document_name),
                    build_param("VmId", "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"),
                    build_param(
                        "ChainConfigDirectory",
                        &spec.avalanchego_config.chain_config_dir,
                    ),
                    build_param(
                        "PlaceHolderWhitelistedSubnetId",
                        whitelisted_subnet_id.as_str(),
                    ),
                    build_param("NewWhitelistedSubnetId", &subnet_id.to_string()),
                ]);
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
                log::info!("created ssm document for {}", subnet_id);

                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\n\n\nSTEP: sending remote commands via an SSM document for restarting node with whitelisted subnet...\n\n"),
                    ResetColor
                )?;
                // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
                let ssm_output = rt
                    .block_on(
                        ssm_cli
                            .send_command()
                            .document_name(ssm_document_name)
                            .set_instance_ids(Some(all_instance_ids.clone()))
                            .parameters(
                                "vmId",
                                vec![String::from(
                                    "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                                )],
                            )
                            .parameters(
                                "placeHolderWhitelistedSubnetId",
                                vec![whitelisted_subnet_id],
                            )
                            .parameters("newWhitelistedSubnetId", vec![subnet_id.to_string()])
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
                // ref. https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetCommandInvocation.html
                for instance_id in all_instance_ids.iter() {
                    loop {
                        let inv_out = rt
                            .block_on(
                                ssm_cli
                                    .get_command_invocation()
                                    .command_id(ssm_command_id)
                                    .instance_id(instance_id)
                                    .send(),
                            )
                            .unwrap();

                        if let Some(sv) = inv_out.status() {
                            log::info!(
                                "command {} status {:?} for instance {}",
                                ssm_command_id,
                                sv,
                                instance_id
                            );
                            if sv.eq(&CommandInvocationStatus::Success) {
                                break;
                            }
                        }

                        thread::sleep(Duration::from_secs(5));
                    }
                }
                thread::sleep(Duration::from_secs(5));

                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\n\n\nSTEP: adding all nodes as subnet validator...\n\n"),
                    ResetColor
                )?;
                for node_id in all_node_ids.iter() {
                    rt.block_on(
                        w.p()
                            .add_subnet_validator()
                            .node_id(node::Id::from_str(node_id.as_str()).unwrap())
                            .subnet_id(subnet_id)
                            .check_acceptance(true)
                            .issue(),
                    )
                    .unwrap();
                }
                log::info!("added subnet validators for {}", subnet_id);
                thread::sleep(Duration::from_secs(5));

                let subnet_evm_genesis_bytes = subnet_evm_genesis.to_bytes().unwrap();
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\n\n\nSTEP: creating a new blockchain...\n\n"),
                    ResetColor
                )?;
                let blockchain_id = rt
                    .block_on(
                        w.p()
                            .create_chain()
                            .subnet_id(subnet_id)
                            .genesis_data(subnet_evm_genesis_bytes.clone())
                            .vm_id(
                                ids::Id::from_str(
                                    "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                                )
                                .unwrap(),
                            )
                            .chain_name(String::from("subnetevm"))
                            .dry_mode(true)
                            .issue(),
                    )
                    .unwrap();
                log::info!("dry mode create_chain Id {}", blockchain_id);

                let blockchain_id = rt
                    .block_on(
                        w.p()
                            .create_chain()
                            .subnet_id(subnet_id)
                            .genesis_data(subnet_evm_genesis_bytes)
                            .vm_id(
                                ids::Id::from_str(
                                    "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy",
                                )
                                .unwrap(),
                            )
                            .chain_name(String::from("subnetevm"))
                            .check_acceptance(true)
                            .issue(),
                    )
                    .unwrap();
                log::info!("created a blockchain {} for {}", blockchain_id, subnet_id);
            }
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::DarkGreen),
        Print(format!(
            "
$ ./scripts/build.release.sh
$ ./target/release/blizzardup-aws \\
default-spec \\
--log-level=info \\
--keys-to-generate=50 \\
--region={region} \\
--use-spot-instance \\
--network-id={network_id} \\
--nodes=3 \\
--blizzard-log-level=info \\
--blizzard-http-rpcs={blizzard_http_rpcs} \\
--blizzard-load-kinds=x,c
",
            region = spec.aws_resources.region,
            network_id = spec.avalanchego_config.network_id,
            blizzard_http_rpcs = http_rpcs.clone().join(","),
        )),
        ResetColor
    )?;
    if spec.subnet_evm_config.is_some() {
        execute!(
            stdout(),
            SetForegroundColor(Color::DarkGreen),
            Print(format!(
                "
$ ./scripts/build.release.sh
$ ./target/release/blizzardup-aws \\
default-spec \\
--log-level=info \\
--keys-to-generate=50 \\
--region={region} \\
--use-spot-instance \\
--network-id={network_id} \\
--nodes=3 \\
--blizzard-log-level=info \\
--blizzard-http-rpcs={blizzard_http_rpcs} \\
--blizzard-subnet-evm-blockchain-id={subnet_evm_blockchain_id} \\
--blizzard-gas=21000 \
--blizzard-gas-price=0 \
--blizzard-load-kinds=x,subnet-evm
",
                region = spec.aws_resources.region,
                network_id = spec.avalanchego_config.network_id,
                blizzard_http_rpcs = http_rpcs.clone().join(","),
                subnet_evm_blockchain_id = "2nBBjWJEiBFjUbDjEvVY9a7XhhtTRzdTWToC9LssJuzHq3LdMv",
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
