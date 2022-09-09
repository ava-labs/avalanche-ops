use std::{
    env,
    fs::{self, File},
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use avalanche_sdk::health as api_health;
use aws_manager::{
    self, cloudformation, ec2,
    kms::{self, envelope},
    s3, sts,
};
use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_s3::model::Object;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

pub const NAME: &str = "apply";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Applies/creates resources based on configuration")
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
                .help("The spec file to load and update")
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

    let mut aws_resources = spec.aws_resources.clone().unwrap();
    let shared_config = rt
        .block_on(aws_manager::load_config(Some(aws_resources.region.clone())))
        .expect("failed to aws_manager::load_config");

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
    match aws_resources.clone().identity {
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
            aws_resources.identity = Some(current_identity);
        }
    }

    // set defaults based on ID
    if aws_resources.ec2_key_name.is_none() {
        aws_resources.ec2_key_name = Some(format!("{}-ec2-key", spec.id));
    }
    if aws_resources.cloudformation_ec2_instance_role.is_none() {
        aws_resources.cloudformation_ec2_instance_role =
            Some(avalancheup_aws::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc =
            Some(avalancheup_aws::StackName::Vpc(spec.id.clone()).encode());
    }
    if spec.avalanchego_config.is_custom_network()
        && aws_resources.cloudformation_asg_anchor_nodes.is_none()
    {
        aws_resources.cloudformation_asg_anchor_nodes =
            Some(avalancheup_aws::StackName::AsgBeaconNodes(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_asg_non_anchor_nodes.is_none() {
        aws_resources.cloudformation_asg_non_anchor_nodes =
            Some(avalancheup_aws::StackName::AsgNonBeaconNodes(spec.id.clone()).encode());
    }
    if aws_resources
        .cloudwatch_avalanche_metrics_namespace
        .is_none()
    {
        aws_resources.cloudwatch_avalanche_metrics_namespace =
            Some(format!("{}-avalanche", spec.id));
    }
    spec.aws_resources = Some(aws_resources.clone());
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
    let s3_manager = s3::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))
        .expect("failed to register os signal");

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 buckets\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.create_bucket(&aws_resources.s3_bucket))
        .unwrap();

    thread::sleep(Duration::from_secs(2));
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
            Arc::new(aws_resources.s3_bucket.clone()),
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
            Arc::new(aws_resources.s3_bucket.clone()),
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
                Arc::new(aws_resources.s3_bucket.clone()),
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
        Arc::new(aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
    ))
    .unwrap();

    if aws_resources.kms_cmk_id.is_none() && aws_resources.kms_cmk_arn.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )?;

        let key = rt
            .block_on(kms_manager.create_key(format!("{}-cmk", spec.id).as_str()))
            .unwrap();

        aws_resources.kms_cmk_id = Some(key.id);
        aws_resources.kms_cmk_arn = Some(key.arn);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }
    let envelope_manager = envelope::Manager::new(
        kms_manager,
        aws_resources.kms_cmk_id.clone().unwrap(),
        "avalanche-ops".to_string(),
    );

    if aws_resources.ec2_key_path.is_none() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = get_ec2_key_path(spec_file_path);
        rt.block_on(ec2_manager.create_key_pair(
            aws_resources.ec2_key_name.clone().unwrap().as_str(),
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
                Arc::new(aws_resources.s3_bucket.clone()),
                Arc::new(
                    avalancheup_aws::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
                        spec.id.clone(),
                    )
                    .encode(),
                ),
            ),
        )
        .unwrap();

        aws_resources.ec2_key_path = Some(ec2_key_path);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
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
            Arc::new(aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::MetricsRules(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    if aws_resources
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
        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        let role_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
            build_param("S3BucketName", &aws_resources.s3_bucket),
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
                aws_resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_none()
        && aws_resources.cloudformation_vpc_security_group_id.is_none()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cfn-templates/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();
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
                aws_resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                aws_resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    log::info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                aws_resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
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
        build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
        build_param("AadTag", &spec.aad_tag),
        build_param("S3BucketName", &aws_resources.s3_bucket),
        build_param(
            "Ec2KeyPairName",
            &aws_resources.ec2_key_name.clone().unwrap(),
        ),
        build_param(
            "InstanceProfileArn",
            &aws_resources
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        ),
        build_param(
            "SecurityGroupId",
            &aws_resources
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        ),
        build_param(
            "NlbVpcId",
            &aws_resources.cloudformation_vpc_id.clone().unwrap(),
        ),
        build_param(
            "NlbHttpPort",
            format!("{}", spec.avalanchego_config.http_port).as_str(),
        ),
    ]);

    let all_public_subnet_ids = aws_resources
        .cloudformation_vpc_public_subnet_ids
        .clone()
        .unwrap();
    if spec.avalanchego_config.is_custom_network() {
        log::info!(
            "custom network, so setting 'PublicSubnetIds' parameter with multiple subnets {:?}",
            all_public_subnet_ids
        );

        // custom network is for testing, for ok to allow multi-AZ
        asg_parameters.push(build_param(
            "PublicSubnetIds",
            &aws_resources
                .cloudformation_vpc_public_subnet_ids
                .clone()
                .unwrap()
                .join(","),
        ));
    } else {
        log::info!(
            "network {}, so choosing only 1 public subnet Id '{}' for 'PublicSubnetIds' parameter",
            spec.avalanchego_config.network_id,
            all_public_subnet_ids[aws_resources.preferred_az_index]
        );

        // only use 1 AZ for main/fuji net
        // to maximize the static EBS provision
        //
        // one can create multiple avalancheup for multi-AZ deployments
        // or manually update the ASG.VPCZoneIdentifier for fallbacks
        //
        // TODO: support AZ choose
        asg_parameters.push(build_param(
            "PublicSubnetIds",
            &all_public_subnet_ids[aws_resources.preferred_az_index],
        ));
    }

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

    // TODO: support bootstrap from existing DB for anchor nodes
    let mut current_nodes: Vec<avalancheup_aws::Node> = Vec::new();
    if spec.machine.anchor_nodes.unwrap_or(0) > 0
        && aws_resources
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
        let cloudformation_asg_anchor_nodes_stack_name = aws_resources
            .cloudformation_asg_anchor_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.anchor_nodes.unwrap();

        // must deep-copy as shared with other node kind
        let mut asg_anchor_params = asg_parameters.clone();
        asg_anchor_params.push(build_param("NodeKind", "anchor"));

        let is_spot_instance = spec.machine.use_spot_instance;
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        asg_anchor_params.push(build_param(
            "AsgSpotInstance",
            format!("{}", is_spot_instance).as_str(),
        ));
        asg_anchor_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        asg_anchor_params.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));
        if aws_resources.nlb_acm_certificate_arn.is_some() {
            asg_anchor_params.push(build_param(
                "NlbAcmCertificateArn",
                &aws_resources.nlb_acm_certificate_arn.clone().unwrap(),
            ));
        };

        let disable_nlb = spec.machine.disable_nlb;
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

        // add 5-minute for ELB creation
        let mut wait_secs = 500 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
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
                aws_resources.cloudformation_asg_anchor_nodes_logical_id = Some(v);
                continue;
            }
            if k.eq("NlbArn") {
                aws_resources.cloudformation_asg_nlb_arn = Some(v);
                continue;
            }
            if k.eq("NlbTargetGroupArn") {
                aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                continue;
            }
            if k.eq("NlbDnsName") {
                aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                continue;
            }
        }
        if aws_resources
            .cloudformation_asg_anchor_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_anchor_nodes_logical_id not found",
            ));
        }
        if aws_resources.cloudformation_asg_nlb_arn.is_none() {
            if spec.machine.disable_nlb {
                log::info!("NLB is disabled so empty NLB ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_arn not found",
                ));
            }
        }
        if aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            if spec.machine.disable_nlb {
                log::info!("NLB is disabled so empty NLB target group ARN...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
        }
        if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
            if spec.machine.disable_nlb {
                log::info!("NLB is disabled so empty NLB DNS name...");
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }

        let asg_name = aws_resources
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

        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
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
                aws_resources.region,
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
                        Arc::new(aws_resources.s3_bucket.clone()),
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
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--spec-file-path {}\n",
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

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
            Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
        ))
        .unwrap();

        log::info!("waiting for anchor nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(15));
    }

    if aws_resources
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
        let cloudformation_asg_non_anchor_nodes_stack_name = aws_resources
            .cloudformation_asg_non_anchor_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.non_anchor_nodes;

        // we did not create anchor nodes for mainnet/* nodes
        // so no nlb creation before
        // we create here for non-anchor nodes
        let need_to_create_nlb = aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none();

        // must deep-copy as shared with other node kind
        let mut asg_non_anchor_params = asg_parameters.clone();
        asg_non_anchor_params.push(build_param("NodeKind", "non-anchor"));

        let is_spot_instance = spec.machine.use_spot_instance;
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        asg_non_anchor_params.push(build_param(
            "AsgSpotInstance",
            format!("{}", is_spot_instance).as_str(),
        ));
        asg_non_anchor_params.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        asg_non_anchor_params.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        let disable_nlb = spec.machine.disable_nlb;
        if disable_nlb {
            asg_non_anchor_params.push(build_param("NlbDisabled", "true"));
        } else {
            asg_non_anchor_params.push(build_param("NlbDisabled", "false"));
            if need_to_create_nlb {
                if aws_resources.nlb_acm_certificate_arn.is_some() {
                    asg_non_anchor_params.push(build_param(
                        "NlbAcmCertificateArn",
                        &aws_resources.nlb_acm_certificate_arn.clone().unwrap(),
                    ));
                };
            } else {
                // NLB already created for anchor nodes
                asg_non_anchor_params.push(build_param(
                    "NlbTargetGroupArn",
                    &aws_resources
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

        let mut wait_secs = 500 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
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
                aws_resources.cloudformation_asg_non_anchor_nodes_logical_id = Some(v);
                continue;
            }
            if need_to_create_nlb {
                if k.eq("NlbArn") {
                    aws_resources.cloudformation_asg_nlb_arn = Some(v);
                    continue;
                }
                if k.eq("NlbTargetGroupArn") {
                    aws_resources.cloudformation_asg_nlb_target_group_arn = Some(v);
                    continue;
                }
                if k.eq("NlbDnsName") {
                    aws_resources.cloudformation_asg_nlb_dns_name = Some(v);
                    continue;
                }
            }
        }
        if aws_resources
            .cloudformation_asg_non_anchor_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_non_anchor_nodes_logical_id not found",
            ));
        }
        if need_to_create_nlb {
            if aws_resources.cloudformation_asg_nlb_arn.is_none() {
                if spec.machine.disable_nlb {
                    log::info!("NLB is disabled so empty NLB ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_arn not found",
                    ));
                }
            }
            if aws_resources
                .cloudformation_asg_nlb_target_group_arn
                .is_none()
            {
                if spec.machine.disable_nlb {
                    log::info!("NLB is disabled so empty NLB target group ARN...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                    ));
                }
            }
            if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
                if spec.machine.disable_nlb {
                    log::info!("NLB is disabled so empty NLB DNS name...");
                } else {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "aws_resources.cloudformation_asg_nlb_dns_name not found",
                    ));
                }
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        let asg_name = aws_resources
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

        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
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
                aws_resources.region,
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
                    Arc::new(aws_resources.s3_bucket.clone()),
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
                            "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--delete-ebs-volumes \\\n--spec-file-path {}\n",
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
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.s3_bucket.clone()),
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

    let rpc_hosts = if let Some(dns_name) = &aws_resources.cloudformation_asg_nlb_dns_name {
        vec![dns_name.clone()]
    } else {
        let mut eps = Vec::new();
        for node in current_nodes.iter() {
            eps.push(node.public_ip.clone())
        }
        eps
    };

    let http_port = spec.avalanchego_config.http_port;
    let nlb_https_enabled = aws_resources.nlb_acm_certificate_arn.is_some();
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
        let mut dns_endpoints = avalancheup_aws::Endpoints::default();

        let http_rpc = format!("{}://{}:{}", scheme_for_dns, host, port_for_dns).to_string();
        http_rpcs.push(http_rpc.clone());

        dns_endpoints.http_rpc = Some(http_rpc.clone());
        dns_endpoints.http_rpc_x = Some(format!("{}/ext/bc/X", http_rpc));
        dns_endpoints.http_rpc_p = Some(format!("{}/ext/bc/P", http_rpc));
        dns_endpoints.http_rpc_c = Some(format!("{}/ext/bc/C/rpc", http_rpc));
        dns_endpoints.metrics = Some(format!("{}/ext/metrics", http_rpc));
        dns_endpoints.health = Some(format!("{}/ext/health", http_rpc));
        dns_endpoints.liveness = Some(format!("{}/ext/health/liveness", http_rpc));
        dns_endpoints.metamask_rpc = Some(format!("{}/ext/bc/C/rpc", http_rpc));
        dns_endpoints.websocket = Some(format!("ws://{}:{}/ext/bc/C/rpc", host, port_for_dns));

        spec.endpoints = Some(dns_endpoints.clone());

        println!("{}", spec.endpoints.clone().unwrap().encode_yaml().unwrap());
    }

    spec.sync(spec_file_path)?;
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode()),
    ))
    .expect("failed put_object ConfigFile");

    for http_rpc in http_rpcs {
        let mut success = false;
        for _ in 0..10_u8 {
            let ret = rt.block_on(api_health::check(Arc::new(http_rpc.clone()), true));
            match ret {
                Ok(res) => {
                    if res.healthy.is_some() && res.healthy.unwrap() {
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
            let ret = rt.block_on(api_health::check(
                Arc::new(node.http_endpoint.clone()),
                true,
            ));
            match ret {
                Ok(res) => {
                    if res.healthy.is_some() && res.healthy.unwrap() {
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
                aws_resources.region, aws_resources.s3_bucket, spec.id
            )),
            ResetColor
        )?;
        let kms_cmk = aws_resources.kms_cmk_id.clone().unwrap();
        for n in nodes.iter() {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "
$ ./scripts/build.release.sh
$ ./target/release/staking-key-cert-s3-downloader \\
--log-level=info \\
--aws-region={aws_region} \\
--s3-bucket={s3_buckeet} \\
--s3-key-tls-key={id}/pki/{node_id}.key.zstd.encrypted \\
--s3-key-tls-cert={id}/pki/{node_id}.crt.zstd.encrypted \\
--kms-cmk-id={kms_cmk_id} \\
--aad-tag='{aad_tag}' \\
--tls-key-path=/tmp/{node_id}.key \\
--tls-cert-path=/tmp/{node_id}.crt
$ cat /tmp/{node_id}.crt
",
                    aws_region = aws_resources.region,
                    s3_buckeet = aws_resources.s3_bucket,
                    id = spec.id,
                    kms_cmk_id = kms_cmk,
                    aad_tag = spec.aad_tag,
                    node_id = n.node_id,
                )),
                ResetColor
            )?;
        }
    } else {
        log::warn!("no current nodes found in spec");
    }

    if let Some(subnet_evm_genesis) = &spec.subnet_evm_genesis {
        let subnet_evm_genesis_file_path =
            dir_manager::home::named(&spec.id, Some(".subnet-evm.genesis.json"));

        println!();
        subnet_evm_genesis
            .sync(&subnet_evm_genesis_file_path)
            .expect("failed subnet_evm_genesis.sync");

        println!();
        println!("# [optional] run the following to create subnet-evm resources");
        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!("cat {} | grep private_key_hex:\n", spec_file_path)),
            ResetColor
        )?;

        let keys = spec
            .generated_seed_private_keys
            .expect("unexpected None generated_seed_private_keys");
        execute!(
            stdout(),
            SetForegroundColor(Color::Cyan),
            Print(format!(
                "cat <<EOF > /tmp/test.key\n{}\nEOF\ncat /tmp/test.key\n",
                keys[0].private_key_hex
            )),
            ResetColor
        )?;

        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!("cat {} | grep http_rpc:\n", spec_file_path)),
            ResetColor
        )?;
        execute!(
            stdout(),
            SetForegroundColor(Color::Magenta),
            Print(format!("cat {}\n", subnet_evm_genesis_file_path)),
            ResetColor
        )?;

        let endpoints = spec.endpoints.expect("unexpected None spec.endpoints");
        let http_rpc = endpoints
            .http_rpc
            .expect("unexpected None endpoints.http_rpc");
        let nodes = spec.current_nodes.expect("unexpected None current_nodes");
        let mut all_node_ids: Vec<String> = Vec::new();
        for node in nodes.iter() {
            let node_id = node.clone().node_id;
            all_node_ids.push(node_id);
        }

        for node in nodes.iter() {
            // "anchor" node in the custom network is already validating the primary network
            if node.kind == "anchor" {
                continue;
            }

            let node_id = node.clone().node_id;

            println!();
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "subnet-cli add validator \\\n--enable-prompt \\\n--private-key-path=/tmp/test.key \\\n--public-uri={} \\\n--stake-amount=2000000000000 \\\n--validate-reward-fee-percent=2 \\\n--node-ids=\"{}\"\n",
                    http_rpc, node_id
                )),
                ResetColor
            )?;
        }

        println!();
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "subnet-cli wizard \\\n--enable-prompt \\\n--private-key-path=/tmp/test.key \\\n--public-uri={} \\\n--vm-genesis-path={} \\\n--vm-id=srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy \\\n--chain-name=subnetevm \\\n--node-ids=\"{}\"\n",
                http_rpc, subnet_evm_genesis_file_path, all_node_ids.join(",")
            )),
            ResetColor
        )?;
    }

    if spec.subnet_evm_config.is_some() {
        let chain_config_dir = spec.avalanchego_config.chain_config_dir.clone();
        let whitelisted_subnet = spec.avalanchego_config.whitelisted_subnets.clone().unwrap();
        let path1 = Path::new(&chain_config_dir)
            .join(whitelisted_subnet)
            .join("config.json");
        let dir2 = Path::new(&chain_config_dir).join("CREATED_BLOCKCHAIN_ID");
        let path2 = Path::new(&chain_config_dir)
            .join("CREATED_BLOCKCHAIN_ID")
            .join("config.json");

        println!();
        println!("# [optional] run the following in remote machines to install subnet-evm config");
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print(format!(
                "sudo mkdir -p {} && sudo cp {} {} && cat {}\n",
                dir2.display(),
                path1.display(),
                path2.display(),
                path2.display()
            )),
            ResetColor
        )?;

        println!();
        println!("# [optional] start the avalanche process to reload the chain config");
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("sudo systemctl restart --no-block avalanche.service\n"),
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
