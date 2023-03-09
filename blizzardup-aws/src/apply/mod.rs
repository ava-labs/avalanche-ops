use std::{
    env,
    fs::File,
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use avalanche_types::jsonrpc::client::{evm as client_evm, info as client_info};
use aws_manager::{self, cloudformation, ec2, s3, sts};
use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use rust_embed::RustEmbed;
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
    #[derive(RustEmbed)]
    #[folder = "cfn-templates/"]
    #[prefix = "cfn-templates/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = blizzardup_aws::Spec::load(spec_file_path).expect("failed to load spec");
    spec.validate()?;

    let mut resources = spec.resources.clone().unwrap();
    let shared_config = aws_manager::load_config(Some(resources.region.clone()))
        .await
        .expect("failed to aws_manager::load_config");

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = sts_manager.get_identity().await.unwrap();

    // validate identity
    match resources.clone().identity {
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
            resources.identity = Some(current_identity);
        }
    }

    // set defaults based on ID
    if resources.ec2_key_name.is_none() {
        resources.ec2_key_name = Some(format!("{}-ec2-key", spec.id));
    }
    if resources.cloudformation_ec2_instance_role.is_none() {
        resources.cloudformation_ec2_instance_role =
            Some(blizzardup_aws::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if resources.cloudformation_vpc.is_none() {
        resources.cloudformation_vpc =
            Some(blizzardup_aws::StackName::Vpc(spec.id.clone()).encode());
    }
    if resources.cloudformation_asg_blizzards.is_none() {
        resources.cloudformation_asg_blizzards =
            Some(blizzardup_aws::StackName::AsgBlizzards(spec.id.clone()).encode());
    }
    spec.resources = Some(resources.clone());
    spec.sync(spec_file_path)?;

    // fetch network_id, chain infos and save to spec
    for chain_rpc_url in spec.blizzard_spec.chain_rpc_urls.iter() {
        log::info!("checking chain RPC {chain_rpc_url}");
        let resp = client_info::get_network_id(chain_rpc_url).await?;
        let network_id = resp.result.unwrap().network_id;
        let chain_id = client_evm::chain_id(chain_rpc_url).await?;
        spec.status = Some(blizzardup_aws::status::Status {
            network_id,
            chain_id,
        });
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

    log::info!("creating resources (with spec path {})", spec_file_path);
    let s3_manager = s3::Manager::new(&shared_config);
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
    s3_manager
        .create_bucket(&resources.s3_bucket)
        .await
        .unwrap();

    sleep(Duration::from_secs(1)).await;
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: upload artifacts to S3 bucket\n"),
        ResetColor
    )?;

    // set before we update "upload_artifacts"
    let blizzard_download_source = if let Some(v) = &spec.upload_artifacts {
        if v.blizzard_bin.is_empty() {
            "github"
        } else {
            "s3"
        }
    } else {
        "github"
    };
    if let Some(v) = &spec.upload_artifacts {
        if !v.blizzard_bin.is_empty() {
            // don't compress since we need to download this in user data
            // while instance bootstrapping
            s3_manager
                .put_object(
                    &v.blizzard_bin,
                    &resources.s3_bucket,
                    &blizzardup_aws::StorageNamespace::BlizzardBin(spec.id.clone()).encode(),
                )
                .await
                .expect("failed put_object upload_artifacts.blizzard_bin");
        }

        log::info!("done with uploading artifacts, thus reset!");
        spec.upload_artifacts = None;
        spec.sync(spec_file_path)?;
    } else {
        log::info!("skipping uploading artifacts...");
    }

    log::info!("uploading blizzardup spec file...");
    s3_manager
        .put_object(
            &spec_file_path,
            &resources.s3_bucket,
            &blizzardup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
        )
        .await
        .unwrap();

    if resources.ec2_key_path.is_none() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = get_ec2_key_path(spec_file_path);
        ec2_manager
            .create_key_pair(
                resources.ec2_key_name.clone().unwrap().as_str(),
                ec2_key_path.as_str(),
            )
            .await
            .unwrap();

        s3_manager
            .put_object(
                &ec2_key_path,
                &resources.s3_bucket,
                &blizzardup_aws::StorageNamespace::Ec2AccessKey(spec.id.clone()).encode(),
            )
            .await
            .unwrap();

        resources.ec2_key_path = Some(ec2_key_path);
        spec.resources = Some(resources.clone());
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &resources.s3_bucket,
                &blizzardup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    if resources.cloudformation_ec2_instance_profile_arn.is_none() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_yaml = Asset::get("cfn-templates/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name =
            resources.cloudformation_ec2_instance_role.clone().unwrap();

        let role_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("S3BucketName", &resources.s3_bucket),
        ]);
        cloudformation_manager
            .create_stack(
                ec2_instance_role_stack_name.as_str(),
                Some(vec![Capability::CapabilityNamedIam]),
                OnFailure::Delete,
                ec2_instance_role_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("blizzardup")
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
                resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.resources = Some(resources.clone());
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &resources.s3_bucket,
                &blizzardup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    if resources.cloudformation_vpc_id.is_none()
        && resources.cloudformation_vpc_security_group_id.is_none()
        && resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cfn-templates/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = resources.cloudformation_vpc.clone().unwrap();
        let vpc_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("SshPortIngressIpv4Range", "0.0.0.0/0"),
        ]);
        cloudformation_manager
            .create_stack(
                vpc_stack_name.as_str(),
                None,
                OnFailure::Delete,
                vpc_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("blizzardup")
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
                resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    log::info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.resources = Some(resources.clone());
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &resources.s3_bucket,
                &blizzardup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .unwrap();
    }

    if resources.cloudformation_asg_blizzards_logical_id.is_none() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for blizzards nodes\n"),
            ResetColor
        )?;

        let public_subnet_ids = resources
            .cloudformation_vpc_public_subnet_ids
            .clone()
            .unwrap();
        let mut asg_parameters = Vec::from([
            build_param("Id", &spec.id),
            build_param("NodeKind", "worker"),
            build_param("S3BucketName", &resources.s3_bucket),
            build_param(
                "Ec2KeyPairName",
                &resources.ec2_key_name.clone().unwrap(),
            ),
            build_param(
                "InstanceProfileArn",
                &resources
                    .cloudformation_ec2_instance_profile_arn
                    .clone()
                    .unwrap(),
            ),
            build_param(
                "SecurityGroupId",
                &resources
                    .cloudformation_vpc_security_group_id
                    .clone()
                    .unwrap(),
            ),
            build_param("PublicSubnetIds", &public_subnet_ids.join(",")),
            build_param("ArchType", &spec.machine.arch_type),
            build_param(
                "ImageIdSsmParameter",
                &format!(
                    "/aws/service/canonical/ubuntu/server/20.04/stable/current/{}/hvm/ebs-gp2/ami-id",
                    spec.machine.arch_type
                ),
            ),
            build_param("RustOsType", &spec.machine.rust_os_type),
        ]);

        if !spec.machine.instance_types.is_empty() {
            let instance_types = spec.machine.instance_types.clone();
            asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
            asg_parameters.push(build_param(
                "InstanceTypesCount",
                format!("{}", instance_types.len()).as_str(),
            ));
        }

        asg_parameters.push(build_param(
            "BlizzardDownloadSource",
            blizzard_download_source,
        ));

        let cloudformation_asg_blizzards_yaml =
            Asset::get("cfn-templates/asg_ubuntu.yaml").unwrap();
        let cloudformation_asg_blizzards_tmpl =
            std::str::from_utf8(cloudformation_asg_blizzards_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_blizzards_stack_name =
            resources.cloudformation_asg_blizzards.clone().unwrap();

        let desired_capacity = spec.machine.nodes;

        let is_spot_instance = spec.machine.instance_mode == String::from("spot");
        let on_demand_pct = if is_spot_instance { 0 } else { 100 };
        asg_parameters.push(build_param("InstanceMode", &spec.machine.instance_mode));
        asg_parameters.push(build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ));

        // AutoScalingGroupName: !Join ["-", [!Ref Id, !Ref NodeKind, !Ref ArchType]]
        asg_parameters.push(build_param(
            "AsgName",
            format!("{}-worker-{}", spec.id, spec.machine.arch_type).as_str(),
        ));
        asg_parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        // for CFN template updates
        // ref. "Temporarily setting autoscaling group MinSize and DesiredCapacity to 2."
        // ref. "Rolling update initiated. Terminating 1 obsolete instance(s) in batches of 1, while keeping at least 1 instance(s) in service."
        asg_parameters.push(build_param(
            "AsgMaxSize",
            format!("{}", desired_capacity + 1).as_str(),
        ));

        cloudformation_manager
            .create_stack(
                cloudformation_asg_blizzards_stack_name.as_str(),
                None,
                OnFailure::Delete,
                cloudformation_asg_blizzards_tmpl,
                Some(Vec::from([Tag::builder()
                    .key("KIND")
                    .value("blizzardup")
                    .build()])),
                Some(asg_parameters),
            )
            .await
            .unwrap();

        // add 5-minute for ELB creation + volume provisioner
        let mut wait_secs = 700 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        sleep(Duration::from_secs(60)).await;
        let stack = cloudformation_manager
            .poll_stack(
                cloudformation_asg_blizzards_stack_name.as_str(),
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
                resources.cloudformation_asg_blizzards_logical_id = Some(v);
                continue;
            }
        }
        if resources.cloudformation_asg_blizzards_logical_id.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "resources.cloudformation_asg_blizzards_logical_id not found",
            ));
        }

        spec.resources = Some(resources.clone());
        spec.sync(spec_file_path)?;

        let asg_name = resources
            .cloudformation_asg_blizzards_logical_id
            .clone()
            .expect("unexpected None cloudformation_asg_blizzards_logical_id");

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let target_nodes = spec.machine.nodes;
        for _ in 0..20 {
            // TODO: better retries
            log::info!(
                "fetching all droplets for non-anchor node SSH access (target nodes {})",
                target_nodes
            );
            droplets = ec2_manager.list_asg(&asg_name).await.unwrap();
            if droplets.len() >= target_nodes {
                break;
            }
            log::info!(
                "retrying fetching all droplets (only got {})",
                droplets.len()
            );
            sleep(Duration::from_secs(30)).await;
        }

        let ec2_key_path = resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();

        println!();
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            println!(
                "# change SSH key permission
chmod 400 {}
# instance '{}' ({}, {})
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
                resources.region,
                d.instance_id,
            );
        }
        println!();

        spec.resources = Some(resources.clone());
        spec.sync(spec_file_path)?;

        s3_manager
            .put_object(
                &spec_file_path,
                &resources.s3_bucket,
                &blizzardup_aws::StorageNamespace::ConfigFile(spec.id.clone()).encode(),
            )
            .await
            .expect("failed put_object ConfigFile");

        log::info!("waiting for non-anchor nodes bootstrap and ready (to be safe)");
        sleep(Duration::from_secs(20)).await;

        // TODO: check some results by querying metrics

        if term.load(Ordering::Relaxed) {
            log::warn!("received signal {}", signal_hook::consts::SIGINT);
            println!();
            println!("# run the following to delete resources");
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "{} delete \\\n--delete-cloudwatch-log-group \\\n--delete-s3-objects \\\n--spec-file-path {}\n",
                    exec_path.display(),
                    spec_file_path
                )),
                ResetColor
            )?;
        };
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
