use std::{
    fs,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    sync::Arc,
};

use crate::flags;
use avalanche_sdk::health as api_health;
use avalanche_types::node;
use aws_manager::{
    self, cloudwatch, ec2,
    kms::{self, envelope},
    s3,
};
use aws_sdk_ec2::model::{Filter, Tag};
use infra_aws::{certs, telemetry};
use tokio::time::{sleep, Duration};

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting avalanched-aws-lite");

    log::info!("STEP 1: fetching EC2 instance metadata...");
    let meta = fetch_metadata().await?;
    log::info!("fetched availability zone {}", meta.az);
    log::info!("fetched region {}", meta.region);
    log::info!("fetched EC2 instance Id {}", meta.ec2_instance_id);
    log::info!("fetched public ipv4 {}", meta.public_ipv4);

    log::info!(
        "STEP 2: loading up AWS credential for region '{}'...",
        meta.region
    );
    let aws_creds = load_aws_credential(Arc::new(meta.region)).await?;

    log::info!("STEP 3: fetching tags...");
    let tags = fetch_tags(
        Arc::new(aws_creds.ec2_manager.clone()),
        Arc::new(meta.ec2_instance_id.clone()),
    )
    .await?;

    log::info!("STEP 4: installing Avalanche...");
    install_avalanche(
        &tags.os_type.clone(),
        &tags.arch_type.clone(),
        &tags.avalanche_bin_path.clone(),
    )
    .await?;

    log::info!("STEP 5: writing Avalanche config file...");
    let avalanchego_config = write_avalanche_config(tags.network_id, &meta.public_ipv4)?;

    log::info!("STEP 6: writing coreth config file...");
    write_coreth_config(&avalanchego_config.chain_config_dir.clone())?;

    log::info!("STEP 7: creating CloudWatch JSON config file...");
    create_cloudwatch_config(
        &tags.id,
        tags.node_kind,
        &avalanchego_config.log_dir,
        true,
        true,
        &tags.avalanche_data_volume_path,
        &tags.cloudwatch_config_file_path,
    )?;

    log::info!("STEP 8: setting up certificates...");
    let envelope_manager = envelope::Manager::new(
        aws_creds.kms_manager.clone(),
        tags.kms_cmk_arn.to_string(),
        tags.aad_tag.to_string(),
    );
    let certs_manager = certs::Manager {
        envelope_manager,
        s3_manager: aws_creds.s3_manager.clone(),
        s3_bucket: tags.s3_bucket.to_string(),
    };
    let tls_key_path = avalanchego_config.staking_tls_key_file.clone().unwrap();
    let tls_cert_path = avalanchego_config.staking_tls_cert_file.clone().unwrap();
    let (node_id, newly_generated) = certs_manager
        .load_or_generate(&tls_key_path, &tls_cert_path)
        .await?;
    log::info!(
        "loaded node ID {} (was generated {})",
        node_id,
        newly_generated
    );

    if newly_generated {
        log::info!("STEP 8: backing up newly generated certificates...");

        let s3_key_tls_key = format!("{}/pki/{}.key.zstd.encrypted", tags.id, node_id);
        let s3_key_tls_cert = format!("{}/pki/{}.crt.zstd.encrypted", tags.id, node_id);

        certs_manager
            .upload(
                &tls_key_path,
                &tls_cert_path,
                &s3_key_tls_key,
                &s3_key_tls_cert,
            )
            .await?;
    }

    if newly_generated {
        log::info!("STEP 8: creating tags for EBS volume with node Id...");

        // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
        let filters: Vec<Filter> = vec![
            Filter::builder()
                .set_name(Some(String::from("attachment.device")))
                .set_values(Some(vec![tags
                    .avalanche_data_volume_ebs_device_name
                    .clone()]))
                .build(),
            // ensures the call only returns the volume that is attached to this local instance
            Filter::builder()
                .set_name(Some(String::from("attachment.instance-id")))
                .set_values(Some(vec![meta.ec2_instance_id.clone()]))
                .build(),
            // ensures the call only returns the volume that is currently attached
            Filter::builder()
                .set_name(Some(String::from("attachment.status")))
                .set_values(Some(vec![String::from("attached")]))
                .build(),
            // ensures the call only returns the volume that is currently in use
            Filter::builder()
                .set_name(Some(String::from("status")))
                .set_values(Some(vec![String::from("in-use")]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("availability-zone")))
                .set_values(Some(vec![meta.az.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("tag:Id")))
                .set_values(Some(vec![tags.id.clone()]))
                .build(),
        ];
        let volumes = aws_creds
            .ec2_manager
            .describe_volumes(Some(filters))
            .await
            .expect("failed describe_volumes");
        log::info!("found {} attached volume", volumes.len());
        assert!(volumes.len() == 1);
        let volume_id = volumes[0].volume_id().unwrap();

        if let Some(v) = volumes[0].tags() {
            let mut tag_exists = false;
            for tg in v.iter() {
                let k = tg.key().unwrap();
                let v = tg.value().unwrap();
                log::info!("'{}' volume tag found {}={}", volume_id, k, v);
                if k.eq("NODE_ID") {
                    tag_exists = true;
                    break;
                }
            }
            if tag_exists {
                log::warn!(
                    "volume '{}' already has NODE_ID tag -- skipping creating tags",
                    volume_id
                );
            } else {
                // assume all data from EBS are never lost
                // and since we persist and retain ever generated certs
                // in the mounted dir, we can safely assume "create tags"
                // will only be called once per volume
                // ref. https://docs.aws.amazon.com/cli/latest/reference/ec2/create-tags.html
                log::info!("creating NODE_ID tag to the EBS volume '{}'", volume_id);
                let ec2_cli = aws_creds.ec2_manager.clone().client();
                ec2_cli
                    .create_tags()
                    .resources(volume_id)
                    .tags(
                        Tag::builder()
                            .key(String::from("NODE_ID"))
                            .value(node_id.to_string())
                            .build(),
                    )
                    .send()
                    .await
                    .map_err(|e| {
                        Error::new(ErrorKind::Other, format!("failed create_tags {}", e))
                    })?;
                log::info!("added node Id tag to the EBS volume '{}'", volume_id);
            }
        }
    }

    log::info!("STEP 9: setting up and starting Avalanche systemd service...");
    start_avalanche_systemd_service(&tags.avalanche_bin_path, avalanchego_config.clone())?;

    log::info!("STEP 10: checking liveness...");
    let http_scheme = {
        if avalanchego_config.http_tls_enabled.is_some()
            && avalanchego_config
                .http_tls_enabled
                .expect("unexpected None avalanchego_config.http_tls_enabled")
        {
            "https"
        } else {
            "http"
        }
    };
    let ep = format!(
        "{}://{}:{}",
        http_scheme, meta.public_ipv4, avalanchego_config.http_port
    );
    check_liveness(&ep).await?;

    log::info!("STEP 11: fetching Avalanche metrics...");
    telemetry::metrics::avalanchego::fetch_loop(
        aws_creds.cw_manager.clone(),
        Arc::new(tags.id.clone()),
        Duration::from_secs(120),
        Duration::from_secs(60),
        Arc::new(ep.to_string()),
    )
    .await;

    Ok(())
}

struct Metadata {
    az: String,
    region: String,
    ec2_instance_id: String,
    public_ipv4: String,
}

async fn fetch_metadata() -> io::Result<Metadata> {
    let az = ec2::fetch_availability_zone().await.map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed fetch_availability_zone {}", e),
        )
    })?;

    let reg = ec2::fetch_region()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_region {}", e)))?;

    let ec2_instance_id = ec2::fetch_instance_id()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_instance_id {}", e)))?;

    let public_ipv4 = ec2::fetch_public_ipv4()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_public_ipv4 {}", e)))?;

    Ok(Metadata {
        az,
        region: reg,
        ec2_instance_id,
        public_ipv4,
    })
}

struct AwsCreds {
    ec2_manager: ec2::Manager,
    kms_manager: kms::Manager,
    s3_manager: s3::Manager,
    cw_manager: cloudwatch::Manager,
}

async fn load_aws_credential(reg: Arc<String>) -> io::Result<AwsCreds> {
    let shared_config = aws_manager::load_config(Some(reg.to_string())).await?;

    let ec2_manager = ec2::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    Ok(AwsCreds {
        ec2_manager,
        kms_manager,
        s3_manager,
        cw_manager,
    })
}

struct Tags {
    id: String,
    network_id: u32,
    arch_type: String,
    os_type: String,
    node_kind: node::Kind,
    kms_cmk_arn: String,
    aad_tag: String,
    s3_bucket: String,
    cloudwatch_config_file_path: String,
    avalanched_bin_path: String,
    avalanche_bin_path: String,
    avalanche_data_volume_path: String,
    avalanche_data_volume_ebs_device_name: String,
}

async fn fetch_tags(
    ec2_manager: Arc<ec2::Manager>,
    ec2_instance_id: Arc<String>,
) -> io::Result<Tags> {
    let tags = ec2_manager
        .fetch_tags(ec2_instance_id)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_tags {}", e)))?;

    let mut fetched_tags = Tags {
        id: String::new(),
        network_id: 0,
        arch_type: String::new(),
        os_type: String::new(),
        node_kind: node::Kind::Unknown(String::new()),
        kms_cmk_arn: String::new(),
        aad_tag: String::new(),
        s3_bucket: String::new(),
        cloudwatch_config_file_path: String::new(),
        avalanched_bin_path: String::new(),
        avalanche_bin_path: String::new(),
        avalanche_data_volume_path: String::new(),
        avalanche_data_volume_ebs_device_name: String::new(),
    };
    for c in tags {
        let k = c.key().unwrap();
        let v = c.value().unwrap();

        log::info!("EC2 tag key='{}', value='{}'", k, v);
        match k {
            "ID" => {
                fetched_tags.id = v.to_string();
            }
            "NETWORK_ID" => {
                fetched_tags.network_id = v.to_string().parse::<u32>().unwrap();
            }
            "ARCH_TYPE" => {
                fetched_tags.arch_type = v.to_string();
            }
            "OS_TYPE" => {
                fetched_tags.os_type = v.to_string();
            }
            "NODE_KIND" => {
                fetched_tags.node_kind = if v.to_string().eq("anchor") {
                    node::Kind::Anchor
                } else {
                    node::Kind::NonAnchor
                };
            }
            "KMS_CMK_ARN" => {
                fetched_tags.kms_cmk_arn = v.to_string();
            }
            "AAD_TAG" => {
                fetched_tags.aad_tag = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                fetched_tags.s3_bucket = v.to_string();
            }
            "CLOUDWATCH_CONFIG_FILE_PATH" => {
                fetched_tags.cloudwatch_config_file_path = v.to_string();
            }
            "AVALANCHED_BIN_PATH" => {
                fetched_tags.avalanched_bin_path = v.to_string();
            }
            "AVALANCHE_BIN_PATH" => {
                fetched_tags.avalanche_bin_path = v.to_string();
            }
            "AVALANCHE_DATA_VOLUME_PATH" => {
                fetched_tags.avalanche_data_volume_path = v.to_string();
            }
            "AVALANCHE_DATA_VOLUME_EBS_DEVICE_NAME" => {
                fetched_tags.avalanche_data_volume_ebs_device_name = v.to_string();
            }
            _ => {}
        }
    }

    assert!(!fetched_tags.id.is_empty());
    assert!(!fetched_tags.network_id > 0);
    assert!(
        fetched_tags.node_kind == node::Kind::Anchor
            || fetched_tags.node_kind == node::Kind::NonAnchor
    );
    assert!(!fetched_tags.arch_type.is_empty());
    assert!(!fetched_tags.os_type.is_empty());
    assert!(!fetched_tags.kms_cmk_arn.is_empty());
    assert!(!fetched_tags.aad_tag.is_empty());
    assert!(!fetched_tags.s3_bucket.is_empty());
    assert!(!fetched_tags.cloudwatch_config_file_path.is_empty());
    assert!(!fetched_tags.avalanched_bin_path.is_empty());
    assert!(!fetched_tags.avalanche_bin_path.is_empty());
    assert!(!fetched_tags.avalanche_data_volume_path.is_empty());
    assert!(!fetched_tags
        .avalanche_data_volume_ebs_device_name
        .is_empty());

    Ok(fetched_tags)
}

async fn install_avalanche(
    arch_type: &str,
    os_type: &str,
    avalanche_bin_path: &str,
) -> io::Result<()> {
    let arch = if arch_type.to_string() == "amd64" {
        Some(avalanche_installer::avalanchego::Arch::Amd64)
    } else {
        None
    };
    let os = if os_type.to_string() == "linux" {
        Some(avalanche_installer::avalanchego::Os::Linux)
    } else {
        None
    };

    let (binary_path, _) = avalanche_installer::avalanchego::download(arch, os).await?;
    fs::copy(&binary_path, avalanche_bin_path)?;

    let plugins_dir = avalanche_installer::avalanchego::get_plugins_dir(avalanche_bin_path);
    if !Path::new(&plugins_dir).exists() {
        log::info!("creating '{}' directory for plugins", plugins_dir);
        fs::create_dir_all(plugins_dir.clone())?;
    };

    Ok(())
}

/// TODO: support other networks
fn write_avalanche_config(
    network_id: u32,
    public_ipv4: &str,
) -> io::Result<avalanchego::config::Config> {
    let mut avalanchego_config = match network_id {
        1 => avalanchego::config::Config::default_main(),
        5 => avalanchego::config::Config::default_fuji(),
        _ => avalanchego::config::Config::default_custom(),
    };
    avalanchego_config.network_id = network_id;
    avalanchego_config.public_ip = Some(public_ipv4.to_string());
    avalanchego_config.sync(None)?;

    Ok(avalanchego_config)
}

fn write_coreth_config(chain_config_dir: &str) -> io::Result<()> {
    fs::create_dir_all(Path::new(chain_config_dir).join("C"))?;

    let coreth_config = coreth::config::Config::default();

    let tmp_coreth_config_path = random_manager::tmp_path(15, Some(".json")).unwrap();
    let chain_config_c_path = Path::new(chain_config_dir).join("C").join("config.json");

    coreth_config.sync(&tmp_coreth_config_path)?;
    fs::copy(&tmp_coreth_config_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_coreth_config_path)?;

    log::info!(
        "saved default coreth config file to {:?}",
        chain_config_c_path.as_os_str()
    );

    Ok(())
}

fn create_cloudwatch_config(
    id: &str,
    node_kind: node::Kind,
    avalanche_logs_dir: &str,
    instance_system_logs: bool,
    instance_system_metrics: bool,
    avalanche_data_volume_path: &str,
    cloudwatch_config_file_path: &str,
) -> io::Result<()> {
    let cw_config_manager = telemetry::cloudwatch::ConfigManager {
        id: id.to_string(),
        node_kind,
        log_dir: avalanche_logs_dir.to_string(),

        instance_system_logs,
        instance_system_metrics,

        data_volume_path: Some(avalanche_data_volume_path.to_string()),

        config_file_path: cloudwatch_config_file_path.to_string(),
    };
    cw_config_manager.sync(Some(vec![String::from("/var/log/avalanched.log")]))
}

fn start_avalanche_systemd_service(
    avalanche_bin_path: &str,
    avalanchego_config: avalanchego::config::Config,
) -> io::Result<()> {
    // persist before starting the service
    avalanchego_config
        .sync(None)
        .expect("failed to sync avalanchego config_file");

    // don't use "Type=notify"
    // as "avalanchego" currently does not do anything specific to systemd
    // ref. "expected that the service sends a notification message via sd_notify"
    // ref. https://www.freedesktop.org/software/systemd/man/systemd.service.html
    //
    // NOTE: remove "StandardOutput" and "StandardError" since we already
    // wildcard all log files in "/var/log/avalanche" (a lot of duplicates)
    let avalanche_service_file_contents = format!(
        "[Unit]
Description=avalanche node

[Service]
Type=exec
TimeoutStartSec=300
Restart=always
RestartSec=5s
LimitNOFILE=40000
ExecStart={} --config-file={}
StandardOutput=append:/var/log/avalanche/avalanche.log
StandardError=append:/var/log/avalanche/avalanche.log

[Install]
WantedBy=multi-user.target",
        avalanche_bin_path,
        avalanchego_config.clone().config_file.unwrap(),
    );

    let mut avalanche_service_file = tempfile::NamedTempFile::new()?;
    avalanche_service_file.write_all(avalanche_service_file_contents.as_bytes())?;

    let avalanche_service_file_path = avalanche_service_file.path().to_str().unwrap();
    fs::copy(
        avalanche_service_file_path,
        "/etc/systemd/system/avalanche.service",
    )?;

    command_manager::run("sudo systemctl daemon-reload")?;
    command_manager::run("sudo systemctl disable avalanche.service")?;
    command_manager::run("sudo systemctl enable avalanche.service")?;
    command_manager::run("sudo systemctl restart --no-block avalanche.service")?;

    Ok(())
}

async fn check_liveness(ep: &str) -> io::Result<()> {
    loop {
        let ret = api_health::spawn_check(&ep, true).await;
        match ret {
            Ok(res) => {
                if res.healthy.is_some() && res.healthy.unwrap() {
                    log::info!("health/liveness check success");
                    break;
                }
            }
            Err(e) => {
                log::warn!("health/liveness check failed ({:?})", e);
            }
        };
        sleep(Duration::from_secs(30)).await;

        let out = command_manager::run("sudo tail -10 /var/log/avalanche/avalanche.log")?;
        println!(
            "\n'/var/log/avalanche/avalanche.log' stdout:\n\n{}\n",
            out.0
        );
        println!("'/var/log/avalanche/avalanche.log' stderr:\n\n{}\n", out.1);

        println!();
        let out =
            command_manager::run("sudo journalctl -u avalanche.service --lines=10 --no-pager")?;
        println!("\n'avalanche.service' stdout:\n\n{}\n", out.0);
        println!("'avalanche.service' stderr:\n\n{}\n", out.1);
    }

    Ok(())
}
