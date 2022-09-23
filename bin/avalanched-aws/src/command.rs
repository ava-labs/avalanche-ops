use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
};

use avalanche_sdk::health as api_health;
use avalanche_types::{genesis as avalanchego_genesis, node};
use aws_manager::{
    self, autoscaling, ec2,
    kms::{self, envelope},
    s3,
};
use aws_sdk_ec2::model::{Filter, Tag, Volume};
use infra_aws::{certs, telemetry};
use tokio::time::{sleep, Duration};

pub async fn execute(opts: crate::flags::Options) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting {}", crate::APP_NAME);

    let meta = fetch_metadata().await?;

    let aws_creds = load_aws_credential(&meta.region).await?;
    let ec2_manager_arc = Arc::new(aws_creds.ec2_manager.clone());
    let asg_manager_arc = Arc::new(aws_creds.asg_manager.clone());
    let s3_manager_arc = Arc::new(aws_creds.s3_manager.clone());

    let tags = fetch_tags(
        Arc::clone(&ec2_manager_arc),
        Arc::new(meta.ec2_instance_id.clone()),
    )
    .await?;

    let (
        mut avalanchego_config,
        coreth_config,
        subnet_evm_config,
        download_avalanchego_from_github,
        metrics_rules,
    ) = if opts.use_default_config {
        let avalanchego_config =
            write_default_avalanche_config(tags.network_id, &meta.public_ipv4)?;
        let coreth_config = write_default_coreth_config(&avalanchego_config.chain_config_dir)?;

        (
            avalanchego_config,
            coreth_config,
            None,
            true,
            avalancheup_aws::default_rules(),
        )
    } else {
        let spec = download_spec(
            Arc::clone(&s3_manager_arc),
            &tags.s3_bucket,
            &tags.id,
            &meta.public_ipv4,
            &tags.avalancheup_spec_path,
        )
        .await?;
        write_coreth_config_from_spec(&spec)?;
        write_subnet_evm_config_from_spec(&spec)?;

        let metrics_rules = if let Some(mm) = spec.metrics_rules {
            mm
        } else {
            avalancheup_aws::default_rules()
        };
        (
            spec.avalanchego_config.clone(),
            spec.coreth_config.clone(),
            spec.subnet_evm_config.clone(),
            spec.install_artifacts.avalanchego_bin.is_none(),
            metrics_rules,
        )
    };
    if !Path::new(&tags.avalanche_telemetry_cloudwatch_rules_file_path).exists() {
        metrics_rules.sync(&tags.avalanche_telemetry_cloudwatch_rules_file_path)?;
    } else {
        log::warn!("skipping writing avalanche-telemetry-cloudwatch rules file (already exists)")
    }

    // do not overwrite "avalanchego" binary
    if !Path::new(&tags.avalanche_bin_path).exists() {
        if download_avalanchego_from_github {
            install_avalanche_from_github(
                &tags.os_type.clone(),
                &tags.arch_type.clone(),
                &tags.avalanche_bin_path.clone(),
            )
            .await?;
        } else {
            install_avalanche_from_s3(
                Arc::clone(&s3_manager_arc),
                &tags.s3_bucket,
                &tags.id,
                &tags.avalanche_bin_path.clone(),
            )
            .await?;
        }
    } else {
        log::warn!("skipping downloading avalanche binary (already exists)")
    }

    if !Path::new(&tags.cloudwatch_config_file_path).exists() {
        create_cloudwatch_config(
            &tags.id,
            tags.node_kind.clone(),
            &avalanchego_config.log_dir,
            true,
            true,
            &tags.avalanche_data_volume_path,
            &tags.cloudwatch_config_file_path,
        )?;
    } else {
        log::warn!("skipping writing cloudwatch config (already exists)")
    }

    let attached_volume = find_attached_volume(
        Arc::clone(&ec2_manager_arc),
        &tags.avalanche_data_volume_ebs_device_name,
        &meta.ec2_instance_id,
        &meta.az,
        &tags.id,
    )
    .await?;
    let attached_volume_id = attached_volume.volume_id().unwrap();

    log::info!("STEP: setting up certificates...");
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
        log::info!("STEP: backing up newly generated certificates...");

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
        log::info!("STEP: creating tags for EBS volume with node Id...");

        if let Some(v) = attached_volume.tags() {
            let mut tag_exists = false;
            for tg in v.iter() {
                let k = tg.key().unwrap();
                let v = tg.value().unwrap();
                log::info!("'{}' volume tag found {}={}", attached_volume_id, k, v);
                if k.eq("NODE_ID") {
                    tag_exists = true;
                    break;
                }
            }
            if tag_exists {
                log::warn!(
                    "volume '{}' already has NODE_ID tag -- overwriting tags",
                    attached_volume_id
                );
            }

            // assume all data from EBS are never lost
            // and since we persist and retain ever generated certs
            // in the mounted dir, we can safely assume "create tags"
            // will only be called once per volume
            // ref. https://docs.aws.amazon.com/cli/latest/reference/ec2/create-tags.html
            log::info!(
                "creating NODE_ID tag to the EBS volume '{}'",
                attached_volume_id
            );
            let ec2_cli = aws_creds.ec2_manager.clone().client();
            ec2_cli
                .create_tags()
                .resources(attached_volume_id)
                .tags(
                    Tag::builder()
                        .key(String::from("NODE_ID"))
                        .value(node_id.to_string())
                        .build(),
                )
                .send()
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("failed create_tags {}", e)))?;
            log::info!(
                "added node Id tag to the EBS volume '{}'",
                attached_volume_id
            );
        }
    }

    if avalanchego_config.is_custom_network()
        && avalanchego_config.genesis.is_some()
        && !Path::new(&avalanchego_config.clone().genesis.unwrap()).exists()
    // check "exists" for idempotency
    {
        log::info!("STEP: running discover/genesis updates for custom network...");

        if matches!(tags.node_kind, node::Kind::Anchor) {
            let bootstrappiong_anchor_node_s3_keys = discover_bootstrapping_anchor_nodes_from_s3(
                &meta.ec2_instance_id,
                &node_id.to_string(),
                &meta.public_ipv4,
                Arc::clone(&s3_manager_arc),
                &tags.s3_bucket,
                &tags.avalancheup_spec_path,
            )
            .await?;

            merge_bootstrapping_anchor_nodes_to_write_genesis(
                bootstrappiong_anchor_node_s3_keys,
                &tags.avalancheup_spec_path,
            )?;

            // for now, just overwrite from every seed anchor node
            sleep(Duration::from_secs(1)).await;

            log::info!("STEP: uploading the new genesis file from each anchor node, which is to be shared with non-anchor nodes");
            s3::spawn_put_object(
                aws_creds.s3_manager.clone(),
                &avalanchego_config.clone().genesis.unwrap(),
                &tags.s3_bucket,
                &avalancheup_aws::StorageNamespace::GenesisFile(tags.id.clone()).encode(),
            )
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_put_object {}", e)))?;
        }

        if matches!(tags.node_kind, node::Kind::NonAnchor) {
            download_genesis_from_ready_anchor_nodes(
                Arc::clone(&s3_manager_arc),
                &tags.s3_bucket,
                &tags.avalancheup_spec_path,
            )
            .await?;

            let (bootstrap_ids, bootstrap_ips) = discover_ready_anchor_nodes_from_s3(
                Arc::clone(&s3_manager_arc),
                &tags.s3_bucket,
                &tags.avalancheup_spec_path,
            )
            .await?;

            // whenever updating "avalanchego_config", we must persist locally
            // via spec file for next spec loads
            log::info!(
                "updating spec and avalanchego_config with bootstrap Ids '{:?}' and Ips '{:?}'",
                bootstrap_ids,
                bootstrap_ips
            );
            avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
            avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));

            let mut spec = avalancheup_aws::Spec::load(&tags.avalancheup_spec_path)?;
            spec.avalanchego_config = avalanchego_config.clone();

            spec.sync(&tags.avalancheup_spec_path)?;
            spec.avalanchego_config.sync(None)?;
        }
    }

    stop_and_start_avalanche_systemd_service(
        &tags.avalanche_bin_path,
        &avalanchego_config,
        &coreth_config,
        subnet_evm_config,
    )?;
    stop_and_start_avalanche_telemetry_cloudwatch_systemd_service(
        &tags.avalanche_telemetry_cloudwatch_bin_path,
        &tags.avalanche_telemetry_cloudwatch_rules_file_path,
        &tags.id,
        avalanchego_config.http_port,
    )?;

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

    let mut handles = vec![tokio::spawn(publish_node_info_ready_loop(
        Arc::new(meta.ec2_instance_id.clone()),
        tags.node_kind.clone(),
        Arc::new(node_id.to_string()),
        Arc::new(meta.public_ipv4.clone()),
        Arc::clone(&s3_manager_arc),
        Arc::new(tags.s3_bucket.clone()),
        Arc::new(tags.avalancheup_spec_path.clone()),
        opts.publish_periodic_node_info,
    ))];

    // assume the tag value is static
    // assume we don't change on-demand to spot, or vice versa
    // if someone changes, tag needs to be updated manually and restart avalanched
    if tags.asg_spot_instance {
        handles.push(tokio::spawn(monitor_spot_instance_action(
            Arc::clone(&ec2_manager_arc),
            Arc::clone(&asg_manager_arc),
            Arc::new(meta.ec2_instance_id.clone()),
            Arc::new(attached_volume_id.to_string()),
        )));
    } else {
        log::info!("skipped monitoring the spot instance-action...");
    }

    log::info!("STEP: blocking on handles via JoinHandle");
    for handle in handles {
        handle.await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed await on JoinHandle {}", e),
            )
        })?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct Metadata {
    az: String,
    region: String,
    ec2_instance_id: String,
    public_ipv4: String,
}

async fn fetch_metadata() -> io::Result<Metadata> {
    log::info!("STEP: fetching EC2 instance metadata...");

    let az = ec2::metadata::fetch_availability_zone()
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed fetch_availability_zone {}", e),
            )
        })?;
    log::info!("fetched availability zone {}", az);

    let reg = ec2::metadata::fetch_region()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_region {}", e)))?;
    log::info!("fetched region {}", reg);

    let ec2_instance_id = ec2::metadata::fetch_instance_id()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_instance_id {}", e)))?;
    log::info!("fetched EC2 instance Id {}", ec2_instance_id);

    let public_ipv4 = ec2::metadata::fetch_public_ipv4()
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_public_ipv4 {}", e)))?;
    log::info!("fetched public ipv4 {}", public_ipv4);

    Ok(Metadata {
        az,
        region: reg,
        ec2_instance_id,
        public_ipv4,
    })
}

#[derive(Debug, Clone)]
struct AwsCreds {
    ec2_manager: ec2::Manager,
    asg_manager: autoscaling::Manager,
    kms_manager: kms::Manager,
    s3_manager: s3::Manager,
}

async fn load_aws_credential(reg: &str) -> io::Result<AwsCreds> {
    log::info!("STEP: loading up AWS credential for region '{}'...", reg);

    let shared_config = aws_manager::load_config(Some(reg.to_string())).await?;

    let ec2_manager = ec2::Manager::new(&shared_config);
    let asg_manager = autoscaling::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);

    Ok(AwsCreds {
        ec2_manager,
        asg_manager,
        kms_manager,
        s3_manager,
    })
}

#[derive(Debug, Clone)]
struct Tags {
    id: String,
    network_id: u32,
    arch_type: String,
    os_type: String,
    asg_spot_instance: bool,
    node_kind: node::Kind,
    kms_cmk_arn: String,
    aad_tag: String,
    s3_bucket: String,
    cloudwatch_config_file_path: String,
    avalanche_telemetry_cloudwatch_bin_path: String,
    avalanche_telemetry_cloudwatch_rules_file_path: String,
    avalancheup_spec_path: String,
    avalanched_bin_path: String,
    avalanche_bin_path: String,
    avalanche_data_volume_path: String,
    avalanche_data_volume_ebs_device_name: String,
}

async fn fetch_tags(
    ec2_manager: Arc<ec2::Manager>,
    ec2_instance_id: Arc<String>,
) -> io::Result<Tags> {
    log::info!("STEP: fetching tags...");

    let tags = ec2_manager
        .fetch_tags(ec2_instance_id)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_tags {}", e)))?;

    let mut fetched_tags = Tags {
        id: String::new(),
        network_id: 0,
        arch_type: String::new(),
        os_type: String::new(),
        asg_spot_instance: false,
        node_kind: node::Kind::Unknown(String::new()),
        kms_cmk_arn: String::new(),
        aad_tag: String::new(),
        s3_bucket: String::new(),
        cloudwatch_config_file_path: String::new(),
        avalanche_telemetry_cloudwatch_bin_path: String::new(),
        avalanche_telemetry_cloudwatch_rules_file_path: String::new(),
        avalancheup_spec_path: String::new(),
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
            "ASG_SPOT_INSTANCE" => {
                fetched_tags.asg_spot_instance = v.to_string().to_lowercase().eq("true");
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
            "AVALANCHE_TELEMETRY_CLOUDWATCH_BIN_PATH" => {
                fetched_tags.avalanche_telemetry_cloudwatch_bin_path = v.to_string();
            }
            "AVALANCHE_TELEMETRY_CLOUDWATCH_RULES_FILE_PATH" => {
                fetched_tags.avalanche_telemetry_cloudwatch_rules_file_path = v.to_string();
            }
            "AVALANCHEUP_SPEC_PATH" => {
                fetched_tags.avalancheup_spec_path = v.to_string();
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
    assert!(!fetched_tags
        .avalanche_telemetry_cloudwatch_bin_path
        .is_empty());
    assert!(!fetched_tags
        .avalanche_telemetry_cloudwatch_rules_file_path
        .is_empty());
    assert!(!fetched_tags.avalancheup_spec_path.is_empty());
    assert!(!fetched_tags.avalanched_bin_path.is_empty());
    assert!(!fetched_tags.avalanche_bin_path.is_empty());
    assert!(!fetched_tags.avalanche_data_volume_path.is_empty());
    assert!(!fetched_tags
        .avalanche_data_volume_ebs_device_name
        .is_empty());

    Ok(fetched_tags)
}

async fn download_spec(
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    id: &str,
    public_ipv4: &str,
    avalancheup_spec_path: &str,
) -> io::Result<avalancheup_aws::Spec> {
    log::info!("STEP: downloading avalancheup spec file from S3...");

    let tmp_spec_file_path = random_manager::tmp_path(15, Some(".yaml"))?;

    let s3_manager: &s3::Manager = s3_manager.as_ref();
    s3::spawn_get_object(
        s3_manager.to_owned(),
        s3_bucket,
        &avalancheup_aws::StorageNamespace::ConfigFile(id.to_string()).encode(),
        &tmp_spec_file_path,
    )
    .await
    .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_get_object {}", e)))?;

    let mut spec = avalancheup_aws::Spec::load(&tmp_spec_file_path)?;

    if let Some(config_file) = &spec.avalanchego_config.config_file {
        // if exists, load the existing one in case manually updated
        if Path::new(&config_file).exists() {
            log::info!("config-file '{}' already exists -- skipping writing/syncing one to avoid overwrites, loading existing one", config_file);
            spec.avalanchego_config = avalanchego::config::Config::load(&config_file)?;
        }
    }

    // always overwrite public-ip flag in case of EC2 instance replacement
    spec.avalanchego_config.public_ip = Some(public_ipv4.to_string());
    spec.avalanchego_config.sync(None)?;

    fs::copy(&tmp_spec_file_path, &avalancheup_spec_path)?;
    fs::remove_file(&tmp_spec_file_path)?; // "avalanched" never updates "spec" file, runs in read-only mode

    Ok(spec)
}

fn write_default_avalanche_config(
    network_id: u32,
    public_ipv4: &str,
) -> io::Result<avalanchego::config::Config> {
    log::info!("STEP: writing Avalanche config file...");

    let mut avalanchego_config = match network_id {
        1 => avalanchego::config::Config::default_main(),
        5 => avalanchego::config::Config::default_fuji(),
        _ => avalanchego::config::Config::default_custom(),
    };

    if let Some(config_file) = &avalanchego_config.config_file {
        if Path::new(&config_file).exists() {
            log::info!("avalanchego config-file '{}' already exists -- skipping writing/syncing one to avoid overwrites, loading existing one", config_file);
            return avalanchego::config::Config::load(&config_file);
        };
    }

    avalanchego_config.network_id = network_id;

    // always overwrite public-ip flag in case of EC2 instance replacement
    avalanchego_config.public_ip = Some(public_ipv4.to_string());
    avalanchego_config.sync(None)?;

    Ok(avalanchego_config)
}

fn write_default_coreth_config(chain_config_dir: &str) -> io::Result<coreth::config::Config> {
    log::info!("STEP: writing default coreth config file...");

    fs::create_dir_all(Path::new(chain_config_dir).join("C"))?;

    let coreth_config = coreth::config::Config::default();

    let chain_config_c_path = Path::new(chain_config_dir).join("C").join("config.json");
    if chain_config_c_path.exists() {
        log::info!("coreth C-chain config file '{}' already exists -- skipping writing/syncing one to avoid overwrites, loading existing one", chain_config_c_path.display());
        return coreth::config::Config::load(chain_config_c_path.display().to_string().as_str());
    };

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    coreth_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved default coreth config file to {:?}",
        chain_config_c_path.as_os_str()
    );

    Ok(coreth_config)
}

fn write_coreth_config_from_spec(spec: &avalancheup_aws::Spec) -> io::Result<()> {
    log::info!("STEP: writing coreth config file from spec for the C-chain...");

    let chain_config_dir = spec.avalanchego_config.chain_config_dir.clone();
    fs::create_dir_all(Path::new(&chain_config_dir).join("C"))?;

    // If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
    // the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json.
    // ref. https://docs.avax.network/subnets/customize-a-subnet#chain-configs
    let chain_config_c_path = Path::new(&chain_config_dir).join("C").join("config.json");
    if chain_config_c_path.exists() {
        log::info!("C-chain config file '{}' already exists -- skipping writing/syncing one to avoid overwrites, loading existing one", chain_config_c_path.display());
        return Ok(());
    };

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    spec.coreth_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved coreth config file to {:?}",
        chain_config_c_path.as_os_str()
    );

    Ok(())
}

fn write_subnet_evm_config_from_spec(spec: &avalancheup_aws::Spec) -> io::Result<()> {
    if let Some(subnet_evm_config) = &spec.subnet_evm_config {
        let whitelisted_subnet = spec.avalanchego_config.whitelisted_subnets.clone().unwrap();
        log::info!(
            "STEP: writing subnet-evm config file from spec for '{}'",
            whitelisted_subnet
        );

        let chain_config_dir = spec.avalanchego_config.chain_config_dir.clone();
        let tmp_path = random_manager::tmp_path(15, Some(".json"))?;

        // If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
        // the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json.
        // ref. https://docs.avax.network/subnets/customize-a-subnet#chain-configs
        fs::create_dir_all(Path::new(&chain_config_dir).join(&whitelisted_subnet))?;
        let chain_config_path = Path::new(&chain_config_dir)
            .join(whitelisted_subnet)
            .join("config.json");

        subnet_evm_config.sync(&tmp_path)?;
        fs::copy(&tmp_path, &chain_config_path)?;
        fs::remove_file(&tmp_path)?;

        log::info!(
            "saved subnet-evm config file to {}",
            chain_config_path.display()
        );
    } else {
        log::info!("STEP: no subnet-evm config is found, skipping writiing subnet-evm config file");
    }

    Ok(())
}

async fn install_avalanche_from_github(
    arch_type: &str,
    os_type: &str,
    avalanche_bin_path: &str,
) -> io::Result<()> {
    log::info!("STEP: installing Avalanche from github...");

    let arch = if arch_type == "amd64" {
        Some(avalanche_installer::avalanchego::Arch::Amd64)
    } else {
        None
    };
    let os = if os_type == "linux" {
        Some(avalanche_installer::avalanchego::Os::Linux)
    } else {
        None
    };

    let (binary_path, _) = avalanche_installer::avalanchego::download_latest(arch, os).await?;
    fs::copy(&binary_path, avalanche_bin_path)?;

    let plugins_dir = avalanche_installer::avalanchego::get_plugins_dir(avalanche_bin_path);
    if !Path::new(&plugins_dir).exists() {
        log::info!("creating '{}' directory for plugins", plugins_dir);
        fs::create_dir_all(plugins_dir)?;
    };

    Ok(())
}

async fn install_avalanche_from_s3(
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    id: &str,
    avalanche_bin_path: &str,
) -> io::Result<()> {
    let s3_manager: &s3::Manager = s3_manager.as_ref();

    if !Path::new(avalanche_bin_path).exists() {
        log::info!("STEP: downloading avalanche binary from S3");

        let s3_key =
            avalancheup_aws::StorageNamespace::AvalancheBinCompressed(id.to_string()).encode();
        let tmp_avalanche_bin_compressed_path = random_manager::tmp_path(15, Some(".zstd"))?;

        s3::spawn_get_object(
            s3_manager.to_owned(),
            s3_bucket,
            &s3_key,
            &tmp_avalanche_bin_compressed_path,
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_get_object {}", e)))?;

        compress_manager::unpack_file(
            &tmp_avalanche_bin_compressed_path,
            avalanche_bin_path,
            compress_manager::Decoder::Zstd,
        )?;

        let f = File::open(&avalanche_bin_path).expect("failed to open avalanche_bin");
        f.set_permissions(PermissionsExt::from_mode(0o777))?;
        fs::remove_file(&tmp_avalanche_bin_compressed_path)?;
    }

    let plugins_dir = avalanche_installer::avalanchego::get_plugins_dir(&avalanche_bin_path);
    if !Path::new(&plugins_dir).exists() {
        log::info!("STEP: creating '{}' for plugins", plugins_dir);
        fs::create_dir_all(plugins_dir.clone())?;

        log::info!("STEP: downloading plugins from S3 (if any)");
        let objects = s3::spawn_list_objects(
            s3_manager.to_owned(),
            s3_bucket,
            Some(s3::append_slash(
                &avalancheup_aws::StorageNamespace::PluginsDir(id.to_string()).encode(),
            )),
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_list_objects {}", e)))?;

        log::info!("listed {} plugins from S3", objects.len());
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object").to_string();
            let tmp_path = random_manager::tmp_path(15, None)?;

            s3::spawn_get_object(s3_manager.to_owned(), s3_bucket, &s3_key, &tmp_path)
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Other, format!("failed spawn_get_object {}", e))
                })?;

            let file_name = extract_filename(&s3_key);
            let file_path = format!("{}/{}", plugins_dir, file_name);
            compress_manager::unpack_file(&tmp_path, &file_path, compress_manager::Decoder::Zstd)?;

            let f = File::open(file_path).expect("failed to open plugin file");
            f.set_permissions(PermissionsExt::from_mode(0o777))?;
            fs::remove_file(&tmp_path)?;
        }
    }

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
    log::info!("STEP: creating CloudWatch JSON config file...");

    let cw_config_manager = telemetry::cloudwatch::ConfigManager {
        id: id.to_string(),
        node_kind,
        log_dir: avalanche_logs_dir.to_string(),

        instance_system_logs,
        instance_system_metrics,

        data_volume_path: Some(avalanche_data_volume_path.to_string()),

        config_file_path: cloudwatch_config_file_path.to_string(),
    };
    cw_config_manager.sync(Some(vec![
        String::from("/var/log/cloud-init-output.log"),
        String::from("/var/log/avalanched.log"),
        String::from("/var/log/avalanche-telemetry-cloudwatch.log"),
    ]))
}

async fn find_attached_volume(
    ec2_manager: Arc<ec2::Manager>,
    avalanche_data_volume_ebs_device_name: &str,
    ec2_instance_id: &str,
    az: &str,
    id: &str,
) -> io::Result<Volume> {
    // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
    let filters: Vec<Filter> = vec![
        Filter::builder()
            .set_name(Some(String::from("attachment.device")))
            .set_values(Some(
                vec![avalanche_data_volume_ebs_device_name.to_string()],
            ))
            .build(),
        // ensures the call only returns the volume that is attached to this local instance
        Filter::builder()
            .set_name(Some(String::from("attachment.instance-id")))
            .set_values(Some(vec![ec2_instance_id.to_string()]))
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
            .set_values(Some(vec![az.to_string()]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("tag:Id")))
            .set_values(Some(vec![id.to_string()]))
            .build(),
    ];

    let ec2_manager: &ec2::Manager = ec2_manager.as_ref();
    let volumes = ec2_manager
        .describe_volumes(Some(filters))
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed describe_volumes {}", e)))?;
    log::info!("found {} attached volume", volumes.len());
    if volumes.len() != 1 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("unexpected {} volumes found", volumes.len()),
        ));
    }

    Ok(volumes[0].clone())
}

/// To be called by each bootstrapping anchor node: Each anchor node publishes
/// the anchor node information to the S3, and waits. And each anchor node
/// lists all keys from the bootstrapping s3 directory for its peer discovery.
/// The function returns all s3 keys that contains the anchor node information.
async fn discover_bootstrapping_anchor_nodes_from_s3(
    ec2_instance_id: &str,
    node_id: &str,
    public_ipv4: &str,
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    avalancheup_spec_path: &str,
) -> io::Result<Vec<String>> {
    log::info!("STEP: publishing bootstrapping local anchor node information for discovery...");

    let spec = avalancheup_aws::Spec::load(avalancheup_spec_path)?;

    let http_scheme = {
        if spec.avalanchego_config.http_tls_enabled.is_some()
            && spec
                .avalanchego_config
                .http_tls_enabled
                .expect("unexpected None avalanchego_config.http_tls_enabled")
        {
            "https"
        } else {
            "http"
        }
    };
    let local_node = avalancheup_aws::Node::new(
        node::Kind::Anchor,
        ec2_instance_id,
        node_id,
        public_ipv4,
        http_scheme,
        spec.avalanchego_config.http_port,
    );

    log::info!(
        "loaded local node information:\n{}",
        local_node
            .encode_yaml()
            .expect("failed to encode node Info")
    );

    let node_info = avalancheup_aws::NodeInfo::new(
        local_node.clone(),
        spec.avalanchego_config.clone(),
        spec.coreth_config.clone(),
    );
    let node_info_path = random_manager::tmp_path(10, Some(".yaml"))?;
    node_info.sync(node_info_path.clone()).unwrap();

    let s3_manager: &s3::Manager = s3_manager.as_ref();
    s3::spawn_put_object(
        s3_manager.clone(),
        node_info_path.as_str(),
        s3_bucket,
        &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNode(
            spec.id.clone(),
            local_node.clone(),
        )
        .encode(),
    )
    .await
    .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_put_object {}", e)))?;

    fs::remove_file(node_info_path)?;

    log::info!("waiting some time for initial anchor nodes to start...");
    sleep(Duration::from_secs(30)).await; // enough time for all anchor nodes up to be

    let target_nodes = spec.machine.anchor_nodes.unwrap();
    log::info!("waiting for all other seed/bootstrapping anchor nodes to publish their own (expected total {} nodes)",target_nodes);

    let s3_key_prefix = s3::append_slash(
        &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNodesDir(spec.id).encode(),
    );

    let mut objects: Vec<aws_sdk_s3::model::Object>;
    loop {
        sleep(Duration::from_secs(20)).await;

        objects =
            s3::spawn_list_objects(s3_manager.clone(), s3_bucket, Some(s3_key_prefix.clone()))
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Other, format!("failed spawn_list_objects {}", e))
                })?;

        log::info!(
            "{} seed/bootstrapping anchor nodes are ready (expecting {} nodes)",
            objects.len(),
            target_nodes
        );

        if objects.len() as u32 >= target_nodes {
            break;
        }
    }

    let mut s3_keys: Vec<String> = Vec::new();
    for obj in objects.iter() {
        let s3_key = obj.key().expect("unexpected None s3 object");
        s3_keys.push(s3_key.to_string());
    }
    // s3 API should return the sorted list
    // in the descending order of "last_modified" timestamps
    // but to make sure, sort in lexicographical order
    s3_keys.sort();

    Ok(s3_keys)
}

/// Combines all anchor node Ids and write them into a genesis for initial stakers.
/// The genesis file path is defined in avalanchego "--genesis" flag.
fn merge_bootstrapping_anchor_nodes_to_write_genesis(
    bootstrapping_anchor_node_s3_keys: Vec<String>,
    avalancheup_spec_path: &str,
) -> io::Result<()> {
    log::info!(
        "STEP: combining {} anchor node S3 keys to write genesis...",
        bootstrapping_anchor_node_s3_keys.len()
    );

    let spec = avalancheup_aws::Spec::load(avalancheup_spec_path)?;

    // "initial_staked_funds" is reserved for locked P-chain balance
    // with "spec.generated_seed_private_key_with_locked_p_chain_balance"
    let seed_priv_keys = spec.clone().generated_seed_private_keys.unwrap();
    let seed_priv_key = seed_priv_keys[0].clone();

    let mut initial_stakers: Vec<avalanchego_genesis::Staker> = vec![];
    for s3_key in bootstrapping_anchor_node_s3_keys.iter() {
        // just parse the s3 key name
        // to reduce "s3_manager.get_object" call volume
        let seed_anchor_node = avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key)?;

        let mut staker = avalanchego_genesis::Staker::default();
        staker.node_id = Some(seed_anchor_node.node_id);
        staker.reward_address = Some(
            seed_priv_key
                .addresses
                .get(&format!("{}", spec.avalanchego_config.network_id))
                .unwrap()
                .x_address
                .clone(),
        );

        initial_stakers.push(staker);
    }
    log::info!(
        "found {} seed anchor nodes for initial stakers",
        initial_stakers.len()
    );

    let avalanchego_genesis_path = spec.avalanchego_config.clone().genesis.unwrap();

    let mut avalanchego_genesis_template = spec
        .avalanchego_genesis_template
        .expect("unexpected None avalanchego_genesis_template for custom network");
    avalanchego_genesis_template.initial_stakers = Some(initial_stakers);
    avalanchego_genesis_template.sync(&avalanchego_genesis_path)?;

    Ok(())
}

async fn download_genesis_from_ready_anchor_nodes(
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    avalancheup_spec_path: &str,
) -> io::Result<()> {
    log::info!("STEP: downloading genesis file from S3 (updated from other anchor nodes)");

    let spec = avalancheup_aws::Spec::load(avalancheup_spec_path)?;
    let tmp_genesis_path = random_manager::tmp_path(15, Some(".json"))?;

    let s3_manager: &s3::Manager = s3_manager.as_ref();
    s3::spawn_get_object(
        s3_manager.clone(),
        s3_bucket,
        &avalancheup_aws::StorageNamespace::GenesisFile(spec.id.clone()).encode(),
        &tmp_genesis_path,
    )
    .await
    .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_get_object {}", e)))?;

    fs::copy(
        &tmp_genesis_path,
        spec.avalanchego_config.clone().genesis.unwrap(),
    )?;
    fs::remove_file(&tmp_genesis_path)?;

    Ok(())
}

/// Discover ready anchor nodes from S3 and returns the
/// combined list of bootstrap Ids and Ips.
/// mainnet/other pre-defined test nets have hard-coded anchor nodes
/// thus no need for anchor nodes.
async fn discover_ready_anchor_nodes_from_s3(
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    avalancheup_spec_path: &str,
) -> io::Result<(Vec<String>, Vec<String>)> {
    log::info!("STEP: listing S3 directory to discover ready anchor nodes...");

    let spec = avalancheup_aws::Spec::load(avalancheup_spec_path)?;

    // "avalanche-ops" should always set up anchor nodes first
    // so here we assume anchor nodes are already set up
    // and their information is already available via shared,
    // remote storage for service discovery
    // so that we block non-anchor nodes until anchor nodes are ready
    //
    // always send a new "list_objects" on remote storage
    // rather than relying on potentially stale (not via "spec")
    // in case the member lists for "anchor" nodes becomes stale
    // (e.g., machine replacement in "anchor" nodes ASG)
    //
    // TODO: handle stale anchor nodes by heartbeats timestamps
    let target_nodes = spec
        .machine
        .anchor_nodes
        .expect("unexpected None machine.anchor_nodes for custom network");

    let s3_key_prefix = s3::append_slash(
        &avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNodesDir(spec.id.clone()).encode(),
    );
    let s3_manager: &s3::Manager = s3_manager.as_ref();
    let mut objects: Vec<aws_sdk_s3::model::Object>;
    loop {
        sleep(Duration::from_secs(20)).await;

        objects =
            s3::spawn_list_objects(s3_manager.clone(), s3_bucket, Some(s3_key_prefix.clone()))
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Other, format!("failed spawn_list_objects {}", e))
                })?;

        log::info!(
            "{} anchor nodes are ready (expecting {} nodes)",
            objects.len(),
            target_nodes
        );

        if objects.len() as u32 >= target_nodes {
            break;
        }
    }

    let mut s3_keys: Vec<String> = Vec::new();
    for obj in objects.iter() {
        let s3_key = obj.key().expect("unexpected None s3 object");
        s3_keys.push(s3_key.to_string());
    }
    // s3 API should return the sorted list
    // in the descending order of "last_modified" timestamps
    // but to make sure, sort in lexicographical order
    s3_keys.sort();

    let mut bootstrap_ids: Vec<String> = vec![];
    let mut bootstrap_ips: Vec<String> = vec![];
    for s3_key in s3_keys.iter() {
        // just parse the s3 key name
        // to reduce "s3_manager.get_object" call volume
        let ready_anchor_node = avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key)?;

        bootstrap_ids.push(ready_anchor_node.node_id);

        // assume all nodes in the network use the same ports
        // ref. "avalanchego/config.StakingPortKey" default value is "9651"
        let staking_port = spec.avalanchego_config.staking_port;
        bootstrap_ips.push(format!("{}:{}", ready_anchor_node.public_ip, staking_port));
    }
    log::info!("found {} seed nodes that are ready", bootstrap_ids.len());

    Ok((bootstrap_ids, bootstrap_ips))
}

fn stop_and_start_avalanche_systemd_service(
    avalanche_bin_path: &str,
    avalanchego_config: &avalanchego::config::Config,
    coreth_config: &coreth::config::Config,
    subnet_evm_config: Option<subnet_evm::config::Config>,
) -> io::Result<()> {
    log::info!("STEP: setting up and starting Avalanche systemd service...");

    fs::create_dir_all(&avalanchego_config.log_dir)?;
    if let Some(v) = &avalanchego_config.subnet_config_dir {
        fs::create_dir_all(Path::new(v).join("C"))?;
    }
    if let Some(v) = &avalanchego_config.profile_dir {
        fs::create_dir_all(v)?;
    }

    if let Some(v) = &coreth_config.continuous_profiler_dir {
        fs::create_dir_all(v)?;
    }
    if let Some(v) = &coreth_config.offline_pruning_data_directory {
        fs::create_dir_all(v)?;
    }

    if let Some(cfg) = &subnet_evm_config {
        if let Some(v) = &cfg.continuous_profiler_dir {
            fs::create_dir_all(v)?;
        }
    }

    avalanchego_config.validate()?;
    if avalanchego_config.config_file.is_none() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "avalanchego_config.config_file is None",
        ));
    }

    // persist before starting the service
    avalanchego_config.sync(None)?;

    // don't use "Type=notify"
    // as "avalanchego" currently does not do anything specific to systemd
    // ref. "expected that the service sends a notification message via sd_notify"
    // ref. https://www.freedesktop.org/software/systemd/man/systemd.service.html
    //
    // NOTE: remove "StandardOutput" and "StandardError" since we already
    // wildcard all log files in "/var/log/avalanche" (a lot of duplicates)
    let service_file_contents = format!(
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

    let mut service_file = tempfile::NamedTempFile::new()?;
    service_file.write_all(service_file_contents.as_bytes())?;

    let service_file_path = service_file.path().to_str().unwrap();
    fs::copy(service_file_path, "/etc/systemd/system/avalanche.service")?;

    command_manager::run("sudo systemctl daemon-reload")?;

    // in case it's already running
    match command_manager::run("sudo systemctl stop avalanche.service") {
        Ok(_) => log::info!("successfully stopped avalanche.service"),
        Err(e) => log::warn!("failed to stop {}", e),
    };

    command_manager::run("sudo systemctl disable avalanche.service")?;
    command_manager::run("sudo systemctl enable avalanche.service")?;
    command_manager::run("sudo systemctl restart --no-block avalanche.service")?;

    Ok(())
}

fn stop_and_start_avalanche_telemetry_cloudwatch_systemd_service(
    avalanche_telemetry_cloudwatch_bin_path: &str,
    avalanche_telemetry_cloudwatch_rules_file_path: &str,
    namespace: &str,
    http_port: u32,
) -> io::Result<()> {
    log::info!("STEP: setting up and starting avalanche-telemetry-cloudwatch systemd service...");

    // don't use "Type=notify"
    // as "avalanchego" currently does not do anything specific to systemd
    // ref. "expected that the service sends a notification message via sd_notify"
    // ref. https://www.freedesktop.org/software/systemd/man/systemd.service.html
    //
    // NOTE: remove "StandardOutput" and "StandardError" since we already
    // wildcard all log files in "/var/log/avalanche" (a lot of duplicates)
    let service_file_contents = format!(
        "[Unit]
Description=avalanche-telemetry-cloudwatch

[Service]
Type=exec
TimeoutStartSec=300
Restart=always
RestartSec=5s
LimitNOFILE=40000
ExecStart={} --log-level=info --initial-wait-seconds=10 --fetch-interval-seconds=60 --rules-file-path={} --namespace={} --rpc-endpoint=http://localhost:{}
StandardOutput=append:/var/log/avalanche-telemetry-cloudwatch.log
StandardError=append:/var/log/avalanche-telemetry-cloudwatch.log

[Install]
WantedBy=multi-user.target",
        avalanche_telemetry_cloudwatch_bin_path,
        avalanche_telemetry_cloudwatch_rules_file_path,
        namespace,
        http_port,
    );

    let mut service_file = tempfile::NamedTempFile::new()?;
    service_file.write_all(service_file_contents.as_bytes())?;

    let service_file_path = service_file.path().to_str().unwrap();
    fs::copy(
        service_file_path,
        "/etc/systemd/system/avalanche-telemetry-cloudwatch.service",
    )?;

    command_manager::run("sudo systemctl daemon-reload")?;

    // in case it's already running
    match command_manager::run("sudo systemctl stop avalanche-telemetry-cloudwatch.service") {
        Ok(_) => log::info!("sucessfully stopped avalanche-telemetry-cloudwatch.service"),
        Err(e) => log::warn!("failed to stop {}", e),
    };

    command_manager::run("sudo systemctl disable avalanche-telemetry-cloudwatch.service")?;
    command_manager::run("sudo systemctl enable avalanche-telemetry-cloudwatch.service")?;
    command_manager::run(
        "sudo systemctl restart --no-block avalanche-telemetry-cloudwatch.service",
    )?;

    Ok(())
}

async fn check_liveness(ep: &str) -> io::Result<()> {
    log::info!("STEP: checking liveness...");

    loop {
        // if cloudwatch log config sets "auto_removal" to true
        // this file might have been garbage collected!
        match command_manager::run("sudo tail -10 /var/log/avalanche/avalanche.log") {
            Ok(out) => {
                println!(
                    "\n'/var/log/avalanche/avalanche.log' stdout:\n\n{}\n",
                    out.0
                );
                println!("'/var/log/avalanche/avalanche.log' stderr:\n\n{}\n", out.1);
            }
            Err(e) => log::warn!("failed to check /var/log/avalanche/avalanche.log: {}", e),
        }

        println!();

        match command_manager::run("sudo journalctl -u avalanche.service --lines=10 --no-pager") {
            Ok(out) => {
                println!("\n'avalanche.service' stdout:\n\n{}\n", out.0);
                println!("'avalanche.service' stderr:\n\n{}\n", out.1);
            }
            Err(e) => log::warn!("failed to check journalctl avalanche.service: {}", e),
        }

        println!();

        let ret = api_health::spawn_check(ep, true).await;
        match ret {
            Ok(res) => {
                if res.healthy.is_some() && res.healthy.unwrap() {
                    log::info!("health/liveness check success");
                    break;
                }
            }
            Err(e) => {
                log::warn!("health/liveness check failed ({:?}) -- retrying...", e);
            }
        };

        sleep(Duration::from_secs(30)).await;
    }

    Ok(())
}

/// if run in anchor nodes, the uploaded file will be downloaded
/// in bootstrapping non-anchor nodes for custom networks
async fn publish_node_info_ready_loop(
    ec2_instance_id: Arc<String>,
    node_kind: node::Kind,
    node_id: Arc<String>,
    public_ipv4: Arc<String>,
    s3_manager: Arc<s3::Manager>,
    s3_bucket: Arc<String>,
    avalancheup_spec_path: Arc<String>,
    publish_periodic_node_info: bool,
) {
    log::info!("STEP: publishing node info for its readiness...");

    let spec =
        avalancheup_aws::Spec::load(avalancheup_spec_path.as_str()).expect("failed to load spec");

    let http_scheme = {
        if spec.avalanchego_config.http_tls_enabled.is_some()
            && spec
                .avalanchego_config
                .http_tls_enabled
                .expect("unexpected None avalanchego_config.http_tls_enabled")
        {
            "https"
        } else {
            "http"
        }
    };
    let local_node = avalancheup_aws::Node::new(
        node_kind.clone(),
        ec2_instance_id.as_str(),
        node_id.as_str(),
        public_ipv4.as_str(),
        http_scheme,
        spec.avalanchego_config.http_port,
    );
    let node_info = avalancheup_aws::NodeInfo::new(
        local_node.clone(),
        spec.avalanchego_config.clone(),
        spec.coreth_config.clone(),
    );

    let node_info_path = random_manager::tmp_path(10, Some(".yaml")).unwrap();
    node_info.sync(node_info_path.clone()).unwrap();

    let node_info_ready_s3_key = {
        if matches!(node_kind, node::Kind::Anchor) {
            avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNode(
                spec.id.clone(),
                local_node.clone(),
            )
            .encode()
        } else {
            avalancheup_aws::StorageNamespace::DiscoverReadyNonAnchorNode(
                spec.id.clone(),
                local_node.clone(),
            )
            .encode()
        }
    };

    let s3_manager: &s3::Manager = s3_manager.as_ref();
    loop {
        match s3::spawn_put_object(
            s3_manager.clone(),
            &node_info_path,
            &s3_bucket,
            &node_info_ready_s3_key,
        )
        .await
        {
            Ok(_) => log::info!(
                "successfully published node info for node kind {}",
                node_info.local_node.kind
            ),
            Err(e) => {
                log::warn!("failed spawn_put_object {}", e);
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        }

        if !publish_periodic_node_info {
            break;
        }

        log::info!("sleeping 10-min for next publish loop");
        sleep(Duration::from_secs(600)).await;
    }

    log::info!("successfully completed node info publish");
}

async fn monitor_spot_instance_action(
    ec2_manager: Arc<ec2::Manager>,
    asg_manager: Arc<autoscaling::Manager>,
    ec2_instance_id: Arc<String>,
    attached_volume_id: Arc<String>,
) {
    let ec2_manager: &ec2::Manager = ec2_manager.as_ref();
    let ec2_cli = ec2_manager.client();

    let asg_manager: &autoscaling::Manager = asg_manager.as_ref();

    loop {
        log::info!(
            "checking spot instance action for {} with attached volume Id {}",
            ec2_instance_id,
            attached_volume_id
        );

        // if the action is "stop" or "terminate", just stop and recylce EC2 instance faster!
        // ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-instance-termination-notices.html#instance-action-metadata
        match ec2::metadata::fetch_spot_instance_action().await {
            Ok(instance_action) => {
                log::info!("received instance action {:?}", instance_action);
                let need_terminate = match instance_action.action.as_str() {
                    "stop" => {
                        log::warn!(
                            "instance '{}' will be stopped at {} -- just terminate now!",
                            ec2_instance_id,
                            instance_action.time
                        );
                        true
                    }
                    "terminate" => {
                        log::warn!(
                            "instance '{}' will be terminated at {} -- just terminate now!",
                            ec2_instance_id,
                            instance_action.time
                        );
                        true
                    }
                    _ => {
                        log::warn!("unknown instance action {}", instance_action.action);
                        false
                    }
                };
                if need_terminate {
                    // manually set instance health to speed up ASG Unhealthy replacement
                    // e.g., "taken out of service in response to a user health-check"
                    log::warn!(
                        "setting the instance {} to 'Unhealthy'",
                        ec2_instance_id.as_str()
                    );
                    match asg_manager
                        .set_instance_health(ec2_instance_id.as_str(), "Unhealthy")
                        .await
                    {
                        Ok(_) => {
                            log::info!("successfully set instance health");
                        }
                        Err(e) => log::warn!("failed to set instance health {}", e),
                    }

                    // ASG may take minutes to detect "Unhealthy" to launch a new instance
                    // sleep some time to minimize the downtime
                    // if we just stop and terminate without sleep,
                    // asg may take up to 2 minutes to replace the instance
                    // ref. https://aws.amazon.com/ec2/autoscaling/faqs/
                    //
                    // NOTE: actually ASG can terminate as fast as in 5 seconds
                    // just wait 8 seconds in case it takes longer than 10 seconds
                    sleep(Duration::from_secs(8)).await;

                    log::warn!("stopping avalanche service before instance termination...");
                    match command_manager::run("sudo systemctl stop avalanche.service") {
                        Ok(_) => log::info!("successfully stopped avalanche service"),
                        Err(e) => log::warn!("failed systemctl stop command {}", e),
                    }
                    match command_manager::run("sudo systemctl disable avalanche.service") {
                        Ok(_) => log::info!("successfully disabled avalanche service"),
                        Err(e) => log::warn!("failed systemctl disable command {}", e),
                    }
                    match command_manager::run("sudo sync") {
                        Ok(_) => log::info!("successfully ran 'sudo sync'"),
                        Err(e) => log::warn!("failed sync command {}", e),
                    }

                    // enough time for avalanche process to gracefully shut down
                    sleep(Duration::from_secs(1)).await;

                    // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachVolume.html
                    log::warn!("detaching EBS volume before instance termination...");
                    match ec2_cli
                        .detach_volume()
                        .instance_id(ec2_instance_id.as_str())
                        .volume_id(attached_volume_id.as_str())
                        .force(false) // "true" can lead to data loss or a corrupted file system
                        .send()
                        .await
                    {
                        Ok(v) => {
                            log::info!("successfully detached volume {:?}", v);
                            sleep(Duration::from_secs(10)).await;
                        }
                        Err(e) => log::warn!("failed to detach volume {}", e),
                    }

                    log::warn!("terminating the instance...");
                    match ec2_cli
                        .terminate_instances()
                        .instance_ids(ec2_instance_id.as_str())
                        .send()
                        .await
                    {
                        Ok(v) => {
                            log::info!("successfully terminated instance {:?}", v);
                            return;
                        }
                        Err(e) => log::warn!("failed to terminate instance {}", e),
                    }
                }
            }

            Err(e) => {
                log::debug!("failed fetch_spot_instance_action {} -- likely no spot instance-action event yet", e);
            }
        }

        // warning will be issued two minutes before EC2 stops or terminates Spot instance
        // so monitor more aggressively
        sleep(Duration::from_secs(20)).await;
    }
}

/// returns "hello" from "a/b/c/hello.zstd"
fn extract_filename(p: &str) -> String {
    let path = Path::new(p);
    let file_stemp = path.file_stem().unwrap();
    String::from(file_stemp.to_str().unwrap())
}
