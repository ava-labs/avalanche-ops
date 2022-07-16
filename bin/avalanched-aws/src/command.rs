use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::SystemTime,
};

use crate::flags;
use avalanche_sdk::health as api_health;
use avalanche_types::{constants, genesis as avalanchego_genesis, node};
use aws_manager::{
    self, cloudwatch, ec2,
    kms::{self, envelope},
    s3,
};
use aws_sdk_ec2::model::{Filter, Tag};
use aws_sdk_s3::model::Object;
use infra_aws::{certs, telemetry};
use tokio::time::{sleep, Duration};

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting avalanched-aws");

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
    let s3_manager_arc = Arc::new(aws_creds.s3_manager.clone());

    log::info!("STEP 3: fetching tags...");
    let tags = fetch_tags(
        Arc::new(aws_creds.ec2_manager.clone()),
        Arc::new(meta.ec2_instance_id.clone()),
    )
    .await?;

    log::info!("STEP 4: installing Avalanche...");
    install_avalanche(
        Arc::clone(&s3_manager_arc),
        &tags.s3_bucket,
        &tags.id,
        &tags.avalanche_bin_path,
    )
    .await?;

    log::info!("STEP 5: downloading avalanche-ops::Spec from S3");
    let mut spec = load_spec(
        Arc::clone(&s3_manager_arc),
        &tags.s3_bucket,
        &tags.id,
        &meta.public_ipv4,
    )
    .await?;

    log::info!("STEP 6: creating CloudWatch JSON config file...");
    create_cloudwatch_config(
        &tags.id,
        tags.node_kind.clone(),
        &spec.avalanchego_config.log_dir,
        true,
        true,
        &tags.avalanche_data_volume_path,
        &tags.cloudwatch_config_file_path,
    )?;

    log::info!("STEP 7: setting up certificates...");
    let envelope_manager = envelope::Manager::new(
        aws_creds.kms_manager.clone(),
        tags.kms_cmk_arn.to_string(),
        tags.aad_tag.to_string(),
    );
    let certs_manager = certs::Manager {
        envelope_manager,
        s3_manager: aws_creds.clone().s3_manager.clone(),
        s3_bucket: tags.s3_bucket.to_string(),
    };
    let tls_key_path = spec
        .avalanchego_config
        .staking_tls_key_file
        .clone()
        .unwrap();
    let tls_cert_path = spec
        .avalanchego_config
        .staking_tls_cert_file
        .clone()
        .unwrap();
    let (node_id, newly_generated) = certs_manager
        .load_or_generate(&tls_key_path, &tls_cert_path)
        .await?;
    log::info!(
        "loaded node ID {} (was generated {})",
        node_id,
        newly_generated
    );

    if newly_generated {
        log::info!("STEP 7: backing up newly generated certificates...");

        let s3_key_tls_key = format!(
            "{}/{}.key.zstd.encrypted",
            avalancheup_aws::StorageNamespace::PkiKeyDir(tags.id.clone()).encode(),
            node_id
        );
        let s3_key_tls_cert = format!(
            "{}/{}.crt.zstd.encrypted",
            avalancheup_aws::StorageNamespace::PkiKeyDir(tags.id.clone()).encode(),
            node_id
        );

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
        log::info!("STEP 7: creating tags for EBS volume with node Id...");

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
        tags.clone().node_kind.clone(),
        &meta.ec2_instance_id,
        &node_id.to_string(),
        &meta.public_ipv4,
        http_scheme,
        spec.avalanchego_config.http_port,
    );
    log::info!(
        "loaded node:\n{}",
        local_node
            .encode_yaml()
            .expect("failed to encode node Info")
    );

    // "63.65 GB" .tar.gz download  takes about 45-min
    // "63.65 GB" .tar.gz unpack    takes about 7-min
    // "75.47 GB" .tar    unarchive takes about 5-min
    if spec.aws_resources.is_some() {
        let aws_resources = spec.clone().aws_resources.unwrap();
        if aws_resources.db_backup_s3_region.is_some()
            && aws_resources.db_backup_s3_bucket.is_some()
            && aws_resources.db_backup_s3_key.is_some()
        {
            log::info!("STEP: publishing node information before db backup downloads");
            let s3_key = {
                if matches!(tags.node_kind, node::Kind::Anchor) {
                    avalancheup_aws::StorageNamespace::DiscoverProvisioningAnchorNode(
                        tags.id.clone(),
                        local_node.clone(),
                    )
                } else {
                    avalancheup_aws::StorageNamespace::DiscoverProvisioningNonAnchorNode(
                        tags.id.clone(),
                        local_node.clone(),
                    )
                }
            }
            .encode();
            let node_info = avalancheup_aws::NodeInfo::new(
                local_node.clone(),
                spec.avalanchego_config.clone(),
                spec.coreth_config.clone(),
            );
            let tmp_path =
                random_manager::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
            node_info.sync(tmp_path.clone()).unwrap();
            s3::spawn_put_object(
                aws_creds.s3_manager.clone(),
                &tmp_path,
                &tags.s3_bucket,
                &s3_key,
            )
            .await
            .expect("failed s3::spawn_put_object");
            fs::remove_file(tmp_path).expect("failed fs::remove_file");

            sleep(Duration::from_secs(1)).await;
            let db_backup_s3_region = aws_resources.db_backup_s3_region.clone().unwrap();
            let db_backup_s3_bucket = aws_resources.db_backup_s3_bucket.clone().unwrap();
            let db_backup_s3_key = aws_resources.db_backup_s3_key.unwrap();
            let dec = compress_manager::DirDecoder::new_from_file_name(&db_backup_s3_key).unwrap();
            log::info!(
                "STEP: downloading database backup file 's3://{}/{}' [{}] in region {}",
                db_backup_s3_bucket,
                db_backup_s3_key,
                dec.id(),
                db_backup_s3_region,
            );

            let db_backup_s3_config =
                tokio::spawn(aws_manager::load_config(Some(db_backup_s3_region)))
                    .await
                    .expect("failed spawn await")
                    .expect("failed aws_manager::load_config");
            let db_backup_s3_manager = s3::Manager::new(&db_backup_s3_config);

            // do not store in "tmp", will run out of space
            let download_path = format!(
                "{}/{}{}",
                spec.avalanchego_config.db_dir,
                random_manager::string(10),
                dec.ext()
            );

            s3::spawn_get_object(
                db_backup_s3_manager.clone(),
                &db_backup_s3_bucket,
                &db_backup_s3_key,
                &download_path,
            )
            .await
            .expect("failed s3::spawn_get_object");

            compress_manager::unpack_directory(
                &download_path,
                &spec.avalanchego_config.db_dir,
                dec,
            )
            .unwrap();

            log::info!("removing downloaded file {} after unpack", download_path);
            fs::remove_file(download_path).expect("failed fs::remove_file");

            // TODO: override network id to support network fork
        } else {
            log::info!(
                "STEP: db_backup_s3_bucket is empty, skipping database backup download from S3"
            )
        }
    }

    if spec.avalanchego_config.is_custom_network()
        && matches!(tags.node_kind, node::Kind::Anchor)
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        log::info!("STEP: publishing seed/bootstrapping anchor node information for discovery");
        let node_info = avalancheup_aws::NodeInfo::new(
            local_node.clone(),
            spec.avalanchego_config.clone(),
            spec.coreth_config.clone(),
        );
        let tmp_path =
            random_manager::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
        node_info.sync(tmp_path.clone()).unwrap();

        s3::spawn_put_object(
            aws_creds.s3_manager.clone(),
            &tmp_path,
            &tags.s3_bucket,
            &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNode(
                tags.id.clone(),
                local_node.clone(),
            )
            .encode(),
        )
        .await
        .expect("failed s3::spawn_put_object");

        fs::remove_file(tmp_path).expect("failed fs::remove_file");

        sleep(Duration::from_secs(30)).await;
        log::info!("STEP: waiting for all seed/bootstrapping anchor nodes to be ready");
        let target_nodes = spec.machine.anchor_nodes.unwrap();
        let s3_key = s3::append_slash(
            &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNodesDir(
                tags.id.clone(),
            )
            .encode(),
        );
        let mut objects: Vec<Object>;
        loop {
            sleep(Duration::from_secs(20)).await;
            objects = s3::spawn_list_objects(
                aws_creds.s3_manager.clone(),
                &tags.s3_bucket,
                Some(s3_key.clone()),
            )
            .await
            .expect("failed s3::spawn_list_objects");
            log::info!(
                "{} seed/bootstrapping anchor nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        log::info!("STEP: update genesis file with seed/bootstrapping anchor nodes");
        let mut initial_stakers: Vec<avalanchego_genesis::Staker> = vec![];

        // "initial_staked_funds" is reserved for locked P-chain balance
        // with "spec.generated_seed_private_key_with_locked_p_chain_balance"
        let seed_priv_keys = spec.clone().generated_seed_private_keys.unwrap();
        let seed_priv_key = seed_priv_keys[0].clone();
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object");

            // just parse the s3 key name
            // to reduce "s3_manager.get_object" call volume
            let seed_anchor_node =
                avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key).unwrap();

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
            .clone()
            .expect("unexpected None avalanchego_genesis_template for custom network");
        avalanchego_genesis_template.initial_stakers = Some(initial_stakers);
        avalanchego_genesis_template
            .sync(&avalanchego_genesis_path)
            .expect("failed to sync avalanchego_genesis_path");

        // for now, just overwrite from every seed anchor node
        sleep(Duration::from_secs(1)).await;

        log::info!("STEP: upload the new genesis file, to be shared with non-anchor nodes");
        s3::spawn_put_object(
            aws_creds.s3_manager.clone(),
            &avalanchego_genesis_path,
            &tags.s3_bucket,
            &avalancheup_aws::StorageNamespace::GenesisFile(spec.id.clone()).encode(),
        )
        .await
        .expect("failed s3::spawn_put_object");
    }

    if spec.avalanchego_config.is_custom_network()
        && matches!(tags.node_kind, node::Kind::NonAnchor)
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        log::info!("STEP: downloading genesis file from S3 (updated from other anchor nodes)");
        let tmp_genesis_path = random_manager::tmp_path(15, Some(".json")).unwrap();
        s3::spawn_get_object(
            aws_creds.s3_manager.clone(),
            &tags.s3_bucket,
            &avalancheup_aws::StorageNamespace::GenesisFile(spec.id.clone()).encode(),
            &tmp_genesis_path,
        )
        .await
        .expect("failed s3::spawn_get_object");
        fs::copy(
            &tmp_genesis_path,
            spec.avalanchego_config.clone().genesis.unwrap(),
        )
        .expect("failed fs::copy genesis file");
    }

    // validate after downloading genesis file
    spec.avalanchego_config.validate().unwrap();
    if spec.avalanchego_config.config_file.is_none() {
        panic!("'spec.avalanchego_config.config_file' not found")
    }

    // mainnet/other pre-defined test nets have hard-coded anchor nodes
    // thus no need for anchor nodes
    if spec.avalanchego_config.is_custom_network()
        && matches!(tags.node_kind, node::Kind::NonAnchor)
    {
        sleep(Duration::from_secs(1)).await;
        log::info!(
            "STEP: downloading anchor node information for network '{}'",
            spec.avalanchego_config.network_id,
        );

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
        let s3_key = s3::append_slash(
            &avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNodesDir(tags.id.clone())
                .encode(),
        );
        let mut objects: Vec<Object>;
        loop {
            sleep(Duration::from_secs(20)).await;

            objects = s3::spawn_list_objects(
                aws_creds.s3_manager.clone(),
                &tags.s3_bucket,
                Some(s3_key.clone()),
            )
            .await
            .expect("failed s3::spawn_list_objects");
            log::info!(
                "{} anchor nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        log::info!("STEP: updating bootstrap IPs/IDs with all anchor nodes");
        let mut bootstrap_ips: Vec<String> = vec![];
        let mut bootstrap_ids: Vec<String> = vec![];
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object");

            // just parse the s3 key name
            // to reduce "s3_manager.get_object" call volume
            let anchor_node = avalancheup_aws::StorageNamespace::parse_node_from_path(s3_key)
                .expect("failed to parse node from storage path");

            // assume all nodes in the network use the same ports
            // ref. "avalanchego/config.StakingPortKey" default value is "9651"
            let staking_port = spec.avalanchego_config.staking_port;
            bootstrap_ips.push(format!("{}:{}", anchor_node.public_ip, staking_port));
            bootstrap_ids.push(anchor_node.node_id);
        }
        log::info!("found {} bootstrap nodes", bootstrap_ids.len());

        spec.avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));
        spec.avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
    }

    log::info!("STEP: writing Avalanche config file...");
    write_avalanche_config(tags.network_id, &spec)?;

    log::info!("STEP: writing coreth config file...");
    write_coreth_config(&spec)?;

    if spec.avalanchego_config.subnet_config_dir.is_some() {
        let subnet_config_dir = spec
            .avalanchego_config
            .clone()
            .subnet_config_dir
            .expect("unexpected None subnet_config_dir");
        fs::create_dir_all(Path::new(&subnet_config_dir).join("C"))?;
    };

    // TODO: upload profile files to s3?
    if spec.avalanchego_config.profile_dir.is_some() {
        let profile_dir = spec
            .avalanchego_config
            .clone()
            .profile_dir
            .expect("unexpected None profile_dir");
        fs::create_dir_all(&profile_dir).expect("failed to create profile_dir");
    };

    // TODO: upload profile files to s3?
    if spec.coreth_config.continuous_profiler_dir.is_some() {
        let continuous_profiler_dir = spec
            .coreth_config
            .clone()
            .continuous_profiler_dir
            .expect("unexpected None continuous_profiler_dir");
        fs::create_dir_all(&continuous_profiler_dir)
            .expect("failed to create continuous_profiler_dir");
    };

    log::info!("STEP: setting up and starting Avalanche systemd service...");
    start_avalanche_systemd_service(&tags.avalanche_bin_path, spec.avalanchego_config.clone())?;

    log::info!("STEP: checking liveness...");
    let ep = format!(
        "{}://{}:{}",
        http_scheme, meta.public_ipv4, spec.avalanchego_config.http_port
    );
    check_liveness(&ep).await?;

    log::info!("spawning async routines...");
    let node_info_ready_s3_key = {
        if matches!(tags.node_kind, node::Kind::Anchor) {
            avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNode(
                tags.id.clone(),
                local_node.clone(),
            )
            .encode()
        } else {
            avalancheup_aws::StorageNamespace::DiscoverReadyNonAnchorNode(
                tags.id.clone(),
                local_node.clone(),
            )
            .encode()
        }
    };

    let mut handles = vec![
        tokio::spawn(publish_node_info_ready_loop(
            aws_creds.s3_manager.clone(),
            Arc::new(tags.s3_bucket.clone()),
            Arc::new(node_info_ready_s3_key),
            Arc::new(avalancheup_aws::NodeInfo::new(
                local_node.clone(),
                spec.avalanchego_config.clone(),
                spec.coreth_config.clone(),
            )),
        )),
        tokio::spawn(telemetry::metrics::avalanchego::fetch_loop(
            aws_creds.cw_manager.clone(),
            Arc::new(
                spec.clone()
                    .aws_resources
                    .clone()
                    .unwrap()
                    .cloudwatch_avalanche_metrics_namespace
                    .unwrap(),
            ),
            Duration::from_secs(120),
            Duration::from_secs(60),
            Arc::new(local_node.http_endpoint.clone()),
        )),
        tokio::spawn(check_node_update_loop(
            aws_creds.s3_manager.clone(),
            Arc::new(tags.s3_bucket.clone()),
            Arc::new(tags.id.clone()),
            Arc::new(tags.avalanche_bin_path),
        )),
    ];
    if spec
        .clone()
        .aws_resources
        .clone()
        .unwrap()
        .db_backup_s3_bucket
        .is_some()
    {
        handles.push(tokio::spawn(print_backup_commands(
            Arc::new(
                spec.clone()
                    .aws_resources
                    .clone()
                    .unwrap()
                    .db_backup_s3_region
                    .clone()
                    .unwrap(),
            ),
            Arc::new(
                spec.clone()
                    .aws_resources
                    .clone()
                    .unwrap()
                    .db_backup_s3_bucket
                    .clone()
                    .unwrap(),
            ),
            Arc::new(tags.id.clone()),
            Arc::new(spec.avalanchego_config.network_id),
            Arc::new(spec.avalanchego_config.db_dir),
        )));
    }

    log::info!("STEP: blocking on handles via JoinHandle");
    for handle in handles {
        handle.await.expect("failed handle");
    }

    Ok(())
}

/// if run in anchor nodes, the uploaded file will be downloaded
/// in bootstrapping non-anchor nodes for custom networks
async fn publish_node_info_ready_loop(
    s3_manager: s3::Manager,
    s3_bucket: Arc<String>,
    s3_key: Arc<String>,
    node_info: Arc<avalancheup_aws::NodeInfo>,
) {
    log::info!("STEP: starting 'publish_node_info_ready_loop'");

    loop {
        log::info!(
            "STEP: posting node info ready for {}",
            node_info.local_node.kind
        );

        let tmp_path =
            random_manager::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
        node_info.sync(tmp_path.clone()).unwrap();

        s3::spawn_put_object(s3_manager.clone(), &tmp_path, &s3_bucket, &s3_key.clone())
            .await
            .expect("failed s3::spawn_put_object");

        fs::remove_file(&tmp_path).expect("failed fs::remove_file");

        log::info!("sleeping 10-min for next 'publish_node_info_ready_loop'");
        sleep(Duration::from_secs(600)).await;
    }
}

async fn check_node_update_loop(
    s3_manager: s3::Manager,
    s3_bucket: Arc<String>,
    id: Arc<String>,
    avalanche_bin_path: Arc<String>,
) {
    log::info!("STEP: starting 'check_node_update_loop'");

    loop {
        log::info!("sleeping 3-min for 'check_node_update_loop'");
        sleep(Duration::from_secs(180)).await;

        log::info!("STEP: checking update artifacts event key");
        let objects = match s3::spawn_list_objects(
            s3_manager.clone(),
            s3_bucket.as_str(),
            Some(
                avalancheup_aws::StorageNamespace::EventsUpdateArtifactsEvent(id.to_string())
                    .encode(),
            ),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed s3::spawn_list_objects {}, retrying...", e);
                continue;
            }
        };

        if objects.is_empty() {
            log::warn!("no event key found");
            continue;
        }

        let obj = objects[0].clone();
        let last_modified = obj.last_modified.unwrap();
        let last_modified_unix = last_modified.as_secs_f64();

        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs() as f64;

        // requested for the last 6-min
        // TODO: can this be smarter...?
        let needs_update = (now_unix - last_modified_unix) < 360_f64;
        log::info!(
            "last_modified_unix {}, now_unix {} [needs update: {}]",
            last_modified_unix,
            now_unix,
            needs_update
        );

        if !needs_update {
            log::warn!(
                "update artifacts event not found (seeing {} objects)",
                objects.len()
            );
            continue;
        }

        log::info!("STEP: downloading avalanched binary from S3");

        // TODO: replace "avalanched" itself?
        // TODO: fs::copy fails with 'Os { code: 26, kind: ExecutableFileBusy, message: "Text file busy" }'
        // can't replace the process itself...

        log::info!("STEP: downloading avalanche binary from S3");
        let tmp_avalanche_bin_compressed_path =
            random_manager::tmp_path(15, Some(".zstd")).unwrap();
        s3::spawn_get_object(
                    s3_manager.clone(),
                    s3_bucket.clone().as_ref().to_string(),
                    avalancheup_aws::StorageNamespace::EventsUpdateArtifactsInstallDirAvalancheBinCompressed(id.to_string()).encode(),
                      tmp_avalanche_bin_compressed_path.clone(),
                )
                .await
                .expect("failed s3::spawn_get_object");

        log::warn!("stopping avalanche.service before unpack...");
        command_manager::run("sudo systemctl stop avalanche.service")
            .expect("failed systemctl stop command");
        log::warn!("stopped avalanche.service before unpack...");
        sleep(Duration::from_secs(10)).await;

        compress_manager::unpack_file(
            &tmp_avalanche_bin_compressed_path,
            avalanche_bin_path.as_str(),
            compress_manager::Decoder::Zstd,
        )
        .expect("failed unpack_file avalanche_bin_compressed_path");

        let f = File::open(avalanche_bin_path.as_str()).expect("failed to open avalanche_bin");
        f.set_permissions(PermissionsExt::from_mode(0o777))
            .expect("failed to set file permission for avalanche_bin");
        fs::remove_file(&tmp_avalanche_bin_compressed_path).expect("failed fs::remove_file");

        let plugins_dir =
            avalanche_installer::avalanchego::get_plugins_dir(avalanche_bin_path.as_str());
        if !Path::new(&plugins_dir).exists() {
            log::info!("STEP: creating '{}' for plugins", plugins_dir);
            fs::create_dir_all(plugins_dir.clone()).unwrap();
        }

        log::info!("STEP: downloading plugins from S3 (if any) to overwrite");
        let objects = s3::spawn_list_objects(
            s3_manager.clone(),
            s3_bucket.clone().as_ref().to_string(),
            Some(s3::append_slash(
                &avalancheup_aws::StorageNamespace::EventsUpdateArtifactsInstallDirPluginsDir(
                    id.to_string(),
                )
                .encode(),
            )),
        )
        .await
        .expect("failed s3::spawn_list_objects");

        log::info!("listed {} plugins from S3", objects.len());
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object").to_string();
            let tmp_path = random_manager::tmp_path(15, None).unwrap();
            s3::spawn_get_object(
                s3_manager.clone(),
                s3_bucket.clone().as_ref().to_string(),
                s3_key.clone(),
                tmp_path.clone(),
            )
            .await
            .expect("failed s3::spawn_get_object");

            let file_name = extract_filename(&s3_key);
            let file_path = format!("{}/{}", plugins_dir, file_name);
            compress_manager::unpack_file(&tmp_path, &file_path, compress_manager::Decoder::Zstd)
                .unwrap();

            let f = File::open(file_path).expect("failed to open plugin file");
            f.set_permissions(PermissionsExt::from_mode(0o777))
                .expect("failed to set file permission");
            fs::remove_file(&tmp_path).expect("failed fs::remove_file");
        }

        // updated the avalanched itself, so sleep for cloudwatch logs and restart
        log::warn!(
            "artifacts have been updated... will trigger avalanched restart by panic here..."
        );
        sleep(Duration::from_secs(240)).await; // sleep to prevent duplicate updates
        panic!("panic avalanched to trigger restarts via systemd service!!!")
    }
}

async fn print_backup_commands(
    s3_region: Arc<String>,
    s3_bucket: Arc<String>,
    id: Arc<String>,
    network_id: Arc<u32>,
    db_dir: Arc<String>,
) {
    log::info!("STEP: starting 'print_backup_commands'");

    loop {
        // e.g., "--pack-dir /data/network-1000000/v1.4.5"
        let db_dir_network = match constants::NETWORK_ID_TO_NETWORK_NAME.get(network_id.as_ref()) {
            Some(v) => String::from(*v),
            None => format!("network-{}", network_id),
        };

        println!("[TO BACK UP DATA] /usr/local/bin/avalanched backup upload --region {} --archive-compression-method {} --pack-dir {}/{} --s3-bucket {} --s3-key {}/backup{}", 
            s3_region,
            compress_manager::DirEncoder::TarGzip.id(),
            db_dir,
            db_dir_network,
            s3_bucket,
            avalancheup_aws::StorageNamespace::BackupsDir(id.to_string()).encode(),
            compress_manager::DirEncoder::TarGzip.ext(),
        );

        println!("[TO DOWNLOAD DATA] /usr/local/bin/avalanched backup download --region {} --unarchive-decompression-method {} --s3-bucket {} --s3-key {}/backup{} --unpack-dir {}",
            s3_region,
            compress_manager::DirDecoder::TarGzip.id(),
            s3_bucket,
            avalancheup_aws::StorageNamespace::BackupsDir(id.to_string()).encode(),
            compress_manager::DirDecoder::TarGzip.ext(),
            db_dir,
        );

        log::info!("sleeping 5-hour 'print_backup_commands'");
        sleep(Duration::from_secs(5 * 3600)).await;
    }
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
        let tmp_avalanche_bin_compressed_path =
            random_manager::tmp_path(15, Some(".zstd")).unwrap();

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
            &avalanche_bin_path,
            compress_manager::Decoder::Zstd,
        )?;

        let f = File::open(&avalanche_bin_path).expect("failed to open avalanche_bin");
        f.set_permissions(PermissionsExt::from_mode(0o777))?;
        fs::remove_file(&tmp_avalanche_bin_compressed_path)?;
    }

    let plugins_dir = avalanche_installer::avalanchego::get_plugins_dir(&avalanche_bin_path);
    if !Path::new(&plugins_dir).exists() {
        log::info!("STEP: creating '{}' for plugins", plugins_dir);
        fs::create_dir_all(plugins_dir.clone()).unwrap();

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
            let tmp_path = random_manager::tmp_path(15, None).unwrap();

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

async fn load_spec(
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    id: &str,
    public_ipv4: &str,
) -> io::Result<avalancheup_aws::Spec> {
    let tmp_spec_file_path = random_manager::tmp_path(15, Some(".yaml")).unwrap();

    let s3_manager: &s3::Manager = s3_manager.as_ref();
    s3::spawn_get_object(
        s3_manager.to_owned(),
        s3_bucket,
        &avalancheup_aws::StorageNamespace::ConfigFile(id.to_string()).encode(),
        &tmp_spec_file_path,
    )
    .await
    .map_err(|e| Error::new(ErrorKind::Other, format!("failed spawn_get_object {}", e)))?;

    let mut spec = avalancheup_aws::Spec::load(&tmp_spec_file_path).unwrap();
    spec.avalanchego_config.public_ip = Some(public_ipv4.to_string());
    spec.avalanchego_config.sync(None)?;

    // "avalanched" never updates "spec" file, runs in read-only mode
    fs::remove_file(&tmp_spec_file_path)?;

    Ok(spec)
}

/// TODO: support other networks
fn write_avalanche_config(network_id: u32, spec: &avalancheup_aws::Spec) -> io::Result<()> {
    if spec.avalanchego_config.network_id != network_id {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "unexpected network Id, [tag {}, avalanchego config {}]",
                network_id, spec.avalanchego_config.network_id
            ),
        ));
    }

    let log_dir = spec.avalanchego_config.clone().log_dir;
    fs::create_dir_all(&log_dir)?;

    spec.avalanchego_config.sync(None)
}

fn write_coreth_config(spec: &avalancheup_aws::Spec) -> io::Result<()> {
    let chain_config_dir = spec.avalanchego_config.chain_config_dir.clone();
    fs::create_dir_all(Path::new(&chain_config_dir).join("C"))?;

    let tmp_coreth_config_path = random_manager::tmp_path(15, Some(".json")).unwrap();
    let chain_config_c_path = Path::new(&chain_config_dir).join("C").join("config.json");

    spec.coreth_config.sync(&tmp_coreth_config_path)?;
    fs::copy(&tmp_coreth_config_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_coreth_config_path)?;

    log::info!(
        "saved coreth config file to {:?}",
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

/// returns "hello" from "a/b/c/hello.zstd"
fn extract_filename(p: &str) -> String {
    let path = Path::new(p);
    let file_stemp = path.file_stem().unwrap();
    String::from(file_stemp.to_str().unwrap())
}
