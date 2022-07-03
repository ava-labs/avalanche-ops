use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use avalanche_sdk::{
    health as api_health,
    metrics::{self as api_metrics, cw as api_cw},
};
use avalanche_types::{
    constants, genesis as avalanchego_genesis, ids, key::cert,
    metrics::avalanchego as avalanchego_metrics, node,
};
use avalanche_utils::{bash, random};
use aws_sdk_manager::{
    self, cloudwatch, ec2,
    kms::{
        self,
        envelope::{self, Envelope},
    },
    s3,
};
use aws_sdk_s3::model::Object;
use clap::{Arg, Command};
use log::{info, warn};
use tokio::time::sleep;

pub const NAME: &str = "run";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not change node ID)
/// TODO: support download mainnet database from s3
pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Runs an Avalanche agent (daemon) on AWS")
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
}

pub async fn execute(log_level: &str) {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    info!("STEP: fetching intance metadata using IMDSv2");

    let az = tokio::spawn(ec2::fetch_availability_zone())
        .await
        .expect("failed spawn await")
        .expect("failed ec2::fetch_availability_zone");
    info!("fetched availability zone {}", az);

    let reg = tokio::spawn(ec2::fetch_region())
        .await
        .expect("failed spawn await")
        .expect("failed ec2::fetch_region");
    info!("fetched region {}", reg);

    let instance_id = tokio::spawn(ec2::fetch_instance_id())
        .await
        .expect("failed spawn await")
        .expect("failed ec2::fetch_instance_id");
    info!("fetched instance ID {}", instance_id);

    let public_ipv4 = tokio::spawn(ec2::fetch_public_ipv4())
        .await
        .expect("failed spawn await")
        .expect("failed ec2::fetch_public_ipv4");
    info!("fetched public ipv4 {}", public_ipv4);

    info!("STEP: loading AWS config");
    let shared_config = tokio::spawn(aws_sdk_manager::load_config(Some(reg.clone())))
        .await
        .expect("failed spawn aws_sdk_manager::load_config")
        .expect("failed aws_sdk_manager::load_config");

    let ec2_manager = ec2::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    info!("STEP: fetching tags from the local instance");
    let instance_id_arc = Arc::new(instance_id.clone());
    let tags = tokio::spawn(async move {
        let ec2_manager_arc = Arc::new(ec2_manager);
        ec2_manager_arc.fetch_tags(instance_id_arc).await
    })
    .await
    .expect("failed spawn await")
    .expect("failed ec2_manager.fetch_tags");

    let mut id: String = String::new();
    let mut _node_kind: String = String::new();
    let mut kms_cmk_arn: String = String::new();
    let mut s3_bucket: String = String::new();
    let mut cloudwatch_config_file_path: String = String::new();
    let mut avalanched_bin_path: String = String::new();
    let mut avalanche_bin_path: String = String::new();
    let mut avalanche_data_volume_path: String = String::new();
    for c in tags {
        let k = c.key().unwrap();
        let v = c.value().unwrap();
        info!("tag key='{}', value='{}'", k, v);
        match k {
            "ID" => {
                id = v.to_string();
            }
            "NODE_KIND" => {
                _node_kind = v.to_string();
            }
            "KMS_CMK_ARN" => {
                kms_cmk_arn = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                s3_bucket = v.to_string();
            }
            "CLOUDWATCH_CONFIG_FILE_PATH" => {
                cloudwatch_config_file_path = v.to_string();
            }
            "AVALANCHED_BIN_PATH" => {
                avalanched_bin_path = v.to_string();
            }
            "AVALANCHE_BIN_PATH" => {
                avalanche_bin_path = v.to_string();
            }
            "AVALANCHE_DATA_VOLUME_PATH" => {
                avalanche_data_volume_path = v.to_string();
            }
            _ => {}
        }
    }
    if id.is_empty() {
        panic!("'ID' tag not found")
    }
    if _node_kind.is_empty() {
        panic!("'NODE_KIND' tag not found")
    }
    let node_kind = {
        if _node_kind.eq("anchor") {
            node::Kind::Anchor
        } else {
            node::Kind::NonAnchor
        }
    };
    if kms_cmk_arn.is_empty() {
        panic!("'KMS_CMK_ARN' tag not found")
    }
    if s3_bucket.is_empty() {
        panic!("'S3_BUCKET_NAME' tag not found")
    }
    if cloudwatch_config_file_path.is_empty() {
        panic!("'CLOUDWATCH_CONFIG_FILE_PATH' tag not found")
    }
    if avalanched_bin_path.is_empty() {
        panic!("'AVALANCHED_BIN_PATH' tag not found")
    }
    if avalanche_bin_path.is_empty() {
        panic!("'AVALANCHE_BIN_PATH' tag not found")
    }
    if avalanche_data_volume_path.is_empty() {
        panic!("'AVALANCHE_DATA_VOLUME_PATH' tag not found")
    }

    let envelope = Envelope {
        kms_manager,
        kms_key_id: kms_cmk_arn,
        aad_tag: "avalanche-ops".to_string(),
    };

    if !Path::new(&avalanche_bin_path).exists() {
        info!("STEP: downloading avalanche binary from S3");
        let s3_key = avalancheup_aws::StorageNamespace::AvalancheBinCompressed(id.clone()).encode();
        let tmp_avalanche_bin_compressed_path = random::tmp_path(15, Some(".zstd")).unwrap();
        s3::spawn_get_object(
            s3_manager.clone(),
            &s3_bucket,
            &s3_key,
            &tmp_avalanche_bin_compressed_path,
        )
        .await
        .expect("failed s3::spawn_get_object");

        compress_manager::unpack_file(
            &tmp_avalanche_bin_compressed_path,
            &avalanche_bin_path,
            compress_manager::Decoder::Zstd,
        )
        .expect("failed unpack_file avalanche_bin_compressed_path");

        let f = File::open(&avalanche_bin_path).expect("failed to open avalanche_bin");
        f.set_permissions(PermissionsExt::from_mode(0o777))
            .expect("failed to set file permission for avalanche_bin");
        fs::remove_file(&tmp_avalanche_bin_compressed_path).expect("failed fs::remove_file");
    }

    let plugins_dir = get_plugins_dir(&avalanche_bin_path);
    if !Path::new(&plugins_dir).exists() {
        info!("STEP: creating '{}' for plugins", plugins_dir);
        fs::create_dir_all(plugins_dir.clone()).unwrap();

        info!("STEP: downloading plugins from S3 (if any)");
        let objects = s3::spawn_list_objects(
            s3_manager.clone(),
            &s3_bucket,
            Some(s3::append_slash(
                &avalancheup_aws::StorageNamespace::PluginsDir(id.clone()).encode(),
            )),
        )
        .await
        .expect("failed s3::spawn_list_objects");
        info!("listed {} plugins from S3", objects.len());
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object").to_string();
            let tmp_path = random::tmp_path(15, None).unwrap();
            s3::spawn_get_object(s3_manager.clone(), &s3_bucket, &s3_key, &tmp_path)
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
    }

    info!("STEP: downloading avalanche-ops::Spec from S3");
    let tmp_spec_file_path = random::tmp_path(15, Some(".yaml")).unwrap();
    s3::spawn_get_object(
        s3_manager.clone(),
        &s3_bucket,
        &avalancheup_aws::StorageNamespace::ConfigFile(id.clone()).encode(),
        &tmp_spec_file_path,
    )
    .await
    .expect("failed s3::spawn_get_object");

    let mut spec = avalancheup_aws::Spec::load(&tmp_spec_file_path).unwrap();
    spec.avalanchego_config.public_ip = Some(public_ipv4.clone());
    spec.avalanchego_config
        .sync(None)
        .expect("failed to sync avalanchego config_file");

    // "avalanched" never updates "spec" file, runs in read-only mode
    fs::remove_file(&tmp_spec_file_path).expect("failed fs::remove_file");

    // ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
    info!("STEP: writing CloudWatch configuration JSON file");
    let aws_resources = spec.aws_resources.clone().unwrap();
    let mut log_collect_list = vec![
        cloudwatch::Collect {
            log_group_name: id.clone(),
            log_stream_name: format!("{{instance_id}}-{}-avalanched", node_kind.as_str()),
            file_path: String::from("/var/log/avalanched/avalanched.log"),
            auto_removal: Some(true),
            retention_in_days: Some(7),
            ..cloudwatch::Collect::default()
        },
        // collect all .log files in the /var/log/avalanche tree
        cloudwatch::Collect {
            log_group_name: id.clone(),
            log_stream_name: format!("{{instance_id}}-{}-all-logs", node_kind.as_str()),
            file_path: format!("{}/**.log", spec.avalanchego_config.log_dir),

            // TODO: replace this with log rotation
            auto_removal: Some(false),

            retention_in_days: Some(7),
            ..cloudwatch::Collect::default()
        },
    ];
    if aws_resources.instance_system_logs.is_some() && aws_resources.instance_system_logs.unwrap() {
        // to check OOMs via "oom-kill" or "Out of memory: Killed process 8266 (srEXiWaHuhNyGwP)"
        log_collect_list.push(cloudwatch::Collect {
            log_group_name: id.clone(),
            log_stream_name: format!("{{instance_id}}-{}-syslog", node_kind.as_str()),
            file_path: String::from("/var/log/syslog"),
            auto_removal: Some(true),
            retention_in_days: Some(7),
            ..cloudwatch::Collect::default()
        });
        // to check device layer logs
        log_collect_list.push(cloudwatch::Collect {
            log_group_name: id.clone(),
            log_stream_name: format!("{{instance_id}}-{}-dmesg", node_kind.as_str()),
            file_path: String::from("/var/log/dmesg"),
            auto_removal: Some(true),
            retention_in_days: Some(7),
            ..cloudwatch::Collect::default()
        });
    }
    let mut cloudwatch_config = cloudwatch::Config::default();
    cloudwatch_config.logs = Some(cloudwatch::Logs {
        force_flush_interval: Some(60),
        logs_collected: Some(cloudwatch::LogsCollected {
            files: Some(cloudwatch::Files {
                collect_list: Some(log_collect_list),
            }),
        }),
    });
    if aws_resources.instance_system_metrics.is_some()
        && aws_resources.instance_system_metrics.unwrap()
    {
        let mut cw_metrics = cloudwatch::Metrics {
            namespace: id.clone(),
            ..Default::default()
        };
        cw_metrics.metrics_collected.disk =
            Some(cloudwatch::Disk::new(vec![avalanche_data_volume_path]));
        cloudwatch_config.metrics = Some(cw_metrics);
    }
    cloudwatch_config
        .sync(&cloudwatch_config_file_path)
        .unwrap();

    // TODO: reuse TLS certs for static node IDs
    info!("checking TLS certs for node ID");
    let tls_key_path = spec
        .avalanchego_config
        .clone()
        .staking_tls_key_file
        .unwrap();
    let tls_key_exists = Path::new(&tls_key_path).exists();
    let tls_cert_path = spec
        .avalanchego_config
        .clone()
        .staking_tls_cert_file
        .unwrap();
    let tls_cert_exists = Path::new(&tls_cert_path).exists();
    if !tls_key_exists || !tls_cert_exists {
        info!(
            "STEP: generating TLS certs (key exists {}, cert exists {})",
            tls_key_exists, tls_cert_exists
        );
        cert::generate_default_pem(&tls_key_path, &tls_cert_path).unwrap();

        info!("uploading generated TLS certs to S3");
        let s3_key = format!(
            "{}/{}.crt",
            avalancheup_aws::StorageNamespace::PkiKeyDir(id.clone()).encode(),
            instance_id
        );
        s3::spawn_put_object(s3_manager.clone(), &tls_cert_path, &s3_bucket, &s3_key)
            .await
            .expect("failed s3::spawn_put_object");

        let tmp_compressed_path = random::tmp_path(15, Some(".zstd")).unwrap();
        let tmp_encrypted_path = random::tmp_path(15, Some(".zstd.encrypted")).unwrap();

        compress_manager::pack_file(
            &tls_key_path,
            &tmp_compressed_path,
            compress_manager::Encoder::Zstd(3),
        )
        .expect("failed pack_file tls_key_path");

        envelope::spawn_seal_aes_256_file(
            envelope.clone(),
            &tmp_compressed_path,
            &tmp_encrypted_path,
        )
        .await
        .expect("failed envelope::spawn_seal_aes_256_file");

        s3::spawn_put_object(
            s3_manager.clone(),
            &tmp_encrypted_path,
            &s3_bucket,
            &format!(
                "{}/{}.key.zstd.seal_aes_256.encrypted",
                avalancheup_aws::StorageNamespace::PkiKeyDir(id.clone()).encode(),
                instance_id
            )
            .to_string(),
        )
        .await
        .expect("failed s3::spawn_put_object");

        fs::remove_file(tmp_compressed_path).expect("failed fs::remove_file");
        fs::remove_file(tmp_encrypted_path).expect("failed fs::remove_file");
    }

    // loads the node ID from generated/existing certs
    let node_id =
        ids::node::Id::from_cert_pem_file(&tls_cert_path).expect("failed to load node ID");
    info!("loaded node ID {}", node_id);

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
        &instance_id,
        &node_id.to_string(),
        &public_ipv4,
        http_scheme,
        spec.avalanchego_config.http_port,
    );
    info!(
        "loaded node:\n{}",
        local_node
            .encode_yaml()
            .expect("failed to encode node Info")
    );

    // "63.65 GB" .tar.gz download  takes about 45-min
    // "63.65 GB" .tar.gz unpack    takes about 7-min
    // "75.47 GB" .tar    unarchive takes about 5-min
    if spec.aws_resources.is_some() {
        let aws_resources = spec.aws_resources.unwrap();
        if aws_resources.db_backup_s3_region.is_some()
            && aws_resources.db_backup_s3_bucket.is_some()
            && aws_resources.db_backup_s3_key.is_some()
        {
            info!("STEP: publishing node information before db backup downloads");
            let s3_key = {
                if matches!(node_kind, node::Kind::Anchor) {
                    avalancheup_aws::StorageNamespace::DiscoverProvisioningAnchorNode(
                        id.clone(),
                        local_node.clone(),
                    )
                } else {
                    avalancheup_aws::StorageNamespace::DiscoverProvisioningNonAnchorNode(
                        id.clone(),
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
                random::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
            node_info.sync(tmp_path.clone()).unwrap();
            s3::spawn_put_object(s3_manager.clone(), &tmp_path, &s3_bucket, &s3_key)
                .await
                .expect("failed s3::spawn_put_object");
            fs::remove_file(tmp_path).expect("failed fs::remove_file");

            sleep(Duration::from_secs(1)).await;
            let db_backup_s3_region = aws_resources.db_backup_s3_region.clone().unwrap();
            let db_backup_s3_bucket = aws_resources.db_backup_s3_bucket.clone().unwrap();
            let db_backup_s3_key = aws_resources.db_backup_s3_key.unwrap();
            let dec = compress_manager::DirDecoder::new_from_file_name(&db_backup_s3_key).unwrap();
            info!(
                "STEP: downloading database backup file 's3://{}/{}' [{}] in region {}",
                db_backup_s3_bucket,
                db_backup_s3_key,
                dec.id(),
                db_backup_s3_region,
            );

            let db_backup_s3_config =
                tokio::spawn(aws_sdk_manager::load_config(Some(db_backup_s3_region)))
                    .await
                    .expect("failed spawn await")
                    .expect("failed aws_sdk_manager::load_config");
            let db_backup_s3_manager = s3::Manager::new(&db_backup_s3_config);

            // do not store in "tmp", will run out of space
            let download_path = format!(
                "{}/{}{}",
                spec.avalanchego_config.db_dir,
                random::string(10),
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

            info!("removing downloaded file {} after unpack", download_path);
            fs::remove_file(download_path).expect("failed fs::remove_file");

            // TODO: override network id to support network fork
        } else {
            info!("STEP: db_backup_s3_bucket is empty, skipping database backup download from S3")
        }
    }

    if spec.avalanchego_config.is_custom_network()
        && matches!(node_kind, node::Kind::Anchor)
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        info!("STEP: publishing seed/bootstrapping anchor node information for discovery");
        let node_info = avalancheup_aws::NodeInfo::new(
            local_node.clone(),
            spec.avalanchego_config.clone(),
            spec.coreth_config.clone(),
        );
        let tmp_path = random::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
        node_info.sync(tmp_path.clone()).unwrap();

        s3::spawn_put_object(
            s3_manager.clone(),
            &tmp_path,
            &s3_bucket,
            &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNode(
                id.clone(),
                local_node.clone(),
            )
            .encode(),
        )
        .await
        .expect("failed s3::spawn_put_object");

        fs::remove_file(tmp_path).expect("failed fs::remove_file");

        sleep(Duration::from_secs(30)).await;
        info!("STEP: waiting for all seed/bootstrapping anchor nodes to be ready");
        let target_nodes = spec.machine.anchor_nodes.unwrap();
        let s3_key = s3::append_slash(
            &avalancheup_aws::StorageNamespace::DiscoverBootstrappingAnchorNodesDir(id.clone())
                .encode(),
        );
        let mut objects: Vec<Object>;
        loop {
            sleep(Duration::from_secs(20)).await;
            objects = s3::spawn_list_objects(s3_manager.clone(), &s3_bucket, Some(s3_key.clone()))
                .await
                .expect("failed s3::spawn_list_objects");
            info!(
                "{} seed/bootstrapping anchor nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        info!("STEP: update genesis file with seed/bootstrapping anchor nodes");
        let mut initial_stakers: Vec<avalanchego_genesis::Staker> = vec![];

        // "initial_staked_funds" is reserved for locked P-chain balance
        // with "spec.generated_seed_private_key_with_locked_p_chain_balance"
        let seed_priv_keys = spec.generated_seed_private_keys.unwrap();
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
        info!(
            "found {} seed anchor nodes for initial stakers",
            initial_stakers.len()
        );

        let avalanchego_genesis_path = spec.avalanchego_config.clone().genesis.unwrap();
        let mut avalanchego_genesis_template = spec
            .avalanchego_genesis_template
            .expect("unexpected None avalanchego_genesis_template for custom network");
        avalanchego_genesis_template.initial_stakers = Some(initial_stakers);
        avalanchego_genesis_template
            .sync(&avalanchego_genesis_path)
            .expect("failed to sync avalanchego_genesis_path");

        // for now, just overwrite from every seed anchor node
        sleep(Duration::from_secs(1)).await;

        info!("STEP: upload the new genesis file, to be shared with non-anchor nodes");
        s3::spawn_put_object(
            s3_manager.clone(),
            &avalanchego_genesis_path,
            &s3_bucket,
            &avalancheup_aws::StorageNamespace::GenesisFile(spec.id.clone()).encode(),
        )
        .await
        .expect("failed s3::spawn_put_object");
    }

    if spec.avalanchego_config.is_custom_network()
        && matches!(node_kind, node::Kind::NonAnchor)
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        info!("STEP: downloading genesis file from S3 (updated from other anchor nodes)");
        let tmp_genesis_path = random::tmp_path(15, Some(".json")).unwrap();
        s3::spawn_get_object(
            s3_manager.clone(),
            &s3_bucket,
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
    if spec.avalanchego_config.is_custom_network() && matches!(node_kind, node::Kind::NonAnchor) {
        sleep(Duration::from_secs(1)).await;
        info!(
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
            &avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNodesDir(id.clone()).encode(),
        );
        let mut objects: Vec<Object>;
        loop {
            sleep(Duration::from_secs(20)).await;

            objects = s3::spawn_list_objects(s3_manager.clone(), &s3_bucket, Some(s3_key.clone()))
                .await
                .expect("failed s3::spawn_list_objects");
            info!(
                "{} anchor nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        info!("STEP: updating bootstrap IPs/IDs with all anchor nodes");
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
        info!("found {} bootstrap nodes", bootstrap_ids.len());

        spec.avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));
        spec.avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
    }

    let log_dir = spec.avalanchego_config.clone().log_dir;
    fs::create_dir_all(&log_dir).expect("failed to create log_dir");

    let chain_config_dir = spec.avalanchego_config.clone().chain_config_dir;
    fs::create_dir_all(Path::new(&chain_config_dir).join("C"))
        .expect("failed to create dir for chain config");

    info!(
        "STEP: saving coreth evm config file to chain config dir {}",
        chain_config_dir
    );
    let tmp_coreth_config_path = random::tmp_path(15, Some(".json")).unwrap();
    let chain_config_dir = spec.avalanchego_config.clone().chain_config_dir;
    let chain_config_c_path = Path::new(&chain_config_dir).join("C").join("config.json");
    info!(
        "saving coreth config file to {:?}",
        chain_config_c_path.as_os_str()
    );
    spec.coreth_config
        .sync(&tmp_coreth_config_path)
        .expect("failed to sync coreth_config");
    fs::copy(&tmp_coreth_config_path, chain_config_c_path).expect("failed fs::copy");
    fs::remove_file(&tmp_coreth_config_path).expect("failed fs::remove_file");

    if spec.avalanchego_config.subnet_config_dir.is_some() {
        let subnet_config_dir = spec
            .avalanchego_config
            .clone()
            .subnet_config_dir
            .expect("unexpected None subnet_config_dir");
        fs::create_dir_all(Path::new(&subnet_config_dir).join("C"))
            .expect("failed to create dir for chain config");
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

    // persist before starting the service
    spec.avalanchego_config
        .sync(None)
        .expect("failed to sync avalanchego config_file");
    info!(
        "STEP: setting up avalanche node systemd service file with --config-file={}",
        spec.avalanchego_config.clone().config_file.unwrap()
    );

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
        spec.avalanchego_config.clone().config_file.unwrap(),
    );
    let mut avalanche_service_file = tempfile::NamedTempFile::new().unwrap();
    avalanche_service_file
        .write_all(avalanche_service_file_contents.as_bytes())
        .expect("failed write_all avalanche_service_file");
    let avalanche_service_file_path = avalanche_service_file.path().to_str().unwrap();
    fs::copy(
        avalanche_service_file_path,
        "/etc/systemd/system/avalanche.service",
    )
    .expect("failed to copy /etc/systemd/system/avalanche.service");
    bash::run("sudo systemctl daemon-reload").expect("failed systemctl daemon-reload command");
    bash::run("sudo systemctl disable avalanche.service")
        .expect("failed systemctl disable command");
    bash::run("sudo systemctl enable avalanche.service").expect("failed systemctl enable command");
    bash::run("sudo systemctl restart --no-block avalanche.service")
        .expect("failed systemctl restart command");

    // this can take awhile if loaded from backups or syncing from peers
    info!("'avalanched run' all success -- now waiting for local node liveness check");
    loop {
        let ret = api_health::spawn_check(&local_node.http_endpoint, true).await;
        match ret {
            Ok(res) => {
                if res.healthy.is_some() && res.healthy.unwrap() {
                    info!("health/liveness check success for {}", instance_id);
                    break;
                }
            }
            Err(e) => {
                warn!("health/liveness check failed for {} ({:?})", instance_id, e);
            }
        };
        sleep(Duration::from_secs(30)).await;

        let out = bash::run("sudo tail -10 /var/log/avalanche/avalanche.log")
            .expect("failed 'tail -10 /var/log/avalanche/avalanche.log'");
        println!(
            "\n'/var/log/avalanche/avalanche.log' stdout:\n\n{}\n",
            out.0
        );
        println!("'/var/log/avalanche/avalanche.log' stderr:\n\n{}\n", out.1);

        println!();
        let out = bash::run("sudo journalctl -u avalanche.service --lines=10 --no-pager")
            .expect("failed 'journalctl -u avalanche.service --lines=10 --no-pager'");
        println!("\n'avalanche.service' stdout:\n\n{}\n", out.0);
        println!("'avalanche.service' stderr:\n\n{}\n", out.1);
    }

    info!("spawning async routines...");
    let node_info_ready_s3_key = {
        if matches!(node_kind, node::Kind::Anchor) {
            avalancheup_aws::StorageNamespace::DiscoverReadyAnchorNode(
                id.to_string(),
                local_node.clone(),
            )
            .encode()
        } else {
            avalancheup_aws::StorageNamespace::DiscoverReadyNonAnchorNode(
                id.to_string(),
                local_node.clone(),
            )
            .encode()
        }
    };
    let mut handles = vec![
        tokio::spawn(publish_node_info_ready_loop(
            s3_manager.clone(),
            Arc::new(s3_bucket.clone()),
            Arc::new(node_info_ready_s3_key),
            Arc::new(avalancheup_aws::NodeInfo::new(
                local_node.clone(),
                spec.avalanchego_config.clone(),
                spec.coreth_config.clone(),
            )),
        )),
        tokio::spawn(fetch_metrics_loop(
            cw_manager.clone(),
            Arc::new(
                aws_resources
                    .clone()
                    .cloudwatch_avalanche_metrics_namespace
                    .unwrap(),
            ),
            Arc::new(local_node.http_endpoint.clone()),
        )),
        tokio::spawn(check_node_update_loop(
            s3_manager.clone(),
            Arc::new(s3_bucket.clone()),
            Arc::new(id.clone()),
            Arc::new(avalanche_bin_path),
        )),
    ];
    if aws_resources.db_backup_s3_bucket.is_some() {
        handles.push(tokio::spawn(print_backup_commands(
            Arc::new(aws_resources.db_backup_s3_region.clone().unwrap()),
            Arc::new(aws_resources.db_backup_s3_bucket.clone().unwrap()),
            Arc::new(id.clone()),
            Arc::new(spec.avalanchego_config.network_id),
            Arc::new(spec.avalanchego_config.db_dir),
        )));
    }

    info!("STEP: blocking on handles via JoinHandle");
    for handle in handles {
        handle.await.expect("failed handle");
    }
}

/// if run in anchor nodes, the uploaded file will be downloaded
/// in bootstrapping non-anchor nodes for custom networks
async fn publish_node_info_ready_loop(
    s3_manager: s3::Manager,
    s3_bucket: Arc<String>,
    s3_key: Arc<String>,
    node_info: Arc<avalancheup_aws::NodeInfo>,
) {
    info!("STEP: starting 'publish_node_info_ready_loop'");

    loop {
        info!(
            "STEP: posting node info ready for {}",
            node_info.local_node.kind
        );

        let tmp_path = random::tmp_path(10, Some(".yaml")).expect("unexpected tmp_path failure");
        node_info.sync(tmp_path.clone()).unwrap();

        s3::spawn_put_object(
            s3_manager.clone(),
            &tmp_path,
            &s3_bucket.clone(),
            &s3_key.clone(),
        )
        .await
        .expect("failed s3::spawn_put_object");

        fs::remove_file(&tmp_path).expect("failed fs::remove_file");

        info!("sleeping 10-min for next 'publish_node_info_ready_loop'");
        sleep(Duration::from_secs(600)).await;
    }
}

async fn fetch_metrics_loop(
    cw_manager: cloudwatch::Manager,
    cw_namespace: Arc<String>,
    metrics_ep: Arc<String>,
) {
    info!("STEP: starting 'fetch_metrics_loop' with initial 2-minute wait");
    sleep(Duration::from_secs(120)).await;

    let mut prev_raw_metrics: Option<avalanchego_metrics::RawMetrics> = None;
    loop {
        info!("STEP: fetching metrics in 1-min");
        sleep(Duration::from_secs(60)).await;

        let cur_metrics = match api_metrics::spawn_get(metrics_ep.as_str()).await {
            Ok(v) => v,
            Err(e) => {
                warn!("failed to fetch metrics {}, retrying...", e);
                continue;
            }
        };

        match cloudwatch::spawn_put_metric_data(
            cw_manager.clone(),
            cw_namespace.as_str(),
            api_cw::convert(&cur_metrics, prev_raw_metrics.clone()),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!("failed to put metric data {}, retrying...", e);
                prev_raw_metrics = Some(cur_metrics.clone());
                continue;
            }
        }

        prev_raw_metrics = Some(cur_metrics.clone());
    }
}

async fn check_node_update_loop(
    s3_manager: s3::Manager,
    s3_bucket: Arc<String>,
    id: Arc<String>,
    avalanche_bin_path: Arc<String>,
) {
    info!("STEP: starting 'check_node_update_loop'");

    loop {
        info!("sleeping 3-min for 'check_node_update_loop'");
        sleep(Duration::from_secs(180)).await;

        info!("STEP: checking update artifacts event key");
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
                warn!("failed s3::spawn_list_objects {}, retrying...", e);
                continue;
            }
        };

        if objects.is_empty() {
            warn!("no event key found");
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
        info!(
            "last_modified_unix {}, now_unix {} [needs update: {}]",
            last_modified_unix, now_unix, needs_update
        );

        if !needs_update {
            warn!(
                "update artifacts event not found (seeing {} objects)",
                objects.len()
            );
            continue;
        }

        info!("STEP: downloading avalanched binary from S3");

        // TODO: replace "avalanched" itself?
        // TODO: fs::copy fails with 'Os { code: 26, kind: ExecutableFileBusy, message: "Text file busy" }'
        // can't replace the process itself...

        info!("STEP: downloading avalanche binary from S3");
        let tmp_avalanche_bin_compressed_path = random::tmp_path(15, Some(".zstd")).unwrap();
        s3::spawn_get_object(
                    s3_manager.clone(),
                    s3_bucket.clone().as_ref().to_string(),
                    avalancheup_aws::StorageNamespace::EventsUpdateArtifactsInstallDirAvalancheBinCompressed(id.to_string()).encode(),
                      tmp_avalanche_bin_compressed_path.clone(),
                )
                .await
                .expect("failed s3::spawn_get_object");

        warn!("stopping avalanche.service before unpack...");
        bash::run("sudo systemctl stop avalanche.service").expect("failed systemctl stop command");
        warn!("stopped avalanche.service before unpack...");
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

        let plugins_dir = get_plugins_dir(avalanche_bin_path.as_str());
        if !Path::new(&plugins_dir).exists() {
            info!("STEP: creating '{}' for plugins", plugins_dir);
            fs::create_dir_all(plugins_dir.clone()).unwrap();
        }

        info!("STEP: downloading plugins from S3 (if any) to overwrite");
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

        info!("listed {} plugins from S3", objects.len());
        for obj in objects.iter() {
            let s3_key = obj.key().expect("unexpected None s3 object").to_string();
            let tmp_path = random::tmp_path(15, None).unwrap();
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
        warn!("artifacts have been updated... will trigger avalanched restart by panic here...");
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
    info!("STEP: starting 'print_backup_commands'");

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
            &s3_bucket,
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

        info!("sleeping 5-hour 'print_backup_commands'");
        sleep(Duration::from_secs(5 * 3600)).await;
    }
}

///  build
///    ├── avalanchego (the binary from compiling the app directory)
///    └── plugins
///        └── evm
fn get_plugins_dir(avalanche_bin: &str) -> String {
    let path = Path::new(avalanche_bin);
    let parent_dir = path.parent().unwrap();
    String::from(
        parent_dir
            .join(Path::new("plugins"))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

/// returns "hello" from "a/b/c/hello.zstd"
fn extract_filename(p: &str) -> String {
    let path = Path::new(p);
    let file_stemp = path.file_stem().unwrap();
    String::from(file_stemp.to_str().unwrap())
}
