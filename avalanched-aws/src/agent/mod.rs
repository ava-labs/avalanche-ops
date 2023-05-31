mod cloudwatch;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{self, Error, ErrorKind, Write},
    path::Path,
    sync::Arc,
};

use avalanche_types::{
    avalanchego::{self, genesis as avalanchego_genesis},
    coreth, ids,
    jsonrpc::client::health as client_health,
    key::bls,
    node,
};
use aws_manager::{
    self, autoscaling, ec2,
    kms::{self, envelope},
    s3,
};
use aws_sdk_ec2::types::{Filter, Tag};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "agent";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    /// Set "true" to run "avalanched-aws" without downloading any "avalancheup" spec dependencies.
    /// Used for CDK integration.
    pub use_default_config: bool,

    /// The node information is published regardless of anchor/non-anchor.
    /// This is set "true" iff the node wishes to publish it periodically.
    /// Otherwise, publish only once until success!
    /// Might be useful to publish ready heartbeats to S3 in the future.
    pub publish_periodic_node_info: bool,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Runs an Avalanche agent (daemon) on AWS")
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
            Arg::new("USE_DEFAULT_CONFIG")
                .long("use-default-config")
                .help("Enables to use the default config without downloading the spec from S3 (useful for CDK integration)")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("PUBLISH_PERIODIC_NODE_INFO")
                .long("publish-periodic-node-info")
                .help("Enables to periodically publish ready node information to S3")
                .required(false)
                .num_args(0),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    println!("starting {} with {:?}", crate::APP_NAME, opts);

    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    //
    //
    //
    //
    //
    //
    //
    let meta = fetch_metadata().await?;

    //
    //
    //
    //
    //
    //
    //
    let shared_config =
        aws_manager::load_config(Some(meta.region.clone()), Some(Duration::from_secs(30))).await;
    let ec2_manager = ec2::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);

    //
    //
    //
    //
    //
    //
    //
    log::info!("STEP: fetching tags...");
    let tags = ec2_manager
        .fetch_tags(&meta.ec2_instance_id)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed fetch_tags {}", e)))?;

    let mut fetched_tags = Tags {
        id: String::new(),
        network_id: 0,
        arch_type: String::new(),
        os_type: String::new(),
        instance_mode: String::new(),
        node_kind: node::Kind::Unknown(String::new()),
        kms_key_arn: String::new(),
        aad_tag: String::new(),
        s3_region: String::new(),
        s3_bucket: String::new(),
        cloudwatch_config_file_path: String::new(),
        avalanche_telemetry_cloudwatch_rules_file_path: String::new(),
        avalancheup_spec_path: String::new(),
        avalanche_data_volume_path: String::new(),
        avalanche_data_volume_ebs_device_name: String::new(),
        eip_file_path: String::new(),
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
            "INSTANCE_MODE" => {
                fetched_tags.instance_mode = v.to_string();
            }
            "NODE_KIND" => {
                fetched_tags.node_kind = if v.to_string().eq("anchor") {
                    node::Kind::Anchor
                } else {
                    node::Kind::NonAnchor
                };
            }
            "KMS_KEY_ARN" => {
                fetched_tags.kms_key_arn = v.to_string();
            }
            "AAD_TAG" => {
                fetched_tags.aad_tag = v.to_string();
            }
            "S3_REGION" => {
                fetched_tags.s3_region = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                fetched_tags.s3_bucket = v.to_string();
            }
            "CLOUDWATCH_CONFIG_FILE_PATH" => {
                fetched_tags.cloudwatch_config_file_path = v.to_string();
            }
            "AVALANCHE_TELEMETRY_CLOUDWATCH_RULES_FILE_PATH" => {
                fetched_tags.avalanche_telemetry_cloudwatch_rules_file_path = v.to_string();
            }
            "AVALANCHEUP_SPEC_PATH" => {
                fetched_tags.avalancheup_spec_path = v.to_string();
            }
            "AVALANCHE_DATA_VOLUME_PATH" => {
                fetched_tags.avalanche_data_volume_path = v.to_string();
            }
            "AVALANCHE_DATA_VOLUME_EBS_DEVICE_NAME" => {
                fetched_tags.avalanche_data_volume_ebs_device_name = v.to_string();
            }
            "EIP_FILE_PATH" => {
                fetched_tags.eip_file_path = v.to_string();
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
    assert!(!fetched_tags.kms_key_arn.is_empty());
    assert!(!fetched_tags.aad_tag.is_empty());
    assert!(!fetched_tags.s3_region.is_empty());
    assert!(!fetched_tags.s3_bucket.is_empty());
    assert!(!fetched_tags.cloudwatch_config_file_path.is_empty());
    assert!(!fetched_tags
        .avalanche_telemetry_cloudwatch_rules_file_path
        .is_empty());
    assert!(!fetched_tags.avalancheup_spec_path.is_empty());
    assert!(!fetched_tags.avalanche_data_volume_path.is_empty());
    assert!(!fetched_tags
        .avalanche_data_volume_ebs_device_name
        .is_empty());

    let s3_manager = s3::Manager::new(
        &aws_manager::load_config(
            Some(fetched_tags.s3_region.clone()),
            Some(Duration::from_secs(30)),
        )
        .await,
    );

    // if EIP is not set, just use the ephemeral IP
    let public_ipv4 = if Path::new(&fetched_tags.eip_file_path).exists() {
        log::info!(
            "non-empty eip file path {} -- loading",
            fetched_tags.eip_file_path
        );
        let eip = ec2::Eip::load(&fetched_tags.eip_file_path)?;
        eip.public_ip
    } else {
        meta.public_ipv4.clone()
    };
    log::info!("public IPv4 for this node {}", public_ipv4);

    //
    //
    //
    //
    //
    //
    //
    let (
        mut avalanchego_config,
        coreth_chain_config,
        region_to_anchor_asg_names,
        metrics_rules,
        logs_auto_removal,
        metrics_fetch_interval_seconds,
    ) = if opts.use_default_config {
        let avalanchego_config =
            write_default_avalanche_config(fetched_tags.network_id, &public_ipv4)?;
        let coreth_chain_config =
            write_default_coreth_chain_config(&avalanchego_config.chain_config_dir)?;

        (
            avalanchego_config,
            coreth_chain_config,
            HashMap::new(),
            avalanche_ops::artifacts::prometheus_rules(),
            true,
            0,
        )
    } else {
        log::info!("STEP: downloading avalancheup spec file from S3...");
        let tmp_spec_file_path = random_manager::tmp_path(15, Some(".yaml"))?;
        let exists = s3_manager
            .get_object_with_retries(
                &fetched_tags.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::ConfigFile(fetched_tags.id.clone())
                    .encode(),
                &tmp_spec_file_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed get_object {}", e)))?;
        if !exists {
            return Err(Error::new(ErrorKind::Other, "spec s3 file not found"));
        }

        let mut spec = avalanche_ops::aws::spec::Spec::load(&tmp_spec_file_path)?;

        // ALWAYS OVERWRITE TO USE S3 AS THE SINGLE SOURCE OF TRUTH
        // local updates will be gone! make sure update the S3 file!
        // except the tracked subnet Ids!
        let track_subnets = if let Some(config_file) = &spec.avalanchego_config.config_file {
            // if exists, load the existing one in case manually updated
            if Path::new(&config_file).exists() {
                log::warn!(
                    "config-file '{}' already exists -- overwriting except tracked subnet ids!",
                    config_file
                );
                let old_cfg = avalanchego::config::Config::load(config_file)?;
                old_cfg.track_subnets
            } else {
                None
            }
        } else {
            None
        };

        // always "only" overwrite public-ip and track-subnets flag in case of EC2 instance replacement
        spec.avalanchego_config.public_ip = Some(public_ipv4.to_string());
        spec.avalanchego_config.add_track_subnets(track_subnets);
        spec.avalanchego_config.sync(None)?;

        // ALWAYS OVERWRITE TO USE S3 AS THE SINGLE SOURCE OF TRUTH
        if Path::new(&fetched_tags.avalancheup_spec_path).exists() {
            log::warn!(
                "overwriting avalancheup_spec_path {}",
                fetched_tags.avalancheup_spec_path
            );
        }
        fs::copy(&tmp_spec_file_path, &fetched_tags.avalancheup_spec_path)?;
        fs::remove_file(&tmp_spec_file_path)?;

        if spec.version != avalanche_ops::aws::spec::VERSION {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "invalid avalanche_ops::aws::spec::VERSION {} (expected {})",
                    spec.version,
                    avalanche_ops::aws::spec::VERSION
                ),
            ));
        }

        write_coreth_chain_config_from_spec(&spec)?;

        // download from S3
        let tmp_prometheus_metrics_file_path = random_manager::tmp_path(15, Some(".yaml"))?;
        let exists = s3_manager
            .get_object_with_retries(
                &fetched_tags.s3_bucket,
                &avalanche_ops::aws::spec::StorageNamespace::MetricsRules(fetched_tags.id.clone())
                    .encode(),
                &tmp_prometheus_metrics_file_path,
                true,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("failed get_object {}", e)))?;
        if !exists {
            return Err(Error::new(ErrorKind::Other, "metrics s3 file not found"));
        }
        let metrics_rules = prometheus_manager::Rules::load(&tmp_prometheus_metrics_file_path)?;

        let mut region_to_anchor_asg_names = HashMap::new();
        for (reg, rsc) in spec.resource.regional_resources.iter() {
            let anchor_asg_names = if let Some(names) = &rsc.cloudformation_asg_anchor_nodes {
                names.clone()
            } else {
                Vec::new()
            };
            region_to_anchor_asg_names.insert(reg.clone(), anchor_asg_names);
        }

        (
            spec.avalanchego_config.clone(),
            spec.coreth_chain_config.clone(),
            region_to_anchor_asg_names,
            metrics_rules,
            !spec.disable_logs_auto_removal,
            spec.metrics_fetch_interval_seconds,
        )
    };
    create_config_dirs(&avalanchego_config, &coreth_chain_config)?;

    //
    //
    //
    //
    //
    //
    //
    if Path::new(&fetched_tags.avalanche_telemetry_cloudwatch_rules_file_path).exists() {
        log::warn!("overwriting avalanche-telemetry-cloudwatch rules file (already exists)")
    }
    metrics_rules.sync(&fetched_tags.avalanche_telemetry_cloudwatch_rules_file_path)?;

    //
    //
    //
    //
    //
    //
    //
    // always overwrite in case we update tags
    write_cloudwatch_config(
        &fetched_tags.id,
        fetched_tags.node_kind.clone(),
        logs_auto_removal,
        &avalanchego_config.log_dir,
        &fetched_tags.avalanche_data_volume_path,
        &fetched_tags.cloudwatch_config_file_path,
        metrics_fetch_interval_seconds as u32,
    )?;

    //
    //
    //
    //
    //
    //
    //
    // ref. <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html>
    let filters: Vec<Filter> = vec![
        Filter::builder()
            .set_name(Some(String::from("attachment.device")))
            .set_values(Some(vec![fetched_tags
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
            .set_values(Some(vec![fetched_tags.id.clone()]))
            .build(),
    ];
    log::info!("describing existing volume to find the attached volume Id");
    let shared_config =
        aws_manager::load_config(Some(meta.region.clone()), Some(Duration::from_secs(30))).await;
    let local_ec2_manager = ec2::Manager::new(&shared_config);

    let volumes = local_ec2_manager
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
    let attached_volume = volumes[0].clone();
    let attached_volume_id = attached_volume.volume_id().unwrap().to_string();

    //
    //
    //
    //
    //
    //
    //
    log::info!("STEP: setting up certificates...");
    let envelope_manager = envelope::Manager::new(
        &kms_manager,
        fetched_tags.kms_key_arn.to_string(),
        fetched_tags.aad_tag.to_string(),
    );
    let local_tls_key_path = avalanchego_config.staking_tls_key_file.clone().unwrap();
    let local_tls_cert_path = avalanchego_config.staking_tls_cert_file.clone().unwrap();
    let (node_id, newly_generated) =
        ids::node::Id::load_or_generate_pem(&local_tls_key_path, &local_tls_cert_path)?;
    log::info!(
        "loaded node ID {} (was generated {})",
        node_id,
        newly_generated
    );

    //
    //
    //
    //
    //
    //
    //
    if newly_generated {
        log::info!("STEP: backing up newly generated certificates...");

        let s3_key_tls_key = format!("{}/pki/{}.key.zstd.encrypted", fetched_tags.id, node_id);
        log::info!("uploading key file {}", s3_key_tls_key);
        envelope_manager
            .compress_seal_put_object(
                &s3_manager,
                &local_tls_key_path,
                &fetched_tags.s3_bucket,
                &s3_key_tls_key,
            )
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed spawn_compress_seal_put_object tls_key_path: {}", e),
                )
            })?;

        let s3_key_tls_cert = format!("{}/pki/{}.crt.zstd.encrypted", fetched_tags.id, node_id);
        log::info!("uploading cert file {}", local_tls_cert_path);
        envelope_manager
            .compress_seal_put_object(
                &s3_manager,
                &local_tls_cert_path,
                &fetched_tags.s3_bucket,
                &s3_key_tls_cert,
            )
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed spawn_compress_seal_put_object tls_cert_path: {}", e),
                )
            })?;
    }

    //
    //
    //
    //
    //
    //
    //
    log::info!("STEP: setting up staking signer key file (BLS)...");
    let local_staking_signer_key_file_path =
        avalanchego_config.staking_signer_key_file.clone().unwrap();
    let (staking_signer_key, staking_signer_key_newly_generated) =
        bls::private_key::Key::load_or_generate(&local_staking_signer_key_file_path)?;
    if staking_signer_key_newly_generated {
        log::info!("STEP: backing up newly generated staking signer key...");

        let s3_key = format!(
            "{}/staking-signer-keys/{}.staking-signer.bls.key.zstd.encrypted",
            fetched_tags.id, node_id
        );
        log::info!("uploading key file {}", s3_key);
        envelope_manager
            .compress_seal_put_object(
                &s3_manager,
                &local_staking_signer_key_file_path,
                &fetched_tags.s3_bucket,
                &s3_key,
            )
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed spawn_compress_seal_put_object local_staking_signer_key_file_path: {}", e),
                )
            })?;
    }

    let proof_of_possession = staking_signer_key.to_proof_of_possession();

    //
    //
    //
    //
    //
    //
    //
    if newly_generated {
        log::info!("STEP: creating tags for EBS volume with node Id...");

        if let Some(v) = attached_volume.tags() {
            let mut need_to_create_tag = true;
            for tg in v.iter() {
                let k = tg.key().unwrap();
                let v = tg.value().unwrap();
                log::info!("volume '{}' has the tag {}={}", attached_volume_id, k, v);
                if k.eq("NODE_ID") && v.eq(&node_id.to_string()) {
                    need_to_create_tag = false;
                    break;
                }
            }
            if !need_to_create_tag {
                log::warn!(
                    "volume '{}' already has the same NODE_ID tag",
                    attached_volume_id
                );
            } else {
                // create a new client as a workaround
                // ref. <https://github.com/awslabs/aws-sdk-rust/issues/611>
                let shared_config = aws_manager::load_config(
                    Some(meta.region.clone()),
                    Some(Duration::from_secs(30)),
                )
                .await;
                let ec2_manager = ec2::Manager::new(&shared_config);

                // TODO: debug when this blocks.....
                // ref. <https://github.com/awslabs/aws-sdk-rust/issues/611>
                sleep(Duration::from_secs(1)).await;

                // assume all data from EBS are never lost
                // and since we persist and retain ever generated certs
                // in the mounted dir, we can safely assume "create tags"
                // will only be called once per volume
                // ref. https://docs.aws.amazon.com/cli/latest/reference/ec2/create-tags.html
                log::info!(
                    "addiing NODE_ID tag to the EBS volume '{}'",
                    attached_volume_id
                );
                ec2_manager
                    .cli
                    .create_tags()
                    .resources(attached_volume_id.clone())
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
                log::info!(
                    "successfully added node Id tag to the EBS volume '{}'",
                    attached_volume_id
                );
            }
        }
    }

    //
    //
    //
    //
    //
    //
    //
    // always overwrite in case of non-anchor node restarts
    if avalanchego_config.is_custom_network() && avalanchego_config.genesis.is_some() {
        let genesis_file_exists = Path::new(&avalanchego_config.clone().genesis.unwrap()).exists();
        if matches!(fetched_tags.node_kind, node::Kind::Anchor) {
            if genesis_file_exists {
                log::info!(
                    "STEP: genesis file already exists -- no need to discover other anchor nodes"
                );
            } else {
                log::info!(
                    "STEP: genesis file dose not exist -- need to discover other anchor nodes"
                );
            }
        } else {
            log::info!("non-anchor nodes always discover anchor nodes using S3");
        }

        //
        //
        //
        //
        //
        //
        //
        if matches!(fetched_tags.node_kind, node::Kind::Anchor)
            // only need to discover and publish once
            && !genesis_file_exists
        {
            // To be called by each bootstrapping anchor node: Each anchor node publishes
            // the anchor node information to the S3, and waits. And each anchor node
            // lists all keys from the bootstrapping s3 directory for its peer discovery.
            // The function returns all s3 keys that contains the anchor node information.
            log::info!(
                "STEP: publishing bootstrapping local anchor node information for discovery and update the local avalanchego config file"
            );
            let spec = avalanche_ops::aws::spec::Spec::load(&fetched_tags.avalancheup_spec_path)?;
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
            let local_node = avalanche_ops::aws::spec::Node::new(
                &meta.region,
                node::Kind::Anchor,
                &meta.ec2_instance_id,
                &node_id.to_string(),
                &public_ipv4,
                http_scheme,
                spec.avalanchego_config.http_port,
                proof_of_possession.public_key.clone(),
                proof_of_possession.proof_of_possession.clone(),
            );

            log::info!(
                "publishing the loaded local anchor node information for discovery:\n{}",
                local_node
                    .encode_yaml()
                    .expect("failed to encode node Info")
            );

            let node_info = avalanche_ops::aws::spec::NodeInfo::new(
                local_node.clone(),
                spec.avalanchego_config.clone(),
                spec.coreth_chain_config.clone(),
            );
            let node_info_path = random_manager::tmp_path(10, Some(".yaml"))?;
            node_info.sync(&node_info_path).unwrap();

            s3_manager
                .put_object(
                    node_info_path.as_str(),
                    &fetched_tags.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::DiscoverBootstrappingAnchorNode(
                        spec.id.clone(),
                        local_node.clone(),
                    )
                    .encode(),
                )
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Other, format!("failed spawn_put_object {}", e))
                })?;

            fs::remove_file(node_info_path)?;

            log::info!("waiting some time for other bootstrapping anchor nodes to start...");
            sleep(Duration::from_secs(30)).await; // enough time for all anchor nodes up to be

            let target_nodes = spec.machine.total_anchor_nodes.unwrap();
            log::info!("waiting for all other seed/bootstrapping anchor nodes to publish their own (expected total {target_nodes} nodes)");

            let s3_key_prefix = s3::append_slash(
                &avalanche_ops::aws::spec::StorageNamespace::DiscoverBootstrappingAnchorNodesDir(
                    spec.id,
                )
                .encode(),
            );

            log::info!("listing s3 for other anchor nodes with the prefix {s3_key_prefix}");
            let mut objects: Vec<aws_sdk_s3::types::Object>;
            loop {
                sleep(Duration::from_secs(20)).await;

                objects = s3_manager
                    .list_objects(&fetched_tags.s3_bucket, Some(&s3_key_prefix))
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

            let mut bootstrappiong_anchor_node_s3_keys: Vec<String> = Vec::new();
            for obj in objects.iter() {
                let s3_key = obj.key().expect("unexpected None s3 object");
                bootstrappiong_anchor_node_s3_keys.push(s3_key.to_string());
            }
            // s3 API should return the sorted list
            // in the descending order of "last_modified" timestamps
            // but to make sure, sort in lexicographical order
            bootstrappiong_anchor_node_s3_keys.sort();

            merge_bootstrapping_anchor_nodes_to_write_genesis(
                bootstrappiong_anchor_node_s3_keys,
                &fetched_tags.avalancheup_spec_path,
            )?;

            // for now, just overwrite from every seed anchor node
            sleep(Duration::from_secs(1)).await;

            log::info!("STEP: uploading the new genesis file from each anchor node, which is to be shared with non-anchor nodes");
            s3_manager
                .put_object(
                    &avalanchego_config.clone().genesis.unwrap(),
                    &fetched_tags.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::GenesisFile(
                        fetched_tags.id.clone(),
                    )
                    .encode(),
                )
                .await
                .map_err(|e| {
                    Error::new(ErrorKind::Other, format!("failed spawn_put_object {}", e))
                })?;
        }

        //
        //
        //
        //
        //
        //
        //
        if matches!(fetched_tags.node_kind, node::Kind::NonAnchor) {
            log::info!("STEP: downloading genesis file from S3 (updated from other anchor nodes) and update the local avalanchego config file");

            let spec = avalanche_ops::aws::spec::Spec::load(&fetched_tags.avalancheup_spec_path)?;
            let tmp_genesis_path = random_manager::tmp_path(15, Some(".json"))?;

            let exists = s3_manager
                .get_object_with_retries(
                    &fetched_tags.s3_bucket,
                    &avalanche_ops::aws::spec::StorageNamespace::GenesisFile(spec.id.clone())
                        .encode(),
                    &tmp_genesis_path,
                    true,
                    Duration::from_secs(30),
                    Duration::from_secs(1),
                )
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("failed get_object {}", e)))?;
            if !exists {
                return Err(Error::new(ErrorKind::Other, "genesis s3 file not found"));
            }

            fs::copy(
                &tmp_genesis_path,
                spec.avalanchego_config.clone().genesis.unwrap(),
            )?;
            fs::remove_file(&tmp_genesis_path)?;

            // Discover ready anchor nodes from S3 and returns the
            // combined list of bootstrap Ids and Ips.
            // mainnet/other pre-defined test nets have hard-coded anchor nodes
            // thus no need for anchor nodes.
            // Assume new anchor nodes statically remap existing node Ids
            // and publish itself with the new S3 key that has a new IP.
            log::info!(
                "non anchor nodes discover anchor nodes from {:?}",
                region_to_anchor_asg_names
            );

            log::info!("STEP: listing S3 directory to discover ready anchor nodes...");

            let spec = avalanche_ops::aws::spec::Spec::load(&fetched_tags.avalancheup_spec_path)?;

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
                .total_anchor_nodes
                .expect("unexpected None machine.anchor_nodes for custom network");

            let s3_key_prefix = s3::append_slash(
                &avalanche_ops::aws::spec::StorageNamespace::DiscoverReadyAnchorNodesDir(
                    spec.id.clone(),
                )
                .encode(),
            );
            let mut objects: Vec<aws_sdk_s3::types::Object>;
            loop {
                sleep(Duration::from_secs(20)).await;

                objects = s3_manager
                    .list_objects(&fetched_tags.s3_bucket, Some(&s3_key_prefix))
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

            // now delete old/terminated instances that were anchor nodes
            let mut running_machine_ids = HashSet::new();
            for (region, anchor_asg_names) in region_to_anchor_asg_names.iter() {
                let shared_config =
                    aws_manager::load_config(Some(region.clone()), Some(Duration::from_secs(30)))
                        .await;
                let regional_ec2_manager = ec2::Manager::new(&shared_config);

                for anchor_asg_name in anchor_asg_names {
                    log::info!("listing anchor node ASG '{anchor_asg_name}' in '{region}'");
                    let droplets = regional_ec2_manager
                        .list_asg(anchor_asg_name)
                        .await
                        .map_err(|e| {
                            Error::new(ErrorKind::Other, format!("failed list_asg {}", e))
                        })?;
                    log::info!(
                        "listed anchor node ASG {anchor_asg_name} with {} droplets in '{region}'",
                        droplets.len()
                    );

                    for d in droplets.iter() {
                        log::info!(
                            "found droplet {} in anchor node ASG with state {}",
                            d.instance_id,
                            d.instance_state_name
                        );
                        if d.instance_state_name.to_lowercase() == "running" {
                            running_machine_ids.insert(d.instance_id.clone());
                        }
                    }
                }
            }

            let mut bootstrap_ids_to_ips = BTreeMap::new();
            for s3_key in s3_keys.iter() {
                // just parse the s3 key name
                // to reduce "s3_manager.get_object" call volume
                let ready_anchor_node =
                    avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key)?;

                let machine_id = ready_anchor_node.machine_id;
                if !running_machine_ids.contains(&machine_id) {
                    log::warn!(
                        "ready anchor node '{}' but machine id {} not found in ASG (likely terminated)",
                        ready_anchor_node.node_id,
                        machine_id
                    );
                    continue;
                }

                log::info!(
                    "ready anchor node '{}' and machine id {} found in ASG",
                    ready_anchor_node.node_id,
                    machine_id
                );

                // assume all nodes in the network use the same ports
                // ref. "avalanchego/config.StakingPortKey" default value is "9651"
                let staking_port = spec.avalanchego_config.staking_port;
                let ip = format!("{}:{}", ready_anchor_node.public_ip, staking_port);
                bootstrap_ids_to_ips.insert(ready_anchor_node.node_id.to_string(), ip);
            }
            let mut bootstrap_ids: Vec<String> = vec![];
            let mut bootstrap_ips: Vec<String> = vec![];
            for (k, v) in bootstrap_ids_to_ips.iter() {
                bootstrap_ids.push(k.clone());
                bootstrap_ips.push(v.clone());
            }
            log::info!("found {} seed nodes that are ready", bootstrap_ids.len());

            if bootstrap_ids.is_empty() {
                log::warn!("custom network but non anchor node cannot discover any anchor nodes for bootstrap Ids");
                return Err(Error::new(ErrorKind::Other, "no anchor node"));
            }

            // whenever updating "avalanchego_config", we must persist locally
            // via spec file for next spec loads
            log::info!(
                "updating spec and avalanchego_config with bootstrap Ids '{:?}' and Ips '{:?}'",
                bootstrap_ids,
                bootstrap_ips
            );
            avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
            avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));

            let mut spec =
                avalanche_ops::aws::spec::Spec::load(&fetched_tags.avalancheup_spec_path)?;
            spec.avalanchego_config = avalanchego_config.clone();

            spec.sync(&fetched_tags.avalancheup_spec_path)?;
            spec.avalanchego_config.sync(None)?;
        }
    }

    //
    //
    //
    //
    //
    //
    //
    stop_and_restart_avalanche_systemd_service("/usr/local/bin/avalanchego", &avalanchego_config)
        .await?;

    //
    //
    //
    //
    //
    //
    //
    if metrics_fetch_interval_seconds > 0 {
        stop_and_restart_avalanche_telemetry_cloudwatch_systemd_service(
            &meta.region,
            "/usr/local/bin/avalanche-telemetry-cloudwatch",
            &fetched_tags.avalanche_telemetry_cloudwatch_rules_file_path,
            &fetched_tags.id,
            avalanchego_config.http_port,
            metrics_fetch_interval_seconds,
        )?;
    } else {
        log::info!("skipping avalanche-telemetry-cloudwatch setup since interval is 0");
    }

    //
    //
    //
    //
    //
    //
    //
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

    // do not use "public_ipv4" in case we limit http port access
    let ep = format!("{http_scheme}://localhost:{}", avalanchego_config.http_port);
    check_liveness(&ep).await?;

    let mut handles = Vec::new();

    // if we are using default config (e.g., CDK)
    // no need to publish the node readiness
    // TODO: implement this better if CDK polls node status
    if !opts.use_default_config {
        handles.push(tokio::spawn(publish_node_info_ready_loop(
            Arc::new(meta.region.clone()),
            Arc::new(meta.ec2_instance_id.clone()),
            fetched_tags.node_kind.clone(),
            Arc::new(node_id.to_string()),
            Arc::new(public_ipv4.clone()),
            Arc::new(fetched_tags.s3_region.clone()),
            Arc::new(fetched_tags.s3_bucket.clone()),
            Arc::new(fetched_tags.avalancheup_spec_path.clone()),
            Arc::new(proof_of_possession.clone()),
            opts.publish_periodic_node_info,
        )));
    }

    //
    //
    //
    //
    //
    //
    //
    // assume the tag value is static
    // assume we don't change on-demand to spot, or vice versa
    // if someone changes, tag needs to be updated manually and restart avalanched
    if fetched_tags.instance_mode == *"spot" {
        handles.push(tokio::spawn(monitor_spot_instance_action(
            Arc::new(meta.region.clone()),
            Arc::new(meta.ec2_instance_id.clone()),
            Arc::new(attached_volume_id.clone()),
        )));
    } else {
        log::info!("skipped monitoring the spot instance-action...");
    }

    // TODO: write notify file to notify it's done and do health check against it

    //
    //
    //
    //
    //
    //
    //
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
struct Tags {
    id: String,
    network_id: u32,
    arch_type: String,
    os_type: String,
    instance_mode: String,
    node_kind: node::Kind,
    kms_key_arn: String,
    aad_tag: String,
    s3_region: String,
    s3_bucket: String,
    cloudwatch_config_file_path: String,
    avalanche_telemetry_cloudwatch_rules_file_path: String,
    avalancheup_spec_path: String,
    avalanche_data_volume_path: String,
    avalanche_data_volume_ebs_device_name: String,
    eip_file_path: String,
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
            return avalanchego::config::Config::load(config_file);
        };
    }

    avalanchego_config.network_id = network_id;

    // always "only" overwrite public-ip flag in case of EC2 instance replacement
    avalanchego_config.public_ip = Some(public_ipv4.to_string());
    avalanchego_config.sync(None)?;

    Ok(avalanchego_config)
}

fn write_default_coreth_chain_config(
    chain_config_dir: &str,
) -> io::Result<coreth::chain_config::Config> {
    log::info!("STEP: writing default coreth chain config file...");

    fs::create_dir_all(Path::new(chain_config_dir).join("C"))?;

    let coreth_config = coreth::chain_config::Config::default();

    let chain_config_c_path = Path::new(chain_config_dir).join("C").join("config.json");
    if chain_config_c_path.exists() {
        log::info!("coreth C-chain config file '{}' already exists -- skipping writing/syncing one to avoid overwrites, loading existing one", chain_config_c_path.display());
        return coreth::chain_config::Config::load(
            chain_config_c_path.display().to_string().as_str(),
        );
    };

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    coreth_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved default coreth chain config file to {:?}",
        chain_config_c_path.as_os_str()
    );

    Ok(coreth_config)
}

fn write_coreth_chain_config_from_spec(spec: &avalanche_ops::aws::spec::Spec) -> io::Result<()> {
    log::info!("STEP: writing coreth chain config file from spec for the C-chain...");

    let chain_config_dir = spec.avalanchego_config.chain_config_dir.clone();
    fs::create_dir_all(Path::new(&chain_config_dir).join("C"))?;

    // If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
    // the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json.
    // ref. https://docs.avax.network/subnets/customize-a-subnet#chain-configs
    let chain_config_c_path = Path::new(&chain_config_dir).join("C").join("config.json");
    if chain_config_c_path.exists() {
        // overwrite, to always use S3 as a single source of truth
        log::info!(
            "C-chain config file '{}' already exists -- overwriting!",
            chain_config_c_path.display()
        );
    };

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    spec.coreth_chain_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &chain_config_c_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved coreth chain config file to {} for C-chain",
        chain_config_c_path.display()
    );

    Ok(())
}

fn create_config_dirs(
    avalanchego_config: &avalanchego::config::Config,
    coreth_chain_config: &coreth::chain_config::Config,
) -> io::Result<()> {
    log::info!("STEP: creating config directories...");

    log::info!("creating directory log-dir {}", avalanchego_config.log_dir);
    fs::create_dir_all(&avalanchego_config.log_dir)?;

    log::info!(
        "creating directory plugin-dir {}",
        avalanchego_config.plugin_dir
    );
    fs::create_dir_all(&avalanchego_config.plugin_dir)?;

    log::info!(
        "create_dir_all subnet-config-dir {}",
        avalanchego_config.subnet_config_dir
    );
    fs::create_dir_all(&avalanchego_config.subnet_config_dir)?;

    log::info!(
        "create_dir_all chain-config-dir {}",
        avalanchego_config.chain_config_dir
    );
    fs::create_dir_all(&avalanchego_config.chain_config_dir)?;

    if let Some(v) = &avalanchego_config.profile_dir {
        log::info!("creating directory profile-dir {}", v);
        fs::create_dir_all(v)?;
    }

    if let Some(v) = &coreth_chain_config.continuous_profiler_dir {
        log::info!("creating directory continuous-profiler-dir {}", v);
        fs::create_dir_all(v)?;
    }
    if let Some(v) = &coreth_chain_config.offline_pruning_data_directory {
        log::info!("creating directory offline-pruning-data-directory {}", v);
        fs::create_dir_all(v)?;
    }

    Ok(())
}

fn write_cloudwatch_config(
    id: &str,
    node_kind: node::Kind,
    log_auto_removal: bool,
    avalanche_logs_dir: &str,
    avalanche_data_volume_path: &str,
    cloudwatch_config_file_path: &str,
    metrics_fetch_interval_seconds: u32,
) -> io::Result<()> {
    log::info!("STEP: writing CloudWatch JSON config file...");

    let cw_config_manager = cloudwatch::ConfigManager {
        id: id.to_string(),
        node_kind,
        log_dir: avalanche_logs_dir.to_string(),
        instance_system_logs: true,
        data_volume_path: Some(avalanche_data_volume_path.to_string()),
        config_file_path: cloudwatch_config_file_path.to_string(),
    };
    cw_config_manager.sync(
        log_auto_removal,
        Some(vec![
            String::from("/var/log/cloud-init-output.log"),
            String::from("/var/log/avalanched-aws.log"),
            String::from("/var/log/avalanche-telemetry-cloudwatch.log"),
        ]),
        metrics_fetch_interval_seconds,
    )
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

    let spec = avalanche_ops::aws::spec::Spec::load(avalancheup_spec_path)?;

    // "initial_staked_funds" is reserved for locked P-chain balance
    // with "spec.generated_seed_private_key_with_locked_p_chain_balance"
    let seed_priv_keys = spec.clone().prefunded_keys.unwrap();
    let seed_priv_key = seed_priv_keys[0].clone();

    let mut initial_stakers: Vec<avalanchego_genesis::Staker> = vec![];
    for s3_key in bootstrapping_anchor_node_s3_keys.iter() {
        // just parse the s3 key name
        // to reduce "s3_manager.get_object" call volume
        let seed_anchor_node =
            avalanche_ops::aws::spec::StorageNamespace::parse_node_from_path(s3_key)?;

        let mut staker = avalanchego_genesis::Staker::default();
        staker.node_id = Some(seed_anchor_node.node_id.to_string());
        staker.reward_address = Some(
            seed_priv_key
                .addresses
                .get(&spec.avalanchego_config.network_id)
                .unwrap()
                .x
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

async fn stop_and_restart_avalanche_systemd_service(
    avalanche_bin_path: &str,
    avalanchego_config: &avalanchego::config::Config,
) -> io::Result<()> {
    log::info!("STEP: setting up and restarting Avalanche systemd service...");

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
    // wildcard all log files in "/var/log/avalanchego" (a lot of duplicates)
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
StandardOutput=append:/var/log/avalanchego/avalanchego.log
StandardError=append:/var/log/avalanchego/avalanchego.log

[Install]
WantedBy=multi-user.target",
        avalanche_bin_path,
        avalanchego_config.clone().config_file.unwrap(),
    );

    let mut service_file = tempfile::NamedTempFile::new()?;
    service_file.write_all(service_file_contents.as_bytes())?;

    let service_file_path = service_file.path().to_str().unwrap();
    fs::copy(service_file_path, "/etc/systemd/system/avalanchego.service")?;

    command_manager::run("sudo systemctl daemon-reload")?;

    // in case it's already running
    match command_manager::run("sudo systemctl stop avalanchego.service") {
        Ok(_) => log::info!("successfully stopped avalanchego.service"),
        Err(e) => log::warn!("failed to stop {}", e),
    };

    command_manager::run("sudo systemctl disable avalanchego.service")?;
    command_manager::run("sudo systemctl enable avalanchego.service")?;
    command_manager::run("sudo systemctl restart --no-block avalanchego.service")?;

    Ok(())
}

fn stop_and_restart_avalanche_telemetry_cloudwatch_systemd_service(
    region: &str,
    avalanche_telemetry_cloudwatch_bin_path: &str,
    avalanche_telemetry_cloudwatch_rules_file_path: &str,
    namespace: &str,
    http_port: u32,
    metrics_fetch_interval_seconds: u64,
) -> io::Result<()> {
    if metrics_fetch_interval_seconds == 0 {
        log::info!("skipping avalanche-telemetry-cloudwatch setup since interval is 0");
        return Ok(());
    };

    log::info!("STEP: setting up and starting avalanche-telemetry-cloudwatch systemd service with namespace {} and fetch interval seconds {}", namespace, metrics_fetch_interval_seconds);

    // don't use "Type=notify"
    // as "avalanchego" currently does not do anything specific to systemd
    // ref. "expected that the service sends a notification message via sd_notify"
    // ref. https://www.freedesktop.org/software/systemd/man/systemd.service.html
    //
    // NOTE: remove "StandardOutput" and "StandardError" since we already
    // wildcard all log files in "/var/log/avalanchego" (a lot of duplicates)
    let service_file_contents = format!(
        "[Unit]
Description=avalanche-telemetry-cloudwatch

[Service]
Type=exec
TimeoutStartSec=300
Restart=always
RestartSec=5s
LimitNOFILE=40000
ExecStart={avalanche_telemetry_cloudwatch_bin_path} --log-level=info --region={region} --initial-wait-seconds=10 --rules-file-path={avalanche_telemetry_cloudwatch_rules_file_path} --namespace={namespace} --rpc-endpoint=http://localhost:{http_port} --fetch-interval-seconds={metrics_fetch_interval_seconds}
StandardOutput=append:/var/log/avalanche-telemetry-cloudwatch.log
StandardError=append:/var/log/avalanche-telemetry-cloudwatch.log

[Install]
WantedBy=multi-user.target",
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
        match command_manager::run("sudo tail -10 /var/log/avalanchego/avalanchego.log") {
            Ok(out) => {
                println!(
                    "\n'/var/log/avalanchego/avalanchego.log' stdout:\n\n{}\n",
                    out.stdout
                );
                println!(
                    "'/var/log/avalanchego/avalanchego.log' stderr:\n\n{}\n",
                    out.stderr
                );
            }
            Err(e) => log::warn!(
                "failed to check /var/log/avalanchego/avalanchego.log: {}",
                e
            ),
        }

        println!();

        match command_manager::run("sudo journalctl -u avalanchego.service --lines=10 --no-pager") {
            Ok(out) => {
                println!("\n'avalanchego.service' stdout:\n\n{}\n", out.stdout);
                println!("'avalanchego.service' stderr:\n\n{}\n", out.stderr);
            }
            Err(e) => log::warn!("failed to check journalctl avalanchego.service: {}", e),
        }

        println!();

        let ret = client_health::spawn_check(ep, true).await;
        match ret {
            Ok(res) => {
                if res.healthy {
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
    local_region: Arc<String>,
    ec2_instance_id: Arc<String>,
    node_kind: node::Kind,
    node_id: Arc<String>,
    public_ipv4: Arc<String>,
    s3_region: Arc<String>,
    s3_bucket: Arc<String>,
    avalancheup_spec_path: Arc<String>,
    proof_of_possession: Arc<bls::ProofOfPossession>,
    publish_periodic_node_info: bool,
) {
    log::info!("STEP: publishing node info for its readiness...");

    let spec =
        avalanche_ops::aws::spec::Spec::load(&avalancheup_spec_path).expect("failed to load spec");

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
    let local_node = avalanche_ops::aws::spec::Node::new(
        local_region.to_string().as_str(),
        node_kind.clone(),
        &ec2_instance_id,
        &node_id,
        &public_ipv4,
        http_scheme,
        spec.avalanchego_config.http_port,
        proof_of_possession.public_key.clone(),
        proof_of_possession.proof_of_possession.clone(),
    );
    let node_info = avalanche_ops::aws::spec::NodeInfo::new(
        local_node.clone(),
        spec.avalanchego_config.clone(),
        spec.coreth_chain_config.clone(),
    );

    let node_info_path = random_manager::tmp_path(10, Some(".yaml")).unwrap();
    node_info.sync(&node_info_path).unwrap();

    let node_info_ready_s3_key = {
        if matches!(node_kind, node::Kind::Anchor) {
            avalanche_ops::aws::spec::StorageNamespace::DiscoverReadyAnchorNode(
                spec.id.clone(),
                local_node.clone(),
            )
            .encode()
        } else {
            avalanche_ops::aws::spec::StorageNamespace::DiscoverReadyNonAnchorNode(
                spec.id.clone(),
                local_node.clone(),
            )
            .encode()
        }
    };

    loop {
        let shared_config =
            aws_manager::load_config(Some(s3_region.to_string()), Some(Duration::from_secs(30)))
                .await;
        let s3_manager = s3::Manager::new(&shared_config);

        match s3_manager
            .put_object(&node_info_path, &s3_bucket, &node_info_ready_s3_key)
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
    local_region: Arc<String>,
    ec2_instance_id: Arc<String>,
    attached_volume_id: Arc<String>,
) {
    loop {
        log::info!(
            "checking spot instance action for {} with attached volume Id {}",
            ec2_instance_id,
            attached_volume_id
        );

        let shared_config = aws_manager::load_config(
            Some(local_region.to_string()),
            Some(Duration::from_secs(30)),
        )
        .await;
        let ec2_manager = ec2::Manager::new(&shared_config);
        let asg_manager = autoscaling::Manager::new(&shared_config);

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
                    log::warn!("setting the instance {} to 'Unhealthy'", ec2_instance_id);
                    match asg_manager
                        .set_instance_health(&ec2_instance_id, "Unhealthy")
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
                    match command_manager::run("sudo systemctl stop avalanchego.service") {
                        Ok(_) => log::info!("successfully stopped avalanche service"),
                        Err(e) => log::warn!("failed systemctl stop command {}", e),
                    }
                    match command_manager::run("sudo systemctl disable avalanchego.service") {
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
                    match ec2_manager
                        .cli
                        .detach_volume()
                        .instance_id(ec2_instance_id.clone().as_ref())
                        .volume_id(attached_volume_id.clone().as_ref())
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
                    match ec2_manager
                        .cli
                        .terminate_instances()
                        .instance_ids(ec2_instance_id.clone().as_ref())
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
