use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_s3::model::Object;
use clap::{Arg, Command};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use avalanche_ops::{
    self, avalanchego, aws, aws_cloudwatch, aws_ec2, aws_kms, aws_s3, bash, cert, compress,
    envelope, node, random,
};

const APP_NAME: &str = "avalanched-aws";
const SUBCOMMAND_RUN: &str = "run";
const SUBCOMMAND_UPLOAD_BACKUP: &str = "upload-backup";
const SUBCOMMAND_DOWNLOAD_BACKUP: &str = "download-backup";

// TODO: support download mainnet database from s3
fn create_run_command() -> Command<'static> {
    Command::new(SUBCOMMAND_RUN)
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

// TODO: make this periodic
fn create_upload_backup_command() -> Command<'static> {
    Command::new(SUBCOMMAND_UPLOAD_BACKUP)
        .about("Uploads the local data directory to remote storage")
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("ARCHIVE_COMPRESSION_METHOD")
                .long("archive-compression-method")
                .short('c')
                .help("Sets the archive and compression method")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .possible_value(compress::DirEncoder::ZipZstd(1).id())
                .possible_value(compress::DirEncoder::ZipZstd(2).id())
                .possible_value(compress::DirEncoder::ZipZstd(3).id())
                .possible_value(compress::DirEncoder::TarZstd(1).id())
                .possible_value(compress::DirEncoder::TarZstd(2).id())
                .possible_value(compress::DirEncoder::TarZstd(3).id())
                .possible_value(compress::DirEncoder::ZipGzip.id())
                .possible_value(compress::DirEncoder::TarGzip.id())
                .default_value(compress::DirEncoder::TarGzip.id()),
        )
        .arg(
            Arg::new("PACK_DIR")
                .long("pack-dir")
                .short('p')
                .help("Sets the source directory path to compress/archive")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .short('b')
                .help("Sets the S3 bucket name to upload to")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_KEY")
                .long("s3-key")
                .short('k')
                .help("Sets the S3 key name for uploading")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

fn create_download_backup_command() -> Command<'static> {
    Command::new(SUBCOMMAND_DOWNLOAD_BACKUP)
        .about("Downloads compressed/archived backup file from remote storage")
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("UNARCHIVE_DECOMPRESSION_METHOD")
                .long("unarchive-decompression-method")
                .short('c')
                .help("Sets the decompression and unarchive method")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .possible_value(compress::DirDecoder::ZipZstd.id())
                .possible_value(compress::DirDecoder::TarZstd.id())
                .possible_value(compress::DirDecoder::ZipGzip.id())
                .possible_value(compress::DirDecoder::TarGzip.id())
                .default_value(compress::DirDecoder::TarGzip.id()),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .short('b')
                .help("Sets the S3 bucket name to upload to")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("S3_KEY")
                .long("s3-key")
                .short('k')
                .help("Sets the S3 key name for uploading")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("UNPACK_DIR")
                .long("unpack-dir")
                .short('u')
                .help("Sets the destition db directory path to unpack")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not change node ID)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("Avalanche agent (daemon) on AWS")
        .subcommands(vec![
            create_run_command(),
            create_upload_backup_command(),
            create_download_backup_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_RUN, sub_matches)) => {
            execute_run(sub_matches.value_of("LOG_LEVEL").unwrap_or("info")).unwrap();
        }

        Some((SUBCOMMAND_UPLOAD_BACKUP, sub_matches)) => {
            execute_upload_backup(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("ARCHIVE_COMPRESSION_METHOD").unwrap(),
                sub_matches.value_of("PACK_DIR").unwrap(),
                sub_matches.value_of("S3_BUCKET").unwrap(),
                sub_matches.value_of("S3_KEY").unwrap(),
            )
            .unwrap();
        }

        Some((SUBCOMMAND_DOWNLOAD_BACKUP, sub_matches)) => {
            execute_download_backup(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches
                    .value_of("UNARCHIVE_DECOMPRESSION_METHOD")
                    .unwrap(),
                sub_matches.value_of("S3_BUCKET").unwrap(),
                sub_matches.value_of("S3_KEY").unwrap(),
                sub_matches.value_of("UNPACK_DIR").unwrap(),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

fn execute_run(log_level: &str) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let rt = Runtime::new().unwrap();

    thread::sleep(Duration::from_secs(1));
    info!("STEP: fetching intance metadata using IMDSv2");

    let az = rt.block_on(aws_ec2::fetch_availability_zone()).unwrap();
    info!("fetched availability zone {}", az);

    let reg = rt.block_on(aws_ec2::fetch_region()).unwrap();
    info!("fetched region {}", reg);

    let instance_id = rt.block_on(aws_ec2::fetch_instance_id()).unwrap();
    info!("fetched instance ID {}", instance_id);

    let public_ipv4 = rt.block_on(aws_ec2::fetch_public_ipv4()).unwrap();
    info!("fetched public ipv4 {}", public_ipv4);

    thread::sleep(Duration::from_secs(1));
    info!("STEP: loading AWS config");
    let shared_config = rt.block_on(aws::load_config(Some(reg.clone()))).unwrap();

    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let s3_manager = aws_s3::Manager::new(&shared_config);

    thread::sleep(Duration::from_secs(1));
    info!("STEP: fetching tags from the local instance");
    let tags = rt.block_on(ec2_manager.fetch_tags(&instance_id)).unwrap();
    let mut id: String = String::new();
    let mut node_kind: String = String::new();
    let mut kms_cmk_arn: String = String::new();
    let mut s3_bucket_name: String = String::new();
    let mut cloudwatch_config_file_path: String = String::new();
    let mut avalanche_bin: String = String::new();
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
                node_kind = v.to_string();
            }
            "KMS_CMK_ARN" => {
                kms_cmk_arn = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                s3_bucket_name = v.to_string();
            }
            "CLOUDWATCH_CONFIG_FILE_PATH" => {
                cloudwatch_config_file_path = v.to_string();
            }
            "AVALANCHE_BIN" => {
                avalanche_bin = v.to_string();
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
    if node_kind.is_empty() {
        panic!("'NODE_KIND' tag not found")
    }
    if kms_cmk_arn.is_empty() {
        panic!("'KMS_CMK_ARN' tag not found")
    }
    if s3_bucket_name.is_empty() {
        panic!("'S3_BUCKET_NAME' tag not found")
    }
    if cloudwatch_config_file_path.is_empty() {
        panic!("'CLOUDWATCH_CONFIG_FILE_PATH' tag not found")
    }
    if avalanche_bin.is_empty() {
        panic!("'AVALANCHE_BIN' tag not found")
    }
    if avalanche_data_volume_path.is_empty() {
        panic!("'AVALANCHE_DATA_VOLUME_PATH' tag not found")
    }

    let envelope = envelope::Envelope::new(Some(kms_manager), Some(kms_cmk_arn));

    if !Path::new(&avalanche_bin).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading avalanche binary from S3");
        let tmp_avalanche_bin_compressed_path = random::tmp_path(15, Some(".zstd")).unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::AvalancheBinCompressed(id.clone()).encode(),
            &tmp_avalanche_bin_compressed_path,
        ))
        .unwrap();
        compress::unpack_file(
            &tmp_avalanche_bin_compressed_path,
            &avalanche_bin,
            compress::Decoder::Zstd,
        )
        .unwrap();
        let f = File::open(&avalanche_bin).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o777)).unwrap();
    }

    let plugins_dir = get_plugins_dir(&avalanche_bin);
    if !Path::new(&plugins_dir).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading plugins from S3");
        fs::create_dir_all(plugins_dir.clone()).unwrap();
        let objects = rt
            .block_on(s3_manager.list_objects(
                &s3_bucket_name,
                Some(aws_s3::append_slash(
                    &aws_s3::KeyPath::PluginsDir(id.clone()).encode(),
                )),
            ))
            .unwrap();
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let file_name = extract_filename(s3_key);
            let file_path = format!("{}/{}", plugins_dir, file_name);

            let tmp_path = random::tmp_path(15, None).unwrap();
            rt.block_on(s3_manager.get_object(&s3_bucket_name, s3_key, &tmp_path))
                .unwrap();
            compress::unpack_file(&tmp_path, &file_path, compress::Decoder::Zstd).unwrap();
            let f = File::open(file_path).unwrap();
            f.set_permissions(PermissionsExt::from_mode(0o777)).unwrap();
        }
    }

    // ref. https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-Configuration-File-Details.html
    // TODO: add more logs for plugins
    thread::sleep(Duration::from_secs(1));
    info!("STEP: writing CloudWatch configuration JSON file");
    let mut cloudwatch_config = aws_cloudwatch::Config::default();
    cloudwatch_config.logs = Some(aws_cloudwatch::Logs {
        force_flush_interval: Some(60),
        logs_collected: Some(aws_cloudwatch::LogsCollected {
            files: Some(aws_cloudwatch::Files {
                collect_list: Some(vec![
                    aws_cloudwatch::Collect {
                        log_group_name: id.clone(),
                        log_stream_name: format!("avalanched-{}-{}", node_kind, instance_id),
                        file_path: String::from("/var/log/avalanched/avalanched.log"),
                        timestamp_format: None,
                        timezone: None,
                        auto_removal: None,
                    },
                    aws_cloudwatch::Collect {
                        log_group_name: id.clone(),
                        log_stream_name: format!("avalanche-{}-{}", node_kind, instance_id),
                        file_path: String::from("/var/log/avalanche/avalanche.log"),
                        timestamp_format: None,
                        timezone: None,
                        auto_removal: None,
                    },
                ]),
            }),
        }),
    });
    let mut cw_metrics = aws_cloudwatch::Metrics {
        namespace: id.clone(),
        ..Default::default()
    };
    cw_metrics.metrics_collected.disk =
        Some(aws_cloudwatch::Disk::new(vec![avalanche_data_volume_path]));
    cloudwatch_config.metrics = Some(cw_metrics);
    cloudwatch_config
        .sync(&cloudwatch_config_file_path)
        .unwrap();

    thread::sleep(Duration::from_secs(1));
    info!("STEP: downloading avalanche-ops::Spec from S3");
    let tmp_spec_file_path = random::tmp_path(15, Some(".yaml")).unwrap();
    rt.block_on(s3_manager.get_object(
        &s3_bucket_name,
        &aws_s3::KeyPath::ConfigFile(id.clone()).encode(),
        &tmp_spec_file_path,
    ))
    .unwrap();

    let mut spec = avalanche_ops::Spec::load(&tmp_spec_file_path).unwrap();
    spec.avalanchego_config.public_ip = Some(public_ipv4.clone());
    spec.avalanchego_config.sync(None).unwrap();

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

    // TODO: reuse TLS certs for static node IDs
    let tls_cert_exists = Path::new(&tls_cert_path).exists();
    if !tls_key_exists || !tls_cert_exists {
        thread::sleep(Duration::from_secs(1));
        info!(
            "STEP: generating TLS certs (key exists {}, cert exists {})",
            tls_key_exists, tls_cert_exists
        );
        cert::generate(&tls_key_path, &tls_cert_path).unwrap();

        info!("uploading generated TLS certs to S3");
        let tmp_compressed_path = random::tmp_path(15, Some(".zstd")).unwrap();
        compress::pack_file(
            &tls_key_path,
            &tmp_compressed_path,
            compress::Encoder::Zstd(3),
        )
        .unwrap();

        let tmp_encrypted_path = random::tmp_path(15, Some(".zstd.encrypted")).unwrap();
        rt.block_on(envelope.seal_aes_256_file(&tmp_compressed_path, &tmp_encrypted_path))
            .unwrap();

        rt.block_on(
            s3_manager.put_object(
                &tmp_encrypted_path,
                &s3_bucket_name,
                format!(
                    "{}/{}.key.zstd.seal_aes_256.encrypted",
                    aws_s3::KeyPath::PkiKeyDir(id.clone()).encode(),
                    instance_id
                )
                .as_str(),
            ),
        )
        .unwrap();
    }
    let node_id = node::load_id(&tls_cert_path).unwrap();
    info!("loaded node ID from cert: {}", node_id);

    if spec.aws_resources.is_some() {
        let aws_resources = spec.aws_resources.unwrap();
        if aws_resources.db_backup_s3_region.is_some()
            && aws_resources.db_backup_s3_bucket.is_some()
            && aws_resources.db_backup_s3_key.is_some()
        {
            thread::sleep(Duration::from_secs(1));
            let db_backup_s3_region = aws_resources.db_backup_s3_region.clone().unwrap();
            let db_backup_s3_bucket = aws_resources.db_backup_s3_bucket.clone().unwrap();
            let db_backup_s3_key = aws_resources.db_backup_s3_key.unwrap();
            let dec = compress::DirDecoder::new_from_file_name(&db_backup_s3_key).unwrap();
            info!(
                "STEP: downloading database backup file 's3://{}/{}' [{}] in region {}",
                db_backup_s3_bucket,
                db_backup_s3_key,
                dec.id(),
                db_backup_s3_region,
            );

            let db_backup_s3_config = rt
                .block_on(aws::load_config(Some(db_backup_s3_region)))
                .unwrap();
            let db_backup_s3_manager = aws_s3::Manager::new(&db_backup_s3_config);

            let download_path = random::tmp_path(15, Some(dec.ext())).unwrap();
            rt.block_on(db_backup_s3_manager.get_object(
                &db_backup_s3_bucket,
                &db_backup_s3_key,
                &download_path,
            ))
            .unwrap();

            compress::unpack_directory(&download_path, &spec.avalanchego_config.db_dir, dec)
                .unwrap();

            // TODO: override network id to support network fork
        } else {
            info!("STEP: db_backup_s3_bucket is empty, skipping database backup download from S3")
        }
    }

    if spec.avalanchego_config.is_custom_network()
        && node_kind.eq("beacon")
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: publishing seed/bootstrapping beacon node information for discovery");
        let node = node::Node::new(node::Kind::Beacon, &instance_id, &node_id, &public_ipv4);
        let s3_key = aws_s3::KeyPath::DiscoverBootstrappingBeaconNode(id.clone(), node.clone());
        let s3_key = s3_key.encode();
        let node_info = NodeInformation {
            node,
            avalanchego_config: spec.avalanchego_config.clone(),
        };
        let tmp_path = random::tmp_path(10, Some(".yaml")).unwrap();
        node_info.sync(tmp_path.clone()).unwrap();
        rt.block_on(s3_manager.put_object(&tmp_path, &s3_bucket_name, &s3_key))
            .unwrap();

        thread::sleep(Duration::from_secs(30));
        info!("STEP: waiting for all seed/bootstrapping beacon nodes to be ready");
        let target_nodes = spec.machine.beacon_nodes.unwrap();
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(20));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &s3_bucket_name,
                    Some(aws_s3::append_slash(
                        &aws_s3::KeyPath::DiscoverBootstrappingBeaconNodesDir(id.clone()).encode(),
                    )),
                ))
                .unwrap();
            info!(
                "{} seed/bootstrapping beacon nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        thread::sleep(Duration::from_secs(1));
        info!("STEP: collect all seed/bootstrapping beacon nodes information from S3 key for initial stakers");
        let mut stakers: Vec<avalanchego::Staker> = vec![];
        let seed_priv_keys = spec.generated_seed_private_keys.unwrap();
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();

            // just parse the s3 key name
            // to reduce "s3_manager.get_object" call volume
            let seed_beacon_node = aws_s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();

            let mut staker = avalanchego::Staker::default();
            staker.node_id = Some(seed_beacon_node.id);
            staker.reward_address = Some(seed_priv_keys[0].x_address.clone());

            stakers.push(staker);
        }
        info!(
            "found {} seed beacon nodes for initial stakers",
            stakers.len()
        );

        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading genesis draft file from S3");
        let tmp_genesis_path = random::tmp_path(15, Some(".json")).unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::GenesisDraftFile(spec.id.clone()).encode(),
            &tmp_genesis_path,
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(1));
        let genesis_path = spec.avalanchego_config.clone().genesis.unwrap();
        info!(
            "STEP: updating genesis draft file and writing to a new genesis file to '{}'",
            genesis_path
        );
        let mut genesis_draft = avalanchego::Genesis::load(&tmp_genesis_path).unwrap();
        genesis_draft.initial_stakers = Some(stakers);
        genesis_draft.sync(&genesis_path).unwrap();

        // for now, just overwrite from every seed beacon node
        thread::sleep(Duration::from_secs(1));
        info!("STEP: upload the new genesis file, to be shared with beacon/non-beacon nodes");
        rt.block_on(s3_manager.put_object(
            &genesis_path,
            &s3_bucket_name,
            &aws_s3::KeyPath::GenesisFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    if spec.avalanchego_config.is_custom_network()
        && node_kind.eq("non-beacon")
        && spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading genesis file from S3");
        let tmp_genesis_path = random::tmp_path(15, Some(".json")).unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::GenesisFile(spec.id.clone()).encode(),
            &tmp_genesis_path,
        ))
        .unwrap();
        fs::copy(
            &tmp_genesis_path,
            spec.avalanchego_config.clone().genesis.unwrap(),
        )
        .unwrap();
    }

    // validate after downloading genesis file
    spec.avalanchego_config.validate().unwrap();
    if spec.avalanchego_config.config_file.is_none() {
        panic!("'spec.avalanchego_config.config_file' not found")
    }

    // mainnet/other pre-defined test nets have hard-coded beacon nodes
    // thus no need for beacon nodes
    if spec.avalanchego_config.is_custom_network() && node_kind.eq("non-beacon") {
        thread::sleep(Duration::from_secs(1));
        info!(
            "STEP: downloading beacon node information for network '{}'",
            spec.avalanchego_config.network_id,
        );

        // "avalanche-ops" should always set up beacon nodes first
        // so here we assume beacon nodes are already set up
        // and their information is already available via shared,
        // remote storage for service discovery
        // so that we block non-beacon nodes until beacon nodes are ready
        //
        // always send a new "list_objects" on remote storage
        // rather than relying on potentially stale (not via "spec")
        // in case the member lists for "beacon" nodes becomes stale
        // (e.g., machine replacement in "beacon" nodes ASG)
        //
        // TODO: handle stale beacon nodes by heartbeats timestamps
        let target_nodes = spec.machine.beacon_nodes.unwrap();
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(20));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &s3_bucket_name,
                    Some(aws_s3::append_slash(
                        &aws_s3::KeyPath::DiscoverReadyBeaconNodesDir(id.clone()).encode(),
                    )),
                ))
                .unwrap();
            info!(
                "{} beacon nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        thread::sleep(Duration::from_secs(1));
        info!("STEP: collect all beacon nodes IDs and IPs from S3 key for bootstrap information");
        let mut bootstrap_ips: Vec<String> = vec![];
        let mut bootstrap_ids: Vec<String> = vec![];
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();

            // just parse the s3 key name
            // to reduce "s3_manager.get_object" call volume
            let beacon_node = aws_s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();

            // assume all nodes in the network use the same ports
            // ref. "avalanchego/config.StakingPortKey" default value is "9651"
            let staking_port = spec
                .avalanchego_config
                .staking_port
                .unwrap_or(avalanchego::DEFAULT_STAKING_PORT);

            bootstrap_ips.push(format!("{}:{}", beacon_node.ip, staking_port));
            bootstrap_ids.push(beacon_node.id);
        }
        info!("found {} bootstrap nodes", bootstrap_ids.len());

        spec.avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));
        spec.avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
    }

    // persist before starting the service
    spec.avalanchego_config.sync(None).unwrap();

    thread::sleep(Duration::from_secs(1));
    info!(
        "STEP: setting up avalanche node systemd service file with --config-file={}",
        spec.avalanchego_config.clone().config_file.unwrap()
    );
    // don't use "Type=notify"
    // as "avalanchego" currently does not do anything specific to systemd
    // ref. "expected that the service sends a notification message via sd_notify"
    // ref. https://www.freedesktop.org/software/systemd/man/systemd.service.html
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
        avalanche_bin,
        spec.avalanchego_config.clone().config_file.unwrap(),
    );
    let mut avalanche_service_file = tempfile::NamedTempFile::new().unwrap();
    avalanche_service_file
        .write_all(avalanche_service_file_contents.as_bytes())
        .unwrap();
    let avalanche_service_file_path = avalanche_service_file.path().to_str().unwrap();
    fs::copy(
        avalanche_service_file_path,
        "/etc/systemd/system/avalanche.service",
    )
    .unwrap();
    bash::run("sudo systemctl daemon-reload").unwrap();
    bash::run("sudo systemctl disable avalanche.service").unwrap();
    bash::run("sudo systemctl enable avalanche.service").unwrap();
    bash::run("sudo systemctl start --no-block avalanche.service").unwrap();

    info!("'avalanched run' all success -- now waiting for local node liveness check");
    loop {
        thread::sleep(Duration::from_secs(10));
        let ret = rt.block_on(avalanchego::check_health_liveness(
            format!(
                "http://{}:{}",
                public_ipv4,
                spec.avalanchego_config.http_port.unwrap()
            )
            .as_str(),
        ));
        let (res, err) = match ret {
            Ok(res) => (res, None),
            Err(e) => (
                avalanchego::APIHealthReply {
                    checks: None,
                    healthy: Some(false),
                },
                Some(e),
            ),
        };
        if res.healthy.is_some() && res.healthy.unwrap() {
            info!("health/liveness check success for {}", instance_id);
            break;
        }
        warn!(
            "health/liveness check failed for {} ({:?}, {:?})",
            instance_id, res, err
        );
    }

    // TODO: check upgrade artifacts by polling s3 /events directory
    // e.g., we can update avalanche node software
    info!("avalanched now periodically publishing node information...");
    loop {
        // to be downloaded in bootstrapping non-beacon nodes
        if spec.avalanchego_config.is_custom_network() && node_kind.eq("beacon") {
            thread::sleep(Duration::from_secs(1));
            info!("STEP: publishing beacon node information");
            let node = node::Node::new(node::Kind::Beacon, &instance_id, &node_id, &public_ipv4);
            let s3_key = aws_s3::KeyPath::DiscoverReadyBeaconNode(id.clone(), node.clone());
            let s3_key = s3_key.encode();
            let node_info = NodeInformation {
                node,
                avalanchego_config: spec.avalanchego_config.clone(),
            };
            let tmp_path = random::tmp_path(10, Some(".yaml")).unwrap();
            node_info.sync(tmp_path.clone()).unwrap();
            rt.block_on(s3_manager.put_object(&tmp_path, &s3_bucket_name, &s3_key))
                .unwrap();
        }

        if node_kind.eq("non-beacon") {
            thread::sleep(Duration::from_secs(1));
            info!("STEP: publishing non-beacon node information");
            let node = node::Node::new(node::Kind::NonBeacon, &instance_id, &node_id, &public_ipv4);
            let s3_key = aws_s3::KeyPath::DiscoverReadyNonBeaconNode(id.clone(), node.clone());
            let s3_key = s3_key.encode();
            let node_info = NodeInformation {
                node,
                avalanchego_config: spec.avalanchego_config.clone(),
            };
            let tmp_path = random::tmp_path(10, Some(".yaml")).unwrap();
            node_info.sync(tmp_path.clone()).unwrap();
            rt.block_on(s3_manager.put_object(&tmp_path, &s3_bucket_name, &s3_key))
                .unwrap();
        }

        // e.g., "--pack-dir /avalanche-data/network-9999/v1.4.5"
        println!("/usr/local/bin/avalanched upload-backup --region {} --archive-compression-method {} --pack-dir {} --s3-bucket {} --s3-key {}/backup{}", 
            reg.clone(),
            compress::DirEncoder::TarGzip.id(),
            spec.avalanchego_config.db_dir.clone(),
            &s3_bucket_name,
            aws_s3::KeyPath::BackupsDir(id.clone()).encode(),
            compress::DirEncoder::TarGzip.ext(),
        );
        println!("/usr/local/bin/avalanched download-backup --region {} --unarchive-decompression-method {} --s3-bucket {} --s3-key {}/backup{} --unpack-dir {}",
            reg,
            compress::DirDecoder::TarGzip.id(),
            &s3_bucket_name,
            aws_s3::KeyPath::BackupsDir(id.clone()).encode(),
            compress::DirDecoder::TarGzip.ext(),
            spec.avalanchego_config.db_dir.clone(),
        );
        thread::sleep(Duration::from_secs(60));
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct NodeInformation {
    pub node: node::Node,
    pub avalanchego_config: avalanchego::Config,
}

impl NodeInformation {
    pub fn sync(&self, file_path: String) -> io::Result<()> {
        info!("syncing NodeInformation to '{}'", file_path);
        let path = Path::new(&file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_json::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize NodeInformation to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(&file_path)?;
        f.write_all(&d)?;

        Ok(())
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

fn execute_upload_backup(
    reg: &str,
    log_level: &str,
    archive_compression_method: &str,
    pack_dir: &str,
    s3_bucket: &str,
    s3_key: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let rt = Runtime::new().unwrap();

    // let reg = rt.block_on(aws_ec2::fetch_region()).unwrap();
    // info!("fetched region {}", reg);
    // let instance_id = rt.block_on(aws_ec2::fetch_instance_id()).unwrap();
    // info!("fetched instance ID {}", instance_id);

    info!("STEP: loading AWS config");
    let shared_config = rt
        .block_on(aws::load_config(Some(reg.to_string())))
        .unwrap();
    let s3_manager = aws_s3::Manager::new(&shared_config);

    let enc = compress::DirEncoder::new(archive_compression_method)?;
    info!("STEP: backup {} with {}", pack_dir, enc.to_string());
    let output_path = random::tmp_path(10, Some(enc.ext())).unwrap();
    compress::pack_directory(pack_dir, &output_path, enc)?;

    info!("STEP: upload output {} to S3", output_path);
    rt.block_on(s3_manager.put_object(&output_path, s3_bucket, s3_key))
        .unwrap();

    info!("'avalanched upload-backup' all success!");
    Ok(())
}

fn execute_download_backup(
    reg: &str,
    log_level: &str,
    decompression_unarchive_method: &str,
    s3_bucket: &str,
    s3_key: &str,
    unpack_dir: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let rt = Runtime::new().unwrap();

    // let reg = rt.block_on(aws_ec2::fetch_region()).unwrap();
    // info!("fetched region {}", reg);
    // let instance_id = rt.block_on(aws_ec2::fetch_instance_id()).unwrap();
    // info!("fetched instance ID {}", instance_id);

    info!("STEP: loading AWS config");
    let shared_config = rt
        .block_on(aws::load_config(Some(reg.to_string())))
        .unwrap();
    let s3_manager = aws_s3::Manager::new(&shared_config);

    let dec = compress::DirDecoder::new(decompression_unarchive_method)?;
    let output_path = random::tmp_path(10, Some(dec.ext())).unwrap();
    info!(
        "STEP: downloading from S3 {} {} to {}",
        s3_bucket, s3_key, output_path
    );
    rt.block_on(s3_manager.get_object(s3_bucket, s3_key, &output_path))
        .unwrap();

    info!(
        "STEP: unpack backup {} to {} with {}",
        output_path,
        unpack_dir,
        dec.to_string()
    );
    compress::unpack_directory(&output_path, unpack_dir, dec)?;

    info!("'avalanched download-backup' all success!");
    Ok(())
}
