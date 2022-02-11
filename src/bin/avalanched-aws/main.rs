use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_s3::model::Object;
use clap::{App, Arg};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{
    self, avalanchego, aws, aws_cloudwatch, aws_ec2, aws_kms, aws_s3, bash, cert, compress, id,
    random,
};

const APP_NAME: &str = "avalanched-aws";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not change node ID)
fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche agent (daemon) on AWS")
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
            Arg::new("AVALANCHE_BIN")
                .long("avalanche-bin")
                .short('b')
                .help("Sets the Avalanche node binary path to locate the downloaded file")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("CLOUDWATCH_CONFIG_FILE_PATH")
                .long("cloudwatch-config-file-path")
                .short('c')
                .help("Sets CloudWatch configuration JSON file path to output")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    let log_level = matches.value_of("LOG_LEVEL").unwrap_or("info");
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
    let shared_config = rt.block_on(aws::load_config(Some(reg))).unwrap();

    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let s3_manager = aws_s3::Manager::new(&shared_config);

    thread::sleep(Duration::from_secs(1));
    info!("STEP: fetching tags from the local instance");
    let tags = rt.block_on(ec2_manager.fetch_tags(&instance_id)).unwrap();
    let mut id: String = String::new();
    let mut node_type: String = String::new();
    let mut kms_cmk_arn: String = String::new();
    let mut s3_bucket_name: String = String::new();
    for c in tags {
        let k = c.key().unwrap();
        let v = c.value().unwrap();
        info!("tag key='{}', value='{}'", k, v);
        match k {
            "ID" => {
                id = v.to_string();
            }
            "NODE_TYPE" => {
                node_type = v.to_string();
            }
            "KMS_CMK_ARN" => {
                kms_cmk_arn = v.to_string();
            }
            "S3_BUCKET_NAME" => {
                s3_bucket_name = v.to_string();
            }
            _ => {}
        }
    }
    if id.is_empty() {
        panic!("'ID' tag not found")
    }
    if node_type.is_empty() {
        panic!("'NODE_TYPE' tag not found")
    }
    if kms_cmk_arn.is_empty() {
        panic!("'KMS_CMK_ARN' tag not found")
    }
    if s3_bucket_name.is_empty() {
        panic!("'S3_BUCKET_NAME' tag not found")
    }

    thread::sleep(Duration::from_secs(1));
    info!("STEP: writing CloudWatch configuration JSON file");
    let cloudwatch_config_file_path = matches
        .value_of("CLOUDWATCH_CONFIG_FILE_PATH")
        .unwrap_or(aws_cloudwatch::DEFAULT_CONFIG_FILE_PATH);
    let mut cloudwatch_config = aws_cloudwatch::Config::default();
    cloudwatch_config.logs = Some(aws_cloudwatch::Logs {
        log_stream_name: id.clone(),
        force_flush_interval: Some(60),
        logs_collected: Some(aws_cloudwatch::LogsCollected {
            files: Some(aws_cloudwatch::Files {
                collect_list: Some(vec![
                    aws_cloudwatch::Collect {
                        log_group_name: format!("avalanched-{}-{}", node_type, instance_id),
                        file_path: String::from("/var/log/avalanched/avalanched.log"),
                        timestamp_format: None,
                        timezone: None,
                        auto_removal: None,
                    },
                    aws_cloudwatch::Collect {
                        log_group_name: format!("avalanche-{}-{}", node_type, instance_id),
                        file_path: String::from("/var/log/avalanche/avalanche.log"),
                        timestamp_format: None,
                        timezone: None,
                        auto_removal: None,
                    },
                ]),
            }),
        }),
    });
    cloudwatch_config.sync(cloudwatch_config_file_path).unwrap();

    thread::sleep(Duration::from_secs(1));
    info!("STEP: downloading network Config from S3");
    let tmp_spec_file_path = random::tmp_path(15).unwrap();
    rt.block_on(s3_manager.get_object(
        &s3_bucket_name,
        &aws_s3::KeyPath::ConfigFile.to_string(&id),
        &tmp_spec_file_path,
    ))
    .unwrap();
    let mut spec = avalanche_ops::load_spec(&tmp_spec_file_path).unwrap();

    if spec.avalanchego_config.genesis.is_some()
        && !Path::new(&spec.avalanchego_config.clone().genesis.unwrap()).exists()
    {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading genesis file from S3");
        let tmp_genesis_path = random::tmp_path(15).unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::GenesisFile.to_string(&spec.id),
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
        thread::sleep(Duration::from_secs(1));
        info!(
            "STEP: generating TLS certs (key exists {}, cert exists {})",
            tls_key_exists, tls_cert_exists
        );
        cert::generate(&tls_key_path, &tls_cert_path).unwrap();

        info!("uploading generated TLS certs to S3");
        let tmp_compressed_path = random::tmp_path(15).unwrap();
        compress::to_zstd(&tls_key_path, &tmp_compressed_path, None).unwrap();

        let tmp_encrypted_path = random::tmp_path(15).unwrap();
        rt.block_on(kms_manager.seal_aes_256_file(
            &kms_cmk_arn,
            &tmp_compressed_path,
            &tmp_encrypted_path,
        ))
        .unwrap();

        rt.block_on(
            s3_manager.put_object(
                &s3_bucket_name,
                &tmp_encrypted_path,
                format!(
                    "{}/{}.key.zstd.seal_aes_256.encrypted",
                    aws_s3::KeyPath::PkiKeyDir.to_string(&id),
                    instance_id
                )
                .as_str(),
            ),
        )
        .unwrap();
    }
    let node_id = id::load_node_id(&tls_cert_path).unwrap();
    info!("loaded node ID from cert: {}", node_id);

    let avalanche_bin = matches.value_of("AVALANCHE_BIN").unwrap();
    if !Path::new(avalanche_bin).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading avalanche binary from S3");
        let tmp_avalanche_bin_compressed_path = random::tmp_path(15).unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::AvalancheBinCompressed.to_string(&id),
            &tmp_avalanche_bin_compressed_path,
        ))
        .unwrap();
        compress::from_zstd(&tmp_avalanche_bin_compressed_path, avalanche_bin).unwrap();
        let f = File::open(avalanche_bin).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o777)).unwrap();
    }

    let plugins_dir = get_plugins_dir(avalanche_bin);
    if !Path::new(&plugins_dir).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading plugins from S3");
        fs::create_dir_all(plugins_dir.clone()).unwrap();
        let objects = rt
            .block_on(s3_manager.list_objects(
                &s3_bucket_name,
                Some(aws_s3::KeyPath::PluginsDir.to_string(&id)),
            ))
            .unwrap();
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let file_name = extract_filename(s3_key);
            let file_path = format!("{}/{}", plugins_dir, file_name);

            let tmp_path = random::tmp_path(15).unwrap();
            rt.block_on(s3_manager.get_object(&s3_bucket_name, s3_key, &tmp_path))
                .unwrap();
            compress::from_zstd(&tmp_path, &file_path).unwrap();
            let f = File::open(file_path).unwrap();
            f.set_permissions(PermissionsExt::from_mode(0o777)).unwrap();
        }
    }

    thread::sleep(Duration::from_secs(1));
    info!("STEP: setting up avalanche node service file");

    // mainnet/other pre-defined test nets have hard-coded beacon nodes
    // thus no need for beacon nodes
    if !spec.avalanchego_config.is_mainnet() && node_type.eq("non-beacon") {
        thread::sleep(Duration::from_secs(1));
        info!(
            "STEP: downloading beacon node information for network '{}'",
            spec.avalanchego_config.network_id.unwrap_or(0),
        );

        // "avalanche-ops" should always set up beacon nodes first
        // so here we assume beacon nodes information are already
        // updated in the remote storage
        let target_nodes = spec.machine.beacon_nodes.unwrap();
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(20));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &s3_bucket_name,
                    Some(aws_s3::KeyPath::BeaconNodesDir.to_string(&id)),
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

        let mut bootstrap_ips: Vec<String> = vec![];
        let mut bootstrap_ids: Vec<String> = vec![];
        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let tmp_path = random::tmp_path(15).unwrap();
            rt.block_on(s3_manager.get_object(&s3_bucket_name, s3_key, &tmp_path))
                .unwrap();

            // ref. "avalanchego/config.StakingPortKey" default value is "9651"
            let staking_port = spec
                .avalanchego_config
                .staking_port
                .unwrap_or(avalanchego::DEFAULT_STAKING_PORT);
            let beacon_node = avalanche_ops::load_beacon_node(&tmp_path).unwrap();
            bootstrap_ips.push(format!("{}:{}", beacon_node.ip, staking_port));
            bootstrap_ids.push(beacon_node.id);
        }
        info!("found {} bootstrap nodes", objects.len());

        spec.avalanchego_config.bootstrap_ips = Some(bootstrap_ips.join(","));
        spec.avalanchego_config.bootstrap_ids = Some(bootstrap_ids.join(","));
    }

    // persist before starting the service
    spec.avalanchego_config.sync(None).unwrap();

    info!("writing avalanche.service file");
    let avalanche_service_file_contents = format!(
        "[Unit]
Description=avalanche node

[Service]
Type=notify
Restart=always
RestartSec=5s
LimitNOFILE=40000
ExecStart={} --config-file={}
StandardOutput=file:/var/log/avalanche/avalanche.log
StandardError=file:/var/log/avalanche/avalanche.log

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

    loop {
        // TODO: periodically upload beacon/non-beacon information to S3 as health check?
        // TODO: check upgrade artifacts by polling s3
        thread::sleep(Duration::from_secs(20));

        if node_type.eq("beacon") {
            thread::sleep(Duration::from_secs(1));
            info!("STEP: publishing beacon node information");
            let beacon_node = avalanche_ops::BeaconNode::new(public_ipv4.clone(), node_id.clone());
            let tmp_beacon_node_path = random::tmp_path(15).unwrap();
            beacon_node.sync(&tmp_beacon_node_path).unwrap();
            rt.block_on(
                s3_manager.put_object(
                    &s3_bucket_name,
                    &tmp_beacon_node_path,
                    format!(
                        "{}/{}.yaml",
                        aws_s3::KeyPath::BeaconNodesDir.to_string(&id),
                        instance_id
                    )
                    .as_str(),
                ),
            )
            .unwrap();
        }

        if node_type.eq("non-beacon") {
            thread::sleep(Duration::from_secs(1));
            info!("STEP: publishing non-beacon node information");
            rt.block_on(
                s3_manager.put_object(
                    &s3_bucket_name,
                    &spec.avalanchego_config.clone().config_file.unwrap(),
                    format!(
                        "{}/{}.json",
                        aws_s3::KeyPath::NonBeaconNodesDir.to_string(&id),
                        instance_id
                    )
                    .as_str(),
                ),
            )
            .unwrap();
        }
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
