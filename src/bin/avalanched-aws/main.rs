use std::{fs, io::Write, path::Path, thread, time::Duration};

use clap::{App, Arg};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{aws, aws_ec2, aws_kms, aws_s3, bash, cert, compress, id, network, random};

const APP_NAME: &str = "avalanched-aws";

const GENESIS_PATH: &str = "/etc/genesis.json";

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
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("AWS region")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_KEY_PATH")
                .long("tls-key-path")
                .short('k')
                .help("TLS key path to save the generated key")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("TLS_CERT_PATH")
                .long("tls-cert-path")
                .short('c')
                .help("TLS cert path to save the generated cert")
                .required(true)
                .takes_value(true)
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
    let region = matches.value_of("REGION").unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(region.to_string())))
        .unwrap();
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
    info!("STEP: generating TLS certs");
    let tls_key_path = matches.value_of("TLS_KEY_PATH").unwrap();
    let tls_cert_path = matches.value_of("TLS_CERT_PATH").unwrap();
    if !Path::new(tls_key_path).exists() {
        info!(
            "TLS key path {} does not exist yet, generating one",
            tls_key_path
        );
        cert::generate(tls_key_path, tls_cert_path).unwrap();

        info!("uploading TLS certs to S3");
        let tmpf_compressed = tempfile::NamedTempFile::new().unwrap();
        let tmpf_compressed_path = tmpf_compressed.path().to_str().unwrap();
        compress::to_zstd(tls_key_path, tmpf_compressed_path, None).unwrap();

        let tmpf_encrypted = tempfile::NamedTempFile::new().unwrap();
        let tmpf_encrypted_path = tmpf_encrypted.path().to_str().unwrap();
        rt.block_on(kms_manager.encrypt_file(
            &kms_cmk_arn,
            None,
            tmpf_compressed_path,
            tmpf_encrypted_path,
        ))
        .unwrap();

        rt.block_on(
            s3_manager.put_object(
                &s3_bucket_name,
                tmpf_encrypted_path,
                format!(
                    "{}/{}.key.zstd.encrypted",
                    aws_s3::KeyPath::PkiKeyDir.to_string(&id),
                    instance_id
                )
                .as_str(),
            ),
        )
        .unwrap();
    }
    let node_id = id::load_node_id(tls_cert_path).unwrap();
    info!("loaded node ID: {}", node_id);

    thread::sleep(Duration::from_secs(1));
    info!("STEP: downloading network Config from S3");
    let tmp_dir = tempfile::tempdir().unwrap();
    let tmp_config_path = tmp_dir.path().join(random::string(10));
    let tmp_config_path = tmp_config_path.as_os_str().to_str().unwrap();
    rt.block_on(s3_manager.get_object(
        &s3_bucket_name,
        &aws_s3::KeyPath::ConfigFile.to_string(&id),
        tmp_config_path,
    ))
    .unwrap();
    let config = network::load_config(tmp_config_path).unwrap();

    let avalanche_bin = matches.value_of("AVALANCHE_BIN").unwrap();
    if !Path::new(avalanche_bin).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading avalanche binary from S3");
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_avalanche_bin_compressed_path = tmp_dir.path().join(random::string(10));
        let tmp_avalanche_bin_compressed_path = tmp_avalanche_bin_compressed_path
            .as_os_str()
            .to_str()
            .unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::AvalancheBinCompressed.to_string(&id),
            tmp_avalanche_bin_compressed_path,
        ))
        .unwrap();
        compress::from_zstd(tmp_avalanche_bin_compressed_path, avalanche_bin).unwrap();
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

            let tmpf = tempfile::NamedTempFile::new().unwrap();
            let tmpf_path = tmpf.path().to_str().unwrap();
            rt.block_on(s3_manager.get_object(&s3_bucket_name, s3_key, tmpf_path))
                .unwrap();
            compress::from_zstd(tmpf_path, &file_path).unwrap();
        }
    }

    if !Path::new(GENESIS_PATH).exists() {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading genesis file from S3");
        let tmpf_genesis = tempfile::NamedTempFile::new().unwrap();
        let tmpf_genesis_path = tmpf_genesis.path().to_str().unwrap();
        rt.block_on(s3_manager.get_object(
            &s3_bucket_name,
            &aws_s3::KeyPath::GenesisFile.to_string(&config.id),
            tmpf_genesis_path,
        ))
        .unwrap();
        fs::copy(tmpf_genesis_path, GENESIS_PATH).unwrap();
    }

    // TODO: set up "--db-dir" based on "df -h"
    thread::sleep(Duration::from_secs(1));
    info!("STEP: setting up avalanche node service file");
    let mut avalanche_node_cmd = format!(
        "{} --network-id={} --genesis={}, --public-ip={}",
        avalanche_bin,
        config.network_id,
        GENESIS_PATH,
        public_ipv4.as_str(),
    );
    avalanche_node_cmd.push_str(
        format!(
            " --staking-enabled=true --staking-tls-key-file={} --staking-tls-cert-file={}",
            tls_key_path, tls_cert_path
        )
        .as_str(),
    );
    if config.snow_sample_size.is_some() {
        let snow_sample_size = config.snow_sample_size.unwrap();
        avalanche_node_cmd.push_str(format!(" --snow-sample-size={}", snow_sample_size).as_str());
    }
    if config.snow_quorum_size.is_some() {
        let snow_quorum_size = config.snow_quorum_size.unwrap();
        avalanche_node_cmd.push_str(format!(" --snow-quorum-size={}", snow_quorum_size).as_str());
    }
    if config.http_port.is_some() {
        let http_port = config.http_port.unwrap();
        avalanche_node_cmd.push_str(format!(" --http-port={}", http_port).as_str());
    }
    if config.staking_port.is_some() {
        let staking_port = config.staking_port.unwrap();
        avalanche_node_cmd.push_str(format!(" --staking-port={}", staking_port).as_str());
    }
    if node_type.eq("non-beacon") {
        thread::sleep(Duration::from_secs(1));
        info!("STEP: downloading beacon node information");
        let objects = rt
            .block_on(s3_manager.list_objects(
                &s3_bucket_name,
                Some(aws_s3::KeyPath::BeaconNodesDir.to_string(&id)),
            ))
            .unwrap();
        if !objects.is_empty() {
            let mut bootstrap_ips: Vec<String> = vec![];
            let mut bootstrap_ids: Vec<String> = vec![];
            for obj in objects.iter() {
                let s3_key = obj.key().unwrap();
                let tmpf = tempfile::NamedTempFile::new().unwrap();
                let tmpf_path = tmpf.path().to_str().unwrap();
                rt.block_on(s3_manager.get_object(&s3_bucket_name, s3_key, tmpf_path))
                    .unwrap();

                let beacon_node = network::load_beacon_node(tmpf_path).unwrap();
                bootstrap_ips.push(beacon_node.ip);
                bootstrap_ids.push(beacon_node.id);
            }
            info!("adding {} bootstrap nodes to the flag", objects.len());
            avalanche_node_cmd
                .push_str(format!(" --bootstrap-ips={}", bootstrap_ips.join(",")).as_str());
            avalanche_node_cmd
                .push_str(format!(" --bootstrap-ids={}", bootstrap_ids.join(",")).as_str());
        }
    }
    let avalanche_service_file_contents = format!(
        "[Unit]
Description=avalanche agent
[Service]
Type=notify
Restart=always
RestartSec=5s
LimitNOFILE=40000
ExecStart={}
[Install]
WantedBy=multi-user.target",
        avalanche_node_cmd
    );
    println!("writing\n\n{}\n", avalanche_service_file_contents);
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
    bash::run("sudo systemctl enable avalanche.service").unwrap();
    bash::run("sudo systemctl restart avalanche.service").unwrap();

    loop {
        // TODO: periodically upload beacon/non-beacon information to S3 as health check?
        // TODO: check upgrade artifacts by polling s3
        thread::sleep(Duration::from_secs(10));

        if node_type.eq("beacon") {
            // only upload when all nodes are ready
            thread::sleep(Duration::from_secs(1));
            info!("STEP: publishing beacon node information");
            let beacon_node = network::BeaconNode::new(public_ipv4.clone(), node_id.clone());
            let tmpf_beacon_node = tempfile::NamedTempFile::new().unwrap();
            let tmpf_beacon_node_path = tmpf_beacon_node.path().to_str().unwrap();
            beacon_node.sync(tmpf_beacon_node_path).unwrap();
            rt.block_on(
                s3_manager.put_object(
                    &s3_bucket_name,
                    tmpf_beacon_node_path,
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
