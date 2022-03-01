use std::{
    fs::{self, File},
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::Duration,
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use aws_sdk_s3::model::Object;
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::{info, warn};
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

use avalanche_ops::{
    self, avalanchego,
    aws::{self, cloudformation, cloudwatch, ec2, envelope, kms, s3, sts},
    constants, node,
    utils::{compress, random},
};

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_SPEC: &str = "default-spec";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

fn create_default_spec_command() -> Command<'static> {
    Command::new(SUBCOMMAND_DEFAULT_SPEC)
        .about("Writes a default configuration")
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
            Arg::new("DB_BACKUP_S3_REGION") 
                .long("db-backup-s3-region")
                .help("Sets S3 region for database backup download")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DB_BACKUP_S3_BUCKET") 
                .long("db-backup-s3-bucket")
                .help("Sets S3 bucket for database backup download")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DB_BACKUP_S3_KEY") 
                .long("db-backup-s3-key")
                .help("Sets S3 key for database backup download")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHED_BIN") 
                .long("install-artifacts-avalanched-bin")
                .help("Sets the Avalanched binary path in the local machine to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_BIN") 
                .long("install-artifacts-avalanche-bin")
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGINS_DIR") 
                .long("install-artifacts-plugins-dir")
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_CORETH_EVM_CONFIG_FILE_PATH") 
                .long("install-artifacts-coreth-evm-config-file-path")
                .help("Sets coreth EVM config file path (ref. https://pkg.go.dev/github.com/ava-labs/coreth/plugin/evm#Config)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("NETWORK_NAME") 
                .long("network-name")
                .help("Sets the type of network by name (e.g., mainnet, fuji, custom)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("custom"),
        )
        .arg(
            Arg::new("KEYS_TO_GENERATE") 
                .long("keys-to-generate")
                .help("Sets the number of keys to generate")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("5"), // ref. "avalanche_ops::DEFAULT_KEYS_TO_GENERATE"
        )
        .arg(
            Arg::new("AVALANCHEGO_LOG_LEVEL") 
                .long("avalanchego-log-level")
                .help("Sets log-level for avalanchego")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value(avalanchego::DEFAULT_LOG_LEVEL),
        )
        .arg(
            Arg::new("AVALANCHEGO_HTTP_TLS_ENABLED") 
                .long("avalanchego-http-tls-enabled")
                .help("Sets to enable HTTP TLS")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

fn create_apply_command() -> Command<'static> {
    Command::new(SUBCOMMAND_APPLY)
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

fn create_delete_command() -> Command<'static> {
    Command::new(SUBCOMMAND_DELETE)
        .about("Deletes resources based on configuration")
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
                .help("The spec file to load")
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
        .arg(
            Arg::new("DELETE_CLOUDWATCH_LOG_GROUP")
                .long("delete-cloudwatch-log-group")
                .help("Enables to delete CloudWatch log group")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DELETE_S3_OBJECTS")
                .long("delete-s3-objects")
                .help("Enables to delete S3 objects")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("DELETE_S3_BUCKET")
                .long("delete-s3-bucket")
                .help("Enables delete S3 bucket (use with caution!)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .subcommands(vec![
            create_default_spec_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_SPEC, sub_matches)) => {
            let keys_to_generate = sub_matches.value_of("KEYS_TO_GENERATE").unwrap_or("");
            let keys_to_generate = keys_to_generate.parse::<usize>().unwrap();
            let opt = DefaultSpecOption {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                region: sub_matches.value_of("REGION").unwrap().to_string(),
                db_backup_s3_region: sub_matches
                    .value_of("DB_BACKUP_S3_REGION")
                    .unwrap_or("")
                    .to_string(),
                db_backup_s3_bucket: sub_matches
                    .value_of("DB_BACKUP_S3_BUCKET")
                    .unwrap_or("")
                    .to_string(),
                db_backup_s3_key: sub_matches
                    .value_of("DB_BACKUP_S3_KEY")
                    .unwrap_or("")
                    .to_string(),
                install_artifacts_avalanched_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHED_BIN")
                    .unwrap()
                    .to_string(),
                install_artifacts_avalanche_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                    .unwrap()
                    .to_string(),
                install_artifacts_plugins_dir: sub_matches
                    .value_of("INSTALL_ARTIFACTS_PLUGINS_DIR")
                    .unwrap_or("")
                    .to_string(),
                install_artifacts_coreth_evm_config_file_path: sub_matches
                    .value_of("INSTALL_ARTIFACTS_CORETH_EVM_CONFIG_FILE_PATH")
                    .unwrap_or("")
                    .to_string(),
                network_name: sub_matches
                    .value_of("NETWORK_NAME")
                    .unwrap_or("")
                    .to_string(),
                keys_to_generate,
                avalanchego_log_level: sub_matches
                    .value_of("AVALANCHEGO_LOG_LEVEL")
                    .unwrap()
                    .to_string(),
                avalanchego_http_tls_enabled: sub_matches
                    .is_present("AVALANCHEGO_HTTP_TLS_ENABLED"),
                spec_file_path: sub_matches.value_of("SPEC_FILE_PATH").unwrap().to_string(),
            };
            execute_default_spec(opt).unwrap();
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            execute_apply(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            execute_delete(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("DELETE_CLOUDWATCH_LOG_GROUP"),
                sub_matches.is_present("DELETE_S3_OBJECTS"),
                sub_matches.is_present("DELETE_S3_BUCKET"),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

struct DefaultSpecOption {
    log_level: String,
    region: String,
    db_backup_s3_region: String,
    db_backup_s3_bucket: String,
    db_backup_s3_key: String,
    install_artifacts_avalanched_bin: String,
    install_artifacts_avalanche_bin: String,
    install_artifacts_plugins_dir: String,
    install_artifacts_coreth_evm_config_file_path: String,
    network_name: String,
    keys_to_generate: usize,
    avalanchego_log_level: String,
    avalanchego_http_tls_enabled: bool,
    spec_file_path: String,
}

fn execute_default_spec(opt: DefaultSpecOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    let _install_artifacts_plugins_dir = {
        if opt.install_artifacts_plugins_dir.is_empty() {
            None
        } else {
            Some(opt.install_artifacts_plugins_dir.clone())
        }
    };
    let _install_artifacts_coreth_evm_config_file_path = {
        if opt.install_artifacts_coreth_evm_config_file_path.is_empty() {
            None
        } else {
            Some(opt.install_artifacts_coreth_evm_config_file_path.clone())
        }
    };

    let network_id = match constants::NETWORK_NAME_TO_NETWORK_ID.get(opt.network_name.as_str()) {
        Some(v) => *v,
        None => avalanchego::DEFAULT_CUSTOM_NETWORK_ID,
    };
    let mut avalanchego_config = avalanchego::Config::default();
    avalanchego_config.network_id = network_id;
    avalanchego_config.log_level = Some(opt.avalanchego_log_level);
    if !avalanchego_config.is_custom_network() {
        avalanchego_config.genesis = None;
    }
    // only set values if non empty
    // otherwise, avalanchego will fail with "couldn't load node config: read .: is a directory"
    if opt.avalanchego_http_tls_enabled {
        // TODO: use different certs than staking?
        avalanchego_config.http_tls_enabled = Some(true);
        avalanchego_config.http_tls_key_file = avalanchego_config.staking_tls_key_file.clone();
        avalanchego_config.http_tls_cert_file = avalanchego_config.staking_tls_cert_file.clone();
    }

    let mut spec = avalanche_ops::Spec::default_aws(
        opt.region.as_str(),
        opt.install_artifacts_avalanched_bin.as_str(),
        opt.install_artifacts_avalanche_bin.as_str(),
        _install_artifacts_plugins_dir,
        _install_artifacts_coreth_evm_config_file_path,
        avalanchego_config,
        opt.keys_to_generate,
    );

    let mut aws_resources = spec.aws_resources.unwrap();
    if !opt.db_backup_s3_region.is_empty() {
        aws_resources.db_backup_s3_region = Some(opt.db_backup_s3_region);
    }
    if !opt.db_backup_s3_bucket.is_empty() {
        aws_resources.db_backup_s3_bucket = Some(opt.db_backup_s3_bucket);
    }
    if !opt.db_backup_s3_key.is_empty() {
        aws_resources.db_backup_s3_key = Some(opt.db_backup_s3_key);
    }
    spec.aws_resources = Some(aws_resources);

    spec.validate()?;
    spec.sync(&opt.spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", opt.spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    Ok(())
}

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

fn execute_apply(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    #[derive(RustEmbed)]
    #[folder = "cloudformation/avalanche-node/"]
    #[prefix = "cloudformation/avalanche-node/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = avalanche_ops::Spec::load(spec_file_path).unwrap();
    spec.validate()?;

    let rt = Runtime::new().unwrap();

    let mut aws_resources = spec.aws_resources.clone().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

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
            Some(avalanche_ops::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc =
            Some(avalanche_ops::StackName::Vpc(spec.id.clone()).encode());
    }
    if spec.avalanchego_config.is_custom_network()
        && aws_resources.cloudformation_asg_beacon_nodes.is_none()
    {
        aws_resources.cloudformation_asg_beacon_nodes =
            Some(avalanche_ops::StackName::AsgBeaconNodes(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_asg_non_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_non_beacon_nodes =
            Some(avalanche_ops::StackName::AsgNonBeaconNodes(spec.id.clone()).encode());
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
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("creating resources (with spec path {})", spec_file_path);
    let s3_manager = s3::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);

    thread::sleep(Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 buckets\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.create_bucket(&aws_resources.s3_bucket))
        .unwrap();
    if aws_resources.db_backup_s3_bucket.is_some() {
        rt.block_on(s3_manager.create_bucket(&aws_resources.db_backup_s3_bucket.clone().unwrap()))
            .unwrap();
    }

    thread::sleep(Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: upload artifacts to S3 bucket\n"),
        ResetColor
    )?;

    // don't compress since we need to download this in user data
    // while instance bootstrapping
    rt.block_on(s3_manager.put_object(
        &spec.install_artifacts.avalanched_bin,
        &aws_resources.s3_bucket,
        &s3::KeyPath::AvalanchedBin(spec.id.clone()).encode(),
    ))
    .unwrap();

    // compress as these will be decompressed by "avalanched"
    let tmp_avalanche_bin_compressed_path =
        random::tmp_path(15, Some(compress::Encoder::Zstd(3).ext())).unwrap();
    compress::pack_file(
        &spec.install_artifacts.avalanchego_bin,
        &tmp_avalanche_bin_compressed_path,
        compress::Encoder::Zstd(3),
    )
    .unwrap();
    rt.block_on(s3_manager.put_object(
        &tmp_avalanche_bin_compressed_path,
        &aws_resources.s3_bucket,
        &s3::KeyPath::AvalancheBinCompressed(spec.id.clone()).encode(),
    ))
    .unwrap();
    if spec.install_artifacts.plugins_dir.is_some() {
        let plugins_dir = spec.install_artifacts.plugins_dir.clone().unwrap();
        for entry in fs::read_dir(plugins_dir.as_str()).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            let tmp_plugin_compressed_path =
                random::tmp_path(15, Some(compress::Encoder::Zstd(3).ext())).unwrap();
            compress::pack_file(
                file_path,
                &tmp_plugin_compressed_path,
                compress::Encoder::Zstd(3),
            )
            .unwrap();

            info!(
                "uploading {} (compressed from {}) from plugins directory {}",
                tmp_plugin_compressed_path, file_path, plugins_dir,
            );
            rt.block_on(
                s3_manager.put_object(
                    &tmp_plugin_compressed_path,
                    &aws_resources.s3_bucket,
                    format!(
                        "{}/{}{}",
                        &s3::KeyPath::PluginsDir(spec.id.clone()).encode(),
                        file_name,
                        compress::Encoder::Zstd(3).ext()
                    )
                    .as_str(),
                ),
            )
            .unwrap();
        }
    }
    if spec.install_artifacts.genesis_draft_file_path.is_some() {
        let genesis_draft_file_path = spec
            .install_artifacts
            .genesis_draft_file_path
            .clone()
            .unwrap();
        if Path::new(&genesis_draft_file_path).exists() {
            rt.block_on(s3_manager.put_object(
                &genesis_draft_file_path,
                &aws_resources.s3_bucket,
                &s3::KeyPath::GenesisDraftFile(spec.id.clone()).encode(),
            ))
            .unwrap();
        }
    }
    if spec.install_artifacts.coreth_evm_config_file_path.is_some() {
        let coreth_evm_config_file_path = spec
            .install_artifacts
            .coreth_evm_config_file_path
            .clone()
            .unwrap();
        if Path::new(&coreth_evm_config_file_path).exists() {
            rt.block_on(s3_manager.put_object(
                &coreth_evm_config_file_path,
                &aws_resources.s3_bucket,
                &s3::KeyPath::CorethEvmConfigFile(spec.id.clone()).encode(),
            ))
            .unwrap();
        }
    }
    rt.block_on(s3_manager.put_object(
        spec_file_path,
        &aws_resources.s3_bucket,
        &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
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

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }
    let envelope = envelope::Envelope::new(Some(kms_manager), aws_resources.kms_cmk_id.clone());

    if aws_resources.ec2_key_path.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )
        .unwrap();
        let ec2_key_path = get_ec2_key_path(spec_file_path);
        rt.block_on(ec2_manager.create_key_pair(
            aws_resources.ec2_key_name.clone().unwrap().as_str(),
            ec2_key_path.as_str(),
        ))
        .unwrap();

        let tmp_compressed_path =
            random::tmp_path(15, Some(compress::Encoder::Zstd(3).ext())).unwrap();
        compress::pack_file(
            ec2_key_path.as_str(),
            &tmp_compressed_path,
            compress::Encoder::Zstd(3),
        )
        .unwrap();

        let tmp_encrypted_path = random::tmp_path(15, Some(".zstd.encrypted")).unwrap();
        rt.block_on(envelope.seal_aes_256_file(&tmp_compressed_path, &tmp_encrypted_path))
            .unwrap();
        rt.block_on(s3_manager.put_object(
            &tmp_encrypted_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::Ec2AccessKeyCompressedEncrypted(spec.id.clone()).encode(),
        ))
        .unwrap();

        aws_resources.ec2_key_path = Some(ec2_key_path);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_yaml =
            Asset::get("cloudformation/avalanche-node/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        let mut role_params = Vec::from([
            build_param("Id", &spec.id),
            build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
            build_param("S3BucketName", &aws_resources.s3_bucket),
        ]);
        if aws_resources.db_backup_s3_bucket.is_some() {
            let param = build_param(
                "S3BucketDbBackupName",
                &aws_resources.db_backup_s3_bucket.clone().unwrap(),
            );
            role_params.push(param);
        }
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
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("InstanceProfileArn") {
                aws_resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_none()
        && aws_resources.cloudformation_vpc_security_group_id.is_none()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cloudformation/avalanche-node/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();

        let mut parameters = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("IngressIpv4Range", "0.0.0.0/0"),
        ]);
        if spec.avalanchego_config.http_port.is_some() {
            let http_port = spec.avalanchego_config.http_port.unwrap();
            let param = build_param("HttpPort", format!("{}", http_port).as_str());
            parameters.push(param);
        }
        if spec.avalanchego_config.staking_port.is_some() {
            let staking_port = spec.avalanchego_config.staking_port.unwrap();
            let param = build_param("StakingPort", format!("{}", staking_port).as_str());
            parameters.push(param);
        }
        rt.block_on(cloudformation_manager.create_stack(
            vpc_stack_name.as_str(),
            None,
            OnFailure::Delete,
            vpc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
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
                    info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                aws_resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
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
            "PublicSubnetIds",
            &aws_resources
                .cloudformation_vpc_public_subnet_ids
                .clone()
                .unwrap()
                .join(","),
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
    ]);
    // mainnet/* requires higher volume size
    // TODO: make this configurable
    if spec.avalanchego_config.is_mainnet() {
        let param = build_param("VolumeSize", "800");
        asg_parameters.push(param);
    } else if !spec.avalanchego_config.is_custom_network() {
        let param = build_param("VolumeSize", "400");
        asg_parameters.push(param);
    }
    if spec.avalanchego_config.http_port.is_some() {
        let http_port = spec.avalanchego_config.http_port.unwrap();
        let param = build_param("NlbHttpPort", format!("{}", http_port).as_str());
        asg_parameters.push(param);
    }
    if spec.machine.instance_types.is_some() {
        let instance_types = spec.machine.instance_types.clone().unwrap();
        asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
        asg_parameters.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    let mut all_nodes: Vec<node::Node> = Vec::new();
    if spec.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for beacon nodes\n"),
            ResetColor
        )?;

        // TODO: support other platforms
        let cloudformation_asg_beacon_nodes_yaml =
            Asset::get("cloudformation/avalanche-node/asg_amd64_ubuntu.yaml").unwrap();
        let cloudformation_asg_beacon_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_beacon_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_beacon_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.beacon_nodes.unwrap();

        // must deep-copy as shared with other node kind
        let mut parameters = asg_parameters.clone();
        parameters.push(build_param("NodeKind", "beacon"));
        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_beacon_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_beacon_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        // add 5-minute for ELB creation
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_beacon_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_beacon_nodes_logical_id = Some(v);
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
            .cloudformation_asg_beacon_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_beacon_nodes_logical_id not found",
            ));
        }
        if aws_resources.cloudformation_asg_nlb_arn.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_arn not found",
            ));
        }
        if aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
            ));
        }
        if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_nlb_dns_name not found",
            ));
        }

        let asg_name = aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .clone()
            .unwrap();
        let droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!("\nchmod 400 {}", ec2_key_path);
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            println!(
                "# instance '{}' ({}, {})\nssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}\naws ssm start-session --region {} --target {}",
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ec2_key_path,
                d.public_ipv4,
                aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        // wait for beacon nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let target_nodes = spec.machine.beacon_nodes.unwrap();
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &aws_resources.s3_bucket,
                    Some(s3::append_slash(
                        &s3::KeyPath::DiscoverReadyBeaconNodesDir(spec.id.clone()).encode(),
                    )),
                ))
                .unwrap();
            info!(
                "{} beacon nodes are bootstrapped and ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let beacon_node = s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();
            all_nodes.push(beacon_node.clone());
        }

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id.clone()).encode(),
        ))
        .unwrap();

        info!("waiting for beacon nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_none()
    {
        thread::sleep(Duration::from_secs(5));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG for non-beacon nodes\n"),
            ResetColor
        )?;

        let cloudformation_asg_non_beacon_nodes_yaml =
            Asset::get("cloudformation/avalanche-node/asg_amd64_ubuntu.yaml").unwrap();
        let cloudformation_asg_non_beacon_nodes_tmpl =
            std::str::from_utf8(cloudformation_asg_non_beacon_nodes_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_non_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_non_beacon_nodes
            .clone()
            .unwrap();

        let desired_capacity = spec.machine.non_beacon_nodes;

        // we don't create beacon nodes for mainnet nodes
        // so no nlb creation before
        // we create here for non-beacon nodes
        let need_to_create_nlb = aws_resources
            .cloudformation_asg_nlb_target_group_arn
            .is_none();

        // must deep-copy as shared with other node kind
        let mut parameters = asg_parameters.clone();
        parameters.push(build_param("NodeKind", "non-beacon"));
        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));
        if !need_to_create_nlb {
            // already created for beacon nodes
            parameters.push(build_param(
                "NlbTargetGroupArn",
                &aws_resources
                    .cloudformation_asg_nlb_target_group_arn
                    .clone()
                    .unwrap(),
            ));
        }

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_non_beacon_nodes_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_non_beacon_nodes_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("avalanche-ops").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_non_beacon_nodes_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_non_beacon_nodes_logical_id = Some(v);
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
            .cloudformation_asg_non_beacon_nodes_logical_id
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_non_beacon_nodes_logical_id not found",
            ));
        }
        if need_to_create_nlb {
            if aws_resources.cloudformation_asg_nlb_arn.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_arn not found",
                ));
            }
            if aws_resources
                .cloudformation_asg_nlb_target_group_arn
                .is_none()
            {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_target_group_arn not found",
                ));
            }
            if aws_resources.cloudformation_asg_nlb_dns_name.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "aws_resources.cloudformation_asg_nlb_dns_name not found",
                ));
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        let asg_name = aws_resources
            .cloudformation_asg_non_beacon_nodes_logical_id
            .clone()
            .unwrap();
        let droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();

        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();
        println!("\nchmod 400 {}", ec2_key_path);
        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            println!(
                "# instance '{}' ({}, {})\nssh -o \"StrictHostKeyChecking no\" -i {} ubuntu@{}\naws ssm start-session --region {} --target {}",
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                ec2_key_path,
                d.public_ipv4,
                aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        // TODO: if downloading mainnet db, it will take a while
        // TODO: better handle this
        println!();
        let require_db_download = aws_resources.db_backup_s3_bucket.is_some();
        if require_db_download {
            spec.aws_resources = Some(aws_resources);
            spec.sync(spec_file_path)?;
            warn!(
                "non-beacon nodes are downloading db backups, can take awhile, check back later..."
            );
            return Ok(());
        }

        // wait for non-beacon nodes to generate certs and node ID and post to remote storage
        // TODO: set timeouts
        let target_nodes = spec.machine.non_beacon_nodes;
        let mut objects: Vec<Object>;
        loop {
            thread::sleep(Duration::from_secs(30));
            objects = rt
                .block_on(s3_manager.list_objects(
                    &aws_resources.s3_bucket,
                    Some(s3::append_slash(
                        &s3::KeyPath::DiscoverReadyNonBeaconNodesDir(spec.id.clone()).encode(),
                    )),
                ))
                .unwrap();
            info!(
                "{} non-beacon nodes are ready (expecting {} nodes)",
                objects.len(),
                target_nodes
            );
            if objects.len() as u32 >= target_nodes {
                break;
            }
        }

        for obj in objects.iter() {
            let s3_key = obj.key().unwrap();
            let non_beacon_node = s3::KeyPath::parse_node_from_s3_path(s3_key).unwrap();
            all_nodes.push(non_beacon_node.clone());
        }

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            spec_file_path,
            &aws_resources.s3_bucket,
            &s3::KeyPath::ConfigFile(spec.id).encode(),
        ))
        .unwrap();

        info!("waiting for non-beacon nodes bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: listing all nodes based on S3 keys...\n"),
        ResetColor
    )?;
    for node in all_nodes.iter() {
        println!("{}", node.encode_yaml().unwrap());
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: nodes are ready -- check the following endpoints!\n"),
        ResetColor
    )?;
    let dns_name = aws_resources.cloudformation_asg_nlb_dns_name.unwrap();
    let http_port = spec
        .avalanchego_config
        .http_port
        .unwrap_or(avalanchego::DEFAULT_HTTP_PORT);

    let https_enabled = spec.avalanchego_config.http_tls_enabled.is_some()
        && spec.avalanchego_config.http_tls_enabled.unwrap();
    let scheme = {
        if https_enabled {
            "https"
        } else {
            "http"
        }
    };
    // TODO: not working if https... associate ACM certs to NLB
    println!("{}://{}:{}/ext/metrics", scheme, dns_name, http_port);
    println!("{}://{}:{}/ext/health", scheme, dns_name, http_port);
    println!(
        "{}://{}:{}/ext/health/liveness",
        scheme, dns_name, http_port
    );
    let mut uris: Vec<String> = vec![];
    for node in all_nodes.iter() {
        let mut success = false;
        for _ in 0..10_u8 {
            let ret = rt.block_on(avalanchego::check_health(
                format!("{}://{}:{}", scheme, node.ip, http_port).as_str(),
                true,
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
            success = res.healthy.is_some() && res.healthy.unwrap();
            if success {
                info!("health/liveness check success for {}", node.machine_id);
                break;
            }
            warn!(
                "health/liveness check failed for {} ({:?}, {:?})",
                node.machine_id, res, err
            );
            if aws_resources.db_backup_s3_bucket.is_some() {
                // TODO: fix this
                warn!("node may be still downloading database backup... skipping for now...");
                success = true;
                break;
            }
            thread::sleep(Duration::from_secs(10));
        }
        if !success {
            warn!(
                "health/liveness check failed for network id {}",
                &spec.avalanchego_config.network_id
            );
            return Err(Error::new(ErrorKind::Other, "health/liveness check failed"));
        }

        println!("{}://{}:{}/ext/metrics", scheme, node.ip, http_port);
        println!("{}://{}:{}/ext/health", scheme, node.ip, http_port);
        println!("{}://{}:{}/ext/health/liveness", scheme, node.ip, http_port);
        uris.push(format!("{}://{}:{}", scheme, node.ip, http_port))
    }
    println!("\nURIs: {}", uris.join(","));

    println!();
    info!("apply all success!");
    println!();
    println!("# run the following to delete resources");
    println!(
        "avalanche-ops-nodes-aws delete --spec-file-path {}",
        spec_file_path
    );
    Ok(())
}

fn execute_delete(
    log_level: &str,
    spec_file_path: &str,
    delete_cloudwatch_log_group: bool,
    delete_s3_objects: bool,
    delete_s3_bucket: bool,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = avalanche_ops::Spec::load(spec_file_path).unwrap();
    let aws_resources = spec.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
    match aws_resources.identity {
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
            return Err(Error::new(ErrorKind::Other, "unknown identity"));
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded configuration: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    if !skip_prompt {
        let options = &[
            "No, I am not ready to delete resources!",
            "Yes, let's delete resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("deleting resources...");
    let s3_manager = s3::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    // delete this first since EC2 key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    if aws_resources.ec2_key_name.is_some() && aws_resources.ec2_key_path.is_some() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete EC2 key pair\n"),
            ResetColor
        )?;

        let ec2_key_path = aws_resources.ec2_key_path.unwrap();
        if Path::new(ec2_key_path.as_str()).exists() {
            fs::remove_file(ec2_key_path.as_str()).unwrap();
        }
        let ec2_key_path_compressed =
            format!("{}{}", ec2_key_path, compress::Encoder::Zstd(3).ext());
        if Path::new(ec2_key_path_compressed.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed.as_str()).unwrap();
        }
        let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
        if Path::new(ec2_key_path_compressed_encrypted.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed_encrypted.as_str()).unwrap();
        }
        rt.block_on(ec2_manager.delete_key_pair(aws_resources.ec2_key_name.unwrap().as_str()))
            .unwrap();
    }

    // delete this first since KMS key delete does not depend on ASG/VPC
    // (mainly to speed up delete operation)
    if aws_resources.kms_cmk_id.is_some() && aws_resources.kms_cmk_arn.is_some() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete KMS key\n"),
            ResetColor
        )?;

        let cmk_id = aws_resources.kms_cmk_id.unwrap();
        rt.block_on(kms_manager.schedule_to_delete(cmk_id.as_str()))
            .unwrap();
    }

    // IAM roles can be deleted without being blocked on ASG/VPC
    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: trigger delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_stack_name.as_str()))
            .unwrap();
    }

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete ASG for non-beacon nodes\n"),
            ResetColor
        )?;

        let asg_non_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_non_beacon_nodes
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_non_beacon_nodes_stack_name.as_str()))
            .unwrap();
    }

    if spec.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: triggering delete ASG for beacon nodes\n"),
            ResetColor
        )?;

        let asg_beacon_nodes_stack_name = aws_resources
            .cloudformation_asg_beacon_nodes
            .clone()
            .unwrap();
        rt.block_on(cloudformation_manager.delete_stack(asg_beacon_nodes_stack_name.as_str()))
            .unwrap();
    }

    if aws_resources
        .cloudformation_asg_non_beacon_nodes_logical_id
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete ASG for non-beacon nodes\n"),
            ResetColor
        )?;

        let asg_non_beacon_nodes_stack_name =
            aws_resources.cloudformation_asg_non_beacon_nodes.unwrap();

        let desired_capacity = spec.machine.non_beacon_nodes;
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        rt.block_on(cloudformation_manager.poll_stack(
            asg_non_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if spec.machine.beacon_nodes.unwrap_or(0) > 0
        && aws_resources
            .cloudformation_asg_beacon_nodes_logical_id
            .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete ASG for beacon nodes\n"),
            ResetColor
        )?;

        let asg_beacon_nodes_stack_name = aws_resources.cloudformation_asg_beacon_nodes.unwrap();

        let desired_capacity = spec.machine.beacon_nodes.unwrap();
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        rt.block_on(cloudformation_manager.poll_stack(
            asg_beacon_nodes_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(wait_secs),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    // VPC delete must run after associated EC2 instances are terminated due to dependencies
    if aws_resources.cloudformation_vpc_id.is_some()
        && aws_resources.cloudformation_vpc_security_group_id.is_some()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete VPC\n"),
            ResetColor
        )?;

        let vpc_stack_name = aws_resources.cloudformation_vpc.unwrap();
        rt.block_on(cloudformation_manager.delete_stack(vpc_stack_name.as_str()))
            .unwrap();
        thread::sleep(Duration::from_secs(10));
        rt.block_on(cloudformation_manager.poll_stack(
            vpc_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_some()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: confirming delete EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_stack_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
        rt.block_on(cloudformation_manager.poll_stack(
            ec2_instance_role_stack_name.as_str(),
            StackStatus::DeleteComplete,
            Duration::from_secs(500),
            Duration::from_secs(30),
        ))
        .unwrap();
    }

    if delete_cloudwatch_log_group {
        // deletes the one auto-created by nodes
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: cloudwatch log groups\n"),
            ResetColor
        )?;
        rt.block_on(cw_manager.delete_log_group(&spec.id)).unwrap();
    }

    if delete_s3_objects {
        thread::sleep(Duration::from_secs(1));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 objects\n"),
            ResetColor
        )?;
        thread::sleep(Duration::from_secs(5));
        rt.block_on(s3_manager.delete_objects(&aws_resources.s3_bucket, Some(spec.id)))
            .unwrap();
    }

    if delete_s3_bucket {
        thread::sleep(Duration::from_secs(1));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\n\nSTEP: delete S3 bucket\n"),
            ResetColor
        )?;
        thread::sleep(Duration::from_secs(5));
        rt.block_on(s3_manager.delete_bucket(&aws_resources.s3_bucket))
            .unwrap();
        // NOTE: do not delete db backups...
        if aws_resources.db_backup_s3_bucket.is_some() {
            info!(
                "skipping deleting {}",
                aws_resources.db_backup_s3_bucket.clone().unwrap()
            );
            // rt.block_on(
            //     s3_manager
            //         .delete_objects(&aws_resources.s3_bucket_db_backup.clone().unwrap(), None),
            // )
            // .unwrap();
            // rt.block_on(
            //     s3_manager.delete_bucket(&aws_resources.s3_bucket_db_backup.clone().unwrap()),
            // )
            // .unwrap();
        }
    }

    println!();
    info!("delete all success!");
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
