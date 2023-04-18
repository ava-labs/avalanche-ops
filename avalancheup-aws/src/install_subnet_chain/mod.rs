use std::{
    collections::HashMap,
    fs::File,
    io::{self, stdout, BufReader, Error, ErrorKind, Read},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use avalanche_types::{
    ids::{self, node},
    jsonrpc::client::info as json_client_info,
    key, subnet, units, wallet,
};
use aws_manager::{self, s3, ssm, sts};
use aws_sdk_ssm::types::CommandInvocationStatus;
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "install-subnet-chain";

/// Defines "install-subnet-chain" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub skip_prompt: bool,

    pub region: String,
    pub s3_bucket: String,
    pub s3_key_prefix: String,
    pub ssm_doc: String,

    pub chain_rpc_url: String,
    pub key: String,

    pub primary_network_validate_period_in_days: u64,
    pub subnet_validate_period_in_days: u64,
    pub staking_amount_in_avax: u64,

    pub subnet_config_local_path: String,
    pub subnet_config_remote_dir: String,

    pub vm_binary_local_path: String,
    pub vm_binary_remote_dir: String,
    pub vm_id: String,
    pub chain_name: String,
    pub chain_genesis_path: String,

    pub chain_config_local_path: String,
    pub chain_config_remote_dir: String,

    pub avalanchego_config_remote_path: String,

    pub node_ids_to_instance_ids: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct HashMapParser;

impl clap::builder::TypedValueParser for HashMapParser {
    type Value = HashMap<String, String>;

    fn parse_ref(
        &self,
        _cmd: &Command,
        _arg: Option<&Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let str = value.to_str().unwrap_or_default();
        let m: HashMap<String, String> = serde_json::from_str(str).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("HashMap parsing failed ({})", e),
            )
        })?;
        Ok(m)
    }
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Installs subnet and chain to target nodes")
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
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("S3_BUCKET")
                .long("s3-bucket")
                .help("Sets the S3 bucket")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("S3_KEY_PREFIX")
                .long("s3-key-prefix")
                .help("Sets the S3 key prefix for all artifacts")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SSM_DOC")
                .long("ssm-doc")
                .help("Sets the SSM document name for subnet and chain install (see avalanche-ops/src/aws/cfn-templates/ssm_install_subnet_chain.yaml)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_RPC_URL")
                .long("chain-rpc-url")
                .help("Sets the P-chain or Avalanche RPC endpoint")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("KEY")
                .long("key")
                .help("Sets the key Id (if hotkey, use private key in hex format)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("PRIMARY_NETWORK_VALIDATE_PERIOD_IN_DAYS") 
                .long("primary-network-validate-period-in-days")
                .help("Sets the number of days to validate primary network")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("16"),
        )
        .arg(
            Arg::new("SUBNET_VALIDATE_PERIOD_IN_DAYS") // TODO: use float
                .long("subnet-validate-period-in-days")
                .help("Sets the number of days to validate/stake the subnet (default 14 since primary network default validate period is 16-day in avalanche-types)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("14"),
        )
        .arg(
            Arg::new("STAKING_AMOUNT_IN_AVAX")
                .long("staking-amount-in-avax")
                .help(
                    "Sets the staking amount in P-chain AVAX (not in nAVAX) for primary network validator",
                )
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("2000"),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_LOCAL_PATH")
                .long("subnet-config-local-path")
                .help("Subnet configuration local file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_S3_KEY")
                .long("subnet-config-s3-key")
                .help("Sets the S3 key for the subnet config (if empty, default to local file name)")
                .required(false)
                .default_value("subnet-config.json")
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_REMOTE_PATH")
                .long("subnet-config-remote-dir")
                .help("Subnet configuration remote file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_LOCAL_PATH")
                .long("vm-binary-local-path")
                .help("VM binary local file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_S3_KEY")
                .long("vm-binary-s3-key")
                .help("Sets the S3 key for the Vm binary (if empty, default to local file name)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_REMOTE_DIR")
                .long("vm-binary-remote-dir")
                .help("Plugin dir for VM binaries")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_ID")
                .long("vm-id")
                .help("Sets the 32-byte Vm Id for the Vm binary (if empty, converts chain name to Id)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_NAME")
                .long("chain-name")
                .help("Sets the chain name")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_GENESIS_PATH")
                .long("chain-genesis-path")
                .help("Chain genesis file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_LOCAL_PATH")
                .long("chain-config-local-path")
                .help("Chain configuration local file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_S3_KEY")
                .long("chain-config-s3-key")
                .help("Sets the S3 key for the subnet chain config (if empty, default to local file name)")
                .required(false)
                .default_value("subnet-chain-config.json")
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_REMOTE_PATH")
                .long("chain-config-remote-dir")
                .help("Chain configuration remote file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("AVALANCHEGO_CONFIG_REMOTE_PATH")
                .long("avalanchego-config-remote-path")
                .help("avalanchego config remote file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("NODE_IDS_TO_INSTANCE_IDS")
                .long("node-ids-to-instance-ids")
                .help("Sets the hash map of node Id to instance Id in JSON format")
                .required(true)
                .value_parser(HashMapParser {})
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    if !Path::new(&opts.vm_binary_local_path).exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("vm binary file '{}' not found", opts.vm_binary_local_path),
        ));
    }

    if !opts.subnet_config_local_path.is_empty() && opts.subnet_config_remote_dir.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "subnet_config_local_path not empty but subnet_config_remote_dir empty",
        ));
    }
    if !opts.chain_config_local_path.is_empty() && opts.chain_config_remote_dir.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "chain_config_local_path not empty but chain_config_remote_dir empty",
        ));
    }

    if !Path::new(&opts.chain_genesis_path).exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("chain genesis file '{}' not found", opts.chain_genesis_path),
        ));
    }
    let f = File::open(&opts.chain_genesis_path).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed to open {} ({})", opts.chain_genesis_path, e),
        )
    })?;
    let mut reader = BufReader::new(f);
    let mut chain_genesis_bytes = Vec::new();
    reader.read_to_end(&mut chain_genesis_bytes)?;

    let vm_id = if opts.vm_id.is_empty() {
        subnet::vm_name_to_id(&opts.chain_name)?
    } else {
        ids::Id::from_str(&opts.vm_id)?
    };

    let resp = json_client_info::get_network_id(&opts.chain_rpc_url)
        .await
        .unwrap();
    let network_id = resp.result.unwrap().network_id;

    let priv_key = key::secp256k1::private_key::Key::from_hex(&opts.key).unwrap();
    let wallet_to_spend = wallet::Builder::new(&priv_key)
        .base_http_url(opts.chain_rpc_url.clone())
        .build()
        .await
        .unwrap();

    let p_chain_balance = wallet_to_spend.p().balance().await.unwrap();
    let p_chain_address = priv_key
        .to_public_key()
        .to_hrp_address(network_id, "P")
        .unwrap();
    log::info!(
        "loaded wallet '{p_chain_address}', fetched its P-chain balance {} AVAX ({p_chain_balance} nAVAX, network id {network_id})",
        units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance))
    );

    let mut all_node_ids = Vec::new();
    let mut all_instance_ids = Vec::new();
    for (node_id, instance_id) in opts.node_ids_to_instance_ids.iter() {
        log::info!("will send SSM doc to {node_id} {instance_id}");
        all_node_ids.push(node_id.clone());
        all_instance_ids.push(instance_id.clone());
    }

    // if all nodes need to be staked
    println!();
    let estimated_required_avax =
        units::cast_avax_to_xp_navax(primitive_types::U256::from(opts.staking_amount_in_avax))
            .checked_mul(primitive_types::U256::from(all_node_ids.len()))
            .unwrap();
    log::info!(
        "required AVAX to validate all nodes {estimated_required_avax} nAVAX ({} AVAX)",
        units::cast_xp_navax_to_avax(estimated_required_avax)
    );
    if primitive_types::U256::from(p_chain_balance) < estimated_required_avax {
        log::warn!("'{p_chain_address}' only has {p_chain_balance}, not enough to validate all nodes (needs {estimated_required_avax} nAVAX)");
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Should we still proceed?")
            .items(&["Yes...?", "No!!!"])
            .default(0)
            .interact()
            .unwrap();
        if selected == 1 {
            return Ok(());
        }
    }

    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nInstalling subnet with network Id '{network_id}', chain rpc url '{}', S3 bucket '{}', S3 key prefix '{}', subnet config local '{}', subnet config remote dir '{}', VM binary local '{}', VM binary remote dir '{}', VM Id '{}', chain name '{}', chain config local '{}', chain config remote dir '{}', chain genesis file '{}', primary network validate period in days '{}', subnet validate period in days '{}', staking amount in avax '{}', node ids to instance ids '{:?}'\n",
            opts.chain_rpc_url,
            opts.s3_bucket,
            opts.s3_key_prefix,
            opts.subnet_config_local_path,
            opts.subnet_config_remote_dir,
            opts.vm_binary_local_path,
            opts.vm_binary_remote_dir,
            vm_id,
            opts.chain_name,
            opts.chain_config_local_path,
            opts.chain_config_remote_dir,
            opts.chain_genesis_path,
            opts.primary_network_validate_period_in_days,
            opts.subnet_validate_period_in_days,
            opts.staking_amount_in_avax,
            opts.node_ids_to_instance_ids,
        )),
        ResetColor
    )?;

    let shared_config =
        aws_manager::load_config(Some(opts.region.clone()), Some(Duration::from_secs(30))).await;
    let sts_manager = sts::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);
    let ssm_manager = ssm::Manager::new(&shared_config);

    let current_identity = sts_manager.get_identity().await.unwrap();
    log::info!("current AWS identity: {:?}", current_identity);

    if !opts.skip_prompt {
        println!();
        println!();
        let options = &[
            format!(
                "No, I am not ready to install a subnet with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, primary network staking {} days, subnet staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.primary_network_validate_period_in_days,
                    opts.subnet_validate_period_in_days,
            ).to_string(),
            format!(
                "Yes, let's install a subnet with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, primary network staking {} days, subnet staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.primary_network_validate_period_in_days,
                    opts.subnet_validate_period_in_days,
                ).to_string(),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'install-subnet-chain' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    //
    //
    //
    //
    //
    if !opts.subnet_config_local_path.is_empty() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: uploading subnet config local file to S3\n\n"),
            ResetColor
        )?;

        if !Path::new(&opts.subnet_config_local_path).exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "subnet config file '{}' not found",
                    opts.subnet_config_local_path
                ),
            ));
        }

        let file_stem = Path::new(&opts.subnet_config_local_path)
            .file_stem()
            .unwrap();
        let subnet_config_s3_key = format!(
            "{}{}",
            s3::append_slash(&opts.s3_key_prefix),
            file_stem.to_str().unwrap().to_string()
        );

        s3_manager
            .put_object(
                &opts.subnet_config_local_path,
                &opts.s3_bucket,
                &subnet_config_s3_key,
            )
            .await
            .expect("failed put_object subnet_config_path");
    }

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: uploading VM binary local file to S3\n\n"),
        ResetColor
    )?;
    let vm_binary_s3_key = format!(
        "{}{}",
        s3::append_slash(&opts.s3_key_prefix),
        vm_id.to_string()
    );
    s3_manager
        .put_object(
            &opts.vm_binary_local_path,
            &opts.s3_bucket,
            &vm_binary_s3_key,
        )
        .await
        .expect("failed put_object vm_binary_path");

    //
    //
    //
    //
    //
    if !opts.chain_config_local_path.is_empty() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: uploading subnet chain config local file to S3\n\n"),
            ResetColor
        )?;

        if !Path::new(&opts.chain_config_local_path).exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "subnet chain config file '{}' not found",
                    opts.chain_config_local_path
                ),
            ));
        }

        let file_stem = Path::new(&opts.chain_config_local_path)
            .file_stem()
            .unwrap();
        let chain_config_s3_key = format!(
            "{}{}",
            s3::append_slash(&opts.s3_key_prefix),
            file_stem.to_str().unwrap().to_string()
        );

        s3_manager
            .put_object(
                &opts.chain_config_local_path,
                &opts.s3_bucket,
                &chain_config_s3_key,
            )
            .await
            .expect("failed put_object chain_config_path");
    }

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\n\n\nSTEP: adding all nodes as primary network validators if not yet (period {})\n\n",
            opts.primary_network_validate_period_in_days
        )),
        ResetColor
    )?;
    let stake_amount_in_navax =
        units::cast_avax_to_xp_navax(primitive_types::U256::from(opts.staking_amount_in_avax))
            .as_u64();

    let mut handles = Vec::new();
    for (i, (node_id, instance_id)) in opts.node_ids_to_instance_ids.iter().enumerate() {
        log::info!(
            "spawning add_primary_network_validator on '{}' (of EC2 instance '{}', staking period in days '{}')",
            node_id,
            instance_id,
            opts.primary_network_validate_period_in_days
        );

        // randomly wait to prevent UTXO double spends from the same wallet
        let random_wait = Duration::from_secs(1 + i as u64)
            .checked_add(Duration::from_millis(500 + random_manager::u64() % 100))
            .unwrap();

        handles.push(tokio::spawn(add_primary_network_validator(
            Arc::new(random_wait),
            Arc::new(wallet_to_spend.clone()),
            Arc::new(node_id.to_owned()),
            Arc::new(stake_amount_in_navax),
            Arc::new(opts.primary_network_validate_period_in_days),
        )));
    }
    log::info!("STEP: blocking on add_validator handles via JoinHandle");
    for handle in handles {
        handle.await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed await on add_validator JoinHandle {}", e),
            )
        })?;
    }

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating a subnet\n\n"),
        ResetColor
    )?;
    let subnet_id = wallet_to_spend
        .p()
        .create_subnet()
        .dry_mode(true)
        .issue()
        .await
        .unwrap();
    log::info!("[dry mode] subnet Id '{}'", subnet_id);

    let created_subnet_id = wallet_to_spend
        .p()
        .create_subnet()
        .check_acceptance(true)
        .issue()
        .await
        .unwrap();
    log::info!("created subnet '{}' (still need track)", created_subnet_id);
    sleep(Duration::from_secs(10)).await;

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: send SSM doc to download Vm binary, track subnet Id, update subnet config\n\n"),
        ResetColor
    )?;
    let subcmd = format!("install-subnet --log-level info --region {region} --s3-bucket {s3_bucket} --vm-binary-s3-key {vm_binary_s3_key} --vm-binary-local-path {vm_binary_local_path} --subnet-id-to-track {subnet_id_to_track} --avalanchego-config-path {avalanchego_config_remote_path}",
        region = opts.region,
        s3_bucket = opts.s3_bucket,
        vm_binary_s3_key = vm_binary_s3_key,
        vm_binary_local_path = format!("{}{}", s3::append_slash(&opts.vm_binary_remote_dir), vm_id.to_string()),
        subnet_id_to_track = created_subnet_id.to_string(),
        avalanchego_config_remote_path = opts.avalanchego_config_remote_path,
    );
    let avalanched_args = if !opts.subnet_config_local_path.is_empty() {
        let file_stem = Path::new(&opts.subnet_config_local_path)
            .file_stem()
            .unwrap();
        let subnet_config_s3_key = format!(
            "{}{}",
            s3::append_slash(&opts.s3_key_prefix),
            file_stem.to_str().unwrap().to_string()
        );

        // If a subnet id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
        // the config file for this subnet is located at {subnet-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt.json.
        format!("{subcmd} --subnet-config-s3-key {subnet_config_s3_key} --subnet-config-local-path {subnet_config_local_path}",
            subnet_config_s3_key = subnet_config_s3_key,
            subnet_config_local_path = format!("{}{}.json", s3::append_slash(&opts.subnet_config_remote_dir), created_subnet_id.to_string()),
        )
    } else {
        subcmd
    };
    // ref. <https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html>
    let ssm_output = ssm_manager
        .cli
        .send_command()
        .document_name(opts.ssm_doc.clone())
        .set_instance_ids(Some(all_instance_ids.clone()))
        .parameters("avalanchedArgs", vec![avalanched_args.clone()])
        .output_s3_region(opts.region.clone())
        .output_s3_bucket_name(opts.s3_bucket.clone())
        .output_s3_key_prefix(format!(
            "{}ssm-output-logs",
            s3::append_slash(&opts.s3_key_prefix)
        ))
        .send()
        .await
        .unwrap();
    let ssm_output = ssm_output.command().unwrap();
    let ssm_command_id = ssm_output.command_id().unwrap();
    log::info!("sent SSM command {}", ssm_command_id);
    sleep(Duration::from_secs(30)).await;

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
        ResetColor
    )?;
    for instance_id in all_instance_ids.iter() {
        let status = ssm_manager
            .poll_command(
                ssm_command_id,
                instance_id,
                CommandInvocationStatus::Success,
                Duration::from_secs(300),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        log::info!("status {:?} for instance id {}", status, instance_id);
    }
    sleep(Duration::from_secs(5)).await;

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as subnet validators\n\n"),
        ResetColor
    )?;
    let mut handles = Vec::new();
    for (i, node_id) in all_node_ids.iter().enumerate() {
        log::info!(
            "spawning add_subnet_validator on '{}' (staking period in days '{}')",
            node_id,
            opts.subnet_validate_period_in_days
        );

        // randomly wait to prevent UTXO double spends from the same wallet
        let random_wait = Duration::from_secs(1 + i as u64)
            .checked_add(Duration::from_millis(500 + random_manager::u64() % 100))
            .unwrap();

        handles.push(tokio::spawn(add_subnet_network_validator(
            Arc::new(random_wait),
            Arc::new(wallet_to_spend.clone()),
            Arc::new(node_id.to_owned()),
            Arc::new(created_subnet_id.to_owned()),
            Arc::new(opts.subnet_validate_period_in_days),
        )));
    }
    log::info!("STEP: blocking on add_subnet_validator handles via JoinHandle");
    for handle in handles {
        handle.await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed await on add_subnet_validator JoinHandle {}", e),
            )
        })?;
    }
    sleep(Duration::from_secs(5)).await;

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: creating a blockchain with the genesis\n\n"),
        ResetColor
    )?;
    let blockchain_id = wallet_to_spend
        .p()
        .create_chain()
        .subnet_id(created_subnet_id)
        .genesis_data(chain_genesis_bytes.clone())
        .vm_id(vm_id.clone())
        .chain_name(opts.chain_name.clone())
        .dry_mode(true)
        .issue()
        .await
        .unwrap();
    log::info!("[dry mode] blockchain Id {blockchain_id} for subnet {created_subnet_id}");

    let blockchain_id = wallet_to_spend
        .p()
        .create_chain()
        .subnet_id(created_subnet_id)
        .genesis_data(chain_genesis_bytes.clone())
        .vm_id(vm_id.clone())
        .chain_name(opts.chain_name.clone())
        .check_acceptance(true)
        .issue()
        .await
        .unwrap();
    log::info!("created a blockchain {blockchain_id} for subnet {created_subnet_id}");

    if !opts.chain_config_local_path.is_empty() {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: sending SSM doc for chain-config updates\n\n"),
            ResetColor
        )?;

        let file_stem = Path::new(&opts.chain_config_local_path)
            .file_stem()
            .unwrap();
        let chain_config_s3_key = format!(
            "{}{}",
            s3::append_slash(&opts.s3_key_prefix),
            file_stem.to_str().unwrap().to_string()
        );

        // If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
        // the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json.
        let avalanched_args = format!("install-chain --log-level info --region {region} --s3-bucket {s3_bucket} --chain-config-s3-key {chain_config_s3_key} --chain-config-local-path {chain_config_local_path}",
            region = opts.region,
            s3_bucket = opts.s3_bucket,
            chain_config_s3_key = chain_config_s3_key,
            chain_config_local_path = format!("{}{}/config.json", s3::append_slash(&opts.chain_config_remote_dir), blockchain_id.to_string()),
        );

        // ref. <https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html>
        let ssm_output = ssm_manager
            .cli
            .send_command()
            .document_name(opts.ssm_doc.clone())
            .set_instance_ids(Some(all_instance_ids.clone()))
            .parameters("avalanchedArgs", vec![avalanched_args.clone()])
            .output_s3_region(opts.region.clone())
            .output_s3_bucket_name(opts.s3_bucket.clone())
            .output_s3_key_prefix(format!(
                "{}ssm-output-logs",
                s3::append_slash(&opts.s3_key_prefix)
            ))
            .send()
            .await
            .unwrap();
        let ssm_output = ssm_output.command().unwrap();
        let ssm_command_id = ssm_output.command_id().unwrap();
        log::info!("sent SSM command {}", ssm_command_id);
        sleep(Duration::from_secs(30)).await;

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: checking the status of SSM command...\n\n"),
            ResetColor
        )?;
        for instance_id in all_instance_ids.iter() {
            let status = ssm_manager
                .poll_command(
                    ssm_command_id,
                    instance_id,
                    CommandInvocationStatus::Success,
                    Duration::from_secs(300),
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            log::info!("status {:?} for instance id {}", status, instance_id);
        }
        sleep(Duration::from_secs(5)).await;
    }

    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "\n\n\nSUCCESS!\nsubnet Id: {created_subnet_id}\nblockchain Id: {blockchain_id}\n\n"
        )),
        ResetColor
    )?;

    Ok(())
}

/// randomly wait to prevent UTXO double spends from the same wallet
async fn add_primary_network_validator(
    random_wait_dur: Arc<Duration>,
    wallet_to_spend: Arc<wallet::Wallet<key::secp256k1::private_key::Key>>,
    node_id: Arc<String>,
    stake_amount_in_navax: Arc<u64>,
    primary_network_validate_period_in_days: Arc<u64>,
) {
    let random_wait_dur = random_wait_dur.as_ref();
    log::info!(
        "adding '{node_id}' as a primary network validator after waiting random {:?}",
        *random_wait_dur
    );
    sleep(*random_wait_dur).await;

    let node_id = node::Id::from_str(&node_id).unwrap();
    let stake_amount_in_navax = stake_amount_in_navax.as_ref();
    let primary_network_validate_period_in_days = primary_network_validate_period_in_days.as_ref();

    let (tx_id, added) = wallet_to_spend
        .p()
        .add_validator()
        .node_id(node_id)
        .stake_amount(*stake_amount_in_navax)
        .validate_period_in_days(*primary_network_validate_period_in_days, 60)
        .check_acceptance(true)
        .issue()
        .await
        .unwrap();

    log::info!("primary network validator tx id {}, added {}", tx_id, added);
}

/// randomly wait to prevent UTXO double spends from the same wallet
async fn add_subnet_network_validator(
    random_wait_dur: Arc<Duration>,
    wallet_to_spend: Arc<wallet::Wallet<key::secp256k1::private_key::Key>>,
    node_id: Arc<String>,
    subnet_id: Arc<ids::Id>,
    subnet_validate_period_in_days: Arc<u64>,
) {
    let random_wait_dur = random_wait_dur.as_ref();
    log::info!(
        "adding '{node_id}' as a subnet validator '{subnet_id}' after waiting random {:?}",
        *random_wait_dur
    );
    sleep(*random_wait_dur).await;

    let node_id = node::Id::from_str(&node_id).unwrap();
    let subnet_id = subnet_id.as_ref();
    let subnet_validate_period_in_days = subnet_validate_period_in_days.as_ref();

    let (tx_id, added) = wallet_to_spend
        .p()
        .add_subnet_validator()
        .node_id(node_id)
        .subnet_id(*subnet_id)
        .validate_period_in_days(*subnet_validate_period_in_days, 60)
        .check_acceptance(true)
        .issue()
        .await
        .unwrap();

    log::info!("subnet validator tx id {}, added {}", tx_id, added);
}
