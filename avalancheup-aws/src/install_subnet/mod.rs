use std::{
    collections::HashMap,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
    str::FromStr,
};

use avalanche_types::{
    ids::{self, node},
    jsonrpc::client::info as json_client_info,
    key, subnet, units, wallet,
};
use aws_manager::{self, s3, ssm, sts};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "install-subnet";

/// Defines "install-subnet" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub skip_prompt: bool,

    pub region: String,
    pub s3_bucket: String,
    pub ssm_doc: String,

    pub chain_rpc_url: String,
    pub key: String,

    pub staking_period_in_days: u64,
    pub staking_amount_in_avax: u64,

    pub subnet_config_path: String,
    pub subnet_config_s3_key: String,

    pub vm_binary_path: String,
    pub vm_binary_s3_key: String,

    pub vm_id: String,
    pub chain_name: String,

    pub chain_config_path: String,
    pub chain_config_s3_key: String,

    pub chain_genesis_path: String,

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
        .about("Installs a subnet to target nodes")
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
            Arg::new("SSM_DOC")
                .long("ssm-doc")
                .help("Sets the SSM document name for subnet install")
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
            Arg::new("STAKING_PERIOID_IN_DAYS")
                .long("staking-perioid-in-days")
                .help("Sets the number of days to stake the node (primary network + subnet)")
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
            Arg::new("SUBNET_CONFIG_PATH")
                .long("subnet-config-path")
                .help("Subnet configuration file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_CONFIG_S3_KEY")
                .long("subnet-config-s3-key")
                .help("Sets the S3 key for the subnet config")
                .required(false)
                .default_value("subnet-config.json")
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_PATH")
                .long("vm-binary-path")
                .help("VM binary file path")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("VM_BINARY_S3_KEY")
                .long("vm-binary-s3-key")
                .help("Sets the S3 key for the Vm binary (if empty, default to file name)")
                .required(false)
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
            Arg::new("CHAIN_CONFIG_PATH")
                .long("chain-config-path")
                .help("Chain configuration file path")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_CONFIG_S3_KEY")
                .long("chain-config-s3-key")
                .help("Sets the S3 key for the subnet chain config")
                .required(false)
                .default_value("subnet-chain-config.json")
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
            Arg::new("NODE_IDS_TO_INSTANCE_IDS")
                .long("node-ids-to-instance-ids")
                .help("Sets the hash map of node Id to instance Id in JSON format")
                .required(true)
                .value_parser(HashMapParser {})
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    if !Path::new(&opts.vm_binary_path).exists() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("vm binary '{}' not found", opts.vm_binary_path),
        ));
    }

    let vm_id = if opts.vm_id.is_empty() {
        subnet::vm_name_to_id(&opts.chain_name)?
    } else {
        ids::Id::from_str(&opts.vm_id)?
    };

    let s3_key_vm_binary = if !opts.vm_binary_s3_key.is_empty() {
        opts.vm_binary_s3_key.clone()
    } else {
        let file_stem = Path::new(&opts.vm_binary_path).file_stem().unwrap();
        file_stem.to_str().unwrap().to_string()
    };

    let resp = json_client_info::get_network_id(&opts.chain_rpc_url)
        .await
        .unwrap();
    let network_id = resp.result.unwrap().network_id;

    let priv_key = key::secp256k1::private_key::Key::from_hex(&opts.key)?;
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

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nInstalling subnet with network Id '{network_id}', chain rpc url '{}', subnet config '{}', VM binary '{}', VM Id '{}', chain name '{}', chain config '{}', chain genesis '{}', staking period in days '{}', staking amount in avax '{}', S3 bucket '{}', S3 key vm binary '{}', node ids to instance ids '{:?}'\n",
            opts.chain_rpc_url,
            opts.subnet_config_path,
            opts.vm_binary_path,
            vm_id,
            opts.chain_name,
            opts.chain_config_path,
            opts.chain_genesis_path,
            opts.staking_period_in_days,
            opts.staking_amount_in_avax,
            opts.s3_bucket,
            s3_key_vm_binary,
            opts.node_ids_to_instance_ids,
        )),
        ResetColor
    )?;

    let shared_config = aws_manager::load_config(Some(opts.region.clone())).await?;
    let sts_manager = sts::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);
    let _ssm_manager = ssm::Manager::new(&shared_config);

    let current_identity = sts_manager.get_identity().await.unwrap();
    log::info!("current AWS identity: {:?}", current_identity);

    if !opts.skip_prompt {
        let options = &[
            format!(
                "No, I am not ready to install a subnet with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.staking_period_in_days,
            ).to_string(),
            format!(
                "Yes, let's install a subnet with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.staking_period_in_days,
                ).to_string(),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'install-subnet' option")
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
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: uploading VM binary to S3\n\n"),
        ResetColor
    )?;
    log::info!(
        "uploading vm binary '{}' to {} {s3_key_vm_binary}",
        opts.vm_binary_path,
        opts.s3_bucket
    );
    s3_manager
        .put_object(&opts.vm_binary_path, &opts.s3_bucket, &s3_key_vm_binary)
        .await
        .expect("failed put_object vm_binary_path");

    //
    //
    //
    //
    //
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: adding all nodes as primary network validators if not yet\n\n"),
        ResetColor
    )?;
    let stake_amount_in_navax =
        units::cast_avax_to_xp_navax(primitive_types::U256::from(opts.staking_amount_in_avax))
            .as_u64();
    for (node_id, instance_id) in opts.node_ids_to_instance_ids.iter() {
        log::info!("adding {} in instance {}", node_id, instance_id);
        let (tx_id, added) = wallet_to_spend
            .p()
            .add_validator()
            .node_id(node::Id::from_str(node_id).unwrap())
            .stake_amount(stake_amount_in_navax)
            .validate_period_in_days(60, opts.staking_period_in_days)
            .check_acceptance(true)
            .issue()
            .await
            .unwrap();
        log::info!("validator tx id {}, added {}", tx_id, added);
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
    // TODO: track subnet by restarting nodes

    if !opts.subnet_config_path.is_empty() {
        //
        //
        //
        //
        //
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: upload subnet config to S3\n\n"),
            ResetColor
        )?;
        // TODO: write subnet config if not empty on remote machines
    }

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
    // TODO: add nodes as subnet network validator if not yet

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
    // TODO: create blockchain with genesis

    if !opts.chain_config_path.is_empty() {
        //
        //
        //
        //
        //
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: upload subnet chain config to S3\n\n"),
            ResetColor
        )?;
        // TODO: write chain config if not empty on remote machines
    }

    Ok(())
}
