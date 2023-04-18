use std::{
    collections::HashMap,
    io::{self, stdout, Error, ErrorKind},
    str::FromStr,
    sync::Arc,
};

use avalanche_types::{ids::node, jsonrpc::client::info as json_client_info, key, units, wallet};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "add-primary-network-validators";

/// Defines "add-primary-network-validators" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,
    pub skip_prompt: bool,
    pub chain_rpc_url: String,
    pub key: String,
    pub primary_network_validate_period_in_days: u64,
    pub staking_amount_in_avax: u64,
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
        .about("Adds nodes as primary network validators")
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

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "\nAdding nodes as primary network validators with network Id '{network_id}', chain rpc url '{}', primary network validate period in days '{}', staking amount in avax '{}', node ids to instance ids '{:?}'\n",
            opts.chain_rpc_url,
            opts.primary_network_validate_period_in_days,
            opts.staking_amount_in_avax,
            opts.node_ids_to_instance_ids,
        )),
        ResetColor
    )?;

    if !opts.skip_prompt {
        println!();
        println!();
        let options = &[
            format!(
                "No, I am not ready to add primary network validators with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, primary network staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.primary_network_validate_period_in_days,
            ).to_string(),
            format!(
                "Yes, let's add primary network validators with the wallet {p_chain_address} of balance {} AVAX, staking amount {} AVAX, primary network staking {} days",
                    units::cast_xp_navax_to_avax(primitive_types::U256::from(p_chain_balance)),
                    opts.staking_amount_in_avax,
                    opts.primary_network_validate_period_in_days,
                ).to_string(),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'add-primary-network-validators' option")
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
        let random_wait = Duration::from_secs(1 + (i + 1) as u64)
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
