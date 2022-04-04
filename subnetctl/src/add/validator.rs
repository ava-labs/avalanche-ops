use std::{
    fs,
    io::{self, stdout, Error, ErrorKind},
    time::SystemTime,
};

use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use lazy_static::lazy_static;
use log::info;
use tokio::runtime::Runtime;

use avalanche_api::{info as api_info, p, x};
use avalanche_types::{avax, constants, ids, platformvm, soft_key};
use utils::rfc3339;

lazy_static! {
    pub static ref DEFAULT_VALIATE_END: &'static str = {
        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();
        let default_validate_end = now_unix + 365 * 24 * 60 * 60;
        let default_validate_end =
            rfc3339::to_str(default_validate_end).expect("failed to convert rfc3339");

        // leak...
        // TODO: find a better way
        Box::leak(default_validate_end.into_boxed_str())
    };
}

pub const NAME: &str = "validator";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Adds a validator")
        .long_about("

e.g.,

$ subnetctl add validator \
--http-rpc-endpoint=http://localhost:52250 \
--private-key-path=.insecure.ewoq.key \
--node-id=\"NodeID-4B4rc5vdD1758JSBYL1xyvE5NHGzz6xzH\" \
--stake-amount=2000000000000 \
--validate-reward-fee-percent=2

See https://github.com/ava-labs/subnet-cli.


")
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
                .default_value("info")
        )
        .arg(
            Arg::new("HTTP_RPC_ENDPOINT")
                .long("http-rpc-endpoint")
                .short('e')
                .help("HTTP RPC endpoint")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
        )
        .arg(
            // TODO: support ledger
            Arg::new("PRIVATE_KEY_PATH")
                .long("private-key-path")
                .short('p')
                .help("private key file path that contains hex string")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
        )
        .arg(
            Arg::new("NODE_ID")
                .long("node-id")
                .short('n')
                .help("node ID (must be formatted in ids::Id")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("STAKE_AMOUNT")
                .long("stake-amount")
                .short('s')
                .help("stake amount denominated in nano AVAX (minimum amount that a validator must stake is 2,000 AVAX)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("2000000000000")
        )
        .arg(
            Arg::new("VALIDATE_END")
                .long("validate-end")
                .short('v')
                .help("validate start timestamp in RFC3339 format")
                .required(true)
                .takes_value(true)
                .default_value(*DEFAULT_VALIATE_END)
                .allow_invalid_utf8(false)
        )
        .arg(
            Arg::new("VALIDATE_REWARD_FEE_PERCENT")
                .long("validate-reward-fee-percent")
                .short('f')
                .help("percentage of fee that the validator will take rewards from its delegators")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("2")
        )
}

pub struct CmdOption {
    pub log_level: String,
    pub http_rpc_ep: String,
    pub private_key_path: Option<String>,
    pub node_id: ids::NodeId,
    pub stake_amount: u64,
    pub validate_end: DateTime<Utc>,
    pub validate_reward_fee_percent: u32,
}

pub fn execute(opt: CmdOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );
    let rt = Runtime::new().unwrap();

    /////
    println!();
    println!();
    println!();
    let keys = {
        if let Some(private_key_path) = opt.private_key_path {
            execute!(
                stdout(),
                SetForegroundColor(Color::Blue),
                Print(format!("loading private key file '{}'\n", private_key_path)),
                ResetColor
            )?;
            let contents = fs::read_to_string(private_key_path).expect("failed to read file");
            let keys = soft_key::load_keys(contents.as_bytes())?;
            keys
        } else {
            panic!("unexpected None opt.private_key_path -- hardware wallet not supported yet");
        }
    };
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    let reward_short_address = key.short_address.clone();
    info!(
        "loaded key at ETH address {} (reward short address {})",
        key.eth_address, reward_short_address
    );

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "connecting to '{}' for network information\n",
            opt.http_rpc_ep
        )),
        ResetColor
    )?;
    let resp = rt
        .block_on(api_info::get_network_id(&opt.http_rpc_ep))
        .expect("failed get_network_id");
    let network_id = resp.result.unwrap().network_id;
    if let Some(name) = constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
        if *name == "mainnet" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "mainnet is not supported yet!",
            ));
        }
    }
    let resp = rt
        .block_on(api_info::get_network_name(&opt.http_rpc_ep))
        .expect("failed get_network_name");
    let network_name = resp.result.unwrap().network_name;
    if network_name == "mainnet" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "mainnet is not supported yet!",
        ));
    }
    info!("NETWORK ID: {}", network_id);
    info!("NETWORK NAME: {}", network_name);

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print("getting chain IDs\n"),
        ResetColor
    )?;
    let resp = rt
        .block_on(api_info::get_blockchain_id(&opt.http_rpc_ep, "X"))
        .expect("failed get_blockchain_id for X");
    let x_chain_id = resp.result.unwrap().blockchain_id;
    info!("X-chain ID is {}", x_chain_id);

    let p_chain_id = platformvm::chain_id();
    info!("P-chain ID is {}", p_chain_id);

    let resp = rt
        .block_on(api_info::get_blockchain_id(&opt.http_rpc_ep, "P"))
        .expect("failed get_blockchain_id for P");
    let p_chain_id = resp.result.unwrap().blockchain_id;
    info!("P-chain ID is {}", p_chain_id);

    let resp = rt
        .block_on(api_info::get_blockchain_id(&opt.http_rpc_ep, "C"))
        .expect("failed get_blockchain_id for C");
    let c_chain_id = resp.result.unwrap().blockchain_id;
    info!("C-chain ID is {}", c_chain_id);

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print("getting asset ID for AVAX\n"),
        ResetColor
    )?;
    let resp = rt
        .block_on(x::get_asset_description(&opt.http_rpc_ep, "AVAX"))
        .expect("failed to get get_asset_description");
    let result = resp.result.unwrap();
    let avax_asset_id = result.clone().asset_id;
    info!("AVAX asset ID: {}", avax_asset_id);
    info!("AVAX asset description: {:?}", result);

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "getting current validators via '{}' to check node '{}' is already a validator\n",
            opt.http_rpc_ep, opt.node_id
        )),
        ResetColor
    )?;
    let resp = rt
        .block_on(p::get_current_validators(&opt.http_rpc_ep))
        .expect("failed get_current_validators");
    let validators = resp.result.unwrap().validators.unwrap();
    for validator in validators.iter() {
        let node_id = validator.node_id.clone().unwrap();
        if node_id == opt.node_id {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("node ID {} is already a validator", node_id),
            ));
        }
        info!("listing current validator {}", node_id);
    }

    /////
    println!();
    println!();
    println!();
    let p_chain_addr = key.address("P", network_id)?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("checking the balance for {}\n", p_chain_addr)),
        ResetColor
    )?;
    let resp = rt
        .block_on(p::get_balance(&opt.http_rpc_ep, &p_chain_addr))
        .expect("failed to get balance");
    // On the X-Chain, one AVAX is 10^9  units.
    // On the P-Chain, one AVAX is 10^9  units.
    // On the C-Chain, one AVAX is 10^18 units.
    // ref. https://docs.avax.network/learn/platform-overview/transaction-fees/#fee-schedule
    let add_validator_fee = 0_u64;
    let stake_amount = opt.stake_amount;
    let total_cost = add_validator_fee + stake_amount;
    let total_cost_avax = (total_cost as f64) / 1000000000_f64;
    let p_chain_balance = resp.result.unwrap().balance.unwrap();
    let p_chain_balance_avax = (p_chain_balance as f64) / 1000000000_f64;
    info!(
        "P-chain CURRENT BALANCE [{}]: {} nano-AVAX ({} AVAX)",
        p_chain_addr, p_chain_balance, p_chain_balance_avax
    );
    info!(
        "TOTAL COST: {} nano-AVAX ({} AVAX)",
        total_cost, total_cost_avax
    );
    let reward_shares = opt.validate_reward_fee_percent * 10000;
    info!(
        "REWARD SHARES: {} (reward fee percent {}%)",
        reward_shares, opt.validate_reward_fee_percent
    );

    /////
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print("checking the validate duration\n".to_string()),
        ResetColor
    )?;
    let now = SystemTime::now();
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unexpected None duration_since")
        .as_secs();
    let validate_start = now_unix + 30;
    let native_dt = NaiveDateTime::from_timestamp(validate_start as i64, 0);
    let validate_start = DateTime::<Utc>::from_utc(native_dt, Utc);
    info!("VALIDATE START {:?}", validate_start);
    info!("VALIDATE END {:?}", opt.validate_end);

    /////
    // ref. "subnet-cli/client/p.stake"
    // ref. "platformvm.VM.stake".
    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/p/builder.go
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print("checking inputs and outputs\n".to_string()),
        ResetColor
    )?;
    let resp = rt
        .block_on(p::get_utxos(&opt.http_rpc_ep, &p_chain_addr))
        .expect("failed to get UTXOs");
    let utxos_raw = resp.result.unwrap().utxos.unwrap();
    let mut utxos: Vec<avax::Utxo> = Vec::new();
    for s in utxos_raw.iter() {
        let utxo = avax::Utxo::unpack_hex(s).expect("failed to unpack raw utxo");
        utxos.push(utxo);
    }

    let staked_amount: u64 = 0_u64;
    for utxo in utxos.iter() {
        if staked_amount >= opt.stake_amount {
            break;
        }
        if utxo.asset_id != avax_asset_id {
            continue;
        }

        // check "*platformvm.StakeableLockOut"
        if utxo.stakeable_lock_out.is_none() {
            // output is not locked, just handle this in the next iteration
            continue;
        }
        let stakeable_lock_out = utxo.stakeable_lock_out.clone().unwrap();
        if stakeable_lock_out.locktime <= now_unix {
            // output is no longer locked, just handle in the next iteration
            continue;
        }

        let transfer_output = stakeable_lock_out.out;
        let input = key.spend(&transfer_output, now_unix)?;
        let _transfer_input = avax::TransferableInput {
            utxo_id: utxo.utxo_id.clone(),
            asset_id: utxo.asset_id.clone(),
            input,
            ..avax::TransferableInput::default()
        };
        // TODO
    }
    // TODO: get *avax.TransferableInput for inputs
    // TODO: get *avax.TransferableOutput for returned outs
    // TODO: get *avax.TransferableOutput for staked outs

    /////
    println!();
    println!();
    println!();
    // TODO: prompt for confirmation

    /////
    println!();
    println!();
    println!();
    // TODO: sign transaction

    /////
    println!();
    println!();
    println!();
    // TODO: send transaction

    /////
    println!();
    println!();
    println!();
    // TODO: poll to confirm transaction

    /////
    println!();
    println!();
    println!();
    // TODO: check current validators

    /////
    println!();
    println!();
    println!();

    Ok(())
}
