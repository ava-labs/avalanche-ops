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
use avalanche_types::{avax, constants, ids, platformvm, secp256k1fx, soft_key, units};
use utils::rfc3339;

lazy_static! {
    pub static ref DEFAULT_STAKE_AMOUNT: &'static str = {
        let default_stake_amount = 2*units::KILO_AVAX;
        let default_stake_amount = format!("{}",default_stake_amount);

        // leak... find a better way!
        Box::leak(default_stake_amount.into_boxed_str())
    };
    pub static ref DEFAULT_VALIATE_END: &'static str = {
        let now = SystemTime::now();
        let now_unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();
        let default_validate_end = now_unix + 365 * 24 * 60 * 60;
        let default_validate_end =
            rfc3339::to_str(default_validate_end).expect("failed to convert rfc3339");

        // leak... find a better way!
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
--stake-amount-in-nano-avax=2000000000000 \
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
            Arg::new("STAKE_AMOUNT_IN_NANO_AVAX")
                .long("stake-amount-in-nano-avax")
                .short('s')
                .help("stake amount denominated in nano AVAX -- minimum amount that a mainnet validator must stake is 2,000 AVAX or 2000000000000 in nano-AVAX, fuji only requires 1 AVAX or 1000000000 nano-AVAX")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value(*DEFAULT_STAKE_AMOUNT)
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
    pub stake_amount_in_nano_avax: u64,
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
            let keys = soft_key::load_encoded_keys(contents.as_bytes())?;
            keys
        } else {
            panic!("unexpected None opt.private_key_path -- hardware wallet not supported yet");
        }
    };

    // TODO: support multiple keys for multi-sig
    // TODO: support ledger
    assert_eq!(keys.len(), 1);

    let loaded_soft_priv_key = &keys[0];
    let reward_short_address = loaded_soft_priv_key.short_address.clone();
    info!(
        "loaded key at ETH address {} (reward short address {})",
        loaded_soft_priv_key.eth_address, reward_short_address
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
    // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go "AddValidator"
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
    let p_chain_addr = loaded_soft_priv_key.address("P", network_id)?;
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("checking the balance for {}\n", p_chain_addr)),
        ResetColor
    )?;
    let resp = rt
        .block_on(p::get_balance(&opt.http_rpc_ep, &p_chain_addr))
        .expect("failed to get balance");
    // ref. https://docs.avax.network/learn/platform-overview/transaction-fees/#fee-schedule
    let add_validator_fee = 0_u64;
    let stake_amount_in_nano_avax = opt.stake_amount_in_nano_avax;
    let total_cost = add_validator_fee + stake_amount_in_nano_avax;
    let total_cost_avax = (total_cost as f64) / units::AVAX as f64;
    let p_chain_balance = resp.result.unwrap().balance.unwrap();
    let p_chain_balance_avax = (p_chain_balance as f64) / units::AVAX as f64;
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
    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/wallet/chain/p/builder.go
    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/add_validator_tx.go#L263
    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L39 "stake"
    // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go#L355 "AddValidator"
    // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go#L614 "stake"
    println!();
    println!();
    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!(
            "checking inputs and outputs for the address '{}'\n",
            p_chain_addr
        )),
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

    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L60
    let soft_key_chain = soft_key::Keychain::new(vec![loaded_soft_priv_key.clone()]);

    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L65
    let mut transferable_inputs: Vec<avax::TransferableInput> = Vec::new();
    let mut staked_transferable_outputs: Vec<avax::TransferableOutput> = Vec::new();
    let mut returned_transferable_outputs: Vec<avax::TransferableOutput> = Vec::new();
    let mut signers: Vec<soft_key::Key> = Vec::new();

    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L71
    // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go#L650
    let amount_staked: u64 = 0_u64;
    for utxo in utxos.iter() {
        // no need to consume more locked AVAX
        // because it already has consumed more than the target stake amount
        if amount_staked >= opt.stake_amount_in_nano_avax {
            break;
        }
        // ignore other assets
        if utxo.asset_id != avax_asset_id {
            continue;
        }

        // check "*platformvm.StakeableLockOut"
        if utxo.stakeable_lock_out.is_none() {
            // output is not locked, thus handle this in the next iteration
            continue;
        }

        // check locktime
        let stakeable_lock_out = utxo.stakeable_lock_out.clone().unwrap();
        if stakeable_lock_out.locktime <= now_unix {
            // output is no longer locked, thus handle in the next iteration
            continue;
        }

        // check "*secp256k1fx.TransferOutpu"
        let transfer_output = stakeable_lock_out.clone().transfer_output;
        let res = soft_key_chain.spend(&transfer_output, now_unix);
        if res.is_none() {
            // cannot spend the output, move onto next
            continue;
        }
        let (transfer_input, input_signers) = res.unwrap();

        // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L117
        let remaining_value = transfer_input.amount;
        let amount_to_stake = (opt.stake_amount_in_nano_avax - amount_staked) // amount we still need to stake
            .min(
                remaining_value, // amount available to stake
            );

        // add input to the consumed inputs
        transferable_inputs.push(avax::TransferableInput {
            utxo_id: utxo.utxo_id.clone(),
            asset_id: utxo.asset_id.clone(),
            stakeable_lock_in: Some(platformvm::StakeableLockIn {
                locktime: stakeable_lock_out.locktime,
                transfer_input,
            }),
            ..avax::TransferableInput::default()
        });

        // add output to the staked outputs
        staked_transferable_outputs.push(avax::TransferableOutput {
            asset_id: utxo.asset_id.clone(),
            stakeable_lock_out: Some(platformvm::StakeableLockOut {
                locktime: stakeable_lock_out.clone().locktime,
                transfer_output: secp256k1fx::TransferOutput {
                    amount: amount_to_stake,
                    output_owners: stakeable_lock_out.clone().transfer_output.output_owners,
                },
            }),
            ..avax::TransferableOutput::default()
        });

        if remaining_value > 0 {
            // this input provided more value than was needed to be locked
            // some must be returned
            returned_transferable_outputs.push(avax::TransferableOutput {
                asset_id: utxo.asset_id.clone(),
                stakeable_lock_out: Some(platformvm::StakeableLockOut {
                    locktime: stakeable_lock_out.clone().locktime,
                    transfer_output: secp256k1fx::TransferOutput {
                        amount: remaining_value,
                        output_owners: stakeable_lock_out.clone().transfer_output.output_owners,
                    },
                }),
                ..avax::TransferableOutput::default()
            });
        }

        signers.extend_from_slice(&input_signers);
    }

    // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L166
    // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go#L732
    let mut amount_burned = 0_u64;
    for utxo in utxos.iter() {
        // have staked more AVAX then we need to
        // have burned more AVAX then we need to
        // no need to consume more AVAX
        if amount_staked >= opt.stake_amount_in_nano_avax && amount_burned >= add_validator_fee {
            break;
        }
        // ignore other assets
        if utxo.asset_id != avax_asset_id {
            continue;
        }

        if utxo.transfer_output.is_none() && utxo.stakeable_lock_out.is_none() {
            panic!("Both Utxo.transfer_output and stakeable_lock_out None");
        }
        let (skip, transfer_output) = {
            if utxo.transfer_output.is_some() {
                let transfer_output = utxo.transfer_output.clone().unwrap();
                (false, transfer_output)
            } else {
                let stakeable_lock_out = utxo.stakeable_lock_out.clone().unwrap();
                (
                    stakeable_lock_out.locktime > now_unix,
                    stakeable_lock_out.transfer_output,
                )
            }
        };
        // output is currently locked, so this output cannot be burned
        // or it may have already been consumed
        if skip {
            continue;
        }

        let res = soft_key_chain.spend(&transfer_output, now_unix);
        if res.is_none() {
            // cannot spend the output, move onto next
            continue;
        }
        let (transfer_input, input_signers) = res.unwrap();

        // ref. https://github.com/ava-labs/avalanchego/blob/v1.7.9/vms/platformvm/spend.go#L205
        // ref. https://github.com/ava-labs/subnet-cli/blob/6bbe9f4aff353b812822af99c08133af35dbc6bd/client/p.go#L763
        let mut remaining_value = transfer_input.amount;
        let amount_to_burn = (add_validator_fee - amount_burned) // amount we still need to burn
            .min(
                remaining_value, // amount available to burn
            );
        amount_burned += amount_to_burn;
        remaining_value -= amount_to_burn;

        let amount_to_stake = (opt.stake_amount_in_nano_avax - amount_staked) // amount we still need to stake
            .min(
                remaining_value, // amount available to stake
            );
        amount_burned += amount_to_stake;
        remaining_value -= amount_to_stake;

        if amount_to_stake > 0 {
            staked_transferable_outputs.push(avax::TransferableOutput {
                asset_id: utxo.asset_id.clone(),
                transfer_output: Some(secp256k1fx::TransferOutput {
                    amount: amount_to_stake,
                    output_owners: secp256k1fx::OutputOwners {
                        locktime: 0,
                        threshold: 1,
                        addrs: vec![loaded_soft_priv_key.clone().short_address],
                    },
                }),
                ..avax::TransferableOutput::default()
            });
        }

        if remaining_value > 0 {
            returned_transferable_outputs.push(avax::TransferableOutput {
                asset_id: utxo.asset_id.clone(),
                transfer_output: Some(secp256k1fx::TransferOutput {
                    amount: remaining_value,
                    output_owners: secp256k1fx::OutputOwners {
                        locktime: 0,
                        threshold: 1,
                        addrs: vec![loaded_soft_priv_key.clone().short_address],
                    },
                }),
                ..avax::TransferableOutput::default()
            });
        }

        transferable_inputs.push(avax::TransferableInput {
            utxo_id: utxo.utxo_id.clone(),
            asset_id: utxo.asset_id.clone(),
            transfer_input: Some(transfer_input),
            ..avax::TransferableInput::default()
        });
        signers.extend_from_slice(&input_signers);
    }

    if amount_staked > 0 && amount_staked < opt.stake_amount_in_nano_avax {
        panic!("insufficient balance for stake amount");
    }
    if amount_burned > 0 && amount_burned < add_validator_fee {
        panic!("insufficient balance for gas fee");
    }

    // TODO: sort "staked_transferable_outputs"
    // TODO: sort "returned_transferable_outputs"
    // TODO: sort "transferable_inputs"
    // TODO: sort "input_signers"

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
