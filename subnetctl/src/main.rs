use std::str::FromStr;

use clap::Command;

use avalanche_types::ids;
use utils::rfc3339;

mod add;
mod create;
mod get_utxos;
mod vm_id;

const APP_NAME: &str = "subnetctl";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("subnetctl (experimental subnet-cli)")
        .subcommands(vec![
            vm_id::command(),
            add::command(),
            create::command(),
            get_utxos::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((vm_id::NAME, sub_matches)) => {
            let opt = vm_id::Option {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                name: sub_matches.value_of("NAME").unwrap_or("").to_string(),
            };
            vm_id::execute(opt).unwrap();
        }

        Some((add::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((add::validator::NAME, sub_sub_matches)) => {
                let node_id = sub_sub_matches
                    .value_of("NODE_ID")
                    .unwrap_or("")
                    .to_string();
                let node_id = ids::NodeId::from_str(&node_id).unwrap();

                let private_key_path = {
                    let v = sub_sub_matches.value_of("PRIVATE_KEY_PATH").unwrap_or("");
                    if v.is_empty() {
                        None
                    } else {
                        Some(String::from(v))
                    }
                };

                let stake_amount = sub_sub_matches.value_of("STAKE_AMOUNT").unwrap_or("");
                let stake_amount = stake_amount.parse::<u64>().unwrap();

                let validate_reward_fee_percent = sub_sub_matches
                    .value_of("VALIDATE_REWARD_FEE_PERCENT")
                    .unwrap_or("");
                let validate_reward_fee_percent =
                    validate_reward_fee_percent.parse::<u32>().unwrap();

                let validate_end = sub_sub_matches.value_of("VALIDATE_END").unwrap_or("");
                let validate_end = rfc3339::parse(validate_end).unwrap();

                let opt = add::validator::CmdOption {
                    log_level: sub_sub_matches
                        .value_of("LOG_LEVEL")
                        .unwrap_or("info")
                        .to_string(),
                    http_rpc_ep: sub_sub_matches
                        .value_of("HTTP_RPC_ENDPOINT")
                        .unwrap_or("")
                        .to_string(),
                    private_key_path,
                    node_id,
                    stake_amount,
                    validate_end,
                    validate_reward_fee_percent,
                };
                add::validator::execute(opt).unwrap();
            }
            Some((add::subnet_validator::NAME, sub_sub_matches)) => {
                let subnet_id = sub_sub_matches
                    .value_of("SUBNET_ID")
                    .unwrap_or("")
                    .to_string();
                let subnet_id = ids::Id::from_str(&subnet_id).unwrap();

                let node_id = sub_sub_matches
                    .value_of("NODE_ID")
                    .unwrap_or("")
                    .to_string();
                let node_id = ids::NodeId::from_str(&node_id).unwrap();

                let validate_weight = sub_sub_matches
                    .value_of("VALIDATE_WEIGHT")
                    .unwrap_or("")
                    .to_string();
                let validate_weight = validate_weight.parse::<u64>().unwrap();

                let opt = add::subnet_validator::Option {
                    log_level: sub_sub_matches
                        .value_of("LOG_LEVEL")
                        .unwrap_or("info")
                        .to_string(),
                    http_rpc_ep: sub_sub_matches
                        .value_of("HTTP_RPC_ENDPOINT")
                        .unwrap_or("")
                        .to_string(),
                    subnet_id,
                    node_id,
                    validate_weight,
                };
                add::subnet_validator::execute(opt).unwrap();
            }
            _ => unreachable!("unknown subcommand"),
        },

        Some((create::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((create::subnet::NAME, sub_sub_matches)) => {
                let opt = create::subnet::Option {
                    log_level: sub_sub_matches
                        .value_of("LOG_LEVEL")
                        .unwrap_or("info")
                        .to_string(),
                    http_rpc_ep: sub_sub_matches
                        .value_of("HTTP_RPC_ENDPOINT")
                        .unwrap_or("")
                        .to_string(),
                };
                create::subnet::execute(opt).unwrap();
            }
            Some((create::blockchain::NAME, sub_sub_matches)) => {
                let subnet_id = sub_sub_matches
                    .value_of("SUBNET_ID")
                    .unwrap_or("")
                    .to_string();
                let subnet_id = ids::Id::from_str(&subnet_id).unwrap();

                let vm_id = sub_sub_matches.value_of("VM_ID").unwrap_or("").to_string();
                let vm_id = ids::Id::from_str(&vm_id).unwrap();

                let opt = create::blockchain::Option {
                    log_level: sub_sub_matches
                        .value_of("LOG_LEVEL")
                        .unwrap_or("info")
                        .to_string(),
                    http_rpc_ep: sub_sub_matches
                        .value_of("HTTP_RPC_ENDPOINT")
                        .unwrap_or("")
                        .to_string(),
                    subnet_id,
                    chain_name: sub_sub_matches
                        .value_of("CHAIN_NAME")
                        .unwrap_or("")
                        .to_string(),
                    vm_id,
                    vm_genesis_path: sub_sub_matches
                        .value_of("VM_GENESIS_PATH")
                        .unwrap_or("")
                        .to_string(),
                };
                create::blockchain::execute(opt).unwrap();
            }
            _ => unreachable!("unknown subcommand"),
        },

        Some((get_utxos::NAME, sub_matches)) => {
            let opt = get_utxos::Option {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                http_rpc_ep: sub_matches
                    .value_of("HTTP_RPC_ENDPOINT")
                    .unwrap_or("")
                    .to_string(),
                paddr: sub_matches
                    .value_of("P_CHAIN_ADDRESS")
                    .unwrap_or("")
                    .to_string(),
            };
            get_utxos::execute(opt).unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
