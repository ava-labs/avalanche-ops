mod add_track_subnet;
mod default;
mod subnet_config;
mod subnet_evm;

use clap::{crate_version, Command};

const APP_NAME: &str = "avalanche-config";

fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Avalanche configuration tools")
        .subcommands(vec![
            add_track_subnet::command(),
            default::command(),
            subnet_evm::command(),
            subnet_config::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((add_track_subnet::NAME, sub_matches)) => {
            add_track_subnet::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("CONFIG_FILE_PATH")
                    .unwrap()
                    .clone(),
                &sub_matches.get_one::<String>("SUBNET_ID").unwrap().clone(),
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .expect("failed to execute 'add-track-subnet'");
        }

        Some((default::NAME, sub_matches)) => {
            let config_file_path =
                if let Some(p) = sub_matches.get_one::<String>("CONFIG_FILE_PATH") {
                    p.clone()
                } else {
                    random_manager::tmp_path(10, Some(".json")).unwrap()
                };

            default::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &config_file_path,
                &sub_matches
                    .get_one::<String>("NETWORK_NAME")
                    .unwrap()
                    .clone(),
            )
            .expect("failed to execute 'default'");
        }

        Some((subnet_config::NAME, sub_matches)) => {
            let opt = subnet_config::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                proposer_min_block_delay: sub_matches
                    .get_one::<u64>("PROPOSER_MIN_BLOCK_DELAY")
                    .unwrap_or(&1000000000)
                    .clone(),
                file_path: sub_matches
                    .get_one::<String>("FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
            };
            subnet_config::execute(opt).expect("failed to execute 'subnet-evm subnet-config'");
        }

        Some((subnet_evm::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((subnet_evm::chain_config::NAME, sub_sub_matches)) => {
                let s = sub_sub_matches
                    .get_one::<String>("PRIORITY_REGOSSIP_ADDRESSES")
                    .unwrap_or(&String::new())
                    .clone();
                let ss: Vec<&str> = s.split(',').collect();
                let mut priority_regossip_addresses = Vec::new();
                for addr in ss.iter() {
                    let trimmed = addr.trim().to_string();
                    if !trimmed.is_empty() {
                        priority_regossip_addresses.push(addr.trim().to_string());
                    }
                }

                let opt = subnet_evm::chain_config::Flags {
                    log_level: sub_sub_matches
                        .get_one::<String>("LOG_LEVEL")
                        .unwrap_or(&String::from("info"))
                        .clone(),

                    tx_pool_account_slots: sub_sub_matches
                        .get_one::<u64>("TX_POOL_ACCOUNT_SLOTS")
                        .unwrap_or(&0)
                        .clone(),
                    tx_pool_global_slots: sub_sub_matches
                        .get_one::<u64>("TX_POOL_GLOBAL_SLOTS")
                        .unwrap_or(&0)
                        .clone(),
                    tx_pool_account_queue: sub_sub_matches
                        .get_one::<u64>("TX_POOL_ACCOUNT_QUEUE")
                        .unwrap_or(&0)
                        .clone(),
                    tx_pool_global_queue: sub_sub_matches
                        .get_one::<u64>("TX_POOL_GLOBAL_QUEUE")
                        .unwrap_or(&0)
                        .clone(),
                    local_txs_enabled: sub_sub_matches.get_flag("LOCAL_TXS_ENABLED"),
                    priority_regossip_frequency: sub_sub_matches
                        .get_one::<i64>("PRIORITY_REGOSSIP_FREQUENCY")
                        .unwrap_or(&0)
                        .clone(),
                    priority_regossip_max_txs: sub_sub_matches
                        .get_one::<i32>("PRIORITY_REGOSSIP_MAX_TXS")
                        .unwrap_or(&0)
                        .clone(),
                    priority_regossip_txs_per_address: sub_sub_matches
                        .get_one::<i32>("PRIORITY_REGOSSIP_TXS_PER_ADDRESS")
                        .unwrap_or(&0)
                        .clone(),
                    priority_regossip_addresses,

                    file_path: sub_sub_matches
                        .get_one::<String>("FILE_PATH")
                        .unwrap_or(&String::new())
                        .clone(),
                };
                subnet_evm::chain_config::execute(opt)
                    .expect("failed to execute 'subnet-evm chain-config'");
            }

            Some((subnet_evm::genesis::NAME, sub_sub_matches)) => {
                let s = sub_sub_matches
                    .get_one::<String>("SEED_ETH_ADDRESSES")
                    .unwrap_or(&String::new())
                    .clone();
                let ss: Vec<&str> = s.split(',').collect();
                let mut seed_eth_addresses = Vec::new();
                for addr in ss.iter() {
                    let trimmed = addr.trim().to_string();
                    if !trimmed.is_empty() {
                        seed_eth_addresses.push(addr.trim().to_string());
                    }
                }

                let opt = subnet_evm::genesis::Flags {
                    log_level: sub_sub_matches
                        .get_one::<String>("LOG_LEVEL")
                        .unwrap_or(&String::from("info"))
                        .clone(),

                    seed_eth_addresses,
                    gas_limit: sub_sub_matches
                        .get_one::<u64>("GAS_LIMIT")
                        .unwrap_or(&0)
                        .clone(),
                    target_block_rate: sub_sub_matches
                        .get_one::<u64>("TARGET_BLOCK_RATE")
                        .unwrap_or(&0)
                        .clone(),
                    min_base_fee: sub_sub_matches
                        .get_one::<u64>("MIN_BASE_FEE")
                        .unwrap_or(&0)
                        .clone(),
                    target_gas: sub_sub_matches
                        .get_one::<u64>("TARGET_GAS")
                        .unwrap_or(&0)
                        .clone(),
                    base_fee_change_denominator: sub_sub_matches
                        .get_one::<u64>("BASE_FEE_CHANGE_DENOMINATOR")
                        .unwrap_or(&0)
                        .clone(),
                    min_block_gas_cost: sub_sub_matches
                        .get_one::<u64>("MIN_BLOCK_GAS_COST")
                        .unwrap_or(&0)
                        .clone(),
                    max_block_gas_cost: sub_sub_matches
                        .get_one::<u64>("MAX_BLOCK_GAS_COST")
                        .unwrap_or(&10_000_000)
                        .clone(),
                    block_gas_cost_step: sub_sub_matches
                        .get_one::<u64>("BLOCK_GAS_COST_STEP")
                        .unwrap_or(&0)
                        .clone(),

                    auto_contract_deployer_allow_list_config: sub_sub_matches
                        .get_flag("AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG"),
                    auto_contract_native_minter_config: sub_sub_matches
                        .get_flag("AUTO_CONTRACT_NATIVE_MINTER_CONFIG"),
                    auto_fee_manager_config: sub_sub_matches.get_flag("AUTO_FEE_MANAGER_CONFIG"),

                    file_path: sub_sub_matches
                        .get_one::<String>("FILE_PATH")
                        .unwrap_or(&String::new())
                        .clone(),
                };
                subnet_evm::genesis::execute(opt).expect("failed to execute 'subnet-evm genesis'");
            }

            _ => unreachable!("unknown subcommand"),
        },

        _ => unreachable!("unknown subcommand"),
    }
}
