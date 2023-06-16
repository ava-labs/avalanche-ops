mod add_primary_network_validators;
mod apply;
mod default_spec;
mod delete;
mod endpoints;
mod install_subnet_chain;
mod subnet_config;
mod subnet_evm;

use std::{collections::HashMap, io};

use clap::{crate_version, Command};

const APP_NAME: &str = "avalancheup-aws";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("AvalancheUp control plane on AWS (requires avalanched)")
        .subcommands(vec![
            default_spec::command(),
            apply::command(),
            delete::command(),
            add_primary_network_validators::command(),
            install_subnet_chain::command(),
            subnet_evm::command(),
            subnet_config::command(),
            endpoints::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let s = sub_matches
                .get_one::<String>("SUBNET_EVM_PRIORITY_REGOSSIP_ADDRESSES")
                .unwrap_or(&String::new())
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut subnet_evm_priority_regossip_addresses = Vec::new();
            for addr in ss.iter() {
                let trimmed = addr.trim().to_string();
                if !trimmed.is_empty() {
                    subnet_evm_priority_regossip_addresses.push(addr.trim().to_string());
                }
            }

            let instance_types: HashMap<String, Vec<String>> = sub_matches
                .get_one::<HashMap<String, Vec<String>>>("INSTANCE_TYPES")
                .unwrap_or(&HashMap::new())
                .clone();

            let nlb_acm_certificate_arns: HashMap<String, String> = sub_matches
                .get_one::<HashMap<String, String>>("NLB_ACM_CERTIFICATE_ARNS")
                .unwrap_or(&HashMap::new())
                .clone();

            let s = sub_matches
                .get_one::<String>("REGIONS")
                .unwrap_or(&String::new())
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut regions = Vec::new();
            for addr in ss.iter() {
                let trimmed = addr.trim().to_string();
                if !trimmed.is_empty() {
                    regions.push(addr.trim().to_string());
                }
            }

            let opt = avalanche_ops::aws::spec::DefaultSpecOption {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                network_name: sub_matches
                    .get_one::<String>("NETWORK_NAME")
                    .unwrap_or(&String::new())
                    .clone(),

                arch_type: sub_matches
                    .get_one::<String>("ARCH_TYPE")
                    .unwrap()
                    .to_string(),
                os_type: sub_matches
                    .get_one::<String>("OS_TYPE")
                    .unwrap()
                    .to_string(),

                anchor_nodes: *sub_matches.get_one::<u32>("ANCHOR_NODES").unwrap_or(&0),
                non_anchor_nodes: *sub_matches.get_one::<u32>("NON_ANCHOR_NODES").unwrap_or(&0),

                key_files_dir: sub_matches
                    .get_one::<String>("KEY_FILES_DIR")
                    .unwrap_or(&String::new())
                    .to_string(),
                keys_to_generate: *sub_matches
                    .get_one::<usize>("KEYS_TO_GENERATE")
                    .unwrap_or(&5),

                regions,
                auto_regions: *sub_matches.get_one::<u32>("AUTO_REGIONS").unwrap_or(&0),

                keep_resources_except_asg_ssm: sub_matches
                    .get_flag("KEEP_RESOURCES_EXCEPT_ASG_SSM"),
                create_dev_machine: sub_matches.get_flag("CREATE_DEV_MACHINE"),
                dev_machine_ssh_key_email: sub_matches
                    .get_one::<String>("DEV_MACHINE_SSH_KEY_EMAIL")
                    .unwrap_or(&String::new())
                    .clone(),

                ingress_ipv4_cidr: sub_matches
                    .get_one::<String>("INGRESS_IPV4_CIDR")
                    .unwrap_or(&String::new())
                    .clone(),

                instance_mode: sub_matches
                    .get_one::<String>("INSTANCE_MODE")
                    .unwrap()
                    .clone(),
                instance_size: sub_matches
                    .get_one::<String>("INSTANCE_SIZE")
                    .unwrap_or(&String::from("large"))
                    .clone(),
                instance_types,

                volume_size_in_gb: *sub_matches
                    .get_one::<u32>("VOLUME_SIZE_IN_GB")
                    .unwrap_or(&300),

                ip_mode: sub_matches
                    .get_one::<String>("IP_MODE")
                    .unwrap_or(&String::new())
                    .to_string(),

                enable_nlb: sub_matches.get_flag("ENABLE_NLB"),
                disable_logs_auto_removal: sub_matches.get_flag("DISABLE_LOGS_AUTO_REMOVAL"),
                metrics_fetch_interval_seconds: *sub_matches
                    .get_one::<u64>("METRICS_FETCH_INTERVAL_SECONDS")
                    .unwrap_or(&0),
                primary_network_validate_period_in_days: *sub_matches
                    .get_one::<u64>("PRIMARY_NETWORK_VALIDATE_PERIOD_IN_DAYS")
                    .unwrap_or(&16),

                aad_tag: sub_matches
                    .get_one::<String>("AAD_TAG")
                    .unwrap()
                    .to_string(),

                nlb_acm_certificate_arns,

                upload_artifacts_aws_volume_provisioner_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AWS_VOLUME_PROVISIONER_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_aws_ip_provisioner_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AWS_IP_PROVISIONER_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_avalanche_telemetry_cloudwatch_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHE_TELEMETRY_CLOUDWATCH_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),

                upload_artifacts_avalanched_aws_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHED_AWS_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_avalanchego_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHEGO_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_prometheus_metrics_rules_file_path: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_PROMETHEUS_METRICS_RULES_FILE_PATH")
                    .unwrap_or(&String::new())
                    .to_string(),

                avalanchego_release_tag: sub_matches
                    .get_one::<String>("AVALANCHEGO_RELEASE_TAG")
                    .unwrap_or(&String::new())
                    .clone(),

                avalanched_log_level: sub_matches
                    .get_one::<String>("AVALANCHED_LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                avalanched_use_default_config: sub_matches
                    .get_flag("AVALANCHED_USE_DEFAULT_CONFIG"),
                avalanched_publish_periodic_node_info: sub_matches
                    .get_flag("AVALANCHED_PUBLISH_PERIODIC_NODE_INFO"),

                avalanchego_log_level: sub_matches
                    .get_one::<String>("AVALANCHEGO_LOG_LEVEL")
                    .unwrap_or(&String::from("INFO"))
                    .clone(),
                avalanchego_http_tls_enabled: sub_matches.get_flag("AVALANCHEGO_HTTP_TLS_ENABLED"),
                avalanchego_state_sync_ids: sub_matches
                    .get_one::<String>("AVALANCHEGO_STATE_SYNC_IDS")
                    .unwrap_or(&String::new())
                    .clone(),
                avalanchego_state_sync_ips: sub_matches
                    .get_one::<String>("AVALANCHEGO_STATE_SYNC_IPS")
                    .unwrap_or(&String::new())
                    .clone(),
                avalanchego_profile_continuous_enabled: sub_matches
                    .get_flag("AVALANCHEGO_PROFILE_CONTINUOUS_ENABLED"),
                avalanchego_profile_continuous_freq: sub_matches
                    .get_one::<String>("AVALANCHEGO_PROFILE_CONTINUOUS_FREQ")
                    .unwrap_or(&String::new())
                    .clone(),
                avalanchego_profile_continuous_max_files: sub_matches
                    .get_one::<String>("AVALANCHEGO_PROFILE_CONTINUOUS_MAX_FILES")
                    .unwrap_or(&String::new())
                    .clone(),

                coreth_continuous_profiler_enabled: sub_matches
                    .get_flag("CORETH_CONTINUOUS_PROFILER_ENABLED"),
                coreth_offline_pruning_enabled: sub_matches
                    .get_flag("CORETH_OFFLINE_PRUNING_ENABLED"),
                coreth_state_sync_enabled: sub_matches.get_flag("CORETH_STATE_SYNC_ENABLED"),

                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
                profile_name: sub_matches
                    .get_one::<String>("PROFILE_NAME")
                    .unwrap_or(&String::from("default"))
                    .clone(),
            };
            default_spec::execute(opt)
                .await
                .expect("failed to execute 'default-spec'");
        }

        Some((apply::NAME, sub_matches)) => {
            apply::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .expect("failed to execute 'apply'");
        }

        Some((delete::NAME, sub_matches)) => {
            delete::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
                sub_matches.get_flag("OVERRIDE_KEEP_RESOURCES_EXCEPT_ASG_SSM"),
                sub_matches.get_flag("DELETE_CLOUDWATCH_LOG_GROUP"),
                sub_matches.get_flag("DELETE_S3_OBJECTS"),
                sub_matches.get_flag("DELETE_S3_BUCKET"),
                sub_matches.get_flag("DELETE_EBS_VOLUMES"),
                sub_matches.get_flag("DELETE_ELASTIC_IPS"),
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .expect("failed to execute 'delete'");
        }

        Some((add_primary_network_validators::NAME, sub_matches)) => {
            let s = sub_matches
                .get_one::<String>("TARGET_NODE_IDS")
                .unwrap_or(&String::new())
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut target_node_ids = Vec::new();
            for addr in ss.iter() {
                let trimmed = addr.trim().to_string();
                if !trimmed.is_empty() {
                    target_node_ids.push(addr.trim().to_string());
                }
            }

            add_primary_network_validators::execute(add_primary_network_validators::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),

                skip_prompt: sub_matches.get_flag("SKIP_PROMPT"),
                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),

                chain_rpc_url: sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap()
                    .clone(),
                key: sub_matches.get_one::<String>("KEY").unwrap().clone(),

                primary_network_validate_period_in_days: *sub_matches
                    .get_one::<u64>("PRIMARY_NETWORK_VALIDATE_PERIOD_IN_DAYS")
                    .unwrap_or(&16),
                staking_amount_in_avax: *sub_matches
                    .get_one::<u64>("STAKING_AMOUNT_IN_AVAX")
                    .unwrap_or(&2000),

                target_node_ids,
            })
            .await
            .expect("failed to execute 'add-primary-network-validators'");
        }

        Some((install_subnet_chain::NAME, sub_matches)) => {
            let ssm_docs: HashMap<String, String> = sub_matches
                .get_one::<HashMap<String, String>>("SSM_DOCS")
                .unwrap_or(&HashMap::new())
                .clone();
            let target_nodes: HashMap<String, avalanche_ops::aws::spec::RegionMachineId> =
                sub_matches
                    .get_one::<HashMap<String, avalanche_ops::aws::spec::RegionMachineId>>(
                        "TARGET_NODES",
                    )
                    .unwrap_or(&HashMap::new())
                    .clone();

            install_subnet_chain::execute(install_subnet_chain::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),

                skip_prompt: sub_matches.get_flag("SKIP_PROMPT"),
                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),

                s3_region: sub_matches.get_one::<String>("S3_REGION").unwrap().clone(),
                s3_bucket: sub_matches.get_one::<String>("S3_BUCKET").unwrap().clone(),
                s3_key_prefix: sub_matches
                    .get_one::<String>("S3_KEY_PREFIX")
                    .unwrap_or(&String::new())
                    .clone(),
                s3_upload_timeout: sub_matches
                    .get_one::<u64>("S3_UPLOAD_TIMEOUT")
                    .unwrap_or(&30)
                    .clone(),

                chain_rpc_url: sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap()
                    .clone(),
                key: sub_matches.get_one::<String>("KEY").unwrap().clone(),

                primary_network_validate_period_in_days: *sub_matches
                    .get_one::<u64>("PRIMARY_NETWORK_VALIDATE_PERIOD_IN_DAYS")
                    .unwrap_or(&16),
                subnet_validate_period_in_days: *sub_matches
                    .get_one::<u64>("SUBNET_VALIDATE_PERIOD_IN_DAYS")
                    .unwrap_or(&14),
                staking_amount_in_avax: *sub_matches
                    .get_one::<u64>("STAKING_AMOUNT_IN_AVAX")
                    .unwrap_or(&2000),

                subnet_config_local_path: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_LOCAL_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
                subnet_config_remote_dir: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_REMOTE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),

                vm_binary_local_path: sub_matches
                    .get_one::<String>("VM_BINARY_LOCAL_PATH")
                    .unwrap()
                    .clone(),
                vm_binary_remote_dir: sub_matches
                    .get_one::<String>("VM_BINARY_REMOTE_DIR")
                    .unwrap()
                    .clone(),

                vm_id: sub_matches
                    .get_one::<String>("VM_ID")
                    .unwrap_or(&String::new())
                    .clone(),
                chain_name: sub_matches.get_one::<String>("CHAIN_NAME").unwrap().clone(),
                chain_genesis_path: sub_matches
                    .get_one::<String>("CHAIN_GENESIS_PATH")
                    .unwrap()
                    .clone(),

                chain_config_local_path: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_LOCAL_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
                chain_config_remote_dir: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_REMOTE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),

                avalanchego_config_remote_path: sub_matches
                    .get_one::<String>("AVALANCHEGO_CONFIG_REMOTE_PATH")
                    .unwrap()
                    .clone(),

                ssm_docs,
                target_nodes,
                profile_name: sub_matches
                    .get_one::<String>("PROFILE_NAME")
                    .unwrap()
                    .clone(),
            })
            .await
            .expect("failed to execute 'install-subnet-chain'");
        }

        Some((subnet_config::NAME, sub_matches)) => {
            let opt = subnet_config::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                proposer_min_block_delay: *sub_matches
                    .get_one::<u64>("PROPOSER_MIN_BLOCK_DELAY")
                    .unwrap_or(&1000000000),
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

                    tx_pool_account_slots: *sub_sub_matches
                        .get_one::<u64>("TX_POOL_ACCOUNT_SLOTS")
                        .unwrap_or(&0),
                    tx_pool_global_slots: *sub_sub_matches
                        .get_one::<u64>("TX_POOL_GLOBAL_SLOTS")
                        .unwrap_or(&0),
                    tx_pool_account_queue: *sub_sub_matches
                        .get_one::<u64>("TX_POOL_ACCOUNT_QUEUE")
                        .unwrap_or(&0),
                    tx_pool_global_queue: *sub_sub_matches
                        .get_one::<u64>("TX_POOL_GLOBAL_QUEUE")
                        .unwrap_or(&0),
                    local_txs_enabled: sub_sub_matches.get_flag("LOCAL_TXS_ENABLED"),
                    priority_regossip_frequency: *sub_sub_matches
                        .get_one::<i64>("PRIORITY_REGOSSIP_FREQUENCY")
                        .unwrap_or(&0),
                    priority_regossip_max_txs: *sub_sub_matches
                        .get_one::<i32>("PRIORITY_REGOSSIP_MAX_TXS")
                        .unwrap_or(&0),
                    priority_regossip_txs_per_address: *sub_sub_matches
                        .get_one::<i32>("PRIORITY_REGOSSIP_TXS_PER_ADDRESS")
                        .unwrap_or(&0),
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
                    .unwrap()
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
                    gas_limit: *sub_sub_matches.get_one::<u64>("GAS_LIMIT").unwrap_or(&0),
                    target_block_rate: *sub_sub_matches
                        .get_one::<u64>("TARGET_BLOCK_RATE")
                        .unwrap_or(&0),
                    min_base_fee: *sub_sub_matches.get_one::<u64>("MIN_BASE_FEE").unwrap_or(&0),
                    target_gas: *sub_sub_matches.get_one::<u64>("TARGET_GAS").unwrap_or(&0),
                    base_fee_change_denominator: *sub_sub_matches
                        .get_one::<u64>("BASE_FEE_CHANGE_DENOMINATOR")
                        .unwrap_or(&0),
                    min_block_gas_cost: *sub_sub_matches
                        .get_one::<u64>("MIN_BLOCK_GAS_COST")
                        .unwrap_or(&0),
                    max_block_gas_cost: *sub_sub_matches
                        .get_one::<u64>("MAX_BLOCK_GAS_COST")
                        .unwrap_or(&10_000_000),
                    block_gas_cost_step: *sub_sub_matches
                        .get_one::<u64>("BLOCK_GAS_COST_STEP")
                        .unwrap_or(&0),

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

        Some((endpoints::NAME, sub_matches)) => {
            let s = sub_matches
                .get_one::<String>("CHAIN_RPC_URLS")
                .unwrap()
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut chain_rpc_urls: Vec<String> = Vec::new();
            for rpc in ss.iter() {
                let trimmed = rpc.trim().to_string();
                if !trimmed.is_empty() {
                    chain_rpc_urls.push(trimmed);
                }
            }

            endpoints::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                chain_rpc_urls,
            )
            .await
            .expect("failed to execute 'endpoints'");
        }

        _ => unreachable!("unknown subcommand"),
    }

    Ok(())
}
