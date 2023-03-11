mod apply;
mod default_spec;
mod delete;

use std::io;

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
                rust_os_type: sub_matches
                    .get_one::<String>("RUST_OS_TYPE")
                    .unwrap()
                    .to_string(),

                anchor_nodes: sub_matches
                    .get_one::<u32>("ANCHOR_NODES")
                    .unwrap_or(&0)
                    .clone(),
                non_anchor_nodes: sub_matches
                    .get_one::<u32>("NON_ANCHOR_NODES")
                    .unwrap_or(&0)
                    .clone(),

                key_files_dir: sub_matches
                    .get_one::<String>("KEY_FILES_DIR")
                    .unwrap_or(&String::new())
                    .to_string(),
                keys_to_generate: sub_matches
                    .get_one::<usize>("KEYS_TO_GENERATE")
                    .unwrap_or(&5)
                    .clone(),

                region: sub_matches.get_one::<String>("REGION").unwrap().clone(),

                instance_mode: sub_matches
                    .get_one::<String>("INSTANCE_MODE")
                    .unwrap()
                    .clone(),
                instance_size: sub_matches
                    .get_one::<String>("INSTANCE_SIZE")
                    .unwrap_or(&String::from("large"))
                    .clone(),

                volume_size_in_gb: sub_matches
                    .get_one::<u32>("VOLUME_SIZE_IN_GB")
                    .unwrap_or(&300)
                    .clone(),

                ip_mode: sub_matches
                    .get_one::<String>("IP_MODE")
                    .unwrap_or(&String::new())
                    .to_string(),

                enable_nlb: sub_matches.get_flag("ENABLE_NLB"),
                disable_logs_auto_removal: sub_matches.get_flag("DISABLE_LOGS_AUTO_REMOVAL"),
                metrics_fetch_interval_seconds: sub_matches
                    .get_one::<u64>("METRICS_FETCH_INTERVAL_SECONDS")
                    .unwrap_or(&0)
                    .clone(),

                aad_tag: sub_matches
                    .get_one::<String>("AAD_TAG")
                    .unwrap()
                    .to_string(),

                nlb_acm_certificate_arn: sub_matches
                    .get_one::<String>("NLB_ACM_CERTIFICATE_ARN")
                    .unwrap_or(&String::new())
                    .to_string(),

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

                upload_artifacts_avalanche_config_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHE_CONFIG_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_avalanched_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHED_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_avalanche_local_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_AVALANCHE_LOCAL_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_plugin_local_dir: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_PLUGIN_LOCAL_DIR")
                    .unwrap_or(&String::new())
                    .to_string(),
                upload_artifacts_prometheus_metrics_rules_file_path: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_PROMETHEUS_METRICS_RULES_FILE_PATH")
                    .unwrap_or(&String::new())
                    .to_string(),

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

                subnet_evms: sub_matches
                    .get_one::<usize>("SUBNET_EVMS")
                    .unwrap_or(&0)
                    .clone(),

                subnet_evm_gas_limit: sub_matches
                    .get_one::<u64>("SUBNET_EVM_GAS_LIMIT")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_target_block_rate: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TARGET_BLOCK_RATE")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_min_base_fee: sub_matches
                    .get_one::<u64>("SUBNET_EVM_MIN_BASE_FEE")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_target_gas: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TARGET_GAS")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_base_fee_change_denominator: sub_matches
                    .get_one::<u64>("SUBNET_EVM_BASE_FEE_CHANGE_DENOMINATOR")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_min_block_gas_cost: sub_matches
                    .get_one::<u64>("SUBNET_EVM_MIN_BLOCK_GAS_COST")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_max_block_gas_cost: sub_matches
                    .get_one::<u64>("SUBNET_EVM_MAX_BLOCK_GAS_COST")
                    .unwrap_or(&10_000_000)
                    .clone(),
                subnet_evm_block_gas_cost_step: sub_matches
                    .get_one::<u64>("SUBNET_EVM_BLOCK_GAS_COST_STEP")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_tx_pool_account_slots: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TX_POOL_ACCOUNT_SLOTS")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_tx_pool_global_slots: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TX_POOL_GLOBAL_SLOTS")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_tx_pool_account_queue: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TX_POOL_ACCOUNT_QUEUE")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_tx_pool_global_queue: sub_matches
                    .get_one::<u64>("SUBNET_EVM_TX_POOL_GLOBAL_QUEUE")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_local_txs_enabled: sub_matches.get_flag("SUBNET_EVM_LOCAL_TXS_ENABLED"),
                subnet_evm_priority_regossip_frequency: sub_matches
                    .get_one::<i64>("SUBNET_EVM_PRIORITY_REGOSSIP_FREQUENCY")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_priority_regossip_max_txs: sub_matches
                    .get_one::<i32>("SUBNET_EVM_PRIORITY_REGOSSIP_MAX_TXS")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_priority_regossip_txs_per_address: sub_matches
                    .get_one::<i32>("SUBNET_EVM_PRIORITY_REGOSSIP_TXS_PER_ADDRESS")
                    .unwrap_or(&0)
                    .clone(),
                subnet_evm_priority_regossip_addresses,

                subnet_evm_auto_contract_deployer_allow_list_config: sub_matches
                    .get_flag("SUBNET_EVM_AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG"),
                subnet_evm_auto_contract_native_minter_config: sub_matches
                    .get_flag("SUBNET_EVM_AUTO_CONTRACT_NATIVE_MINTER_CONFIG"),
                subnet_evm_proposer_min_block_delay: sub_matches
                    .get_one::<u64>("SUBNET_EVM_PROPOSER_MIN_BLOCK_DELAY")
                    .unwrap_or(&1000000000)
                    .clone(),

                xsvms: sub_matches.get_one::<usize>("XSVMS").unwrap_or(&0).clone(),

                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
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

        _ => unreachable!("unknown subcommand"),
    }

    Ok(())
}
