mod apply;
mod default_spec;
mod delete;

use clap::{crate_version, Command};

const APP_NAME: &str = "avalancheup-aws";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
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
            let keys_to_generate = sub_matches
                .get_one::<usize>("KEYS_TO_GENERATE")
                .unwrap_or(&5)
                .clone();

            let volume_size_in_gb = sub_matches
                .get_one::<u32>("VOLUME_SIZE_IN_GB")
                .unwrap_or(&300)
                .clone();

            let metrics_fetch_interval_seconds = sub_matches
                .get_one::<u64>("METRICS_FETCH_INTERVAL_SECONDS")
                .unwrap_or(&3600)
                .clone();

            let preferred_az_index = sub_matches
                .get_one::<usize>("PREFERRED_AZ_INDEX")
                .unwrap_or(&0)
                .clone();

            let subnet_evm_gas_limit = sub_matches
                .get_one::<u64>("SUBNET_EVM_GAS_LIMIT")
                .unwrap_or(&8000000)
                .clone();

            let opt = avalancheup_aws::DefaultSpecOption {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                network_name: sub_matches
                    .get_one::<String>("NETWORK_NAME")
                    .unwrap_or(&String::new())
                    .clone(),

                key_files_dir: sub_matches
                    .get_one::<String>("KEY_FILES_DIR")
                    .unwrap_or(&String::new())
                    .to_string(),
                keys_to_generate,

                region: sub_matches.get_one::<String>("REGION").unwrap().clone(),
                preferred_az_index,

                instance_mode: sub_matches
                    .get_one::<String>("INSTANCE_MODE")
                    .unwrap()
                    .clone(),
                disable_spot_instance_for_anchor_nodes: sub_matches
                    .get_flag("DISABLE_SPOT_INSTANCE_FOR_ANCHOR_NODES"),

                volume_size_in_gb,

                ip_mode: sub_matches
                    .get_one::<String>("IP_MODE")
                    .unwrap_or(&String::new())
                    .to_string(),

                enable_nlb: sub_matches.get_flag("ENABLE_NLB"),
                disable_logs_auto_removal: sub_matches.get_flag("DISABLE_LOGS_AUTO_REMOVAL"),
                metrics_fetch_interval_seconds,

                aad_tag: sub_matches
                    .get_one::<String>("AAD_TAG")
                    .unwrap()
                    .to_string(),

                nlb_acm_certificate_arn: sub_matches
                    .get_one::<String>("NLB_ACM_CERTIFICATE_ARN")
                    .unwrap_or(&String::new())
                    .to_string(),

                install_artifacts_aws_volume_provisioner_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_AWS_VOLUME_PROVISIONER_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                install_artifacts_aws_ip_provisioner_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_AWS_IP_PROVISIONER_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                install_artifacts_avalanche_telemetry_cloudwatch_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_AVALANCHE_TELEMETRY_CLOUDWATCH_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),

                install_artifacts_avalanched_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_AVALANCHED_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                install_artifacts_avalanche_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                install_artifacts_plugins_dir: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_PLUGINS_DIR")
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

                coreth_metrics_enabled: sub_matches.get_flag("CORETH_METRICS_ENABLED"),
                coreth_continuous_profiler_enabled: sub_matches
                    .get_flag("CORETH_CONTINUOUS_PROFILER_ENABLED"),
                coreth_offline_pruning_enabled: sub_matches
                    .get_flag("CORETH_OFFLINE_PRUNING_ENABLED"),
                coreth_state_sync_enabled: sub_matches.get_flag("CORETH_STATE_SYNC_ENABLED"),
                coreth_state_sync_metrics_enabled: sub_matches
                    .get_flag("CORETH_STATE_SYNC_METRICS_ENABLED"),

                enable_subnet_evm: sub_matches.get_flag("ENABLE_SUBNET_EVM"),

                subnet_evm_gas_limit,
                subnet_evm_auto_contract_deployer_allow_list_config: sub_matches
                    .get_flag("SUBNET_EVM_AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG"),
                subnet_evm_auto_contract_native_minter_config: sub_matches
                    .get_flag("SUBNET_EVM_AUTO_CONTRACT_NATIVE_MINTER_CONFIG"),
                subnet_evm_auto_fee_manager_config: sub_matches
                    .get_flag("SUBNET_EVM_AUTO_FEE_MANAGER_CONFIG"),
                subnet_evm_config_proposer_min_block_delay_seconds: sub_matches
                    .get_one::<u64>("SUBNET_EVM_CONFIG_PROPOSER_MIN_BLOCK_DELAY")
                    .unwrap_or(&1)
                    .clone(),

                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
            };
            default_spec::execute(opt).expect("failed to execute 'default-spec'");
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
            .expect("failed to execute 'delete'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
