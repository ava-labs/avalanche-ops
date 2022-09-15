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
        .about("Avalanche node operations on AWS")
        .subcommands(vec![
            default_spec::command(),
            apply::command(),
            delete::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let keys_to_generate = sub_matches.value_of("KEYS_TO_GENERATE").unwrap_or("");
            let keys_to_generate = keys_to_generate.parse::<usize>().unwrap();

            let volume_size_in_gb = sub_matches.value_of("VOLUME_SIZE_IN_GB").unwrap_or("0");
            let volume_size_in_gb = volume_size_in_gb.parse::<u32>().unwrap();

            let preferred_az_index = sub_matches.value_of("PREFERRED_AZ_INDEX").unwrap_or("0");
            let preferred_az_index = preferred_az_index.parse::<usize>().unwrap();

            let subnet_evm_gas_limit = sub_matches.value_of("SUBNET_EVM_GAS_LIMIT").unwrap_or("0");
            let subnet_evm_gas_limit = subnet_evm_gas_limit.parse::<u64>().unwrap();

            let opt = avalancheup_aws::DefaultSpecOption {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                network_name: sub_matches
                    .value_of("NETWORK_NAME")
                    .unwrap_or("")
                    .to_string(),
                keys_to_generate,

                region: sub_matches.value_of("REGION").unwrap().to_string(),
                preferred_az_index,

                use_spot_instance: sub_matches.is_present("USE_SPOT_INSTANCE"),
                disable_spot_instance_for_anchor_nodes: sub_matches
                    .is_present("DISABLE_SPOT_INSTANCE_FOR_ANCHOR_NODES"),
                disable_nlb: sub_matches.is_present("DISABLE_NLB"),
                volume_size_in_gb,

                key_files_dir: sub_matches
                    .value_of("KEY_FILES_DIR")
                    .unwrap_or("")
                    .to_string(),
                aad_tag: sub_matches.value_of("AAD_TAG").unwrap().to_string(),

                nlb_acm_certificate_arn: sub_matches
                    .value_of("NLB_ACM_CERTIFICATE_ARN")
                    .unwrap_or("")
                    .to_string(),

                install_artifacts_avalanched_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHED_BIN")
                    .unwrap_or("")
                    .to_string(),
                install_artifacts_avalanche_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                    .unwrap_or("")
                    .to_string(),
                install_artifacts_plugins_dir: sub_matches
                    .value_of("INSTALL_ARTIFACTS_PLUGINS_DIR")
                    .unwrap_or("")
                    .to_string(),

                avalanched_log_level: sub_matches
                    .value_of("AVALANCHED_LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                avalanched_use_default_config: sub_matches
                    .is_present("AVALANCHED_USE_DEFAULT_CONFIG"),
                avalanched_skip_publish_node_info: sub_matches
                    .is_present("AVALANCHED_SKIP_PUBLISH_NODE_INFO"),

                avalanchego_log_level: sub_matches
                    .value_of("AVALANCHEGO_LOG_LEVEL")
                    .unwrap_or("INFO")
                    .to_string(),
                avalanchego_whitelisted_subnets: sub_matches
                    .value_of("AVALANCHEGO_WHITELISTED_SUBNETS")
                    .unwrap_or("")
                    .to_string(),
                avalanchego_http_tls_enabled: sub_matches
                    .is_present("AVALANCHEGO_HTTP_TLS_ENABLED"),
                avalanchego_state_sync_ids: sub_matches
                    .value_of("AVALANCHEGO_STATE_SYNC_IDS")
                    .unwrap_or("")
                    .to_string(),
                avalanchego_state_sync_ips: sub_matches
                    .value_of("AVALANCHEGO_STATE_SYNC_IPS")
                    .unwrap_or("")
                    .to_string(),
                avalanchego_profile_continuous_enabled: sub_matches
                    .is_present("AVALANCHEGO_PROFILE_CONTINUOUS_ENABLED"),
                avalanchego_profile_continuous_freq: sub_matches
                    .value_of("AVALANCHEGO_PROFILE_CONTINUOUS_FREQ")
                    .unwrap_or("")
                    .to_string(),
                avalanchego_profile_continuous_max_files: sub_matches
                    .value_of("AVALANCHEGO_PROFILE_CONTINUOUS_MAX_FILES")
                    .unwrap_or("")
                    .to_string(),

                coreth_metrics_enabled: sub_matches.is_present("CORETH_METRICS_ENABLED"),
                coreth_continuous_profiler_enabled: sub_matches
                    .is_present("CORETH_CONTINUOUS_PROFILER_ENABLED"),
                coreth_offline_pruning_enabled: sub_matches
                    .is_present("CORETH_OFFLINE_PRUNING_ENABLED"),
                coreth_state_sync_enabled: sub_matches.is_present("CORETH_STATE_SYNC_ENABLED"),
                coreth_state_sync_metrics_enabled: sub_matches
                    .is_present("CORETH_STATE_SYNC_METRICS_ENABLED"),

                enable_subnet_evm: sub_matches.is_present("ENABLE_SUBNET_EVM"),

                subnet_evm_gas_limit,
                subnet_evm_auto_contract_deployer_allow_list_config: sub_matches
                    .is_present("SUBNET_EVM_AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG"),
                subnet_evm_auto_contract_native_minter_config: sub_matches
                    .is_present("SUBNET_EVM_AUTO_CONTRACT_NATIVE_MINTER_CONFIG"),
                subnet_evm_auto_fee_manager_config: sub_matches
                    .is_present("SUBNET_EVM_AUTO_FEE_MANAGER_CONFIG"),

                spec_file_path: sub_matches
                    .value_of("SPEC_FILE_PATH")
                    .unwrap_or("")
                    .to_string(),
            };
            default_spec::execute(opt).expect("failed to execute 'default-spec'");
        }

        Some((apply::NAME, sub_matches)) => {
            apply::execute(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .expect("failed to execute 'apply'");
        }

        Some((delete::NAME, sub_matches)) => {
            delete::execute(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("DELETE_CLOUDWATCH_LOG_GROUP"),
                sub_matches.is_present("DELETE_S3_OBJECTS"),
                sub_matches.is_present("DELETE_S3_BUCKET"),
                sub_matches.is_present("DELETE_EBS_VOLUMES"),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .expect("failed to execute 'delete'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
