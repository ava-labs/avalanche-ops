use clap::Command;

mod apply;
mod check_balances;
mod default_spec;
mod delete;
mod events;
mod read_spec;

const NAME: &str = "avalanche-ops-aws";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(NAME)
        .about("Avalanche node operations on AWS")
        .subcommands(vec![
            default_spec::command(),
            read_spec::command(),
            check_balances::command(),
            events::command(),
            apply::command(),
            delete::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let keys_to_generate = sub_matches.value_of("KEYS_TO_GENERATE").unwrap_or("");
            let keys_to_generate = keys_to_generate.parse::<usize>().unwrap();
            let opt = avalanche_ops_aws::DefaultSpecOption {
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

                db_backup_s3_region: sub_matches
                    .value_of("DB_BACKUP_S3_REGION")
                    .unwrap_or("")
                    .to_string(),
                db_backup_s3_bucket: sub_matches
                    .value_of("DB_BACKUP_S3_BUCKET")
                    .unwrap_or("")
                    .to_string(),
                db_backup_s3_key: sub_matches
                    .value_of("DB_BACKUP_S3_KEY")
                    .unwrap_or("")
                    .to_string(),

                nlb_acm_certificate_arn: sub_matches
                    .value_of("NLB_ACM_CERTIFICATE_ARN")
                    .unwrap_or("")
                    .to_string(),

                install_artifacts_avalanched_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHED_BIN")
                    .unwrap()
                    .to_string(),
                install_artifacts_avalanche_bin: sub_matches
                    .value_of("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                    .unwrap()
                    .to_string(),
                install_artifacts_plugins_dir: sub_matches
                    .value_of("INSTALL_ARTIFACTS_PLUGINS_DIR")
                    .unwrap_or("")
                    .to_string(),

                avalanchego_log_level: sub_matches
                    .value_of("AVALANCHEGO_LOG_LEVEL")
                    .unwrap()
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

                disable_instance_system_logs: sub_matches
                    .is_present("DISABLE_INSTANCE_SYSTEM_LOGS"),
                disable_instance_system_metrics: sub_matches
                    .is_present("DISABLE_INSTANCE_SYSTEM_METRICS"),

                spec_file_path: sub_matches
                    .value_of("SPEC_FILE_PATH")
                    .unwrap_or("")
                    .to_string(),
            };
            default_spec::execute(opt).expect("failed to execute 'default-spec'");
        }

        Some((read_spec::NAME, sub_matches)) => {
            read_spec::execute(
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("INSTANCE_IDS"),
                sub_matches.is_present("PUBLIC_IPS"),
                sub_matches.is_present("NLB_ENDPOINT"),
                sub_matches.is_present("HTTP_ENDPOINTS"),
                sub_matches.is_present("NODE_IDS"),
            )
            .expect("failed to execute 'read-spec'");
        }

        Some((check_balances::NAME, sub_matches)) => {
            check_balances::execute(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
            )
            .expect("failed to execute 'check-balances'");
        }

        Some((events::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((events::update_artifacts::NAME, sub_sub_matches)) => {
                events::update_artifacts::execute(
                    sub_sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                    sub_sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                    sub_sub_matches
                        .value_of("INSTALL_ARTIFACTS_AVALANCHE_BIN")
                        .unwrap(),
                    sub_sub_matches
                        .value_of("INSTALL_ARTIFACTS_PLUGINS_DIR")
                        .unwrap_or(""),
                    sub_sub_matches.is_present("SKIP_PROMPT"),
                )
                .expect("failed to execute 'events update-artifacts'");
            }
            _ => unreachable!("unknown sub-subcommand"),
        },

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
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .expect("failed to execute 'delete'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
