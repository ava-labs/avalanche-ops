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
        .about("Blizzard control plane on AWS (requires blizzard)")
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

            let blizzard_metrics_push_interval_seconds = sub_matches
                .get_one::<u64>("BLIZZARD_METRICS_PUSH_INTERVAL_SECONDS")
                .unwrap_or(&60)
                .clone();

            let nodes = sub_matches.get_one::<usize>("NODES").unwrap_or(&2).clone();
            let network_id = sub_matches
                .get_one::<u32>("NETWORK_ID")
                .unwrap_or(&2000777)
                .clone();

            let opt = blizzardup_aws::DefaultSpecOption {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),

                key_files_dir: sub_matches
                    .get_one::<String>("KEY_FILES_DIR")
                    .unwrap_or(&String::new())
                    .to_string(),
                keys_to_generate,

                region: sub_matches.get_one::<String>("REGION").unwrap().clone(),
                use_spot_instance: sub_matches.get_flag("USE_SPOT_INSTANCE"),

                nodes,
                network_id,

                install_artifacts_blizzard_bin: sub_matches
                    .get_one::<String>("INSTALL_ARTIFACTS_BLIZZARD_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                blizzard_log_level: sub_matches
                    .get_one::<String>("BLIZZARD_LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                blizzard_metrics_push_interval_seconds,

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
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .expect("failed to execute 'delete'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
