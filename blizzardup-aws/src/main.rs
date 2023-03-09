mod apply;
mod default_spec;
mod delete;
mod query;

use clap::{crate_version, Command};

const APP_NAME: &str = "blizzardup-aws";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Blizzard control plane on AWS (requires blizzard)")
        .subcommands(vec![
            default_spec::command(),
            apply::command(),
            delete::command(),
            query::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let funded_keys = sub_matches
                .get_one::<usize>("FUNDED_KEYS")
                .unwrap_or(&5)
                .clone();
            let blizzard_keys_to_generate = sub_matches
                .get_one::<usize>("BLIZZARD_KEYS_TO_GENERATE")
                .unwrap_or(&5)
                .clone();

            let nodes = sub_matches.get_one::<usize>("NODES").unwrap_or(&2).clone();

            let s = sub_matches
                .get_one::<String>("BLIZZARD_CHAIN_RPC_URLS")
                .unwrap()
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut blizzard_chain_rpc_urls: Vec<String> = Vec::new();
            for rpc in ss.iter() {
                let trimmed = rpc.trim().to_string();
                if !trimmed.is_empty() {
                    blizzard_chain_rpc_urls.push(trimmed);
                }
            }

            let blizzard_load_kinds_str = sub_matches
                .get_one::<String>("BLIZZARD_LOAD_KINDS")
                .unwrap()
                .clone();
            let blizzard_load_kinds_str: Vec<&str> = blizzard_load_kinds_str.split(',').collect();
            let mut blizzard_load_kinds: Vec<String> = Vec::new();
            for lk in blizzard_load_kinds_str.iter() {
                blizzard_load_kinds.push(lk.to_string());
            }

            let blizzard_workers = sub_matches
                .get_one::<usize>("BLIZZARD_WORKERS")
                .unwrap_or(&5)
                .clone();

            let opt = blizzardup_aws::DefaultSpecOption {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),

                funded_keys,

                region: sub_matches.get_one::<String>("REGION").unwrap().clone(),
                instance_mode: sub_matches
                    .get_one::<String>("INSTANCE_MODE")
                    .unwrap()
                    .clone(),

                nodes,

                upload_artifacts_blizzard_bin: sub_matches
                    .get_one::<String>("UPLOAD_ARTIFACTS_BLIZZARD_BIN")
                    .unwrap_or(&String::new())
                    .to_string(),
                blizzard_log_level: sub_matches
                    .get_one::<String>("BLIZZARD_LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                blizzard_chain_rpc_urls,
                blizzard_load_kinds,
                blizzard_keys_to_generate,
                blizzard_workers,

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
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .expect("failed to execute 'delete'");
        }

        Some((query::NAME, sub_matches)) => {
            query::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
            )
            .await
            .expect("failed to execute 'delete'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
