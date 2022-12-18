mod create;
mod delete;
mod info;

use clap::{crate_version, Command};

const APP_NAME: &str = "avalanche-kms-aws";

fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Avalanche KMS AWS tools")
        .subcommands(vec![create::command(), delete::command(), info::command()])
        .get_matches();

    match matches.subcommand() {
        Some((create::NAME, sub_matches)) => {
            let key_name = if let Some(p) = sub_matches.get_one::<String>("KEY_NAME") {
                p.clone()
            } else {
                id_manager::time::with_prefix("avalanche-kms")
            };

            create::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &key_name,
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .expect("failed to execute 'create'");
        }

        Some((delete::NAME, sub_matches)) => {
            let pending_windows_in_days = sub_matches
                .get_one::<i32>("PENDING_WINDOWS_IN_DAYS")
                .unwrap_or(&1)
                .clone();

            delete::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY_ARN").unwrap().clone(),
                pending_windows_in_days,
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .expect("failed to execute 'create'");
        }

        Some((info::NAME, sub_matches)) => {
            let network_id = sub_matches
                .get_one::<u32>("NETWORK_ID")
                .unwrap_or(&1)
                .clone();

            info::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY_ARN").unwrap().clone(),
                network_id,
            )
            .expect("failed to execute 'create'");
        }

        _ => unreachable!("unknown subcommand"),
    }
}
