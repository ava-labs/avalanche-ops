mod add_track_subnet;
mod default;

use clap::{crate_version, Command};

const APP_NAME: &str = "avalanche-config";

fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Avalanche configuration tools")
        .subcommands(vec![add_track_subnet::command(), default::command()])
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

        _ => unreachable!("unknown subcommand"),
    }
}
