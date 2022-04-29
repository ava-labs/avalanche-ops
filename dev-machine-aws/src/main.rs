use clap::{crate_version, Command};

mod apply;
mod default_spec;
mod delete;

const APP_NAME: &str = "dev-machine";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Development machine provisioner")
        .subcommands(vec![
            default_spec::command(),
            apply::command(),
            delete::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let opt = default_spec::Option {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                arch: sub_matches.value_of("ARCH").unwrap().to_string(),
                os: sub_matches.value_of("OS").unwrap().to_string(),
                spec_file_path: sub_matches.value_of("SPEC_FILE_PATH").unwrap().to_string(),
            };
            default_spec::execute(opt).unwrap();
        }

        Some((apply::NAME, sub_matches)) => {
            apply::execute(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        Some((delete::NAME, sub_matches)) => {
            delete::execute(
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("SPEC_FILE_PATH").unwrap(),
                sub_matches.is_present("DELETE_ALL"),
                sub_matches.is_present("SKIP_PROMPT"),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
