use std::io::{self, stdout};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

use avalanche_ops::avalanche::vm;

const APP_NAME: &str = "subnetctl";
const SUBCOMMAND_VM_ID: &str = "vm-id";

fn create_vm_id_command() -> Command<'static> {
    Command::new(SUBCOMMAND_VM_ID)
        .about("Generates the VM ID based on its name")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("NAME")
                .long("name")
                .short('n')
                .help("Sets the VM name")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("subnetctl (experimental subnet-cli)")
        .long_about(
            "
e.g.,
subnetctl vm-id --name subnet-evm

See https://github.com/ava-labs/subnet-cli.

",
        )
        .subcommands(vec![create_vm_id_command()])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_VM_ID, sub_matches)) => {
            let opt = VmIdOption {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                name: sub_matches.value_of("NAME").unwrap_or("").to_string(),
            };
            execute_vm_id(opt).unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

struct VmIdOption {
    log_level: String,
    name: String,
}

fn execute_vm_id(opt: VmIdOption) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nGenerating VM ID for: '{}'\n", opt.name)),
        ResetColor
    )?;
    let short_id = vm::id_from_str(&opt.name).expect("failed to generate VM ID");
    println!("{}", short_id);

    Ok(())
}
