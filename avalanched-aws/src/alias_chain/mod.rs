use std::{collections::HashMap, fs::File, io, path::Path};

use clap::{Arg, Command};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "alias-chain";

/// Defines "alias-chain" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub chain_id: String,
    pub chain_name: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Sets chain alias (WARN: ALWAYS OVERWRITES)")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("CHAIN_ID")
                .long("chain-id")
                .help("Chain ID")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("CHAIN_NAME")
                .long("chain-name")
                .help("Chain name to use as an alias")
                .required(false)
                .num_args(1),
        )
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    // Create alias.json file
    // TODO: import type from avalanche-rust
    pub type Aliases = HashMap<String, Vec<String>>;
    let mut aliases = Aliases::new();
    aliases.insert(opts.chain_id, Vec::from([opts.chain_name]));

    // Write it to default location
    // TODO: import location from avalanche-rust
    pub const DEFAULT_CHAIN_ALIASES_PATH: &str = "/data/avalanche-configs/chains/aliases.json";
    let path = Path::new(DEFAULT_CHAIN_ALIASES_PATH);

    let file = File::create(path)?;
    ::serde_json::to_writer(file, &aliases)?;

    // At this point avalanchego should be restarted to notice the new alias.
    // This is done via the ssm_install_subnet_chain SSM document under src/aws/cfn-templates.
    Ok(())
}
