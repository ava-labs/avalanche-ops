pub mod chain_config;
pub mod genesis;

use clap::Command;

pub const NAME: &str = "subnet-evm";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes subnet-evm configurations")
        .subcommands(vec![chain_config::command(), genesis::command()])
}
