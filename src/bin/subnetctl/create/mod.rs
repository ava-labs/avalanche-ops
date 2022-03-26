pub mod blockchain;
pub mod subnet;

use clap::Command;

pub const NAME: &str = "create";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Creates subnet/blockchain")
        .subcommands(vec![subnet::command(), blockchain::command()])
}
