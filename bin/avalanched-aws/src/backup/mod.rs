pub mod download;
pub mod upload;

use clap::Command;

pub const NAME: &str = "backup";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Events to trigger to the network")
        .subcommands(vec![download::subcommand(), upload::subcommand()])
}
