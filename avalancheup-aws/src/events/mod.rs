pub mod update_artifacts;

use clap::Command;

pub const NAME: &str = "events";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Events to trigger to the network")
        .subcommand(update_artifacts::subcommand())
}
