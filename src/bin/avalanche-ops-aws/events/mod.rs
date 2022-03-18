use clap::Command;

pub mod update_artifacts;

pub const NAME: &str = "events";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Events to trigger to the network")
        .subcommand(update_artifacts::subcommand())
}
