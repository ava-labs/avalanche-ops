pub mod subnet_validator;
pub mod validator;

use clap::Command;

pub const NAME: &str = "add";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Adds validator/subnet-validator")
        .subcommands(vec![subnet_validator::command(), validator::command()])
}
