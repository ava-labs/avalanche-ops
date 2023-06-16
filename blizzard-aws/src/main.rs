mod cloudwatch;
mod command;
mod evm;
mod flags;
mod x;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "blizzard-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs a Blizzard agent (daemon) on AWS")
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
            Arg::new("PROFILE_NAME")
                .long("profile-name")
                .help("Sets the AWS credential profile name for API calls/endpoints")
                .required(false)
                .default_value("default")
                .num_args(1),
        )
        .get_matches();

    println!("{} version: {}", APP_NAME, crate_version!());
    let opts = flags::Options {
        log_level: matches
            .get_one::<String>("LOG_LEVEL")
            .unwrap_or(&String::from("info"))
            .clone(),
        profile_name: matches.get_one::<String>("PROFILE_NAME").unwrap().clone(),
    };
    command::execute(opts).await.unwrap();
}
