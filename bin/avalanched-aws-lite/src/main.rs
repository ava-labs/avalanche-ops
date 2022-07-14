pub mod command;
pub mod flags;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "avalanched-aws-lite";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs an Avalanche node")
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
        .get_matches();

    let opts = flags::Options {
        log_level: matches.value_of("LOG_LEVEL").unwrap_or("info").to_string(),
    };
    command::execute(opts).await.unwrap();
}
