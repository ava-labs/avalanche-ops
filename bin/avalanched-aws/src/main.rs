mod cloudwatch;
mod command;
mod flags;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "avalanched-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs an Avalanche agent (daemon) on AWS")
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
            Arg::new("USE_DEFAULT_CONFIG")
                .long("use-default-config")
                .help("Enables to use the default config without downloading the spec from S3 (useful for CDK integration)")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("PUBLISH_PERIODIC_NODE_INFO")
                .long("publish-periodic-node-info")
                .help("Enables to periodically publish ready node information to S3")
                .required(false)
                .num_args(0),
        )
        .get_matches();

    println!("{} version: {}", APP_NAME, crate_version!());
    let opts = flags::Options {
        log_level: matches
            .get_one::<String>("LOG_LEVEL")
            .unwrap_or(&String::from("info"))
            .clone(),
        use_default_config: matches.get_flag("USE_DEFAULT_CONFIG"),
        publish_periodic_node_info: matches.get_flag("PUBLISH_PERIODIC_NODE_INFO"),
    };
    command::execute(opts).await.unwrap();
}
