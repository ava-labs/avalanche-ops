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
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("USE_DEFAULT_CONFIG")
                .long("use-default-config")
                .help("Enables to use the default config without downloading the spec from S3 (useful for CDK integration)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SKIP_PUBLISH_NODE_INFO")
                .long("skip-publish-node-info")
                .help("Enables to skip publishing node info (useful for CDK integration)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    let opts = flags::Options {
        log_level: matches.value_of("LOG_LEVEL").unwrap_or("info").to_string(),
        use_default_config: matches.is_present("USE_DEFAULT_CONFIG"),
        skip_publish_node_info: matches.is_present("SKIP_PUBLISHING_NODE_INFO"),
    };
    command::execute(opts).await.unwrap();
}
