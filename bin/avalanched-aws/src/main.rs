mod cloudwatch;
mod command;
mod flags;
mod install;
mod sync_subnet_evm_chain_config;
mod sync_subnet_evm_subnet_config;
mod sync_xsvm_subnet_config;

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
        .subcommands(vec![
            install::command(),
            sync_subnet_evm_chain_config::command(),
            sync_subnet_evm_subnet_config::command(),
            sync_xsvm_subnet_config::command(),
        ])
        .get_matches();

    println!("{} version: {}", APP_NAME, crate_version!());

    match matches.subcommand() {
        Some((install::NAME, sub_matches)) => {
            install::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("REGION")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHEGO_S3_KEY")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHEGO_TARGET_FILE_PATH")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHEGO_PLUGIN_S3_PREFIX")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHEGO_PLUGIN_TARGET_DIR")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("RUST_OS_TYPE")
                    .unwrap_or(&String::from("ubuntu20.04")),
                &sub_matches
                    .get_one::<String>("AVALANCHE_CONFIG_S3_KEY")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHE_CONFIG_TARGET_FILE_PATH")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AWS_VOLUME_PROVISIONER_S3_KEY")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AWS_VOLUME_PROVISIONER_TARGET_FILE_PATH")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AWS_IP_PROVISIONER_S3_KEY")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AWS_IP_PROVISIONER_TARGET_FILE_PATH")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHE_TELEMETRY_CLOUDWATCH_S3_KEY")
                    .unwrap_or(&String::new()),
                &sub_matches
                    .get_one::<String>("AVALANCHE_TELEMETRY_CLOUDWATCH_TARGET_FILE_PATH")
                    .unwrap_or(&String::new()),
            )
            .await
            .unwrap();
        }

        Some((sync_subnet_evm_subnet_config::NAME, sub_matches)) => {
            sync_subnet_evm_subnet_config::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
                &sub_matches
                    .get_one::<String>("SUBNET_EVM_NAME")
                    .unwrap()
                    .clone(),
                &sub_matches.get_one::<String>("SUBNET_ID").unwrap().clone(),
            )
            .expect("failed to execute 'sync_subnet_evm_subnet_config'");
        }

        Some((sync_subnet_evm_chain_config::NAME, sub_matches)) => {
            sync_subnet_evm_chain_config::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
                &sub_matches
                    .get_one::<String>("SUBNET_EVM_NAME")
                    .unwrap()
                    .clone(),
                &sub_matches
                    .get_one::<String>("BLOCKCHAIN_ID")
                    .unwrap()
                    .clone(),
            )
            .expect("failed to execute 'sync_subnet_evm_chain_config'");
        }

        Some((sync_xsvm_subnet_config::NAME, sub_matches)) => {
            sync_xsvm_subnet_config::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
                &sub_matches.get_one::<String>("XSVM_NAME").unwrap().clone(),
                &sub_matches.get_one::<String>("SUBNET_ID").unwrap().clone(),
            )
            .expect("failed to execute 'sync_xsvm_subnet_config'");
        }

        _ => {
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
    }
}
