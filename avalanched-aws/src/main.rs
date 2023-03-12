mod agent;
mod install;
mod install_chain;
mod install_subnet;

// TODO: remove this
//
mod sync_subnet_evm_chain_config;
mod sync_subnet_evm_subnet_config;
mod sync_xsvm_subnet_config;

use clap::{crate_version, Command};

pub const APP_NAME: &str = "avalanched-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs an Avalanche agent (daemon) on AWS")
        .subcommands(vec![
            agent::command(),
            install::command(),
            install_chain::command(),
            install_subnet::command(),
            //
            //
            //
            //
            //
            //
            //
            // TODO: remove
            sync_subnet_evm_chain_config::command(),
            sync_subnet_evm_subnet_config::command(),
            sync_xsvm_subnet_config::command(),
        ])
        .get_matches();

    println!("{} version: {}", APP_NAME, crate_version!());

    match matches.subcommand() {
        Some((agent::NAME, sub_matches)) => {
            let opts = agent::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                use_default_config: sub_matches.get_flag("USE_DEFAULT_CONFIG"),
                publish_periodic_node_info: sub_matches.get_flag("PUBLISH_PERIODIC_NODE_INFO"),
            };
            agent::execute(opts).await.unwrap();
        }

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

        Some((install_subnet::NAME, sub_matches)) => {
            install_subnet::execute(install_subnet::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                region: sub_matches.get_one::<String>("REGION").unwrap().to_string(),
                s3_bucket: sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap()
                    .to_string(),
                subnet_config_s3_key: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_S3_KEY")
                    .unwrap()
                    .to_string(),
                subnet_config_path: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_PATH")
                    .unwrap()
                    .to_string(),
                vm_binary_s3_key: sub_matches
                    .get_one::<String>("VM_BINARY_S3_KEY")
                    .unwrap()
                    .to_string(),
                vm_binary_path: sub_matches
                    .get_one::<String>("VM_BINARY_PATH")
                    .unwrap()
                    .to_string(),
            })
            .await
            .unwrap();
        }

        Some((install_chain::NAME, sub_matches)) => {
            install_chain::execute(install_chain::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                region: sub_matches.get_one::<String>("REGION").unwrap().to_string(),
                s3_bucket: sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap()
                    .to_string(),
                chain_config_s3_key: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_S3_KEY")
                    .unwrap()
                    .to_string(),
                chain_config_path: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_PATH")
                    .unwrap()
                    .to_string(),
            })
            .await
            .unwrap();
        }

        // TODO: remove the below
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
        //
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

        _ => unreachable!("unknown subcommand"),
    }
}
