mod agent;
mod alias_chain;
mod install_artifacts;
mod install_chain;
mod install_subnet;

use clap::{crate_version, Command};

pub const APP_NAME: &str = "avalanched-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs an Avalanche agent (daemon) on AWS")
        .subcommands(vec![
            agent::command(),
            install_artifacts::command(),
            install_chain::command(),
            install_subnet::command(),
            alias_chain::command(),
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

        Some((install_artifacts::NAME, sub_matches)) => {
            let v = sub_matches
                .get_one::<String>("AVALANCHEGO_RELEASE_TAG")
                .unwrap_or(&String::new())
                .clone();
            let avalanchego_release_tag = if v.is_empty() { None } else { Some(v.clone()) };

            install_artifacts::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                sub_matches.get_one::<String>("S3_REGION").unwrap(),
                sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AVALANCHEGO_S3_KEY")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AVALANCHEGO_LOCAL_PATH")
                    .unwrap_or(&String::new()),
                avalanchego_release_tag,
                sub_matches
                    .get_one::<String>("OS_TYPE")
                    .unwrap_or(&String::from("ubuntu20.04")),
                sub_matches
                    .get_one::<String>("AWS_VOLUME_PROVISIONER_S3_KEY")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AWS_VOLUME_PROVISIONER_LOCAL_PATH")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AWS_IP_PROVISIONER_S3_KEY")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AWS_IP_PROVISIONER_LOCAL_PATH")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AVALANCHE_TELEMETRY_CLOUDWATCH_S3_KEY")
                    .unwrap_or(&String::new()),
                sub_matches
                    .get_one::<String>("AVALANCHE_TELEMETRY_CLOUDWATCH_LOCAL_PATH")
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
                s3_region: sub_matches
                    .get_one::<String>("S3_REGION")
                    .unwrap()
                    .to_string(),
                s3_bucket: sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap()
                    .to_string(),
                subnet_config_s3_key: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_S3_KEY")
                    .unwrap_or(&String::new())
                    .to_string(),
                subnet_config_local_path: sub_matches
                    .get_one::<String>("SUBNET_CONFIG_LOCAL_PATH")
                    .unwrap_or(&String::new())
                    .to_string(),
                vm_binary_s3_key: sub_matches
                    .get_one::<String>("VM_BINARY_S3_KEY")
                    .unwrap()
                    .to_string(),
                vm_binary_local_path: sub_matches
                    .get_one::<String>("VM_BINARY_LOCAL_PATH")
                    .unwrap()
                    .to_string(),
                subnet_id_to_track: sub_matches
                    .get_one::<String>("SUBNET_ID_TO_TRACK")
                    .unwrap()
                    .to_string(),
                avalanchego_config_path: sub_matches
                    .get_one::<String>("AVALANCHEGO_CONFIG_PATH")
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
                s3_region: sub_matches
                    .get_one::<String>("S3_REGION")
                    .unwrap()
                    .to_string(),
                s3_bucket: sub_matches
                    .get_one::<String>("S3_BUCKET")
                    .unwrap()
                    .to_string(),
                chain_config_s3_key: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_S3_KEY")
                    .unwrap()
                    .to_string(),
                chain_config_local_path: sub_matches
                    .get_one::<String>("CHAIN_CONFIG_LOCAL_PATH")
                    .unwrap()
                    .to_string(),
            })
            .await
            .unwrap();
        }

        Some((alias_chain::NAME, sub_matches)) => {
            alias_chain::execute(alias_chain::Flags {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .to_string(),
                chain_name: sub_matches
                    .get_one::<String>("CHAIN_NAME")
                    .unwrap()
                    .to_string(),
                chain_id: sub_matches
                    .get_one::<String>("CHAIN_ID")
                    .unwrap()
                    .to_string(),
            })
            .await
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
