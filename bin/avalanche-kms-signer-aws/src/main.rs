mod balance;
mod create;
mod delete;
mod info;
mod transfer_from_hot;

use std::{io, str::FromStr};

use clap::{crate_version, Command};
use primitive_types::{H160, U256};

const APP_NAME: &str = "avalanche-kms-signer-aws";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Avalanche KMS AWS tools")
        .subcommands(vec![
            balance::command(),
            create::command(),
            delete::command(),
            info::command(),
            transfer_from_hot::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((balance::NAME, sub_matches)) => {
            let addr = sub_matches
                .get_one::<String>("ADDRESS")
                .unwrap_or(&String::new())
                .clone();
            let addr = H160::from_str(addr.trim_start_matches("0x")).unwrap();

            balance::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap_or(&String::new())
                    .clone(),
                addr,
            )
            .await
            .unwrap();
        }

        Some((create::NAME, sub_matches)) => {
            let key_name = if let Some(p) = sub_matches.get_one::<String>("KEY_NAME") {
                p.clone()
            } else {
                id_manager::time::with_prefix("avalanche-kms")
            };

            create::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &key_name,
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .unwrap();
        }

        Some((delete::NAME, sub_matches)) => {
            let pending_windows_in_days = sub_matches
                .get_one::<i32>("PENDING_WINDOWS_IN_DAYS")
                .unwrap_or(&1)
                .clone();

            delete::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY_ARN").unwrap().clone(),
                pending_windows_in_days,
            )
            .await
            .unwrap();
        }

        Some((info::NAME, sub_matches)) => {
            info::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY_ARN").unwrap().clone(),
                &sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap_or(&String::new())
                    .clone(),
            )
            .await
            .unwrap();
        }

        Some((transfer_from_hot::NAME, sub_matches)) => {
            let transferer_key = sub_matches
                .get_one::<String>("TRANSFERER_KEY")
                .unwrap_or(&String::new())
                .clone();

            let transfer_amount = sub_matches
                .get_one::<u64>("TRANSFER_AMOUNT")
                .unwrap_or(&0)
                .clone();
            let transfer_amount = U256::from(transfer_amount);

            let transferee_addr = sub_matches
                .get_one::<String>("TRANSFEREE_ADDRESS")
                .unwrap_or(&String::new())
                .clone();
            let transferee_addr = H160::from_str(transferee_addr.trim_start_matches("0x")).unwrap();

            transfer_from_hot::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap_or(&String::new())
                    .clone(),
                &transferer_key,
                transfer_amount,
                transferee_addr,
            )
            .await
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }

    Ok(())
}
