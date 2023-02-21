mod balance;
mod create;
mod delete;
mod evm_transfer_from_hot;
mod info;

use std::{
    io::{self, Error, ErrorKind},
    str::FromStr,
};

use avalanche_types::units;
use clap::{crate_version, Command};
use primitive_types::{H160, U256};

const APP_NAME: &str = "avalanche-kms";

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
            evm_transfer_from_hot::command(),
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
                &sub_matches.get_one::<String>("KEY_TYPE").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY").unwrap().clone(),
                &sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap_or(&String::new())
                    .clone(),
            )
            .await
            .unwrap();
        }

        Some((evm_transfer_from_hot::NAME, sub_matches)) => {
            let transferer_key = sub_matches
                .get_one::<String>("TRANSFERER_KEY")
                .unwrap_or(&String::new())
                .clone();

            let transfer_amount_in_navax = sub_matches
                .get_one::<String>("TRANSFER_AMOUNT_IN_NANO_AVAX")
                .unwrap_or(&String::new())
                .clone();
            let transfer_amount_in_navax = U256::from_dec_str(&transfer_amount_in_navax).unwrap();

            let transfer_amount_in_avax = sub_matches
                .get_one::<String>("TRANSFER_AMOUNT_IN_AVAX")
                .unwrap_or(&String::new())
                .clone();
            let transfer_amount_in_avax = U256::from_dec_str(&transfer_amount_in_avax).unwrap();

            if transfer_amount_in_navax.is_zero() && transfer_amount_in_avax.is_zero() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "both TRANSFER_AMOUNT_IN_NANO_AVAX and TRANSFER_AMOUNT_IN_AVAX cannot be zero",
                ));
            }

            let transfer_amount_navax = if transfer_amount_in_navax.is_zero() {
                units::cast_avax_to_navax(transfer_amount_in_avax)
            } else {
                transfer_amount_in_navax
            };

            let transferee_addr = sub_matches
                .get_one::<String>("TRANSFEREE_ADDRESS")
                .unwrap_or(&String::new())
                .clone();
            let transferee_addr = H160::from_str(transferee_addr.trim_start_matches("0x")).unwrap();

            evm_transfer_from_hot::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("CHAIN_RPC_URL")
                    .unwrap_or(&String::new())
                    .clone(),
                &transferer_key,
                transfer_amount_navax,
                transferee_addr,
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }

    Ok(())
}
