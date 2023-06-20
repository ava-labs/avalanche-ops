mod create;
mod delete;
mod evm_balance;
mod evm_transfer_from_hotkey;
mod info;

use std::{
    io::{self, Error, ErrorKind},
    str::FromStr,
};

use avalanche_types::{key::secp256k1::KeyType, units};
use clap::{crate_version, Command};
use primitive_types::{H160, U256};

const APP_NAME: &str = "avalanche-kms";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Avalanche KMS AWS tools")
        .subcommands(vec![
            evm_balance::command(),
            create::command(),
            delete::command(),
            info::command(),
            evm_transfer_from_hotkey::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((evm_balance::NAME, sub_matches)) => {
            let addr = sub_matches
                .get_one::<String>("ADDRESS")
                .unwrap_or(&String::new())
                .clone();
            let addr = H160::from_str(addr.trim_start_matches("0x")).unwrap();

            evm_balance::execute(
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
            let s = sub_matches
                .get_one::<String>("KEY_TYPE")
                .unwrap_or(&String::new())
                .clone();
            let key_type = KeyType::from_str(&s).unwrap();

            let key_name_prefix = if let Some(p) = sub_matches.get_one::<String>("KEY_NAME_PREFIX")
            {
                p.clone()
            } else {
                id_manager::time::with_prefix("avalanche-kms")
            };

            let grantee_principal = sub_matches
                .get_one::<String>("GRANTEE_PRINCIPAL")
                .unwrap_or(&String::new())
                .clone();

            let evm_chain_rpc_url = sub_matches
                .get_one::<String>("EVM_CHAIN_RPC_URL")
                .unwrap_or(&String::new())
                .clone();

            let evm_funding_hotkey = sub_matches
                .get_one::<String>("EVM_FUNDING_HOTKEY")
                .unwrap_or(&String::new())
                .clone();

            let evm_funding_amount_in_navax = sub_matches
                .get_one::<String>("EVM_FUNDING_AMOUNT_IN_NANO_AVAX")
                .unwrap_or(&String::new())
                .clone();
            let evm_funding_amount_in_navax =
                U256::from_dec_str(&evm_funding_amount_in_navax).unwrap();

            let evm_funding_amount_in_avax = sub_matches
                .get_one::<String>("EVM_FUNDING_AMOUNT_IN_AVAX")
                .unwrap_or(&String::new())
                .clone();
            let evm_funding_amount_in_avax =
                U256::from_dec_str(&evm_funding_amount_in_avax).unwrap();

            if !evm_funding_amount_in_navax.is_zero() && !evm_funding_amount_in_avax.is_zero() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "both EVM_FUNDING_AMOUNT_IN_NANO_AVAX and EVM_FUNDING_AMOUNT_IN_AVAX cannot be non-zero",
                ));
            }

            let evm_funding_amount_navax = if evm_funding_amount_in_navax.is_zero() {
                units::cast_avax_to_evm_navax(evm_funding_amount_in_avax)
            } else {
                evm_funding_amount_in_navax
            };

            let keys_file_output = sub_matches
                .get_one::<String>("KEYS_FILE_OUTPUT")
                .unwrap_or(&random_manager::tmp_path(15, Some(".yaml"))?)
                .clone();

            create::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                key_type,
                &key_name_prefix,
                *sub_matches.get_one::<usize>("KEYS").unwrap_or(&1),
                &keys_file_output,
                *sub_matches
                    .get_one::<usize>("KEYS_FILE_CHUNKS")
                    .unwrap_or(&1),
                &grantee_principal,
                &evm_chain_rpc_url,
                &evm_funding_hotkey,
                evm_funding_amount_navax,
                sub_matches.get_flag("SKIP_PROMPT"),
                sub_matches
                    .get_one::<String>("PROFILE_NAME")
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
        }

        Some((delete::NAME, sub_matches)) => {
            let pending_windows_in_days = *sub_matches
                .get_one::<i32>("PENDING_WINDOWS_IN_DAYS")
                .unwrap_or(&1);

            delete::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches.get_one::<String>("REGION").unwrap().clone(),
                &sub_matches.get_one::<String>("KEY_ARN").unwrap().clone(),
                pending_windows_in_days,
                sub_matches.get_flag("UNSAFE_SKIP_PROMPT"),
                sub_matches
                    .get_one::<String>("PROFILE_NAME")
                    .unwrap()
                    .clone(),
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
                sub_matches
                    .get_one::<String>("PROFILE_NAME")
                    .unwrap()
                    .clone(),
            )
            .await
            .unwrap();
        }

        Some((evm_transfer_from_hotkey::NAME, sub_matches)) => {
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
            if !transfer_amount_in_navax.is_zero() && !transfer_amount_in_avax.is_zero() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "both TRANSFER_AMOUNT_IN_NANO_AVAX and TRANSFER_AMOUNT_IN_AVAX cannot be non-zero",
                ));
            }

            let transfer_amount_navax = if transfer_amount_in_navax.is_zero() {
                units::cast_avax_to_evm_navax(transfer_amount_in_avax)
            } else {
                transfer_amount_in_navax
            };

            let s = sub_matches
                .get_one::<String>("TRANSFEREE_ADDRESSES")
                .unwrap_or(&String::new())
                .clone();
            let ss: Vec<&str> = s.split(',').collect();
            let mut transferee_addrs: Vec<H160> = Vec::new();
            for addr in ss.iter() {
                let transferee_addr = H160::from_str(addr.trim_start_matches("0x")).unwrap();
                transferee_addrs.push(transferee_addr);
            }

            evm_transfer_from_hotkey::execute(
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
                transferee_addrs,
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .await
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }

    Ok(())
}
