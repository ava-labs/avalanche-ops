use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::{self, stdout, Error, ErrorKind, Write},
    path::Path,
};

use avalanche_types::{
    jsonrpc::client::{evm as json_client_evm, info as json_client_info},
    key::secp256k1::{self, private_key::Key, KeyType},
    units, wallet,
};
use aws_manager::{self, kms, sts};
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::time::{sleep, Duration};

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Entry {
    /// Either "hot" or "aws-kms".
    #[serde_as(as = "DisplayFromStr")]
    pub key_type: KeyType,
    /// Either hex-encoded private key or AWS KMS ARN.
    pub key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_token: Option<String>,
}

impl Default for Entry {
    fn default() -> Self {
        Self::default()
    }
}

impl Entry {
    pub fn default() -> Self {
        Self {
            key_type: KeyType::Hot,
            key: String::new(),
            grant_token: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Keys(pub Vec<Entry>);

impl Keys {
    /// Saves the current keys to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing to '{}'", file_path);

        let path = Path::new(file_path);
        if let Some(parent_dir) = path.parent() {
            log::info!("creating parent dir '{}'", parent_dir.display());
            fs::create_dir_all(parent_dir)?;
        }

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize keys info to YAML {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())
    }
}

pub const NAME: &str = "create";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Create and fund AWS KMS keys")
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
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(false)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("KEY_TYPE")
                .long("key-type")
                .help("Sets the key type")
                .required(false)
                .num_args(1)
                .value_parser([KeyType::Hot.as_str(), KeyType::AwsKms.as_str()])
                .default_value(KeyType::Hot.as_str()),
        )
        .arg(
            Arg::new("KEY_NAME_PREFIX")
                .long("key-name-prefix")
                .help("KMS key name prefix")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("KEYS")
                .long("keys")
                .help("Sets the number of keys to create")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("KEYS_FILE_OUTPUT")
                .long("keys-file-output")
                .help("Sets the YAML file path of the keys file (if empty, uses random temp file path)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("KEYS_FILE_CHUNKS")
                .long("keys-file-chunks")
                .help("Sets the number of keys-file chunks")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )

        // optional for cross-account grants
        .arg(
            Arg::new("GRANTEE_PRINCIPAL")
                .long("grantee-principal")
                .help("KMS key grantee principal ARN")
                .required(false)
                .num_args(1),
        )

        // optional to fund keys
        .arg(
            Arg::new("EVM_CHAIN_RPC_URL")
                .long("evm-chain-rpc-url")
                .help("Sets EVM chain RPC endpoint")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_HOTKEY")
                .long("evm-funding-hotkey")
                .help("Sets the private key in hex format to fund the created key (leave empty to skip funding)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_AMOUNT_IN_NANO_AVAX")
                .long("evm-funding-amount-in-nano-avax")
                .help("Sets the funding amount in nAVAX (cannot be overlapped with --funding-amount-in-avax)")
                .required(false)
                .num_args(1),
        )
        .arg(
            Arg::new("EVM_FUNDING_AMOUNT_IN_AVAX")
                .long("evm-funding-amount-in-avax")
                .help("Sets the funding amount in AVAX (cannot be overlapped with --funding-amount-in-nano-avax)")
                .required(false)
                .num_args(1),
        )

        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("PROFILE_NAME")
                .long("profile-name")
                .help("Sets the AWS credential profile name for API calls/endpoints")
                .required(false)
                .default_value("default")
                .num_args(1),
        )
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    log_level: &str,
    region: &str,
    key_type: KeyType,
    key_name_prefix: &str,
    keys: usize,
    keys_file_output: &str,
    keys_file_chunks: usize,
    grantee_principal: &str,
    evm_chain_rpc_url: &str,
    evm_funding_hotkey: &str,
    evm_funding_amount_navax: U256,
    skip_prompt: bool,
    profile_name: String,
) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    if !skip_prompt {
        let options = &[
            format!("No, I am not ready to create new {keys} with key type {key_type}."),
            format!("Yes, let's create new {keys} with key type {key_type}."),
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'create' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    } else {
        log::info!("skipping prompt...")
    }

    match key_type {
        KeyType::AwsKms => {
            log::info!(
            "requesting to create new {keys} KMS key(s) with prefix '{key_name_prefix}' (in the {region}, grantee principal {grantee_principal}, keys file output {keys_file_output})"
        );

            let shared_config = aws_manager::load_config(
                Some(region.to_string()),
                Some(profile_name),
                Some(Duration::from_secs(30)),
            )
            .await;
            let kms_manager = kms::Manager::new(&shared_config);

            let sts_manager = sts::Manager::new(&shared_config);
            let current_identity = sts_manager.get_identity().await.unwrap();
            log::info!("current identity {:?}", current_identity);
            println!();

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\nCreating new KMS keys with '{key_name_prefix}' in region {region}\n",
                )),
                ResetColor
            )?;
            let mut kms_keys = Vec::new();
            let mut kms_grant_tokens = Vec::new();
            let mut entries = Vec::new();
            for i in 0..keys {
                // to prevent rate limit errors
                // e.g.,
                // { source: CreateKeyError { kind: Unhandled(Unhandled { source: Error { code: Some(\\\"ThrottlingException\\\"), message: Some(\\\"You have exceeded the rate at which you may call KMS. Reduce the frequency of your calls.\\\"
                sleep(Duration::from_secs(2)).await;

                println!();
                log::info!("[{i}] creating KMS key");
                let mut tags = HashMap::new();
                tags.insert(
                    String::from("Name"),
                    format!("{key_name_prefix}-{:03}", i + 1),
                );
                let key = secp256k1::kms::aws::Key::create(kms_manager.clone(), tags)
                    .await
                    .unwrap();

                let key_info: secp256k1::Info = key.to_info(1).unwrap();
                kms_keys.push(key_info.clone());

                println!();
                println!("loaded created KMS key\n\n{}\n", key_info);
                println!();

                let mut entry = Entry {
                    key_type: KeyType::AwsKms,
                    key: key.arn.clone(),
                    ..Default::default()
                };
                if !grantee_principal.is_empty() {
                    log::info!("KMS granting {} to {grantee_principal}", key.arn);
                    let (grant_id, grant_token) = kms_manager
                        .create_grant_for_sign_reads(&key.id, grantee_principal)
                        .await
                        .unwrap();
                    log::info!("KMS granted Id {grant_id}");
                    entry.grant_token = Some(grant_token.clone());
                    kms_grant_tokens.push(grant_token);
                }
                entries.push(entry);

                if evm_funding_hotkey.is_empty() {
                    log::info!("no evm-funding-hotkey given, skipping...");
                    continue;
                }

                let resp = json_client_info::get_network_id(evm_chain_rpc_url)
                    .await
                    .unwrap();
                let network_id = resp.result.unwrap().network_id;

                let chain_id = json_client_evm::chain_id(evm_chain_rpc_url).await.unwrap();
                log::info!(
                    "running against {evm_chain_rpc_url}, network Id {network_id}, chain Id {chain_id}"
                );

                let funding_key =
                    secp256k1::private_key::Key::from_hex(evm_funding_hotkey).unwrap();
                let funding_key_info = funding_key.to_info(network_id).unwrap();
                log::info!("loaded funding key: {}", funding_key_info.eth_address);

                let transferee_addr = key_info.h160_address;
                execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!(
                    "\ntransfering {evm_funding_amount_navax} ({} ETH/AVAX) from {} to {transferee_addr} via {evm_chain_rpc_url}\n",
                    units::cast_evm_navax_to_avax_i64(evm_funding_amount_navax), funding_key_info.eth_address
                )),
                    ResetColor
                )?;
                let funding_key_signer: ethers_signers::LocalWallet =
                    funding_key.to_ethers_core_signing_key().into();

                let w = wallet::Builder::new(&funding_key)
                    .base_http_url(evm_chain_rpc_url.to_string())
                    .build()
                    .await
                    .unwrap();
                let funding_evm_wallet = w
                    .evm(&funding_key_signer, evm_chain_rpc_url, chain_id)
                    .unwrap();

                let transferer_balance = funding_evm_wallet.balance().await.unwrap();
                println!(
                    "transferrer {} current balance: {} ({} ETH/AVAX)",
                    funding_key_info.eth_address,
                    transferer_balance,
                    units::cast_evm_navax_to_avax_i64(transferer_balance)
                );
                let transferee_balance =
                    json_client_evm::get_balance(evm_chain_rpc_url, transferee_addr)
                        .await
                        .unwrap();
                println!(
                    "transferee 0x{:x} current balance: {} ({} ETH/AVAX)",
                    transferee_addr,
                    transferee_balance,
                    units::cast_evm_navax_to_avax_i64(transferee_balance)
                );

                let tx_id = funding_evm_wallet
                    .eip1559()
                    .recipient(transferee_addr)
                    .value(evm_funding_amount_navax)
                    .urgent()
                    .check_acceptance(true)
                    .submit()
                    .await
                    .unwrap();
                log::info!("evm ethers wallet SUCCESS with transaction id {}", tx_id);
            }

            for (i, k) in kms_keys.iter().enumerate() {
                if kms_grant_tokens.is_empty() {
                    println!("{},{}", k.id.clone().unwrap(), k.eth_address)
                } else {
                    println!(
                        "{},{},{}",
                        k.id.clone().unwrap(),
                        k.eth_address,
                        kms_grant_tokens[i]
                    )
                }
            }

            let exec_path = env::current_exe().expect("unexpected None current_exe");
            println!("\n# [UNSAFE] schedule to delete the KMS keys");
            for k in kms_keys.iter() {
                println!("{} delete --region={region} --pending-windows-in-days 7 --unsafe-skip-prompt --key-arn {}", exec_path.display(), k.id.clone().unwrap());
            }

            println!("\n# [UNSAFE] fund the keys from a hotkey");
            let mut addresses = Vec::new();
            for k in kms_keys.iter() {
                addresses.push(k.eth_address.clone());
            }
            println!("{} evm-transfer-from-hotkey --chain-rpc-url={evm_chain_rpc_url} --transferer-key=[FUNDING_HOTKEY] --transfer-amount-in-avax \"30000000\" --transferee-addresses {}", exec_path.display(), addresses.join(","));

            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print(format!("\nWrote keys to {keys_file_output}\n",)),
                ResetColor
            )?;
            let keys = Keys(entries);
            keys.sync(keys_file_output)?;

            if keys_file_chunks > 1 {
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Green),
                    Print("\nWrote keys in chunk\n".to_string()),
                    ResetColor
                )?;

                let mut chunk_size = keys.0.len() / keys_file_chunks;
                let remainder = keys.0.len() % keys_file_chunks;
                if remainder != 0 {
                    chunk_size += 1;
                }
                for (cursor, chunk) in keys.0.chunks(chunk_size).enumerate() {
                    let chunk_file_output_path = format!("{keys_file_output}.{}.yaml", cursor + 1);
                    let chunk_keys = Keys(chunk.to_vec());
                    chunk_keys.sync(&chunk_file_output_path)?;
                }
            }
        }
        KeyType::Hot => {
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("\nCreating new hot keys\n"),
                ResetColor
            )?;
            for i in 0..keys {
                let k = Key::generate().unwrap();
                let key_info = k.to_info(1).unwrap();

                println!();
                println!("[{i}] created hotkey\n\n{}\n", key_info);
                println!();
            }

            // transfer not supported for hotkey yet
        }
        KeyType::Unknown(u) => {
            panic!("unknown key type {u}");
        }
    }

    Ok(())
}
