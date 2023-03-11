use std::io::{self, stdout};

use avalanche_types::subnet_evm::genesis as subnet_evm_genesis;
use clap::{value_parser, Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "genesis";

/// Defines "subnet-evm genesis" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Flags {
    pub log_level: String,

    pub seed_eth_addresses: Vec<String>,
    pub gas_limit: u64,
    pub target_block_rate: u64,
    pub min_base_fee: u64,
    pub target_gas: u64,
    pub base_fee_change_denominator: u64,
    pub min_block_gas_cost: u64,
    pub max_block_gas_cost: u64,
    pub block_gas_cost_step: u64,

    pub auto_contract_deployer_allow_list_config: bool,
    pub auto_contract_native_minter_config: bool,
    pub auto_fee_manager_config: bool,

    pub file_path: String,
}

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default genesis")
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
            Arg::new("SEED_ETH_ADDRESSES")
                .long("seed-eth-addresses")
                .help("Sets the comma-separated ETH addresses for initial allocations")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("GAS_LIMIT")
                .long("gas-limit")
                .help("Sets subnet-evm gas limit (zero then use defaults)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("TARGET_BLOCK_RATE")
                .long("target-block-rate")
                .help("Sets non-zero to set subnet-evm target block rate (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("MIN_BASE_FEE")
                .long("min-base-fee")
                .help("Sets non-zero to set subnet-evm min base fee (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("TARGET_GAS")
                .long("target-gas")
                .help("Sets non-zero to set subnet-evm target gas (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("BASE_FEE_CHANGE_DENOMINATOR")
                .long("base-fee-change-denominator")
                .help("Sets non-zero to set subnet-evm base fee change denominator (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("MIN_BLOCK_GAS_COST")
                .long("min-block-gas-cost")
                .help("Sets subnet-evm min block gas cost (can be zero, in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("MAX_BLOCK_GAS_COST")
                .long("max-block-gas-cost")
                .help("Sets subnet-evm max block gas cost (can be zero, in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("10000000"),
        )
        .arg(
            Arg::new("BLOCK_GAS_COST_STEP")
                .long("block-gas-cost-step")
                .help("Sets non-zero to set subnet-evm block gas cost step (in genesis)")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            Arg::new("AUTO_CONTRACT_DEPLOYER_ALLOW_LIST_CONFIG")
                .long("auto-contract-deployer-allow-list-config")
                .help("Sets to auto-populate subnet-evm allow list config")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AUTO_CONTRACT_NATIVE_MINTER_CONFIG")
                .long("auto-contract-native-minter-config")
                .help("Sets to auto-populate subnet-evm native minter config")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("AUTO_FEE_MANAGER_CONFIG")
                .long("auto-fee-manager-config")
                .help("Sets to auto-populate subnet-evm fee manager config")
                .required(false)
                .num_args(0),
        )
        .arg(
            Arg::new("FILE_PATH")
                .long("file-path")
                .short('s')
                .help("The config file to create")
                .required(false)
                .num_args(1),
        )
}

pub  fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default()
            .filter_or(env_logger::DEFAULT_FILTER_ENV, opts.clone().log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", opts.file_path)),
        ResetColor
    )?;
    let mut genesis = subnet_evm_genesis::Genesis::new(opts.seed_eth_addresses.clone())
        .expect("failed to generate genesis");

    let mut chain_config = subnet_evm_genesis::ChainConfig::default();

    let mut fee_config = subnet_evm_genesis::FeeConfig::default();
    if opts.gas_limit > 0 {
        fee_config.gas_limit = Some(opts.gas_limit);
        genesis.gas_limit = primitive_types::U256::from(opts.gas_limit);
    }
    if opts.target_block_rate > 0 {
        fee_config.target_block_rate = Some(opts.target_block_rate);
    }
    if opts.min_base_fee > 0 {
        fee_config.min_base_fee = Some(opts.min_base_fee);
    }
    if opts.target_gas > 0 {
        fee_config.target_gas = Some(opts.target_gas);
    }
    if opts.base_fee_change_denominator > 0 {
        fee_config.base_fee_change_denominator = Some(opts.base_fee_change_denominator);
    }
    fee_config.min_block_gas_cost = Some(opts.min_block_gas_cost);
    fee_config.max_block_gas_cost = Some(opts.max_block_gas_cost);

    if opts.block_gas_cost_step > 0 {
        fee_config.block_gas_cost_step = Some(opts.block_gas_cost_step);
    }
    chain_config.fee_config = Some(fee_config);

    if opts.auto_contract_deployer_allow_list_config {
        chain_config.contract_deployer_allow_list_config =
            Some(subnet_evm_genesis::ContractDeployerAllowListConfig {
                allow_list_admins: Some(opts.seed_eth_addresses.clone()),
                ..subnet_evm_genesis::ContractDeployerAllowListConfig::default()
            });
    }
    if opts.auto_contract_native_minter_config {
        chain_config.contract_native_minter_config =
            Some(subnet_evm_genesis::ContractNativeMinterConfig {
                allow_list_admins: Some(opts.seed_eth_addresses.clone()),
                ..subnet_evm_genesis::ContractNativeMinterConfig::default()
            });
    }
    if opts.auto_fee_manager_config {
        chain_config.fee_manager_config = Some(subnet_evm_genesis::FeeManagerConfig {
            allow_list_admins: Some(opts.seed_eth_addresses.clone()),
            ..subnet_evm_genesis::FeeManagerConfig::default()
        });
    }
    genesis.config = Some(chain_config);

    genesis.sync(&opts.file_path)?;
    let d = genesis.encode_json().expect("failed encode_json");
    println!("{d}");

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved genesis to '{}'\n", opts.file_path)),
        ResetColor
    )?;

    Ok(())
}
