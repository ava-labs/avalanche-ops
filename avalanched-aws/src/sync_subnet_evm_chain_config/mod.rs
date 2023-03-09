use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
    str::FromStr,
};

use avalanche_types::ids;
use clap::{Arg, Command};

pub const NAME: &str = "sync-subnet-evm-chain-config";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Loads the avalanceup spec file and writes the subnet-evm chain config file")
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load and update")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_EVM_NAME")
                .long("subnet-evm-name")
                .help("subnet-evm name in the spec")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("BLOCKCHAIN_ID")
                .long("blockchain-id")
                .help("Sets the blockchain Id")
                .required(true)
                .num_args(1),
        )
}

pub fn execute(
    log_level: &str,
    spec_file_path: &str,
    subnet_evm_name: &str,
    blockchain_id: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("validating blockchain-id '{}'", blockchain_id);
    let converted = ids::Id::from_str(blockchain_id)?;
    log::info!("validated blockchain-id '{}'", converted);

    log::info!("loading spec {spec_file_path} for subnet-evm name {subnet_evm_name}");
    let spec = avalanche_ops::aws::spec::Spec::load(spec_file_path)?;
    let chain_config_dir = spec.avalanchego_config.chain_config_dir;
    let subnet_evm = if let Some(subnet_evms) = &spec.subnet_evms {
        if let Some(subnet_evm) = subnet_evms.get(subnet_evm_name) {
            subnet_evm.clone()
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("spec.subnet_evms['{subnet_evm_name}'] not found"),
            ));
        }
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "spec.subnet_evms not found",
        ));
    };
    log::info!(
        "successfully loaded spec {spec_file_path} and found {:?} for {subnet_evm_name}",
        subnet_evm
    );

    // If a Subnet's chain id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
    // the config file for this chain is located at {chain-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt/config.json.
    // so this file needs to be moved again once the blockchain is created
    // SSM doc will do such updates
    // ref. https://docs.avax.network/subnets/customize-a-subnet#chain-configs
    // ref. https://docs.avax.network/subnets/customize-a-subnet#initial-precompile-configurations
    // ref. https://docs.avax.network/subnets/customize-a-subnet#initial-configuration-3
    // ref. https://github.com/ava-labs/public-chain-assets/blob/main/chains/53935/genesis.json
    log::info!("creating chain configuration directory {chain_config_dir}");
    fs::create_dir_all(Path::new(&chain_config_dir).join(blockchain_id))?;

    log::info!("writing subnet-evm subnet config for subnet {blockchain_id} in {chain_config_dir}");
    let chain_config_path = Path::new(&chain_config_dir)
        .join(blockchain_id)
        .join("config.json");

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    subnet_evm.chain_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &chain_config_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved subnet-evm chain config file to {} for blockchain id {blockchain_id}",
        chain_config_path.display()
    );

    Ok(())
}
