use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
    str::FromStr,
};

use avalanche_types::ids;
use clap::{Arg, Command};

pub const NAME: &str = "sync-xsvm-subnet-config";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Loads the avalanceup spec file and writes the XSVM subnet config file")
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
            Arg::new("XSVM_NAME")
                .long("xsvm-name")
                .help("xsvm name in the spec")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SUBNET_ID")
                .long("subnet-id")
                .help("Sets the subnet Id to add")
                .required(true)
                .num_args(1),
        )
}

pub fn execute(
    log_level: &str,
    spec_file_path: &str,
    xsvm_name: &str,
    subnet_id: &str,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    log::info!("validating subnet-id '{}'", subnet_id);
    let converted = ids::Id::from_str(subnet_id)?;
    log::info!("validated subnet-id '{}'", converted);

    log::info!("loading spec {spec_file_path} for xsvm name {xsvm_name}");
    let spec = avalanche_ops::aws::spec::Spec::load(spec_file_path)?;
    let subnet_config_dir = spec.avalanchego_config.subnet_config_dir;
    let xsvm = if let Some(xsvms) = &spec.xsvms {
        if let Some(xsvm) = xsvms.get(xsvm_name) {
            xsvm.clone()
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("spec.xsvms['{xsvm_name}'] not found"),
            ));
        }
    } else {
        return Err(Error::new(ErrorKind::InvalidInput, "spec.xsvms not found"));
    };
    log::info!(
        "successfully loaded spec {spec_file_path} and found {:?} for {xsvm_name}",
        xsvm
    );

    // If a subnet id is 2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt,
    // the config file for this subnet is located at {subnet-config-dir}/2ebCneCbwthjQ1rYT41nhd7M76Hc6YmosMAQrTFhBq8qeqh6tt.json.
    log::info!("creating subnet configuration directory {subnet_config_dir}");
    fs::create_dir_all(Path::new(&subnet_config_dir))?;

    log::info!("writing xsvm subnet config for subnet {subnet_id} in {subnet_config_dir}");
    let subnet_config_path = Path::new(&subnet_config_dir).join(format!("{subnet_id}.json"));

    let tmp_path = random_manager::tmp_path(15, Some(".json"))?;
    xsvm.subnet_config.sync(&tmp_path)?;
    fs::copy(&tmp_path, &subnet_config_path)?;
    fs::remove_file(&tmp_path)?;

    log::info!(
        "saved xsvm subnet config file to {} for subnet-id {subnet_id}",
        subnet_config_path.display()
    );

    Ok(())
}
