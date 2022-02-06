use std::{
    io::{self, stdout, Error, ErrorKind},
    thread, time,
};

use clap::{arg, App, AppSettings};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use tokio::runtime::Runtime;

use avalanche_ops::{aws, aws_cloudformation, aws_ec2, aws_kms, aws_s3, aws_sts, network};

const APP_NAME: &str = "avalanche-ops-nodes-aws";
const SUBCOMMAND_DEFAULT_CONFIG: &str = "default-config";
const SUBCOMMAND_APPLY: &str = "apply";
const SUBCOMMAND_DELETE: &str = "delete";

fn main() {
    let matches = App::new(APP_NAME)
        .about("Avalanche node operations on AWS")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowInvalidUtf8ForExternalSubcommands)
        .subcommands(vec![
            create_default_config_command(),
            create_apply_command(),
            create_delete_command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((SUBCOMMAND_DEFAULT_CONFIG, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            let config_path = sub_matches.value_of("config").unwrap();
            let network_id = sub_matches.value_of("NETWORK_ID").unwrap_or("custom");
            run_default_config(log_level, config_path, network_id).unwrap();
        }

        Some((SUBCOMMAND_APPLY, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            let config_path = sub_matches.value_of("config").unwrap();
            let prompt = sub_matches.value_of("prompt").unwrap_or("true") == "true";
            run_apply(log_level, config_path, prompt).unwrap();
        }

        Some((SUBCOMMAND_DELETE, sub_matches)) => {
            let log_level = sub_matches.value_of("log").unwrap_or("info");
            let config_path = sub_matches.value_of("config").unwrap();
            let prompt = sub_matches.value_of("prompt").unwrap_or("true") == "true";
            run_delete(log_level, config_path, prompt).unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}

fn create_default_config_command() -> App<'static> {
    App::new(SUBCOMMAND_DEFAULT_CONFIG)
        .about("Writes a default configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-c --config <FILE> "Sets a config file to write")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(arg!(<NETWORK_ID>).required(true).allow_invalid_utf8(false))
}

fn create_apply_command() -> App<'static> {
    App::new(SUBCOMMAND_APPLY)
        .about("Applies/creates resources based on configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-c --config <FILE> "The config file to load and update")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-p --prompt <PROMPT> "Enables prompt mode")
                .required(false)
                .possible_value("true")
                .possible_value("false")
                .allow_invalid_utf8(false),
        )
}

fn create_delete_command() -> App<'static> {
    App::new(SUBCOMMAND_DELETE)
        .about("Deletes resources based on configuration")
        .arg(
            arg!(-l --log <LOG_LEVEL> "Sets the log level")
                .required(false)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-c --config <FILE> "The config file to load")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-p --prompt <PROMPT> "Enables prompt mode")
                .required(false)
                .possible_value("true")
                .possible_value("false")
                .allow_invalid_utf8(false),
        )
}

fn run_default_config(log_level: &str, config_path: &str, network_id: &str) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let config = network::Config::default_aws(network_id);
    config.sync(config_path).unwrap();

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}", config_contents);

    Ok(())
}

fn run_apply(log_level: &str, config_path: &str, prompt: bool) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut config = network::load_config(config_path).unwrap();
    let mut aws_resources = config.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = aws_sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // configuration must be valid
    config.validate().unwrap();

    // validate identity
    match aws_resources.clone().identity {
        Some(identity) => {
            // AWS calls must be made from the same caller
            if identity != current_identity {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "config identity {:?} != currently loaded identity {:?}",
                        identity, current_identity
                    ),
                ));
            }
        }
        None => {
            aws_resources.identity = Some(current_identity);
        }
    }

    // set defaults
    aws_resources.ec2_key_name = Some(format!("{}-ec2-key", config.id));
    aws_resources.cloudformation_ec2_instance_role =
        Some(format!("{}-ec2-instance-role", config.id));
    aws_resources.cloudformation_vpc = Some(format!("{}-vpc", config.id));
    if !config.is_mainnet() {
        aws_resources.cloudformation_asg_beacon_nodes =
            Some(format!("{}-asg-beacon-nodes", config.id));
    }
    aws_resources.cloudformation_asg_non_beacon_nodes =
        Some(format!("{}-asg-non-beacon-nodes", config.id));
    config.aws_resources = Some(aws_resources.clone());

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}\n", config_contents);

    if prompt {
        let options = &[
            "No, I am not ready to create resources!",
            "Yes, let's create resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("creating resources (with config path {})", config_path);
    let s3_manager = aws_s3::Manager::new(&shared_config);
    let _kms_manager = aws_kms::Manager::new(&shared_config);
    let _ec2_manager = aws_ec2::Manager::new(&shared_config);
    let _cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 1: create S3 bucket\n"),
        ResetColor
    )
    .unwrap();
    let _ret = rt
        .block_on(s3_manager.create_bucket(&aws_resources.bucket))
        .unwrap();
    // wait some time for bucket creation complete
    thread::sleep(time::Duration::from_secs(2));

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 2: create KMS key\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 3: create EC2 key pair\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 4: create EC2 instance role\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 5: create VPC\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    if config.machine.beacon_nodes.unwrap_or(0) > 0 {
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\nSTEP 6: create ASG for beacon nodes\n"),
            ResetColor
        )
        .unwrap();
        // TODO
        // get all IPs and IDs, update config path
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 6: create ASG for non-beacon nodes\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    Ok(())
}

fn run_delete(log_level: &str, config_path: &str, prompt: bool) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let config = network::load_config(config_path).unwrap();
    let aws_resources = config.aws_resources.clone().unwrap();

    let rt = Runtime::new().unwrap();
    let shared_config = rt
        .block_on(aws::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = aws_sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
    match aws_resources.identity {
        Some(identity) => {
            // AWS calls must be made from the same caller
            if identity != current_identity {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "config identity {:?} != currently loaded identity {:?}",
                        identity, current_identity
                    ),
                ));
            }
        }
        None => {
            return Err(Error::new(ErrorKind::Other, "unknown identity"));
        }
    }

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded configuration: '{}'\n", config_path)),
        ResetColor
    )
    .unwrap();
    let config_contents = config.to_string().unwrap();
    println!("{}\n", config_contents);

    if prompt {
        let options = &[
            "No, I am not ready to delete resources!",
            "Yes, let's delete resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    info!("deleting resources...");
    let _s3_manager = aws_s3::Manager::new(&shared_config);
    let _kms_manager = aws_kms::Manager::new(&shared_config);
    let _ec2_manager = aws_ec2::Manager::new(&shared_config);
    let _cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    Ok(())
}
