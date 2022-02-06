use std::{
    fs,
    io::{self, stdout, Error, ErrorKind},
    path::Path,
    thread,
    time::{self, Duration},
};

use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use clap::{arg, App, AppSettings};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

use avalanche_ops::{
    aws, aws_cloudformation, aws_ec2, aws_kms, aws_s3, aws_sts, compress, network,
};

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

/// TODO: better error handling rather than just panic with "unwrap"
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

/// TODO: better error handling rather than just panic with "unwrap"
fn run_apply(log_level: &str, config_path: &str, prompt: bool) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    #[derive(RustEmbed)]
    #[folder = "cloudformation/"]
    #[prefix = "cloudformation/"]
    struct Asset;

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
    if aws_resources.ec2_key_name.is_none() {
        aws_resources.ec2_key_name = Some(format!("{}-ec2-key", config.id));
    }
    if aws_resources.cloudformation_ec2_instance_role.is_none() {
        aws_resources.cloudformation_ec2_instance_role =
            Some(format!("{}-ec2-instance-role", config.id));
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc = Some(format!("{}-vpc", config.id));
    }
    if !config.is_mainnet() && aws_resources.cloudformation_asg_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_beacon_nodes =
            Some(format!("{}-asg-beacon-nodes", config.id));
    }
    if aws_resources.cloudformation_asg_non_beacon_nodes.is_none() {
        aws_resources.cloudformation_asg_non_beacon_nodes =
            Some(format!("{}-asg-non-beacon-nodes", config.id));
    }
    config.aws_resources = Some(aws_resources.clone());
    config.sync(config_path).unwrap();

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
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 1: create S3 bucket\n"),
        ResetColor
    )
    .unwrap();
    rt.block_on(s3_manager.create_bucket(&aws_resources.bucket))
        .unwrap();

    if aws_resources.kms_cmk_id.is_none() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\nSTEP 2: create KMS key\n"),
            ResetColor
        )
        .unwrap();
        let key = rt
            .block_on(kms_manager.create_key(format!("{}-cmk", config.id).as_str()))
            .unwrap();
        aws_resources.kms_cmk_id = Some(key.id);
        aws_resources.kms_cmk_arn = Some(key.arn);
        config.aws_resources = Some(aws_resources.clone());
        config.sync(config_path).unwrap();
    }

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 3: create EC2 key pair\n"),
        ResetColor
    )
    .unwrap();
    let ec2_key_path = get_ec2_key_path(config_path);
    rt.block_on(ec2_manager.create_key_pair(
        aws_resources.ec2_key_name.unwrap().as_str(),
        ec2_key_path.as_str(),
    ))
    .unwrap();
    aws_resources.ec2_key_path = Some(ec2_key_path.clone());
    config.sync(config_path).unwrap();
    let ec2_key_path_compressed = get_zstd_path(ec2_key_path.as_str());
    compress::compress_zstd(
        ec2_key_path.as_str(),
        ec2_key_path_compressed.as_str(),
        None,
    )
    .unwrap();
    let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
    rt.block_on(kms_manager.encrypt_file(
        aws_resources.kms_cmk_id.unwrap().as_str(),
        None,
        ec2_key_path_compressed.as_str(),
        ec2_key_path_compressed_encrypted.as_str(),
    ))
    .unwrap();
    rt.block_on(s3_manager.put_object(
        aws_resources.bucket.as_str(),
        ec2_key_path_compressed_encrypted.as_str(),
        format!("{}/ec2.key-compressed.zstd.encrypted", config.id).as_str(),
    ))
    .unwrap();

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 4: create EC2 instance role\n"),
        ResetColor
    )
    .unwrap();
    let ec2_instance_role_yaml = Asset::get("cloudformation/ec2_instance_role.yaml").unwrap();
    let ec2_instance_role_tmpl = std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
    let ec2_instance_role_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
    rt.block_on(
        cloudformation_manager.create_stack(
            ec2_instance_role_name.as_str(),
            Capability::CapabilityNamedIam,
            OnFailure::Delete,
            ec2_instance_role_tmpl,
            Some(Vec::from([Tag::builder()
                .key("kind")
                .value("avalanche-ops")
                .build()])),
            Some(Vec::from([
                Parameter::builder()
                    .parameter_key("Id")
                    .parameter_value(config.id)
                    .build(),
                Parameter::builder()
                    .parameter_key("KMSKeyArn")
                    .parameter_value(aws_resources.kms_cmk_arn.unwrap())
                    .build(),
                Parameter::builder()
                    .parameter_key("S3BucketName")
                    .parameter_value(aws_resources.bucket)
                    .build(),
            ])),
        ),
    )
    .unwrap();
    thread::sleep(time::Duration::from_secs(10));
    rt.block_on(cloudformation_manager.poll_stack(
        ec2_instance_role_name.as_str(),
        StackStatus::CreateComplete,
        Duration::from_secs(300),
        Duration::from_secs(20),
    ))
    .unwrap();

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 5: create VPC\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    if config.machine.beacon_nodes.unwrap_or(0) > 0 {
        thread::sleep(time::Duration::from_secs(2));
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

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\nSTEP 7: create ASG for non-beacon nodes\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    Ok(())
}

/// TODO: better error handling rather than just panic with "unwrap"
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
    let s3_manager = aws_s3::Manager::new(&shared_config);
    let kms_manager = aws_kms::Manager::new(&shared_config);
    let ec2_manager = aws_ec2::Manager::new(&shared_config);
    let cloudformation_manager = aws_cloudformation::Manager::new(&shared_config);

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\nSTEP 1: delete ASG for non-beacon nodes\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    if config.machine.beacon_nodes.unwrap_or(0) > 0 {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\nSTEP 2: delete ASG for beacon nodes\n"),
            ResetColor
        )
        .unwrap();
        // TODO
    }

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\nSTEP 3: delete VPC\n"),
        ResetColor
    )
    .unwrap();
    // TODO

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\nSTEP 4: delete EC2 instance role\n"),
        ResetColor
    )
    .unwrap();
    let ec2_instance_role_name = aws_resources.cloudformation_ec2_instance_role.unwrap();
    rt.block_on(cloudformation_manager.delete_stack(ec2_instance_role_name.as_str()))
        .unwrap();
    thread::sleep(time::Duration::from_secs(10));
    rt.block_on(cloudformation_manager.poll_stack(
        ec2_instance_role_name.as_str(),
        StackStatus::DeleteComplete,
        Duration::from_secs(300),
        Duration::from_secs(20),
    ))
    .unwrap();

    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\nSTEP 5: delete EC2 key pair\n"),
        ResetColor
    )
    .unwrap();
    if aws_resources.ec2_key_path.is_some() {
        let ec2_key_path = aws_resources.ec2_key_path.unwrap();
        if Path::new(ec2_key_path.as_str()).exists() {
            fs::remove_file(ec2_key_path.as_str()).unwrap();
        }
        let ec2_key_path_compressed = get_zstd_path(ec2_key_path.as_str());
        if Path::new(ec2_key_path_compressed.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed.as_str()).unwrap();
        }
        let ec2_key_path_compressed_encrypted = format!("{}.encrypted", ec2_key_path_compressed);
        if Path::new(ec2_key_path_compressed_encrypted.as_str()).exists() {
            fs::remove_file(ec2_key_path_compressed_encrypted.as_str()).unwrap();
        }
    }
    if aws_resources.ec2_key_name.is_some() {
        rt.block_on(ec2_manager.delete_key_pair(aws_resources.ec2_key_name.unwrap().as_str()))
            .unwrap();
    }

    if aws_resources.kms_cmk_id.is_some() {
        thread::sleep(time::Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Red),
            Print("\n\nSTEP 6: delete KMS key\n"),
            ResetColor
        )
        .unwrap();
        let cmk_id = aws_resources.kms_cmk_id.unwrap();
        rt.block_on(kms_manager.schedule_to_delete(cmk_id.as_str()))
            .unwrap();
    }

    // TODO: add "--delete-bucket" flag to skip delete
    thread::sleep(time::Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print("\n\nSTEP 7: delete S3 bucket\n"),
        ResetColor
    )
    .unwrap();
    rt.block_on(s3_manager.delete_objects(aws_resources.bucket.as_str(), None))
        .unwrap();
    rt.block_on(s3_manager.delete_bucket(aws_resources.bucket.as_str()))
        .unwrap();

    Ok(())
}

fn get_ec2_key_path(config_path: &str) -> String {
    let path = Path::new(config_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ec2.key", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

fn get_zstd_path(p: &str) -> String {
    let path = Path::new(p);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-compressed.zstd", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}
