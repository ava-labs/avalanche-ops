use std::{
    fs,
    io::{self, stdout},
    sync::Arc,
};

use avalanche_utils::random;
use aws_sdk_manager::{self, s3};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use log::info;
use tokio::runtime::Runtime;

pub const NAME: &str = "update-artifacts";

pub fn subcommand() -> Command<'static> {
    Command::new(NAME)
        .about("Uploads new artifacts and triggers update event based on the spec file")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load and update")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_AVALANCHE_BIN") 
                .long("install-artifacts-avalanche-bin")
                .help("Sets the Avalanche node binary path in the local machine to be shared with remote machines")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTALL_ARTIFACTS_PLUGINS_DIR") 
                .long("install-artifacts-plugins-dir")
                .help("Sets 'plugins' directory in the local machine to be shared with remote machines")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

pub fn execute(
    log_level: &str,
    spec_file_path: &str,
    install_artifacts_avalanche_bin: &str,
    install_artifacts_plugins_dir: &str,
    skip_prompt: bool,
) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = avalancheup_aws::Spec::load(spec_file_path).expect("failed to load spec");
    spec.validate()?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded Spec: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml()?;
    println!("{}\n", spec_contents);

    if !skip_prompt {
        let options = &[
            "No, I am not ready to update artifacts!",
            "Yes, let's update artifacts!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'update-artifacts' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    let rt = Runtime::new().unwrap();
    let aws_resources = spec.aws_resources.expect("unexpected None aws_resources");
    let shared_config = rt
        .block_on(aws_sdk_manager::load_config(Some(
            aws_resources.region.clone(),
        )))
        .expect("failed to aws_sdk_manager::load_config");
    let s3_manager = s3::Manager::new(&shared_config);

    // compress as these will be decompressed by "avalanched"
    let tmp_avalanche_bin_compressed_path =
        random::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext())).unwrap();
    compress_manager::pack_file(
        install_artifacts_avalanche_bin,
        &tmp_avalanche_bin_compressed_path,
        compress_manager::Encoder::Zstd(3),
    )
    .expect("failed pack_file install_artifacts_avalanche_bin");
    rt.block_on(s3_manager.put_object(
        Arc::new(tmp_avalanche_bin_compressed_path.clone()),
        Arc::new(aws_resources.s3_bucket.clone()),
        Arc::new(avalancheup_aws::StorageNamespace::EventsUpdateArtifactsInstallDirAvalancheBinCompressed(spec.id.clone()).encode()),
    ))
    .expect("failed put_object compressed install_artifacts_avalanche_bin");
    fs::remove_file(tmp_avalanche_bin_compressed_path)?;
    if !install_artifacts_plugins_dir.is_empty() {
        for entry in fs::read_dir(&install_artifacts_plugins_dir).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();

            let file_path = entry_path.to_str().unwrap();
            let file_name = entry.file_name();
            let file_name = file_name.as_os_str().to_str().unwrap();

            let tmp_plugin_compressed_path =
                random::tmp_path(15, Some(compress_manager::Encoder::Zstd(3).ext())).unwrap();
            compress_manager::pack_file(
                file_path,
                &tmp_plugin_compressed_path,
                compress_manager::Encoder::Zstd(3),
            )
            .unwrap();

            info!(
                "uploading {} (compressed from {}) from plugins directory {}",
                tmp_plugin_compressed_path, file_path, install_artifacts_plugins_dir,
            );
            rt.block_on(
                s3_manager.put_object(
                    Arc::new(tmp_plugin_compressed_path.clone()),
                        Arc::new(aws_resources.s3_bucket.clone()),
                    Arc::new(format!(
                        "{}/{}{}",
                        &avalancheup_aws::StorageNamespace::EventsUpdateArtifactsInstallDirPluginsDir(spec.id.clone()).encode(),
                        file_name,
                        compress_manager::Encoder::Zstd(3).ext()
                    )),
                ),
            )
            .expect("failed put_object tmp_plugin_compressed_path");
            fs::remove_file(tmp_plugin_compressed_path)?;
        }
    }
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(aws_resources.s3_bucket),
        Arc::new(avalancheup_aws::StorageNamespace::EventsUpdateArtifactsEvent(spec.id).encode()),
    ))
    .expect("failed put_object EventsUpdateArtifactsEvent");

    println!();
    info!("update-artifacts all success!");
    println!();

    Ok(())
}
