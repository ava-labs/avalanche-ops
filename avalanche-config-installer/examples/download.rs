use std::{fs, io};

use avalanche_config_installer::{github, s3 as s3_installer};
use aws_manager::{self, s3};
use tokio::time::{sleep, Duration};

/// cargo run --example download
#[tokio::main]
async fn main() -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let bin_path = random_manager::tmp_path(10, None)?;
    github::download_latest(None, None, &bin_path)
        .await
        .unwrap();
    log::info!("downloaded {bin_path}");

    let shared_config = aws_manager::load_config(Some(String::from("us-east-1")))
        .await
        .unwrap();
    let s3_manager = s3::Manager::new(&shared_config);
    let s3_bucket = format!(
        "installer-{}",
        random_manager::secure_string(10).to_lowercase()
    );

    s3_manager.create_bucket(&s3_bucket).await.unwrap();

    sleep(Duration::from_secs(2)).await;
    let s3_installer_key = "sub-dir/test-bin".to_string();
    s3_manager
        .put_object(&bin_path, &s3_bucket, &s3_installer_key)
        .await
        .unwrap();

    sleep(Duration::from_secs(5)).await;
    let target_bin_path = random_manager::tmp_path(15, None)?;
    s3_installer::download(
        true,
        &s3_manager,
        &s3_bucket,
        &s3_installer_key,
        &target_bin_path,
    )
    .await
    .unwrap();

    log::info!("removing {target_bin_path}");
    fs::remove_file(&target_bin_path)?;

    s3_manager.delete_objects(&s3_bucket, None).await.unwrap();

    sleep(Duration::from_secs(2)).await;
    s3_manager.delete_bucket(&s3_bucket).await.unwrap();

    Ok(())
}
