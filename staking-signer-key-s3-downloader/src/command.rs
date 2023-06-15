use std::{
    io::{self, Error, ErrorKind},
    path::Path,
};

use crate::flags;
use aws_manager::{
    self,
    kms::{self, envelope},
    s3,
};
use tokio::time::Duration;

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    println!("starting {} with {:?}", crate::APP_NAME, opts);

    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let s3_shared_config = aws_manager::load_config(
        Some(opts.s3_region.clone()),
        Some(opts.profile_name.clone()),
        Some(Duration::from_secs(30)),
    )
    .await;
    let s3_manager = s3::Manager::new(&s3_shared_config);

    let kms_shared_config = aws_manager::load_config(
        Some(opts.kms_region.clone()),
        Some(opts.profile_name.clone()),
        Some(Duration::from_secs(30)),
    )
    .await;
    let kms_manager = kms::Manager::new(&kms_shared_config);

    let envelope_manager = envelope::Manager::new(
        &kms_manager,
        opts.kms_key_id.clone(),
        // must've be equal for envelope encryption
        // e.g., "cfn-templates" tag "AAD_TAG"
        opts.aad_tag.clone(),
    );

    let key_exists = Path::new(&opts.key_path).exists();
    log::info!("staking TLS key {} exists? {}", opts.key_path, key_exists);

    log::info!("downloading key file {}", opts.key_path);
    envelope_manager
        .get_object_unseal_decompress(
            &s3_manager,
            &opts.s3_bucket,
            &opts.s3_key,
            &opts.key_path,
            false,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed get_object_unseal_decompress key_path: {}", e),
            )
        })?;

    Ok(())
}
