use std::{
    io::{self, Error, ErrorKind},
    path::Path,
};

use crate::flags;
use avalanche_types::ids::node;
use aws_manager::{
    self,
    kms::{self, envelope},
    s3,
};

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    println!("starting {} with {:?}", crate::APP_NAME, opts);

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let shared_config = aws_manager::load_config(Some(opts.region.clone())).await?;
    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);

    let envelope_manager = envelope::Manager::new(
        &kms_manager,
        opts.kms_cmk_id.clone(),
        // must've be equal for envelope encryption
        // e.g., "cfn-templates" tag "AAD_TAG"
        opts.aad_tag.clone(),
    );

    let tls_key_exists = Path::new(&opts.tls_key_path).exists();
    log::info!(
        "staking TLS key {} exists? {}",
        opts.tls_key_path,
        tls_key_exists
    );

    let tls_cert_exists = Path::new(&opts.tls_cert_path).exists();
    log::info!(
        "staking TLS cert {} exists? {}",
        opts.tls_cert_path,
        tls_cert_exists
    );

    if tls_key_exists || tls_cert_exists {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "TLS key {} or cert {} already exists on disk",
                opts.tls_key_path, opts.tls_cert_path
            ),
        ));
    }

    log::info!("downloading key file {}", opts.tls_key_path);
    envelope_manager
        .get_object_unseal_decompress(
            &s3_manager,
            &opts.s3_bucket,
            &opts.s3_key_tls_key,
            &opts.tls_key_path,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed get_object_unseal_decompress tls_key_path: {}", e),
            )
        })?;

    log::info!("downloading cert file {}", opts.tls_cert_path);
    envelope_manager
        .get_object_unseal_decompress(
            &s3_manager,
            &opts.s3_bucket,
            &opts.s3_key_tls_cert,
            &opts.tls_cert_path,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed get_object_unseal_decompress tls_cert_path: {}", e),
            )
        })?;

    let node_id = node::Id::from_cert_pem_file(&opts.tls_cert_path)?;

    log::info!(
        "downloaded the node Id '{}' cert in '{}' and '{}'",
        node_id,
        opts.tls_key_path,
        opts.tls_cert_path
    );

    Ok(())
}
