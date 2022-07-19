use std::io;

use crate::flags;
use aws_manager::{
    self,
    kms::{self, envelope},
    s3,
};
use infra_aws::certs;

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting {}", crate::APP_NAME);

    let aws_creds = load_aws_credential(&opts.aws_region).await?;
    let envelope_manager = envelope::Manager::new(
        aws_creds.kms_manager.clone(),
        opts.kms_cmk_id.clone(),
        // must've be equal for envelope encryption
        // e.g., "cfn-templates" tag "AAD_TAG"
        opts.aad_tag.clone(),
    );
    let certs_manager = certs::Manager {
        envelope_manager,
        s3_manager: aws_creds.s3_manager.clone(),
        s3_bucket: opts.s3_bucket.clone(),
    };

    let node_id = certs_manager
        .download(
            &opts.s3_key_tls_key,
            &opts.s3_key_tls_cert,
            &opts.tls_key_path,
            &opts.tls_cert_path,
        )
        .await?;
    log::info!(
        "downloaded the node Id '{}' cert in '{}' and '{}'",
        node_id,
        opts.tls_key_path,
        opts.tls_cert_path
    );

    Ok(())
}

#[derive(Debug, Clone)]
struct AwsCreds {
    kms_manager: kms::Manager,
    s3_manager: s3::Manager,
}

async fn load_aws_credential(reg: &str) -> io::Result<AwsCreds> {
    log::info!("STEP: loading up AWS credential for region '{}'...", reg);

    let shared_config = aws_manager::load_config(Some(reg.to_string())).await?;

    let kms_manager = kms::Manager::new(&shared_config);
    let s3_manager = s3::Manager::new(&shared_config);

    Ok(AwsCreds {
        kms_manager,
        s3_manager,
    })
}
