use std::{
    io::{self, Error, ErrorKind},
    path::Path,
};

use avalanche_types::{ids::node, key::cert};
use aws_manager::{self, kms::envelope, s3};

/// Generates a new certificate if there is no existing certificate for reuse.
/// Once generated, it backs up to S3.
pub struct Manager {
    pub envelope_manager: envelope::Manager,
    pub s3_manager: s3::Manager,
    pub s3_bucket: String,
}

impl Manager {
    /// Loads the existing staking certificates if exists.
    /// Otherwise, generate a pair.
    /// Returns "true" if generated.
    pub async fn load_or_generate(
        &self,
        tls_key_path: &str,
        tls_cert_path: &str,
    ) -> io::Result<(node::Id, bool)> {
        let tls_key_exists = Path::new(&tls_key_path).exists();
        log::info!(
            "staking TLS key {} exists? {}",
            tls_key_path,
            tls_key_exists
        );

        let tls_cert_exists = Path::new(&tls_cert_path).exists();
        log::info!(
            "staking TLS cert {} exists? {}",
            tls_cert_path,
            tls_cert_exists
        );

        let mut generated = false;
        if !tls_key_exists || !tls_cert_exists {
            log::info!(
                "generating TLS certs (key exists {}, cert exists {})",
                tls_key_exists,
                tls_cert_exists
            );
            cert::x509::generate_default_pem(tls_key_path, tls_cert_path)?;
            generated = true;
        } else {
            log::info!(
                "loading existing staking TLS certificates from '{}' and '{}'",
                tls_key_path,
                tls_cert_path
            );
        }

        let node_id = node::Id::from_cert_pem_file(tls_cert_path)?;
        Ok((node_id, generated))
    }

    /// Uploads the staking certificates to the remote storage.
    /// It envelope-encrypts using KMS.
    pub async fn upload(
        &self,
        tls_key_path: &str,
        tls_cert_path: &str,
        s3_key_tls_key: &str,
        s3_key_tls_cert: &str,
    ) -> io::Result<()> {
        log::info!("uploading key file {}", tls_key_path);
        s3::spawn_compress_seal_put_object(
            self.s3_manager.clone(),
            self.envelope_manager.clone(),
            tls_key_path,
            &self.s3_bucket,
            s3_key_tls_key,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed spawn_compress_seal_put_object tls_key_path: {}", e),
            )
        })?;

        log::info!("uploading cert file {}", tls_cert_path);
        s3::spawn_compress_seal_put_object(
            self.s3_manager.clone(),
            self.envelope_manager.clone(),
            tls_cert_path,
            &self.s3_bucket,
            s3_key_tls_cert,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed spawn_compress_seal_put_object tls_cert_path: {}", e),
            )
        })
    }

    /// Downloads the staking certificates from the remote storage.
    /// It envelope-decrypts using KMS.
    pub async fn download(
        &self,
        s3_key_tls_key: &str,
        s3_key_tls_cert: &str,
        tls_key_path: &str,
        tls_cert_path: &str,
    ) -> io::Result<node::Id> {
        let tls_key_exists = Path::new(&tls_key_path).exists();
        log::info!(
            "staking TLS key {} exists? {}",
            tls_key_path,
            tls_key_exists
        );

        let tls_cert_exists = Path::new(&tls_cert_path).exists();
        log::info!(
            "staking TLS cert {} exists? {}",
            tls_cert_path,
            tls_cert_exists
        );

        if tls_key_exists || tls_cert_exists {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "TLS key {} or cert {} already exists on disk",
                    tls_key_path, tls_cert_path
                ),
            ));
        }

        log::info!("downloading key file {}", tls_key_path);
        s3::spawn_get_object_unseal_decompress(
            self.s3_manager.clone(),
            self.envelope_manager.clone(),
            self.s3_bucket.as_str(),
            s3_key_tls_key,
            tls_key_path,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "failed spawn_get_object_unseal_decompress tls_key_path: {}",
                    e
                ),
            )
        })?;

        log::info!("downloading cert file {}", tls_cert_path);
        s3::spawn_get_object_unseal_decompress(
            self.s3_manager.clone(),
            self.envelope_manager.clone(),
            self.s3_bucket.as_str(),
            s3_key_tls_cert,
            tls_cert_path,
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "failed spawn_get_object_unseal_decompress tls_cert_path: {}",
                    e
                ),
            )
        })?;

        node::Id::from_cert_pem_file(tls_cert_path)
    }
}
