use crate::aws::{
    Error::{Other, API},
    Result,
};

use aws_sdk_kms::{
    error::{
        CreateKeyError, CreateKeyErrorKind, DecryptError, DecryptErrorKind, EncryptError,
        EncryptErrorKind, GenerateDataKeyError, GenerateDataKeyErrorKind, ScheduleKeyDeletionError,
        ScheduleKeyDeletionErrorKind,
    },
    model::{DataKeySpec, EncryptionAlgorithmSpec},
    Client, SdkError,
};
use aws_smithy_types::Blob;
use log::{info, warn};

/// Implements AWS KMS manager.
pub struct Manager {
    #[allow(dead_code)]
    shared_config: aws_config::Config,
    cli: Client,
}

impl Manager {
    pub fn new(shared_config: &aws_config::Config) -> Self {
        let cloned = shared_config.clone();
        let cli = Client::new(shared_config);
        Self {
            shared_config: cloned,
            cli,
        }
    }

    /// Creates an AWS KMS CMK.
    pub async fn create_key(&self, key_desc: &str) -> Result<Key> {
        info!("creating KMS CMK '{}'", key_desc);
        let ret = self.cli.create_key().description(key_desc).send().await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed create_key {:?}", e),
                    is_retryable: is_error_retryable_create_key(&e),
                });
            }
        };

        let meta = match resp.key_metadata() {
            Some(v) => v,
            None => {
                return Err(Other {
                    message: String::from("unexpected empty key metadata"),
                    is_retryable: false,
                });
            }
        };
        let key_id = meta.key_id().unwrap_or("");
        let key_arn = meta.arn().unwrap_or("");

        info!("created KMS CMK id '{}' and arn '{}'", key_id, key_arn);
        Ok(Key::new(key_id, key_arn))
    }

    /// Schedules to delete a KMS CMK.
    pub async fn schedule_to_delete(&self, key_id: &str) -> Result<()> {
        info!("deleting KMS CMK '{}'", key_id);
        let ret = self
            .cli
            .schedule_key_deletion()
            .key_id(key_id)
            .pending_window_in_days(7)
            .send()
            .await;

        let deleted = match ret {
            Ok(_) => true,
            Err(e) => {
                let mut ignore_err: bool = false;
                if is_error_schedule_key_deletion_does_not_exist(&e) {
                    warn!("KMS CMK '{}' does not exist", key_id);
                    ignore_err = true
                }
                if is_error_schedule_key_deletion_already_scheduled(&e) {
                    warn!("KMS CMK '{}' already scheduled for deletion", key_id);
                    ignore_err = true
                }
                if !ignore_err {
                    return Err(API {
                        message: format!("failed schedule_key_deletion {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                false
            }
        };
        if deleted {
            info!("scheduled to delete KMS CMK '{}'", key_id);
        };

        Ok(())
    }

    /// Generates a data-encryption key.
    /// TODO: implement envelope encryption using DEK.
    /// ref. https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
    pub async fn generate_data_key(
        &self,
        key_id: &str,
        spec: Option<DataKeySpec>,
    ) -> Result<crate::crypto::DEK> {
        // default to "AES_256" for generate 256-bit symmetric key (32-byte)
        let dek_spec = spec.unwrap_or(DataKeySpec::Aes256);
        info!(
            "generating KMS data key for '{}' with key space {:?}",
            key_id, dek_spec
        );
        let ret = self
            .cli
            .generate_data_key()
            .key_id(key_id)
            .key_spec(dek_spec)
            .send()
            .await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed generate_data_key {:?}", e),
                    is_retryable: is_error_retryable_generate_data_key(&e),
                });
            }
        };

        let cipher = resp.ciphertext_blob().unwrap();
        let plain = resp.plaintext().unwrap();

        Ok(crate::crypto::DEK::new(
            cipher.clone().into_inner(),
            plain.clone().into_inner(),
        ))
    }

    /// Encrypts data.
    /// The maximum size of the data to encrypt is 4096 bytes to
    /// "SYMMETRIC_DEFAULT".
    /// ref. https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
    pub async fn encrypt(
        &self,
        key_id: &str,
        spec: Option<EncryptionAlgorithmSpec>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // default to "SYMMETRIC_DEFAULT"
        let key_spec = spec.unwrap_or(EncryptionAlgorithmSpec::SymmetricDefault);
        info!(
            "encrypting data with key '{}' and algorithm {:?} (total size {})",
            key_id,
            key_spec,
            crate::humanize::bytes(plaintext.len() as f64),
        );

        let ret = self
            .cli
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::new(plaintext))
            .encryption_algorithm(key_spec)
            .send()
            .await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed encrypt {:?}", e),
                    is_retryable: is_error_retryable_encrypt(&e),
                });
            }
        };

        let ciphertext = resp.ciphertext_blob().unwrap();
        Ok(ciphertext.clone().into_inner())
    }

    /// Decrypts data.
    /// The maximum length of "ciphertext" is 6144 bytes.
    /// ref. https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
    pub async fn decrypt(
        &self,
        key_id: &str,
        spec: Option<EncryptionAlgorithmSpec>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // default to "SYMMETRIC_DEFAULT"
        let key_spec = spec.unwrap_or(EncryptionAlgorithmSpec::SymmetricDefault);
        info!(
            "decrypting data with key '{}' and algorithm {:?} (total size {})",
            key_id,
            key_spec,
            crate::humanize::bytes(ciphertext.len() as f64),
        );

        let ret = self
            .cli
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext))
            .encryption_algorithm(key_spec)
            .send()
            .await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed decrypt {:?}", e),
                    is_retryable: is_error_retryable_decrypt(&e),
                });
            }
        };

        let plaintext = resp.plaintext().unwrap();
        Ok(plaintext.clone().into_inner())
    }
}

/// Represents the KMS CMK.
#[derive(Debug)]
pub struct Key {
    pub id: String,
    pub arn: String,
}

impl Key {
    pub fn new(id: &str, arn: &str) -> Self {
        // ref. https://doc.rust-lang.org/1.0.0/style/ownership/constructors.html
        Self {
            id: String::from(id),
            arn: String::from(arn),
        }
    }
}

#[inline]
pub fn is_error_retryable<E>(e: &SdkError<E>) -> bool {
    match e {
        SdkError::TimeoutError(_) | SdkError::ResponseError { .. } => true,
        SdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
pub fn is_error_retryable_create_key(e: &SdkError<CreateKeyError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                CreateKeyErrorKind::DependencyTimeoutException(_)
                    | CreateKeyErrorKind::KmsInternalException(_)
            )
        }
        _ => is_error_retryable(e),
    }
}

#[inline]
pub fn is_error_retryable_generate_data_key(e: &SdkError<GenerateDataKeyError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                GenerateDataKeyErrorKind::DependencyTimeoutException(_)
                    | GenerateDataKeyErrorKind::KmsInternalException(_)
                    | GenerateDataKeyErrorKind::KeyUnavailableException(_)
            )
        }
        _ => is_error_retryable(e),
    }
}

#[inline]
pub fn is_error_retryable_encrypt(e: &SdkError<EncryptError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                EncryptErrorKind::DependencyTimeoutException(_)
                    | EncryptErrorKind::KmsInternalException(_)
                    | EncryptErrorKind::KeyUnavailableException(_)
            )
        }
        _ => is_error_retryable(e),
    }
}

#[inline]
pub fn is_error_retryable_decrypt(e: &SdkError<DecryptError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                DecryptErrorKind::DependencyTimeoutException(_)
                    | DecryptErrorKind::KmsInternalException(_)
                    | DecryptErrorKind::KeyUnavailableException(_)
            )
        }
        _ => is_error_retryable(e),
    }
}

#[inline]
fn is_error_schedule_key_deletion_does_not_exist(e: &SdkError<ScheduleKeyDeletionError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(err.kind, ScheduleKeyDeletionErrorKind::NotFoundException(_))
        }
        _ => false,
    }
}

#[inline]
fn is_error_schedule_key_deletion_already_scheduled(
    e: &SdkError<ScheduleKeyDeletionError>,
) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            let msg = format!("{:?}", err);
            msg.contains("pending deletion")
        }
        _ => false,
    }
}
