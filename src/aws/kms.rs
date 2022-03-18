use std::{
    fs::{self, File},
    io::Write,
    string::String,
};

use aws_sdk_kms::{
    error::{
        CreateKeyError, CreateKeyErrorKind, DecryptError, DecryptErrorKind, EncryptError,
        EncryptErrorKind, GenerateDataKeyError, GenerateDataKeyErrorKind, ScheduleKeyDeletionError,
        ScheduleKeyDeletionErrorKind,
    },
    model::{DataKeySpec, EncryptionAlgorithmSpec, Tag},
    types::{Blob, SdkError},
    Client,
};
use aws_types::SdkConfig as AwsSdkConfig;
use log::{info, warn};

use crate::{
    errors::{
        Error::{Other, API},
        Result,
    },
    utils::humanize,
};

/// Represents the data encryption key.
#[derive(Debug)]
pub struct DEK {
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
}

impl DEK {
    pub fn new(cipher: Vec<u8>, plain: Vec<u8>) -> Self {
        // ref. https://doc.rust-lang.org/1.0.0/style/ownership/constructors.html
        Self {
            ciphertext: cipher,
            plaintext: plain,
        }
    }
}

/// Implements AWS KMS manager.
#[derive(Debug, Clone)]
pub struct Manager {
    #[allow(dead_code)]
    shared_config: AwsSdkConfig,
    cli: Client,
}

impl Manager {
    pub fn new(shared_config: &AwsSdkConfig) -> Self {
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
        let ret = self
            .cli
            .create_key()
            .description(key_desc)
            .tags(Tag::builder().tag_key("Name").tag_value(key_desc).build())
            .tags(
                Tag::builder()
                    .tag_key("KIND")
                    .tag_value("avalanche-ops")
                    .build(),
            )
            .send()
            .await;
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

    /// Encrypts data. The maximum size of the data KMS can encrypt is 4096 bytes for
    /// "SYMMETRIC_DEFAULT" encryption algorithm. To specify a KMS key, use its key ID,
    /// key ARN, alias name, or alias ARN.
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
            "encrypting data (plaintext size {})",
            humanize::bytes(plaintext.len() as f64),
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

        let ciphertext = match resp.ciphertext_blob() {
            Some(v) => v,
            None => {
                return Err(API {
                    message: String::from("EncryptOutput.ciphertext_blob not foun"),
                    is_retryable: false,
                });
            }
        };
        let ciphertext = ciphertext.clone().into_inner();

        info!(
            "encrypted data (ciphertext size {})",
            humanize::bytes(ciphertext.len() as f64),
        );
        Ok(ciphertext)
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
            "decrypting data (ciphertext size {})",
            humanize::bytes(ciphertext.len() as f64),
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

        let plaintext = match resp.plaintext() {
            Some(v) => v,
            None => {
                return Err(API {
                    message: String::from("DecryptOutput.plaintext not foun"),
                    is_retryable: false,
                });
            }
        };
        let plaintext = plaintext.clone().into_inner();

        info!(
            "decrypted data (plaintext size {})",
            humanize::bytes(plaintext.len() as f64),
        );
        Ok(plaintext)
    }

    /// Encrypts data from a file and save the ciphertext to the other file.
    pub async fn encrypt_file(
        &self,
        key_id: &str,
        spec: Option<EncryptionAlgorithmSpec>,
        src_file: &str,
        dst_file: &str,
    ) -> Result<()> {
        info!("encrypting file {} to {}", src_file, dst_file);
        let d = match fs::read(src_file) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let ciphertext = match self.encrypt(key_id, spec, d).await {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };

        let mut f = match File::create(dst_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Other {
                    message: format!("failed File::create {:?}", e),
                    is_retryable: false,
                });
            }
        };
        match f.write_all(&ciphertext) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed File::write_all {:?}", e),
                    is_retryable: false,
                });
            }
        };

        Ok(())
    }

    /// Decrypts data from a file and save the plaintext to the other file.
    pub async fn decrypt_file(
        &self,
        key_id: &str,
        spec: Option<EncryptionAlgorithmSpec>,
        src_file: &str,
        dst_file: &str,
    ) -> Result<()> {
        info!("decrypting file {} to {}", src_file, dst_file);
        let d = match fs::read(src_file) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let plaintext = match self.decrypt(key_id, spec, d).await {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };

        let mut f = match File::create(dst_file) {
            Ok(f) => f,
            Err(e) => {
                return Err(Other {
                    message: format!("failed File::create {:?}", e),
                    is_retryable: false,
                });
            }
        };
        match f.write_all(&plaintext) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed File::write_all {:?}", e),
                    is_retryable: false,
                });
            }
        };

        Ok(())
    }

    /// Generates a data-encryption key.
    /// The default key spec is AES_256 generate a 256-bit symmetric key.
    /// ref. https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
    pub async fn generate_data_key(&self, key_id: &str, spec: Option<DataKeySpec>) -> Result<DEK> {
        // default to "AES_256" for generate 256-bit symmetric key (32-byte)
        let dek_spec = spec.unwrap_or(DataKeySpec::Aes256);
        info!(
            "generating KMS data key for '{}' with key spec {:?}",
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
        Ok(DEK::new(
            cipher.clone().into_inner(),
            plain.clone().into_inner(),
        ))
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
        _ => false,
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
        _ => false,
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
        _ => false,
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
        _ => false,
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
