use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    string::String,
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
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{info, warn};
/// "NONCE_LEN" is the per-record nonce (iv_length), 12-byte
/// ref. https://www.rfc-editor.org/rfc/rfc8446#appendix-E.2
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

use crate::aws::{
    Error::{Other, API},
    Result,
};

const DEK_AES_256_LENGTH: usize = 32;

const AAD_TAG: &str = "avalanche-ops-envelope-encryption";

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
            crate::humanize::bytes(ciphertext.len() as f64),
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
            crate::humanize::bytes(plaintext.len() as f64),
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

    /// Envelope-encrypts the data using KMS data-encryption key (DEK)
    /// and "AES_256_GCM", since kms:Encrypt can only encrypt 4 KiB).
    /// The encrypted data are aligned as below:
    /// [ Nonce bytes "length" ][ DEK.ciphertext "length" ][ Nonce bytes ][ DEK.ciphertext ][ data ciphertext ]
    pub async fn seal_aes_256(&self, key_id: &str, d: &[u8]) -> Result<Vec<u8>> {
        info!(
            "AES_256 envelope-encrypting data (size before encryption {})",
            crate::humanize::bytes(d.len() as f64)
        );
        let dek = self
            .generate_data_key(key_id, Some(DataKeySpec::Aes256))
            .await?;
        if dek.plaintext.len() != DEK_AES_256_LENGTH {
            return Err(Other {
                message: format!(
                    "DEK.plaintext for AES_256 must be {}-byte, got {}-byte",
                    DEK_AES_256_LENGTH,
                    dek.plaintext.len()
                ),
                is_retryable: false,
            });
        }

        let random = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        match random.fill(&mut nonce_bytes) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to generate ring.random for nonce ({:?})", e),
                    is_retryable: false,
                });
            }
        }
        let unbound_key = match UnboundKey::new(&AES_256_GCM, &dek.plaintext) {
            Ok(v) => v,
            Err(e) => {
                return Err(Other {
                    message: format!("failed to create UnboundKey ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        let safe_key = LessSafeKey::new(unbound_key);

        // overwrites the original array
        let mut cipher = d.to_vec();
        match safe_key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD_TAG),
            &mut cipher,
        ) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to seal ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        // align bytes in the order of
        // - Nonce bytes "length"
        // - DEK.ciphertext "length"
        // - Nonce bytes
        // - DEK.ciphertext
        // - data ciphertext
        let mut encrypted = Vec::new();

        // Nonce bytes "length"
        match encrypted.write_u16::<LittleEndian>(NONCE_LEN as u16) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        // DEK.ciphertext "length"
        match encrypted.write_u16::<LittleEndian>(dek.ciphertext.len() as u16) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        // Nonce bytes
        match encrypted.write_all(&nonce_bytes) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        // DEK.ciphertext
        match encrypted.write_all(&dek.ciphertext) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        // data ciphertext
        match encrypted.write_all(&cipher) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write ({:?})", e),
                    is_retryable: false,
                });
            }
        }

        info!(
            "AES_256 envelope-encrypted data (encrypted size {})",
            crate::humanize::bytes(encrypted.len() as f64)
        );
        Ok(encrypted)
    }

    /// Envelope-decrypts using KMS DEK and "AES_256_GCM".
    /// Assume the input (ciphertext) data are packed in the order of:
    /// [ Nonce bytes "length" ][ DEK.ciphertext "length" ][ Nonce bytes ][ DEK.ciphertext ][ data ciphertext ]
    pub async fn unseal_aes_256(&self, key_id: &str, d: &[u8]) -> Result<Vec<u8>> {
        info!(
            "AES_256 envelope-decrypting data (size before decryption {})",
            crate::humanize::bytes(d.len() as f64)
        );

        // bytes are packed in the order of
        // - Nonce bytes "length"
        // - DEK.ciphertext "length"
        // - Nonce bytes
        // - DEK.ciphertext
        // - data ciphertext
        let mut buf = Cursor::new(d);

        let nonce_len = match buf.read_u16::<LittleEndian>() {
            Ok(v) => v as usize,
            Err(e) => {
                return Err(Other {
                    message: format!("failed to read_u16 for nonce_len ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        if nonce_len != NONCE_LEN {
            return Err(Other {
                message: format!("nonce_len {} != NONCE_LEN {}", nonce_len, NONCE_LEN),
                is_retryable: false,
            });
        }

        let dek_ciphertext_len = match buf.read_u16::<LittleEndian>() {
            Ok(v) => v as usize,
            Err(e) => {
                return Err(Other {
                    message: format!("failed to read_u16 for dek_ciphertext_len ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        if dek_ciphertext_len > d.len() {
            return Err(Other {
                message: format!(
                    "invalid DEK ciphertext len {} > cipher.len {}",
                    dek_ciphertext_len,
                    d.len()
                ),
                is_retryable: false,
            });
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        match buf.read_exact(&mut nonce_bytes) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to read_exact for nonce_bytes ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut dek_ciphertext = zero_vec(dek_ciphertext_len);
        match buf.read_exact(&mut dek_ciphertext) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to read_exact for DEK.ciphertext ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        // use the default "SYMMETRIC_DEFAULT"
        let dek_plain = self
            .decrypt(
                key_id,
                Some(EncryptionAlgorithmSpec::SymmetricDefault),
                dek_ciphertext,
            )
            .await?;
        let unbound_key = match UnboundKey::new(&AES_256_GCM, &dek_plain) {
            Ok(v) => v,
            Err(e) => {
                return Err(Other {
                    message: format!("failed to create UnboundKey ({:?})", e),
                    is_retryable: false,
                });
            }
        };
        let safe_key = LessSafeKey::new(unbound_key);

        let mut cipher = Vec::new();
        match buf.read_to_end(&mut cipher) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to read_to_end for ciphertext ({:?})", e),
                    is_retryable: false,
                });
            }
        };

        let decrypted = match safe_key.open_in_place(nonce, Aad::from(AAD_TAG), &mut cipher) {
            Ok(plaintext) => plaintext.to_vec(),
            Err(e) => {
                return Err(Other {
                    message: format!("failed to open_in_place ciphertext ({:?})", e),
                    is_retryable: false,
                });
            }
        };

        info!(
            "AES_256 envelope-decrypted data (decrypted size {})",
            crate::humanize::bytes(decrypted.len() as f64)
        );
        Ok(decrypted)
    }

    /// Envelope-encrypts data from a file and save the ciphertext to the other file.
    pub async fn seal_aes_256_file(
        &self,
        key_id: &str,
        src_file: &str,
        dst_file: &str,
    ) -> Result<()> {
        info!("envelope-encrypting file {} to {}", src_file, dst_file);
        let d = match fs::read(src_file) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let ciphertext = match self.seal_aes_256(key_id, &d).await {
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

    /// Envelope-decrypts data from a file and save the plaintext to the other file.
    pub async fn unseal_aes_256_file(
        &self,
        key_id: &str,
        src_file: &str,
        dst_file: &str,
    ) -> Result<()> {
        info!("envelope-decrypting file {} to {}", src_file, dst_file);
        let d = match fs::read(src_file) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let plaintext = match self.unseal_aes_256(key_id, &d).await {
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

fn zero_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| 0).collect()
}
