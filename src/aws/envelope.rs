use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    sync::Arc,
};

use aws_sdk_kms::model::{DataKeySpec, EncryptionAlgorithmSpec};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::info;
/// "NONCE_LEN" is the per-record nonce (iv_length), 12-byte
/// ref. https://www.rfc-editor.org/rfc/rfc8446#appendix-E.2
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

use crate::{
    aws::kms,
    errors::{Error::Other, Result},
    utils::humanize,
};

const DEK_AES_256_LENGTH: usize = 32;

const AAD_TAG: &str = "avalanche-ops-envelope-encryption";

/// Implements envelope encryption manager.
#[derive(std::clone::Clone)]
pub struct Envelope {
    aws_kms_manager: Option<kms::Manager>,
    aws_kms_key_id: Option<String>,
}

impl Envelope {
    pub fn new(aws_kms_manager: Option<kms::Manager>, aws_kms_key_id: Option<String>) -> Self {
        Self {
            aws_kms_manager,
            aws_kms_key_id,
        }
    }

    /// Envelope-encrypts the data using AWS KMS data-encryption key (DEK)
    /// and "AES_256_GCM", since kms:Encrypt can only encrypt 4 KiB).
    /// The encrypted data are aligned as below:
    /// [ Nonce bytes "length" ][ DEK.ciphertext "length" ][ Nonce bytes ][ DEK.ciphertext ][ data ciphertext ]
    pub async fn seal_aes_256(&self, d: &[u8]) -> Result<Vec<u8>> {
        info!(
            "AES_256 envelope-encrypting data (size before encryption {})",
            humanize::bytes(d.len() as f64)
        );

        if self.aws_kms_manager.is_none() || self.aws_kms_key_id.is_none() {
            return Err(Other {
                message: String::from("Envelope.aws_kms_manager and aws_kms_key_id not found"),
                is_retryable: false,
            });
        }
        let kms_manager = self.aws_kms_manager.clone().unwrap();
        let key_id = self.aws_kms_key_id.clone().unwrap();

        let dek = kms_manager
            .generate_data_key(&key_id, Some(DataKeySpec::Aes256))
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
            humanize::bytes(encrypted.len() as f64)
        );
        Ok(encrypted)
    }

    /// Envelope-decrypts using KMS DEK and "AES_256_GCM".
    /// Assume the input (ciphertext) data are packed in the order of:
    /// [ Nonce bytes "length" ][ DEK.ciphertext "length" ][ Nonce bytes ][ DEK.ciphertext ][ data ciphertext ]
    pub async fn unseal_aes_256(&self, d: &[u8]) -> Result<Vec<u8>> {
        info!(
            "AES_256 envelope-decrypting data (size before decryption {})",
            humanize::bytes(d.len() as f64)
        );

        if self.aws_kms_manager.is_none() || self.aws_kms_key_id.is_none() {
            return Err(Other {
                message: String::from("Envelope.aws_kms_manager and aws_kms_key_id not found"),
                is_retryable: false,
            });
        }
        let kms_manager = self.aws_kms_manager.clone().unwrap();
        let key_id = self.aws_kms_key_id.clone().unwrap();

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
        let dek_plain = kms_manager
            .decrypt(
                &key_id,
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
            humanize::bytes(decrypted.len() as f64)
        );
        Ok(decrypted)
    }

    /// Envelope-encrypts data from a file and save the ciphertext to the other file.
    pub async fn seal_aes_256_file(
        &self,
        src_file: Arc<String>,
        dst_file: Arc<String>,
    ) -> Result<()> {
        info!("envelope-encrypting file {} to {}", src_file, dst_file);
        let d = match fs::read(src_file.to_string()) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let ciphertext = match self.seal_aes_256(&d).await {
            Ok(d) => d,
            Err(e) => {
                return Err(e);
            }
        };

        let mut f = match File::create(dst_file.as_str()) {
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
    pub async fn unseal_aes_256_file(&self, src_file: &str, dst_file: &str) -> Result<()> {
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

        let plaintext = match self.unseal_aes_256(&d).await {
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

fn zero_vec(n: usize) -> Vec<u8> {
    (0..n).map(|_| 0).collect()
}
