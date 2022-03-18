use std::{
    fs::File,
    io::{Read, Write},
    sync::Arc,
    thread, time,
};

use log::info;

extern crate avalanche_ops;
use avalanche_ops::{
    aws::{self, envelope, kms},
    utils::{id, random},
};

/// cargo run --example aws_kms
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    macro_rules! ab {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    info!("creating AWS KMS resources!");

    let shared_config = ab!(aws::load_config(None)).unwrap();
    let kms_manager = kms::Manager::new(&shared_config);

    let mut key_desc = id::with_time("test");
    key_desc.push_str("-cmk");

    // error should be ignored if it does not exist
    let ret = ab!(kms_manager.schedule_to_delete("invalid_id"));
    assert!(ret.is_ok());

    let cmk = ab!(kms_manager.create_key(&key_desc)).unwrap();
    let dek = ab!(kms_manager.generate_data_key(&cmk.id, None)).unwrap();

    let dek_ciphertext_decrypted = ab!(kms_manager.decrypt(&cmk.id, None, dek.ciphertext)).unwrap();
    assert_eq!(dek.plaintext, dek_ciphertext_decrypted);

    let dek_plaintext_encrypted =
        ab!(kms_manager.encrypt(&cmk.id, None, dek.plaintext.clone())).unwrap();
    let dek_plaintext_encrypted_decrypted =
        ab!(kms_manager.decrypt(&cmk.id, None, dek_plaintext_encrypted)).unwrap();
    assert_eq!(dek.plaintext, dek_plaintext_encrypted_decrypted);
    assert_eq!(dek_ciphertext_decrypted, dek_plaintext_encrypted_decrypted);

    let plaintext = "Hello World!";
    let mut plaintext_file = tempfile::NamedTempFile::new().unwrap();
    let ret = plaintext_file.write_all(plaintext.as_bytes());
    assert!(ret.is_ok());
    let plaintext_file_path = plaintext_file.path().to_str().unwrap();

    let encrypted_file_path = random::tmp_path(10, Some(".encrypted")).unwrap();
    let decrypted_file_path = random::tmp_path(10, Some(".encrypted")).unwrap();
    ab!(kms_manager.encrypt_file(&cmk.id, None, plaintext_file_path, &encrypted_file_path))
        .unwrap();
    ab!(kms_manager.decrypt_file(&cmk.id, None, &encrypted_file_path, &decrypted_file_path))
        .unwrap();

    let mut encrypted_file = File::open(encrypted_file_path).unwrap();
    let mut encrypted_file_contents = Vec::new();
    encrypted_file
        .read_to_end(&mut encrypted_file_contents)
        .unwrap();
    let mut decrypted_file = File::open(decrypted_file_path).unwrap();
    let mut decrypted_file_contents = Vec::new();
    decrypted_file
        .read_to_end(&mut decrypted_file_contents)
        .unwrap();
    info!("encrypted_file_contents: {:?}", encrypted_file_contents);
    info!("decrypted_file_contents: {:?}", decrypted_file_contents);
    assert_eq!(&decrypted_file_contents, plaintext.as_bytes());
    assert!(eq_vectors(&decrypted_file_contents, plaintext.as_bytes()));

    let envelope = envelope::Envelope::new(Some(kms_manager.clone()), Some(cmk.id.clone()));
    let sealed_aes_256_file_path = random::tmp_path(10, Some(".encrypted")).unwrap();
    let unsealed_aes_256_file_path = random::tmp_path(10, None).unwrap();
    ab!(envelope.seal_aes_256_file(
        Arc::new(plaintext_file_path.to_string()),
        Arc::new(sealed_aes_256_file_path.clone())
    ))
    .unwrap();
    ab!(envelope.unseal_aes_256_file(
        Arc::new(sealed_aes_256_file_path.clone()),
        Arc::new(unsealed_aes_256_file_path.clone())
    ))
    .unwrap();
    let mut sealed_aes_256_file = File::open(sealed_aes_256_file_path).unwrap();
    let mut sealed_aes_256_file_contents = Vec::new();
    sealed_aes_256_file
        .read_to_end(&mut sealed_aes_256_file_contents)
        .unwrap();
    let mut unsealed_aes_256_file = File::open(unsealed_aes_256_file_path).unwrap();
    let mut unsealed_aes_256_file_contents = Vec::new();
    unsealed_aes_256_file
        .read_to_end(&mut unsealed_aes_256_file_contents)
        .unwrap();
    info!(
        "sealed_aes_256_file_contents: {:?}",
        sealed_aes_256_file_contents
    );
    info!(
        "unsealed_aes_256_file_contents: {:?}",
        unsealed_aes_256_file_contents
    );
    assert_eq!(&unsealed_aes_256_file_contents, plaintext.as_bytes());
    assert!(eq_vectors(
        &unsealed_aes_256_file_contents,
        plaintext.as_bytes()
    ));

    thread::sleep(time::Duration::from_secs(2));

    // envelope encryption with "AES_256" (32-byte)
    let plaintext_sealed = ab!(envelope.seal_aes_256(plaintext.as_bytes())).unwrap();
    thread::sleep(time::Duration::from_secs(1));
    let plaintext_sealed_unsealed = ab!(envelope.unseal_aes_256(&plaintext_sealed)).unwrap();
    info!("plaintext_sealed: {:?}", plaintext_sealed);
    info!("plaintext_sealed_unsealed: {:?}", plaintext_sealed_unsealed);
    assert_eq!(&plaintext_sealed_unsealed, plaintext.as_bytes());
    assert!(eq_vectors(&plaintext_sealed_unsealed, plaintext.as_bytes()));

    let ret = ab!(kms_manager.schedule_to_delete(&cmk.id));
    assert!(ret.is_ok());

    thread::sleep(time::Duration::from_secs(2));

    // error should be ignored if it's already scheduled for delete
    let ret = ab!(kms_manager.schedule_to_delete(&cmk.id));
    assert!(ret.is_ok());
}

fn eq_vectors(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) && va.iter().zip(vb).all(|(a, b)| *a == *b)
}
