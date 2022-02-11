use std::{thread, time};

use log::info;

extern crate avalanche_ops;
use avalanche_ops::{aws, aws_kms, id};

fn main() {
    use std::{
        fs::File,
        io::{Read, Write},
    };

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
    let kms_manager = aws_kms::Manager::new(&shared_config);

    let mut key_desc = id::generate("test");
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
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let ret = file.write_all(plaintext.as_bytes());
    assert!(ret.is_ok());
    let file_path = file.path().to_str().unwrap();
    let encrypted_file_path = avalanche_ops::random::tmp_path(10).unwrap();
    let decrypted_file_path = avalanche_ops::random::tmp_path(10).unwrap();

    ab!(kms_manager.encrypt_file(&cmk.id, None, file_path, &encrypted_file_path)).unwrap();
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

    thread::sleep(time::Duration::from_secs(2));

    // envelope encryption with "AES_256" (32-byte)
    let plaintext_sealed = ab!(kms_manager.seal_aes_256(&cmk.id, plaintext.as_bytes())).unwrap();
    thread::sleep(time::Duration::from_secs(1));
    let plaintext_sealed_unsealed =
        ab!(kms_manager.unseal_aes_256(&cmk.id, &plaintext_sealed)).unwrap();
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
