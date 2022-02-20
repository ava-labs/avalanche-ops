use std::{env, io};

use lazy_static::lazy_static;
use ring::rand::{SecureRandom, SystemRandom};

/// Generates a random string of length "n".
pub fn string(n: usize) -> String {
    let bytes = rand_bytes(n).unwrap();
    let mut d = bs58::encode(&bytes[..]).into_string();
    if n > 0 && d.len() > n {
        d.truncate(n);
    }
    d
}

/// Generates a random string of length "n".
fn rand_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut d: Vec<u8> = vec![0u8; n];
    secure_random().fill(&mut d).map_err(|e| e.to_string())?;
    Ok(d)
}

fn secure_random() -> &'static dyn SecureRandom {
    use std::ops::Deref;
    lazy_static! {
        static ref RANDOM: SystemRandom = SystemRandom::new();
    }
    RANDOM.deref()
}

#[test]
fn test_string() {
    use log::info;
    let _ = env_logger::builder().is_test(true).try_init();

    let word1 = string(100);
    let word2 = string(100);

    assert_eq!(word1.len(), 100);
    assert_eq!(word2.len(), 100);
    assert_ne!(word1, word2);

    info!("word1: {:?}", word1);
    info!("word2: {:?}", word2);
}

/// Returns a file path randomly generated in tmp directory.
/// The file does not exist yet.
pub fn tmp_path(n: usize) -> io::Result<String> {
    let tmp_dir = env::temp_dir();
    let tmp_file_path = tmp_dir.join(string(n));
    let tmp_file_path = tmp_file_path.as_os_str().to_str().unwrap();
    Ok(String::from(tmp_file_path))
}

#[test]
fn test_temp_path() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let p1 = tmp_path(10).unwrap();
    let p2 = tmp_path(10).unwrap();
    assert_ne!(p1, p2);

    info!("p1: {:?}", p1);
    info!("p2: {:?}", p2);
}
