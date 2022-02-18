use ripemd::{Digest, Ripemd160};

use crate::{random, time};

/// Generates a random ID with the prefix followed by a
/// timestamp and random characters.
pub fn generate(pfx: &str) -> String {
    format!("{}-{}-{}", pfx, time::get(6), random::string(6))
}

#[test]
fn test_generate() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let id1 = generate("avax");
    let id2 = generate("avax");
    assert_ne!(id1, id2);

    info!("id1: {:?}", id1);
    info!("id2: {:?}", id2);
}

/// Creates an ID based on host information.
pub fn sid(n: usize) -> String {
    let id = format!(
        "{}-{}-{}",
        whoami::username(),
        whoami::hostname(),
        whoami::platform()
    );

    let mut hasher = Ripemd160::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();

    let mut id = hex::encode(&result[..]);
    if n > 0 && id.len() > n {
        id.truncate(n);
    }
    id
}

#[test]
fn test_sid() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let id1 = sid(10);
    let id2 = sid(10);
    assert_eq!(id1, id2);

    info!("id1: {:?}", id1);
    info!("id2: {:?}", id2);
}
