use ripemd::{Digest, Ripemd160};

use crate::{random, time};

/// Generates a random ID with the prefix followed by a
/// timestamp and random characters.
pub fn with_time(pfx: &str) -> String {
    format!("{}-{}-{}", pfx, time::get(6), random::string(6))
}

#[test]
fn test_with_time() {
    use log::info;
    let _ = env_logger::builder().is_test(true).try_init();

    let id1 = with_time("avax");
    let id2 = with_time("avax");
    assert_ne!(id1, id2);

    info!("id1: {:?}", id1);
    info!("id2: {:?}", id2);
}

/// Creates an ID based on host information.
pub fn system(n: usize) -> String {
    let id = format!(
        "{}-{}-{}-{}-{}",
        whoami::username(),
        whoami::realname(),
        whoami::hostname(),
        whoami::platform(),
        whoami::devicename(),
    );

    let mut hasher = Ripemd160::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();

    let mut id = bs58::encode(&result[..]).into_string();
    if n > 0 && id.len() > n {
        id.truncate(n);
    }
    id.to_lowercase()
}

#[test]
fn test_system() {
    let _ = env_logger::builder().is_test(true).try_init();
    use log::info;

    let system1 = system(10);
    let system2 = system(10);
    assert_eq!(system1, system2);

    info!("system1: {:?}", system1);
    info!("system2: {:?}", system2);
}
