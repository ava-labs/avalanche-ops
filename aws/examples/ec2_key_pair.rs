use std::{fs, thread, time};

use log::info;

use aws::{self, ec2};
use utils::id;

/// cargo run --example ec2_key_pair
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

    info!("creating AWS EC2 key-pair resources!");

    let ret = ab!(aws::load_config(None));
    let shared_config = ret.unwrap();
    let ec2_manager = ec2::Manager::new(&shared_config);

    let mut key_name = id::with_time("test");
    key_name.push_str("-key");

    // error should be ignored if it does not exist
    let ret = ab!(ec2_manager.delete_key_pair(&key_name));
    assert!(ret.is_ok());

    let f = tempfile::NamedTempFile::new().unwrap();
    let key_path = f.path().to_str().unwrap();
    fs::remove_file(key_path).unwrap();
    info!("created file path {}", key_path);

    let ret = ab!(ec2_manager.create_key_pair(&key_name, key_path));
    assert!(ret.is_ok());

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(ec2_manager.delete_key_pair(&key_name));
    assert!(ret.is_ok());
}
