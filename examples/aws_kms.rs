use std::{thread, time};

use log::info;

extern crate avalanche_ops;
use avalanche_ops::{aws, aws_kms, id};

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

    let ret = ab!(aws::load_config(None));
    assert!(ret.is_ok());
    let shared_config = ret.unwrap();
    let manager = aws_kms::Manager::new(&shared_config);

    let mut key_desc = id::generate("test");
    key_desc.push_str("-cmk");

    // error should be ignored
    let ret = ab!(manager.schedule_to_delete("invalid_id"));
    assert!(ret.is_ok());

    let ret = ab!(manager.create_key(&key_desc));
    assert!(ret.is_ok());
    let key = ret.unwrap();

    let ret = ab!(manager.generate_data_key(&key.id, None));
    assert!(ret.is_ok());
    let dek = ret.unwrap();

    let ret = ab!(manager.decrypt(&key.id, None, dek.cipher));
    assert!(ret.is_ok());
    let plain1 = ret.unwrap();
    assert_eq!(dek.plain, plain1);

    let ret = ab!(manager.encrypt(&key.id, None, dek.plain.clone()));
    assert!(ret.is_ok());
    let cipher = ret.unwrap();
    let ret = ab!(manager.decrypt(&key.id, None, cipher));
    assert!(ret.is_ok());
    let plain2 = ret.unwrap();
    assert_eq!(dek.plain, plain2);
    assert_eq!(plain1, plain2);

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(manager.schedule_to_delete(&key.id));
    assert!(ret.is_ok());
}
