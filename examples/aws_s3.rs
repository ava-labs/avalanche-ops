use std::{io::Write, thread, time};

use log::info;

extern crate avalanche_ops;
use avalanche_ops::{aws, aws_s3, id, random};

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

    info!("creating AWS S3 resources!");

    let ret = ab!(aws::load_config(None));
    let shared_config = ret.unwrap();
    let s3_manager = aws_s3::Manager::new(&shared_config);

    let mut bucket_name = id::generate("test");
    bucket_name.push_str("-bucket");

    // error should be ignored if it does not exist
    let ret = ab!(s3_manager.delete_bucket(&bucket_name));
    assert!(ret.is_ok());

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(s3_manager.create_bucket(&bucket_name));
    assert!(ret.is_ok());

    thread::sleep(time::Duration::from_secs(5));

    // already exists so should just succeed with warnings
    let ret = ab!(s3_manager.create_bucket(&bucket_name));
    assert!(ret.is_ok());

    let text = "Hello World!";
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    let ret = f1.write_all(text.as_bytes());
    assert!(ret.is_ok());
    let p1 = f1.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let p2 = tmp_dir.path().join(random::string(10));
    let p2 = p2.as_os_str().to_str().unwrap();

    let ret = ab!(s3_manager.put_object(&bucket_name, p1, "directory/aaa.txt"));
    assert!(ret.is_ok());
    let ret = ab!(s3_manager.put_object(&bucket_name, p1, "directory/bbb.txt"));
    assert!(ret.is_ok());

    let ret = ab!(s3_manager.get_object(&bucket_name, "directory/aaa.txt", &p2));
    match ret {
        Ok(_) => {}
        Err(e) => panic!("failed!!!! {}", e.message()),
    }

    let ret = ab!(s3_manager.list_objects(&bucket_name, Some(String::from("directory/"))));
    let objects = ret.unwrap();
    for o in objects {
        info!(
            "key {:?} (last modified {:?}, size {:?})",
            o.key(),
            o.last_modified(),
            o.size()
        );
    }

    thread::sleep(time::Duration::from_secs(5));

    let ret = ab!(s3_manager.delete_objects(&bucket_name, None));
    assert!(ret.is_ok());

    thread::sleep(time::Duration::from_secs(2));

    let ret = ab!(s3_manager.delete_bucket(&bucket_name));
    assert!(ret.is_ok());
}
