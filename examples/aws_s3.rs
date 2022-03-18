use std::{fs, io::Write, sync::Arc, thread, time};

use log::info;
use tokio::runtime::Runtime;

extern crate avalanche_ops;
use avalanche_ops::{
    aws::{self, s3},
    utils::{id, random, time as atime},
};

/// cargo run --example aws_s3
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let rt = Runtime::new().unwrap();

    println!();
    println!();
    println!();
    info!("creating AWS S3 resources!");
    let shared_config = rt.block_on(aws::load_config(None)).unwrap();
    let s3_manager = s3::Manager::new(&shared_config);

    println!();
    println!();
    println!();
    let bucket = format!(
        "avalanche-ops-examples-tests-s3-{}-{}",
        atime::get(6),
        id::system(10)
    );
    rt.block_on(s3_manager.delete_bucket(&bucket)).unwrap(); // error should be ignored if it does not exist

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(5));
    rt.block_on(s3_manager.create_bucket(&bucket)).unwrap();

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(3));
    rt.block_on(s3_manager.create_bucket(&bucket)).unwrap();

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(3));
    let contents = vec![7; 50 * 1024 * 1024];
    let mut upload_file = tempfile::NamedTempFile::new().unwrap();
    upload_file.write_all(&contents.to_vec()).unwrap();
    let upload_path = upload_file.path().to_str().unwrap();
    let s3_key = "sub-dir/aaa.txt";
    rt.block_on(s3::spawn_put_object(
        s3_manager.clone(),
        &upload_path,
        &bucket,
        &s3_key,
    ))
    .unwrap();

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(2));
    let download_path = random::tmp_path(10, None).unwrap();
    rt.block_on(s3::spawn_get_object(
        s3_manager.clone(),
        &bucket,
        &s3_key,
        &download_path,
    ))
    .unwrap();
    let download_contents = fs::read(download_path).unwrap();
    assert_eq!(contents.to_vec().len(), download_contents.len());
    assert_eq!(contents.to_vec(), download_contents);

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(1));
    let objects = rt
        .block_on(s3::spawn_list_objects(
            s3_manager.clone(),
            &bucket,
            Some(String::from("sub-dir/")),
        ))
        .unwrap();
    for obj in objects.iter() {
        info!("object: {}", obj.key().unwrap());
    }

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(1));
    rt.block_on(s3_manager.delete_objects(Arc::new(bucket.clone()), None))
        .unwrap();

    println!();
    println!();
    println!();
    thread::sleep(time::Duration::from_secs(2));
    rt.block_on(s3_manager.delete_bucket(&bucket)).unwrap();
}
