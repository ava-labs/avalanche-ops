use std::{thread, time};

use log::info;
use tokio;

/// cargo run --example scratch
#[tokio::main]
async fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    info!("Hello World!");

    run().await;
}

async fn run() {
    let h = tokio::spawn(async move {
        info!("123");
        thread::sleep(time::Duration::from_secs(3));
    });
    h.await.expect("failed spawn");

    let mut handles = Vec::new();
    handles.push(tokio::spawn(echo1()));
    handles.push(tokio::spawn(echo2()));
    for handle in handles {
        handle.await.expect("failed handle");
    }
}

async fn echo1() {
    for _ in 0..50 {
        info!("echo1");
        thread::sleep(time::Duration::from_secs(1));
    }
}

async fn echo2() {
    for _ in 0..30 {
        info!("echo2");
        thread::sleep(time::Duration::from_secs(1));
    }
}
