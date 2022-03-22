use std::{thread, time};

use bytes::BufMut;
use log::info;
use tokio::{self, time::sleep};

/// cargo run --example scratch
#[tokio::main]
async fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    info!("Hello World!");

    let mut buf = vec![];
    buf.put_u8(0x01);
    assert_eq!(buf, b"\x01");
    info!("{}", buf.len());

    run().await;
}

async fn run() {
    let h = tokio::spawn(async move {
        info!("123");
        sleep(time::Duration::from_secs(3)).await;
    });
    h.await.expect("failed spawn");

    let mut handles = Vec::new();
    handles.push(tokio::spawn(non_blocking_echo1()));
    handles.push(tokio::spawn(non_blocking_echo2()));
    handles.push(tokio::spawn(blocking_echo_1()));
    handles.push(tokio::spawn(blocking_echo_2()));
    for handle in handles {
        handle.await.expect("failed handle");
    }
}

#[allow(dead_code)]
async fn non_blocking_echo1() {
    for _ in 0..50 {
        info!("non_blocking_echo1");
        sleep(time::Duration::from_secs(1)).await;
    }
}

#[allow(dead_code)]
async fn non_blocking_echo2() {
    for _ in 0..30 {
        info!("non_blocking_echo2");
        sleep(time::Duration::from_secs(2)).await;
    }
}

#[allow(dead_code)]
async fn blocking_echo_1() {
    info!("start blocking_echo_1");
    thread::sleep(time::Duration::from_secs(1));

    for _ in 0..30 {
        info!("blocking_echo_1");
        thread::sleep(time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
async fn blocking_echo_2() {
    info!("start blocking_echo_2");
    thread::sleep(time::Duration::from_secs(10000));

    for _ in 0..30 {
        info!("blocking_echo_2");
        thread::sleep(time::Duration::from_secs(1));
    }
}
