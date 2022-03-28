use chrono::prelude::*;

/// Gets the current timestamp in concatenated string format.
pub fn get(n: usize) -> String {
    let local: DateTime<Local> = Local::now();
    let mut d = format!(
        "{}{:02}{:02}{:02}{:02}",
        local.year(),
        local.month(),
        local.day(),
        local.hour(),
        local.second(),
    );
    if d.len() > n {
        d.truncate(n);
    }
    d
}

#[test]
fn test_get() {
    use log::info;
    use std::{thread, time};
    let _ = env_logger::builder().is_test(true).try_init();

    let ts1 = get(12);
    thread::sleep(time::Duration::from_millis(1001));
    let ts2 = get(12);
    assert_ne!(ts1, ts2);

    info!("ts1: {:?}", ts1);
    info!("ts2: {:?}", ts2);
}
