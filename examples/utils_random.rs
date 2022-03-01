use log::info;

extern crate avalanche_ops;
use avalanche_ops::utils::random;

fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let id1 = random::sid(100);
    let id2 = random::sid(100);
    info!("id1: {}", id1);
    info!("id2: {}", id2);
}
