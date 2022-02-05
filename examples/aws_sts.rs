use log::info;

extern crate avalanche_ops;
use avalanche_ops::{aws, aws_sts};

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

    info!("connecting to AWS STS!");

    let ret = ab!(aws::load_config(None));
    assert!(ret.is_ok());
    let shared_config = ret.unwrap();
    let manager = aws_sts::Manager::new(&shared_config);
    let ret = ab!(manager.get_identity());
    assert!(ret.is_ok());

    let identity1 = ret.unwrap();
    info!("identity1: {:?}", identity1);

    let ret = ab!(aws::load_config(None));
    assert!(ret.is_ok());
    let shared_config = ret.unwrap();
    let manager = aws_sts::Manager::new(&shared_config);
    let ret = ab!(manager.get_identity());

    let identity2 = ret.unwrap();
    info!("identity2: {:?}", identity2);

    assert_eq!(identity1, identity2);
}
