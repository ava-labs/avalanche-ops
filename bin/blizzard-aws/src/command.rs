use std::io;

use crate::flags;

pub async fn execute(opts: flags::Options) -> io::Result<()> {
    println!("starting {} with {:?}", crate::APP_NAME, opts);

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    Ok(())
}
