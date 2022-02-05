use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    /// Sets log level.
    #[clap(short, long, default_value = "info")]
    log: String,
}

fn main() {
    let opts: Opts = Opts::parse();

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log),
    );

    info!("Hello, world!");
}
