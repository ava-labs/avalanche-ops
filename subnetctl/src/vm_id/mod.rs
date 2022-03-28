use std::io::{self, stdout};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

use avalanche_types::vm;

pub const NAME: &str = "vm-id";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Generates the VM ID based on its name")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("NAME")
                .long("name")
                .short('n')
                .help("Sets the VM name")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

pub struct Option {
    pub log_level: String,
    pub name: String,
}

pub fn execute(opt: Option) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nGenerating VM ID for: '{}'\n", opt.name)),
        ResetColor
    )?;
    let short_id = vm::id_from_str(&opt.name).expect("failed to generate VM ID");
    println!("{}", short_id);

    Ok(())
}
