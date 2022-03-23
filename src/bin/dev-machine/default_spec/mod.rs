use std::io::{self, stdout};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

use avalanche_ops::{self, dev};

pub const NAME: &str = "default-spec";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Writes a default configuration")
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
            Arg::new("ARCH")
                .long("arch")
                .short('a')
                .help("Sets the machine architecture")
                .required(true)
                .takes_value(true)
                .possible_value(dev::ARCH_AMD64)
                .possible_value(dev::ARCH_ARM64)
                .allow_invalid_utf8(false)
                .default_value(dev::ARCH_ARM64),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The config file to create")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

pub struct Option {
    pub log_level: String,
    pub arch: String,
    pub spec_file_path: String,
}

pub fn execute(opt: Option) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opt.log_level),
    );

    let spec = dev::Spec::default(&opt.arch).unwrap();
    spec.validate()?;
    spec.sync(&opt.spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", opt.spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    execute!(
        stdout(),
        SetForegroundColor(Color::Magenta),
        Print(format!("\ncat {}\n", opt.spec_file_path)),
        ResetColor
    )?;
    println!();
    println!("# run the following to create resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{} apply \\\n--spec-file-path {}\n",
            std::env::current_exe()
                .expect("unexpected None current_exe")
                .display(),
            opt.spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
