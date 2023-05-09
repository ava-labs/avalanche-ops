mod command;
mod flags;

use std::net::SocketAddr;

use clap::{crate_version, Arg, Command};

pub const APP_NAME: &str = "devnet-faucet";

/// ref. <https://github.com/seanmonstar/warp/blob/master/examples/sse_chat.rs>
#[tokio::main]
async fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Runs a gasless voting demo")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("HTTP_HOST")
                .long("http-host")
                .help("Sets the HTTP host/port to serve (0.0.0.0:3031 to open to all)")
                .required(false)
                .num_args(1)
                .default_value("127.0.0.1:3031"),
        )
        .arg(
            Arg::new("CHAIN_RPC_URLS")
                .long("chain-rpc-urls")
                .help("Comma-separated Chain RPC URLs (e.g., http://[HOST]:[PORT]/ext/C/rpc)")
                .required(false) // TODO: make this required
                .num_args(1)
                .default_value("http://localhost:9650/ext/C/rpc"),
        )
        .arg(
            Arg::new("KEYS_FILE")
                .long("keys-file")
                .help("Sets the YAML file path that contains the key information (if not exists, retries with interval)")
                .required(true)
                .num_args(1),
        )
        .get_matches();

    println!("{} version: {}", APP_NAME, crate_version!());

    let http_host = matches
        .get_one::<String>("HTTP_HOST")
        .unwrap_or(&String::from("127.0.0.1:3031")) // "0.0.0.0:3031" to open to all IPs
        .clone();
    let http_host: SocketAddr = http_host.parse().unwrap();

    let s = matches
        .get_one::<String>("CHAIN_RPC_URLS")
        .unwrap_or(&String::new())
        .clone();
    let ss: Vec<&str> = s.split(',').collect();
    let mut chain_rpc_urls: Vec<String> = Vec::new();
    for rpc in ss.iter() {
        chain_rpc_urls.push(rpc.to_string());
    }

    command::execute(flags::Options {
        log_level: matches
            .get_one::<String>("LOG_LEVEL")
            .unwrap_or(&String::from("info"))
            .clone(),
        http_host,
        chain_rpc_urls,
        keys_file: matches
            .get_one::<String>("KEYS_FILE")
            .unwrap_or(&String::new()) // TODO: make this required
            .clone(),
    })
    .await
    .unwrap();
}
