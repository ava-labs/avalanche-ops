use std::net::SocketAddr;

/// Defines flag options.
#[derive(Debug)]
pub struct Options {
    pub log_level: String,
    pub http_host: SocketAddr,
    pub chain_rpc_urls: Vec<String>,
    pub keys_file: String,
}
