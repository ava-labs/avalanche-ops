use std::io;

use crate::ids;

pub trait ReadOnly {
    fn get_address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String>;
    fn get_short_address(&self) -> ids::ShortId;
    fn get_eth_address(&self) -> String;
}
