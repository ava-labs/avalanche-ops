use std::io;

use crate::{ids, secp256k1fx};

pub trait Key {
    fn get_address(&self, chain_id_alias: &str, network_id: u32) -> io::Result<String>;
    fn get_short_address(&self) -> ids::ShortId;
    fn get_eth_address(&self) -> String;

    fn check_threshold(
        &self,
        output_owners: &secp256k1fx::OutputOwners,
        time: u64,
    ) -> Option<Vec<u32>>;
}
