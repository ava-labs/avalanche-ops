use primitive_types::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Status {
    pub network_id: u32,
    pub chain_id: U256,
}
