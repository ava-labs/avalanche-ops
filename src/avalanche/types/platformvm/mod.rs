pub mod add_subnet_validator;
pub mod add_validator;
pub mod create_chain;
pub mod create_subnet;
pub mod export;
pub mod import;

use crate::avalanche::types::ids;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Validator {
    pub node_id: ids::ShortId,
    pub start: u64,
    pub end: u64,
    pub weight: u64,
}

impl Default for Validator {
    fn default() -> Self {
        Self::default()
    }
}

impl Validator {
    pub fn default() -> Self {
        Self {
            node_id: ids::ShortId::empty(),
            start: 0,
            end: 0,
            weight: 0,
        }
    }
}
