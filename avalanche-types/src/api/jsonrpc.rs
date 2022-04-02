use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    string::String,
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_VERSION: &str = "2.0";
pub const DEFAULT_ID: u32 = 1;

/// ref. https://docs.avax.network/build/avalanchego-apis/issuing-api-calls
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Data {
    pub jsonrpc: String,
    pub id: u32,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, String>>,
}

impl Default for Data {
    fn default() -> Self {
        Self::default()
    }
}

impl Data {
    pub fn default() -> Self {
        Self {
            jsonrpc: String::from(DEFAULT_VERSION),
            id: DEFAULT_ID,
            method: String::new(),
            params: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to JSON {}", e),
                ));
            }
        }
    }
}

/// ref. https://docs.avax.network/build/avalanchego-apis/c-chain#eth_getassetbalance
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DataWithParamsArray {
    pub jsonrpc: String,
    pub id: u32,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<String>>,
}

impl Default for DataWithParamsArray {
    fn default() -> Self {
        Self::default()
    }
}

impl DataWithParamsArray {
    pub fn default() -> Self {
        Self {
            jsonrpc: String::from(DEFAULT_VERSION),
            id: DEFAULT_ID,
            method: String::new(),
            params: None,
        }
    }

    pub fn encode_json(&self) -> io::Result<String> {
        match serde_json::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize to JSON {}", e),
                ));
            }
        }
    }
}
