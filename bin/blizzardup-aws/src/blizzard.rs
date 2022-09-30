use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    pub log_level: String,
    pub metrics_push_interval_seconds: u64,
    pub rpc_endpoints: Vec<Endpoints>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Endpoints {
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_subnet_evm: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::default()
    }
}

impl Endpoints {
    pub fn default() -> Self {
        Self {
            http_rpc: None,
            http_rpc_x: None,
            http_rpc_p: None,
            http_rpc_c: None,
            http_rpc_subnet_evm: None,
            metrics: None,
            health: None,
            liveness: None,
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Endpoints to YAML {}", e),
            )),
        }
    }
}
