use std::io::{self, Error, ErrorKind};

use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    pub log_level: String,
    pub network_id: u32,
    pub rpc_endpoints: Vec<Endpoints>,
    pub load_kinds: Vec<String>,
    pub metrics_push_interval_seconds: u64,

    pub gas: Option<u64>,
    pub gas_price: Option<u64>,
    // TODO: set test run timeout
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Endpoints {
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(default)]
    pub http_rpc: String,
    #[serde(default)]
    pub http_rpc_x: String,
    #[serde(default)]
    pub http_rpc_p: String,
    #[serde(default)]
    pub http_rpc_c: String,
    #[serde(default)]
    pub http_rpc_subnet_evm: Option<String>,
    #[serde(default)]
    pub subnet_evm_blockchain_id: Option<String>,
    #[serde(default)]
    pub metrics: String,
    #[serde(default)]
    pub health: String,
    #[serde(default)]
    pub liveness: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::default()
    }
}

impl Endpoints {
    pub fn default() -> Self {
        Self {
            http_rpc: String::new(),
            http_rpc_x: String::new(),
            http_rpc_p: String::new(),
            http_rpc_c: String::new(),
            http_rpc_subnet_evm: None,
            subnet_evm_blockchain_id: None,
            metrics: String::new(),
            health: String::new(),
            liveness: String::new(),
        }
    }

    pub fn new(http_rpc: &str, subnet_evm_blockchain_id: Option<String>) -> Self {
        let http_rpc_subnet_evm = if let Some(blk_chain_id) = &subnet_evm_blockchain_id {
            Some(format!("{}/ext/bc/{}/rpc", http_rpc, blk_chain_id))
        } else {
            None
        };
        Self {
            http_rpc: http_rpc.to_string(),
            http_rpc_x: format!("{}/ext/bc/X", http_rpc),
            http_rpc_p: format!("{}/ext/bc/P", http_rpc),
            http_rpc_c: format!("{}/ext/bc/C/rpc", http_rpc),
            http_rpc_subnet_evm,
            subnet_evm_blockchain_id,
            metrics: format!("{}/ext/metrics", http_rpc),
            health: format!("{}/ext/health", http_rpc),
            liveness: format!("{}/ext/health/liveness", http_rpc),
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

/// Defines the node type.
#[derive(
    std::clone::Clone,
    std::cmp::Eq,
    std::cmp::Ord,
    std::cmp::PartialEq,
    std::cmp::PartialOrd,
    std::fmt::Debug,
    std::hash::Hash,
)]
pub enum LoadKind {
    X,
    C,
    SubnetEvm,
    Unknown(String),
}

impl std::convert::From<&str> for LoadKind {
    fn from(s: &str) -> Self {
        match s {
            "x" => LoadKind::X,
            "c" => LoadKind::C,
            "subnet-evm" => LoadKind::SubnetEvm,

            other => LoadKind::Unknown(other.to_owned()),
        }
    }
}

impl std::str::FromStr for LoadKind {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(LoadKind::from(s))
    }
}

impl LoadKind {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            LoadKind::X => "x",
            LoadKind::C => "c",
            LoadKind::SubnetEvm => "subnet-evm",

            LoadKind::Unknown(s) => s.as_ref(),
        }
    }

    /// Returns all the `&str` values of the enum members.
    pub fn values() -> &'static [&'static str] {
        &[
            "x",          //
            "c",          //
            "subnet-evm", //
        ]
    }
}

impl AsRef<str> for LoadKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
