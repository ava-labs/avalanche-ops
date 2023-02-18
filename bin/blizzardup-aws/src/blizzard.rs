use std::io::{self, Error, ErrorKind};

use serde::{Deserialize, Serialize};

/// Defines flag options.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    pub log_level: String,

    pub chain_rpc_urls: Vec<String>,
    pub load_kinds: Vec<String>,
    pub keys_to_generate: usize,

    pub workers: usize,
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
    XTransfers,
    CTransfers,
    SubnetEvmTransfers,
    Unknown(String),
}

impl std::convert::From<&str> for LoadKind {
    fn from(s: &str) -> Self {
        match s {
            "x-transfers" => LoadKind::XTransfers,
            "c-transfers" => LoadKind::CTransfers,
            "subnet-evm-transfers" => LoadKind::SubnetEvmTransfers,

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
            LoadKind::XTransfers => "x-transfers",
            LoadKind::CTransfers => "c-transfers",
            LoadKind::SubnetEvmTransfers => "subnet-evm-transfers",

            LoadKind::Unknown(s) => s.as_ref(),
        }
    }

    /// Returns all the `&str` values of the enum members.
    pub fn values() -> &'static [&'static str] {
        &[
            "x-transfers",          //
            "c-transfers",          //
            "subnet-evm-transfers", //
        ]
    }
}

impl AsRef<str> for LoadKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
