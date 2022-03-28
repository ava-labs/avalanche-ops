use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct UtxoId {
    #[serde(rename = "txID", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "outputIndex", skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
}
