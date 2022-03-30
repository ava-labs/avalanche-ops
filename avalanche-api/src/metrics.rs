use std::{io, sync::Arc};

use aws_sdk_cloudwatch::model::{MetricDatum, StandardUnit};
use aws_smithy_types::DateTime as SmithyDateTime;
use chrono::{DateTime, Utc};
use log::info;
use serde::Serialize;

use utils::{http, prometheus, rfc3339};

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Metrics {
    /// Represents the data format in RFC3339.
    /// ref. https://serde.rs/custom-date-format.html
    #[serde(with = "rfc3339::serde_format")]
    pub ts: DateTime<Utc>,

    /// Network metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_peers: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_pull_query_sent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_push_query_sent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_msgs_failed_to_parse: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_inbound_conn_throttler_allowed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_byte_throttler_inbound_awaiting_release: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_throttler_outbound_acquire_failures: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_throttler_outbound_awaiting_release: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_requests_average_latency: Option<f64>,

    /// Handshake messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_version_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_version_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_peerlist_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_peerlist_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_ping_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_ping_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_pong_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_pong_received_bytes: Option<f64>,

    /// Consensus messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_chits_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_chits_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_put_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_put_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_pull_query_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_pull_query_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_push_query_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_push_query_received_bytes: Option<f64>,

    /// Bootstrap messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_accepted_frontier_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_accepted_frontier_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_accepted_frontier_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_accepted_frontier_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_accepted_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_accepted_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_accepted_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_accepted_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_ancestors_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_get_ancestors_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_ancestors_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_ancestors_received_bytes: Option<f64>,

    /// App messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_gossip_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_gossip_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_request_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_request_received_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_response_sent_bytes: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_app_response_received_bytes: Option<f64>,

    /// X-chain metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_db_get_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_db_write_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_db_read_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_vtx_processing: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_rejected_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_rejected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_polls_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_txs_polls_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_polls_successful: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_polls_failed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_handler_chits_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_handler_query_failed_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_polls_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_polls_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_polls_rejected_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_polls_rejected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_processing: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_rejected_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_tx_rejected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_vtx_issue_failure: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_whitelist_vtx_issue_success: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_benchlist_benched_num: Option<f64>,

    /// P-chain metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_vm_total_staked: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_db_get_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_db_write_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_db_read_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_rejected_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_rejected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_polls_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_blks_polls_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_polls_successful: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_polls_failed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_handler_chits_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_handler_query_failed_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_p_benchlist_benched_num: Option<f64>,

    /// C-chain metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_db_get_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_db_write_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_db_read_size_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_processing: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_rejected_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_rejected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_polls_accepted_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_blks_polls_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_polls_successful: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_polls_failed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_chits_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_query_failed_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_accepted_frontier_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_app_gossip_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_app_request_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_app_request_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_app_response_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_accepted_frontier_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_accepted_frontier_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_accepted_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_accepted_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_ancestors_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_ancestors_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_ancestors_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_put_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_get_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_push_query_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_pull_query_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_chits_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_query_failed_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_connected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_handler_disconnected_sum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_benchlist_benched_num: Option<f64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::default()
    }
}

impl Metrics {
    pub fn default() -> Self {
        Self {
            ts: Utc::now(),

            // Network metrics.
            avalanche_network_peers: None,
            avalanche_network_pull_query_sent: None,
            avalanche_network_push_query_sent: None,
            avalanche_network_msgs_failed_to_parse: None,
            avalanche_network_inbound_conn_throttler_allowed: None,
            avalanche_network_byte_throttler_inbound_awaiting_release: None,
            avalanche_network_throttler_outbound_acquire_failures: None,
            avalanche_network_throttler_outbound_awaiting_release: None,
            avalanche_requests_average_latency: None,

            // Handshake messages.
            avalanche_network_version_sent_bytes: None,
            avalanche_network_version_received_bytes: None,
            avalanche_network_peerlist_sent_bytes: None,
            avalanche_network_peerlist_received_bytes: None,
            avalanche_network_ping_sent_bytes: None,
            avalanche_network_ping_received_bytes: None,
            avalanche_network_pong_sent_bytes: None,
            avalanche_network_pong_received_bytes: None,

            // Consensus messages.
            avalanche_network_chits_sent_bytes: None,
            avalanche_network_chits_received_bytes: None,
            avalanche_network_get_sent_bytes: None,
            avalanche_network_get_received_bytes: None,
            avalanche_network_put_sent_bytes: None,
            avalanche_network_put_received_bytes: None,
            avalanche_network_pull_query_sent_bytes: None,
            avalanche_network_pull_query_received_bytes: None,
            avalanche_network_push_query_sent_bytes: None,
            avalanche_network_push_query_received_bytes: None,

            // Bootstrap messages.
            avalanche_network_get_accepted_frontier_sent_bytes: None,
            avalanche_network_get_accepted_frontier_received_bytes: None,
            avalanche_network_accepted_frontier_sent_bytes: None,
            avalanche_network_accepted_frontier_received_bytes: None,
            avalanche_network_get_accepted_sent_bytes: None,
            avalanche_network_get_accepted_received_bytes: None,
            avalanche_network_accepted_sent_bytes: None,
            avalanche_network_accepted_received_bytes: None,
            avalanche_network_get_ancestors_sent_bytes: None,
            avalanche_network_get_ancestors_received_bytes: None,
            avalanche_network_ancestors_sent_bytes: None,
            avalanche_network_ancestors_received_bytes: None,

            // App messages.
            avalanche_network_app_gossip_sent_bytes: None,
            avalanche_network_app_gossip_received_bytes: None,
            avalanche_network_app_request_sent_bytes: None,
            avalanche_network_app_request_received_bytes: None,
            avalanche_network_app_response_sent_bytes: None,
            avalanche_network_app_response_received_bytes: None,

            // X-chain metrics.
            avalanche_x_db_get_count: None,
            avalanche_x_db_write_size_sum: None,
            avalanche_x_db_read_size_sum: None,
            avalanche_x_vtx_processing: None,
            avalanche_x_txs_accepted_count: None,
            avalanche_x_txs_accepted_sum: None,
            avalanche_x_txs_rejected_count: None,
            avalanche_x_txs_rejected_sum: None,
            avalanche_x_txs_polls_accepted_count: None,
            avalanche_x_txs_polls_accepted_sum: None,
            avalanche_x_polls_successful: None,
            avalanche_x_polls_failed: None,
            avalanche_x_handler_chits_count: None,
            avalanche_x_handler_query_failed_count: None,
            avalanche_x_whitelist_tx_accepted_count: None,
            avalanche_x_whitelist_tx_accepted_sum: None,
            avalanche_x_whitelist_tx_polls_accepted_count: None,
            avalanche_x_whitelist_tx_polls_accepted_sum: None,
            avalanche_x_whitelist_tx_polls_rejected_count: None,
            avalanche_x_whitelist_tx_polls_rejected_sum: None,
            avalanche_x_whitelist_tx_processing: None,
            avalanche_x_whitelist_tx_rejected_count: None,
            avalanche_x_whitelist_tx_rejected_sum: None,
            avalanche_x_whitelist_vtx_issue_failure: None,
            avalanche_x_whitelist_vtx_issue_success: None,
            avalanche_x_benchlist_benched_num: None,

            // P-chain metrics.
            avalanche_p_vm_total_staked: None,
            avalanche_p_db_get_count: None,
            avalanche_p_db_write_size_sum: None,
            avalanche_p_db_read_size_sum: None,
            avalanche_p_blks_accepted_count: None,
            avalanche_p_blks_accepted_sum: None,
            avalanche_p_blks_rejected_count: None,
            avalanche_p_blks_rejected_sum: None,
            avalanche_p_blks_polls_accepted_count: None,
            avalanche_p_blks_polls_accepted_sum: None,
            avalanche_p_polls_successful: None,
            avalanche_p_polls_failed: None,
            avalanche_p_handler_chits_count: None,
            avalanche_p_handler_query_failed_count: None,
            avalanche_p_benchlist_benched_num: None,

            // C-chain metrics.
            avalanche_c_db_get_count: None,
            avalanche_c_db_write_size_sum: None,
            avalanche_c_db_read_size_sum: None,
            avalanche_c_blks_processing: None,
            avalanche_c_blks_accepted_count: None,
            avalanche_c_blks_accepted_sum: None,
            avalanche_c_blks_rejected_count: None,
            avalanche_c_blks_rejected_sum: None,
            avalanche_c_blks_polls_accepted_count: None,
            avalanche_c_blks_polls_accepted_sum: None,
            avalanche_c_polls_successful: None,
            avalanche_c_polls_failed: None,
            avalanche_c_handler_chits_count: None,
            avalanche_c_handler_query_failed_count: None,
            avalanche_c_handler_get_accepted_frontier_sum: None,
            avalanche_c_handler_app_gossip_sum: None,
            avalanche_c_handler_app_request_sum: None,
            avalanche_c_handler_app_request_failed_sum: None,
            avalanche_c_handler_app_response_sum: None,
            avalanche_c_handler_accepted_frontier_sum: None,
            avalanche_c_handler_get_accepted_frontier_failed_sum: None,
            avalanche_c_handler_get_accepted_sum: None,
            avalanche_c_handler_accepted_sum: None,
            avalanche_c_handler_get_accepted_failed_sum: None,
            avalanche_c_handler_get_ancestors_sum: None,
            avalanche_c_handler_ancestors_sum: None,
            avalanche_c_handler_get_ancestors_failed_sum: None,
            avalanche_c_handler_get_sum: None,
            avalanche_c_handler_put_sum: None,
            avalanche_c_handler_get_failed_sum: None,
            avalanche_c_handler_push_query_sum: None,
            avalanche_c_handler_pull_query_sum: None,
            avalanche_c_handler_chits_sum: None,
            avalanche_c_handler_query_failed_sum: None,
            avalanche_c_handler_connected_sum: None,
            avalanche_c_handler_disconnected_sum: None,
            avalanche_c_benchlist_benched_num: None,
        }
    }

    pub fn x_polls_success_rate(&self) -> f64 {
        let success = self.avalanche_x_polls_successful.unwrap_or(0.0);
        let failed = self.avalanche_x_polls_failed.unwrap_or(0.0);
        if success == 0.0 {
            0.0
        } else {
            success / (success + failed)
        }
    }

    pub fn p_polls_success_rate(&self) -> f64 {
        let success = self.avalanche_p_polls_successful.unwrap_or(0.0);
        let failed = self.avalanche_p_polls_failed.unwrap_or(0.0);
        if success == 0.0 {
            0.0
        } else {
            success / (success + failed)
        }
    }

    pub fn c_polls_success_rate(&self) -> f64 {
        let success = self.avalanche_c_polls_successful.unwrap_or(0.0);
        let failed = self.avalanche_c_polls_failed.unwrap_or(0.0);
        if success == 0.0 {
            0.0
        } else {
            success / (success + failed)
        }
    }

    pub fn c_blks_accepted_per_second(&self, prev: Metrics) -> f64 {
        let elapsed = (self.ts.timestamp_millis() - prev.ts.timestamp_millis()) as f64;
        let elapsed_seconds = elapsed / 1000.0;

        let prev_accepted = prev.avalanche_c_blks_accepted_sum.unwrap_or(0.0);
        let now_accepted = self.avalanche_c_blks_accepted_sum.unwrap_or(0.0);
        let accepted = now_accepted - prev_accepted;

        if accepted == 0.0 {
            0.0
        } else {
            accepted / elapsed_seconds
        }
    }

    pub fn to_cw_metric_data(&self, prev: Option<Metrics>) -> Vec<MetricDatum> {
        let ts = SmithyDateTime::from_nanos(self.ts.timestamp_nanos() as i128)
            .expect("failed to convert DateTime<Utc>");
        let mut data = vec![
            // Network metrics.
            MetricDatum::builder()
                .metric_name("avalanche_network_peers")
                .value(self.avalanche_network_peers.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_pull_query_sent")
                .value(self.avalanche_network_pull_query_sent.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_push_query_sent")
                .value(self.avalanche_network_push_query_sent.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_msgs_failed_to_parse")
                .value(self.avalanche_network_msgs_failed_to_parse.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_inbound_conn_throttler_allowed")
                .value(
                    self.avalanche_network_inbound_conn_throttler_allowed
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_byte_throttler_inbound_awaiting_release")
                .value(
                    self.avalanche_network_byte_throttler_inbound_awaiting_release
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_throttler_outbound_acquire_failures")
                .value(
                    self.avalanche_network_throttler_outbound_acquire_failures
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_throttler_outbound_awaiting_release")
                .value(
                    self.avalanche_network_throttler_outbound_awaiting_release
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_requests_average_latency_seconds")
                .value(self.avalanche_requests_average_latency.unwrap() / 1000000000.0)
                .unit(StandardUnit::Seconds)
                .timestamp(ts)
                .build(),
            // Handshake messages.
            MetricDatum::builder()
                .metric_name("avalanche_network_version_sent_bytes")
                .value(self.avalanche_network_version_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_version_received_bytes")
                .value(self.avalanche_network_version_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_peerlist_sent_bytes")
                .value(self.avalanche_network_peerlist_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_peerlist_received_bytes")
                .value(self.avalanche_network_peerlist_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_ping_sent_bytes")
                .value(self.avalanche_network_ping_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_ping_received_bytes")
                .value(self.avalanche_network_ping_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_pong_sent_bytes")
                .value(self.avalanche_network_pong_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_pong_received_bytes")
                .value(self.avalanche_network_pong_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            // Consensus messages.
            MetricDatum::builder()
                .metric_name("avalanche_network_chits_sent_bytes")
                .value(self.avalanche_network_chits_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_chits_received_bytes")
                .value(self.avalanche_network_chits_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_sent_bytes")
                .value(self.avalanche_network_get_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_received_bytes")
                .value(self.avalanche_network_get_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_put_sent_bytes")
                .value(self.avalanche_network_put_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_put_received_bytes")
                .value(self.avalanche_network_put_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_pull_query_sent_bytes")
                .value(self.avalanche_network_pull_query_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_pull_query_received_bytes")
                .value(self.avalanche_network_pull_query_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_push_query_sent_bytes")
                .value(self.avalanche_network_push_query_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_push_query_received_bytes")
                .value(self.avalanche_network_push_query_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            // Bootstrap messages.
            MetricDatum::builder()
                .metric_name("avalanche_network_get_accepted_frontier_sent_bytes")
                .value(
                    self.avalanche_network_get_accepted_frontier_sent_bytes
                        .unwrap(),
                )
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_accepted_frontier_received_bytes")
                .value(
                    self.avalanche_network_get_accepted_frontier_received_bytes
                        .unwrap(),
                )
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_accepted_frontier_sent_bytes")
                .value(self.avalanche_network_accepted_frontier_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_accepted_frontier_received_bytes")
                .value(
                    self.avalanche_network_accepted_frontier_received_bytes
                        .unwrap(),
                )
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_accepted_sent_bytes")
                .value(self.avalanche_network_get_accepted_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_accepted_received_bytes")
                .value(self.avalanche_network_get_accepted_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_accepted_sent_bytes")
                .value(self.avalanche_network_accepted_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_accepted_received_bytes")
                .value(self.avalanche_network_accepted_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_ancestors_sent_bytes")
                .value(self.avalanche_network_get_ancestors_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_get_ancestors_received_bytes")
                .value(self.avalanche_network_get_ancestors_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_ancestors_sent_bytes")
                .value(self.avalanche_network_ancestors_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_ancestors_received_bytes")
                .value(self.avalanche_network_ancestors_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            // App messages.
            MetricDatum::builder()
                .metric_name("avalanche_network_app_gossip_sent_bytes")
                .value(self.avalanche_network_app_gossip_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_app_gossip_received_bytes")
                .value(self.avalanche_network_app_gossip_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_app_request_sent_bytes")
                .value(self.avalanche_network_app_request_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_app_request_received_bytes")
                .value(self.avalanche_network_app_request_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_app_response_sent_bytes")
                .value(self.avalanche_network_app_response_sent_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_app_response_received_bytes")
                .value(self.avalanche_network_app_response_received_bytes.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            // X-chain metrics.
            MetricDatum::builder()
                .metric_name("avalanche_X_db_get_count")
                .value(self.avalanche_x_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_db_write_size_sum")
                .value(self.avalanche_x_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_db_read_size_sum")
                .value(self.avalanche_x_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_vtx_processing")
                .value(self.avalanche_x_vtx_processing.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_accepted_count")
                .value(self.avalanche_x_txs_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_accepted_sum")
                .value(self.avalanche_x_txs_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_rejected_count")
                .value(self.avalanche_x_txs_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_rejected_sum")
                .value(self.avalanche_x_txs_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_polls_accepted_count")
                .value(self.avalanche_x_txs_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_polls_accepted_sum")
                .value(self.avalanche_x_txs_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_successful")
                .value(self.avalanche_x_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_failed")
                .value(self.avalanche_x_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_success_rate")
                .value(self.x_polls_success_rate())
                .unit(StandardUnit::Percent)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_handler_chits_count")
                .value(self.avalanche_x_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_handler_query_failed_count")
                .value(self.avalanche_x_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_count")
                .value(self.avalanche_x_whitelist_tx_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_count")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_count")
                .value(self.avalanche_x_whitelist_tx_polls_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_sum")
                .value(self.avalanche_x_whitelist_tx_polls_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_processing")
                .value(self.avalanche_x_whitelist_tx_processing.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_count")
                .value(self.avalanche_x_whitelist_tx_rejected_count.unwrap())
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_sum")
                .value(self.avalanche_x_whitelist_tx_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_failure")
                .value(self.avalanche_x_whitelist_vtx_issue_failure.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_success")
                .value(self.avalanche_x_whitelist_vtx_issue_success.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_benchlist_benched_num")
                .value(self.avalanche_x_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            // P-chain metrics.
            MetricDatum::builder()
                .metric_name("avalanche_P_vm_total_staked_avax")
                .value(self.avalanche_p_vm_total_staked.unwrap() / 1000000000.0) // On the P-Chain, one AVAX is 10^9  units.
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_get_count")
                .value(self.avalanche_p_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_write_size_sum")
                .value(self.avalanche_p_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_read_size_sum")
                .value(self.avalanche_p_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_accepted_count")
                .value(self.avalanche_p_blks_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_accepted_sum")
                .value(self.avalanche_p_blks_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_rejected_count")
                .value(self.avalanche_p_blks_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_rejected_sum")
                .value(self.avalanche_p_blks_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_polls_accepted_count")
                .value(self.avalanche_p_blks_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_polls_accepted_sum")
                .value(self.avalanche_p_blks_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_successful")
                .value(self.avalanche_p_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_failed")
                .value(self.avalanche_p_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_success_rate")
                .value(self.p_polls_success_rate())
                .unit(StandardUnit::Percent)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_handler_chits_count")
                .value(self.avalanche_p_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_handler_query_failed_count")
                .value(self.avalanche_p_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_benchlist_benched_num")
                .value(self.avalanche_p_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            // C-chain metrics.
            MetricDatum::builder()
                .metric_name("avalanche_C_db_get_count")
                .value(self.avalanche_c_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_write_size_sum")
                .value(self.avalanche_c_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_read_size_sum")
                .value(self.avalanche_c_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_processing")
                .value(self.avalanche_c_blks_processing.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_accepted_count")
                .value(self.avalanche_c_blks_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_accepted_sum")
                .value(self.avalanche_c_blks_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_rejected_count")
                .value(self.avalanche_c_blks_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_rejected_sum")
                .value(self.avalanche_c_blks_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_polls_accepted_count")
                .value(self.avalanche_c_blks_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_polls_accepted_sum")
                .value(self.avalanche_c_blks_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_successful")
                .value(self.avalanche_c_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_failed")
                .value(self.avalanche_c_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_success_rate")
                .value(self.c_polls_success_rate())
                .unit(StandardUnit::Percent)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_chits_count")
                .value(self.avalanche_c_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_query_failed_count")
                .value(self.avalanche_c_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_sum")
                .value(self.avalanche_c_handler_get_accepted_frontier_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_gossip_sum")
                .value(self.avalanche_c_handler_app_gossip_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_sum")
                .value(self.avalanche_c_handler_app_request_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_failed_sum")
                .value(self.avalanche_c_handler_app_request_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_response_sum")
                .value(self.avalanche_c_handler_app_response_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_accepted_frontier_sum")
                .value(self.avalanche_c_handler_accepted_frontier_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_failed_sum")
                .value(
                    self.avalanche_c_handler_get_accepted_frontier_failed_sum
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_sum")
                .value(self.avalanche_c_handler_get_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_accepted_sum")
                .value(self.avalanche_c_handler_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_failed_sum")
                .value(self.avalanche_c_handler_get_accepted_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_sum")
                .value(self.avalanche_c_handler_get_ancestors_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_ancestors_sum")
                .value(self.avalanche_c_handler_ancestors_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_failed_sum")
                .value(self.avalanche_c_handler_get_ancestors_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_sum")
                .value(self.avalanche_c_handler_get_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_put_sum")
                .value(self.avalanche_c_handler_put_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_failed_sum")
                .value(self.avalanche_c_handler_get_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_push_query_sum")
                .value(self.avalanche_c_handler_push_query_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_pull_query_sum")
                .value(self.avalanche_c_handler_pull_query_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_chits_sum")
                .value(self.avalanche_c_handler_chits_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_query_failed_sum")
                .value(self.avalanche_c_handler_query_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_connected_sum")
                .value(self.avalanche_c_handler_connected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_disconnected_sum")
                .value(self.avalanche_c_handler_disconnected_sum.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_benchlist_benched_num")
                .value(self.avalanche_c_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .build(),
        ];
        if let Some(prev_datum) = prev {
            data.push(
                MetricDatum::builder()
                    .metric_name("avalanche_C_blks_accepted_per_second")
                    .value(self.c_blks_accepted_per_second(prev_datum))
                    .unit(StandardUnit::Count)
                    .timestamp(ts)
                    .build(),
            );
        }
        data
    }
}

/// "If a single piece of data must be accessible from more than one task
/// concurrently, then it must be shared using synchronization primitives such as Arc."
/// ref. https://tokio.rs/tokio/tutorial/spawning
pub async fn get(url: Arc<String>) -> io::Result<Metrics> {
    let ts = Utc::now();

    let joined = http::join_uri(url.as_str(), "ext/metrics")?;
    info!("checking for {:?}", joined);

    let rb = http::insecure_get(url.as_str(), "ext/metrics").await?;
    let s = prometheus::Scrape::from_bytes(&rb)?;

    Ok(Metrics {
        ts,

        // Network metrics.
        avalanche_network_peers: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_network_peers")
                .value
                .to_f64(),
        ),
        avalanche_network_pull_query_sent: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_pull_query_sent"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_push_query_sent: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_push_query_sent"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_msgs_failed_to_parse: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_msgs_failed_to_parse"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_inbound_conn_throttler_allowed: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_inbound_conn_throttler_allowed"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_byte_throttler_inbound_awaiting_release: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_byte_throttler_inbound_awaiting_release"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_throttler_outbound_acquire_failures: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_throttler_outbound_acquire_failures"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_throttler_outbound_awaiting_release: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_throttler_outbound_awaiting_release"
            })
            .value
            .to_f64(),
        ),
        avalanche_requests_average_latency: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_requests_average_latency"
            })
            .value
            .to_f64(),
        ),

        // Handshake messages.
        avalanche_network_version_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_version_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_version_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_version_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_peerlist_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_peerlist_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_peerlist_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_peerlist_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_ping_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_ping_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_ping_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_ping_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_pong_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_pong_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_pong_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_pong_received_bytes"
            })
            .value
            .to_f64(),
        ),

        // Consensus messages.
        avalanche_network_chits_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_chits_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_chits_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_chits_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_put_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_put_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_put_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_put_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_pull_query_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_pull_query_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_pull_query_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_pull_query_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_push_query_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_push_query_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_push_query_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_push_query_received_bytes"
            })
            .value
            .to_f64(),
        ),

        // Bootstrap messages.
        avalanche_network_get_accepted_frontier_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_accepted_frontier_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_accepted_frontier_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_accepted_frontier_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_accepted_frontier_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_accepted_frontier_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_accepted_frontier_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_accepted_frontier_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_accepted_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_accepted_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_accepted_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_accepted_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_accepted_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_accepted_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_accepted_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_accepted_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_ancestors_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_ancestors_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_get_ancestors_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_get_ancestors_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_ancestors_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_ancestors_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_ancestors_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_ancestors_received_bytes"
            })
            .value
            .to_f64(),
        ),

        // App messages.
        avalanche_network_app_gossip_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_gossip_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_app_gossip_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_gossip_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_app_request_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_request_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_app_request_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_request_received_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_app_response_sent_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_response_sent_bytes"
            })
            .value
            .to_f64(),
        ),
        avalanche_network_app_response_received_bytes: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_network_app_response_received_bytes"
            })
            .value
            .to_f64(),
        ),

        // X-chain metrics.
        avalanche_x_db_get_count: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_db_get_count")
                .value
                .to_f64(),
        ),
        avalanche_x_db_write_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_db_write_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_x_db_read_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_db_read_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_x_vtx_processing: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_vtx_processing")
                .value
                .to_f64(),
        ),
        avalanche_x_txs_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_txs_accepted_count")
                .value
                .to_f64(),
        ),
        avalanche_x_txs_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_txs_accepted_sum")
                .value
                .to_f64(),
        ),
        avalanche_x_txs_rejected_count: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_txs_rejected_count")
                .value
                .to_f64(),
        ),
        avalanche_x_txs_rejected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_txs_rejected_sum")
                .value
                .to_f64(),
        ),
        avalanche_x_txs_polls_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_txs_polls_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_txs_polls_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_txs_polls_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_polls_successful: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_polls_successful")
                .value
                .to_f64(),
        ),
        avalanche_x_polls_failed: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_polls_failed")
                .value
                .to_f64(),
        ),
        avalanche_x_handler_chits_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_handler_chits_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_handler_query_failed_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_handler_query_failed_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_polls_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_polls_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_polls_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_polls_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_polls_rejected_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_polls_rejected_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_polls_rejected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_polls_rejected_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_processing: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_processing"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_rejected_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_rejected_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_tx_rejected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_tx_rejected_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_vtx_issue_failure: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_vtx_issue_failure"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_whitelist_vtx_issue_success: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_whitelist_vtx_issue_success"
            })
            .value
            .to_f64(),
        ),
        avalanche_x_benchlist_benched_num: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_X_benchlist_benched_num"
            })
            .value
            .to_f64(),
        ),

        // P-chain metrics.
        avalanche_p_vm_total_staked: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_vm_total_staked")
                .value
                .to_f64(),
        ),
        avalanche_p_db_get_count: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_db_get_count")
                .value
                .to_f64(),
        ),
        avalanche_p_db_write_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_db_write_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_p_db_read_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_db_read_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_p_blks_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_blks_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_blks_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_blks_accepted_sum")
                .value
                .to_f64(),
        ),
        avalanche_p_blks_rejected_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_blks_rejected_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_blks_rejected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_blks_rejected_sum")
                .value
                .to_f64(),
        ),
        avalanche_p_polls_successful: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_polls_successful")
                .value
                .to_f64(),
        ),
        avalanche_p_polls_failed: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_polls_failed")
                .value
                .to_f64(),
        ),
        avalanche_p_blks_polls_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_blks_polls_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_blks_polls_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_blks_polls_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_handler_chits_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_handler_chits_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_handler_query_failed_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_handler_query_failed_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_p_benchlist_benched_num: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_P_benchlist_benched_num"
            })
            .value
            .to_f64(),
        ),

        // C-chain metrics.
        avalanche_c_db_get_count: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_db_get_count")
                .value
                .to_f64(),
        ),
        avalanche_c_db_write_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_db_write_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_db_read_size_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_db_read_size_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_blks_processing: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_blks_processing")
                .value
                .to_f64(),
        ),
        avalanche_c_blks_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_blks_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_blks_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_blks_accepted_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_blks_rejected_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_blks_rejected_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_blks_rejected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_blks_rejected_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_blks_polls_accepted_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_blks_polls_accepted_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_blks_polls_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_blks_polls_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_polls_successful: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_polls_successful")
                .value
                .to_f64(),
        ),
        avalanche_c_polls_failed: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_polls_failed")
                .value
                .to_f64(),
        ),
        avalanche_c_handler_chits_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_chits_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_query_failed_count: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_query_failed_count"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_accepted_frontier_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_accepted_frontier_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_app_gossip_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_app_gossip_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_app_request_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_app_request_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_app_request_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_app_request_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_app_response_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_app_response_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_accepted_frontier_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_accepted_frontier_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_accepted_frontier_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_accepted_frontier_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_accepted_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_accepted_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_accepted_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_accepted_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_ancestors_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_ancestors_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_ancestors_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_ancestors_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_ancestors_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_ancestors_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_get_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_get_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_handler_put_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_put_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_handler_get_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_get_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_push_query_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_push_query_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_pull_query_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_pull_query_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_chits_sum: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_chits_sum")
                .value
                .to_f64(),
        ),
        avalanche_c_handler_query_failed_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_query_failed_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_connected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_connected_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_handler_disconnected_sum: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_handler_disconnected_sum"
            })
            .value
            .to_f64(),
        ),
        avalanche_c_benchlist_benched_num: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_C_benchlist_benched_num"
            })
            .value
            .to_f64(),
        ),
    })
}

pub async fn spawn_get(u: &str) -> io::Result<Metrics> {
    let ep_arc = Arc::new(u.to_string());
    tokio::spawn(async move { get(ep_arc).await })
        .await
        .expect("failed spawn await")
}

#[test]
fn test_parse_avalanchego_metrics() {
    use rust_embed::RustEmbed;
    use utils::prometheus;
    let _ = env_logger::builder().is_test(true).try_init();

    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let metrics_raw = Asset::get("artifacts/metrics.avalanchego.v1.7.7").unwrap();
    let metrics_raw = std::str::from_utf8(metrics_raw.data.as_ref()).unwrap();

    let s = prometheus::Scrape::from_bytes(metrics_raw.as_bytes()).unwrap();
    info!("{}", s.metrics.len());

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric
            == "avalanche_network_ancestors_failed"),
        &prometheus::Metric {
            metric: "avalanche_network_ancestors_failed".to_string(),
            value: prometheus::Value::Counter(0.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric
            == "avalanche_network_codec_put_compress_time_sum"),
        &prometheus::Metric {
            metric: "avalanche_network_codec_put_compress_time_sum".to_string(),
            value: prometheus::Value::Gauge(115966061.0),
            labels: None,
            timestamp: None,
        }
    );

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_db_read_size_sum");
    assert_eq!(mv.value.to_f64(), 92685.0);
    assert_eq!(
        mv,
        &prometheus::Metric {
            metric: "avalanche_db_read_size_sum".to_string(),
            value: prometheus::Value::Gauge(92685.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_db_new_iterator_sum"),
        &prometheus::Metric {
            metric: "avalanche_db_new_iterator_sum".to_string(),
            value: prometheus::Value::Gauge(37150.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric
            == "avalanche_C_handler_get_accepted_frontier_sum"),
        &prometheus::Metric {
            metric: "avalanche_C_handler_get_accepted_frontier_sum".to_string(),
            value: prometheus::Value::Gauge(913967.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| {
            s.metric == "avalanche_network_bandwidth_throttler_inbound_acquire_latency_sum"
        }),
        &prometheus::Metric {
            metric: "avalanche_network_bandwidth_throttler_inbound_acquire_latency_sum".to_string(),
            value: prometheus::Value::Gauge(3476103.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric
            == "avalanche_network_peerlist_compression_saved_sent_bytes_sum"),
        &prometheus::Metric {
            metric: "avalanche_network_peerlist_compression_saved_sent_bytes_sum".to_string(),
            value: prometheus::Value::Gauge(8982.0),
            labels: None,
            timestamp: None,
        }
    );

    assert_eq!(
        prometheus::match_metric(&s.metrics, |s| s.metric
            == "avalanche_network_peerlist_received_bytes"),
        &prometheus::Metric {
            metric: "avalanche_network_peerlist_received_bytes".to_string(),
            value: prometheus::Value::Counter(848517.0),
            labels: None,
            timestamp: None,
        }
    );
}
