use std::{io, process::Command, time::Duration};

use aws_sdk_cloudwatch::model::{MetricDatum, StandardUnit};
use chrono::{DateTime, Utc};
use log::info;
use serde::Serialize;

use crate::utils::{http, prometheus, rfc3339};

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Metrics {
    /// Represents the data format in RFC3339.
    /// ref. https://serde.rs/custom-date-format.html
    #[serde(with = "rfc3339::serde_format")]
    pub ts: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_peers: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_network_throttler_outbound_acquire_failures: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_requests_average_latency: Option<f64>,

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

            avalanche_network_peers: None,
            avalanche_network_throttler_outbound_acquire_failures: None,
            avalanche_requests_average_latency: None,

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
        let mut data = vec![
            MetricDatum::builder()
                .metric_name("avalanche_network_peers")
                .value(self.avalanche_network_peers.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_network_throttler_outbound_acquire_failures")
                .value(
                    self.avalanche_network_throttler_outbound_acquire_failures
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_requests_average_latency_seconds")
                .value(self.avalanche_requests_average_latency.unwrap() / 1000000000.0)
                .unit(StandardUnit::Milliseconds)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_db_get_count")
                .value(self.avalanche_x_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_db_write_size_sum")
                .value(self.avalanche_x_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_db_read_size_sum")
                .value(self.avalanche_x_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_vtx_processing")
                .value(self.avalanche_x_vtx_processing.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_accepted_count")
                .value(self.avalanche_x_txs_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_accepted_sum")
                .value(self.avalanche_x_txs_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_rejected_count")
                .value(self.avalanche_x_txs_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_rejected_sum")
                .value(self.avalanche_x_txs_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_polls_accepted_count")
                .value(self.avalanche_x_txs_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_txs_polls_accepted_sum")
                .value(self.avalanche_x_txs_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_successful")
                .value(self.avalanche_x_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_failed")
                .value(self.avalanche_x_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_polls_success_rate")
                .value(self.x_polls_success_rate())
                .unit(StandardUnit::Percent)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_handler_chits_count")
                .value(self.avalanche_x_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_handler_query_failed_count")
                .value(self.avalanche_x_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_count")
                .value(self.avalanche_x_whitelist_tx_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_count")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_count")
                .value(self.avalanche_x_whitelist_tx_polls_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_sum")
                .value(self.avalanche_x_whitelist_tx_polls_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_processing")
                .value(self.avalanche_x_whitelist_tx_processing.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_count")
                .value(self.avalanche_x_whitelist_tx_rejected_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_sum")
                .value(self.avalanche_x_whitelist_tx_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_failure")
                .value(self.avalanche_x_whitelist_vtx_issue_failure.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_success")
                .value(self.avalanche_x_whitelist_vtx_issue_success.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_benchlist_benched_num")
                .value(self.avalanche_x_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_vm_total_staked")
                .value(self.avalanche_p_vm_total_staked.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_get_count")
                .value(self.avalanche_p_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_write_size_sum")
                .value(self.avalanche_p_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_read_size_sum")
                .value(self.avalanche_p_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_accepted_count")
                .value(self.avalanche_p_blks_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_accepted_sum")
                .value(self.avalanche_p_blks_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_rejected_count")
                .value(self.avalanche_p_blks_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_rejected_sum")
                .value(self.avalanche_p_blks_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_polls_accepted_count")
                .value(self.avalanche_p_blks_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_blks_polls_accepted_sum")
                .value(self.avalanche_p_blks_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_successful")
                .value(self.avalanche_p_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_failed")
                .value(self.avalanche_p_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_polls_success_rate")
                .value(self.p_polls_success_rate())
                .unit(StandardUnit::Percent)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_handler_chits_count")
                .value(self.avalanche_p_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_handler_query_failed_count")
                .value(self.avalanche_p_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_benchlist_benched_num")
                .value(self.avalanche_p_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_get_count")
                .value(self.avalanche_c_db_get_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_write_size_sum")
                .value(self.avalanche_c_db_write_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_read_size_sum")
                .value(self.avalanche_c_db_read_size_sum.unwrap())
                .unit(StandardUnit::Bytes)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_processing")
                .value(self.avalanche_c_blks_processing.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_accepted_count")
                .value(self.avalanche_c_blks_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_accepted_sum")
                .value(self.avalanche_c_blks_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_rejected_count")
                .value(self.avalanche_c_blks_rejected_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_rejected_sum")
                .value(self.avalanche_c_blks_rejected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_polls_accepted_count")
                .value(self.avalanche_c_blks_polls_accepted_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_polls_accepted_sum")
                .value(self.avalanche_c_blks_polls_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_successful")
                .value(self.avalanche_c_polls_successful.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_failed")
                .value(self.avalanche_c_polls_failed.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_polls_success_rate")
                .value(self.c_polls_success_rate())
                .unit(StandardUnit::Percent)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_chits_count")
                .value(self.avalanche_c_handler_chits_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_query_failed_count")
                .value(self.avalanche_c_handler_query_failed_count.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_sum")
                .value(self.avalanche_c_handler_get_accepted_frontier_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_gossip_sum")
                .value(self.avalanche_c_handler_app_gossip_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_sum")
                .value(self.avalanche_c_handler_app_request_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_failed_sum")
                .value(self.avalanche_c_handler_app_request_failed_sum.unwrap())
                .unit(StandardUnit::Count)
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
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_failed_sum")
                .value(
                    self.avalanche_c_handler_get_accepted_frontier_failed_sum
                        .unwrap(),
                )
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_sum")
                .value(self.avalanche_c_handler_get_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_accepted_sum")
                .value(self.avalanche_c_handler_accepted_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_failed_sum")
                .value(self.avalanche_c_handler_get_accepted_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_sum")
                .value(self.avalanche_c_handler_get_ancestors_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_ancestors_sum")
                .value(self.avalanche_c_handler_ancestors_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_failed_sum")
                .value(self.avalanche_c_handler_get_ancestors_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_sum")
                .value(self.avalanche_c_handler_get_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_put_sum")
                .value(self.avalanche_c_handler_put_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_failed_sum")
                .value(self.avalanche_c_handler_get_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_push_query_sum")
                .value(self.avalanche_c_handler_push_query_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_pull_query_sum")
                .value(self.avalanche_c_handler_pull_query_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_chits_sum")
                .value(self.avalanche_c_handler_chits_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_query_failed_sum")
                .value(self.avalanche_c_handler_query_failed_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_connected_sum")
                .value(self.avalanche_c_handler_connected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_disconnected_sum")
                .value(self.avalanche_c_handler_disconnected_sum.unwrap())
                .unit(StandardUnit::Count)
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_benchlist_benched_num")
                .value(self.avalanche_c_benchlist_benched_num.unwrap())
                .unit(StandardUnit::Count)
                .build(),
        ];
        if prev.is_some() {
            let prev_datum = prev.unwrap();
            data.push(
                MetricDatum::builder()
                    .metric_name("avalanche_C_blks_accepted_per_second")
                    .value(self.c_blks_accepted_per_second(prev_datum))
                    .unit(StandardUnit::Count)
                    .build(),
            );
        }
        data
    }
}

pub async fn get(u: &str) -> io::Result<Metrics> {
    let ts = Utc::now();
    let url_path = "ext/metrics";
    info!("checking {}/{}", u, url_path);

    let output = {
        if u.starts_with("https") {
            let joined = http::join_uri(u, url_path)?;

            // TODO: implement this with native Rust
            info!("sending via curl --insecure");
            let mut cmd = Command::new("curl");
            cmd.arg("--insecure");
            cmd.arg(joined.as_str());

            let output = cmd.output()?;
            output.stdout
        } else {
            let req = http::create_get(u, url_path)?;
            let buf =
                match http::read_bytes(req, Duration::from_secs(5), u.starts_with("https"), false)
                    .await
                {
                    Ok(u) => u,
                    Err(e) => return Err(e),
                };
            buf.to_vec()
        }
    };

    let s = prometheus::Scrape::from_bytes(&output)?;

    Ok(Metrics {
        ts,

        avalanche_network_peers: Some(
            prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_network_peers")
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

        avalanche_requests_average_latency: Some(
            prometheus::match_metric(&s.metrics, |s| {
                s.metric == "avalanche_requests_average_latency"
            })
            .value
            .to_f64(),
        ),

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
