use std::{io, sync::Arc};

use avalanche_types::metrics::avalanchego::RawMetrics;
use aws_sdk_cloudwatch::{
    model::{Dimension, MetricDatum, StandardUnit},
    types::DateTime as SmithyDateTime,
};
use chrono::Utc;
use log::info;
use avalanche_utils::{http, prometheus};

pub fn to_cw_metric_data(cur: &RawMetrics, prev: Option<RawMetrics>) -> Vec<MetricDatum> {
    let ts = SmithyDateTime::from_nanos(cur.ts.timestamp_nanos() as i128)
        .expect("failed to convert DateTime<Utc>");

    let mut data = vec![
        // Network metrics.
        MetricDatum::builder()
            .metric_name("avalanche_network_peers")
            .value(cur.avalanche_network_peers.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_pull_query_sent")
            .value(cur.avalanche_network_pull_query_sent.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_push_query_sent")
            .value(cur.avalanche_network_push_query_sent.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_msgs_failed_to_parse")
            .value(cur.avalanche_network_msgs_failed_to_parse.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_inbound_conn_throttler_allowed")
            .value(
                cur.avalanche_network_inbound_conn_throttler_allowed
                    .unwrap(),
            )
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_byte_throttler_inbound_awaiting_release")
            .value(
                cur.avalanche_network_byte_throttler_inbound_awaiting_release
                    .unwrap(),
            )
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_throttler_outbound_acquire_failures")
            .value(
                cur.avalanche_network_throttler_outbound_acquire_failures
                    .unwrap(),
            )
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_throttler_outbound_awaiting_release")
            .value(
                cur.avalanche_network_throttler_outbound_awaiting_release
                    .unwrap(),
            )
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_requests_average_latency_seconds")
            .value(cur.avalanche_requests_average_latency.unwrap() / 1000000000.0)
            .unit(StandardUnit::Seconds)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // Handshake messages.
        MetricDatum::builder()
            .metric_name("avalanche_network_version_sent_bytes")
            .value(cur.avalanche_network_version_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_version_received_bytes")
            .value(cur.avalanche_network_version_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_peerlist_sent_bytes")
            .value(cur.avalanche_network_peerlist_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_peerlist_received_bytes")
            .value(cur.avalanche_network_peerlist_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_ping_sent_bytes")
            .value(cur.avalanche_network_ping_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_ping_received_bytes")
            .value(cur.avalanche_network_ping_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_pong_sent_bytes")
            .value(cur.avalanche_network_pong_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_pong_received_bytes")
            .value(cur.avalanche_network_pong_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // Consensus messages.
        MetricDatum::builder()
            .metric_name("avalanche_network_chits_sent_bytes")
            .value(cur.avalanche_network_chits_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_chits_received_bytes")
            .value(cur.avalanche_network_chits_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_sent_bytes")
            .value(cur.avalanche_network_get_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_received_bytes")
            .value(cur.avalanche_network_get_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_put_sent_bytes")
            .value(cur.avalanche_network_put_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_put_received_bytes")
            .value(cur.avalanche_network_put_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_pull_query_sent_bytes")
            .value(cur.avalanche_network_pull_query_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_pull_query_received_bytes")
            .value(cur.avalanche_network_pull_query_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_push_query_sent_bytes")
            .value(cur.avalanche_network_push_query_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_push_query_received_bytes")
            .value(cur.avalanche_network_push_query_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // Bootstrap messages.
        MetricDatum::builder()
            .metric_name("avalanche_network_get_accepted_frontier_sent_bytes")
            .value(
                cur.avalanche_network_get_accepted_frontier_sent_bytes
                    .unwrap(),
            )
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_accepted_frontier_received_bytes")
            .value(
                cur.avalanche_network_get_accepted_frontier_received_bytes
                    .unwrap(),
            )
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_accepted_frontier_sent_bytes")
            .value(cur.avalanche_network_accepted_frontier_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_accepted_frontier_received_bytes")
            .value(
                cur.avalanche_network_accepted_frontier_received_bytes
                    .unwrap(),
            )
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_accepted_sent_bytes")
            .value(cur.avalanche_network_get_accepted_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_accepted_received_bytes")
            .value(cur.avalanche_network_get_accepted_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_accepted_sent_bytes")
            .value(cur.avalanche_network_accepted_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_accepted_received_bytes")
            .value(cur.avalanche_network_accepted_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_ancestors_sent_bytes")
            .value(cur.avalanche_network_get_ancestors_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_get_ancestors_received_bytes")
            .value(cur.avalanche_network_get_ancestors_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_ancestors_sent_bytes")
            .value(cur.avalanche_network_ancestors_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_ancestors_received_bytes")
            .value(cur.avalanche_network_ancestors_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // App messages.
        MetricDatum::builder()
            .metric_name("avalanche_network_app_gossip_sent_bytes")
            .value(cur.avalanche_network_app_gossip_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_app_gossip_received_bytes")
            .value(cur.avalanche_network_app_gossip_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_app_request_sent_bytes")
            .value(cur.avalanche_network_app_request_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_app_request_received_bytes")
            .value(cur.avalanche_network_app_request_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_app_response_sent_bytes")
            .value(cur.avalanche_network_app_response_sent_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_network_app_response_received_bytes")
            .value(cur.avalanche_network_app_response_received_bytes.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // X-chain metrics.
        MetricDatum::builder()
            .metric_name("avalanche_X_db_get_count")
            .value(cur.avalanche_x_db_get_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_db_write_size_sum")
            .value(cur.avalanche_x_db_write_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_db_read_size_sum")
            .value(cur.avalanche_x_db_read_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_vtx_processing")
            .value(cur.avalanche_x_vtx_processing.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_accepted_count")
            .value(cur.avalanche_x_txs_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_accepted_sum")
            .value(cur.avalanche_x_txs_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_rejected_count")
            .value(cur.avalanche_x_txs_rejected_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_rejected_sum")
            .value(cur.avalanche_x_txs_rejected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_polls_accepted_count")
            .value(cur.avalanche_x_txs_polls_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_txs_polls_accepted_sum")
            .value(cur.avalanche_x_txs_polls_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_polls_successful")
            .value(cur.avalanche_x_polls_successful.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_polls_failed")
            .value(cur.avalanche_x_polls_failed.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_polls_success_rate")
            .value(cur.x_polls_success_rate())
            .unit(StandardUnit::Percent)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_handler_chits_count")
            .value(cur.avalanche_x_handler_chits_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_handler_query_failed_count")
            .value(cur.avalanche_x_handler_query_failed_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_accepted_count")
            .value(cur.avalanche_x_whitelist_tx_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_accepted_sum")
            .value(cur.avalanche_x_whitelist_tx_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_polls_accepted_count")
            .value(cur.avalanche_x_whitelist_tx_polls_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_polls_accepted_sum")
            .value(cur.avalanche_x_whitelist_tx_polls_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_polls_rejected_count")
            .value(cur.avalanche_x_whitelist_tx_polls_rejected_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_polls_rejected_sum")
            .value(cur.avalanche_x_whitelist_tx_polls_rejected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_processing")
            .value(cur.avalanche_x_whitelist_tx_processing.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_rejected_count")
            .value(cur.avalanche_x_whitelist_tx_rejected_count.unwrap())
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_tx_rejected_sum")
            .value(cur.avalanche_x_whitelist_tx_rejected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_vtx_issue_failure")
            .value(cur.avalanche_x_whitelist_vtx_issue_failure.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_whitelist_vtx_issue_success")
            .value(cur.avalanche_x_whitelist_vtx_issue_success.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_X_benchlist_benched_num")
            .value(cur.avalanche_x_benchlist_benched_num.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // P-chain metrics.
        MetricDatum::builder()
            .metric_name("avalanche_P_vm_total_staked_avax")
            .value(cur.avalanche_p_vm_total_staked.unwrap() / 1000000000.0) // On the P-Chain, one AVAX is 10^9  units.
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_db_get_count")
            .value(cur.avalanche_p_db_get_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_db_write_size_sum")
            .value(cur.avalanche_p_db_write_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_db_read_size_sum")
            .value(cur.avalanche_p_db_read_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_accepted_count")
            .value(cur.avalanche_p_blks_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_accepted_sum")
            .value(cur.avalanche_p_blks_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_rejected_count")
            .value(cur.avalanche_p_blks_rejected_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_rejected_sum")
            .value(cur.avalanche_p_blks_rejected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_polls_accepted_count")
            .value(cur.avalanche_p_blks_polls_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_blks_polls_accepted_sum")
            .value(cur.avalanche_p_blks_polls_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_polls_successful")
            .value(cur.avalanche_p_polls_successful.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_polls_failed")
            .value(cur.avalanche_p_polls_failed.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_polls_success_rate")
            .value(cur.p_polls_success_rate())
            .unit(StandardUnit::Percent)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_handler_chits_count")
            .value(cur.avalanche_p_handler_chits_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_handler_query_failed_count")
            .value(cur.avalanche_p_handler_query_failed_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_P_benchlist_benched_num")
            .value(cur.avalanche_p_benchlist_benched_num.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        // C-chain metrics.
        MetricDatum::builder()
            .metric_name("avalanche_C_db_get_count")
            .value(cur.avalanche_c_db_get_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_db_write_size_sum")
            .value(cur.avalanche_c_db_write_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_db_read_size_sum")
            .value(cur.avalanche_c_db_read_size_sum.unwrap())
            .unit(StandardUnit::Bytes)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_processing")
            .value(cur.avalanche_c_blks_processing.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_accepted_count")
            .value(cur.avalanche_c_blks_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_accepted_sum")
            .value(cur.avalanche_c_blks_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_rejected_count")
            .value(cur.avalanche_c_blks_rejected_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_rejected_sum")
            .value(cur.avalanche_c_blks_rejected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_polls_accepted_count")
            .value(cur.avalanche_c_blks_polls_accepted_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_blks_polls_accepted_sum")
            .value(cur.avalanche_c_blks_polls_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_polls_successful")
            .value(cur.avalanche_c_polls_successful.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_polls_failed")
            .value(cur.avalanche_c_polls_failed.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_polls_success_rate")
            .value(cur.c_polls_success_rate())
            .unit(StandardUnit::Percent)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_chits_count")
            .value(cur.avalanche_c_handler_chits_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_query_failed_count")
            .value(cur.avalanche_c_handler_query_failed_count.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_accepted_frontier_sum")
            .value(cur.avalanche_c_handler_get_accepted_frontier_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_app_gossip_sum")
            .value(cur.avalanche_c_handler_app_gossip_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_app_request_sum")
            .value(cur.avalanche_c_handler_app_request_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_app_request_failed_sum")
            .value(cur.avalanche_c_handler_app_request_failed_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_app_response_sum")
            .value(cur.avalanche_c_handler_app_response_sum.unwrap())
            .unit(StandardUnit::Count)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_accepted_frontier_sum")
            .value(cur.avalanche_c_handler_accepted_frontier_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_accepted_frontier_failed_sum")
            .value(
                cur.avalanche_c_handler_get_accepted_frontier_failed_sum
                    .unwrap(),
            )
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_accepted_sum")
            .value(cur.avalanche_c_handler_get_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_accepted_sum")
            .value(cur.avalanche_c_handler_accepted_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_accepted_failed_sum")
            .value(cur.avalanche_c_handler_get_accepted_failed_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_ancestors_sum")
            .value(cur.avalanche_c_handler_get_ancestors_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_ancestors_sum")
            .value(cur.avalanche_c_handler_ancestors_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_ancestors_failed_sum")
            .value(cur.avalanche_c_handler_get_ancestors_failed_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_sum")
            .value(cur.avalanche_c_handler_get_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_put_sum")
            .value(cur.avalanche_c_handler_put_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_get_failed_sum")
            .value(cur.avalanche_c_handler_get_failed_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_push_query_sum")
            .value(cur.avalanche_c_handler_push_query_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_pull_query_sum")
            .value(cur.avalanche_c_handler_pull_query_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_chits_sum")
            .value(cur.avalanche_c_handler_chits_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_query_failed_sum")
            .value(cur.avalanche_c_handler_query_failed_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_connected_sum")
            .value(cur.avalanche_c_handler_connected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_handler_disconnected_sum")
            .value(cur.avalanche_c_handler_disconnected_sum.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
        MetricDatum::builder()
            .metric_name("avalanche_C_benchlist_benched_num")
            .value(cur.avalanche_c_benchlist_benched_num.unwrap())
            .unit(StandardUnit::Count)
            .timestamp(ts)
            .dimensions(
                Dimension::builder()
                    .name("avalanche-metrics")
                    .value("raw")
                    .build(),
            )
            .build(),
    ];
    if let Some(prev_datum) = prev {
        data.push(
            MetricDatum::builder()
                .metric_name("avalanche_C_blks_accepted_per_second")
                .value(cur.c_blks_accepted_per_second(prev_datum))
                .unit(StandardUnit::Count)
                .timestamp(ts)
                .dimensions(
                    Dimension::builder()
                        .name("avalanche-metrics")
                        .value("processed")
                        .build(),
                )
                .build(),
        );
    }
    data
}

/// "If a single piece of data must be accessible from more than one task
/// concurrently, then it must be shared using synchronization primitives such as Arc."
/// ref. https://tokio.rs/tokio/tutorial/spawning
pub async fn get(url: Arc<String>) -> io::Result<RawMetrics> {
    let ts = Utc::now();

    let joined = http::join_uri(url.as_str(), "ext/metrics")?;
    info!("checking for {:?}", joined);

    let rb = http::get_non_tls(url.as_str(), "ext/metrics").await?;
    let s = prometheus::Scrape::from_bytes(&rb)?;

    Ok(RawMetrics {
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

pub async fn spawn_get(u: &str) -> io::Result<RawMetrics> {
    let ep_arc = Arc::new(u.to_string());
    tokio::spawn(async move { get(ep_arc).await })
        .await
        .expect("failed spawn await")
}
