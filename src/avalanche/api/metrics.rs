use std::{io, process::Command, time::Duration};

use aws_sdk_cloudwatch::model::MetricDatum;
use log::info;
use serde::Serialize;

use crate::utils::{http, prometheus};

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_x_db_get_count: Option<f64>,
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
    pub avalanche_p_db_get_count: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanche_c_db_get_count: Option<f64>,
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
}

impl Metrics {
    pub fn to_cw_metric_data(&self) -> Vec<Vec<MetricDatum>> {
        let batch1: Vec<MetricDatum> = vec![
            MetricDatum::builder()
                .metric_name("avalanche_X_db_get_count")
                .value(self.avalanche_x_db_get_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_count")
                .value(self.avalanche_x_whitelist_tx_accepted_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_accepted_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_count")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_accepted_sum")
                .value(self.avalanche_x_whitelist_tx_polls_accepted_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_count")
                .value(self.avalanche_x_whitelist_tx_polls_rejected_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_polls_rejected_sum")
                .value(self.avalanche_x_db_get_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_processing")
                .value(self.avalanche_x_whitelist_tx_processing.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_count")
                .value(self.avalanche_x_whitelist_tx_rejected_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_tx_rejected_sum")
                .value(self.avalanche_x_whitelist_tx_rejected_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_failure")
                .value(self.avalanche_x_whitelist_vtx_issue_failure.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_X_whitelist_vtx_issue_success")
                .value(self.avalanche_x_whitelist_vtx_issue_success.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_P_db_get_count")
                .value(self.avalanche_p_db_get_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_db_get_count")
                .value(self.avalanche_c_db_get_count.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_sum")
                .value(self.avalanche_c_handler_get_accepted_frontier_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_gossip_sum")
                .value(self.avalanche_c_handler_app_gossip_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_sum")
                .value(self.avalanche_c_handler_app_request_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_request_failed_sum")
                .value(self.avalanche_c_handler_app_request_failed_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_app_response_sum")
                .value(self.avalanche_c_handler_app_response_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_accepted_frontier_sum")
                .value(self.avalanche_c_handler_accepted_frontier_sum.unwrap())
                .build(),
        ];

        let batch2: Vec<MetricDatum> = vec![
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_frontier_failed_sum")
                .value(
                    self.avalanche_c_handler_get_accepted_frontier_failed_sum
                        .unwrap(),
                )
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_sum")
                .value(self.avalanche_c_handler_get_accepted_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_accepted_sum")
                .value(self.avalanche_c_handler_accepted_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_accepted_failed_sum")
                .value(self.avalanche_c_handler_get_accepted_failed_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_sum")
                .value(self.avalanche_c_handler_get_ancestors_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_ancestors_sum")
                .value(self.avalanche_c_handler_ancestors_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_ancestors_failed_sum")
                .value(self.avalanche_c_handler_get_ancestors_failed_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_sum")
                .value(self.avalanche_c_handler_get_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_put_sum")
                .value(self.avalanche_c_handler_put_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_get_failed_sum")
                .value(self.avalanche_c_handler_get_failed_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_push_query_sum")
                .value(self.avalanche_c_handler_push_query_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_pull_query_sum")
                .value(self.avalanche_c_handler_pull_query_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_chits_sum")
                .value(self.avalanche_c_handler_chits_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_query_failed_sum")
                .value(self.avalanche_c_handler_query_failed_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_connected_sum")
                .value(self.avalanche_c_handler_connected_sum.unwrap())
                .build(),
            MetricDatum::builder()
                .metric_name("avalanche_C_handler_disconnected_sum")
                .value(self.avalanche_c_handler_disconnected_sum.unwrap())
                .build(),
        ];

        vec![batch1, batch2]
    }
}

pub async fn get(u: &str) -> io::Result<Metrics> {
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

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_X_db_get_count");
    let avalanche_x_db_get_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_accepted_count"
    });
    let avalanche_x_whitelist_tx_accepted_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_accepted_sum"
    });
    let avalanche_x_whitelist_tx_accepted_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_polls_accepted_count"
    });
    let avalanche_x_whitelist_tx_polls_accepted_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_polls_accepted_sum"
    });
    let avalanche_x_whitelist_tx_polls_accepted_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_polls_rejected_count"
    });
    let avalanche_x_whitelist_tx_polls_rejected_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_polls_rejected_sum"
    });
    let avalanche_x_whitelist_tx_polls_rejected_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_processing"
    });
    let avalanche_x_whitelist_tx_processing = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_rejected_count"
    });
    let avalanche_x_whitelist_tx_rejected_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_tx_rejected_sum"
    });
    let avalanche_x_whitelist_tx_rejected_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_vtx_issue_failure"
    });
    let avalanche_x_whitelist_vtx_issue_failure = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_X_whitelist_vtx_issue_success"
    });
    let avalanche_x_whitelist_vtx_issue_success = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_P_db_get_count");
    let avalanche_p_db_get_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_db_get_count");
    let avalanche_c_db_get_count = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_accepted_frontier_sum"
    });
    let avalanche_c_handler_get_accepted_frontier_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_app_gossip_sum"
    });
    let avalanche_c_handler_app_gossip_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_app_request_sum"
    });
    let avalanche_c_handler_app_request_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_app_request_failed_sum"
    });
    let avalanche_c_handler_app_request_failed_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_app_response_sum"
    });
    let avalanche_c_handler_app_response_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_accepted_frontier_sum"
    });
    let avalanche_c_handler_accepted_frontier_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_accepted_frontier_failed_sum"
    });
    let avalanche_c_handler_get_accepted_frontier_failed_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_accepted_sum"
    });
    let avalanche_c_handler_get_accepted_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_accepted_sum"
    });
    let avalanche_c_handler_accepted_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_accepted_failed_sum"
    });
    let avalanche_c_handler_get_accepted_failed_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_ancestors_sum"
    });
    let avalanche_c_handler_get_ancestors_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_ancestors_sum"
    });
    let avalanche_c_handler_ancestors_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_ancestors_failed_sum"
    });
    let avalanche_c_handler_get_ancestors_failed_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_get_sum");
    let avalanche_c_handler_get_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_put_sum");
    let avalanche_c_handler_put_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_failed_sum"
    });
    let avalanche_c_handler_get_failed_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_push_query_sum"
    });
    let avalanche_c_handler_push_query_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_pull_query_sum"
    });
    let avalanche_c_handler_pull_query_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| s.metric == "avalanche_C_handler_chits_sum");
    let avalanche_c_handler_chits_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_query_failed_sum"
    });
    let avalanche_c_handler_query_failed_sum = Some(mv.value.to_f64());
    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_connected_sum"
    });
    let avalanche_c_handler_connected_sum = Some(mv.value.to_f64());

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_disconnected_sum"
    });
    let avalanche_c_handler_disconnected_sum = Some(mv.value.to_f64());

    Ok(Metrics {
        avalanche_x_db_get_count,
        avalanche_x_whitelist_tx_accepted_count,
        avalanche_x_whitelist_tx_accepted_sum,
        avalanche_x_whitelist_tx_polls_accepted_count,
        avalanche_x_whitelist_tx_polls_accepted_sum,
        avalanche_x_whitelist_tx_polls_rejected_count,
        avalanche_x_whitelist_tx_polls_rejected_sum,
        avalanche_x_whitelist_tx_processing,
        avalanche_x_whitelist_tx_rejected_count,
        avalanche_x_whitelist_tx_rejected_sum,
        avalanche_x_whitelist_vtx_issue_failure,
        avalanche_x_whitelist_vtx_issue_success,

        avalanche_p_db_get_count,

        avalanche_c_db_get_count,
        avalanche_c_handler_get_accepted_frontier_sum,
        avalanche_c_handler_app_gossip_sum,
        avalanche_c_handler_app_request_sum,
        avalanche_c_handler_app_request_failed_sum,
        avalanche_c_handler_app_response_sum,
        avalanche_c_handler_accepted_frontier_sum,
        avalanche_c_handler_get_accepted_frontier_failed_sum,
        avalanche_c_handler_get_accepted_sum,
        avalanche_c_handler_accepted_sum,
        avalanche_c_handler_get_accepted_failed_sum,
        avalanche_c_handler_get_ancestors_sum,
        avalanche_c_handler_ancestors_sum,
        avalanche_c_handler_get_ancestors_failed_sum,
        avalanche_c_handler_get_sum,
        avalanche_c_handler_put_sum,
        avalanche_c_handler_get_failed_sum,
        avalanche_c_handler_push_query_sum,
        avalanche_c_handler_pull_query_sum,
        avalanche_c_handler_chits_sum,
        avalanche_c_handler_query_failed_sum,
        avalanche_c_handler_connected_sum,
        avalanche_c_handler_disconnected_sum,
    })
}
