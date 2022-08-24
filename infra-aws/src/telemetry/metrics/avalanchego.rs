use std::sync::Arc;

use aws_manager::cloudwatch;
use aws_sdk_cloudwatch::{
    model::{Dimension, MetricDatum, StandardUnit},
    types::DateTime as SmithyDateTime,
};
use chrono::Utc;
use regex::RegexSet;
use tokio::time::{sleep, Duration};

/// Periodically collects the "avalanchego" metrics
/// and uploads them to cloudwatch.
pub async fn fetch_loop(
    cloudwatch_manager: Arc<cloudwatch::Manager>,
    cloudwatch_namespace: Arc<String>,

    initial_wait: Duration,
    interval: Duration,

    avalanchego_rpc_endpoint: Arc<String>,
    metrics_regexes: Arc<Vec<String>>,
) {
    log::info!(
        "fetching AvalancheGo metrics with initial wait {:?}",
        initial_wait
    );
    sleep(initial_wait).await;

    let regexes = metrics_regexes.as_ref();
    let regex_set: RegexSet = RegexSet::new(regexes).unwrap();

    let cloudwatch_manager: &cloudwatch::Manager = cloudwatch_manager.as_ref();
    loop {
        log::info!(
            "fetching AvalancheGo metrics in {:?} for {}",
            interval,
            avalanchego_rpc_endpoint
        );
        sleep(interval).await;

        let ts = Utc::now();
        let ts = SmithyDateTime::from_nanos(ts.timestamp_nanos() as i128)
            .expect("failed to convert DateTime<Utc>");

        let rb = match http_manager::get_non_tls(avalanchego_rpc_endpoint.as_str(), "ext/metrics")
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed get_non_tls {}, retrying...", e);
                continue;
            }
        };
        let s = match prometheus_manager::Scrape::from_bytes(&rb) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed scrape {}, retrying...", e);
                continue;
            }
        };
        let cur_metrics = prometheus_manager::match_name_set_all(&s.metrics, regex_set.clone());

        let mut data = vec![];
        for mv in cur_metrics {
            data.push(
                MetricDatum::builder()
                    .metric_name(mv.metric.as_str())
                    .value(mv.value.to_f64())
                    .unit(StandardUnit::Count)
                    .timestamp(ts)
                    .dimensions(
                        Dimension::builder()
                            .name("avalanche-metrics")
                            .value("raw")
                            .build(),
                    )
                    .build(),
            )
        }
        match cloudwatch::spawn_put_metric_data(
            cloudwatch_manager.clone(),
            cloudwatch_namespace.as_str(),
            data,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                log::warn!("failed to put metric data {}, retrying...", e);
                continue;
            }
        }
    }
}
