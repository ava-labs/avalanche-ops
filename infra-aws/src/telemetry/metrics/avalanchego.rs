use std::sync::Arc;

use avalanche_sdk::metrics::{self as api_metrics, cw as api_cw};
use avalanche_types::metrics::avalanchego as avalanchego_metrics;
use aws_manager::cloudwatch;
use tokio::time::{sleep, Duration};

/// Periodically collects the "avalanchego" metrics
/// and uploads them to cloudwatch.
pub async fn fetch_loop(
    cloudwatch_manager: Arc<cloudwatch::Manager>,
    cloudwatch_namespace: Arc<String>,

    initial_wait: Duration,
    interval: Duration,

    avalanchego_rpc_endpoint: Arc<String>,
) {
    log::info!(
        "fetching AvalancheGo metrics with initial wait {:?}",
        initial_wait
    );
    sleep(initial_wait).await;

    let cloudwatch_manager: &cloudwatch::Manager = cloudwatch_manager.as_ref();
    let mut prev_raw_metrics: Option<avalanchego_metrics::RawMetrics> = None;
    loop {
        log::info!("fetching AvalancheGo metrics in {:?}", interval);
        sleep(interval).await;

        let cur_metrics = match api_metrics::spawn_get(&avalanchego_rpc_endpoint).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed to fetch metrics {}, retrying...", e);
                continue;
            }
        };

        match cloudwatch::spawn_put_metric_data(
            cloudwatch_manager.clone(),
            cloudwatch_namespace.as_str(),
            api_cw::convert(&cur_metrics, prev_raw_metrics.clone()),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                log::warn!("failed to put metric data {}, retrying...", e);
                prev_raw_metrics = Some(cur_metrics.clone());
                continue;
            }
        }

        prev_raw_metrics = Some(cur_metrics.clone());
    }
}
