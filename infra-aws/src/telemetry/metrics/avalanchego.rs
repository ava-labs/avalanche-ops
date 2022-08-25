use std::sync::Arc;

use aws_manager::cloudwatch;
use aws_sdk_cloudwatch::{
    model::{Dimension, MetricDatum, StandardUnit},
    types::DateTime as SmithyDateTime,
};
use chrono::Utc;
use rust_embed::RustEmbed;
use tokio::time::{sleep, Duration};

pub fn default_rules() -> prometheus_manager::Rules {
    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let filters_raw = Asset::get("artifacts/default.metrics.filters.yaml").unwrap();
    let filters_raw = std::str::from_utf8(filters_raw.data.as_ref()).unwrap();
    serde_yaml::from_str(filters_raw).unwrap()
}

/// Periodically collects the "avalanchego" metrics
/// and uploads them to cloudwatch.
pub async fn fetch_loop(
    cloudwatch_manager: Arc<cloudwatch::Manager>,
    cloudwatch_namespace: Arc<String>,

    initial_wait: Duration,
    interval: Duration,

    avalanchego_rpc_endpoint: Arc<String>,
    metrics_rules: Arc<prometheus_manager::Rules>,
) {
    log::info!(
        "fetching AvalancheGo metrics with initial wait {:?}",
        initial_wait
    );
    sleep(initial_wait).await;

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
        let cur_metrics = match prometheus_manager::match_all_by_rules(
            &s.metrics,
            metrics_rules.as_ref().clone(),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed match_all_by_rules {}, retrying...", e);
                continue;
            }
        };

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
