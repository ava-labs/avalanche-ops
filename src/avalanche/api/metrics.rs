use std::{io, process::Command, time::Duration};

use log::info;
use serde::Serialize;

use crate::utils::{http, prometheus};

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct Metrics {
    #[serde(
        rename = "avalanche_C_handler_get_accepted_frontier_sum",
        skip_serializing_if = "Option::is_none"
    )]
    pub avalanche_c_handler_get_accepted_frontier_sum: Option<f64>,
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

    let mv = prometheus::match_metric(&s.metrics, |s| {
        s.metric == "avalanche_C_handler_get_accepted_frontier_sum"
    });
    let avalanche_c_handler_get_accepted_frontier_sum = Some(mv.value.to_f64());

    Ok(Metrics {
        avalanche_c_handler_get_accepted_frontier_sum,
    })
}
