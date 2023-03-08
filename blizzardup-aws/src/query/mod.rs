use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
};

use avalanche_types::utils;
use clap::{Arg, Command};
use lazy_static::lazy_static;
use regex::RegexSet;
use reqwest::ClientBuilder;
use tokio::time::{sleep, Duration};

pub const NAME: &str = "query";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Queries test progress")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
                .required(true)
                .num_args(1),
        )
}

pub async fn execute(log_level: &str, spec_file_path: &str) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = blizzardup_aws::Spec::load(spec_file_path).expect("failed to load spec");
    log::info!("querying {:?} endpoints", spec.blizzard_spec.chain_rpc_urls);

    lazy_static! {
        static ref REGEXES: Vec<String> = vec![
            r"^avalanche_(C|(([0-9a-zA-Z]+)+){40,})_last_accepted_(height|timestamp)$".to_string(),
            r"^avalanche_(C|(([0-9a-zA-Z]+)+){40,})_vm_eth_chain_txs_accepted$".to_string(),
        ];
    }
    let rset = RegexSet::new(REGEXES.to_vec()).unwrap();

    // map from "http_rpc" to its previous metrics
    let mut prev: HashMap<String, HashMap<String, f64>> = HashMap::new();

    // TODO: implement better math...
    loop {
        for rpc_ep in spec.blizzard_spec.chain_rpc_urls.iter() {
            let (scheme, host, port, _, _) =
                utils::urls::extract_scheme_host_port_path_chain_alias(rpc_ep)?;
            let u = if let Some(scheme) = scheme {
                if let Some(port) = port {
                    format!("{scheme}://{host}:{port}/ext/metrics")
                } else {
                    format!("{scheme}://{host}/ext/metrics")
                }
            } else {
                format!("http://{host}/ext/metrics")
            };

            let req_cli_builder = ClientBuilder::new()
                .user_agent(env!("CARGO_PKG_NAME"))
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(15))
                .connection_verbose(true)
                .build()
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("failed ClientBuilder build {}", e),
                    )
                })?;
            let resp = req_cli_builder.get(&u).send().await.map_err(|e| {
                Error::new(ErrorKind::Other, format!("failed ClientBuilder send {}", e))
            })?;
            let out = resp.bytes().await.map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed ClientBuilder bytes {}", e),
                )
            })?;
            let out: Vec<u8> = out.into();

            let s = match prometheus_manager::Scrape::from_bytes(&out) {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, format!("failed scrape {}", e)));
                }
            };

            let matched = prometheus_manager::match_all_by_regex_set(&s.metrics, rset.clone());
            let mut cur_data: HashMap<String, f64> = HashMap::new();
            for m in matched {
                cur_data.insert(m.metric.clone(), m.value.to_f64());
            }

            if let Some(prev_data) = prev.get(&u) {
                // previous data found, compute delta
                let (mut prev_height_c, mut cur_height_c) = (0_f64, 0_f64);
                let (mut prev_timestamp_c, mut cur_timestamp_c) = (0_f64, 0_f64);
                let (mut prev_tx_accepted_c, mut cur_tx_accepted_c) = (0_f64, 0_f64);

                let (mut prev_height_subnet_evm, mut cur_height_subnet_evm) = (0_f64, 0_f64);
                let (mut prev_timestamp_subnet_evm, mut cur_timestamp_subnet_evm) = (0_f64, 0_f64);
                let (mut prev_tx_accepted_subnet_evm, mut cur_tx_accepted_subnet_evm) =
                    (0_f64, 0_f64);

                for (k, v) in prev_data.iter() {
                    if k.contains("avalanche_C_") {
                        if k.ends_with("last_accepted_height") {
                            prev_height_c = *v;
                        } else if k.ends_with("last_accepted_timestamp") {
                            prev_timestamp_c = *v;
                        } else if k.ends_with("vm_eth_chain_txs_accepted") {
                            prev_tx_accepted_c = *v;
                        }
                        continue;
                    }
                    if k.ends_with("last_accepted_height") {
                        prev_height_subnet_evm = *v;
                    } else if k.ends_with("last_accepted_timestamp") {
                        prev_timestamp_subnet_evm = *v;
                    } else if k.ends_with("vm_eth_chain_txs_accepted") {
                        prev_tx_accepted_subnet_evm = *v;
                    }
                }
                for (k, v) in cur_data.iter() {
                    if k.contains("avalanche_C_") {
                        if k.ends_with("last_accepted_height") {
                            cur_height_c = *v;
                        } else if k.ends_with("last_accepted_timestamp") {
                            cur_timestamp_c = *v;
                        } else if k.ends_with("vm_eth_chain_txs_accepted") {
                            cur_tx_accepted_c = *v;
                        }
                        continue;
                    }
                    if k.ends_with("last_accepted_height") {
                        cur_height_subnet_evm = *v;
                    } else if k.ends_with("last_accepted_timestamp") {
                        cur_timestamp_subnet_evm = *v;
                    } else if k.ends_with("vm_eth_chain_txs_accepted") {
                        cur_tx_accepted_subnet_evm = *v;
                    }
                }

                log::info!(
                    "c: previous height {}, current height {}",
                    prev_height_c,
                    cur_height_c
                );
                log::info!(
                    "c: previous timestamp {}, current timestamp {}",
                    prev_timestamp_c,
                    cur_timestamp_c
                );
                let tps_c = if (cur_timestamp_c > prev_timestamp_c)
                    && (cur_tx_accepted_c > prev_tx_accepted_c)
                {
                    let second_delta = cur_timestamp_c - prev_timestamp_c;
                    let tx_delta = cur_tx_accepted_c - prev_tx_accepted_c;
                    tx_delta / second_delta
                } else {
                    0_f64
                };
                log::info!(
                    "c: previous tx_accepted {}, current tx_accepted {} (TPS {})",
                    prev_tx_accepted_c,
                    cur_tx_accepted_c,
                    tps_c,
                );

                log::info!(
                    "subnet-evm: previous height {}, current height {}",
                    prev_height_subnet_evm,
                    cur_height_subnet_evm
                );
                log::info!(
                    "subnet-evm: previous timestamp {}, current timestamp {}",
                    prev_timestamp_subnet_evm,
                    cur_timestamp_subnet_evm
                );
                let tps_subnet_evm = if (cur_timestamp_subnet_evm > prev_timestamp_subnet_evm)
                    && (cur_tx_accepted_subnet_evm > prev_tx_accepted_subnet_evm)
                {
                    let second_delta = cur_timestamp_subnet_evm - prev_timestamp_subnet_evm;
                    let tx_delta = cur_tx_accepted_subnet_evm - prev_tx_accepted_subnet_evm;
                    tx_delta / second_delta
                } else {
                    0_f64
                };
                log::info!(
                    "subnet-evm: previous tx_accepted {}, current tx_accepted {} (TPS {})",
                    prev_tx_accepted_subnet_evm,
                    cur_tx_accepted_subnet_evm,
                    tps_subnet_evm,
                );
            } else {
                log::info!("previous data empty -- first try...")
            }

            // done with comparison so update for next iteration
            prev.insert(u.clone(), cur_data);

            sleep(Duration::from_secs(20)).await;
        }

        break;
    }

    Ok(())
}
