use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, stdout},
};

use avalanche_types::{ids, jsonrpc};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use serde::{Deserialize, Serialize};

pub const NAME: &str = "endpoints";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Queries RPC endpoints")
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
            Arg::new("CHAIN_RPC_URLS")
                .long("chain-rpc-urls")
                .help("Comma-separated chain RPC URLs")
                .required(false)
                .num_args(1)
                .default_value("http://localhost:9650/ext/C/rpc"),
        )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Peer {
    pub http_rpc: String,

    #[serde(flatten)]
    pub peer: jsonrpc::info::Peer,
}

pub async fn execute(log_level: &str, chain_rpc_urls: Vec<String>) -> io::Result<()> {
    // ref. <https://github.com/env-logger-rs/env_logger/issues/47>
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut all_nodes_set = BTreeSet::new();
    let mut all_blockchains: BTreeSet<jsonrpc::platformvm::Blockchain> = BTreeSet::new();
    for u in chain_rpc_urls.iter() {
        let resp = jsonrpc::client::info::get_node_id(u).await?;
        log::info!(
            "chain rpc url '{u}' node id: {}",
            serde_json::to_string_pretty(&resp).unwrap()
        );
        all_nodes_set.insert(resp.result.unwrap().node_id);

        let resp = jsonrpc::client::p::get_blockchains(u).await?;
        log::info!(
            "blockchains at '{u}': {}",
            serde_json::to_string_pretty(&resp).unwrap()
        );
        if let Some(rs) = &resp.result {
            if let Some(bs) = &rs.blockchains {
                for b in bs.iter() {
                    all_blockchains.insert(b.clone());
                }
            }
        }
    }
    let mut all_node_ids = Vec::new();
    for n in all_nodes_set.iter() {
        all_node_ids.push(n.clone());
    }

    let mut node_id_to_peer: BTreeMap<ids::node::Id, Peer> = BTreeMap::new();
    let mut tracked_subnet_id_to_node_ids: BTreeMap<ids::Id, BTreeSet<ids::node::Id>> =
        BTreeMap::new();
    for u in chain_rpc_urls.iter() {
        let resp = jsonrpc::client::info::peers(u, Some(all_node_ids.clone())).await?;
        log::info!(
            "peers at '{u}': {}",
            serde_json::to_string_pretty(&resp).unwrap()
        );

        if let Some(rs) = &resp.result {
            if let Some(ps) = &rs.peers {
                for p in ps.iter() {
                    if !all_nodes_set.contains(&p.node_id) {
                        continue;
                    }

                    node_id_to_peer.insert(
                        p.node_id.clone(),
                        Peer {
                            http_rpc: format!("http://{}:9650", p.ip.to_string()),

                            peer: p.clone(),
                        },
                    );

                    for tracked_subnet_id in &p.tracked_subnets {
                        if let Some(v) = tracked_subnet_id_to_node_ids.get_mut(tracked_subnet_id) {
                            v.insert(p.node_id.clone());
                            continue;
                        }

                        let mut ss = BTreeSet::new();
                        ss.insert(p.node_id.clone());
                        tracked_subnet_id_to_node_ids.insert(tracked_subnet_id.clone(), ss);
                    }
                }
            }
        }
    }

    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nALL TRACKED SUBNETS\n"),
        ResetColor
    )?;
    for p in tracked_subnet_id_to_node_ids.iter() {
        println!();
        println!("subnet id '{}' are tracked by", p.0);
        for node_id in p.1.iter() {
            println!("{}", node_id);
        }
    }

    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nALL PEERS\n"),
        ResetColor
    )?;
    for p in node_id_to_peer.iter() {
        println!();
        println!("{}:\n{}", p.0, serde_yaml::to_string(&p.1).unwrap());
    }

    println!();
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nALL BLOCKCHAINS\n"),
        ResetColor
    )?;
    for blkc in all_blockchains.iter() {
        println!("{}", serde_yaml::to_string(blkc).unwrap());
    }

    Ok(())
}
