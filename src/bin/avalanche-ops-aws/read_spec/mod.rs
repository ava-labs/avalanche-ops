use std::io;

use clap::{Arg, Command};

pub const NAME: &str = "read-spec";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Reads the spec file and outputs the selected fields based on 'current_nodes' field")
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("INSTANCE_IDS")
                .long("instance-ids")
                .short('i')
                .help("Set to get instance IDs (comma-separated)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("PUBLIC_IPS")
                .long("public-ips")
                .short('p')
                .help("Set to get public IPs (comma-separated)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("NLB_ENDPOINT")
                .long("nlb-endpoint")
                .short('n')
                .help("Set to get NLB endpoint")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("HTTP_ENDPOINTS")
                .long("http-endpoints")
                .help("Set to get HTTP endpoints (comma-separated)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("NODE_IDS")
                .long("node-ids")
                .help("Set to get all node IDs (comma-separated)")
                .required(false)
                .takes_value(false)
                .allow_invalid_utf8(false),
        )
}

pub fn execute(
    spec_file_path: &str,
    instance_ids: bool,
    public_ips: bool,
    nlb_endpoint: bool,
    http_endpoints: bool,
    node_ids: bool,
) -> io::Result<()> {
    let spec = avalanche_ops::Spec::load(spec_file_path).expect("failed to load spec");
    let current_nodes = spec
        .current_nodes
        .expect("unexpected None current_nodes in spec file");

    if instance_ids {
        let mut rs = Vec::new();
        for node in current_nodes.iter() {
            rs.push(node.machine_id.clone());
        }
        println!("{}", rs.join(","));
    };

    if public_ips {
        let mut rs = Vec::new();
        for node in current_nodes.iter() {
            rs.push(node.public_ip.clone());
        }
        println!("{}", rs.join(","));
    };

    if nlb_endpoint {
        let aws_resources = spec.aws_resources.expect("unexpected None aws_resources");
        let nlb_https_enabled = aws_resources.nlb_acm_certificate_arn.is_some();
        let dns_name = aws_resources.cloudformation_asg_nlb_dns_name.unwrap();
        let (scheme_for_dns, port_for_dns) = {
            if nlb_https_enabled {
                ("https", 443)
            } else {
                ("http", spec.avalanchego_config.http_port)
            }
        };
        println!(
            "{}://{}:{}/ext/metrics",
            scheme_for_dns, dns_name, port_for_dns
        );
    };

    if http_endpoints {
        let mut rs = Vec::new();
        for node in current_nodes.iter() {
            rs.push(node.http_endpoint.clone());
        }
        println!("{}", rs.join(","));
    };

    if node_ids {
        let mut rs = Vec::new();
        for node in current_nodes.iter() {
            rs.push(node.node_id.clone());
        }
        println!("{}", rs.join(","));
    };

    Ok(())
}
