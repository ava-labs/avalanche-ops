use std::io;

use avalanche_api::{c, p, x};
use clap::{Arg, Command};
use tokio::runtime::Runtime;

pub const NAME: &str = "check-balances";

pub fn command() -> Command<'static> {
    Command::new(NAME)
        .about("Reads the spec file and outputs all the balances for the generated keys")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

/*
curl -X POST --data '{
  "jsonrpc":"2.0",
  "id"     : 1,
  "method" :"avm.getBalance",
  "params" :{
      "address":"X-[ADDRESS]",
      "assetID": "AVAX"
  }
}' -H 'content-type:application/json;' [HTTP_RPC_ENDPOINT]/ext/bc/X

curl -X POST --data '{
  "jsonrpc":"2.0",
  "id"     : 1,
  "method" :"platform.getBalance",
  "params" :{
      "address":"P-[ADDRESS]"
  }
}' -H 'content-type:application/json;' [HTTP_RPC_ENDPOINT]/ext/bc/P


curl --location --request POST [HTTP_RPC_ENDPOINT]/ext/bc/C/rpc \
--header 'Content-Type: application/json' \
--data-raw '{
    "jsonrpc": "2.0",
    "method": "eth_getBalance",
    "params": [
        "0x[ADDRESS]",
        "latest"
    ],
    "id": 1
}'
*/

pub fn execute(log_level: &str, spec_file_path: &str) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let spec = avalancheup_aws::Spec::load(spec_file_path).expect("failed to load spec");
    let eps = spec.endpoints.expect("unexpected None endpoints");
    let http_rpc = eps.http_rpc.expect("unexpected None http_rpc");

    let mut keys = vec![spec
        .generated_seed_private_key_with_locked_p_chain_balance
        .expect("unexpected None generated_seed_private_key_with_locked_p_chain_balance")];
    let generated_keys = spec
        .generated_seed_private_keys
        .expect("unexpected None generated_seed_private_keys");
    for k in generated_keys.iter() {
        keys.push(k.clone());
    }

    let network_id = {
        if spec.avalanchego_genesis_template.is_some() {
            spec.avalanchego_genesis_template.unwrap().network_id
        } else {
            1
        }
    };

    println!();
    let rt = Runtime::new().unwrap();
    for k in keys.iter() {
        let (xaddr, paddr, caddr) = {
            (
                k.addresses
                    .get(&format!("{}", network_id))
                    .unwrap()
                    .x_address
                    .clone(),
                k.addresses
                    .get(&format!("{}", network_id))
                    .unwrap()
                    .p_address
                    .clone(),
                k.eth_address.clone(),
            )
        };
        let (xb, pb, cb) = {
            let x = rt
                .block_on(x::get_balance(&http_rpc, &xaddr))
                .expect("failed x::get_balance");
            let x = x.result.expect("unexpected None x result");
            let x = x.balance;

            let p = rt
                .block_on(p::get_balance(&http_rpc, &paddr))
                .expect("failed p::get_balance");
            let p = p.result.expect("unexpected None p result");
            let p = p.balance.expect("unexpected None p result balance");

            let c = rt
                .block_on(c::get_balance(&http_rpc, &caddr))
                .expect("failed c::get_balance");
            let c = c.result;

            (x, p, c)
        };
        println!("{}: {}", xaddr, xb);
        println!("{}: {}", paddr, pb);
        println!("{}: {}", caddr, cb);
        println!();
    }

    Ok(())
}
