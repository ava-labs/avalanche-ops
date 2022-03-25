use clap::Command;

mod get_utxos;
mod vm_id;

const APP_NAME: &str = "subnetctl";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .about("subnetctl (experimental subnet-cli)")
        .long_about(
            "
e.g.,
subnetctl vm-id --name subnet-evm

See https://github.com/ava-labs/subnet-cli.

",
        )
        .subcommands(vec![vm_id::command(), get_utxos::command()])
        .get_matches();

    match matches.subcommand() {
        Some((vm_id::NAME, sub_matches)) => {
            let opt = vm_id::Option {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                name: sub_matches.value_of("NAME").unwrap_or("").to_string(),
            };
            vm_id::execute(opt).unwrap();
        }

        Some((get_utxos::NAME, sub_matches)) => {
            let opt = get_utxos::Option {
                log_level: sub_matches
                    .value_of("LOG_LEVEL")
                    .unwrap_or("info")
                    .to_string(),
                http_rpc_ep: sub_matches
                    .value_of("HTTP_RPC_ENDPOINT")
                    .unwrap_or("")
                    .to_string(),
                paddr: sub_matches
                    .value_of("P_CHAIN_ADDRESS")
                    .unwrap_or("")
                    .to_string(),
            };
            get_utxos::execute(opt).unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
