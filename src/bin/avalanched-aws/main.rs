use clap::Command;

mod backup;
mod run;

const NAME: &str = "avalanched-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(NAME)
        .about("avalanched on AWS")
        .long_about("Avalanche agent (daemon) on AWS")
        .subcommands(vec![run::command(), backup::command()])
        .get_matches();

    match matches.subcommand() {
        Some((run::NAME, sub_matches)) => {
            let log_lvl = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            run::execute(log_lvl).await;
        }

        Some((backup::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((backup::download::NAME, sub_sub_matches)) => {
                let log_lvl = sub_sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
                backup::download::execute(
                    sub_sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                    log_lvl,
                    sub_sub_matches
                        .value_of("UNARCHIVE_DECOMPRESSION_METHOD")
                        .unwrap(),
                    sub_sub_matches.value_of("S3_BUCKET").unwrap(),
                    sub_sub_matches.value_of("S3_KEY").unwrap(),
                    sub_sub_matches.value_of("UNPACK_DIR").unwrap(),
                )
                .unwrap();
            }

            Some((backup::upload::NAME, sub_sub_matches)) => {
                let log_lvl = sub_sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
                backup::upload::execute(
                    sub_sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                    log_lvl,
                    sub_sub_matches
                        .value_of("ARCHIVE_COMPRESSION_METHOD")
                        .unwrap(),
                    sub_sub_matches.value_of("PACK_DIR").unwrap(),
                    sub_sub_matches.value_of("S3_BUCKET").unwrap(),
                    sub_sub_matches.value_of("S3_KEY").unwrap(),
                )
                .unwrap();
            }

            _ => unreachable!("unknown sub-subcommand"),
        },

        _ => unreachable!("unknown subcommand"),
    }
}
