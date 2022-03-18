use clap::Command;
use tokio;

mod download_backup;
mod run;
mod upload_backup;

const NAME: &str = "avalanched-aws";

#[tokio::main]
async fn main() {
    let matches = Command::new(NAME)
        .about("avalanched on AWS")
        .long_about("Avalanche agent (daemon) on AWS")
        .subcommands(vec![
            run::command(),
            upload_backup::command(),
            download_backup::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((run::NAME, sub_matches)) => {
            let log_lvl = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            run::execute(log_lvl).await;
        }

        Some((upload_backup::NAME, sub_matches)) => {
            let log_lvl = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            upload_backup::execute(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                log_lvl,
                sub_matches.value_of("ARCHIVE_COMPRESSION_METHOD").unwrap(),
                sub_matches.value_of("PACK_DIR").unwrap(),
                sub_matches.value_of("S3_BUCKET").unwrap(),
                sub_matches.value_of("S3_KEY").unwrap(),
            )
            .unwrap();
        }

        Some((download_backup::NAME, sub_matches)) => {
            let log_lvl = sub_matches.value_of("LOG_LEVEL").unwrap_or("info");
            download_backup::execute(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                log_lvl,
                sub_matches
                    .value_of("UNARCHIVE_DECOMPRESSION_METHOD")
                    .unwrap(),
                sub_matches.value_of("S3_BUCKET").unwrap(),
                sub_matches.value_of("S3_KEY").unwrap(),
                sub_matches.value_of("UNPACK_DIR").unwrap(),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
