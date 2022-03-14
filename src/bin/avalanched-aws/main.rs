use clap::Command;

mod download_backup;
mod run;
mod upload_backup;

const NAME: &str = "avalanched-aws";

fn main() {
    let matches = Command::new(NAME)
        .about("Avalanche agent (daemon) on AWS")
        .subcommands(vec![
            run::command(),
            upload_backup::command(),
            download_backup::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((run::NAME, sub_matches)) => {
            run::execute(sub_matches.value_of("LOG_LEVEL").unwrap_or("info")).unwrap();
        }

        Some((upload_backup::NAME, sub_matches)) => {
            upload_backup::execute(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
                sub_matches.value_of("ARCHIVE_COMPRESSION_METHOD").unwrap(),
                sub_matches.value_of("PACK_DIR").unwrap(),
                sub_matches.value_of("S3_BUCKET").unwrap(),
                sub_matches.value_of("S3_KEY").unwrap(),
            )
            .unwrap();
        }

        Some((download_backup::NAME, sub_matches)) => {
            download_backup::execute(
                sub_matches.value_of("REGION").unwrap_or("us-west-2"),
                sub_matches.value_of("LOG_LEVEL").unwrap_or("info"),
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
