use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
};

use aws_manager::{self, s3};
use tokio::time::{sleep, Duration};

pub async fn download(
    overwrite: bool,
    s3_manager: Arc<s3::Manager>,
    s3_bucket: &str,
    source_bin_s3_path: &str,
    target_bin_path: &str,
) -> io::Result<()> {
    log::info!("downloading binary in bucket {s3_bucket} (overwrite {overwrite})");
    let s3_manager: &s3::Manager = s3_manager.as_ref();

    let mut need_download = !Path::new(target_bin_path).exists();
    if overwrite {
        need_download = true;
    }
    if need_download {
        let tmp_path = random_manager::tmp_path(15, None)?;

        let mut success = false;
        for round in 0..20 {
            log::info!("[ROUND {round}] get_object for {source_bin_s3_path}");

            let res = s3_manager
                .get_object(
                    Arc::new(s3_bucket.to_owned()),
                    Arc::new(source_bin_s3_path.to_owned()),
                    Arc::new(tmp_path.clone()),
                )
                .await;

            if res.is_ok() {
                success = true;
                break;
            }

            let err = res.err().unwrap();
            if err.is_retryable() {
                log::warn!("get_object retriable error: {}", err);
                sleep(Duration::from_secs((round + 1) * 5)).await;
                continue;
            }

            return Err(Error::new(
                ErrorKind::Other,
                format!("get_object failed for non-retriable error {}", err),
            ));
        }
        if !success {
            return Err(Error::new(
                ErrorKind::Other,
                "get_object failed to download with retries",
            ));
        }

        log::info!("successfully downloaded to {tmp_path}");
        {
            let f = File::open(&tmp_path)?;
            f.set_permissions(PermissionsExt::from_mode(0o777))?;
        }
        fs::copy(&tmp_path, &target_bin_path)?;
        fs::remove_file(&tmp_path)?;
    } else {
        log::info!("skipping downloads")
    }

    Ok(())
}
