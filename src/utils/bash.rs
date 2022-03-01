use std::{
    io::{self, Error, ErrorKind},
    process::Command,
    string::String,
};

use log::{info, warn};

/// Runs bash command(s) and returns the result.
#[allow(dead_code)]
pub fn run(cmd: &str) -> io::Result<(String, String)> {
    info!("running {}", cmd);
    match Command::new("sh").args(&["-c", cmd]).output() {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).as_ref().to_owned();
            let stderr = String::from_utf8_lossy(&o.stderr).as_ref().to_owned();
            if o.status.success() {
                info!("command run success");
                Ok((stdout, stderr))
            } else {
                match o.status.code() {
                    Some(code) => {
                        warn!("command failed with status code {}: {}", code, stderr);
                        Err(Error::new(
                            ErrorKind::Other,
                            format!("command failed with status code {}: {}", code, stderr),
                        ))
                    }
                    None => {
                        warn!(
                            "command terminated by signal with no status code: {}",
                            stderr
                        );
                        Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "command terminated by signal with no status code: {}",
                                stderr
                            ),
                        ))
                    }
                }
            }
        }
        Err(e) => {
            warn!("command failed: {}", e);
            Err(e)
        }
    }
}

#[test]
fn test_bash_run() {
    let ret = run("ls -lah .");
    assert!(ret.is_ok());
    let t = ret.unwrap();
    println!("stdout:\n{}", t.0);
    println!("stderr:\n{}", t.1);
}
