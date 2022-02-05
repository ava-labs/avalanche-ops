use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use log::info;
use serde::{Deserialize, Serialize};

use avalanche_ops::network;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Status {
    pub config: network::Config,
}

impl Status {
    /// Converts to string.
    pub fn to_string(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current status to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing status to '{}'", file_path);
        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Config to YAML {}", e),
                ));
            }
        };

        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

pub fn load_status(file_path: &str) -> io::Result<Status> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("file {} does not exists", file_path),
        ));
    }

    let f = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            ));
        }
    };
    serde_yaml::from_reader(f).map_err(|e| {
        return Error::new(ErrorKind::InvalidInput, format!("invalid JSON: {}", e));
    })
}

#[test]
fn test_status() {
    let _ = env_logger::builder().is_test(true).try_init();

    let f = tempfile::NamedTempFile::new().unwrap();
    let p = f.path().to_str().unwrap();

    let status = Status {
        config: network::Config::default("fuji"),
    };

    let ret = status.sync(p);
    assert!(ret.is_ok());
}
