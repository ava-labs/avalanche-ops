use std::io::{stdout, Error, ErrorKind, Write};
/// Module for extracting and running dev machine scripts on startup
/// Users can provide a path to a script file, or a directory containing multiple scripts, to execute.
/// Note: scripts must be written in bash with a bash shebang included.
/// Note: scripts must ensure that the network is up and running before executing(polling the liveness API for example).
use std::path::Path;
use std::process::Command;

/// Parses the user-provided path to an script or a directory containing scripts for the dev machine to execute.
#[allow(dead_code)]
pub fn parse_path(provided_path: Option<Box<Path>>) -> Result<Option<Vec<Box<Path>>>, Error> {
    if provided_path.is_none() {
        return Ok(None);
    }

    let mut out_vec: Vec<Box<Path>> = Vec::new();

    if let Some(path) = provided_path {
        if !path.exists() {
            return Err(Error::new(ErrorKind::NotFound, "{path} not found"));
        }
        if path.is_file() {
            // return the path to the file
            out_vec.push(path);
        } else if path.is_dir() {
            // return the paths to a series of files in the directory
            todo!();
        }
    }
    Ok(Some(out_vec))
}

#[allow(dead_code)]
pub fn execute_script(scripts: Vec<Box<Path>>) -> Result<(), Error> {
    for script in scripts {
        let output = Command::new("/bin/sh")
            .arg("-C")
            .arg(script.as_os_str())
            .output()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("{:?} script failed to execute: {e}", script.as_os_str()),
                )
            })?;

        stdout().write_all(&output.stdout).unwrap();
    }

    Ok(())
}
