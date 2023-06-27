//! Module for extracting and running dev machine scripts on startup.
use std::io::{stdout, Error, ErrorKind, Write};
use std::path::PathBuf;
use std::process::Command;

/// Parses the user-provided path to a script for the dev machine to execute.
#[allow(dead_code)]
pub fn parse_path(provided_path: PathBuf) -> Result<PathBuf, Error> {
    if !provided_path.exists() {
        return Err(Error::new(ErrorKind::NotFound, "{provided_path} not found"));
    }
    if !provided_path.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "{provided_path} is not a file",
        ));
    }

    Ok(provided_path)
}

#[allow(dead_code)]
pub fn execute_script(script: PathBuf) -> Result<(), Error> {
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

    Ok(())
}

mod test {

    #[test]
    fn test_parse_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("my-script.sh");
        let _ = std::fs::File::create(file_path.clone()).unwrap();

        let result = super::parse_path(file_path);
        assert!(result.is_ok());

        // create subdirectory and try again (error)
        let result = super::parse_path(dir.path().to_path_buf());
        assert!(result.is_err());
    }
}
