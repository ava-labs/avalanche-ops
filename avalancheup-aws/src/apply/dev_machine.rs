use std::fs;
use std::io::{self, stdout, Error, ErrorKind, Write};
/// Module for extracting and running dev machine scripts on startup
/// Users provide a path to a directory containing multiple scripts, to execute.
/// Scripts are executed in lexicographical order.
/// Scripts should be placed at the top level without any subdirectories.
use std::path::PathBuf;
use std::process::Command;

/// Parses the user-provided path to a directory containing scripts for the dev machine to execute.
#[allow(dead_code)]
pub fn parse_path(provided_path: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut out_vec: Vec<PathBuf> = Vec::new();

    if !provided_path.exists() {
        return Err(Error::new(ErrorKind::NotFound, "{provided_path} not found"));
    }
    if provided_path.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "{provided_path} is a file, not a directory",
        ));
    }

    // sort the entries in the directory lexicographically
    let mut entries = fs::read_dir(provided_path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort();

    // return the paths to a series of files in the directory
    for entry in entries {
        if entry.is_file() {
            out_vec.push(entry);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "{provided_path} should only contain files, not directories",
            ));
        }
    }

    Ok(out_vec)
}

#[allow(dead_code)]
pub fn execute_script(scripts: Vec<PathBuf>) -> Result<(), Error> {
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

mod test {

    #[test]
    fn test_parse_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("my-script.sh");
        let _ = std::fs::File::create(file_path).unwrap();

        let scripts_dir = std::path::PathBuf::from(dir.path());
        let result = super::parse_path(scripts_dir.clone());
        assert!(result.is_ok());

        // create subdirectory and try again (error)
        let sub_dir = dir.path().join("subdir");
        std::fs::DirBuilder::new().create(sub_dir).unwrap();
        let result = super::parse_path(scripts_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_sorting() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("00_my-script.sh");
        let _ = std::fs::File::create(file_path).unwrap();
        let file_path = dir.path().join("01_my-script.sh");
        let _ = std::fs::File::create(file_path).unwrap();
        let file_path = dir.path().join("02_my-script.sh");
        let _ = std::fs::File::create(file_path).unwrap();

        let scripts_dir = std::path::PathBuf::from(dir.path());
        let result = super::parse_path(scripts_dir).unwrap();
        assert_eq!(result[0], dir.path().join("00_my-script.sh"));
        assert_eq!(result[1], dir.path().join("01_my-script.sh"));
        assert_eq!(result[2], dir.path().join("02_my-script.sh"));
    }
}
