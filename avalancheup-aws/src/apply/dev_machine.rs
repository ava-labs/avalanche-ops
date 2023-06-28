//! Module for dev machine specific functionality.
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

/// Parses the user-provided path to a script for the dev machine to execute.
pub fn validate_path(provided_path: PathBuf) -> Result<PathBuf, Error> {
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

mod test {

    #[test]
    fn test_parse_path() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("my-script.sh");
        let _ = std::fs::File::create(file_path.clone()).unwrap();

        let result = super::validate_path(file_path);
        assert!(result.is_ok());

        // create subdirectory and try again (error)
        let result = super::validate_path(dir.path().to_path_buf());
        assert!(result.is_err());
    }
}
