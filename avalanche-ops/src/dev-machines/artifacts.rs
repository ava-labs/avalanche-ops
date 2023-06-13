use std::io::{self, Error, ErrorKind};

use rust_embed::RustEmbed;

pub fn asg_ubuntu_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/dev-machines/cfn-templates/"]
    #[prefix = "src/dev-machines/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/dev-machines/cfn-templates/asg_ubuntu.yaml").unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}
