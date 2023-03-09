use std::io::{self, Error, ErrorKind};

use rust_embed::RustEmbed;

pub fn asg_ubuntu_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/aws/cfn-templates/asg_ubuntu.yaml").unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}

pub fn ec2_instance_role_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/aws/cfn-templates/ec2_instance_role.yaml").unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}

pub fn ssm_doc_restart_node_chain_config_subnet_evm_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/aws/cfn-templates/ssm_doc_restart_node_chain_config_subnet_evm.yaml")
        .unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}

pub fn ssm_doc_restart_node_tracked_subnet_subnet_evm_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/aws/cfn-templates/ssm_doc_restart_node_tracked_subnet_subnet_evm.yaml")
        .unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}

pub fn ssm_doc_restart_node_tracked_subnet_xsvm_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f =
        Asset::get("src/aws/cfn-templates/ssm_doc_restart_node_tracked_subnet_xsvm.yaml").unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}

pub fn vpc_yaml() -> io::Result<String> {
    #[derive(RustEmbed)]
    #[folder = "src/aws/cfn-templates/"]
    #[prefix = "src/aws/cfn-templates/"]
    struct Asset;
    let f = Asset::get("src/aws/cfn-templates/vpc.yaml").unwrap();
    let s = std::str::from_utf8(f.data.as_ref()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("failed to convert embed file to str {}", e),
        )
    })?;
    Ok(s.to_string())
}
