use std::{
    fs::File,
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use log::info;
use serde::{Deserialize, Serialize};

use avalanche_ops::{aws_sts, network};

/// Represents the current status of the network.
/// Used for "apply" and "delete".
/// "Clone" is for deep-copying.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Status {
    /// Network-level configuration.
    pub config: network::Config,

    /// AWS STS caller loaded from its local environment.
    pub identity: aws_sts::Identity,

    /// KMS CMK ID to encrypt resources.
    /// None if not created yet.
    pub kms_cmk_id: Option<String>,

    /// EC2 key pair name for SSH access to EC2 instances.
    pub ec2_key_name: String,

    /// CloudFormation stack name for EC2 instance role.
    pub cloudformation_ec2_instance_role: String,

    /// CloudFormation stack name for VPC.
    pub cloudformation_vpc: String,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for beacon nodes.
    /// None if mainnet.
    pub cloudformation_asg_beacon_nodes: Option<String>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for non-beacon nodes.
    pub cloudformation_asg_non_beacon_nodes: String,
}

impl Status {
    /// Creates a default Status based on configuration.
    pub fn default(config: &network::Config, identity: &aws_sts::Identity) -> Self {
        let id = config.id.clone();

        let ec2_key_name = format!("{}-ec2-key", id);
        let cloudformation_ec2_instance_role = format!("{}-ec2-instance-role", id);
        let cloudformation_vpc = format!("{}-vpc", id);
        let mut cloudformation_asg_beacon_nodes = Some(format!("{}-asg-beacon-nodes", id));
        if config.is_mainnet() {
            cloudformation_asg_beacon_nodes = None
        }
        let cloudformation_asg_non_beacon_nodes = format!("{}-asg-non-beacon-nodes", id);

        Self {
            config: config.clone(),
            identity: identity.clone(),
            kms_cmk_id: None, // not created yet
            ec2_key_name,
            cloudformation_ec2_instance_role,
            cloudformation_vpc,
            cloudformation_asg_beacon_nodes,
            cloudformation_asg_non_beacon_nodes,
        }
    }

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
    info!("loading status from {}", file_path);

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
        identity: aws_sts::Identity {
            account_id: String::from(""),
            role_arn: String::from(""),
            user_id: String::from(""),
        },
        kms_cmk_id: Some(String::from("")),
        ec2_key_name: String::from(""),
        cloudformation_ec2_instance_role: String::from(""),
        cloudformation_vpc: String::from(""),
        cloudformation_asg_beacon_nodes: Some(String::from("")),
        cloudformation_asg_non_beacon_nodes: String::from(""),
    };

    let ret = status.sync(p);
    assert!(ret.is_ok());
}
