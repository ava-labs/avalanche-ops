use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use avalanche_utils::{system_id, time as atime};
use aws::sts;
use lazy_static::lazy_static;
use log::info;
use serde::{Deserialize, Serialize};

pub const MIN_MACHINES: u32 = 1;
pub const MAX_MACHINES: u32 = 2;

pub const ARCH_AMD64: &str = "amd64";
pub const ARCH_ARM64: &str = "arm64";

pub const OS_AL2: &str = "al2";
pub const OS_AL2_USER_NAME: &str = "ec2-user";

pub const OS_UBUNTU: &str = "ubuntu";
pub const OS_UBUNTU_USER_NAME: &str = "ubuntu";

lazy_static! {
    /// Avalanche consensus paper used "c5.large" for testing 125 ~ 2,000 nodes
    /// Avalanche test net ("fuji") runs "c5.2xlarge"
    ///
    /// https://aws.amazon.com/ec2/instance-types/c6a/
    /// c6a.large:   2  vCPU + 4  GiB RAM
    /// c6a.xlarge:  4  vCPU + 8  GiB RAM
    /// c6a.2xlarge: 8  vCPU + 16 GiB RAM
    /// c6a.4xlarge: 16 vCPU + 32 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m6a/
    /// m6a.large:   2  vCPU + 8  GiB RAM
    /// m6a.xlarge:  4  vCPU + 16 GiB RAM
    /// m6a.2xlarge: 8  vCPU + 32 GiB RAM
    /// m6a.4xlarge: 16 vCPU + 64 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m5/
    /// m5.large:   2 vCPU + 8  GiB RAM
    /// m5.xlarge:  4 vCPU + 16 GiB RAM
    /// m5.2xlarge: 8 vCPU + 32 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/c5/
    /// c5.large:   2 vCPU + 4  GiB RAM
    /// c5.xlarge:  4 vCPU + 8  GiB RAM
    /// c5.2xlarge: 8 vCPU + 16 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/r5/
    /// r5.large:   2 vCPU + 16 GiB RAM
    /// r5.xlarge:  4 vCPU + 32 GiB RAM
    /// r5.2xlarge: 8 vCPU + 64 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/t3/
    /// t3.large:   2 vCPU + 8 GiB RAM
    /// t3.xlarge:  4 vCPU + 16 GiB RAM
    /// t3.2xlarge: 8 vCPU + 32 GiB RAM
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_AMD64: Vec<String> = vec![
        String::from("c6a.4xlarge"),
        String::from("m6a.2xlarge"),
        String::from("m5.2xlarge"),
        String::from("c5.2xlarge"),
    ];

    /// Avalanche consensus paper used "c5.large" for testing 125 ~ 2,000 nodes
    /// Avalanche test net ("fuji") runs "c5.2xlarge"
    ///
    /// Graviton 3 (in preview)
    /// https://aws.amazon.com/ec2/instance-types/c7g/
    /// c7g.large:   2 vCPU + 8  GiB RAM
    /// c7g.xlarge:  4 vCPU + 16 GiB RAM
    /// c7g.2xlarge: 8 vCPU + 32 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/c6g/
    /// c6g.large:   2 vCPU + 4  GiB RAM
    /// c6g.xlarge:  4 vCPU + 8  GiB RAM
    /// c6g.2xlarge: 8 vCPU + 16 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/m6g/
    /// m6g.large:   2 vCPU + 8  GiB RAM
    /// m6g.xlarge:  4 vCPU + 16 GiB RAM
    /// m6g.2xlarge: 8 vCPU + 32 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/r6g/
    /// r6g.large:   2 vCPU + 16 GiB RAM
    /// r6g.xlarge:  4 vCPU + 32 GiB RAM
    /// r6g.2xlarge: 8 vCPU + 64 GiB RAM
    ///
    /// Graviton 2
    /// https://aws.amazon.com/ec2/instance-types/t4/
    /// t4g.large:   2 vCPU + 8 GiB RAM
    /// t4g.xlarge:  4 vCPU + 16 GiB RAM
    /// t4g.2xlarge: 8 vCPU + 32 GiB RAM
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_ARM64: Vec<String> = vec![
        String::from("c6g.2xlarge"),
        String::from("m6g.2xlarge"),
        String::from("r6g.2xlarge"),
        String::from("t4g.2xlarge"),
    ];
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    #[serde(default)]
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_resources: Option<AWSResources>,
    pub machine: Machine,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default)]
    pub machines: u32,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AWSResources {
    #[serde(default)]
    pub region: String,

    #[serde(default)]
    pub bucket: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<sts::Identity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_arn: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_profile_arn: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_security_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_public_subnet_ids: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_logical_id: Option<String>,
}

impl Default for AWSResources {
    fn default() -> Self {
        Self::default()
    }
}

impl AWSResources {
    pub fn default() -> Self {
        Self {
            region: String::from("us-west-2"),
            bucket: String::from(""),

            identity: None,

            kms_cmk_id: None,
            kms_cmk_arn: None,

            ec2_key_name: None,
            ec2_key_path: None,

            cloudformation_ec2_instance_role: None,
            cloudformation_ec2_instance_profile_arn: None,

            cloudformation_vpc: None,
            cloudformation_vpc_id: None,
            cloudformation_vpc_security_group_id: None,
            cloudformation_vpc_public_subnet_ids: None,

            cloudformation_asg: None,
            cloudformation_asg_logical_id: None,
        }
    }
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String),
    Vpc(String),
    Asg(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::Asg(id) => format!("{}-asg", id),
        }
    }
}

impl Spec {
    pub fn default(arch: &str, os: &str) -> io::Result<Self> {
        let instance_types = match arch {
            ARCH_AMD64 => DEFAULT_EC2_INSTANCE_TYPES_AMD64.to_vec(),
            ARCH_ARM64 => DEFAULT_EC2_INSTANCE_TYPES_ARM64.to_vec(),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("arch {} is not supported yet", arch),
                ));
            }
        };

        Ok(Self {
            id: atime::with_prefix("dev-machine"),

            aws_resources: Some(AWSResources {
                region: String::from("us-west-2"),
                bucket: format!(
                    "dev-machine-{}-{}",
                    atime::timestamp(6),
                    system_id::string(7)
                ), // [year][month][date]-[system host-based id]
                ..AWSResources::default()
            }),

            machine: Machine {
                machines: 1,
                arch: arch.to_string(),
                os: os.to_string(),
                instance_types,
            },
        })
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Spec to YAML {}", e),
                ));
            }
        }
    }

    /// Saves the current spec to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Spec to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_vec(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Spec to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading Spec from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(&file_path).map_err(|e| {
            return Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            );
        })?;
        serde_yaml::from_reader(f).map_err(|e| {
            return Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e));
        })
    }

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating Spec");

        if self.id.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "'id' cannot be empty"));
        }

        // some AWS resources have tag limit of 32-character
        if self.id.len() > 28 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'id' length cannot be >28 (got {})", self.id.len()),
            ));
        }

        match &self.aws_resources {
            Some(v) => {
                if v.region.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "'machine.region' cannot be empty",
                    ));
                }
            }
            None => {}
        }

        if self.machine.machines < MIN_MACHINES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.machines' {} <minimum {}",
                    self.machine.machines, MIN_MACHINES
                ),
            ));
        }
        if self.machine.machines > MAX_MACHINES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.machines' {} >maximum {}",
                    self.machine.machines, MAX_MACHINES
                ),
            ));
        }

        Ok(())
    }
}

#[test]
fn test_spec() {
    use avalanche_utils::random;
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random::string(10);
    let bucket = format!("test-{}", atime::timestamp(8));

    let contents = format!(
        r#"

id: {}

aws_resources:
  region: us-west-2
  bucket: {}

machine:
  machines: 1
  arch: arm64
  os: al2
  instance_types:
  - c6g.large


"#,
        id, bucket,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let ret = Spec::load(config_path);
    assert!(ret.is_ok());
    let cfg = ret.unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let orig = Spec {
        id: id.clone(),

        aws_resources: Some(AWSResources {
            region: String::from("us-west-2"),
            bucket: bucket.clone(),
            ..AWSResources::default()
        }),

        machine: Machine {
            arch: ARCH_ARM64.to_string(),
            os: OS_AL2.to_string(),
            machines: 1,
            instance_types: vec![String::from("c6g.large")],
        },
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);

    assert!(cfg.aws_resources.is_some());
    let aws_reesources = cfg.aws_resources.unwrap();
    assert_eq!(aws_reesources.region, "us-west-2");
    assert_eq!(aws_reesources.bucket, bucket);

    assert_eq!(cfg.machine.machines, 1);
    assert_eq!(cfg.machine.arch, ARCH_ARM64);
    assert_eq!(cfg.machine.os, OS_AL2);
    let instance_types = cfg.machine.instance_types;
    assert_eq!(instance_types[0], "c6g.large");
}

/// Represents the S3/storage key path.
/// MUST be kept in sync with "cfn-templates/ec2_instance_role.yaml".
pub enum StorageNamespace {
    DevMachineConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::DevMachineConfigFile(id) => format!("{}/dev-machine.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }
        }
    }
}
