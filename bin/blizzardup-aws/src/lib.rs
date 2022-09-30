mod aws;
pub mod blizzard;

use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use avalanche_types::key::hot;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

/// Default machine nodes size.
pub const DEFAULT_MACHINE_NODES: usize = 2;
pub const MIN_MACHINE_NODES: usize = 1;
pub const MAX_MACHINE_NODES: usize = 10;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    /// User-provided ID of the cluster/test.
    /// This is NOT the avalanche node ID.
    /// This is NOT the avalanche network ID.
    #[serde(default)]
    pub id: String,

    /// AWS resources if run in AWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_resources: Option<aws::Resources>,

    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,
    /// Install artifacts to share with remote machines.
    pub install_artifacts: InstallArtifacts,

    /// Flag to pass to the "blizzard" command-line interface.
    pub blizzard_spec: blizzard::Spec,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_private_key_faucet: Option<hot::PrivateKeyInfoEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_private_keys: Option<Vec<hot::PrivateKeyInfoEntry>>,
}

/// Defines how the underlying infrastructure is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default)]
    pub nodes: usize,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
    #[serde(default)]
    pub use_spot_instance: bool,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct InstallArtifacts {
    /// "blizzard" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/blizzard" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub blizzard_bin: Option<String>,
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String),
    Vpc(String),
    AsgBlizzards(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::AsgBlizzards(id) => format!("{}-asg-blizzards", id),
        }
    }
}

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,

    pub key_files_dir: String,
    pub keys_to_generate: usize,

    pub region: String,
    pub use_spot_instance: bool,

    pub network_id: u32,
    pub nodes: usize,

    pub install_artifacts_blizzard_bin: String,
    pub blizzard_log_level: String,
    pub blizzard_metrics_push_interval_seconds: u64,
    pub blizzard_http_rpcs: Vec<String>,
    pub blizzard_subnet_evm_blockchain_id: Option<String>,

    pub spec_file_path: String,
}

pub const ARCH_AMD64: &str = "amd64";
pub const ARCH_ARM64: &str = "arm64";

lazy_static! {
    /// https://aws.amazon.com/ec2/instance-types/c6a/
    /// c6a.large:   2  vCPU + 4  GiB RAM
    /// c6a.xlarge:  4  vCPU + 8  GiB RAM
    /// c6a.2xlarge: 8  vCPU + 16 GiB RAM
    /// c6a.4xlarge: 16 vCPU + 32 GiB RAM
    /// c6a.8xlarge: 32 vCPU + 64 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m6a/
    /// m6a.large:   2  vCPU + 8  GiB RAM
    /// m6a.xlarge:  4  vCPU + 16 GiB RAM
    /// m6a.2xlarge: 8  vCPU + 32 GiB RAM
    /// m6a.4xlarge: 16 vCPU + 64 GiB RAM
    /// m6a.8xlarge: 32 vCPU + 128 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/m5/
    /// m5.large:   2  vCPU + 8  GiB RAM
    /// m5.xlarge:  4  vCPU + 16 GiB RAM
    /// m5.2xlarge: 8  vCPU + 32 GiB RAM
    /// m5.4xlarge: 16 vCPU + 64 GiB RAM
    /// m5.8xlarge: 32 vCPU + 128 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/c5/
    /// c5.large:   2  vCPU + 4  GiB RAM
    /// c5.xlarge:  4  vCPU + 8  GiB RAM
    /// c5.2xlarge: 8  vCPU + 16 GiB RAM
    /// c5.4xlarge: 16 vCPU + 32 GiB RAM
    /// c5.9xlarge: 32 vCPU + 72 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/r5/
    /// r5.large:   2  vCPU + 16 GiB RAM
    /// r5.xlarge:  4  vCPU + 32 GiB RAM
    /// r5.2xlarge: 8  vCPU + 64 GiB RAM
    /// r5.4xlarge: 16 vCPU + 128 GiB RAM
    /// r5.8xlarge: 32 vCPU + 256 GiB RAM
    ///
    /// https://aws.amazon.com/ec2/instance-types/t3/
    /// t3.large:    2  vCPU + 8 GiB RAM
    /// t3.xlarge:   4  vCPU + 16 GiB RAM
    /// t3.2xlarge:  8  vCPU + 32 GiB RAM
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_AMD64: Vec<String> = vec![
        String::from("c6a.2xlarge"),
        String::from("m6a.2xlarge"),
        String::from("m5.2xlarge"),
        String::from("c5.2xlarge"),
    ];

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

impl Spec {
    /// Creates a default spec.
    pub fn default_aws(opts: DefaultSpecOption) -> Self {
        let mut rpc_endpoints: Vec<blizzard::Endpoints> = Vec::new();
        for http_rpc in opts.blizzard_http_rpcs.iter() {
            rpc_endpoints.push(blizzard::Endpoints::new(
                http_rpc,
                opts.blizzard_subnet_evm_blockchain_id.clone(),
            ))
        }

        let blizzard_spec = blizzard::Spec {
            log_level: opts.blizzard_log_level,
            network_id: opts.network_id,
            rpc_endpoints,
            metrics_push_interval_seconds: opts.blizzard_metrics_push_interval_seconds,
        };

        let id = {
            if !opts.spec_file_path.is_empty() {
                let spec_file_stem = Path::new(&opts.spec_file_path).file_stem().unwrap();
                spec_file_stem.to_str().unwrap().to_string()
            } else {
                id_manager::time::with_prefix("blizzard")
            }
        };

        if !opts.key_files_dir.is_empty() {
            log::info!("creating key-files-dir '{}'", opts.key_files_dir);
            fs::create_dir_all(&opts.key_files_dir).unwrap();
        }

        // existing network has only 1 pre-funded key "ewoq"
        let mut generated_key_infos: Vec<hot::PrivateKeyInfoEntry> = Vec::new();
        let mut generated_keys: Vec<hot::Key> = Vec::new();
        for i in 0..opts.keys_to_generate {
            let k = {
                if i < hot::TEST_KEYS.len() {
                    hot::TEST_KEYS[i].clone()
                } else {
                    hot::Key::generate().expect("unexpected key generate failure")
                }
            };

            let info = k
                .private_key_info_entry(opts.network_id)
                .expect("unexpected private_key_info_entry failure");
            generated_key_infos.push(info.clone());

            generated_keys.push(k);

            if !opts.key_files_dir.is_empty() {
                // file name is eth address with 0x, contents are "private_key_hex"
                let p = Path::new(&opts.key_files_dir).join(Path::new(&info.eth_address));
                log::info!("writing key file {:?}", p);

                let mut f = File::create(p).unwrap();
                f.write_all(info.private_key_hex.as_bytes()).unwrap();
            }
        }

        let generated_private_key_faucet = Some(generated_key_infos[0].clone());
        let generated_private_keys = Some(generated_key_infos[1..].to_vec());

        // [year][month][date]-[system host-based id]
        let s3_bucket = format!(
            "blizzard-{}-{}-{}",
            id_manager::time::timestamp(6),
            id_manager::system::string(10),
            opts.region
        );
        let aws_resources = aws::Resources {
            region: opts.region,
            s3_bucket,
            ..aws::Resources::default()
        };
        let aws_resources = Some(aws_resources);

        let mut install_artifacts = InstallArtifacts { blizzard_bin: None };
        if !opts.install_artifacts_blizzard_bin.is_empty() {
            install_artifacts.blizzard_bin = Some(opts.install_artifacts_blizzard_bin);
        }

        let machine = Machine {
            nodes: opts.nodes,

            // TODO: support "arm64"
            arch: ARCH_AMD64.to_string(),
            instance_types: DEFAULT_EC2_INSTANCE_TYPES_AMD64.to_vec(),

            use_spot_instance: opts.use_spot_instance,
        };

        Self {
            id,

            aws_resources,
            machine,
            install_artifacts,

            blizzard_spec,

            generated_private_key_faucet,
            generated_private_keys,
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec to YAML {}", e),
            )),
        }
    }

    /// Saves the current spec to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing Spec to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_string(self);
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
        f.write_all(d.as_bytes())?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        log::info!("loading Spec from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(&file_path).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            )
        })?;
        serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        log::info!("validating Spec");

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

        if self.aws_resources.is_some() {
            let aws_resources = self.aws_resources.clone().unwrap();
            if aws_resources.region.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "'machine.region' cannot be empty",
                ));
            }
        }

        if self.machine.nodes < MIN_MACHINE_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.nodes' {} <minimum {}",
                    self.machine.nodes, MIN_MACHINE_NODES
                ),
            ));
        }
        if self.machine.nodes > MAX_MACHINE_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.nodes' {} >maximum {}",
                    self.machine.nodes, MAX_MACHINE_NODES
                ),
            ));
        }

        if let Some(v) = &self.install_artifacts.blizzard_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("blizzard_bin {} does not exist", v),
                ));
            }
        }

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package blizzardup-aws --lib -- test_spec --exact --show-output
#[test]
fn test_spec() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let blizzard_bin = f.path().to_str().unwrap();

    let id = random_manager::string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

id: {}

aws_resources:
  region: us-west-2
  use_spot_instance: false
  s3_bucket: {}

machine:
  nodes: 1
  arch: amd64
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large

install_artifacts:
  blizzard_bin: {}

blizzard_spec:
  log_level: info
  network_id: 99999
  rpc_endpoints: []
  metrics_push_interval_seconds: 60

"#,
        id, bucket, blizzard_bin,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let cfg = Spec::load(config_path).unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let orig = Spec {
        id: id.clone(),
        aws_resources: Some(aws::Resources {
            region: String::from("us-west-2"),
            s3_bucket: bucket.clone(),
            ..aws::Resources::default()
        }),

        machine: Machine {
            nodes: 1,
            arch: "amd64".to_string(),
            instance_types: vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ],
            use_spot_instance: false,
        },

        install_artifacts: InstallArtifacts {
            blizzard_bin: Some(blizzard_bin.to_string()),
        },

        blizzard_spec: blizzard::Spec {
            log_level: String::from("info"),
            network_id: 99999,
            rpc_endpoints: Vec::new(),
            metrics_push_interval_seconds: 60,
        },

        generated_private_key_faucet: None,
        generated_private_keys: None,
    };

    assert_eq!(cfg, orig);
    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);

    let aws_resources = cfg.aws_resources.unwrap();
    assert_eq!(aws_resources.region, "us-west-2");
    assert_eq!(aws_resources.s3_bucket, bucket);

    assert_eq!(
        cfg.install_artifacts.blizzard_bin.unwrap_or(String::new()),
        blizzard_bin
    );

    assert_eq!(cfg.machine.nodes, 1);
    let instance_types = cfg.machine.instance_types;
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");
}

/// Represents the S3/storage key path.
/// MUST be kept in sync with "cfn-templates/ec2_instance_role.yaml".
pub enum StorageNamespace {
    ConfigFile(String),
    Ec2AccessKey(String),
    BlizzardBin(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::ConfigFile(id) => format!("{}/blizzard.config.yaml", id),
            StorageNamespace::Ec2AccessKey(id) => {
                format!("{}/ec2-access.key", id)
            }
            StorageNamespace::BlizzardBin(id) => format!("{}/install/blizzard", id),
        }
    }
}
