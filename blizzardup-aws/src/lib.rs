mod aws;
pub mod blizzard;
pub mod status;

use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use avalanche_types::key;
use aws_manager::ec2;
use serde::{Deserialize, Serialize};

/// Default machine nodes size.
pub const DEFAULT_MACHINE_NODES: usize = 2;
pub const MIN_MACHINE_NODES: usize = 1;
pub const MAX_MACHINE_NODES: usize = 300;

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
    pub resources: Option<aws::Resources>,

    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,
    /// Install artifacts to share with remote machines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_artifacts: Option<UploadArtifacts>,

    /// Flag to pass to the "blizzard" command-line interface.
    pub blizzard_spec: blizzard::Spec,

    #[serde(default)]
    pub prefunded_key_infos: Vec<key::secp256k1::Info>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<status::Status>,
}

/// Defines how the underlying infrastructure is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default)]
    pub nodes: usize,
    #[serde(default)]
    pub arch_type: String,
    #[serde(default)]
    pub rust_os_type: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
    #[serde(default)]
    pub instance_mode: String,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UploadArtifacts {
    /// "blizzard" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/blizzard" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub blizzard_bin: String,
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
            StackName::AsgBlizzards(id) => format!("{}-blizzards", id),
        }
    }
}

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,

    pub funded_keys: usize,

    pub region: String,
    pub instance_mode: String,

    pub nodes: usize,

    pub upload_artifacts_blizzard_bin: String,
    pub blizzard_log_level: String,
    pub blizzard_chain_rpc_urls: Vec<String>,
    pub blizzard_load_kinds: Vec<String>,
    pub blizzard_keys_to_generate: usize,
    pub blizzard_workers: usize,

    pub spec_file_path: String,
}

impl Spec {
    /// Creates a default spec.
    pub fn default_aws(opts: DefaultSpecOption) -> Self {
        let blizzard_spec = blizzard::Spec {
            log_level: opts.blizzard_log_level,
            chain_rpc_urls: opts.blizzard_chain_rpc_urls.clone(),
            load_kinds: opts.blizzard_load_kinds,
            keys_to_generate: opts.blizzard_keys_to_generate,
            workers: opts.blizzard_workers,
        };

        let id = {
            if !opts.spec_file_path.is_empty() {
                let spec_file_stem = Path::new(&opts.spec_file_path).file_stem().unwrap();
                spec_file_stem.to_str().unwrap().to_string()
            } else {
                id_manager::time::with_prefix("blizzard")
            }
        };

        // same order as avalanche-types genesis
        // assume they are pre-funded
        assert!(key::secp256k1::TEST_KEYS.len() >= opts.funded_keys);
        let mut prefunded_key_infos: Vec<key::secp256k1::Info> = Vec::new();
        for i in 0..opts.funded_keys {
            let info = key::secp256k1::TEST_KEYS[i]
                .to_info(1)
                .expect("unexpected to_info failure");
            prefunded_key_infos.push(info.clone());
        }

        // [year][month][date]-[system host-based id]
        let s3_bucket = format!(
            "blizzard-{}-{}-{}",
            id_manager::time::timestamp(6),
            id_manager::system::string(10),
            opts.region
        );
        let resources = aws::Resources {
            region: opts.region.clone(),
            s3_bucket,
            ..aws::Resources::default()
        };
        let resources = Some(resources);

        let upload_artifacts = if !opts.upload_artifacts_blizzard_bin.is_empty() {
            Some(UploadArtifacts {
                blizzard_bin: opts.upload_artifacts_blizzard_bin.clone(),
            })
        } else {
            None
        };

        let machine = Machine {
            nodes: opts.nodes,

            // TODO: support "arm64"
            arch_type: "amd64".to_string(),
            rust_os_type: "ubuntu20.04".to_string(),
            instance_types: ec2::default_instance_types(&opts.region, "amd64", "large").unwrap(),

            instance_mode: opts.instance_mode,
        };

        Self {
            id,

            resources,
            machine,
            upload_artifacts,

            blizzard_spec,

            prefunded_key_infos,

            status: None,
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

        let f = File::open(file_path).map_err(|e| {
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

        if self.resources.is_some() {
            let resources = self.resources.clone().unwrap();
            if resources.region.is_empty() {
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

        if let Some(v) = &self.upload_artifacts {
            if !v.blizzard_bin.is_empty() && !Path::new(&v.blizzard_bin).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("blizzard_bin {} does not exist", v.blizzard_bin),
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

    let id = random_manager::secure_string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

id: {}

resources:
  region: us-west-2
  use_spot_instance: false
  s3_bucket: {}

machine:
  nodes: 1
  arch_type: amd64
  rust_os_type: ubuntu20.04
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large
  instance_mode: spot

upload_artifacts:
  blizzard_bin: {}

blizzard_spec:
  log_level: info
  network_id: 99999
  chain_rpc_urls: []
  load_kinds: ["x-transfers", "evm-transfers"]
  metrics_push_interval_seconds: 60
  workers: 10
  keys_to_generate: 1000

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
        resources: Some(aws::Resources {
            region: String::from("us-west-2"),
            s3_bucket: bucket.clone(),
            ..aws::Resources::default()
        }),

        machine: Machine {
            nodes: 1,
            arch_type: "amd64".to_string(),
            rust_os_type: "ubuntu20.04".to_string(),
            instance_types: vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ],
            instance_mode: String::from("spot"),
        },

        upload_artifacts: Some(UploadArtifacts {
            blizzard_bin: blizzard_bin.to_string(),
        }),

        blizzard_spec: blizzard::Spec {
            log_level: String::from("info"),
            chain_rpc_urls: Vec::new(),
            load_kinds: vec![String::from("x-transfers"), String::from("evm-transfers")],
            keys_to_generate: 1000,
            workers: 10,
        },

        prefunded_key_infos: Vec::new(),

        status: None,
    };

    assert_eq!(cfg, orig);
    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);

    let resources = cfg.resources.unwrap();
    assert_eq!(resources.region, "us-west-2");
    assert_eq!(resources.s3_bucket, bucket);

    assert_eq!(
        cfg.upload_artifacts.clone().unwrap().blizzard_bin,
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
