use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
};

use avalanche_types::{
    avalanchego::{config as avalanchego_config, genesis as avalanchego_genesis},
    constants,
    coreth::chain_config as coreth_chain_config,
    key, node,
};
use aws_manager::{ec2, sts};
use serde::{Deserialize, Serialize};

pub const VERSION: usize = 3;

/// Represents network-level configuration shared among all nodes.
/// The node-level configuration is generated during each
/// bootstrap process (e.g., certificates) and not defined
/// in this cluster-level "Config".
/// At the beginning, the user is expected to provide this configuration.
/// "Clone" is for deep-copying.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    #[serde(default)]
    pub version: usize,

    /// User-provided ID of the cluster/test.
    /// This is NOT the avalanche node ID.
    /// This is NOT the avalanche network ID.
    #[serde(default)]
    pub id: String,

    /// AAD tag used for envelope encryption with KMS.
    #[serde(default)]
    pub aad_tag: String,

    /// AWS profile to use for API calls.
    #[serde(default)]
    pub profile_name: String,

    /// AWS resources if run in AWS.
    pub resource: Resource,
    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,

    /// Upload artifacts from the local machine to share with remote machines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_artifacts: Option<UploadArtifacts>,
    /// Non-empty to specify avalanchego release tag to download.
    /// Discarded if avalanchego binary was uploaded to S3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanchego_release_tag: Option<String>,

    /// Flag to pass to the "avalanched" command-line interface.
    pub avalanched_config: crate::aws::avalanched::Flags,

    /// Set "true" to keep resources for reuse.
    #[serde(default)]
    pub keep_resources_except_asg_ssm: bool,
    /// Set "true" to create a dev machine.
    #[serde(default)]
    pub create_dev_machine: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_machine: Option<DevMachine>,

    /// Set "true" to enable NLB.
    #[serde(default)]
    pub enable_nlb: bool,
    /// Set "true" to disable CloudWatch log auto removal.
    #[serde(default)]
    pub disable_logs_auto_removal: bool,
    /// Interval in seconds to fetch system and avalanche node metrics.
    /// Set to 0 to disable metrics collection.
    #[serde(default)]
    pub metrics_fetch_interval_seconds: u64,
    #[serde(default)]
    pub primary_network_validate_period_in_days: u64,

    /// Required for custom networks with pre-funded wallets!
    /// These are used for custom primary network genesis generation and will be pre-funded.
    /// The first key will have locked P-chain balance with initial stake duration in genesis.
    /// Except the first key in the list, all keys have immediately unlocked P-chain balance.
    /// Should never be used for mainnet as it's store in plaintext for testing purposes only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefunded_keys: Option<Vec<key::secp256k1::Info>>,

    /// Represents the configuration for "avalanchego".
    /// Set as if run in remote machines.
    /// For instance, "config-file" must be the path valid
    /// in the remote machines.
    /// MUST BE "kebab-case" to be compatible with "avalanchego".
    pub avalanchego_config: avalanchego_config::Config,
    /// If non-empty, the JSON-encoded data are saved to a file
    /// in Path::new(&avalanchego_config.chain_config_dir).join("C").
    pub coreth_chain_config: coreth_chain_config::Config,

    /// If non-empty, the JSON-encoded data are saved to a file
    /// and used for "--genesis" in Path::new(&avalanchego_config.genesis).
    /// This includes "coreth_genesis::Genesis".
    /// Names after "_template" since it has not included
    /// initial stakers yet with to-be-created node IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avalanchego_genesis_template: Option<avalanchego_genesis::Genesis>,
}

/// Represents the KMS key resource.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct KmsKey {
    /// Key Id.
    pub id: String,
    /// Key Arn.
    pub arn: String,
}

/// Represents the current AWS resource configurations and states.
/// These states are necessary for resource cleanups.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Resource {
    /// AWS STS caller loaded from its local environment.
    /// READ ONLY.
    #[serde(default)]
    pub identity: sts::Identity,

    /// AWS region to create resources.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub regions: Vec<String>,
    /// Name of the bucket to store (or download from)
    /// the configuration and resources (e.g., S3).
    /// If not exists, it creates automatically.
    /// If exists, it skips creation and uses the existing one.
    /// MUST BE NON-EMPTY.
    /// ALWAYS USE THE FIRST REGION IN `regions` for S3.
    /// AND SHARED ACROSS MULTIPLE REGIONS.
    #[serde(default)]
    pub s3_bucket: String,

    #[serde(default)]
    pub ingress_ipv4_cidr: String,

    /// Only populate as many as we need to fill up anchor/non-anchor nodes.
    /// e.g., "regions" may have 5 but we may only need 2 regions for 3 node cluster.
    #[serde(default)]
    pub regional_resources: BTreeMap<String, RegionalResource>,

    /// Created nodes at the start of the network.
    /// May become stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_nodes: Option<Vec<Node>>,
}

impl Default for Resource {
    fn default() -> Self {
        Self::default()
    }
}

impl Resource {
    pub fn default() -> Self {
        Self {
            identity: sts::Identity::default(),

            regions: vec![String::from("us-west-2")],
            s3_bucket: String::new(),
            ingress_ipv4_cidr: String::from("0.0.0.0/0"),

            regional_resources: BTreeMap::new(),

            created_nodes: None,
        }
    }
}

/// Represents the AWS region-specific configuration and states.
/// These states are necessary for resource cleanups.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RegionalResource {
    #[serde(default)]
    pub region: String,

    /// EC2 key pair name for SSH access to EC2 instances.
    /// READ ONLY -- DO NOT SET.
    #[serde(default)]
    pub ec2_key_name: String,
    #[serde(default)]
    pub ec2_key_path: String,
    #[serde(default)]
    pub ssh_commands_path_anchor_nodes: String,
    #[serde(default)]
    pub ssh_commands_path_non_anchor_nodes: String,
    #[serde(default)]
    pub ssh_commands_path_dev_machine: String,

    /// CloudFormation stack name for EC2 instance role.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,
    /// Instance profile ARN from "cloudformation_ec2_instance_role".
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_profile_arn: Option<String>,

    /// AWS region to create resources.
    /// NON-EMPTY TO ENABLE HTTPS over NLB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nlb_acm_certificate_arn: Option<String>,

    /// KMS key ID to encrypt resources.
    /// Only used for encrypting node certs and EC2 keys.
    /// None if not created yet.
    /// READ ONLY -- DO NOT SET.
    /// TODO: support existing key and load the ARN based on region and account number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_symmetric_default_encrypt_key: Option<KmsKey>,

    /// CloudFormation stack name for VPC.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc: Option<String>,
    /// VPC ID from "cloudformation_vpc".
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_id: Option<String>,
    /// Security group ID from "cloudformation_vpc".
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_security_group_id: Option<String>,
    /// Public subnet IDs from "cloudformation_vpc".
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_public_subnet_ids: Option<Vec<String>>,

    /// CloudFormation stack names of Auto Scaling Group (ASG)
    /// for anchor nodes.
    /// None if mainnet.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_anchor_nodes: Option<Vec<String>>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_anchor_nodes_logical_ids: Option<Vec<String>>,

    /// CloudFormation stack names of Auto Scaling Group (ASG)
    /// for non-anchor nodes.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_anchor_nodes: Option<Vec<String>>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_anchor_nodes_logical_ids: Option<Vec<String>>,

    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_nlb_arn: Option<String>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_nlb_target_group_arn: Option<String>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_nlb_dns_name: Option<String>,

    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_launch_template_id: Option<String>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_launch_template_version: Option<String>,

    /// CloudFormation stack name for SSM document that installs subnet.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ssm_install_subnet_chain: Option<String>,

    /// CloudFormation stack name of Auto Scaling Group (ASG)
    /// for anchor nodes.
    /// None if mainnet.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_dev_machine: Option<String>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_dev_machine_logical_id: Option<String>,
}

impl Default for RegionalResource {
    fn default() -> Self {
        Self::default()
    }
}

impl RegionalResource {
    pub fn default() -> Self {
        Self {
            region: String::from("us-west-2"),
            ec2_key_name: String::new(),
            ec2_key_path: String::new(),
            ssh_commands_path_anchor_nodes: String::new(),
            ssh_commands_path_non_anchor_nodes: String::new(),
            ssh_commands_path_dev_machine: String::new(),

            cloudformation_ec2_instance_role: None,
            cloudformation_ec2_instance_profile_arn: None,

            nlb_acm_certificate_arn: None,

            kms_symmetric_default_encrypt_key: None,

            cloudformation_vpc: None,
            cloudformation_vpc_id: None,
            cloudformation_vpc_security_group_id: None,
            cloudformation_vpc_public_subnet_ids: None,

            cloudformation_asg_anchor_nodes: None,
            cloudformation_asg_anchor_nodes_logical_ids: None,

            cloudformation_asg_non_anchor_nodes: None,
            cloudformation_asg_non_anchor_nodes_logical_ids: None,

            cloudformation_asg_nlb_arn: None,
            cloudformation_asg_nlb_target_group_arn: None,
            cloudformation_asg_nlb_dns_name: None,

            cloudformation_asg_launch_template_id: None,
            cloudformation_asg_launch_template_version: None,

            cloudformation_ssm_install_subnet_chain: None,

            cloudformation_asg_dev_machine: None,
            cloudformation_asg_dev_machine_logical_id: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RegionMachineId {
    pub region: String,
    pub machine_id: String,
}

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,
    pub network_name: String,

    pub arch_type: String,
    pub os_type: String,
    pub anchor_nodes: u32,
    pub non_anchor_nodes: u32,

    pub key_files_dir: String,
    pub keys_to_generate: usize,

    pub regions: Vec<String>,
    pub auto_regions: u32,

    pub ingress_ipv4_cidr: String,
    pub instance_mode: String,
    pub instance_size: String,
    pub instance_types: HashMap<String, Vec<String>>,
    pub volume_size_in_gb: u32,

    pub ip_mode: String,

    pub keep_resources_except_asg_ssm: bool,
    pub create_dev_machine: bool,
    pub dev_machine_ssh_key_email: String,

    pub enable_nlb: bool,
    pub disable_logs_auto_removal: bool,
    pub metrics_fetch_interval_seconds: u64,

    pub aad_tag: String,

    pub nlb_acm_certificate_arns: HashMap<String, String>,

    pub upload_artifacts_aws_volume_provisioner_local_bin: String,
    pub upload_artifacts_aws_ip_provisioner_local_bin: String,
    pub upload_artifacts_avalanche_telemetry_cloudwatch_local_bin: String,
    pub upload_artifacts_avalanched_aws_local_bin: String,
    pub upload_artifacts_avalanchego_local_bin: String,
    pub upload_artifacts_prometheus_metrics_rules_file_path: String,

    pub avalanchego_release_tag: String,

    pub avalanched_log_level: String,
    pub avalanched_use_default_config: bool,
    pub avalanched_publish_periodic_node_info: bool,

    pub primary_network_validate_period_in_days: u64,

    pub avalanchego_log_level: String,
    pub avalanchego_http_tls_enabled: bool,
    pub avalanchego_state_sync_ids: String,
    pub avalanchego_state_sync_ips: String,
    pub avalanchego_profile_continuous_enabled: bool,
    pub avalanchego_profile_continuous_freq: String,
    pub avalanchego_profile_continuous_max_files: String,

    pub coreth_continuous_profiler_enabled: bool,
    pub coreth_offline_pruning_enabled: bool,
    pub coreth_state_sync_enabled: bool,

    pub spec_file_path: String,
    /// The AWS profile to use.
    pub profile_name: String,
}

impl Spec {
    /// Creates a default spec.
    pub async fn default_aws(opts: DefaultSpecOption) -> io::Result<(Self, String)> {
        let network_id = match constants::NETWORK_NAME_TO_NETWORK_ID.get(opts.network_name.as_str())
        {
            Some(v) => *v,
            None => constants::DEFAULT_CUSTOM_NETWORK_ID,
        };

        if opts.network_name == "custom" && opts.keys_to_generate == 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "can't --keys-to-generate=0 for {} network",
                    opts.network_name
                ),
            ));
        }
        if opts.network_name != "custom" && opts.keys_to_generate > 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "can't --keys-to-generate={} (>0) for {} network",
                    opts.keys_to_generate, opts.network_name
                ),
            ));
        }

        let mut avalanched_config = crate::aws::avalanched::Flags {
            log_level: opts.avalanched_log_level,
            use_default_config: opts.avalanched_use_default_config,
            publish_periodic_node_info: None,
        };
        if opts.avalanched_publish_periodic_node_info {
            avalanched_config.publish_periodic_node_info = Some(true);
        }

        if opts.primary_network_validate_period_in_days < 14 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "can't --primary-network-validate-period-in-days={} <14",
                    opts.primary_network_validate_period_in_days
                ),
            ));
        }

        let mut avalanchego_config = match network_id {
            1 => avalanchego_config::Config::default_main(),
            5 => avalanchego_config::Config::default_fuji(),
            _ => avalanchego_config::Config::default_custom(),
        };
        avalanchego_config.log_level = Some(opts.avalanchego_log_level);

        // only set values if non empty
        // otherwise, avalanchego will fail with "couldn't load node config: read .: is a directory"
        // TODO: use different certs than staking?
        if opts.avalanchego_http_tls_enabled {
            avalanchego_config.http_tls_enabled = Some(true);
            avalanchego_config.http_tls_key_file = avalanchego_config.staking_tls_key_file.clone();
            avalanchego_config.http_tls_cert_file =
                avalanchego_config.staking_tls_cert_file.clone();
        }

        if !opts.avalanchego_state_sync_ids.is_empty() {
            avalanchego_config.state_sync_ids = Some(opts.avalanchego_state_sync_ids.clone());
        };
        if !opts.avalanchego_state_sync_ips.is_empty() {
            avalanchego_config.state_sync_ips = Some(opts.avalanchego_state_sync_ips.clone());
        };
        if opts.avalanchego_profile_continuous_enabled {
            avalanchego_config.profile_continuous_enabled = Some(true);
        }
        if !opts.avalanchego_profile_continuous_freq.is_empty() {
            avalanchego_config.profile_continuous_freq =
                Some(opts.avalanchego_profile_continuous_freq.clone());
        };
        if !opts.avalanchego_profile_continuous_max_files.is_empty() {
            let profile_continuous_max_files = opts.avalanchego_profile_continuous_max_files;
            let profile_continuous_max_files = profile_continuous_max_files.parse::<u32>().unwrap();
            avalanchego_config.profile_continuous_max_files = Some(profile_continuous_max_files);
        };

        let network_id = avalanchego_config.network_id;
        let (id, spec_file_path) = {
            if !opts.spec_file_path.is_empty() {
                let spec_file_stem = Path::new(&opts.spec_file_path).file_stem().unwrap();
                let id = spec_file_stem.to_str().unwrap().to_string();
                (id, opts.spec_file_path.clone())
            } else {
                let id = match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                    Some(v) => id_manager::time::with_prefix(format!("aops-{}", *v).as_str()),
                    None => id_manager::time::with_prefix("aops-custom"),
                };
                (id.clone(), dir_manager::home::named(&id, Some(".yaml")))
            }
        };

        let (total_anchor_nodes, total_non_anchor_nodes) =
            match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                // non-custom network only single node to utilize single AZ
                Some(_) => (
                    None,
                    if opts.non_anchor_nodes > 0 {
                        opts.non_anchor_nodes
                    } else {
                        DEFAULT_MACHINE_NON_ANCHOR_NODES
                    },
                ),

                // custom network
                None => {
                    let anchor_nodes = if opts.anchor_nodes > 0 {
                        opts.anchor_nodes
                    } else {
                        DEFAULT_MACHINE_ANCHOR_NODES
                    };
                    let non_anchor_nodes = if opts.non_anchor_nodes > 0 {
                        opts.non_anchor_nodes
                    } else {
                        DEFAULT_MACHINE_NON_ANCHOR_NODES
                    };

                    (Some(anchor_nodes), non_anchor_nodes)
                }
            };

        if !opts.key_files_dir.is_empty() {
            log::info!("creating key-files-dir '{}'", opts.key_files_dir);
            fs::create_dir_all(&opts.key_files_dir).unwrap();
        }

        log::info!("generating hot keys...");
        let mut prefunded_keys_info: Vec<key::secp256k1::Info> = Vec::new();
        let mut prefunded_pubkeys: Vec<key::secp256k1::public_key::Key> = Vec::new();
        for i in 0..opts.keys_to_generate {
            let (key_info, key_read_only) = if i < key::secp256k1::TEST_KEYS.len() {
                (
                    key::secp256k1::TEST_KEYS[i].to_info(network_id).unwrap(),
                    key::secp256k1::TEST_KEYS[i].to_public_key(),
                )
            } else {
                let k = key::secp256k1::private_key::Key::generate().unwrap();
                (k.to_info(network_id).unwrap(), k.to_public_key())
            };
            prefunded_keys_info.push(key_info.clone());
            prefunded_pubkeys.push(key_read_only);

            if !opts.key_files_dir.is_empty() {
                // file name is eth address with 0x, contents are "private_key_hex"
                let p = Path::new(&opts.key_files_dir).join(Path::new(&key_info.eth_address));
                log::info!("writing key file {:?}", p);

                let mut f = File::create(p).unwrap();
                f.write_all(
                    prefix_manager::strip_0x(&key_info.private_key_hex.clone().unwrap()).as_bytes(),
                )
                .unwrap();
            }
        }

        let avalanchego_genesis_template = {
            if avalanchego_config.is_custom_network() {
                let g = avalanchego_genesis::Genesis::new(network_id, &prefunded_pubkeys)
                    .expect("unexpected None genesis");
                Some(g)
            } else {
                None
            }
        };

        let mut regions = opts.regions.clone();
        if opts.auto_regions > 0 {
            regions = vec!["us-west-2".to_string()];
            if opts.auto_regions > 1 {
                // ICN
                regions.push("ap-northeast-2".to_string());
            }
            if opts.auto_regions > 2 {
                // DUB
                regions.push("eu-west-1".to_string());
            }
            if opts.auto_regions > 3 {
                // IAD
                regions.push("us-east-1".to_string());
            }
            if opts.auto_regions > 4 {
                // FRA
                regions.push("eu-central-1".to_string());
            }
            if opts.auto_regions > 5 {
                panic!("auto-regions only supported up to 5 regions!")
            }
        }
        log::info!("generating configuration with the regions {:?}", regions);

        let region_to_instance_types = if !opts.instance_types.is_empty() {
            opts.instance_types.clone()
        } else {
            let mut reg_to_instance_types = HashMap::new();
            for reg in &regions {
                let iss =
                    ec2::default_instance_types(reg, &opts.arch_type, &opts.instance_size).unwrap();
                reg_to_instance_types.insert(reg.to_string(), iss);
            }
            reg_to_instance_types
        };

        // only iterate until we used up all total* nodes
        let mut current_anchor_nodes = 0_u32;
        let mut current_non_anchor_nodes = 0_u32;

        let mut regional_resources = BTreeMap::new();
        let mut regional_machines = BTreeMap::new();

        for (i, reg) in regions.iter().enumerate() {
            let mut regional_machine = RegionalMachine {
                anchor_nodes: None,
                non_anchor_nodes: 0,
                instance_types: region_to_instance_types.get(reg).unwrap().clone(),
            };

            // last iteration, but still remaining... use them up
            // or even if we don't use the last regions, make sure we add the remaining
            // e.g., 3 nodes for 1 regions ==> [3]
            // e.g., 3 nodes for 2 regions ==> [1, 2]
            // e.g., 3 nodes for 3 regions ==> [1, 1, 1]
            // e.g., 3 nodes for 5 regions ==> [1, 1, 1, break]
            // e.g., 4 nodes for 3 regions ==> [1, 1, 2, break]
            if let Some(total_anchors) = &total_anchor_nodes {
                if *total_anchors > current_anchor_nodes {
                    let mut per_region = *total_anchors / regions.len() as u32;
                    if per_region == 0 {
                        per_region = 1;
                    }
                    if i == regions.len() - 1 {
                        regional_machine.anchor_nodes = Some(*total_anchors - current_anchor_nodes);
                        current_anchor_nodes = *total_anchors;
                    } else {
                        regional_machine.anchor_nodes = Some(per_region);
                        current_anchor_nodes += per_region;
                    }
                }
            }
            if total_non_anchor_nodes > current_non_anchor_nodes {
                let mut per_region = total_non_anchor_nodes / regions.len() as u32;
                if per_region == 0 {
                    per_region = 1;
                }
                if i == regions.len() - 1 {
                    regional_machine.non_anchor_nodes =
                        total_non_anchor_nodes - current_non_anchor_nodes;
                    current_non_anchor_nodes = total_non_anchor_nodes;
                } else {
                    regional_machine.non_anchor_nodes = per_region;
                    current_non_anchor_nodes += per_region;
                }
            }

            if regional_machine.anchor_nodes.is_none() && regional_machine.non_anchor_nodes == 0 {
                log::info!("no more node to allocate in region '{reg}' -- skipping");
                continue;
            }
            regional_machines.insert(reg.to_string(), regional_machine);

            let mut regional_resource = RegionalResource {
                region: reg.to_string(),
                ec2_key_name: format!("{id}-ec2-key"),
                ec2_key_path: get_ec2_key_path(&spec_file_path, reg.as_str()),
                ssh_commands_path_anchor_nodes: get_ssh_commands_path(
                    &spec_file_path,
                    reg.as_str(),
                    "anchor-nodes",
                ),
                ssh_commands_path_non_anchor_nodes: get_ssh_commands_path(
                    &spec_file_path,
                    reg.as_str(),
                    "non-anchor-nodes",
                ),
                ssh_commands_path_dev_machine: get_ssh_commands_path(
                    &spec_file_path,
                    reg.as_str(),
                    "dev-machine",
                ),
                ..RegionalResource::default()
            };
            if let Some(nlb_acm_certificate_arn) = opts.nlb_acm_certificate_arns.get(reg) {
                regional_resource.nlb_acm_certificate_arn = Some(nlb_acm_certificate_arn.clone());
            }
            regional_resources.insert(reg.to_string(), regional_resource);
        }

        let dev_machine = if opts.create_dev_machine {
            let ssh_key_email = if opts.dev_machine_ssh_key_email.is_empty() {
                None
            } else {
                Some(opts.dev_machine_ssh_key_email.clone())
            };
            Some(DevMachine {
                ssh_key_email,
                arch_type: opts.arch_type.clone(),
                os_type: opts.os_type.clone(),
                instance_mode: opts.instance_mode.clone(),
                ip_mode: opts.ip_mode.clone(),
                volume_size_in_gb: opts.volume_size_in_gb,
                instance_types: region_to_instance_types.get(&regions[0]).unwrap().clone(),
            })
        } else {
            None
        };

        // [year][month][date]-[system host-based id]
        let s3_bucket = format!(
            "avalanche-ops-{}-{}-{}",
            id_manager::time::timestamp(6),
            id_manager::system::string(10),
            regions[0] // always use the first region
        );
        let mut resource = Resource {
            regions: regions.clone(),
            s3_bucket,
            regional_resources,
            ..Resource::default()
        };

        // TODO: we need also whitelist within-VPC traffic
        // resources.ingress_ipv4_cidr = "0.0.0.0/0".to_string();
        if !opts.ingress_ipv4_cidr.is_empty() {
            resource.ingress_ipv4_cidr = opts.ingress_ipv4_cidr.clone();
        } else {
            log::info!("empty ingress_ipv4_cidr, so default to public IP on the local host");
            resource.ingress_ipv4_cidr = if let Some(ip) = public_ip::addr().await {
                log::info!("found public ip address {:?}", ip);
                format!("{}/32", ip)
            } else {
                log::warn!("failed to get a public IP address -- default to 0.0.0.0/0");
                "0.0.0.0/0".to_string()
            };
        };
        log::info!("ingress IPv4 range {}", resource.ingress_ipv4_cidr);

        let mut upload_artifacts = UploadArtifacts {
            avalanched_local_bin: String::new(),
            aws_volume_provisioner_local_bin: String::new(),
            aws_ip_provisioner_local_bin: String::new(),
            avalanche_telemetry_cloudwatch_local_bin: String::new(),
            avalanchego_local_bin: String::new(),
            prometheus_metrics_rules_file_path: String::new(),
        };
        if !opts
            .upload_artifacts_aws_volume_provisioner_local_bin
            .is_empty()
        {
            upload_artifacts.aws_volume_provisioner_local_bin = opts
                .upload_artifacts_aws_volume_provisioner_local_bin
                .clone();
        }
        if !opts
            .upload_artifacts_aws_ip_provisioner_local_bin
            .is_empty()
        {
            upload_artifacts.aws_ip_provisioner_local_bin =
                opts.upload_artifacts_aws_ip_provisioner_local_bin.clone();
        }
        if !opts
            .upload_artifacts_avalanche_telemetry_cloudwatch_local_bin
            .is_empty()
        {
            upload_artifacts.avalanche_telemetry_cloudwatch_local_bin = opts
                .upload_artifacts_avalanche_telemetry_cloudwatch_local_bin
                .clone();
        }
        if !opts.upload_artifacts_avalanched_aws_local_bin.is_empty() {
            upload_artifacts.avalanched_local_bin =
                opts.upload_artifacts_avalanched_aws_local_bin.clone();
        }
        if !opts.upload_artifacts_avalanchego_local_bin.is_empty() {
            upload_artifacts.avalanchego_local_bin =
                opts.upload_artifacts_avalanchego_local_bin.clone();
        }
        if !opts
            .upload_artifacts_prometheus_metrics_rules_file_path
            .is_empty()
        {
            upload_artifacts.prometheus_metrics_rules_file_path = opts
                .upload_artifacts_prometheus_metrics_rules_file_path
                .clone();
        }

        if upload_artifacts
            .prometheus_metrics_rules_file_path
            .is_empty()
        {
            upload_artifacts.prometheus_metrics_rules_file_path =
                get_prometheus_metrics_rules_file_path(&spec_file_path);
        }
        if !Path::new(&upload_artifacts.prometheus_metrics_rules_file_path).exists() {
            log::info!(
                "prometheus_metrics_rules_file_path {} does not exist -- writing default rules",
                upload_artifacts.prometheus_metrics_rules_file_path
            );

            let metrics_rules = crate::artifacts::prometheus_rules();
            metrics_rules.sync(&upload_artifacts.prometheus_metrics_rules_file_path)?;
        }
        let upload_artifacts = if upload_artifacts.avalanched_local_bin.is_empty()
            && upload_artifacts.aws_volume_provisioner_local_bin.is_empty()
            && upload_artifacts.aws_ip_provisioner_local_bin.is_empty()
            && upload_artifacts
                .avalanche_telemetry_cloudwatch_local_bin
                .is_empty()
            && upload_artifacts.avalanchego_local_bin.is_empty()
            && upload_artifacts
                .prometheus_metrics_rules_file_path
                .is_empty()
        {
            None
        } else {
            Some(upload_artifacts)
        };

        let avalanchego_release_tag = if opts.avalanchego_release_tag.is_empty() {
            None
        } else {
            Some(opts.avalanchego_release_tag.clone())
        };

        let mut coreth_chain_config = coreth_chain_config::Config::default();
        if opts.coreth_continuous_profiler_enabled {
            coreth_chain_config.continuous_profiler_dir =
                Some(String::from(coreth_chain_config::DEFAULT_PROFILE_DIR));
            coreth_chain_config.continuous_profiler_frequency =
                Some(coreth_chain_config::DEFAULT_PROFILE_FREQUENCY);
            coreth_chain_config.continuous_profiler_max_files =
                Some(coreth_chain_config::DEFAULT_PROFILE_MAX_FILES);
        }
        if opts.coreth_offline_pruning_enabled {
            coreth_chain_config.offline_pruning_enabled = Some(true);
        }
        if opts.coreth_state_sync_enabled {
            coreth_chain_config.state_sync_enabled = Some(true);
            if !opts.avalanchego_state_sync_ids.is_empty() {
                coreth_chain_config.state_sync_ids = Some(opts.avalanchego_state_sync_ids.clone());
            }
        }

        let state_sync_enabled = if let Some(b) = coreth_chain_config.state_sync_enabled {
            b
        } else {
            false
        };
        let volume_size_in_gb = if opts.volume_size_in_gb > 0 {
            opts.volume_size_in_gb
        } else if avalanchego_config.is_mainnet() {
            if state_sync_enabled {
                300
            } else {
                1024
            }
        } else if !avalanchego_config.is_custom_network() {
            // fuji/*
            if state_sync_enabled {
                250
            } else {
                600
            }
        } else if state_sync_enabled {
            200
        } else {
            400
        };

        let machine = Machine {
            total_anchor_nodes,
            total_non_anchor_nodes,

            arch_type: opts.arch_type,
            os_type: opts.os_type,
            regional_machines,

            instance_mode: opts.instance_mode,
            ip_mode: opts.ip_mode,

            volume_size_in_gb,
        };

        let profile_name = opts.profile_name;

        Ok((
            Self {
                version: VERSION,

                id,
                aad_tag: opts.aad_tag,

                resource,
                machine,

                upload_artifacts,
                avalanchego_release_tag,

                avalanched_config,

                keep_resources_except_asg_ssm: opts.keep_resources_except_asg_ssm,
                create_dev_machine: opts.create_dev_machine,
                dev_machine,

                enable_nlb: opts.enable_nlb,
                disable_logs_auto_removal: opts.disable_logs_auto_removal,
                metrics_fetch_interval_seconds: opts.metrics_fetch_interval_seconds,
                primary_network_validate_period_in_days: opts
                    .primary_network_validate_period_in_days,

                prefunded_keys: Some(prefunded_keys_info),

                avalanchego_config,
                coreth_chain_config,
                avalanchego_genesis_template,
                profile_name,
            },
            spec_file_path,
        ))
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
        if let Some(parent_dir) = path.parent() {
            log::info!("creating parent dir '{}'", parent_dir.display());
            fs::create_dir_all(parent_dir)?;
        }

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec info to YAML {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())
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

        if self.version != VERSION {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("version unexpected {}, expected {}", self.version, VERSION),
            ));
        }

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

        if self.resource.regions.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'machine.regions' cannot be empty",
            ));
        }
        if self.resource.regions.len() > 5 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'machine.regions' cannot exceed 5",
            ));
        }

        if self.machine.total_non_anchor_nodes < MIN_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} <minimum {}",
                    self.machine.total_non_anchor_nodes, MIN_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if self.machine.total_non_anchor_nodes > MAX_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} >maximum {}",
                    self.machine.total_non_anchor_nodes, MAX_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if self.avalanchego_config.is_custom_network()
            && self.machine.total_anchor_nodes.unwrap_or(0) == 0
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.total_anchor_nodes' must be >1 (set to {:?})",
                    self.machine.total_anchor_nodes
                ),
            ));
        }

        if let Some(v) = &self.upload_artifacts {
            if !v.aws_volume_provisioner_local_bin.is_empty()
                && !Path::new(&v.aws_volume_provisioner_local_bin).exists()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "aws_volume_provisioner_bin {} does not exist",
                        v.aws_volume_provisioner_local_bin
                    ),
                ));
            }
            if !v.aws_ip_provisioner_local_bin.is_empty()
                && !Path::new(&v.aws_ip_provisioner_local_bin).exists()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "aws_ip_provisioner_bin {} does not exist",
                        v.aws_ip_provisioner_local_bin
                    ),
                ));
            }

            if !v.avalanched_local_bin.is_empty() && !Path::new(&v.avalanched_local_bin).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanched_bin {} does not exist", v.avalanched_local_bin),
                ));
            }
            if !v.avalanchego_local_bin.is_empty() && !Path::new(&v.avalanchego_local_bin).exists()
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanchego_bin {} does not exist", v.avalanchego_local_bin),
                ));
            }
        }

        if !self.avalanchego_config.is_custom_network() {
            if self.avalanchego_genesis_template.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify 'avalanchego_genesis_template' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
            if self.machine.total_anchor_nodes.unwrap_or(0) > 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot specify non-zero 'machine.anchor_nodes' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
        } else {
            if self.avalanchego_genesis_template.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "must specify 'avalanchego_genesis_template' for network_id {:?}",
                        self.avalanchego_config.network_id
                    ),
                ));
            }
            if self.machine.total_anchor_nodes.unwrap_or(0) == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot specify 0 for 'machine.anchor_nodes' for custom network",
                ));
            }
            if self.machine.total_anchor_nodes.unwrap_or(0) < MIN_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.total_anchor_nodes' {} below min {}",
                        self.machine.total_anchor_nodes.unwrap_or(0),
                        MIN_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
            if self.machine.total_anchor_nodes.unwrap_or(0) > MAX_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.total_anchor_nodes' {} exceeds limit {}",
                        self.machine.total_anchor_nodes.unwrap_or(0),
                        MAX_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
        }

        if self.machine.total_anchor_nodes.unwrap_or(0) > 0 {
            let mut total_anchor_nodes = 0;
            for (_, regional_machine) in self.machine.regional_machines.iter() {
                total_anchor_nodes += regional_machine.anchor_nodes.unwrap_or(0);
            }
            if self.machine.total_anchor_nodes.unwrap_or(0) != total_anchor_nodes {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.total_anchor_nodes' {} != {total_anchor_nodes} from regions",
                        self.machine.total_anchor_nodes.unwrap_or(0)
                    ),
                ));
            }
        }
        let mut total_non_anchor_nodes = 0;
        for (_, regional_machine) in self.machine.regional_machines.iter() {
            total_non_anchor_nodes += regional_machine.non_anchor_nodes;
        }
        if self.machine.total_non_anchor_nodes != total_non_anchor_nodes {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.total_non_anchor_nodes' {} != {total_non_anchor_nodes} from regions",
                    self.machine.total_non_anchor_nodes
                ),
            ));
        }

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- aws::spec::test_spec --exact --show-output
#[test]
fn test_spec() {
    use std::fs;

    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&[0]);
    assert!(ret.is_ok());
    let avalanche_config_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&[0]);
    assert!(ret.is_ok());
    let avalanched_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&[0]);
    assert!(ret.is_ok());
    let avalanchego_bin = f.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let plugin_path = tmp_dir.path().join(random_manager::secure_string(10));
    let mut f = File::create(&plugin_path).unwrap();
    let ret = f.write_all(&[0]);
    assert!(ret.is_ok());
    let plugin_dir = tmp_dir.path().as_os_str().to_str().unwrap();

    // test just to see how "read_dir" works in Rust
    for entry in fs::read_dir(plugin_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        log::info!("read_dir: {:?}", path);
    }

    let id = random_manager::secure_string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

version: 3


id: {id}

aad_tag: test

resource:
  regions:
  - us-west-2
  s3_bucket: {bucket}
  use_spot_instance: false

machine:
  total_non_anchor_nodes: 1
  arch_type: amd64
  os_type: ubuntu20.04
  volume_size_in_gb: 500
  instance_mode: spot
  ip_mode: elastic

  regional_machines:
    us-west-2:
      non_anchor_nodes: 1
      instance_types:
      - m5.large
      - c5.large
      - r5.large
      - t3.large

upload_artifacts:
  avalanched_local_bin: {avalanched_bin}
  avalanche_config_local_bin: {avalanche_config_bin}
  avalanchego_local_bin: {avalanchego_bin}
avalanchego_release_tag: latest

avalanched_config:
  log_level: info
  use_default_config: false
  publish_periodic_node_info: false


keep_resources_except_asg_ssm: false
create_dev_machine: false

enable_nlb: false
disable_logs_auto_removal: false
metrics_fetch_interval_seconds: 5000

primary_network_validate_period_in_days: 25

avalanchego_config:
  config-file: /data/avalanche-configs/config.json
  network-id: 1
  db-type: leveldb
  db-dir: /data/db
  chain-data-dir: /data/chainData
  log-dir: /var/log/avalanchego
  log-level: INFO
  log-format: json
  http-port: 9650
  http-host: 0.0.0.0
  http-tls-enabled: false
  staking-enabled: true
  staking-port: 9651
  staking-tls-key-file: "/data/staking.key"
  staking-tls-cert-file: "/data/staking.crt"
  staking-signer-key-file: "/data/staking-signer.bls.key"
  snow-sample-size: 20
  snow-quorum-size: 15
  index-enabled: false
  index-allow-incomplete: false
  api-admin-enabled: false
  api-info-enabled: true
  api-keystore-enabled: false
  api-metrics-enabled: true
  api-health-enabled: true
  api-ipcs-enabled: false
  chain-config-dir: /data/avalanche-configs/chains
  subnet-config-dir: /data/avalanche-configs/subnets
  profile-dir: /var/log/avalanchego-profile/avalanche
  proposervm-use-current-height: true
  throttler-inbound-at-large-alloc-size: 6291456
  throttler-inbound-bandwidth-max-burst-size: 1073741824
  throttler-inbound-bandwidth-refill-rate: 1073741824
  throttler-inbound-cpu-validator-alloc: 100000
  throttler-inbound-disk-validator-alloc: 10737418240000
  throttler-inbound-node-max-at-large-bytes: 2097152
  throttler-inbound-node-max-processing-msgs: 100000

  throttler-outbound-at-large-alloc-size: 33550000
  throttler-outbound-validator-alloc-size: 33550000
  throttler-outbound-node-max-at-large-bytes: 2097152

  snow-mixed-query-num-push-vdr: 10
  consensus-gossip-frequency: 10000000000
  consensus-app-concurrency: 2
  consensus-on-accept-gossip-validator-size: 0
  consensus-on-accept-gossip-non-validator-size: 0
  consensus-on-accept-gossip-peer-size: 10
  consensus-accepted-frontier-gossip-peer-size: 10
  network-compression-type: gzip

coreth_chain_config:
  coreth-admin-api-enabled: true
  offline-pruning-enabled: false
  offline-pruning-data-directory: /data/c-chain-offline-pruning
  metrics-enabled: true
  pruning-enabled: true
  log-level: "info"
  log-json-format: true
  state-sync-enabled: true
  eth-apis:
  - eth
  - eth-filter
  - net
  - web3
  - internal-eth
  - internal-blockchain
  - internal-transaction

"#
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    let config_path = f.path().to_str().unwrap();

    let cfg = Spec::load(config_path).unwrap();

    cfg.sync(config_path).unwrap();

    let mut regional_machines = BTreeMap::new();
    regional_machines.insert(
        "us-west-2".to_string(),
        RegionalMachine {
            anchor_nodes: None,
            non_anchor_nodes: 1,
            instance_types: vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ],
        },
    );

    let avalanchego_config = avalanchego_config::Config::default_main();
    let orig = Spec {
        version: VERSION,

        id: id.clone(),
        aad_tag: String::from("test"),
        profile_name: String::from("default"),

        resource: Resource {
            regions: vec![String::from("us-west-2")],
            s3_bucket: bucket.clone(),
            ..Resource::default()
        },

        machine: Machine {
            total_anchor_nodes: None,
            total_non_anchor_nodes: 1,

            arch_type: "amd64".to_string(),
            os_type: "ubuntu20.04".to_string(),

            instance_mode: String::from("spot"),
            ip_mode: String::from("elastic"),
            volume_size_in_gb: 500,
            regional_machines,
        },

        upload_artifacts: Some(UploadArtifacts {
            avalanched_local_bin: avalanched_bin.to_string(),

            aws_volume_provisioner_local_bin: String::new(),
            aws_ip_provisioner_local_bin: String::new(),
            avalanche_telemetry_cloudwatch_local_bin: String::new(),

            avalanchego_local_bin: avalanchego_bin.to_string(),

            prometheus_metrics_rules_file_path: String::new(),
        }),
        avalanchego_release_tag: Some(String::from("latest")),

        avalanched_config: crate::aws::avalanched::Flags {
            log_level: String::from("info"),
            use_default_config: false,
            publish_periodic_node_info: Some(false),
        },

        keep_resources_except_asg_ssm: false,
        create_dev_machine: false,
        dev_machine: None,

        enable_nlb: false,
        disable_logs_auto_removal: false,
        metrics_fetch_interval_seconds: 5000,
        primary_network_validate_period_in_days: 25,

        prefunded_keys: None,

        avalanchego_config,
        coreth_chain_config: coreth_chain_config::Config::default(),
        avalanchego_genesis_template: None,
    };

    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.aad_tag, "test");

    assert_eq!(cfg.resource.regions[0], "us-west-2");
    assert_eq!(cfg.resource.s3_bucket, bucket);

    assert_eq!(
        cfg.upload_artifacts.clone().unwrap().avalanched_local_bin,
        avalanched_bin
    );
    assert_eq!(
        cfg.upload_artifacts.clone().unwrap().avalanchego_local_bin,
        avalanchego_bin
    );

    assert!(cfg.machine.total_anchor_nodes.is_none());
    assert_eq!(cfg.machine.total_non_anchor_nodes, 1);
    let regional_machine = cfg.machine.regional_machines.get("us-west-2").unwrap();
    assert_eq!(regional_machine.instance_types[0], "m5.large");
    assert_eq!(regional_machine.instance_types[1], "c5.large");
    assert_eq!(regional_machine.instance_types[2], "r5.large");
    assert_eq!(regional_machine.instance_types[3], "t3.large");

    assert_eq!(cfg.avalanchego_config.clone().network_id, 1);
    assert_eq!(
        cfg.avalanchego_config
            .clone()
            .config_file
            .unwrap_or("".to_string()),
        avalanchego_config::DEFAULT_CONFIG_FILE_PATH,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().snow_sample_size.unwrap_or(0),
        20
    );
    assert_eq!(
        cfg.avalanchego_config.clone().snow_quorum_size.unwrap_or(0),
        15
    );
    assert_eq!(
        cfg.avalanchego_config.clone().http_port,
        avalanchego_config::DEFAULT_HTTP_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().staking_port,
        avalanchego_config::DEFAULT_STAKING_PORT,
    );
    assert_eq!(
        cfg.avalanchego_config.clone().db_dir,
        avalanchego_config::DEFAULT_DB_DIR,
    );
}

/// Represents each anchor/non-anchor node.
/// "camelCase" to be consistent with "ProofOfPossession".
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub region: String,
    pub kind: String,
    pub machine_id: String,
    pub node_id: String,
    pub proof_of_possession: key::bls::ProofOfPossession,
    /// Overwrites with the persistent elastic IP
    /// if provisioned and mounted via EBS.
    pub public_ip: String,
    pub http_endpoint: String,
}

impl Node {
    pub fn new(
        region: &str,
        kind: node::Kind,
        machine_id: &str,
        node_id: &str,
        public_ip: &str,
        http_scheme: &str,
        http_port: u32,
        public_key: Vec<u8>,
        proof_of_possession: Vec<u8>,
    ) -> Self {
        let proof_of_possession =
            key::bls::ProofOfPossession::new(&public_key, &proof_of_possession).unwrap();
        Self {
            region: region.to_owned(),
            kind: String::from(kind.as_str()),
            machine_id: String::from(machine_id),
            node_id: node_id.to_string(),
            proof_of_possession,
            public_ip: String::from(public_ip),
            http_endpoint: format!("{}://{}:{}", http_scheme, public_ip, http_port),
        }
    }

    /// Converts to string with YAML encoder.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize to YAML {}", e),
            )),
        }
    }

    /// Saves the current anchor node to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing Node to '{}'", file_path);
        let path = Path::new(file_path);
        if let Some(parent_dir) = path.parent() {
            log::info!("creating parent dir '{}'", parent_dir.display());
            fs::create_dir_all(parent_dir)?;
        }

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Node info to YAML {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        log::info!("loading node from {}", file_path);

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

        let mut loaded: Self = serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))?;

        let pubkey = loaded.proof_of_possession.load_pubkey()?;
        loaded.proof_of_possession.pubkey = Some(pubkey);

        Ok(loaded)
    }

    /// Encodes the object in YAML format, compresses, and apply base58.
    /// Used for shortening S3 file name (s3 supports up to 1,024-byte key name).
    pub fn compress_base58(&self) -> io::Result<String> {
        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed serde_yaml::to_string {}", e),
            )
        })?;

        let compressed =
            compress_manager::pack(d.as_bytes(), compress_manager::Encoder::ZstdBase58(3))?;
        Ok(String::from_utf8(compressed).expect("unexpected None String::from_utf8"))
    }

    /// Reverse of "compress_base58" by decoding YAML.
    pub fn decompress_base58(d: String) -> io::Result<Self> {
        let decompressed =
            compress_manager::unpack(d.as_bytes(), compress_manager::Decoder::ZstdBase58)?;

        let mut loaded: Self = serde_yaml::from_slice(&decompressed)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))?;

        let pubkey = loaded.proof_of_possession.load_pubkey()?;
        loaded.proof_of_possession.pubkey = Some(pubkey);

        Ok(loaded)
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- aws::spec::test_node --exact --show-output
#[test]
fn test_node() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let d = r#"
region: ap-northeast-2
kind: anchor
machineId: i-123123

nodeId: NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx

proofOfPossession:
  publicKey: 0x8f95423f7142d00a48e1014a3de8d28907d420dc33b3052a6dee03a3f2941a393c2351e354704ca66a3fc29870282e15
  proofOfPossession: 0x86a3ab4c45cfe31cae34c1d06f212434ac71b1be6cfe046c80c162e057614a94a5bc9f1ded1a7029deb0ba4ca7c9b71411e293438691be79c2dbf19d1ca7c3eadb9c756246fc5de5b7b89511c7d7302ae051d9e03d7991138299b5ed6a570a98

publicIp: 1.2.3.4
httpEndpoint: http://1.2.3.4:9650

"#;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(d.as_bytes()).unwrap();
    let node_path = f.path().to_str().unwrap();

    let node = Node::load(node_path).unwrap();
    node.sync(node_path).unwrap();

    let orig = Node::new(
        "ap-northeast-2",
        node::Kind::Anchor,
        "i-123123",
        "NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx",
        "1.2.3.4",
        "http",
        9650,
        hex::decode("0x8f95423f7142d00a48e1014a3de8d28907d420dc33b3052a6dee03a3f2941a393c2351e354704ca66a3fc29870282e15".trim_start_matches("0x")).unwrap(),
        hex::decode("0x86a3ab4c45cfe31cae34c1d06f212434ac71b1be6cfe046c80c162e057614a94a5bc9f1ded1a7029deb0ba4ca7c9b71411e293438691be79c2dbf19d1ca7c3eadb9c756246fc5de5b7b89511c7d7302ae051d9e03d7991138299b5ed6a570a98".trim_start_matches("0x")).unwrap(),
    );
    assert_eq!(node, orig);

    // manually check to make sure the serde deserializer works
    assert_eq!(node.region, String::from("ap-northeast-2"));
    assert_eq!(node.kind, String::from("anchor"));
    assert_eq!(node.machine_id, String::from("i-123123"));
    assert_eq!(node.node_id, "NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx");
    assert_eq!(node.public_ip, String::from("1.2.3.4"));
    assert_eq!(node.http_endpoint, String::from("http://1.2.3.4:9650"));

    let encoded_yaml = node.encode_yaml().unwrap();
    log::info!("node.encode_yaml: {}", encoded_yaml);
    let compressed = node.compress_base58().unwrap();
    log::info!(
        "node.compress_base58: {} ({}-byte)",
        compressed,
        compressed.len()
    );
    let decompressed_node = Node::decompress_base58(compressed).unwrap();
    assert_eq!(node, decompressed_node);
}

/// Default machine anchor nodes size.
/// only required for custom networks
pub const DEFAULT_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MIN_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_ANCHOR_NODES: u32 = 100;

pub const MIN_MACHINE_NON_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_NON_ANCHOR_NODES: u32 = 500;
pub const DEFAULT_MACHINE_NON_ANCHOR_NODES: u32 = 1;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Endpoints {
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_rpc_c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metamask_rpc_c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_rpc_c: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self::default()
    }
}

impl Endpoints {
    pub fn default() -> Self {
        Self {
            http_rpc: None,
            http_rpc_x: None,
            http_rpc_p: None,
            http_rpc_c: None,
            metrics: None,
            health: None,
            liveness: None,
            metamask_rpc_c: None,
            websocket_rpc_c: None,
        }
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Endpoints to YAML {}", e),
            )),
        }
    }
}

/// Defines how the underlying infrastructure is set up.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_anchor_nodes: Option<u32>,
    #[serde(default)]
    pub total_non_anchor_nodes: u32,

    #[serde(default)]
    pub arch_type: String,
    #[serde(default)]
    pub os_type: String,

    /// Either "spot" or "on-demand".
    #[serde(default)]
    pub instance_mode: String,

    /// Either "elastic" or "ephemeral".
    #[serde(default)]
    pub ip_mode: String,

    /// Initial EBS volume size in GB.
    /// Can be resized with no downtime.
    /// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html
    #[serde(default)]
    pub volume_size_in_gb: u32,

    #[serde(default)]
    pub regional_machines: BTreeMap<String, RegionalMachine>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DevMachine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_email: Option<String>,

    #[serde(default)]
    pub arch_type: String,
    #[serde(default)]
    pub os_type: String,

    /// Either "spot" or "on-demand".
    #[serde(default)]
    pub instance_mode: String,

    /// Either "elastic" or "ephemeral".
    #[serde(default)]
    pub ip_mode: String,

    /// Initial EBS volume size in GB.
    /// Can be resized with no downtime.
    /// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html
    #[serde(default)]
    pub volume_size_in_gb: u32,

    #[serde(default)]
    pub instance_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RegionalMachine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_nodes: Option<u32>,
    #[serde(default)]
    pub non_anchor_nodes: u32,
    #[serde(default)]
    pub instance_types: Vec<String>,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UploadArtifacts {
    #[serde(default)]
    pub avalanched_local_bin: String,

    #[serde(default)]
    pub aws_volume_provisioner_local_bin: String,
    #[serde(default)]
    pub aws_ip_provisioner_local_bin: String,
    #[serde(default)]
    pub avalanche_telemetry_cloudwatch_local_bin: String,

    /// AvalancheGo binary path in the local environment.
    /// The file is "compressed" and uploaded to remote storage
    /// to be shared with remote machines.
    ///
    ///  build
    ///    ├── avalanchego (the binary from compiling the app directory)
    ///    └── plugin
    ///        └── evm
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanchego_local_bin: String,

    #[serde(default)]
    pub prometheus_metrics_rules_file_path: String,
}

impl Default for UploadArtifacts {
    fn default() -> Self {
        Self::default()
    }
}

impl UploadArtifacts {
    pub fn default() -> Self {
        Self {
            avalanched_local_bin: String::new(),
            aws_volume_provisioner_local_bin: String::new(),
            aws_ip_provisioner_local_bin: String::new(),
            avalanche_telemetry_cloudwatch_local_bin: String::new(),
            avalanchego_local_bin: String::new(),
            prometheus_metrics_rules_file_path: String::new(),
        }
    }
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String, String),
    Vpc(String),
    SsmInstallSubnetChain(String),
    DevMachine(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id, region) => format!("{id}-ec2-instance-role-{region}"),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::SsmInstallSubnetChain(id) => {
                format!("{id}-ssm-install-subnet-chain")
            }
            StackName::DevMachine(id) => format!("{}-dev-machine", id),
        }
    }
}

/// Represents the S3/storage key path.
/// MUST be kept in sync with "cfn-templates/ec2_instance_role.yaml".
pub enum StorageNamespace {
    ConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),

    /// Valid genesis file with initial stakers.
    /// Only updated after anchor nodes become active.
    GenesisFile(String),

    AvalanchedAwsBin(String),

    AwsVolumeProvisionerBin(String),
    AwsIpProvisionerBin(String),
    AvalancheTelemetryCloudwatchBin(String),

    AvalancheGoBin(String),

    PkiKeyDir(String),
    MetricsRules(String),

    /// before db downloads
    DiscoverProvisioningAnchorNodesDir(String),
    DiscoverProvisioningAnchorNode(String, Node),
    DiscoverProvisioningNonAnchorNodesDir(String),
    DiscoverProvisioningNonAnchorNode(String, Node),

    DiscoverBootstrappingAnchorNodesDir(String),
    DiscoverBootstrappingAnchorNode(String, Node),

    DiscoverReadyAnchorNodesDir(String),
    DiscoverReadyAnchorNode(String, Node),
    DiscoverReadyNonAnchorNodesDir(String),
    DiscoverReadyNonAnchorNode(String, Node),

    BackupsDir(String),

    /// If this "event" file has been modified for the last x-min,
    /// avalanched triggers updates events based on the install artifacts
    /// in "EventsUpdateArtifactsInstallDir"
    EventsUpdateArtifactsEvent(String),
    EventsUpdateArtifactsInstallDirPluginDir(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::ConfigFile(id) => format!("{}/avalanche-ops.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }

            StorageNamespace::GenesisFile(id) => format!("{}/genesis.json", id),

            StorageNamespace::AvalanchedAwsBin(id) => {
                format!("{}/bootstrap/install/avalanched-aws", id)
            }

            StorageNamespace::AwsVolumeProvisionerBin(id) => {
                format!("{}/bootstrap/install/aws-volume-provisioner", id)
            }
            StorageNamespace::AwsIpProvisionerBin(id) => {
                format!("{}/bootstrap/install/aws-ip-provisioner", id)
            }
            StorageNamespace::AvalancheTelemetryCloudwatchBin(id) => {
                format!("{}/bootstrap/install/avalanche-telemetry-cloudwatch", id)
            }

            StorageNamespace::AvalancheGoBin(id) => {
                format!("{}/bootstrap/install/avalanchego", id)
            }

            StorageNamespace::PkiKeyDir(id) => {
                format!("{}/pki", id)
            }
            StorageNamespace::MetricsRules(id) => {
                format!("{}/avalanche-telemetry-cloudwatch.rules.yaml", id)
            }

            StorageNamespace::DiscoverProvisioningAnchorNodesDir(id) => {
                format!("{}/discover/provisioning-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverProvisioningNonAnchorNodesDir(id) => {
                format!("{}/discover/provisioning-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverProvisioningNonAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/provisioning-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverBootstrappingAnchorNodesDir(id) => {
                format!("{}/discover/bootstrapping-anchor-nodes", id)
            }
            StorageNamespace::DiscoverBootstrappingAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/bootstrapping-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::DiscoverReadyAnchorNodesDir(id) => {
                format!("{}/discover/ready-anchor-nodes", id)
            }
            StorageNamespace::DiscoverReadyAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            StorageNamespace::DiscoverReadyNonAnchorNodesDir(id) => {
                format!("{}/discover/ready-non-anchor-nodes", id)
            }
            StorageNamespace::DiscoverReadyNonAnchorNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-non-anchor-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            StorageNamespace::BackupsDir(id) => {
                format!("{}/backups", id)
            }

            StorageNamespace::EventsUpdateArtifactsEvent(id) => {
                format!("{}/events/update-artifacts/event", id)
            }
            StorageNamespace::EventsUpdateArtifactsInstallDirPluginDir(id) => {
                format!("{}/events/update-artifacts/install/plugin", id)
            }
        }
    }

    pub fn parse_node_from_path(storage_path: &str) -> io::Result<Node> {
        let p = Path::new(storage_path);
        let file_name = match p.file_name() {
            Some(v) => v,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    String::from("failed Path.file_name (None)"),
                ));
            }
        };
        let file_name = file_name.to_str().unwrap();
        let splits: Vec<&str> = file_name.split('_').collect();
        if splits.len() != 2 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "file name {} of storage_path {} expected two splits for '_' (got {})",
                    file_name,
                    storage_path,
                    splits.len(),
                ),
            ));
        }

        let compressed_id = splits[1];
        match Node::decompress_base58(compressed_id.replace(".yaml", "")) {
            Ok(node) => {
                let pop = key::bls::ProofOfPossession::new(
                    &node.proof_of_possession.public_key,
                    &node.proof_of_possession.proof_of_possession,
                )?;

                let mut cloned = node;
                cloned.proof_of_possession = pop;

                Ok(cloned)
            }
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed node::Node::decompress_base58 {}", e),
            )),
        }
    }
}

/// RUST_LOG=debug cargo test --package avalanche-ops --lib -- aws::spec::test_storage_path --exact --show-output
#[test]
fn test_storage_path() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let id = random_manager::secure_string(10);
    let instance_id = random_manager::secure_string(5);
    let node_id = "NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx";
    let node_ip = "1.2.3.4";

    let node = Node::new(
        "ap-northeast-2",
        node::Kind::NonAnchor,
        &instance_id,
        node_id,
        node_ip,
        "http",
        9650,
        hex::decode("0x8f95423f7142d00a48e1014a3de8d28907d420dc33b3052a6dee03a3f2941a393c2351e354704ca66a3fc29870282e15".trim_start_matches("0x")).unwrap(),
        hex::decode("0x86a3ab4c45cfe31cae34c1d06f212434ac71b1be6cfe046c80c162e057614a94a5bc9f1ded1a7029deb0ba4ca7c9b71411e293438691be79c2dbf19d1ca7c3eadb9c756246fc5de5b7b89511c7d7302ae051d9e03d7991138299b5ed6a570a98".trim_start_matches("0x")).unwrap(),
    );

    let proof_of_possession = key::bls::ProofOfPossession::new(
        &hex::decode("0x8f95423f7142d00a48e1014a3de8d28907d420dc33b3052a6dee03a3f2941a393c2351e354704ca66a3fc29870282e15".trim_start_matches("0x")).unwrap(),
        &hex::decode("0x86a3ab4c45cfe31cae34c1d06f212434ac71b1be6cfe046c80c162e057614a94a5bc9f1ded1a7029deb0ba4ca7c9b71411e293438691be79c2dbf19d1ca7c3eadb9c756246fc5de5b7b89511c7d7302ae051d9e03d7991138299b5ed6a570a98".trim_start_matches("0x")).unwrap()
    ).unwrap();
    let p = StorageNamespace::DiscoverReadyNonAnchorNode(
        id,
        Node {
            region: "ap-northeast-2".to_string(),
            kind: String::from("non-anchor"),
            machine_id: instance_id,
            node_id: "NodeID-6ZmBHXTqjknJoZtXbnJ6x7af863rXDTwx".to_string(),
            proof_of_possession,
            public_ip: node_ip.to_string(),
            http_endpoint: format!("http://{}:9650", node_ip),
        },
    );
    let storage_path = p.encode();
    log::info!("KeyPath: {storage_path} ({}-byte)", storage_path.len());

    let node_parsed = StorageNamespace::parse_node_from_path(&storage_path).unwrap();
    assert_eq!(node, node_parsed);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct NodeInfo {
    pub local_node: Node,
    pub avalanchego_config: avalanchego_config::Config,
    pub coreth_chain_config: coreth_chain_config::Config,
}

impl NodeInfo {
    pub fn new(
        local_node: Node,
        avalanchego_config: avalanchego_config::Config,
        coreth_chain_config: coreth_chain_config::Config,
    ) -> Self {
        Self {
            local_node,
            avalanchego_config,
            coreth_chain_config,
        }
    }

    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        log::info!("syncing Info to '{file_path}'");
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let d = serde_json::to_vec(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize NodeInfo info to JSON {}", e),
            )
        })?;

        let mut f = File::create(file_path)?;
        f.write_all(&d)?;

        Ok(())
    }
}

fn get_ec2_key_path(spec_file_path: &str, region: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ec2-access.{region}.key", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

fn get_ssh_commands_path(spec_file_path: &str, region: &str, kind: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ssh-commands.{region}.{kind}.sh", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}

fn get_prometheus_metrics_rules_file_path(spec_file_path: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-prometheus-metrics-rules.yaml", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}
