use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    str::FromStr,
};

use avalanche_types::{
    avalanchego::{config as avalanchego_config, genesis as avalanchego_genesis},
    constants,
    coreth::chain_config as coreth_chain_config,
    key, node, subnet,
    subnet_evm::{chain_config as subnet_evm_chain_config, genesis as subnet_evm_genesis},
    xsvm::genesis as xsvm_genesis,
};
use aws_manager::kms;
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};

pub const VERSION: usize = 1;

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
    /// AWS resources if run in AWS.
    pub aws_resources: crate::aws::Resources,

    /// Defines how the underlying infrastructure is set up.
    /// MUST BE NON-EMPTY.
    pub machine: Machine,
    /// Install artifacts to share with remote machines.
    pub install_artifacts: InstallArtifacts,

    /// Flag to pass to the "avalanched" command-line interface.
    pub avalanched_config: crate::avalanched::Flags,

    /// Set "true" to enable NLB.
    #[serde(default)]
    pub enable_nlb: bool,
    /// Set "true" to disable CloudWatch log auto removal.
    #[serde(default)]
    pub disable_logs_auto_removal: bool,

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

    /// Use sorted map in order to map each whitelisted subnet id (placeholder)
    /// to each subnet/chain configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_evms: Option<BTreeMap<String, SubnetEvm>>,
    /// Use sorted map in order to map each whitelisted subnet id (placeholder)
    /// to each subnet configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xsvms: Option<BTreeMap<String, Xsvm>>,
    #[serde(default)]
    pub xsvms_split_validators: bool,

    /// NOTE: Only required for custom networks with pre-funded wallets!
    /// These are used for custom primary network genesis generation and will be pre-funded.
    /// The first key will have locked P-chain balance with initial stake duration in genesis.
    /// Except the first key in the list, all keys have immediately unlocked P-chain balance.
    /// Should never be used for mainnet as it's store in plaintext for testing purposes only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_key_infos: Option<Vec<key::secp256k1::Info>>,

    /// Created nodes at the start of the network.
    /// May become stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_nodes: Option<Vec<Node>>,
    /// Created endpoints at the start of the network.
    /// May become stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_endpoints: Option<Endpoints>,

    /// Interval in seconds to fetch system and avalanche node metrics.
    /// Set to 0 to disable metrics collection.
    #[serde(default)]
    pub metrics_fetch_interval_seconds: u64,

    /// Prometheus rules for telemetry.
    /// "avalanched" reads this metrics and writes to disk (ALWAYS OVERWRITE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prometheus_metrics_rules: Option<prometheus_manager::Rules>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SubnetEvm {
    pub genesis: subnet_evm_genesis::Genesis,
    pub chain_config: subnet_evm_chain_config::Config,
    pub subnet_config: subnet::config::Config,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Xsvm {
    pub genesis: xsvm_genesis::Genesis,
    pub subnet_config: subnet::config::Config,
}

/// Defines "default-spec" option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DefaultSpecOption {
    pub log_level: String,
    pub network_name: String,

    pub key_files_dir: String,
    pub keys_to_generate: usize,
    pub keys_to_generate_type: String,

    pub region: String,
    pub preferred_az_index: usize,
    pub instance_mode: String,
    pub disable_spot_instance_for_anchor_nodes: bool,
    pub volume_size_in_gb: u32,

    pub ip_mode: String,

    pub enable_nlb: bool,
    pub disable_logs_auto_removal: bool,
    pub metrics_fetch_interval_seconds: u64,

    pub aad_tag: String,

    pub nlb_acm_certificate_arn: String,

    pub install_artifacts_aws_volume_provisioner_local_bin: String,
    pub install_artifacts_aws_ip_provisioner_local_bin: String,
    pub install_artifacts_avalanche_telemetry_cloudwatch_local_bin: String,
    pub install_artifacts_avalanche_config_local_bin: String,
    pub install_artifacts_avalanched_local_bin: String,
    pub install_artifacts_avalanche_local_bin: String,
    pub install_artifacts_plugins_local_dir: String,

    pub avalanched_log_level: String,
    pub avalanched_use_default_config: bool,
    pub avalanched_publish_periodic_node_info: bool,

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

    pub subnet_evms: usize,

    pub subnet_evm_gas_limit: u64,
    pub subnet_evm_min_max_gas_cost: u64,

    pub subnet_evm_auto_contract_deployer_allow_list_config: bool,
    pub subnet_evm_auto_contract_native_minter_config: bool,
    pub subnet_evm_auto_fee_manager_config: bool,
    pub subnet_evm_config_proposer_min_block_delay_seconds: u64,

    pub xsvms: usize,
    pub xsvms_split_validators: bool,

    pub spec_file_path: String,
}

pub const ARCH_AMD64: &str = "amd64";
pub const ARCH_ARM64: &str = "arm64";

lazy_static! {
    /// Avalanche consensus paper used "c5.large" for testing 125 ~ 2,000 nodes
    /// Avalanche test net ("fuji") runs "c5.2xlarge"
    ///
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
    ///
    pub static ref DEFAULT_EC2_INSTANCE_TYPES_AMD64: Vec<String> = vec![
        String::from("c6a.xlarge"),
        String::from("m6a.xlarge"),
        String::from("m5.xlarge"),
        String::from("c5.xlarge"),
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
        String::from("c6g.xlarge"),
        String::from("m6g.xlarge"),
        String::from("r6g.xlarge"),
        String::from("t4g.xlarge"),
    ];
}

pub fn default_prometheus_rules() -> prometheus_manager::Rules {
    #[derive(RustEmbed)]
    #[folder = "artifacts/"]
    #[prefix = "artifacts/"]
    struct Asset;

    let filters_raw = Asset::get("artifacts/default.metrics.rules.yaml").unwrap();
    let filters_raw = std::str::from_utf8(filters_raw.data.as_ref()).unwrap();
    serde_yaml::from_str(filters_raw).unwrap()
}

impl Spec {
    /// Creates a default spec.
    pub async fn default_aws(opts: DefaultSpecOption) -> Self {
        let network_id = match constants::NETWORK_NAME_TO_NETWORK_ID.get(opts.network_name.as_str())
        {
            Some(v) => *v,
            None => constants::DEFAULT_CUSTOM_NETWORK_ID,
        };

        let mut avalanched_config = crate::avalanched::Flags {
            log_level: opts.avalanched_log_level,
            use_default_config: opts.avalanched_use_default_config,
            publish_periodic_node_info: None,
        };
        if opts.avalanched_publish_periodic_node_info {
            avalanched_config.publish_periodic_node_info = Some(true);
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
        let id = {
            if !opts.spec_file_path.is_empty() {
                let spec_file_stem = Path::new(&opts.spec_file_path).file_stem().unwrap();
                spec_file_stem.to_str().unwrap().to_string()
            } else {
                match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                    Some(v) => id_manager::time::with_prefix(format!("aops-{}", *v).as_str()),
                    None => id_manager::time::with_prefix("aops-custom"),
                }
            }
        };
        let (anchor_nodes, non_anchor_nodes) =
            match constants::NETWORK_ID_TO_NETWORK_NAME.get(&network_id) {
                // non-custom network only single node to utilize single AZ
                Some(_) => (None, 1),

                // custom network
                None => (
                    Some(DEFAULT_MACHINE_ANCHOR_NODES),
                    DEFAULT_MACHINE_NON_ANCHOR_NODES,
                ),
            };

        if !opts.key_files_dir.is_empty() {
            log::info!("creating key-files-dir '{}'", opts.key_files_dir);
            fs::create_dir_all(&opts.key_files_dir).unwrap();
        }

        let key_type = key::secp256k1::KeyType::from_str(&opts.keys_to_generate_type).unwrap();
        match key_type {
            key::secp256k1::KeyType::Hot => log::info!("generating hot keys..."),
            key::secp256k1::KeyType::AwsKms => log::info!("generating AWS KMS CMKs..."),
            _ => panic!("unknown key type {}", key_type),
        }
        if key_type == key::secp256k1::KeyType::AwsKms && opts.keys_to_generate > 2 {
            panic!(
                "key::secp256k1::KeyType::AwsKms only supported up to 2 keys, got {}",
                opts.keys_to_generate
            );
        }

        let mut test_keys_infos: Vec<key::secp256k1::Info> = Vec::new();
        let mut test_keys_read_only: Vec<key::secp256k1::public_key::Key> = Vec::new();
        for i in 0..opts.keys_to_generate {
            let (key_info, key_read_only) = {
                match key_type {
                    key::secp256k1::KeyType::Hot => {
                        if i < key::secp256k1::TEST_KEYS.len() {
                            (
                                key::secp256k1::TEST_KEYS[i].to_info(network_id).unwrap(),
                                key::secp256k1::TEST_KEYS[i].to_public_key(),
                            )
                        } else {
                            let k = key::secp256k1::private_key::Key::generate().unwrap();
                            (k.to_info(network_id).unwrap(), k.to_public_key())
                        }
                    }

                    key::secp256k1::KeyType::AwsKms => {
                        let shared_config = aws_manager::load_config(Some(opts.region.clone()))
                            .await
                            .unwrap();

                        let kms_manager = kms::Manager::new(&shared_config);

                        let cmk = key::secp256k1::kms::aws::Cmk::create(
                            kms_manager.clone(),
                            &format!("{id}-cmk-{i}"),
                        )
                        .await
                        .unwrap();

                        let cmk_info = cmk.to_info(network_id).unwrap();
                        println!("cmk_info: {}", cmk_info);

                        (cmk_info, cmk.to_public_key())
                    }

                    _ => panic!("unknown key type {}", key_type),
                }
            };
            test_keys_infos.push(key_info.clone());
            test_keys_read_only.push(key_read_only);

            if key_type == key::secp256k1::KeyType::Hot && !opts.key_files_dir.is_empty() {
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
                let g = avalanchego_genesis::Genesis::new(network_id, &test_keys_read_only)
                    .expect("unexpected None genesis");
                Some(g)
            } else {
                None
            }
        };

        let subnet_evms = {
            if opts.subnet_evms > 0 {
                let mut genesis = subnet_evm_genesis::Genesis::new(&test_keys_read_only)
                    .expect("failed to generate genesis");

                let mut admin_addresses: Vec<String> = Vec::new();
                for key_info in test_keys_infos.iter() {
                    admin_addresses.push(key_info.eth_address.clone());
                }

                let mut chain_config = subnet_evm_genesis::ChainConfig::default();
                if opts.subnet_evm_gas_limit > 0 {
                    let mut fee_config = subnet_evm_genesis::FeeConfig::default();
                    fee_config.gas_limit = Some(opts.subnet_evm_gas_limit);
                    chain_config.fee_config = Some(fee_config);

                    genesis.gas_limit = primitive_types::U256::from(opts.subnet_evm_gas_limit);
                }
                if opts.subnet_evm_min_max_gas_cost > 0 {
                    if let Some(chain_config_fee_config) = &chain_config.fee_config {
                        let mut chain_config_fee_config = chain_config_fee_config.clone();
                        chain_config_fee_config.min_block_gas_cost =
                            Some(opts.subnet_evm_min_max_gas_cost);
                        chain_config_fee_config.max_block_gas_cost =
                            Some(opts.subnet_evm_min_max_gas_cost);
                        chain_config.fee_config = Some(chain_config_fee_config);
                    }
                }
                if opts.subnet_evm_auto_contract_deployer_allow_list_config {
                    chain_config.contract_deployer_allow_list_config =
                        Some(subnet_evm_genesis::ContractDeployerAllowListConfig {
                            allow_list_admins: Some(admin_addresses.clone()),
                            ..subnet_evm_genesis::ContractDeployerAllowListConfig::default()
                        });
                }
                if opts.subnet_evm_auto_contract_native_minter_config {
                    chain_config.contract_native_minter_config =
                        Some(subnet_evm_genesis::ContractNativeMinterConfig {
                            allow_list_admins: Some(admin_addresses.clone()),
                            ..subnet_evm_genesis::ContractNativeMinterConfig::default()
                        });
                }
                if opts.subnet_evm_auto_fee_manager_config {
                    chain_config.fee_manager_config = Some(subnet_evm_genesis::FeeManagerConfig {
                        allow_list_admins: Some(admin_addresses),
                        ..subnet_evm_genesis::FeeManagerConfig::default()
                    });
                }
                genesis.config = Some(chain_config);

                let chain_config = subnet_evm_chain_config::Config::default();
                let mut subnet_config = subnet::config::Config::default();
                if opts.subnet_evm_config_proposer_min_block_delay_seconds > 0 {
                    subnet_config.proposer_min_block_delay = opts
                        .subnet_evm_config_proposer_min_block_delay_seconds
                        * 1000
                        * 1000
                        * 1000;
                }

                let subnet_evm = SubnetEvm {
                    genesis,
                    chain_config,
                    subnet_config,
                };
                let mut subnet_evms = BTreeMap::new();
                for i in 0..opts.subnet_evms {
                    subnet_evms.insert(
                        format!("{}{}", i + 1, random_manager::string(5)),
                        subnet_evm.clone(),
                    );
                }
                Some(subnet_evms)
            } else {
                None
            }
        };

        let xsvms = {
            if opts.xsvms > 0 {
                let genesis = xsvm_genesis::Genesis::new(&test_keys_read_only)
                    .expect("failed to generate genesis");

                let mut subnet_config = subnet::config::Config::default();
                if opts.subnet_evm_config_proposer_min_block_delay_seconds > 0 {
                    subnet_config.proposer_min_block_delay = opts
                        .subnet_evm_config_proposer_min_block_delay_seconds
                        * 1000
                        * 1000
                        * 1000;
                }

                let xsvm = Xsvm {
                    genesis,
                    subnet_config,
                };
                let mut xsvms = BTreeMap::new();
                for i in 0..opts.xsvms {
                    xsvms.insert(
                        format!("{}{}", i + 1, random_manager::string(5)),
                        xsvm.clone(),
                    );
                }
                Some(xsvms)
            } else {
                None
            }
        };

        // [year][month][date]-[system host-based id]
        let s3_bucket = format!(
            "avalanche-ops-{}-{}-{}",
            id_manager::time::timestamp(6),
            id_manager::system::string(10),
            opts.region
        );
        let mut aws_resources = crate::aws::Resources {
            region: opts.region,
            s3_bucket,
            ..crate::aws::Resources::default()
        };
        if !opts.nlb_acm_certificate_arn.is_empty() {
            aws_resources.nlb_acm_certificate_arn = Some(opts.nlb_acm_certificate_arn);
        }
        let mut kms_cmk_secp256k1_cmks = Vec::new();
        for test_key_info in test_keys_infos.iter() {
            if test_key_info.key_type == key::secp256k1::KeyType::AwsKms {
                kms_cmk_secp256k1_cmks.push(crate::aws::KmsCmk {
                    id: test_key_info.id.clone().unwrap(),
                    arn: test_key_info.id.clone().unwrap(),
                })
            }
        }
        if !kms_cmk_secp256k1_cmks.is_empty() {
            aws_resources.kms_cmk_secp256k1_cmks = Some(kms_cmk_secp256k1_cmks);
        }

        let mut install_artifacts = InstallArtifacts {
            aws_volume_provisioner_local_bin: None,
            aws_volume_provisioner_bin_install_from_s3: None,

            aws_ip_provisioner_local_bin: None,
            aws_ip_provisioner_bin_install_from_s3: None,

            avalanche_telemetry_cloudwatch_local_bin: None,
            avalanche_telemetry_cloudwatch_bin_install_from_s3: None,

            avalanche_config_local_bin: None,
            avalanche_config_bin_install_from_s3: None,

            avalanched_local_bin: None,
            avalanched_bin_install_from_s3: None,

            avalanchego_local_bin: None,
            avalanchego_bin_install_from_s3: None,

            plugins_local_dir: None,
            plugins_dir_install_from_s3: None,
        };
        if !opts
            .install_artifacts_aws_volume_provisioner_local_bin
            .is_empty()
        {
            install_artifacts.aws_volume_provisioner_local_bin =
                Some(opts.install_artifacts_aws_volume_provisioner_local_bin);
            install_artifacts.aws_volume_provisioner_bin_install_from_s3 = Some(true);
        }
        if !opts
            .install_artifacts_aws_ip_provisioner_local_bin
            .is_empty()
        {
            install_artifacts.aws_ip_provisioner_local_bin =
                Some(opts.install_artifacts_aws_ip_provisioner_local_bin);
            install_artifacts.aws_ip_provisioner_bin_install_from_s3 = Some(true);
        }
        if !opts
            .install_artifacts_avalanche_telemetry_cloudwatch_local_bin
            .is_empty()
        {
            install_artifacts.avalanche_telemetry_cloudwatch_local_bin =
                Some(opts.install_artifacts_avalanche_telemetry_cloudwatch_local_bin);
            install_artifacts.avalanche_telemetry_cloudwatch_bin_install_from_s3 = Some(true);
        }
        if !opts.install_artifacts_avalanche_config_local_bin.is_empty() {
            install_artifacts.avalanche_config_local_bin =
                Some(opts.install_artifacts_avalanche_config_local_bin);
            install_artifacts.avalanche_config_bin_install_from_s3 = Some(true);
        }
        if !opts.install_artifacts_avalanched_local_bin.is_empty() {
            install_artifacts.avalanched_local_bin =
                Some(opts.install_artifacts_avalanched_local_bin);
            install_artifacts.avalanched_bin_install_from_s3 = Some(true);
        }
        if !opts.install_artifacts_avalanche_local_bin.is_empty() {
            install_artifacts.avalanchego_local_bin =
                Some(opts.install_artifacts_avalanche_local_bin);
            install_artifacts.avalanchego_bin_install_from_s3 = Some(true);
        }
        if !opts.install_artifacts_plugins_local_dir.is_empty() {
            install_artifacts.plugins_local_dir = Some(opts.install_artifacts_plugins_local_dir);
            install_artifacts.plugins_dir_install_from_s3 = Some(true);
        }

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
        } else {
            if avalanchego_config.is_mainnet() {
                if state_sync_enabled {
                    500
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
            } else {
                if state_sync_enabled {
                    200
                } else {
                    400
                }
            }
        };

        let machine = Machine {
            anchor_nodes,
            non_anchor_nodes,

            // TODO: support "arm64"
            arch: ARCH_AMD64.to_string(),
            instance_types: DEFAULT_EC2_INSTANCE_TYPES_AMD64.to_vec(),

            instance_mode: opts.instance_mode,
            disable_spot_instance_for_anchor_nodes: opts.disable_spot_instance_for_anchor_nodes,
            ip_mode: opts.ip_mode,

            volume_size_in_gb,
        };

        Self {
            version: VERSION,

            id,
            aad_tag: opts.aad_tag,

            aws_resources,
            machine,
            install_artifacts,

            avalanched_config,

            enable_nlb: opts.enable_nlb,
            disable_logs_auto_removal: opts.disable_logs_auto_removal,

            avalanchego_config,
            coreth_chain_config,
            avalanchego_genesis_template,

            subnet_evms,
            xsvms,
            xsvms_split_validators: opts.xsvms_split_validators,

            test_key_infos: Some(test_keys_infos),

            created_nodes: None,
            created_endpoints: None,

            metrics_fetch_interval_seconds: opts.metrics_fetch_interval_seconds,
            prometheus_metrics_rules: Some(default_prometheus_rules()),
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

        let d = serde_yaml::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec info to YAML {}", e),
            )
        })?;

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

        if self.aws_resources.region.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "'machine.region' cannot be empty",
            ));
        }

        if self.machine.non_anchor_nodes < MIN_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} <minimum {}",
                    self.machine.non_anchor_nodes, MIN_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if self.machine.non_anchor_nodes > MAX_MACHINE_NON_ANCHOR_NODES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' {} >maximum {}",
                    self.machine.non_anchor_nodes, MAX_MACHINE_NON_ANCHOR_NODES
                ),
            ));
        }
        if !self.avalanchego_config.is_custom_network() && self.machine.non_anchor_nodes != 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.non_anchor_nodes' must be 1 (set to {}) in order to maximize the benefit of static EBS provision per AZ",
                    self.machine.non_anchor_nodes
                ),
            ));
        }

        if let Some(v) = &self.install_artifacts.aws_volume_provisioner_local_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("aws_volume_provisioner_bin {} does not exist", v),
                ));
            }
        }
        if let Some(v) = &self.install_artifacts.aws_ip_provisioner_local_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("aws_ip_provisioner_bin {} does not exist", v),
                ));
            }
        }

        if let Some(v) = &self.install_artifacts.avalanched_local_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanched_bin {} does not exist", v),
                ));
            }
        }
        if let Some(v) = &self.install_artifacts.avalanchego_local_bin {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("avalanchego_bin {} does not exist", v),
                ));
            }
        }
        if let Some(v) = &self.install_artifacts.plugins_local_dir {
            if !Path::new(v).exists() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("plugins_dir {} does not exist", v),
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
            if self.machine.anchor_nodes.unwrap_or(0) > 0 {
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
            if self.machine.anchor_nodes.unwrap_or(0) == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "cannot specify 0 for 'machine.anchor_nodes' for custom network",
                ));
            }
            if self.machine.anchor_nodes.unwrap_or(0) < MIN_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.anchor_nodes' {} below min {}",
                        self.machine.anchor_nodes.unwrap_or(0),
                        MIN_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
            if self.machine.anchor_nodes.unwrap_or(0) > MAX_MACHINE_ANCHOR_NODES {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "'machine.anchor_nodes' {} exceeds limit {}",
                        self.machine.anchor_nodes.unwrap_or(0),
                        MAX_MACHINE_ANCHOR_NODES
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package avalancheup-aws --lib -- spec::test_spec --exact --show-output
#[test]
fn test_spec() {
    use std::fs;
    let _ = env_logger::builder().is_test(true).try_init();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanche_config_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanched_bin = f.path().to_str().unwrap();

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let avalanchego_bin = f.path().to_str().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let plugin_path = tmp_dir.path().join(random_manager::string(10));
    let mut f = File::create(&plugin_path).unwrap();
    let ret = f.write_all(&vec![0]);
    assert!(ret.is_ok());
    let plugins_dir = tmp_dir.path().as_os_str().to_str().unwrap();

    // test just to see how "read_dir" works in Rust
    for entry in fs::read_dir(plugins_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        log::info!("read_dir: {:?}", path);
    }

    let id = random_manager::string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

version: 1


id: {}

aad_tag: test

aws_resources:
  region: us-west-2
  preferred_az_index: 2
  use_spot_instance: false
  disable_spot_instance_for_anchor_nodes: false
  s3_bucket: {}

machine:
  non_anchor_nodes: 1
  arch: amd64
  instance_types:
  - m5.large
  - c5.large
  - r5.large
  - t3.large
  volume_size_in_gb: 500
  instance_mode: spot
  ip_mode: elastic

install_artifacts:
  avalanche_config_local_bin: {}
  avalanche_config_bin_install_from_s3: true
  avalanched_local_bin: {}
  avalanched_bin_install_from_s3: true
  avalanchego_local_bin: {}
  avalanchego_bin_install_from_s3: true
  plugins_local_dir: {}
  plugins_dir_install_from_s3: true

avalanched_config:
  log_level: info
  use_default_config: false
  publish_periodic_node_info: false

enable_nlb: false
disable_logs_auto_removal: false

avalanchego_config:
  config-file: /data/avalanche-configs/config.json
  network-id: 1
  db-type: leveldb
  db-dir: /data
  log-dir: /var/log/avalanche
  log-level: INFO
  log-format: json
  http-port: 9650
  http-host: 0.0.0.0
  http-tls-enabled: false
  staking-enabled: true
  staking-port: 9651
  staking-tls-key-file: "/data/staking.key"
  staking-tls-cert-file: "/data/staking.crt"
  snow-sample-size: 20
  snow-quorum-size: 15
  index-enabled: false
  index-allow-incomplete: false
  api-admin-enabled: true
  api-info-enabled: true
  api-keystore-enabled: true
  api-metrics-enabled: true
  api-health-enabled: true
  api-ipcs-enabled: true
  chain-config-dir: /data/avalanche-configs/chains
  subnet-config-dir: /data/avalanche-configs/subnets
  profile-dir: /var/log/avalanche-profile/avalanche
  throttler-inbound-node-max-at-large-bytes: 2097152
  throttler-inbound-at-large-alloc-size: 6291456

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

metrics_fetch_interval_seconds: 5000

"#,
        id, bucket, avalanche_config_bin, avalanched_bin, avalanchego_bin, plugins_dir,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let cfg = Spec::load(config_path).unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let avalanchego_config = avalanchego_config::Config::default_main();
    let orig = Spec {
        version: VERSION,

        id: id.clone(),
        aad_tag: String::from("test"),

        aws_resources: crate::aws::Resources {
            region: String::from("us-west-2"),
            preferred_az_index: 2,
            s3_bucket: bucket.clone(),
            ..crate::aws::Resources::default()
        },

        machine: Machine {
            anchor_nodes: None,
            non_anchor_nodes: 1,
            arch: "amd64".to_string(),
            instance_types: vec![
                String::from("m5.large"),
                String::from("c5.large"),
                String::from("r5.large"),
                String::from("t3.large"),
            ],
            instance_mode: String::from("spot"),
            disable_spot_instance_for_anchor_nodes: false,
            ip_mode: String::from("elastic"),
            volume_size_in_gb: 500,
        },

        install_artifacts: InstallArtifacts {
            aws_volume_provisioner_local_bin: None,
            aws_volume_provisioner_bin_install_from_s3: None,
            aws_ip_provisioner_local_bin: None,
            aws_ip_provisioner_bin_install_from_s3: None,
            avalanche_telemetry_cloudwatch_local_bin: None,
            avalanche_telemetry_cloudwatch_bin_install_from_s3: None,
            avalanche_config_local_bin: Some(avalanche_config_bin.to_string()),
            avalanche_config_bin_install_from_s3: Some(true),
            avalanched_local_bin: Some(avalanched_bin.to_string()),
            avalanched_bin_install_from_s3: Some(true),
            avalanchego_local_bin: Some(avalanchego_bin.to_string()),
            avalanchego_bin_install_from_s3: Some(true),
            plugins_local_dir: Some(plugins_dir.to_string()),
            plugins_dir_install_from_s3: Some(true),
        },

        avalanched_config: crate::avalanched::Flags {
            log_level: String::from("info"),
            use_default_config: false,
            publish_periodic_node_info: Some(false),
        },

        enable_nlb: false,
        disable_logs_auto_removal: false,
        metrics_fetch_interval_seconds: 5000,

        avalanchego_config,
        coreth_chain_config: coreth_chain_config::Config::default(),
        avalanchego_genesis_template: None,

        subnet_evms: None,
        xsvms: None,
        xsvms_split_validators: false,

        test_key_infos: None,
        created_nodes: None,
        created_endpoints: None,

        prometheus_metrics_rules: None,
    };

    // assert_eq!(cfg, orig);
    cfg.validate().expect("unexpected validate failure");
    orig.validate().expect("unexpected validate failure");

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.aad_tag, "test");

    assert_eq!(cfg.aws_resources.region, "us-west-2");
    assert_eq!(cfg.aws_resources.preferred_az_index, 2);
    assert_eq!(cfg.aws_resources.s3_bucket, bucket);

    assert_eq!(
        cfg.install_artifacts
            .avalanche_config_local_bin
            .unwrap_or(String::new()),
        avalanche_config_bin
    );
    assert_eq!(
        cfg.install_artifacts
            .avalanched_local_bin
            .unwrap_or(String::new()),
        avalanched_bin
    );
    assert_eq!(
        cfg.install_artifacts
            .avalanchego_local_bin
            .unwrap_or(String::new()),
        avalanchego_bin
    );
    assert_eq!(
        cfg.install_artifacts
            .plugins_local_dir
            .unwrap_or(String::new()),
        plugins_dir.to_string()
    );

    assert!(cfg.machine.anchor_nodes.is_none());
    assert_eq!(cfg.machine.non_anchor_nodes, 1);
    let instance_types = cfg.machine.instance_types;
    assert_eq!(instance_types[0], "m5.large");
    assert_eq!(instance_types[1], "c5.large");
    assert_eq!(instance_types[2], "r5.large");
    assert_eq!(instance_types[3], "t3.large");

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
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Node {
    pub kind: String,
    pub machine_id: String,
    pub node_id: String,

    /// Overwrites with the persistent elastic IP
    /// if provisioned and mounted via EBS.
    pub public_ip: String,

    pub http_endpoint: String,
}

impl Node {
    pub fn new(
        kind: node::Kind,
        machine_id: &str,
        node_id: &str,
        public_ip: &str,
        http_scheme: &str,
        http_port: u32,
    ) -> Self {
        Self {
            kind: String::from(kind.as_str()),
            machine_id: String::from(machine_id),
            node_id: String::from(node_id),
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
        let parent_dir = path.parent().expect("unexpected None parent");
        fs::create_dir_all(parent_dir)?;

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

        serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }

    /// Encodes the object in YAML format, compresses, and apply base58.
    /// Used for shortening S3 file name.
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

    /// Reverse of "compress_base64".
    pub fn decompress_base58(d: String) -> io::Result<Self> {
        let decompressed =
            compress_manager::unpack(d.as_bytes(), compress_manager::Decoder::ZstdBase58)?;
        serde_yaml::from_slice(&decompressed)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }
}

#[test]
fn test_node() {
    let d = r#"
kind: anchor
machine_id: i-123123
node_id: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
public_ip: 1.2.3.4
http_endpoint: http://1.2.3.4:9650

"#;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(d.as_bytes());
    assert!(ret.is_ok());
    let node_path = f.path().to_str().unwrap();

    let ret = Node::load(node_path);
    assert!(ret.is_ok());
    let node = ret.unwrap();

    let ret = node.sync(node_path);
    assert!(ret.is_ok());

    let orig = Node::new(
        node::Kind::Anchor,
        "i-123123",
        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
        "1.2.3.4",
        "http",
        9650,
    );
    assert_eq!(node, orig);

    // manually check to make sure the serde deserializer works
    assert_eq!(node.kind, String::from("anchor"));
    assert_eq!(node.machine_id, String::from("i-123123"));
    assert_eq!(
        node.node_id,
        String::from("NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg")
    );
    assert_eq!(node.public_ip, String::from("1.2.3.4"));
    assert_eq!(node.http_endpoint, String::from("http://1.2.3.4:9650"));

    let encoded_yaml = node.encode_yaml().unwrap();
    log::info!("node.encode_yaml: {}", encoded_yaml);
    let compressed = node.compress_base58().unwrap();
    log::info!("node.compress_base64: {}", compressed);
    let decompressed_node = Node::decompress_base58(compressed).unwrap();
    assert_eq!(node, decompressed_node);
}

/// Default machine anchor nodes size.
/// only required for custom networks
pub const DEFAULT_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MIN_MACHINE_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_ANCHOR_NODES: u32 = 10;

/// Default machine non-anchor nodes size.
/// "1" is better in order to choose only one AZ for static EBS provision.
/// If one wants to run multiple nodes, it should create multiple groups
/// of avalanche ops clusters.
pub const DEFAULT_MACHINE_NON_ANCHOR_NODES: u32 = 2;
pub const MIN_MACHINE_NON_ANCHOR_NODES: u32 = 1;
pub const MAX_MACHINE_NON_ANCHOR_NODES: u32 = 20;

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
    pub anchor_nodes: Option<u32>,
    #[serde(default)]
    pub non_anchor_nodes: u32,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
    /// Either "spot" or "on-demand".
    #[serde(default)]
    pub instance_mode: String,
    #[serde(default)]
    pub disable_spot_instance_for_anchor_nodes: bool,

    /// Either "elastic" or "ephemeral".
    #[serde(default)]
    pub ip_mode: String,

    /// Initial EBS volume size in GB.
    /// Can be resized with no downtime.
    /// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/recognize-expanded-volume-linux.html
    #[serde(default)]
    pub volume_size_in_gb: u32,
}

/// Represents artifacts for installation, to be shared with
/// remote machines. All paths are local to the caller's environment.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct InstallArtifacts {
    /// "aws-volume-provisioner" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/aws-volume-provisioner" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub aws_volume_provisioner_local_bin: Option<String>,
    #[serde(default)]
    pub aws_volume_provisioner_bin_install_from_s3: Option<bool>,

    /// "aws-ip-provisioner" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/aws-ip-provisioner" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub aws_ip_provisioner_local_bin: Option<String>,
    #[serde(default)]
    pub aws_ip_provisioner_bin_install_from_s3: Option<bool>,

    /// "aws-telemetry-cloudwatch" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/aws-telemetry-cloudwatch" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanche_telemetry_cloudwatch_local_bin: Option<String>,
    #[serde(default)]
    pub avalanche_telemetry_cloudwatch_bin_install_from_s3: Option<bool>,

    /// "avalanche-config" binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/avalanche-config" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanche_config_local_bin: Option<String>,
    #[serde(default)]
    pub avalanche_config_bin_install_from_s3: Option<bool>,

    /// "avalanched" agent binary path in the local environment.
    /// The file is uploaded to the remote storage with the path
    /// "bootstrap/install/avalanched" to be shared with remote machines.
    /// The file is NOT compressed when uploaded.
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanched_local_bin: Option<String>,
    #[serde(default)]
    pub avalanched_bin_install_from_s3: Option<bool>,

    /// AvalancheGo binary path in the local environment.
    /// The file is "compressed" and uploaded to remote storage
    /// to be shared with remote machines.
    ///
    ///  build
    ///    ├── avalanchego (the binary from compiling the app directory)
    ///    └── plugins
    ///        └── evm
    ///
    /// If none, it downloads the latest from github.
    #[serde(default)]
    pub avalanchego_local_bin: Option<String>,
    #[serde(default)]
    pub avalanchego_bin_install_from_s3: Option<bool>,

    /// Plugin directories in the local environment.
    /// Files (if any) are uploaded to the remote storage to be shared
    /// with remote machiens.
    #[serde(default)]
    pub plugins_local_dir: Option<String>,
    #[serde(default)]
    pub plugins_dir_install_from_s3: Option<bool>,
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String),
    Vpc(String),
    AsgAnchorNodes(String),
    AsgNonAnchorNodes(String),
    SsmDocRestartNodeWhitelistSubnetSubnetEvm(String),
    SsmDocRestartNodeWhitelistSubnetXsvm(String),
    SsmDocRestartNodeChanConfigSubnetEvm(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::AsgAnchorNodes(id) => format!("{}-asg-anchor-nodes", id),
            StackName::AsgNonAnchorNodes(id) => format!("{}-asg-non-anchor-nodes", id),
            StackName::SsmDocRestartNodeWhitelistSubnetSubnetEvm(id) => {
                format!("{}-ssm-doc-restart-node-whitelist-subnet-subnet-evm", id)
            }
            StackName::SsmDocRestartNodeWhitelistSubnetXsvm(id) => {
                format!("{}-ssm-doc-restart-node-whitelist-subnet-xsvm", id)
            }
            StackName::SsmDocRestartNodeChanConfigSubnetEvm(id) => {
                format!("{}-ssm-doc-restart-node-chain-config-subnet-evm", id)
            }
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

    AwsVolumeProvisionerBin(String),
    AwsIpProvisionerBin(String),
    AvalancheTelemetryCloudwatchBin(String),

    AvalancheConfigBin(String),
    AvalanchedBin(String),
    AvalancheBin(String),
    PluginsDir(String),

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
    EventsUpdateArtifactsInstallDirPluginsDir(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::ConfigFile(id) => format!("{}/avalanche-ops.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }

            StorageNamespace::GenesisFile(id) => format!("{}/genesis.json", id),

            StorageNamespace::AwsVolumeProvisionerBin(id) => {
                format!("{}/bootstrap/install/aws-volume-provisioner", id)
            }
            StorageNamespace::AwsIpProvisionerBin(id) => {
                format!("{}/bootstrap/install/aws-ip-provisioner", id)
            }
            StorageNamespace::AvalancheTelemetryCloudwatchBin(id) => {
                format!("{}/bootstrap/install/avalanche-telemetry-cloudwatch", id)
            }

            StorageNamespace::AvalancheConfigBin(id) => {
                format!("{}/bootstrap/install/avalanche-config", id)
            }
            StorageNamespace::AvalanchedBin(id) => format!("{}/bootstrap/install/avalanched", id),
            StorageNamespace::AvalancheBin(id) => {
                format!("{}/bootstrap/install/avalanche", id)
            }
            StorageNamespace::PluginsDir(id) => format!("{}/bootstrap/install/plugins", id),

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
            StorageNamespace::EventsUpdateArtifactsInstallDirPluginsDir(id) => {
                format!("{}/events/update-artifacts/install/plugins", id)
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
            Ok(node) => Ok(node),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed node::Node::decompress_base64 {}", e),
            )),
        }
    }
}

#[test]
fn test_storage_path() {
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random_manager::string(10);
    let instance_id = random_manager::string(5);
    let node_id = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_ip = "1.2.3.4";

    let node = Node::new(
        node::Kind::NonAnchor,
        &instance_id,
        node_id,
        node_ip,
        "http",
        9650,
    );
    let p = StorageNamespace::DiscoverReadyNonAnchorNode(
        id,
        Node {
            kind: String::from("non-anchor"),
            machine_id: instance_id.clone(),
            node_id: node_id.to_string(),
            public_ip: node_ip.to_string(),
            http_endpoint: format!("http://{}:9650", node_ip),
        },
    );
    let storage_path = p.encode();
    log::info!("KeyPath: {}", storage_path);

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

    pub fn sync(&self, file_path: String) -> io::Result<()> {
        log::info!("syncing Info to '{}'", file_path);
        let path = Path::new(&file_path);
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
