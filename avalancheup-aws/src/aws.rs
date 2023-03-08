use aws_manager::sts;
use serde::{Deserialize, Serialize};

/// Represents the current AWS resource status.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Resources {
    /// AWS STS caller loaded from its local environment.
    /// READ ONLY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<sts::Identity>,

    /// AWS region to create resources.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub region: String,

    /// Name of the bucket to store (or download from)
    /// the configuration and resources (e.g., S3).
    /// If not exists, it creates automatically.
    /// If exists, it skips creation and uses the existing one.
    /// MUST BE NON-EMPTY.
    #[serde(default)]
    pub s3_bucket: String,

    /// AWS region to create resources.
    /// NON-EMPTY TO ENABLE HTTPS over NLB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nlb_acm_certificate_arn: Option<String>,

    /// KMS CMK ID to encrypt resources.
    /// Only used for encrypting node certs and EC2 keys.
    /// None if not created yet.
    /// READ ONLY -- DO NOT SET.
    /// TODO: support existing key and load the ARN based on region and account number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_symmetric_default_encrypt_key: Option<KmsCmk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Generated CMKs.
    pub kms_cmk_secp256k1_cmks: Option<Vec<KmsCmk>>,

    /// EC2 key pair name for SSH access to EC2 instances.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_name: Option<String>,
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_path: Option<String>,

    /// CloudFormation stack name for EC2 instance role.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,
    /// Instance profile ARN from "cloudformation_ec2_instance_role".
    /// Only updated after creation.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_profile_arn: Option<String>,

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

    /// CloudFormation stack name for SSM document that restarts node with subnet tracking.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm: Option<String>,
    /// CloudFormation stack name for SSM document that restarts node with subnet tracking.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm: Option<String>,
    /// CloudFormation stack name for SSM document that restarts node to load chain config.
    /// READ ONLY -- DO NOT SET.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ssm_doc_restart_node_chain_config_subnet_evm: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudwatch_avalanche_metrics_namespace: Option<String>,
}

impl Default for Resources {
    fn default() -> Self {
        Self::default()
    }
}

impl Resources {
    pub fn default() -> Self {
        Self {
            identity: None,

            region: String::from("us-west-2"),

            s3_bucket: String::new(),

            nlb_acm_certificate_arn: None,

            kms_cmk_symmetric_default_encrypt_key: None,
            kms_cmk_secp256k1_cmks: None,

            ec2_key_name: None,
            ec2_key_path: None,

            cloudformation_ec2_instance_role: None,
            cloudformation_ec2_instance_profile_arn: None,

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

            cloudformation_ssm_doc_restart_node_tracked_subnet_subnet_evm: None,
            cloudformation_ssm_doc_restart_node_tracked_subnet_xsvm: None,
            cloudformation_ssm_doc_restart_node_chain_config_subnet_evm: None,
            cloudwatch_avalanche_metrics_namespace: None,
        }
    }
}

/// Represents the KMS CMK resource.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct KmsCmk {
    /// CMK Id.
    pub id: String,
    /// CMK Arn.
    pub arn: String,
}
