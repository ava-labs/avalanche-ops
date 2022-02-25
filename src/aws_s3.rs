use std::{fs, path::Path};

use aws_sdk_s3::{
    error::{CreateBucketError, CreateBucketErrorKind, DeleteBucketError},
    model::{
        BucketCannedAcl, BucketLocationConstraint, CreateBucketConfiguration, Delete, Object,
        ObjectCannedAcl, ObjectIdentifier, PublicAccessBlockConfiguration, ServerSideEncryption,
        ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
    },
    types::{ByteStream, SdkError},
    Client,
};
use log::{debug, info, warn};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::{
    errors::{
        Error::{Other, API},
        Result,
    },
    humanize, node,
};

/// Implements AWS S3 manager.
pub struct Manager {
    #[allow(dead_code)]
    shared_config: aws_config::Config,
    cli: Client,
}

impl Manager {
    pub fn new(shared_config: &aws_config::Config) -> Self {
        let cloned = shared_config.clone();
        let cli = Client::new(shared_config);
        Self {
            shared_config: cloned,
            cli,
        }
    }

    /// Creates a S3 bucket.
    pub async fn create_bucket(&self, bucket_name: &str) -> Result<()> {
        let reg = self.shared_config.region().unwrap();
        let constraint = BucketLocationConstraint::from(reg.to_string().as_str());
        let bucket_cfg = CreateBucketConfiguration::builder()
            .location_constraint(constraint)
            .build();

        info!(
            "creating S3 bucket '{}' in region {}",
            bucket_name,
            reg.to_string()
        );
        let ret = self
            .cli
            .create_bucket()
            .create_bucket_configuration(bucket_cfg)
            .bucket(bucket_name)
            .acl(BucketCannedAcl::Private)
            .send()
            .await;
        let already_created = match ret {
            Ok(_) => false,
            Err(e) => {
                if !is_error_bucket_already_exist(&e) {
                    return Err(API {
                        message: format!("failed create_bucket {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                warn!("bucket already exists ({})", e);
                true
            }
        };
        if already_created {
            return Ok(());
        }
        info!("created S3 bucket '{}'", bucket_name);

        info!("setting S3 bucket public_access_block configuration to private");
        let public_access_block_cfg = PublicAccessBlockConfiguration::builder()
            .block_public_acls(true)
            .block_public_policy(true)
            .ignore_public_acls(true)
            .restrict_public_buckets(true)
            .build();
        self.cli
            .put_public_access_block()
            .bucket(bucket_name)
            .public_access_block_configuration(public_access_block_cfg)
            .send()
            .await
            .map_err(|e| API {
                message: format!("failed put_public_access_block {}", e),
                is_retryable: is_error_retryable(&e),
            })?;

        let algo = ServerSideEncryption::Aes256;
        let sse = ServerSideEncryptionByDefault::builder()
            .set_sse_algorithm(Some(algo))
            .build();
        let server_side_encryption_rule = ServerSideEncryptionRule::builder()
            .apply_server_side_encryption_by_default(sse)
            .build();
        let server_side_encryption_cfg = ServerSideEncryptionConfiguration::builder()
            .rules(server_side_encryption_rule)
            .build();
        self.cli
            .put_bucket_encryption()
            .bucket(bucket_name)
            .server_side_encryption_configuration(server_side_encryption_cfg)
            .send()
            .await
            .map_err(|e| API {
                message: format!("failed put_bucket_encryption {}", e),
                is_retryable: is_error_retryable(&e),
            })?;

        Ok(())
    }

    /// Deletes a S3 bucket.
    pub async fn delete_bucket(&self, bucket_name: &str) -> Result<()> {
        let reg = self.shared_config.region().unwrap();
        info!(
            "deleting S3 bucket '{}' in region {}",
            bucket_name,
            reg.to_string()
        );
        let ret = self.cli.delete_bucket().bucket(bucket_name).send().await;
        match ret {
            Ok(_) => {}
            Err(e) => {
                if !is_error_bucket_does_not_exist(&e) {
                    return Err(API {
                        message: format!("failed delete_bucket {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                warn!("bucket already deleted or does not exist ({})", e);
            }
        };
        info!("deleted S3 bucket '{}'", bucket_name);

        Ok(())
    }

    /// Deletes objects by "prefix".
    /// If "prefix" is "None", empties a S3 bucket, deleting all files.
    /// ref. https://github.com/awslabs/aws-sdk-rust/blob/main/examples/s3/src/bin/delete-objects.rs
    pub async fn delete_objects(&self, bucket_name: &str, prefix: Option<String>) -> Result<()> {
        let reg = self.shared_config.region().unwrap();
        info!(
            "deleting objects S3 bucket '{}' in region {} (prefix {:?})",
            bucket_name,
            reg.to_string(),
            prefix,
        );

        let objects = self.list_objects(bucket_name, prefix).await?;
        let mut object_ids: Vec<ObjectIdentifier> = vec![];
        for obj in objects {
            let k = String::from(obj.key().unwrap_or(""));
            let obj_id = ObjectIdentifier::builder().set_key(Some(k)).build();
            object_ids.push(obj_id);
        }

        let n = object_ids.len();
        if n > 0 {
            let deletes = Delete::builder().set_objects(Some(object_ids)).build();
            let ret = self
                .cli
                .delete_objects()
                .bucket(bucket_name)
                .delete(deletes)
                .send()
                .await;
            match ret {
                Ok(_) => {}
                Err(e) => {
                    return Err(API {
                        message: format!("failed delete_bucket {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
            };
            info!("deleted {} objets in S3 bucket '{}'", n, bucket_name);
        } else {
            info!("nothing to delete; skipping...");
        }

        Ok(())
    }

    /// List objects in the bucket with an optional prefix,
    /// in the descending order of "last_modified" timestamps.
    /// "bucket_name" implies the suffix "/", so no need to prefix
    /// sub-directory with "/".
    /// Passing "bucket_name" + "directory" is enough!
    ///
    /// e.g.
    /// "foo-mydatabucket" for bucket_name
    /// "mydata/myprefix/" for prefix
    pub async fn list_objects(
        &self,
        bucket_name: &str,
        prefix: Option<String>,
    ) -> Result<Vec<Object>> {
        let pfx = prefix.unwrap_or_default();

        info!("listing bucket {} with prefix '{:?}'", bucket_name, pfx);
        let mut objects: Vec<Object> = Vec::new();
        let mut token = String::new();
        loop {
            let mut builder = self.cli.list_objects_v2().bucket(bucket_name);
            if !pfx.is_empty() {
                builder = builder.set_prefix(Some(pfx.to_owned()));
            }
            if !token.is_empty() {
                builder = builder.set_continuation_token(Some(token.to_owned()));
            }
            let ret = match builder.send().await {
                Ok(r) => r,
                Err(e) => {
                    return Err(API {
                        message: format!("failed list_objects_v2 {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
            };
            if ret.key_count == 0 {
                break;
            }
            if ret.contents.is_none() {
                break;
            }
            let contents = ret.contents.unwrap();
            for obj in contents.iter() {
                let k = obj.key().unwrap_or("");
                if k.is_empty() {
                    return Err(API {
                        message: String::from("empty key returned"),
                        is_retryable: false,
                    });
                }
                debug!("listing [{}]", k);
                objects.push(obj.to_owned());
            }

            token = match ret.next_continuation_token {
                Some(v) => v,
                None => String::new(),
            };
            if token.is_empty() {
                break;
            }
        }

        if objects.len() > 1 {
            info!(
                "sorting {} objects in bucket {} with prefix {}",
                objects.len(),
                bucket_name,
                pfx
            );
            objects.sort_by(|a, b| {
                let a_modified = a.last_modified.unwrap();
                let a_modified = a_modified.as_nanos();

                let b_modified = b.last_modified.unwrap();
                let b_modified = b_modified.as_nanos();

                // reverse comparison!
                // older file placed in later in the array
                // latest file first!
                b_modified.cmp(&a_modified)
            });
        }
        Ok(objects)
    }

    /// Writes an object to a S3 bucket using stream.
    ///
    /// WARN: use stream! otherwise it can cause OOM -- don't do the following!
    ///       "fs::read" reads all data onto memory
    ///       ".body(ByteStream::from(contents))" passes the whole data to an API call
    ///
    pub async fn put_object(&self, file_path: &str, s3_bucket: &str, s3_key: &str) -> Result<()> {
        if !Path::new(file_path).exists() {
            return Err(Other {
                message: format!("file path {} does not exist", file_path),
                is_retryable: false,
            });
        }

        let meta = fs::metadata(file_path).map_err(|e| Other {
            message: format!("failed metadata {}", e),
            is_retryable: false,
        })?;
        let size = meta.len() as f64;
        info!(
            "starting put_object '{}' (size {}) to 's3://{}/{}'",
            file_path,
            humanize::bytes(size),
            s3_bucket,
            s3_key
        );

        let byte_stream = ByteStream::from_path(Path::new(file_path))
            .await
            .map_err(|e| Other {
                message: format!("failed ByteStream::from_file {}", e),
                is_retryable: false,
            })?;
        self.cli
            .put_object()
            .bucket(s3_bucket)
            .key(s3_key)
            .body(byte_stream)
            .acl(ObjectCannedAcl::Private)
            .send()
            .await
            .map_err(|e| API {
                message: format!("failed put_object {}", e),
                is_retryable: is_error_retryable(&e),
            })?;

        Ok(())
    }

    /// Downloads an object from a S3 bucket using stream.
    ///
    /// WARN: use stream! otherwise it can cause OOM -- don't do the following!
    ///       "aws_smithy_http::byte_stream:ByteStream.collect" reads all the data into memory
    ///       "File.write_all_buf(&mut bytes)" to write bytes
    ///
    pub async fn get_object(&self, s3_bucket: &str, s3_key: &str, file_path: &str) -> Result<()> {
        if Path::new(file_path).exists() {
            return Err(Other {
                message: format!("file path {} already exists", file_path),
                is_retryable: false,
            });
        }

        let head_output = self
            .cli
            .head_object()
            .bucket(s3_bucket)
            .key(s3_key)
            .send()
            .await
            .map_err(|e| API {
                message: format!("failed head_object {}", e),
                is_retryable: is_error_retryable(&e),
            })?;

        info!(
            "starting get_object 's3://{}/{}' (content type '{}', size {})",
            s3_bucket,
            s3_key,
            head_output.content_type().unwrap(),
            humanize::bytes(head_output.content_length() as f64),
        );
        let mut output = self
            .cli
            .get_object()
            .bucket(s3_bucket)
            .key(s3_key)
            .send()
            .await
            .map_err(|e| API {
                message: format!("failed get_object {}", e),
                is_retryable: is_error_retryable(&e),
            })?;

        // ref. https://docs.rs/tokio-stream/latest/tokio_stream/
        let mut file = File::create(file_path).await.map_err(|e| Other {
            message: format!("failed File::create {}", e),
            is_retryable: false,
        })?;

        info!("writing byte stream to file {}", file_path);
        while let Some(d) = output.body.try_next().await.map_err(|e| Other {
            message: format!("failed ByteStream::try_next {}", e),
            is_retryable: false,
        })? {
            file.write_all(&d).await.map_err(|e| API {
                message: format!("failed File.write_all {}", e),
                is_retryable: false,
            })?;
        }
        file.flush().await.map_err(|e| Other {
            message: format!("failed File.flush {}", e),
            is_retryable: false,
        })?;

        Ok(())
    }
}

#[inline]
pub fn is_error_retryable<E>(e: &SdkError<E>) -> bool {
    match e {
        SdkError::TimeoutError(_) | SdkError::ResponseError { .. } => true,
        SdkError::DispatchFailure(e) => e.is_timeout() || e.is_io(),
        _ => false,
    }
}

#[inline]
fn is_error_bucket_already_exist(e: &SdkError<CreateBucketError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            matches!(
                err.kind,
                CreateBucketErrorKind::BucketAlreadyExists(_)
                    | CreateBucketErrorKind::BucketAlreadyOwnedByYou(_)
            )
        }
        _ => false,
    }
}

#[inline]
fn is_error_bucket_does_not_exist(e: &SdkError<DeleteBucketError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            let msg = format!("{:?}", err);
            msg.contains("bucket does not exist")
        }
        _ => false,
    }
}

/// Represents the S3 key path.
/// MUST be kept in sync with "cloudformation/avalanche-node/ec2_instance_role.yaml".
pub enum KeyPath {
    ConfigFile(String),
    DevMachineConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),

    // basic, common, top-level genesis, not ready for full use
    // e.g., initial stakers are empty since there's no beacon node yet
    GenesisDraftFile(String),
    // valid genesis file with fully specified initial stakers
    // after beacon nodes become active
    GenesisFile(String),

    AvalanchedBin(String),
    AvalancheBin(String),
    AvalancheBinCompressed(String),
    PluginsDir(String),

    PkiKeyDir(String),

    DiscoverBootstrappingBeaconNodesDir(String),
    DiscoverBootstrappingBeaconNode(String, node::Node),
    DiscoverReadyBeaconNodesDir(String),
    DiscoverReadyBeaconNode(String, node::Node),
    DiscoverReadyNonBeaconNodesDir(String),
    DiscoverReadyNonBeaconNode(String, node::Node),

    BackupsDir(String),
    EventsDir(String),
}

impl KeyPath {
    pub fn encode(&self) -> String {
        match self {
            KeyPath::ConfigFile(id) => format!("{}/avalanche-ops.config.yaml", id),
            KeyPath::DevMachineConfigFile(id) => format!("{}/dev-machine.config.yaml", id),
            KeyPath::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }

            KeyPath::GenesisDraftFile(id) => format!("{}/install/genesis.draft.json", id),
            KeyPath::GenesisFile(id) => format!("{}/genesis.json", id),

            KeyPath::AvalanchedBin(id) => format!("{}/install/avalanched", id),
            KeyPath::AvalancheBin(id) => format!("{}/install/avalanche", id),
            KeyPath::AvalancheBinCompressed(id) => format!("{}/install/avalanche.zstd", id),
            KeyPath::PluginsDir(id) => format!("{}/install/plugins", id),

            KeyPath::PkiKeyDir(id) => {
                format!("{}/pki", id)
            }

            KeyPath::DiscoverBootstrappingBeaconNodesDir(id) => {
                format!("{}/discover/bootstrapping-beacon-nodes", id)
            }
            KeyPath::DiscoverBootstrappingBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/bootstrapping-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            KeyPath::DiscoverReadyBeaconNodesDir(id) => {
                format!("{}/discover/ready-beacon-nodes", id)
            }
            KeyPath::DiscoverReadyBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }
            KeyPath::DiscoverReadyNonBeaconNodesDir(id) => {
                format!("{}/discover/ready-non-beacon-nodes", id)
            }
            KeyPath::DiscoverReadyNonBeaconNode(id, node) => {
                let compressed_id = node.compress_base58().unwrap();
                format!(
                    "{}/discover/ready-non-beacon-nodes/{}_{}.yaml",
                    id, node.machine_id, compressed_id
                )
            }

            KeyPath::BackupsDir(id) => {
                format!("{}/backups", id)
            }
            KeyPath::EventsDir(id) => {
                format!("{}/events", id)
            }
        }
    }

    pub fn parse_node_from_s3_path(s3_path: &str) -> Result<node::Node> {
        let p = Path::new(s3_path);
        let file_name = match p.file_name() {
            Some(v) => v,
            None => {
                return Err(Other {
                    message: String::from("failed Path.file_name (None)"),
                    is_retryable: false,
                });
            }
        };
        let file_name = file_name.to_str().unwrap();
        let splits: Vec<&str> = file_name.split('_').collect();
        if splits.len() != 2 {
            return Err(Other {
                message: format!(
                    "file name {} of s3_path {} expected two splits for '_' (got {})",
                    file_name,
                    s3_path,
                    splits.len(),
                ),
                is_retryable: false,
            });
        }

        let compressed_id = splits[1];
        match node::Node::decompress_base58(compressed_id.replace(".yaml", "")) {
            Ok(node) => Ok(node),
            Err(e) => {
                return Err(Other {
                    message: format!("failed node::Node::decompress_base64 {}", e),
                    is_retryable: false,
                });
            }
        }
    }
}

#[test]
fn test_key_path() {
    use crate::random;
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random::string(10);
    let instance_id = random::string(5);
    let node_id = "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg";
    let node_ip = "1.2.3.4";

    let node = node::Node::new(node::Kind::NonBeacon, &instance_id, node_id, node_ip);
    let p = KeyPath::DiscoverReadyNonBeaconNode(
        id,
        node::Node {
            kind: String::from("non-beacon"),
            machine_id: instance_id.clone(),
            id: node_id.to_string(),
            ip: node_ip.to_string(),
        },
    );
    let s3_path = p.encode();
    info!("KeyPath: {}", s3_path);

    let node_parsed = KeyPath::parse_node_from_s3_path(&s3_path).unwrap();
    assert_eq!(node, node_parsed);
}

#[test]
fn test_append_slash() {
    let s = "hello";
    assert_eq!(append_slash(s), "hello/");

    let s = "hello/";
    assert_eq!(append_slash(s), "hello/");
}

pub fn append_slash(k: &str) -> String {
    let n = k.len();
    if &k[n - 1..] == "/" {
        String::from(k)
    } else {
        format!("{}/", k)
    }
}
