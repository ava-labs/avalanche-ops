use std::{fs, path::Path};

use aws_sdk_s3::{
    error::{CreateBucketError, CreateBucketErrorKind, DeleteBucketError},
    model::{
        BucketCannedAcl, BucketLocationConstraint, CreateBucketConfiguration, Delete, Object,
        ObjectCannedAcl, ObjectIdentifier, PublicAccessBlockConfiguration, ServerSideEncryption,
        ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
    },
    ByteStream, Client, SdkError,
};
use log::{debug, info, warn};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::errors::{
    Error::{Other, API},
    Result,
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
        info!("deleted objets in S3 bucket '{}'", bucket_name);

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

        info!("listing bucket {} with prefix {}", bucket_name, pfx);
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

    /// Writes an object to a S3 bucket.
    pub async fn put_object(&self, bucket_name: &str, file_path: &str, s3_key: &str) -> Result<()> {
        if !Path::new(file_path).exists() {
            return Err(Other {
                message: format!("file path {} does not exist", file_path),
                is_retryable: false,
            });
        }

        // this will fail with
        // "failed read_to_string stream did not contain valid UTF-8"
        //
        // tokio::io::AsyncReadExt
        // let mut file = File::open(file_path).await.map_err(|e| Other {
        //     message: format!("failed open {}", e),
        //     is_retryable: false,
        // })?;
        // let mut contents = String::new();
        // file.read_to_string(&mut contents)
        //     .await
        //     .map_err(|e| Other {
        //         message: format!("failed read_to_string {}", e),
        //         is_retryable: false,
        //     })?;

        let contents = match fs::read(file_path) {
            Ok(d) => d,
            Err(e) => {
                return Err(Other {
                    message: format!("failed read {:?}", e),
                    is_retryable: false,
                });
            }
        };

        info!(
            "writing '{}' to '{}/{}' (size {})",
            file_path,
            bucket_name,
            s3_key,
            crate::humanize::bytes(contents.len() as f64)
        );
        let ret = self
            .cli
            .put_object()
            .bucket(bucket_name)
            .key(s3_key)
            .body(ByteStream::from(contents))
            .acl(ObjectCannedAcl::Private)
            .send()
            .await;
        match ret {
            Ok(_) => {}
            Err(e) => {
                return Err(API {
                    message: format!("failed put_object {:?}", e),
                    is_retryable: is_error_retryable(&e),
                });
            }
        };
        info!("uploaded {} to S3 bucket '{}'", file_path, bucket_name);

        Ok(())
    }

    /// Downloads an object from a S3 bucket.
    pub async fn get_object(&self, bucket_name: &str, s3_key: &str, file_path: &str) -> Result<()> {
        if Path::new(file_path).exists() {
            return Err(Other {
                message: format!("file path {} already exists", file_path),
                is_retryable: false,
            });
        }

        info!(
            "downloading '{}/{}' to '{}'",
            bucket_name, s3_key, file_path,
        );

        let ret = self
            .cli
            .get_object()
            .bucket(bucket_name)
            .key(s3_key)
            .send()
            .await;
        let output = match ret {
            Ok(v) => v,
            Err(e) => {
                warn!("get failed {}", e);
                return Err(API {
                    message: format!("failed get_object {:?}", e),
                    is_retryable: is_error_retryable(&e),
                });
            }
        };

        let ret = output.body.collect().await;
        let mut bytes = match ret {
            Ok(v) => v,
            Err(e) => {
                warn!("get failed {}", e);
                return Err(Other {
                    message: format!("failed output.body.collect {:?}", e),
                    is_retryable: false,
                });
            }
        };

        let mut file = File::create(file_path).await.map_err(|e| Other {
            message: format!("failed create {}", e),
            is_retryable: false,
        })?;
        file.write_all_buf(&mut bytes).await.map_err(|e| Other {
            message: format!("failed write_all_buf {}", e),
            is_retryable: false,
        })?;
        file.flush().await.map_err(|e| Other {
            message: format!("failed flush {}", e),
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
/// MUST be kept in sync with "cloudformation/ec2_instance_role.yaml".
pub enum KeyPath {
    GenesisFile,
    AvalanchedBin,
    AvalancheBin,
    AvalancheBinCompressed,
    Ec2AccessKeyCompressedEncrypted,
    PluginsDir,
    PkiKeyDir,
    BeaconNodesDir,
    NonBeaconNodesDir,
    ConfigFile,
}

impl KeyPath {
    pub fn to_string(&self, id: &str) -> String {
        match self {
            KeyPath::GenesisFile => format!("{}/install/genesis.json", id),
            KeyPath::AvalanchedBin => format!("{}/install/avalanched", id),
            KeyPath::AvalancheBin => format!("{}/install/avalanche", id),
            KeyPath::AvalancheBinCompressed => format!("{}/install/avalanche.zstd", id),
            KeyPath::Ec2AccessKeyCompressedEncrypted => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }
            KeyPath::PluginsDir => format!("{}/install/plugins", id),
            KeyPath::PkiKeyDir => {
                format!("{}/pki", id)
            }
            KeyPath::BeaconNodesDir => {
                format!("{}/beacon-nodes", id)
            }
            KeyPath::NonBeaconNodesDir => {
                format!("{}/non-beacon-nodes", id)
            }
            KeyPath::ConfigFile => format!("{}/config.yaml", id),
        }
    }
}
