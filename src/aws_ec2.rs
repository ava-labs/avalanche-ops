use std::{fs::File, io::prelude::*, path::Path, time::Duration};

use crate::aws::{
    Error::{Other, API},
    Result,
};

use aws_sdk_ec2::{error::DeleteKeyPairError, model::Tag, Client, SdkError};
use hyper::{Body, Method, Request};
use log::{info, warn};

/// Implements AWS EC2 manager.
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

    /// Creates an AWS EC2 key-pair and saves the private key to disk.
    pub async fn create_key_pair(&self, key_name: &str, key_path: &str) -> Result<()> {
        let path = Path::new(key_path);
        if path.exists() {
            return Err(Other {
                message: format!("key path {} already exists", key_path),
                is_retryable: false,
            });
        }

        info!("creating EC2 key-pair '{}'", key_name);
        let ret = self.cli.create_key_pair().key_name(key_name).send().await;
        let resp = match ret {
            Ok(v) => v,
            Err(e) => {
                return Err(API {
                    message: format!("failed create_key_pair {:?}", e),
                    is_retryable: is_error_retryable(&e),
                });
            }
        };

        info!("saving EC2 key-pair '{}' to '{}'", key_name, key_path);
        let key_material = resp.key_material().unwrap();

        let mut f = match File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                return Err(Other {
                    message: format!("failed to create file {:?}", e),
                    is_retryable: false,
                });
            }
        };
        match f.write_all(key_material.as_bytes()) {
            Ok(_) => {}
            Err(e) => {
                return Err(Other {
                    message: format!("failed to write file {:?}", e),
                    is_retryable: false,
                });
            }
        }

        Ok(())
    }

    /// Deletes the AWS EC2 key-pair.
    pub async fn delete_key_pair(&self, key_name: &str) -> Result<()> {
        info!("deleting EC2 key-pair '{}'", key_name);
        let ret = self.cli.delete_key_pair().key_name(key_name).send().await;
        match ret {
            Ok(_) => {}
            Err(e) => {
                info!("hey! {}", e);
                if !is_error_delete_key_pair_does_not_exist(&e) {
                    return Err(API {
                        message: format!("failed delete_key_pair {:?}", e),
                        is_retryable: is_error_retryable(&e),
                    });
                }
                warn!("key already deleted ({})", e);
            }
        };

        Ok(())
    }

    /// Fetches all tags for the specified instance.
    pub async fn fetch_tags(&self, instance_id: &str) -> Result<Vec<Tag>> {
        info!("fetching tags for '{}'", instance_id);
        let ret = self
            .cli
            .describe_instances()
            .instance_ids(String::from(instance_id))
            .send()
            .await;
        let resp = match ret {
            Ok(r) => r,
            Err(e) => {
                return Err(API {
                    message: format!("failed describe_instances {:?}", e),
                    is_retryable: is_error_retryable(&e),
                });
            }
        };

        let reservations = match resp.reservations {
            Some(rvs) => rvs,
            None => {
                return Err(API {
                    message: String::from("empty reservation from describe_instances response"),
                    is_retryable: false,
                });
            }
        };
        if reservations.len() != 1 {
            return Err(API {
                message: format!(
                    "expected only 1 reservation from describe_instances response but got {}",
                    reservations.len()
                ),
                is_retryable: false,
            });
        }

        let rvs = reservations.get(0).unwrap();
        let instances = rvs.instances.to_owned().unwrap();
        if instances.len() != 1 {
            return Err(API {
                message: format!(
                    "expected only 1 instance from describe_instances response but got {}",
                    instances.len()
                ),
                is_retryable: false,
            });
        }

        let instance = instances.get(0).unwrap();
        let tags = match instance.tags.to_owned() {
            Some(ss) => ss,
            None => {
                return Err(API {
                    message: String::from("empty tags from describe_instances response"),
                    is_retryable: false,
                });
            }
        };
        info!("fetched {} tags for '{}'", tags.len(), instance_id);

        Ok(tags)
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

/// EC2 does not return any error for non-existing key deletes, just in case...
#[inline]
fn is_error_delete_key_pair_does_not_exist(e: &SdkError<DeleteKeyPairError>) -> bool {
    match e {
        SdkError::ServiceError { err, .. } => {
            let msg = format!("{:?}", err);
            msg.contains("does not exist")
        }
        _ => false,
    }
}

/// Serves instance id for instance metadata service v2.
/// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
/// e.g., curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/instance-id
const IMDS_V2_INSTANCE_ID_URI: &str = "http://169.254.169.254/latest/meta-data/instance-id";

/// Fetches the instance ID on the host EC2 machine.
pub async fn fetch_instance_id() -> Result<String> {
    info!("fetching the local instance ID");

    let token = fetch_token().await?;
    let req = match Request::builder()
        .method(Method::GET)
        .uri(IMDS_V2_INSTANCE_ID_URI)
        .header("X-aws-ec2-metadata-token", token)
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            return Err(API {
                message: format!("failed to build GET meta-data/instance-id {:?}", e),
                is_retryable: false,
            });
        }
    };

    let ret = crate::http::read_bytes(req, Duration::from_secs(5)).await;
    let id = match ret {
        Ok(bytes) => {
            let s = match String::from_utf8(bytes.to_vec()) {
                Ok(text) => text,
                Err(e) => {
                    return Err(API {
                        message: format!(
                            "GET meta-data/instance-id returned unexpected bytes {:?} ({})",
                            bytes, e
                        ),
                        is_retryable: false,
                    });
                }
            };
            s
        }
        Err(e) => {
            return Err(API {
                message: format!("failed GET meta-data/instance-id {:?}", e),
                is_retryable: false,
            })
        }
    };
    Ok(id)
}

/// Serves session token for instance metadata service v2.
/// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
/// e.g., curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
const IMDS_V2_SESSION_TOKEN_URI: &str = "http://169.254.169.254/latest/api/token";

/// Fetches the IMDS v2 token.
async fn fetch_token() -> Result<String> {
    info!("fetching IMDS v2 token");

    let req = match Request::builder()
        .method(Method::PUT)
        .uri(IMDS_V2_SESSION_TOKEN_URI)
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            return Err(API {
                message: format!("failed to build PUT api/token {:?}", e),
                is_retryable: false,
            });
        }
    };

    let ret = crate::http::read_bytes(req, Duration::from_secs(5)).await;
    let token = match ret {
        Ok(bytes) => {
            let s = match String::from_utf8(bytes.to_vec()) {
                Ok(text) => text,
                Err(e) => {
                    return Err(API {
                        message: format!(
                            "PUT api/token returned unexpected bytes {:?} ({})",
                            bytes, e
                        ),
                        is_retryable: false,
                    });
                }
            };
            s
        }
        Err(e) => {
            return Err(API {
                message: format!("failed PUT api/token {:?}", e),
                is_retryable: false,
            })
        }
    };
    Ok(token)
}
