use std::{fs::File, io::prelude::*, path::Path, time::Duration};

use aws_sdk_ec2::{
    error::DeleteKeyPairError,
    model::{Filter, Instance, InstanceState, InstanceStateName, Tag},
    types::SdkError,
    Client,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use hyper::{Body, Method, Request};
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::errors::{
    Error::{Other, API},
    Result,
};

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
    /// It overwrites "key_path" file with the newly created key.
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

    /// Lists instances by the Auto Scaling Groups name.
    pub async fn list_asg(&self, asg_name: &str) -> Result<Vec<Droplet>> {
        let filter = Filter::builder()
            .set_name(Some(String::from("tag:aws:autoscaling:groupName")))
            .set_values(Some(vec![String::from(asg_name)]))
            .build();
        let resp = match self
            .cli
            .describe_instances()
            .set_filters(Some(vec![filter]))
            .send()
            .await
        {
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
                warn!("empty reservation from describe_instances response");
                return Ok(vec![]);
            }
        };

        let mut droplets: Vec<Droplet> = Vec::new();
        for rsv in reservations.iter() {
            let instances = rsv.instances().unwrap();
            for instance in instances {
                let instance_id = instance.instance_id().unwrap();
                info!("instance {}", instance_id);
                droplets.push(Droplet::new(instance));
            }
        }

        Ok(droplets)
    }
}

/// Represents the underlying EC2 instance.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Droplet {
    pub instance_id: String,
    /// Represents the data format in RFC3339.
    /// ref. https://serde.rs/custom-date-format.html
    #[serde(with = "rfc3339_format")]
    pub launched_at_utc: DateTime<Utc>,
    pub instance_state_code: i32,
    pub instance_state_name: String,
    pub availability_zone: String,
    pub public_hostname: String,
    pub public_ipv4: String,
}

impl Droplet {
    pub fn new(inst: &Instance) -> Self {
        let instance_id = match inst.instance_id.to_owned() {
            Some(v) => v,
            None => String::new(),
        };
        let launch_time = inst.launch_time().unwrap();
        let native_dt = NaiveDateTime::from_timestamp(launch_time.secs(), 0);
        let launched_at_utc = DateTime::<Utc>::from_utc(native_dt, Utc);

        let instance_state = match inst.state.to_owned() {
            Some(v) => v,
            None => InstanceState::builder().build(),
        };
        let instance_state_code = instance_state.code.unwrap_or(0);
        let instance_state_name = instance_state
            .name
            .unwrap_or_else(|| InstanceStateName::Unknown(String::from("unknown")));
        let instance_state_name = instance_state_name.as_str().to_string();

        let availability_zone = match inst.placement.to_owned() {
            Some(v) => match v.availability_zone {
                Some(v2) => v2,
                None => String::new(),
            },
            None => String::new(),
        };

        let public_hostname = inst
            .public_dns_name
            .to_owned()
            .unwrap_or_else(|| String::from(""));
        let public_ipv4 = inst
            .public_ip_address
            .to_owned()
            .unwrap_or_else(|| String::from(""));

        Self {
            instance_id,
            launched_at_utc,
            instance_state_code,
            instance_state_name,
            availability_zone,
            public_hostname,
            public_ipv4,
        }
    }
}

/// ref. https://serde.rs/custom-date-format.html
mod rfc3339_format {
    use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.to_rfc3339_opts
        serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // ref. https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.parse_from_rfc3339
        match DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom) {
            Ok(dt) => Ok(Utc.from_utc_datetime(&dt.naive_utc())),
            Err(e) => Err(e),
        }
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

/// Fetches the instance ID on the host EC2 machine.
pub async fn fetch_instance_id() -> Result<String> {
    fetch_metadata("instance-id").await
}

/// Fetches the public hostname of the host EC2 machine.
pub async fn fetch_public_hostname() -> Result<String> {
    fetch_metadata("public-hostname").await
}

/// Fetches the public IPv4 address of the host EC2 machine.
pub async fn fetch_public_ipv4() -> Result<String> {
    fetch_metadata("public-ipv4").await
}

/// Fetches the availability of the host EC2 machine.
pub async fn fetch_availability_zone() -> Result<String> {
    fetch_metadata("placement/availability-zone").await
}

/// Fetches the region of the host EC2 machine.
/// TODO: fix this...
pub async fn fetch_region() -> Result<String> {
    let mut az = fetch_availability_zone().await?;
    az.truncate(az.len() - 1);
    Ok(az)
}

/// Fetches instance metadata service v2 with the "path".
/// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
/// ref. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
/// e.g., curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/public-ipv4
async fn fetch_metadata(path: &str) -> Result<String> {
    info!("fetching meta-data/{}", path);

    let uri = format!("http://169.254.169.254/latest/meta-data/{}", path);
    let token = fetch_token().await?;
    let req = match Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("X-aws-ec2-metadata-token", token)
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            return Err(API {
                message: format!("failed to build GET meta-data/{} {:?}", path, e),
                is_retryable: false,
            });
        }
    };

    let ret = crate::http::read_bytes(req, Duration::from_secs(5), true).await;
    let rs = match ret {
        Ok(bytes) => {
            let s = match String::from_utf8(bytes.to_vec()) {
                Ok(text) => text,
                Err(e) => {
                    return Err(API {
                        message: format!(
                            "GET meta-data/{} returned unexpected bytes {:?} ({})",
                            path, bytes, e
                        ),
                        is_retryable: false,
                    });
                }
            };
            s
        }
        Err(e) => {
            return Err(API {
                message: format!("failed GET meta-data/{} {:?}", path, e),
                is_retryable: false,
            })
        }
    };
    Ok(rs)
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

    let ret = crate::http::read_bytes(req, Duration::from_secs(5), true).await;
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
