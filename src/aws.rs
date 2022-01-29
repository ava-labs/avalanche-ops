use std::io;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ec2::Region;
use log::info;
use thiserror::Error;

/// Loads an AWS config from default environments.
pub async fn load_config(reg: Option<String>) -> io::Result<aws_config::Config> {
    info!("loading AWS configuration for region {:?}", reg);
    let regp = RegionProviderChain::first_try(reg.map(Region::new))
        .or_default_provider()
        .or_else(Region::new("us-west-2"));

    let shared_config = aws_config::from_env().region(regp).load().await;
    Ok(shared_config)
}

pub type Result<T> = std::result::Result<T, Error>;

/// Backing errors for all AWS operations.
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed API")]
    API { message: String, is_retryable: bool },
    #[error("failed for other reasons")]
    Other { message: String, is_retryable: bool },
}

impl Error {
    /// Returns the error message in "String".
    #[inline]
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Error::API { message, .. } | Error::Other { message, .. } => message.clone(),
        }
    }

    /// Returns if the error is retryable.
    #[inline]
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::API { is_retryable, .. } | Error::Other { is_retryable, .. } => *is_retryable,
        }
    }
}
