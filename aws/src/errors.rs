use thiserror::Error;

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
