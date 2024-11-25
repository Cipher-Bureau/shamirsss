use thiserror::Error;

/// SSSErrors contains all the errors types that are returned in Result.
///
#[derive(Error, Debug)]
pub enum SSSError {
    #[error("failed with openssl error: {0}")]
    FromOpenssl(#[from] openssl::error::ErrorStack),
    #[error("failed with hex operation: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("failed with base64 operation: {0}")]
    FromBase64(#[from] base64::DecodeError),
    #[error("failed with reason: {0}")]
    WithReason(String),
}
