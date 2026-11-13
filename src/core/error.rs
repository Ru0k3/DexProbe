use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("archive limit exceeded: {0}")]
    ArchiveLimit(String),
    #[error("malformed archive: {0}")]
    MalformedArchive(String),
    #[error("manifest decode failed: {0}")]
    ManifestDecode(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("service error: {0}")]
    Service(String),
    #[error("policy failure: {0}")]
    Policy(String),
}
