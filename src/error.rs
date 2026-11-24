use thiserror::Error;

#[derive(Error, Debug)]
pub enum UfwError {
    #[error("Failed to read UFW log: {0}")]
    LogRead(#[from] std::io::Error),

    #[error("No UFW log found at {0}")]
    LogNotFound(String),

    #[error("Path is not a regular file: {0}")]
    NotAFile(String),

    #[error("Permission denied reading {path}. Hint: {hint}")]
    PermissionDenied { path: String, hint: String },
}
