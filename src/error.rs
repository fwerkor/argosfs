use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArgosError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("erasure coding error: {0}")]
    Erasure(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("not a directory: {0}")]
    NotDirectory(String),
    #[error("is a directory: {0}")]
    IsDirectory(String),
    #[error("directory not empty: {0}")]
    DirectoryNotEmpty(String),
    #[error("not enough online disks: need {need}, have {have}")]
    NotEnoughDisks { need: usize, have: usize },
    #[error("disk {disk_id} is full: required {required} bytes, available {available} bytes")]
    DiskFull {
        disk_id: String,
        required: u64,
        available: u64,
    },
    #[error("unrecoverable stripe {stripe_id}: {reason}")]
    UnrecoverableStripe { stripe_id: String, reason: String },
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("metadata conflict: {0}")]
    Conflict(String),
    #[error("injected crash point: {0}")]
    InjectedCrash(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

impl ArgosError {
    pub fn errno(&self) -> i32 {
        match self {
            ArgosError::NotFound(_) => libc::ENOENT,
            ArgosError::AlreadyExists(_) => libc::EEXIST,
            ArgosError::NotDirectory(_) => libc::ENOTDIR,
            ArgosError::IsDirectory(_) => libc::EISDIR,
            ArgosError::DirectoryNotEmpty(_) => libc::ENOTEMPTY,
            ArgosError::NotEnoughDisks { .. } => libc::ENOSPC,
            ArgosError::DiskFull { .. } => libc::ENOSPC,
            ArgosError::UnrecoverableStripe { .. } => libc::EIO,
            ArgosError::Invalid(_) => libc::EINVAL,
            ArgosError::PermissionDenied(_) => libc::EACCES,
            ArgosError::Conflict(_) => libc::EAGAIN,
            ArgosError::InjectedCrash(_) => libc::EIO,
            ArgosError::Unsupported(_) => libc::ENOTSUP,
            ArgosError::Io(err) => err.raw_os_error().unwrap_or(libc::EIO),
            _ => libc::EIO,
        }
    }
}

pub type Result<T> = std::result::Result<T, ArgosError>;
