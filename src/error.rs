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
    #[error("no data: {0}")]
    NoData(String),
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
    #[error("file name is too long: {0}")]
    NameTooLong(String),
    #[error("file or operation is too large: {0}")]
    FileTooLarge(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("metadata conflict: {0}")]
    Conflict(String),
    #[error("injected crash point: {0}")]
    InjectedCrash(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("checksum error: {0}")]
    Checksum(String),
    #[error("corrupted metadata: {0}")]
    CorruptedMetadata(String),
    #[error("incompatible format: {0}")]
    IncompatibleFormat(String),
    #[error("missing device: {0}")]
    MissingDevice(String),
    #[error("degraded pool: {0}")]
    DegradedPool(String),
    #[error("unsafe mount: {0}")]
    UnsafeMount(String),
    #[error("journal replay required: {0}")]
    JournalReplayRequired(String),
    #[error("readonly mount required: {0}")]
    ReadonlyRequired(String),
}

impl ArgosError {
    pub fn errno(&self) -> i32 {
        match self {
            ArgosError::NotFound(_) => libc::ENOENT,
            ArgosError::NoData(_) => libc::ENXIO,
            ArgosError::AlreadyExists(_) => libc::EEXIST,
            ArgosError::NotDirectory(_) => libc::ENOTDIR,
            ArgosError::IsDirectory(_) => libc::EISDIR,
            ArgosError::DirectoryNotEmpty(_) => libc::ENOTEMPTY,
            ArgosError::NotEnoughDisks { .. } => libc::ENOSPC,
            ArgosError::DiskFull { .. } => libc::ENOSPC,
            ArgosError::UnrecoverableStripe { .. } => libc::EIO,
            ArgosError::Invalid(_) => libc::EINVAL,
            ArgosError::NameTooLong(_) => libc::ENAMETOOLONG,
            ArgosError::FileTooLarge(_) => libc::EFBIG,
            ArgosError::PermissionDenied(_) => libc::EACCES,
            ArgosError::Conflict(_) => libc::EAGAIN,
            ArgosError::InjectedCrash(_) => libc::EIO,
            ArgosError::Unsupported(_) => libc::ENOTSUP,
            ArgosError::Checksum(_) => libc::EIO,
            ArgosError::CorruptedMetadata(_) => libc::EIO,
            ArgosError::IncompatibleFormat(_) => libc::EINVAL,
            ArgosError::MissingDevice(_) => libc::ENODEV,
            ArgosError::DegradedPool(_) => libc::EIO,
            ArgosError::UnsafeMount(_) => libc::EROFS,
            ArgosError::JournalReplayRequired(_) => libc::EAGAIN,
            ArgosError::ReadonlyRequired(_) => libc::EROFS,
            ArgosError::Io(err) => err.raw_os_error().unwrap_or(libc::EIO),
            _ => libc::EIO,
        }
    }
}

pub type Result<T> = std::result::Result<T, ArgosError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_variant_has_the_expected_errno() {
        let cases = [
            (ArgosError::Message("x".into()), libc::EIO),
            (
                ArgosError::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
                libc::EIO,
            ),
            (ArgosError::Erasure("x".into()), libc::EIO),
            (ArgosError::NotFound("x".into()), libc::ENOENT),
            (ArgosError::NoData("x".into()), libc::ENXIO),
            (ArgosError::AlreadyExists("x".into()), libc::EEXIST),
            (ArgosError::NotDirectory("x".into()), libc::ENOTDIR),
            (ArgosError::IsDirectory("x".into()), libc::EISDIR),
            (ArgosError::DirectoryNotEmpty("x".into()), libc::ENOTEMPTY),
            (
                ArgosError::NotEnoughDisks { need: 2, have: 1 },
                libc::ENOSPC,
            ),
            (
                ArgosError::DiskFull {
                    disk_id: "d".into(),
                    required: 2,
                    available: 1,
                },
                libc::ENOSPC,
            ),
            (
                ArgosError::UnrecoverableStripe {
                    stripe_id: "s".into(),
                    reason: "x".into(),
                },
                libc::EIO,
            ),
            (ArgosError::Invalid("x".into()), libc::EINVAL),
            (ArgosError::NameTooLong("x".into()), libc::ENAMETOOLONG),
            (ArgosError::FileTooLarge("x".into()), libc::EFBIG),
            (ArgosError::PermissionDenied("x".into()), libc::EACCES),
            (ArgosError::Conflict("x".into()), libc::EAGAIN),
            (ArgosError::InjectedCrash("x".into()), libc::EIO),
            (ArgosError::Unsupported("x".into()), libc::ENOTSUP),
            (ArgosError::Checksum("x".into()), libc::EIO),
            (ArgosError::CorruptedMetadata("x".into()), libc::EIO),
            (ArgosError::IncompatibleFormat("x".into()), libc::EINVAL),
            (ArgosError::MissingDevice("x".into()), libc::ENODEV),
            (ArgosError::DegradedPool("x".into()), libc::EIO),
            (ArgosError::UnsafeMount("x".into()), libc::EROFS),
            (ArgosError::JournalReplayRequired("x".into()), libc::EAGAIN),
            (ArgosError::ReadonlyRequired("x".into()), libc::EROFS),
        ];
        for (error, expected) in cases {
            assert_eq!(error.errno(), expected, "{error}");
        }
        assert_eq!(
            ArgosError::Io(std::io::Error::from_raw_os_error(libc::ENOSPC)).errno(),
            libc::ENOSPC
        );
        assert_eq!(
            ArgosError::Io(std::io::Error::other("no errno")).errno(),
            libc::EIO
        );
    }
}
