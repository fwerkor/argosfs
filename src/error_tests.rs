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
