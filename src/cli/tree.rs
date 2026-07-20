use super::*;

pub(super) fn import_tree(volume: &ArgosFs, source: &Path, dest: &str) -> Result<()> {
    if !source.is_dir() {
        bail!("source must be a directory: {}", source.display());
    }
    let dest = normalize_dest(dest);
    if dest != "/" {
        ensure_virtual_dir(volume, &dest, 0o755)?;
    }
    let dest_ino = volume.resolve_path(&dest, true)?;

    let mut imported_dirs = BTreeMap::<PathBuf, u64>::new();
    imported_dirs.insert(PathBuf::new(), dest_ino);
    let mut imported_files = BTreeMap::<(u64, u64), u64>::new();

    let mut directories = vec![(source.to_path_buf(), dest_ino)];
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        let path = entry.path();
        if path == source {
            continue;
        }

        let rel = path.strip_prefix(source)?;
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        let parent_ino = *imported_dirs
            .get(parent_rel)
            .with_context(|| format!("missing imported parent for {}", path.display()))?;
        let name = rel
            .file_name()
            .with_context(|| format!("missing file name for {}", path.display()))?;

        let meta = fs::symlink_metadata(path)?;
        let ft = meta.file_type();
        let mode = meta.mode();

        if ft.is_dir() {
            let ino = match volume.mkdir_at_with_owner(
                parent_ino,
                name,
                mode & 0o7777,
                meta.uid(),
                meta.gid(),
            ) {
                Ok(attr) => attr.ino,
                Err(ArgosError::AlreadyExists(_)) => {
                    let attr = volume.lookup(parent_ino, name)?;
                    if attr.kind != NodeKind::Directory {
                        bail!(
                            "import target exists but is not a directory: {}",
                            path.display()
                        );
                    }
                    attr.ino
                }
                Err(err) => return Err(err.into()),
            };
            imported_dirs.insert(rel.to_path_buf(), ino);
            directories.push((path.to_path_buf(), ino));
        } else if ft.is_file() {
            let key = (meta.dev(), meta.ino());
            if meta.nlink() > 1 {
                if let Some(existing_ino) = imported_files.get(&key).copied() {
                    match volume.link_at(existing_ino, parent_ino, name) {
                        Ok(attr) => {
                            apply_import_metadata(volume, path, attr.ino, &meta)?;
                            continue;
                        }
                        Err(ArgosError::AlreadyExists(_)) => {
                            let attr = volume.lookup(parent_ino, name)?;
                            if attr.ino != existing_ino {
                                bail!("hardlink import target already exists with a different inode: {}", path.display());
                            }
                            apply_import_metadata(volume, path, attr.ino, &meta)?;
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }

            let data = fs::read(path)?;
            let ino = match volume.create_file_at_with_owner(
                parent_ino,
                name,
                mode & 0o7777,
                meta.uid(),
                meta.gid(),
            ) {
                Ok(attr) => attr.ino,
                Err(ArgosError::AlreadyExists(_)) => {
                    let attr = volume.lookup(parent_ino, name)?;
                    if attr.kind != NodeKind::File {
                        bail!("import target exists but is not a file: {}", path.display());
                    }
                    volume.truncate_inode(attr.ino, 0)?;
                    attr.ino
                }
                Err(err) => return Err(err.into()),
            };
            if meta.nlink() > 1 {
                imported_files.insert(key, ino);
            }
            if !data.is_empty() {
                volume.write_inode_range(ino, 0, &data).map_err(|err| {
                    anyhow::anyhow!("import file data from {}: {err}", path.display())
                })?;
            }
            apply_import_metadata(volume, path, ino, &meta)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(path)?;
            let attr =
                volume.symlink_at_with_owner(parent_ino, name, &target, meta.uid(), meta.gid())?;
            apply_import_metadata(volume, path, attr.ino, &meta)?;
        } else if ft.is_char_device() || ft.is_block_device() || ft.is_fifo() || ft.is_socket() {
            let attr = volume.mknod_at_with_owner(
                parent_ino,
                name,
                mode,
                meta.rdev(),
                meta.uid(),
                meta.gid(),
            )?;
            apply_import_metadata(volume, path, attr.ino, &meta)?;
        }
    }

    for (path, ino) in directories.into_iter().rev() {
        let meta = fs::symlink_metadata(&path)?;
        apply_import_metadata(volume, &path, ino, &meta)?;
    }
    Ok(())
}

fn apply_import_metadata(
    volume: &ArgosFs,
    source: &Path,
    ino: u64,
    meta: &fs::Metadata,
) -> Result<()> {
    let _ = volume.chown_inode(ino, Some(meta.uid()), Some(meta.gid()))?;
    if !meta.file_type().is_symlink() {
        let _ = volume.chmod_inode(ino, meta.mode() & 0o7777)?;
    }
    let atime = meta.atime() as f64 + meta.atime_nsec() as f64 / 1_000_000_000.0;
    let mtime = meta.mtime() as f64 + meta.mtime_nsec() as f64 / 1_000_000_000.0;
    let _ = volume.utimens_inode(ino, atime, mtime)?;
    for (name, value) in read_xattrs(source)? {
        volume
            .importxattr_inode(ino, &name, &value)
            .with_context(|| format!("import xattr {name:?} from {}", source.display()))?;
    }
    Ok(())
}

fn ensure_virtual_dir(volume: &ArgosFs, path: &str, mode: u32) -> Result<()> {
    let path = normalize_dest(path);
    if path == "/" {
        return Ok(());
    }
    let mut current = String::new();
    for part in path.trim_start_matches('/').split('/') {
        current.push('/');
        current.push_str(part);
        match volume.mkdir(&current, if current == path { mode } else { 0o755 }) {
            Ok(_) => {}
            Err(ArgosError::AlreadyExists(_)) => {
                let attr = volume.attr_path(&current, true)?;
                if attr.kind != NodeKind::Directory {
                    bail!("import target exists but is not a directory: {current}");
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

pub(super) fn export_tree(volume: &ArgosFs, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    let mut paths = volume.iter_path_bytes();
    paths.sort_by_key(|(path, _)| path.iter().filter(|byte| **byte == b'/').count());

    let mut directories = Vec::new();
    let mut exported_files = BTreeMap::<u64, PathBuf>::new();
    for (path, ino) in paths {
        if path.as_slice() == b"/" {
            continue;
        }
        let attr = volume.attr_inode(ino)?;
        let target = export_target_from_path_bytes(dest, &path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        match attr.kind {
            NodeKind::Directory => {
                prepare_export_target(&target, &attr.kind)?;
                fs::create_dir_all(&target)?;
                directories.push((ino, target, attr));
            }
            NodeKind::File => {
                prepare_export_target(&target, &attr.kind)?;
                if attr.nlink > 1 {
                    if let Some(first_target) = exported_files.get(&ino) {
                        fs::hard_link(first_target, &target).with_context(|| {
                            format!(
                                "hardlink {} -> {}",
                                target.display(),
                                first_target.display()
                            )
                        })?;
                        apply_export_metadata(volume, ino, &target, &attr)?;
                        continue;
                    }
                    exported_files.insert(ino, target.clone());
                }
                fs::write(&target, volume.read_inode(ino, 0, u64::MAX as usize, true)?)?;
                apply_export_metadata(volume, ino, &target, &attr)?;
            }
            NodeKind::Symlink => {
                prepare_export_target(&target, &attr.kind)?;
                let link = volume.readlink_inode_bytes(ino)?;
                let link = Path::new(std::ffi::OsStr::from_bytes(&link));
                std::os::unix::fs::symlink(link, &target)?;
                apply_export_metadata(volume, ino, &target, &attr)?;
            }
            NodeKind::Special => {
                prepare_export_target(&target, &attr.kind)?;
                let c_path = CString::new(target.as_os_str().as_bytes())?;
                let rc = unsafe {
                    libc::mknod(
                        c_path.as_ptr(),
                        attr.mode as libc::mode_t,
                        attr.rdev as libc::dev_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("mknod {}", target.display()));
                }
                apply_export_metadata(volume, ino, &target, &attr)?;
            }
        }
    }

    for (ino, target, attr) in directories.into_iter().rev() {
        apply_export_metadata(volume, ino, &target, &attr)?;
    }
    let root_attr = volume.attr_path("/", false)?;
    apply_export_metadata(volume, root_attr.ino, dest, &root_attr)?;
    Ok(())
}

fn export_target_from_path_bytes(dest: &Path, path: &[u8]) -> PathBuf {
    let mut target = dest.to_path_buf();
    let rel = path.strip_prefix(b"/").unwrap_or(path);
    for component in rel.split(|byte| *byte == b'/') {
        if !component.is_empty() {
            target.push(std::ffi::OsStr::from_bytes(component));
        }
    }
    target
}

fn apply_export_metadata(volume: &ArgosFs, ino: u64, target: &Path, attr: &NodeAttr) -> Result<()> {
    if let Err(err) = lchown_path(target, attr.uid, attr.gid) {
        let non_fatal_chown = matches!(
            err.downcast_ref::<io::Error>()
                .and_then(|err| err.raw_os_error()),
            Some(libc::EPERM) | Some(libc::EINVAL)
        );
        if !non_fatal_chown {
            return Err(err);
        }
    }
    if attr.kind != NodeKind::Symlink {
        fs::set_permissions(target, fs::Permissions::from_mode(attr.mode & 0o7777))?;
    }
    set_times_nofollow(target, attr.atime, attr.mtime)?;
    for name in volume.listxattr_inode(ino)? {
        if is_internal_export_xattr(&name) {
            continue;
        }
        let value = volume.getxattr_inode(ino, &name)?;
        if let Err(err) = write_xattr_nofollow(target, &name, &value) {
            let non_fatal = matches!(
                err.downcast_ref::<io::Error>()
                    .and_then(|err| err.raw_os_error()),
                Some(libc::EOPNOTSUPP)
                    | Some(libc::EPERM)
                    | Some(libc::EACCES)
                    | Some(libc::EINVAL)
            );
            if name == "security.capability" || name.starts_with("user.") {
                return Err(err)
                    .with_context(|| format!("write xattr {name:?} to {}", target.display()));
            }
            if non_fatal {
                eprintln!(
                    "warning: skipped unsupported export xattr {name:?} on {}: {err}",
                    target.display()
                );
            } else {
                return Err(err)
                    .with_context(|| format!("write xattr {name:?} to {}", target.display()));
            }
        }
    }
    Ok(())
}

fn prepare_export_target(target: &Path, kind: &NodeKind) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(target) else {
        return Ok(());
    };
    let file_type = metadata.file_type();
    match kind {
        NodeKind::Directory => {
            if file_type.is_dir() && !file_type.is_symlink() {
                Ok(())
            } else {
                fs::remove_file(target).with_context(|| format!("replace {}", target.display()))
            }
        }
        NodeKind::File | NodeKind::Symlink | NodeKind::Special => {
            if file_type.is_dir() && !file_type.is_symlink() {
                bail!("export target exists as a directory: {}", target.display());
            }
            fs::remove_file(target).with_context(|| format!("replace {}", target.display()))
        }
    }
}

fn c_path(path: &Path) -> Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

const XATTR_READ_RETRIES: usize = 4;

fn read_xattrs(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let c_path = c_path(path)?;
    let mut names = Vec::new();
    for _ in 0..XATTR_READ_RETRIES {
        let size = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EOPNOTSUPP)) {
                return Ok(Vec::new());
            }
            return Err(err.into());
        }
        if size == 0 {
            names.clear();
            break;
        }
        names.resize(size as usize, 0);
        let read = unsafe {
            libc::llistxattr(
                c_path.as_ptr(),
                names.as_mut_ptr().cast::<libc::c_char>(),
                names.len(),
            )
        };
        if read >= 0 {
            names.truncate(read as usize);
            break;
        }
        let err = io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::ERANGE)) {
            return Err(err.into());
        }
    }
    let mut out = Vec::new();
    for raw_name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = std::str::from_utf8(raw_name)
            .with_context(|| format!("non-UTF-8 xattr name on {}", path.display()))?;
        let value = read_xattr(path, name)
            .with_context(|| format!("read xattr {name:?} from {}", path.display()))?;
        out.push((name.to_string(), value));
    }
    Ok(out)
}

fn read_xattr(path: &Path, name: &str) -> Result<Vec<u8>> {
    let c_path = c_path(path)?;
    let c_name = CString::new(name)?;
    let mut value = Vec::new();
    for attempt in 0..XATTR_READ_RETRIES {
        let size =
            unsafe { libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error().into());
        }
        value.resize(size as usize, 0);
        let read = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast::<libc::c_void>(),
                value.len(),
            )
        };
        if read >= 0 {
            value.truncate(read as usize);
            return Ok(value);
        }
        let err = io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::ERANGE)) || attempt + 1 == XATTR_READ_RETRIES {
            return Err(err.into());
        }
    }
    Ok(value)
}

fn write_xattr_nofollow(path: &Path, name: &str, value: &[u8]) -> Result<()> {
    let c_path = c_path(path)?;
    let c_name = CString::new(name)?;
    let rc = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn is_internal_export_xattr(name: &str) -> bool {
    name.starts_with("system.argosfs.")
}

fn lchown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = c_path(path)?;
    let rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("lchown {}", path.display()));
    }
    Ok(())
}

fn set_times_nofollow(path: &Path, atime: f64, mtime: f64) -> Result<()> {
    let c_path = c_path(path)?;
    let times = [timespec_from_f64(atime), timespec_from_f64(mtime)];
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("utimensat {}", path.display()));
    }
    Ok(())
}

fn timespec_from_f64(value: f64) -> libc::timespec {
    let seconds = value.trunc().max(0.0);
    let nanos = ((value - seconds) * 1_000_000_000.0).clamp(0.0, 999_999_999.0);
    libc::timespec {
        tv_sec: seconds as _,
        tv_nsec: nanos as _,
    }
}

fn normalize_dest(dest: &str) -> String {
    clean_path(dest.trim())
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
