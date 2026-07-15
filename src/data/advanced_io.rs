use crate::error::{ArgosError, Result};
use crate::types::IoMode;
use crate::util::{ensure_private_dir, read_to_vec};
use io_uring::{opcode, types, IoUring};
use memmap2::MmapOptions;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const ALIGN: usize = 4096;
const MAX_SHARD_IO_BYTES: usize = 256 * 1024 * 1024;

pub fn write_all(path: &Path, data: &[u8], mode: IoMode) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    match mode {
        IoMode::Buffered => write_buffered(path, data),
        IoMode::Direct => write_direct(path, data).or_else(|_| write_buffered(path, data)),
        IoMode::IoUring => write_iouring(path, data).or_else(|_| write_buffered(path, data)),
    }
}

pub fn read_all(
    path: &Path,
    expected_size: usize,
    mode: IoMode,
    zero_copy: bool,
) -> Result<Vec<u8>> {
    match mode {
        IoMode::IoUring => {
            read_iouring(path, expected_size).or_else(|_| read_mmap_or_buffered(path, zero_copy))
        }
        IoMode::Direct => {
            read_direct(path, expected_size).or_else(|_| read_mmap_or_buffered(path, zero_copy))
        }
        IoMode::Buffered => read_mmap_or_buffered(path, zero_copy),
    }
}

pub fn io_uring_available() -> bool {
    IoUring::new(2).is_ok()
}

pub fn current_numa_node() -> Option<i32> {
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        return None;
    }
    for entry in fs::read_dir("/sys/devices/system/node").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("node") {
            continue;
        }
        let cpulist = fs::read_to_string(entry.path().join("cpulist")).ok()?;
        if cpu_list_contains(&cpulist, cpu as u32) {
            return name.strip_prefix("node")?.parse::<i32>().ok();
        }
    }
    None
}

fn write_buffered(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn read_mmap_or_buffered(path: &Path, zero_copy: bool) -> Result<Vec<u8>> {
    let file_size = usize::try_from(fs::metadata(path)?.len())
        .map_err(|_| ArgosError::FileTooLarge(path.display().to_string()))?;
    if file_size > MAX_SHARD_IO_BYTES {
        return Err(ArgosError::FileTooLarge(format!(
            "shard {} is {file_size} bytes, limit is {MAX_SHARD_IO_BYTES}",
            path.display()
        )));
    }
    if zero_copy {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len > 0 {
            let mmap = unsafe { MmapOptions::new().map(&file)? };
            return Ok(mmap.as_ref().to_vec());
        }
    }
    read_to_vec(path)
}

fn write_iouring(path: &Path, data: &[u8]) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let fd = file.as_raw_fd();
    let mut ring = IoUring::new(2).map_err(ArgosError::Io)?;
    let mut written = 0usize;
    while written < data.len() {
        let entry = opcode::Write::new(
            types::Fd(fd),
            data[written..].as_ptr(),
            (data.len() - written) as _,
        )
        .offset(written as u64)
        .build()
        .user_data(1);
        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                ArgosError::Invalid("io_uring submission queue is full".to_string())
            })?;
        }
        ring.submit_and_wait(1).map_err(ArgosError::Io)?;
        let cqe = ring.completion().next().ok_or_else(|| {
            ArgosError::Invalid("io_uring write produced no completion".to_string())
        })?;
        if cqe.result() < 0 {
            return Err(ArgosError::Io(std::io::Error::from_raw_os_error(
                -cqe.result(),
            )));
        }
        if cqe.result() == 0 {
            return Err(ArgosError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short io_uring write",
            )));
        }
        written = written.saturating_add(cqe.result() as usize);
    }
    file.sync_all()?;
    Ok(())
}

fn read_iouring(path: &Path, expected_size: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let file_size = usize::try_from(file.metadata()?.len())
        .map_err(|_| ArgosError::Invalid("file is too large to read".to_string()))?;
    let size = expected_size.max(file_size);
    if size > MAX_SHARD_IO_BYTES {
        return Err(ArgosError::FileTooLarge(format!(
            "io_uring shard read requires {size} bytes, limit is {MAX_SHARD_IO_BYTES}"
        )));
    }
    let mut data = Vec::new();
    data.try_reserve_exact(size)
        .map_err(|_| ArgosError::Io(std::io::Error::from_raw_os_error(libc::ENOMEM)))?;
    data.resize(size, 0);
    if size == 0 {
        return Ok(data);
    }
    let fd = file.as_raw_fd();
    let mut ring = IoUring::new(2).map_err(ArgosError::Io)?;
    let mut read_total = 0usize;
    while read_total < size {
        let entry = opcode::Read::new(
            types::Fd(fd),
            data[read_total..].as_mut_ptr(),
            (size - read_total) as _,
        )
        .offset(read_total as u64)
        .build()
        .user_data(1);
        unsafe {
            ring.submission().push(&entry).map_err(|_| {
                ArgosError::Invalid("io_uring submission queue is full".to_string())
            })?;
        }
        ring.submit_and_wait(1).map_err(ArgosError::Io)?;
        let cqe = ring.completion().next().ok_or_else(|| {
            ArgosError::Invalid("io_uring read produced no completion".to_string())
        })?;
        if cqe.result() < 0 {
            return Err(ArgosError::Io(std::io::Error::from_raw_os_error(
                -cqe.result(),
            )));
        }
        if cqe.result() == 0 {
            break;
        }
        read_total = read_total.saturating_add(cqe.result() as usize);
    }
    data.truncate(read_total);
    Ok(data)
}

fn write_direct(path: &Path, data: &[u8]) -> Result<()> {
    if data.is_empty() || !data.len().is_multiple_of(ALIGN) {
        return Err(ArgosError::Unsupported(
            "O_DIRECT requires aligned length".to_string(),
        ));
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(libc::O_DIRECT)
        .mode(0o600)
        .open(path)?;
    let mut aligned = AlignedBuf::new(data.len())?;
    aligned.as_mut_slice().copy_from_slice(data);
    let mut written_total = 0usize;
    while written_total < data.len() {
        let written = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                aligned.ptr.add(written_total).cast(),
                data.len() - written_total,
                written_total as libc::off_t,
            )
        };
        if written < 0 {
            return Err(ArgosError::Io(std::io::Error::last_os_error()));
        }
        if written == 0 {
            return Err(ArgosError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short O_DIRECT write",
            )));
        }
        written_total = written_total.saturating_add(written as usize);
    }
    file.sync_all()?;
    Ok(())
}

fn read_direct(path: &Path, expected_size: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)?;
    let file_size = usize::try_from(file.metadata()?.len())
        .map_err(|_| ArgosError::Invalid("file is too large to read".to_string()))?;
    let read_size = expected_size.max(file_size);
    if read_size > MAX_SHARD_IO_BYTES {
        return Err(ArgosError::FileTooLarge(format!(
            "direct shard read requires {read_size} bytes, limit is {MAX_SHARD_IO_BYTES}"
        )));
    }
    if read_size == 0 || !read_size.is_multiple_of(ALIGN) {
        return Err(ArgosError::Unsupported(
            "O_DIRECT requires aligned length".to_string(),
        ));
    }
    let aligned = AlignedBuf::new(read_size)?;
    let mut read_total = 0usize;
    while read_total < read_size {
        let read = unsafe {
            libc::pread(
                file.as_raw_fd(),
                aligned.ptr.add(read_total).cast(),
                read_size - read_total,
                read_total as libc::off_t,
            )
        };
        if read < 0 {
            return Err(ArgosError::Io(std::io::Error::last_os_error()));
        }
        if read == 0 {
            break;
        }
        read_total = read_total.saturating_add(read as usize);
        if read_total < read_size && !(read_total.is_multiple_of(ALIGN)) {
            break;
        }
    }
    Ok(aligned.as_slice()[..read_total].to_vec())
}

struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Result<Self> {
        let mut ptr = std::ptr::null_mut();
        let rc = unsafe { libc::posix_memalign(&mut ptr, ALIGN, len) };
        if rc != 0 {
            return Err(ArgosError::Io(std::io::Error::from_raw_os_error(rc)));
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { libc::free(self.ptr.cast()) }
    }
}

fn cpu_list_contains(spec: &str, cpu: u32) -> bool {
    spec.trim().split(',').any(|part| {
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.parse::<u32>() else {
                return false;
            };
            let Ok(end) = end.parse::<u32>() else {
                return false;
            };
            cpu >= start && cpu <= end
        } else {
            part.parse::<u32>().is_ok_and(|value| value == cpu)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn buffered_and_mmap_round_trips_include_empty_files() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("nested/data.bin");
        let payload = b"advanced io payload";
        write_all(&file, payload, IoMode::Buffered).unwrap();
        assert_eq!(
            read_all(&file, payload.len(), IoMode::Buffered, false).unwrap(),
            payload
        );
        assert_eq!(
            read_all(&file, payload.len(), IoMode::Buffered, true).unwrap(),
            payload
        );

        let empty = dir.path().join("empty.bin");
        write_all(&empty, b"", IoMode::Buffered).unwrap();
        assert!(read_all(&empty, 0, IoMode::Buffered, true)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn direct_mode_round_trips_aligned_data_or_falls_back_safely() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("direct.bin");
        let data = vec![0x5a; ALIGN * 2];
        write_all(&file, &data, IoMode::Direct).unwrap();
        assert_eq!(
            read_all(&file, data.len(), IoMode::Direct, false).unwrap(),
            data
        );
        assert!(matches!(
            write_direct(&file, b"unaligned"),
            Err(ArgosError::Unsupported(_))
        ));
        assert!(matches!(
            write_direct(&file, b""),
            Err(ArgosError::Unsupported(_))
        ));
    }

    #[test]
    fn direct_reads_validate_alignment_and_size_before_allocating() {
        let dir = tempdir().unwrap();
        let empty = dir.path().join("empty.bin");
        File::create(&empty).unwrap();
        assert!(matches!(
            read_direct(&empty, 0),
            Err(ArgosError::Unsupported(_))
        ));
        assert!(matches!(
            read_direct(&empty, 3),
            Err(ArgosError::Unsupported(_))
        ));
        assert!(matches!(
            read_direct(&empty, MAX_SHARD_IO_BYTES + 1),
            Err(ArgosError::FileTooLarge(_))
        ));
        assert!(matches!(
            read_iouring(&empty, MAX_SHARD_IO_BYTES + 1),
            Err(ArgosError::FileTooLarge(_))
        ));
    }

    #[test]
    fn mmap_reader_rejects_oversized_sparse_shards() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("huge.bin");
        File::create(&file)
            .unwrap()
            .set_len((MAX_SHARD_IO_BYTES + 1) as u64)
            .unwrap();
        assert!(matches!(
            read_mmap_or_buffered(&file, false),
            Err(ArgosError::FileTooLarge(_))
        ));
    }

    #[test]
    fn aligned_buffer_exposes_mutable_and_immutable_views() {
        let mut buffer = AlignedBuf::new(ALIGN).unwrap();
        assert_eq!((buffer.ptr as usize) % ALIGN, 0);
        buffer.as_mut_slice()[..4].copy_from_slice(b"test");
        assert_eq!(&buffer.as_slice()[..4], b"test");
    }

    #[test]
    fn cpu_list_parser_accepts_ranges_singletons_and_bad_fields() {
        assert!(cpu_list_contains("0-3,8,10-12", 0));
        assert!(cpu_list_contains("0-3,8,10-12", 8));
        assert!(cpu_list_contains("0-3,8,10-12", 11));
        assert!(!cpu_list_contains("0-3,8,10-12", 9));
        assert!(!cpu_list_contains("bad-3,also-bad", 1));
        assert!(!cpu_list_contains("3-bad", 3));
        let _ = current_numa_node();
        let _ = io_uring_available();
    }

    #[test]
    fn io_uring_mode_always_has_a_buffered_fallback() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("uring.bin");
        let payload = b"fallback payload";
        write_all(&file, payload, IoMode::IoUring).unwrap();
        assert_eq!(
            read_all(&file, payload.len(), IoMode::IoUring, true).unwrap(),
            payload
        );
    }
}
