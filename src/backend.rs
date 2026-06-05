use crate::error::{ArgosError, Result};
use crate::types::{BackendKind, DiskStatus};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type DeviceId = String;

#[derive(Clone, Debug)]
pub struct BackendCapabilities {
    pub direct_io: bool,
    pub fallocate: bool,
    pub discard: bool,
}

#[derive(Clone, Debug)]
pub struct BackendDeviceInfo {
    pub device_id: DeviceId,
    pub path: PathBuf,
    pub capacity: u64,
    pub status: DiskStatus,
}

pub trait StorageBackend: Send + Sync {
    fn backend_kind(&self) -> BackendKind;
    fn list_devices(&self) -> Result<Vec<BackendDeviceInfo>>;
    fn read_at(&self, device_id: &DeviceId, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_at(&self, device_id: &DeviceId, offset: u64, data: &[u8]) -> Result<()>;
    fn flush_device(&self, device_id: &DeviceId) -> Result<()>;
    fn flush_all(&self) -> Result<()>;
    fn capacity(&self, device_id: &DeviceId) -> Result<u64>;
    fn device_status(&self, device_id: &DeviceId) -> Result<DiskStatus>;
    fn capabilities(&self) -> BackendCapabilities;
}

#[derive(Clone)]
pub struct HostFsBackend {
    root: PathBuf,
}

impl HostFsBackend {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }
}

impl StorageBackend for HostFsBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Host
    }

    fn list_devices(&self) -> Result<Vec<BackendDeviceInfo>> {
        Ok(Vec::new())
    }

    fn read_at(&self, _device_id: &DeviceId, _offset: u64, _buf: &mut [u8]) -> Result<()> {
        Err(ArgosError::Unsupported(format!(
            "host backend at {} does not expose raw read_at",
            self.root.display()
        )))
    }

    fn write_at(&self, _device_id: &DeviceId, _offset: u64, _data: &[u8]) -> Result<()> {
        Err(ArgosError::Unsupported(format!(
            "host backend at {} does not expose raw write_at",
            self.root.display()
        )))
    }

    fn flush_device(&self, _device_id: &DeviceId) -> Result<()> {
        Ok(())
    }

    fn flush_all(&self) -> Result<()> {
        Ok(())
    }

    fn capacity(&self, _device_id: &DeviceId) -> Result<u64> {
        Err(ArgosError::Unsupported(
            "host backend capacity is tracked in metadata".to_string(),
        ))
    }

    fn device_status(&self, _device_id: &DeviceId) -> Result<DiskStatus> {
        Ok(DiskStatus::Online)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            direct_io: false,
            fallocate: true,
            discard: false,
        }
    }
}

#[derive(Clone)]
pub struct FileBlockBackend {
    kind: BackendKind,
    devices: Arc<BTreeMap<DeviceId, BlockDevice>>,
}

#[derive(Debug)]
struct BlockDevice {
    path: PathBuf,
    file: File,
    capacity: u64,
}

impl FileBlockBackend {
    pub fn open_loop(paths: &[PathBuf], write: bool) -> Result<Self> {
        Self::open(paths, BackendKind::LoopBlock, write)
    }

    pub fn open_raw(paths: &[PathBuf], write: bool) -> Result<Self> {
        Self::open(paths, BackendKind::RawBlock, write)
    }

    pub fn open_with_ids(
        kind: BackendKind,
        devices: Vec<(DeviceId, PathBuf)>,
        write: bool,
    ) -> Result<Self> {
        let mut map = BTreeMap::new();
        for (device_id, path) in devices {
            let device = open_block_device(&path, write)?;
            map.insert(device_id, device);
        }
        Ok(Self {
            kind,
            devices: Arc::new(map),
        })
    }

    fn open(paths: &[PathBuf], kind: BackendKind, write: bool) -> Result<Self> {
        let mut map = BTreeMap::new();
        for (index, path) in paths.iter().enumerate() {
            let id = format!("disk-{index:04}");
            let device = open_block_device(path, write)?;
            map.insert(id, device);
        }
        Ok(Self {
            kind,
            devices: Arc::new(map),
        })
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.devices
            .values()
            .map(|device| device.path.clone())
            .collect()
    }

    fn device(&self, device_id: &DeviceId) -> Result<&BlockDevice> {
        self.devices
            .get(device_id)
            .ok_or_else(|| ArgosError::MissingDevice(device_id.clone()))
    }
}

impl StorageBackend for FileBlockBackend {
    fn backend_kind(&self) -> BackendKind {
        self.kind
    }

    fn list_devices(&self) -> Result<Vec<BackendDeviceInfo>> {
        Ok(self
            .devices
            .iter()
            .map(|(device_id, device)| BackendDeviceInfo {
                device_id: device_id.clone(),
                path: device.path.clone(),
                capacity: device.capacity,
                status: DiskStatus::Online,
            })
            .collect())
    }

    fn read_at(&self, device_id: &DeviceId, offset: u64, mut buf: &mut [u8]) -> Result<()> {
        let device = self.device(device_id)?;
        let mut cursor = offset;
        while !buf.is_empty() {
            let read = device.file.read_at(buf, cursor)?;
            if read == 0 {
                return Err(ArgosError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("short read on {device_id} at offset {cursor}"),
                )));
            }
            cursor = cursor.saturating_add(read as u64);
            let (_, rest) = buf.split_at_mut(read);
            buf = rest;
        }
        Ok(())
    }

    fn write_at(&self, device_id: &DeviceId, offset: u64, mut data: &[u8]) -> Result<()> {
        let device = self.device(device_id)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| ArgosError::Invalid("write offset overflow".to_string()))?;
        if end > device.capacity {
            return Err(ArgosError::DiskFull {
                disk_id: device_id.clone(),
                required: data.len() as u64,
                available: device.capacity.saturating_sub(offset),
            });
        }
        let mut cursor = offset;
        while !data.is_empty() {
            let written = device.file.write_at(data, cursor)?;
            if written == 0 {
                return Err(ArgosError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("short write on {device_id} at offset {cursor}"),
                )));
            }
            cursor = cursor.saturating_add(written as u64);
            data = &data[written..];
        }
        Ok(())
    }

    fn flush_device(&self, device_id: &DeviceId) -> Result<()> {
        self.device(device_id)?.file.sync_all()?;
        Ok(())
    }

    fn flush_all(&self) -> Result<()> {
        for device_id in self.devices.keys() {
            self.flush_device(device_id)?;
        }
        Ok(())
    }

    fn capacity(&self, device_id: &DeviceId) -> Result<u64> {
        Ok(self.device(device_id)?.capacity)
    }

    fn device_status(&self, device_id: &DeviceId) -> Result<DiskStatus> {
        let _ = self.device(device_id)?;
        Ok(DiskStatus::Online)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            direct_io: false,
            fallocate: true,
            discard: self.kind == BackendKind::RawBlock,
        }
    }
}

fn open_block_device(path: &Path, write: bool) -> Result<BlockDevice> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(write)
        .create(false)
        .open(path)?;
    let capacity = detect_capacity(&mut file)?;
    Ok(BlockDevice {
        path: path.to_path_buf(),
        file,
        capacity,
    })
}

fn detect_capacity(file: &mut File) -> Result<u64> {
    let len = file.metadata()?.len();
    if len != 0 {
        return Ok(len);
    }

    if let Some(bytes) = block_device_capacity(file)? {
        return Ok(bytes);
    }

    Ok(file.seek(SeekFrom::End(0))?)
}

#[cfg(target_os = "linux")]
fn block_device_capacity(file: &File) -> Result<Option<u64>> {
    const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;

    let mut bytes = 0u64;
    let result = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut bytes) };
    if result == 0 && bytes != 0 {
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}

#[cfg(not(target_os = "linux"))]
fn block_device_capacity(_file: &File) -> Result<Option<u64>> {
    Ok(None)
}
