use super::*;
use super::{parse_byte_size_u64, parse_byte_size_usize, parse_u32_auto, parse_u64_auto};

#[derive(Args, Clone, Debug, Default)]
pub(super) struct BackendArgs {
    /// Storage backend. When omitted, ArgosFS infers loop/raw from the supplied paths.
    #[arg(long, value_name = "BACKEND")]
    pub(super) backend: Option<BackendKind>,

    /// Comma-separated loop image files. Conflicts with --devices.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "PATHS",
        conflicts_with = "devices"
    )]
    pub(super) images: Vec<PathBuf>,

    /// Comma-separated raw block devices. Conflicts with --images.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "PATHS",
        conflicts_with = "images"
    )]
    pub(super) devices: Vec<PathBuf>,

    /// Load backend, device paths, and optional pool identity from a JSON file.
    #[arg(long, value_name = "FILE")]
    pub(super) pool_config: Option<PathBuf>,
}

#[derive(Args, Clone, Debug, Default)]
pub(super) struct PoolArgs {
    #[command(flatten)]
    pub(super) storage: BackendArgs,

    /// Require the opened pool to have this UUID or pool name.
    #[arg(long, value_name = "POOL")]
    pub(super) pool: Option<String>,
}

#[derive(Debug)]
pub(super) struct ResolvedBackendArgs {
    pub(super) backend: BackendKind,
    pub(super) images: Vec<PathBuf>,
    pub(super) devices: Vec<PathBuf>,
    pub(super) pool: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolConfigFile {
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    images: Vec<PathBuf>,
    #[serde(default)]
    devices: Vec<PathBuf>,
    #[serde(default)]
    pool: Option<String>,
}

impl BackendArgs {
    pub(super) fn resolve(self, default_backend: BackendKind) -> Result<ResolvedBackendArgs> {
        let config_path = self.pool_config.clone();
        let mut config = match self.pool_config {
            Some(path) => load_pool_config(&path)?,
            None => PoolConfigFile::default(),
        };
        if let Some(path) = config_path.as_deref() {
            resolve_config_paths(path, &mut config.images);
            resolve_config_paths(path, &mut config.devices);
        }

        if !self.images.is_empty() && !self.devices.is_empty() {
            bail!("--images and --devices cannot be used together");
        }

        let cli_has_images = !self.images.is_empty();
        let cli_has_devices = !self.devices.is_empty();
        let images = if cli_has_images {
            self.images
        } else if cli_has_devices {
            Vec::new()
        } else {
            config.images
        };
        let devices = if cli_has_devices {
            self.devices
        } else if cli_has_images {
            Vec::new()
        } else {
            config.devices
        };

        if !images.is_empty() && !devices.is_empty() {
            bail!(
                "pool configuration resolves both images and devices; choose exactly one storage path type"
            );
        }

        let inferred_from_cli = if cli_has_images {
            Some(BackendKind::LoopBlock)
        } else if cli_has_devices {
            Some(BackendKind::RawBlock)
        } else {
            None
        };
        let configured_backend = config
            .backend
            .as_deref()
            .map(str::parse::<BackendKind>)
            .transpose()
            .map_err(anyhow::Error::msg)?;
        let inferred_from_config = if !images.is_empty() {
            Some(BackendKind::LoopBlock)
        } else if !devices.is_empty() {
            Some(BackendKind::RawBlock)
        } else {
            None
        };
        let backend = self
            .backend
            .or(inferred_from_cli)
            .or(configured_backend)
            .or(inferred_from_config)
            .unwrap_or(default_backend);

        validate_backend_selector(backend, &images, &devices)?;
        Ok(ResolvedBackendArgs {
            backend,
            images,
            devices,
            pool: config.pool,
        })
    }
}

impl PoolArgs {
    pub(super) fn resolve(self, default_backend: BackendKind) -> Result<ResolvedBackendArgs> {
        let requested_pool = self.pool;
        let mut resolved = self.storage.resolve(default_backend)?;
        if requested_pool.is_some() {
            resolved.pool = requested_pool;
        }
        if resolved.backend == BackendKind::Host && resolved.pool.is_some() {
            bail!("--pool and pool-config pool identities are only valid for loop/raw backends");
        }
        Ok(resolved)
    }
}

fn load_pool_config(path: &Path) -> Result<PoolConfigFile> {
    let bytes = fs::read(path).with_context(|| format!("read pool config {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse pool config {} as JSON", path.display()))
}

fn resolve_config_paths(config_path: &Path, paths: &mut [PathBuf]) {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    for path in paths {
        if path.is_relative() {
            *path = base.join(&*path);
        }
    }
}

fn validate_backend_selector(
    backend: BackendKind,
    images: &[PathBuf],
    devices: &[PathBuf],
) -> Result<()> {
    match backend {
        BackendKind::Host if !images.is_empty() || !devices.is_empty() => {
            bail!("host backend uses ROOT and cannot be combined with --images or --devices")
        }
        BackendKind::LoopBlock if !devices.is_empty() => {
            bail!("loop backend requires --images and cannot be combined with --devices")
        }
        BackendKind::RawBlock if !images.is_empty() => {
            bail!("raw backend requires --devices and cannot be combined with --images")
        }
        _ => Ok(()),
    }
}

#[derive(Subcommand)]
pub(super) enum Command {
    #[command(about = "Create a new host, loop-image, or raw-device ArgosFS volume")]
    Mkfs {
        /// Host-backend volume directory. Omit for loop/raw pools.
        root: Option<PathBuf>,
        #[command(flatten)]
        storage: BackendArgs,
        /// Size used when creating a loop image (for example 64MiB or 2GiB).
        #[arg(long, value_name = "SIZE", value_parser = parse_byte_size_u64)]
        image_size: Option<u64>,
        /// Human-readable name stored in a loop/raw pool.
        #[arg(long, value_name = "NAME")]
        pool_name: Option<String>,
        /// Number of host-backend shard directories to create.
        #[arg(long, value_name = "COUNT")]
        disks: Option<usize>,
        /// Number of data shards required to reconstruct each stripe.
        #[arg(long, default_value_t = 4)]
        k: usize,
        /// Number of parity shards available for failure tolerance.
        #[arg(long, default_value_t = 2)]
        m: usize,
        /// Logical stripe chunk size (for example 256KiB or 1MiB).
        #[arg(long, default_value = "256KiB", value_name = "SIZE", value_parser = parse_byte_size_usize)]
        chunk_size: usize,
        /// Per-stripe compression codec: none, lz4, or zstd.
        #[arg(long, default_value = "zstd")]
        compression: Compression,
        /// Codec-specific compression level.
        #[arg(long, default_value_t = 3)]
        compression_level: i32,
        /// Batch journal flushes; intended for block-backed group commit.
        #[arg(long)]
        defer_journal_flush: bool,
        /// Enable bounded metadata group commit on loop/raw pools.
        #[arg(long)]
        defer_metadata_commit: bool,
        /// Batch data flushes until the metadata durability boundary.
        #[arg(long)]
        defer_data_flush: bool,
        /// Maximum idle time before a deferred metadata group is committed.
        #[arg(long, default_value_t = DEFAULT_DEFERRED_COMMIT_INTERVAL_MS)]
        deferred_commit_interval_ms: u64,
        /// Maximum metadata transactions in one deferred group.
        #[arg(long, default_value_t = DEFAULT_DEFERRED_COMMIT_MAX_TRANSACTIONS)]
        deferred_commit_max_transactions: u64,
        /// Permit destructive replacement of recognized signatures or existing images.
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Scan loop images or raw devices for ArgosFS signatures")]
    Scan {
        #[command(flatten)]
        storage: BackendArgs,
    },
    #[command(about = "Inspect one loop image or raw device without modifying it")]
    InspectDevice {
        path: PathBuf,
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
    },
    #[command(about = "Show health and identity information for a block-backed pool")]
    InspectPool {
        #[command(flatten)]
        storage: PoolArgs,
    },
    #[command(about = "List members of a block-backed pool")]
    ListDevices {
        #[command(flatten)]
        storage: PoolArgs,
    },
    #[command(about = "Add a loop image or raw device to a block-backed pool")]
    AddDevice {
        #[command(flatten)]
        storage: PoolArgs,
        /// New loop-image path or raw block-device path.
        #[arg(long)]
        device: PathBuf,
        /// Size used when creating a loop image (for example 64MiB or 2GiB).
        #[arg(long, value_name = "SIZE", value_parser = parse_byte_size_u64)]
        image_size: Option<u64>,
        /// Permit reuse of an existing loop image or signed block path.
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Move data away from a block-backed pool member")]
    DrainDevice {
        #[command(flatten)]
        storage: PoolArgs,
        /// Logical member ID, such as disk-0002.
        #[arg(long)]
        device: String,
    },
    #[command(about = "Add a replacement member and remove an old member")]
    ReplaceDevice {
        #[command(flatten)]
        storage: PoolArgs,
        /// Logical member ID being replaced.
        #[arg(long)]
        old: String,
        /// Replacement loop-image or raw-device path.
        #[arg(long)]
        new: PathBuf,
        /// Size used when creating a loop image (for example 64MiB or 2GiB).
        #[arg(long, value_name = "SIZE", value_parser = parse_byte_size_u64)]
        image_size: Option<u64>,
        /// Permit reuse of an existing replacement path.
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Remove a member after rewriting its data elsewhere")]
    RemoveDevice {
        #[command(flatten)]
        storage: PoolArgs,
        /// Logical member ID to remove.
        #[arg(long)]
        device: String,
    },
    #[command(about = "Mount a host-backend volume through FUSE")]
    Mount {
        /// Host-backend volume directory.
        root: PathBuf,
        /// Existing directory used as the FUSE mountpoint.
        mountpoint: PathBuf,
        /// Retained for service compatibility; the current frontend stays foregrounded.
        #[arg(long)]
        foreground: bool,
        /// FUSE mount option; repeat for multiple options.
        #[arg(short = 'o', long = "option")]
        option: Vec<String>,
    },
    #[command(about = "Mount a loop/raw pool as a root filesystem")]
    MountRoot {
        #[command(flatten)]
        storage: PoolArgs,
        /// Existing directory that will become the mounted root.
        #[arg(long, default_value = "/sysroot")]
        target: PathBuf,
        /// Mount policy: rw, ro, degraded-ro, degraded-rw, or recovery.
        #[arg(long, default_value = "rw")]
        mode: RootMountMode,
        /// Retained for service compatibility; the current frontend stays foregrounded.
        #[arg(long)]
        foreground: bool,
        /// FUSE mount option; repeat for multiple options.
        #[arg(short = 'o', long = "option")]
        option: Vec<String>,
    },
    #[command(about = "Validate whether a loop/raw pool is safe to mount as root")]
    PreflightRoot {
        #[command(flatten)]
        storage: PoolArgs,
        /// Requested root policy: rw, ro, degraded-ro, degraded-rw, or recovery.
        #[arg(long, default_value = "rw")]
        mode: RootMountMode,
    },
    #[command(about = "Replay and synchronize a loop/raw pool journal")]
    ReplayJournal {
        #[command(flatten)]
        storage: PoolArgs,
    },
    #[command(about = "Mount a loop/raw pool read-only for recovery")]
    MountRecovery {
        #[command(flatten)]
        storage: PoolArgs,
        /// Existing directory used as the read-only recovery mountpoint.
        #[arg(long)]
        target: PathBuf,
    },
    #[command(about = "Copy a local file into a host-backend volume")]
    Put {
        root: PathBuf,
        local: PathBuf,
        path: String,
    },
    #[command(about = "Copy a file from a host-backend volume to the host")]
    Get {
        root: PathBuf,
        path: String,
        local: PathBuf,
    },
    #[command(about = "Write a file from a host-backend volume to stdout")]
    Cat { root: PathBuf, path: String },
    #[command(about = "List a directory in a host-backend volume")]
    Ls {
        root: PathBuf,
        #[arg(default_value = "/")]
        path: String,
    },
    #[command(about = "Show inode metadata for a path")]
    Stat { root: PathBuf, path: String },
    #[command(about = "Remove a file or empty directory")]
    Rm { root: PathBuf, path: String },
    #[command(about = "Create a directory")]
    Mkdir {
        root: PathBuf,
        path: String,
        #[arg(long, default_value = "755", value_parser = parse_u32_auto)]
        mode: u32,
    },
    #[command(about = "Create a special node")]
    Mknod {
        root: PathBuf,
        path: String,
        #[arg(long, value_parser = parse_u32_auto)]
        mode: u32,
        #[arg(long, default_value = "0", value_parser = parse_u64_auto)]
        rdev: u64,
    },
    #[command(about = "Create a symbolic link")]
    Symlink {
        root: PathBuf,
        target: String,
        link: String,
    },
    #[command(about = "Rename or move a path")]
    Rename {
        root: PathBuf,
        old: String,
        new: String,
    },
    #[command(about = "Change path permissions")]
    Chmod {
        root: PathBuf,
        path: String,
        #[arg(value_parser = parse_u32_auto)]
        mode: u32,
    },
    #[command(about = "Set a file length")]
    Truncate {
        root: PathBuf,
        path: String,
        size: u64,
    },
    #[command(about = "Import a host directory tree into a volume")]
    ImportTree {
        #[command(flatten)]
        storage: BackendArgs,
        #[arg(required = true, num_args = 1..=3)]
        args: Vec<PathBuf>,
    },
    #[command(about = "Export a volume tree to a host directory")]
    ExportTree {
        #[command(flatten)]
        storage: BackendArgs,
        #[arg(required = true, num_args = 1..=2)]
        args: Vec<PathBuf>,
    },
    #[command(about = "Add a host-backend storage directory")]
    AddDisk {
        root: PathBuf,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        tier: Option<StorageTier>,
        #[arg(long)]
        weight: Option<f64>,
        /// Override capacity; accepts bytes or suffixes such as GiB/TiB.
        #[arg(long, value_name = "SIZE", value_parser = parse_byte_size_u64)]
        capacity_bytes: Option<u64>,
        #[arg(long)]
        rebalance: bool,
    },
    #[command(about = "Refresh host-backend device class and capacity observations")]
    ProbeDisks {
        root: PathBuf,
        disk_id: Option<String>,
    },
    #[command(about = "Refresh SMART/NVMe health data for host-backend disks")]
    RefreshSmart {
        root: PathBuf,
        disk_id: Option<String>,
    },
    #[command(about = "Remove a host-backend disk after rewriting its data")]
    RemoveDisk { root: PathBuf, disk_id: String },
    #[command(about = "Set the administrative state of a host-backend disk")]
    MarkDisk {
        root: PathBuf,
        disk_id: String,
        status: DiskStatus,
    },
    #[command(about = "Override observed health counters for testing or recovery")]
    SetHealth {
        root: PathBuf,
        disk_id: String,
        #[arg(long)]
        reallocated_sectors: Option<u64>,
        #[arg(long)]
        pending_sectors: Option<u64>,
        #[arg(long)]
        crc_errors: Option<u64>,
        #[arg(long)]
        io_errors: Option<u64>,
        #[arg(long)]
        latency_ms: Option<f64>,
        #[arg(long)]
        wear_percent: Option<f64>,
        #[arg(long)]
        temperature_c: Option<f64>,
    },
    #[command(about = "Show volume and disk health")]
    Health {
        /// Host-backend volume directory.
        root: PathBuf,
    },
    #[command(about = "Check consistency and optionally repair a volume")]
    Fsck {
        /// Host-backend volume directory. Omit for loop/raw selectors.
        root: Option<PathBuf>,
        #[command(flatten)]
        storage: PoolArgs,
        /// Rewrite recoverable damaged data and metadata.
        #[arg(long)]
        repair: bool,
        /// Remove unreferenced shard data; implies writable open.
        #[arg(long)]
        remove_orphans: bool,
    },
    #[command(about = "Verify data and repair recoverable corruption")]
    Scrub {
        /// Host-backend volume directory. Omit for loop/raw selectors.
        root: Option<PathBuf>,
        #[command(flatten)]
        storage: PoolArgs,
    },
    #[command(about = "Redistribute host-backend files across disks")]
    Rebalance { root: PathBuf },
    #[command(about = "Migrate data to a new k+m erasure layout")]
    Reshape {
        /// Host-backend volume directory. Omit for loop/raw selectors.
        root: Option<PathBuf>,
        #[command(flatten)]
        storage: PoolArgs,
        /// Target number of data shards.
        #[arg(long)]
        k: usize,
        /// Target number of parity shards.
        #[arg(long)]
        m: usize,
        /// Bound this invocation to at most this many files.
        #[arg(long)]
        max_files: Option<usize>,
    },
    #[command(about = "Run health-driven maintenance once or continuously")]
    Autopilot {
        /// Host-backend volume directory.
        root: PathBuf,
        /// Optional JSON policy; defaults to ROOT/.argosfs/autopilot-policy.json.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Run one maintenance cycle and exit.
        #[arg(long)]
        once: bool,
        /// Plan actions without mutating the volume.
        #[arg(long)]
        dry_run: bool,
        /// Alias for a detailed non-mutating plan.
        #[arg(long)]
        explain: bool,
        /// Seconds between continuous maintenance cycles.
        #[arg(long, default_value_t = 60)]
        interval: u64,
    },
    #[command(about = "Create a named metadata snapshot")]
    Snapshot { root: PathBuf, name: String },
    #[command(about = "Enable authenticated data encryption")]
    EnableEncryption {
        root: PathBuf,
        #[arg(
            long,
            help = "INSECURE/testing-only: visible in argv and shell history; prefer --key-file or --passphrase-stdin"
        )]
        passphrase: Option<String>,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long)]
        reencrypt: bool,
    },
    #[command(about = "Show encryption state and encrypted block count")]
    EncryptionStatus { root: PathBuf },
    #[command(about = "Persist the data-plane I/O policy")]
    SetIoMode {
        root: PathBuf,
        #[arg(long, default_value = "buffered")]
        mode: IoMode,
        #[arg(long)]
        direct_io: bool,
        #[arg(long)]
        no_zero_copy: bool,
        #[arg(long)]
        no_numa: bool,
    },
    #[command(about = "Serve Prometheus metrics over HTTP")]
    Prometheus {
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9108")]
        listen: String,
    },
    #[command(about = "Set a POSIX ACL on a path")]
    SetPosixAcl {
        root: PathBuf,
        path: String,
        acl: String,
        #[arg(long)]
        default_acl: bool,
    },
    #[command(about = "Print a POSIX ACL")]
    GetPosixAcl {
        root: PathBuf,
        path: String,
        #[arg(long)]
        default_acl: bool,
    },
    #[command(about = "Set an NFSv4 ACL from inline JSON or @FILE")]
    SetNfs4Acl {
        root: PathBuf,
        path: String,
        acl_json: String,
    },
    #[command(about = "Print an NFSv4 ACL as JSON")]
    GetNfs4Acl { root: PathBuf, path: String },
    #[command(about = "Verify journal and metadata hash chains")]
    VerifyJournal {
        /// Host-backend volume directory. Omit for loop/raw selectors.
        root: Option<PathBuf>,
        #[command(flatten)]
        storage: PoolArgs,
    },
    #[command(about = "Compact a host-backend transaction journal")]
    CompactJournal { root: PathBuf },
}
