use super::*;
use super::{parse_u32_auto, parse_u64_auto};

#[derive(Subcommand)]
pub(super) enum Command {
    Mkfs {
        root: Option<PathBuf>,
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        image_size: u64,
        #[arg(long, default_value = "argosfs-root")]
        pool_name: String,
        #[arg(long, default_value_t = 6)]
        disks: usize,
        #[arg(long, default_value_t = 4)]
        k: usize,
        #[arg(long, default_value_t = 2)]
        m: usize,
        #[arg(long, default_value_t = 256 * 1024)]
        chunk_size: usize,
        #[arg(long, default_value = "zstd")]
        compression: Compression,
        #[arg(long, default_value_t = 3)]
        compression_level: i32,
        #[arg(long)]
        defer_journal_flush: bool,
        #[arg(long)]
        defer_metadata_commit: bool,
        #[arg(long)]
        defer_data_flush: bool,
        #[arg(long)]
        force: bool,
    },
    Scan {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    InspectDevice {
        path: PathBuf,
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
    },
    InspectPool {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
    },
    ListDevices {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
    },
    AddDevice {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        device: PathBuf,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        image_size: u64,
        #[arg(long)]
        force: bool,
    },
    DrainDevice {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        device: String,
    },
    ReplaceDevice {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        old: String,
        #[arg(long)]
        new: PathBuf,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        image_size: u64,
        #[arg(long)]
        force: bool,
    },
    RemoveDevice {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        device: String,
    },
    Mount {
        root: PathBuf,
        mountpoint: PathBuf,
        #[arg(long)]
        foreground: bool,
        #[arg(short = 'o', long = "option")]
        option: Vec<String>,
    },
    MountRoot {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long, default_value = "/sysroot")]
        target: PathBuf,
        #[arg(long, default_value = "rw")]
        mode: RootMountMode,
        #[arg(long)]
        foreground: bool,
        #[arg(short = 'o', long = "option")]
        option: Vec<String>,
    },
    PreflightRoot {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long, default_value = "rw")]
        mode: RootMountMode,
    },
    ReplayJournal {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
    },
    MountRecovery {
        #[arg(long, default_value = "loop")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        target: PathBuf,
    },
    Put {
        root: PathBuf,
        local: PathBuf,
        path: String,
    },
    Get {
        root: PathBuf,
        path: String,
        local: PathBuf,
    },
    Cat {
        root: PathBuf,
        path: String,
    },
    Ls {
        root: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(long)]
        json: bool,
    },
    Stat {
        root: PathBuf,
        path: String,
    },
    Rm {
        root: PathBuf,
        path: String,
    },
    Mkdir {
        root: PathBuf,
        path: String,
        #[arg(long, default_value = "755", value_parser = parse_u32_auto)]
        mode: u32,
    },
    Mknod {
        root: PathBuf,
        path: String,
        #[arg(long, value_parser = parse_u32_auto)]
        mode: u32,
        #[arg(long, default_value = "0", value_parser = parse_u64_auto)]
        rdev: u64,
    },
    Symlink {
        root: PathBuf,
        target: String,
        link: String,
    },
    Rename {
        root: PathBuf,
        old: String,
        new: String,
    },
    Chmod {
        root: PathBuf,
        path: String,
        #[arg(value_parser = parse_u32_auto)]
        mode: u32,
    },
    Truncate {
        root: PathBuf,
        path: String,
        size: u64,
    },
    ImportTree {
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(required = true, num_args = 1..=3)]
        args: Vec<PathBuf>,
    },
    ExportTree {
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(required = true, num_args = 1..=2)]
        args: Vec<PathBuf>,
    },
    AddDisk {
        root: PathBuf,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        tier: Option<StorageTier>,
        #[arg(long)]
        weight: Option<f64>,
        #[arg(long)]
        capacity_bytes: Option<u64>,
        #[arg(long)]
        rebalance: bool,
    },
    ProbeDisks {
        root: PathBuf,
        disk_id: Option<String>,
    },
    RefreshSmart {
        root: PathBuf,
        disk_id: Option<String>,
    },
    RemoveDisk {
        root: PathBuf,
        disk_id: String,
    },
    MarkDisk {
        root: PathBuf,
        disk_id: String,
        status: DiskStatus,
    },
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
    Health {
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Fsck {
        root: Option<PathBuf>,
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        repair: bool,
        #[arg(long)]
        remove_orphans: bool,
    },
    Scrub {
        root: Option<PathBuf>,
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
    },
    Rebalance {
        root: PathBuf,
    },
    Reshape {
        root: Option<PathBuf>,
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        k: usize,
        #[arg(long)]
        m: usize,
        #[arg(long)]
        max_files: Option<usize>,
    },
    Autopilot {
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        explain: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 60)]
        interval: u64,
    },
    Snapshot {
        root: PathBuf,
        name: String,
    },
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
    EncryptionStatus {
        root: PathBuf,
    },
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
    Prometheus {
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9108")]
        listen: String,
    },
    SetPosixAcl {
        root: PathBuf,
        path: String,
        acl: String,
        #[arg(long)]
        default_acl: bool,
    },
    GetPosixAcl {
        root: PathBuf,
        path: String,
        #[arg(long)]
        default_acl: bool,
    },
    SetNfs4Acl {
        root: PathBuf,
        path: String,
        acl_json: String,
    },
    GetNfs4Acl {
        root: PathBuf,
        path: String,
    },
    VerifyJournal {
        root: Option<PathBuf>,
        #[arg(long, default_value = "host")]
        backend: BackendKind,
        #[arg(long, value_delimiter = ',')]
        images: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<PathBuf>,
        #[arg(long)]
        pool: Option<String>,
    },
    CompactJournal {
        root: PathBuf,
    },
}
