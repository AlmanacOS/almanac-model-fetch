//! Filesystem capability detection for almanac-model-fetch destinations.
//!
//! The job of this crate is to answer one question before a single byte is
//! downloaded: *can this destination actually hold what we are about to write?*
//!
//! GGUF files routinely exceed FAT32's 4 GiB per-file ceiling, and the failure
//! mode is a truncated write partway through a multi-gigabyte transfer. Finding
//! that out after a 40 GB download is precisely the outcome this crate exists to
//! prevent, so every check here is designed to run at preflight.

use std::fmt;
use std::path::{Path, PathBuf};

mod fat;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use fat::{classify_boot_sector, FatVariant};

/// FAT32's hard per-file ceiling: 4 GiB minus one byte.
pub const FAT_MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024 - 1;

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("destination path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("could not inspect filesystem at {path}: {source}")]
    Syscall {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem detection is not implemented for this platform")]
    UnsupportedPlatform,
}

/// The filesystem family at a destination, normalised across platforms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FsKind {
    /// FAT12/16/32. Refused outright — see [`Suitability`].
    Fat {
        variant: FatVariant,
    },
    ExFat,
    Ntfs,
    Ext4,
    Btrfs,
    Xfs,
    F2fs,
    Zfs,
    Apfs,
    Hfs,
    Tmpfs,
    Overlay,
    /// Recognised by the OS but not one we have an opinion about.
    Other {
        name: String,
    },
    /// The OS gave us nothing usable.
    Unknown,
}

impl FsKind {
    /// Largest single file the filesystem can represent, where we know it.
    ///
    /// `None` means "no limit we need to care about at model-file scale" — not
    /// "unlimited". Every filesystem has a ceiling; these are just far above
    /// anything a GGUF will reach.
    pub fn max_file_size(&self) -> Option<u64> {
        match self {
            FsKind::Fat { .. } => Some(FAT_MAX_FILE_SIZE),
            _ => None,
        }
    }

    /// Human-readable name for messages.
    pub fn display_name(&self) -> String {
        match self {
            FsKind::Fat { variant } => variant.display_name().to_string(),
            FsKind::ExFat => "exFAT".into(),
            FsKind::Ntfs => "NTFS".into(),
            FsKind::Ext4 => "ext4".into(),
            FsKind::Btrfs => "Btrfs".into(),
            FsKind::Xfs => "XFS".into(),
            FsKind::F2fs => "F2FS".into(),
            FsKind::Zfs => "ZFS".into(),
            FsKind::Apfs => "APFS".into(),
            FsKind::Hfs => "HFS+".into(),
            FsKind::Tmpfs => "tmpfs".into(),
            FsKind::Overlay => "overlayfs".into(),
            FsKind::Other { name } => name.clone(),
            FsKind::Unknown => "unknown".into(),
        }
    }

    /// Whether this is the FAT family, which we refuse regardless of variant.
    pub fn is_fat(&self) -> bool {
        matches!(self, FsKind::Fat { .. })
    }
}

impl fmt::Display for FsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_name())
    }
}

/// What we learned about a destination.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FsInfo {
    pub kind: FsKind,
    /// The raw type string or magic the platform reported, kept for the manifest
    /// so a later reader can second-guess our normalisation.
    pub raw_type: String,
    pub mount_point: PathBuf,
    pub available_bytes: u64,
    pub total_bytes: u64,
}

/// The verdict on writing `required_bytes` (largest single file `largest_file`)
/// to a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suitability {
    /// Good to go.
    Ok,
    /// Proceed, but the operator should know something.
    Warn(String),
    /// Do not write here. Not overridable by `--force`.
    Refuse(String),
}

impl Suitability {
    pub fn is_refusal(&self) -> bool {
        matches!(self, Suitability::Refuse(_))
    }
}

/// Inspect the filesystem backing `path`.
///
/// `path` must exist; callers should create the destination directory first, or
/// pass an existing ancestor.
pub fn inspect(path: &Path) -> Result<FsInfo, FsError> {
    if !path.exists() {
        return Err(FsError::NotFound(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        unix::inspect(path)
    }
    #[cfg(windows)]
    {
        windows::inspect(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(FsError::UnsupportedPlatform)
    }
}

/// Decide whether a destination is fit to receive a bundle.
///
/// `total_bytes` is the summed size of everything to be written; `largest_file`
/// is the biggest single file, which is what runs into the FAT ceiling.
///
/// FAT is refused **outright**, whether or not the current selection happens to
/// fit. A drive is a long-lived object: it accumulates bundles across many runs,
/// and a FAT drive that swallows a 2 GB Q2_K today is the drive someone writes a
/// 40 GB Q8_0 to next month. Refusing at the filesystem level makes the property
/// hold for the life of the drive rather than for one lucky invocation.
pub fn assess(info: &FsInfo, total_bytes: u64, largest_file: u64) -> Suitability {
    if let FsKind::Fat { variant } = &info.kind {
        return Suitability::Refuse(format!(
            "destination {} is {}, which cannot store files larger than {}.\n\
             \n\
             almanac-model-fetch refuses FAT destinations outright, even when the \
             current selection would fit ({} largest file here), because a drive \
             accumulates bundles over time and the next model will not fit. This \
             is not overridable with --force.\n\
             \n\
             Reformat the drive as exFAT (this erases it):\n    {}",
            info.mount_point.display(),
            variant.display_name(),
            human_bytes(FAT_MAX_FILE_SIZE),
            human_bytes(largest_file),
            reformat_hint(),
        ));
    }

    if info.available_bytes < total_bytes {
        return Suitability::Refuse(format!(
            "destination {} has {} free but the selection needs {}.",
            info.mount_point.display(),
            human_bytes(info.available_bytes),
            human_bytes(total_bytes),
        ));
    }

    if let Some(limit) = info.kind.max_file_size() {
        if largest_file > limit {
            return Suitability::Refuse(format!(
                "destination {} is {} and cannot store a file of {} (limit {}).",
                info.mount_point.display(),
                info.kind,
                human_bytes(largest_file),
                human_bytes(limit),
            ));
        }
    }

    match info.kind {
        // We could not identify it. It may well be fine — refusing would block
        // legitimate exotic setups — but the operator should know we could not
        // confirm the file-size ceiling.
        FsKind::Unknown => Suitability::Warn(format!(
            "could not identify the filesystem at {} (reported as {:?}); \
             proceeding, but the per-file size limit is unverified.",
            info.mount_point.display(),
            info.raw_type,
        )),
        FsKind::Other { ref name } => Suitability::Warn(format!(
            "destination {} is {}, which is not a filesystem this tool knows the \
             limits of; proceeding, but the per-file size limit is unverified.",
            info.mount_point.display(),
            name,
        )),
        _ => Suitability::Ok,
    }
}

fn reformat_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "sudo mkfs.exfat /dev/sdXN        # replace sdXN with the USB partition"
    }
    #[cfg(target_os = "macos")]
    {
        "diskutil eraseVolume ExFAT ALMANAC /dev/diskXsY"
    }
    #[cfg(windows)]
    {
        "format X: /FS:exFAT"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        "reformat the drive as exFAT using your platform's disk utility"
    }
}

/// Byte formatting for operator-facing messages. Binary units, because that is
/// what filesystem limits are actually expressed in.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(kind: FsKind, available: u64) -> FsInfo {
        FsInfo {
            kind,
            raw_type: "test".into(),
            mount_point: PathBuf::from("/mnt/usb"),
            available_bytes: available,
            total_bytes: available,
        }
    }

    #[test]
    fn fat_is_refused_even_when_the_file_fits() {
        // The whole point of the outright refusal: a 2 GB file fits on FAT32
        // today, and we refuse anyway.
        let i = info(
            FsKind::Fat {
                variant: FatVariant::Fat32,
            },
            500 * 1024 * 1024 * 1024,
        );
        let verdict = assess(&i, 2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
        assert!(
            verdict.is_refusal(),
            "FAT32 must be refused, got {verdict:?}"
        );
        match verdict {
            Suitability::Refuse(msg) => {
                assert!(msg.contains("FAT32"), "message should name the fs: {msg}");
                assert!(
                    msg.contains("--force"),
                    "message should say --force will not help: {msg}"
                );
                assert!(msg.contains("exFAT"), "message should give the fix: {msg}");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn fat16_and_fat12_are_refused_too() {
        for v in [FatVariant::Fat12, FatVariant::Fat16, FatVariant::Unknown] {
            let i = info(FsKind::Fat { variant: v }, u64::MAX / 2);
            assert!(assess(&i, 1024, 1024).is_refusal(), "{v:?} must be refused");
        }
    }

    #[test]
    fn exfat_accepts_a_large_file() {
        let i = info(FsKind::ExFat, 200 * 1024 * 1024 * 1024);
        let forty_gb = 40 * 1024 * 1024 * 1024;
        assert_eq!(assess(&i, forty_gb, forty_gb), Suitability::Ok);
    }

    #[test]
    fn insufficient_space_is_refused() {
        let i = info(FsKind::ExFat, 1024 * 1024 * 1024);
        let verdict = assess(&i, 40 * 1024 * 1024 * 1024, 40 * 1024 * 1024 * 1024);
        assert!(verdict.is_refusal());
    }

    #[test]
    fn unknown_filesystem_warns_but_proceeds() {
        let i = info(FsKind::Unknown, u64::MAX / 2);
        match assess(&i, 1024, 1024) {
            Suitability::Warn(msg) => assert!(msg.contains("unverified"), "{msg}"),
            other => panic!("expected a warning, got {other:?}"),
        }
    }

    #[test]
    fn other_filesystem_warns_but_proceeds() {
        let i = info(
            FsKind::Other {
                name: "reiserfs".into(),
            },
            u64::MAX / 2,
        );
        assert!(matches!(assess(&i, 1024, 1024), Suitability::Warn(_)));
    }

    #[test]
    fn fat_ceiling_is_four_gib_minus_one() {
        assert_eq!(FAT_MAX_FILE_SIZE, 4_294_967_295);
    }

    #[test]
    fn human_bytes_formats_sensibly() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(FAT_MAX_FILE_SIZE), "4.0 GiB");
        assert_eq!(human_bytes(5_027_784_512), "4.7 GiB");
    }

    #[test]
    fn inspect_reports_something_for_the_temp_dir() {
        // Smoke test against the real platform code path.
        let dir = tempfile::tempdir().unwrap();
        let got = inspect(dir.path()).expect("inspect should succeed on a temp dir");
        assert!(got.total_bytes > 0, "total should be non-zero: {got:?}");
        assert!(
            !got.raw_type.is_empty(),
            "raw type should be populated: {got:?}"
        );
    }

    #[test]
    fn inspect_rejects_a_missing_path() {
        let err = inspect(Path::new("/definitely/not/here/almanac")).unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)));
    }
}
