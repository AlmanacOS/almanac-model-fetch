//! Unix filesystem detection (Linux and macOS).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::{FsError, FsInfo, FsKind};

pub fn inspect(path: &Path) -> Result<FsInfo, FsError> {
    let (available_bytes, total_bytes) = space(path)?;
    let (kind, raw_type, mount_point) = detect(path)?;
    Ok(FsInfo {
        kind,
        raw_type,
        mount_point,
        available_bytes,
        total_bytes,
    })
}

fn cpath(path: &Path) -> Result<CString, FsError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| FsError::Syscall {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains an interior NUL byte",
        ),
    })
}

/// Free and total bytes, via `statvfs`.
///
/// We deliberately use `f_bavail` (blocks available to unprivileged users)
/// rather than `f_bfree`: on filesystems with reserved blocks, `f_bfree`
/// overstates what we can actually write, and overstating free space on a
/// preflight check defeats the purpose of having one.
fn space(path: &Path) -> Result<(u64, u64), FsError> {
    let c = cpath(path)?;
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(FsError::Syscall {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // f_frsize is the fragment size and is the correct multiplier for the
    // block counts; f_bsize is a preferred I/O size and can differ.
    let unit = if buf.f_frsize > 0 {
        buf.f_frsize as u64
    } else {
        buf.f_bsize as u64
    };
    Ok((buf.f_bavail as u64 * unit, buf.f_blocks as u64 * unit))
}

#[cfg(target_os = "linux")]
mod magic {
    pub const MSDOS: i64 = 0x4d44;
    pub const EXFAT: i64 = 0x2011_BAB0;
    pub const NTFS: i64 = 0x5346_544e;
    pub const NTFS3: i64 = 0x7366_746e;
    pub const EXT: i64 = 0xEF53;
    pub const BTRFS: i64 = 0x9123_683E;
    pub const XFS: i64 = 0x5846_5342;
    pub const F2FS: i64 = 0xF2F5_2010;
    pub const ZFS: i64 = 0x2fc1_2fc1;
    pub const TMPFS: i64 = 0x0102_1994;
    pub const OVERLAY: i64 = 0x794c_7630;
    pub const FUSE: i64 = 0x6573_5546;
}

#[cfg(target_os = "linux")]
fn detect(path: &Path) -> Result<(FsKind, String, PathBuf), FsError> {
    let c = cpath(path)?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(FsError::Syscall {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    let magic = buf.f_type as i64;

    // mountinfo gives us the mount point, the driver name, and the backing
    // device. The driver name matters because a FUSE-mounted exFAT reports the
    // FUSE magic, so the magic alone would leave us none the wiser.
    let entry = mountinfo_for(path);
    let fstype = entry.as_ref().map(|e| e.fstype.clone()).unwrap_or_default();
    let mount_point = entry
        .as_ref()
        .map(|e| e.mount_point.clone())
        .unwrap_or_else(|| path.to_path_buf());
    let source = entry.as_ref().map(|e| e.source.clone());

    let kind = match magic {
        magic::MSDOS => FsKind::Fat {
            variant: fat_variant(source.as_deref()),
        },
        magic::EXFAT => FsKind::ExFat,
        magic::NTFS | magic::NTFS3 => FsKind::Ntfs,
        magic::EXT => FsKind::Ext4,
        magic::BTRFS => FsKind::Btrfs,
        magic::XFS => FsKind::Xfs,
        magic::F2FS => FsKind::F2fs,
        magic::ZFS => FsKind::Zfs,
        magic::TMPFS => FsKind::Tmpfs,
        magic::OVERLAY => FsKind::Overlay,
        // FUSE, or anything we do not have a magic for: fall back to the driver
        // name, which is what tells exfat-fuse apart from ntfs-3g.
        magic::FUSE => kind_from_name(&fstype, source.as_deref()),
        _ => kind_from_name(&fstype, source.as_deref()),
    };

    let raw = if fstype.is_empty() {
        format!("statfs magic {magic:#x}")
    } else {
        format!("{fstype} (statfs magic {magic:#x})")
    };
    Ok((kind, raw, mount_point))
}

#[cfg(target_os = "macos")]
fn detect(path: &Path) -> Result<(FsKind, String, PathBuf), FsError> {
    let c = cpath(path)?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return Err(FsError::Syscall {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    let fstype = cstr_array_to_string(&buf.f_fstypename);
    let mount_point = PathBuf::from(cstr_array_to_string(&buf.f_mntonname));
    let source = cstr_array_to_string(&buf.f_mntfromname);
    let kind = kind_from_name(&fstype, Some(source.as_str()));
    Ok((kind, fstype, mount_point))
}

#[cfg(target_os = "macos")]
fn cstr_array_to_string(arr: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Map a driver/type name to a filesystem kind.
fn kind_from_name(name: &str, source: Option<&str>) -> FsKind {
    let lower = name.to_ascii_lowercase();
    // Match the most specific names first: "exfat" contains "fat", so a naive
    // substring check in the wrong order would classify exFAT as FAT and refuse
    // a perfectly good drive.
    if lower.contains("exfat") {
        return FsKind::ExFat;
    }
    match lower.as_str() {
        "vfat" | "msdos" | "fat" | "fat32" | "fat16" | "fat12" | "msdosfs" => {
            return FsKind::Fat {
                variant: fat_variant(source),
            }
        }
        "ntfs" | "ntfs3" | "ntfs-3g" | "fuseblk-ntfs" => return FsKind::Ntfs,
        "ext2" | "ext3" | "ext4" => return FsKind::Ext4,
        "btrfs" => return FsKind::Btrfs,
        "xfs" => return FsKind::Xfs,
        "f2fs" => return FsKind::F2fs,
        "zfs" => return FsKind::Zfs,
        "apfs" => return FsKind::Apfs,
        "hfs" | "hfsplus" => return FsKind::Hfs,
        "tmpfs" | "ramfs" => return FsKind::Tmpfs,
        "overlay" | "overlayfs" => return FsKind::Overlay,
        "" => return FsKind::Unknown,
        _ => {}
    }
    // A FUSE mount whose driver name we did not match: the backing device name
    // is sometimes the only hint (e.g. source "/dev/sdb1", fstype "fuseblk").
    if lower.contains("ntfs") {
        return FsKind::Ntfs;
    }
    FsKind::Other { name: name.to_string() }
}

/// Determine which FAT variant, best-effort, from the backing device.
fn fat_variant(source: Option<&str>) -> crate::FatVariant {
    match source {
        Some(dev) if dev.starts_with('/') => crate::fat::variant_from_device(Path::new(dev)),
        _ => crate::FatVariant::Unknown,
    }
}

#[cfg(target_os = "linux")]
struct MountEntry {
    mount_point: PathBuf,
    fstype: String,
    source: String,
}

/// Find the mountinfo entry governing `path`: the longest mount point that is a
/// prefix of it.
///
/// Longest-prefix matters because mounts nest — `/mnt` and `/mnt/usb` can both
/// be mounts, and only the deeper one describes the drive we are writing to.
#[cfg(target_os = "linux")]
fn mountinfo_for(path: &Path) -> Option<MountEntry> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;

    let mut best: Option<(usize, MountEntry)> = None;
    for line in content.lines() {
        // Format: id parent major:minor root mount-point opts... - fstype source superopts
        let (before, after) = match line.split_once(" - ") {
            Some(parts) => parts,
            None => continue,
        };
        let mount_point = match before.split_whitespace().nth(4) {
            Some(mp) => PathBuf::from(unescape_octal(mp)),
            None => continue,
        };
        if !target.starts_with(&mount_point) {
            continue;
        }
        let mut after_fields = after.split_whitespace();
        let fstype = after_fields.next().unwrap_or_default().to_string();
        let source = unescape_octal(after_fields.next().unwrap_or_default());

        let depth = mount_point.components().count();
        let better = best.as_ref().map(|(d, _)| depth >= *d).unwrap_or(true);
        if better {
            best = Some((
                depth,
                MountEntry {
                    mount_point,
                    fstype,
                    source,
                },
            ));
        }
    }
    best.map(|(_, e)| e)
}

/// mountinfo escapes space, tab, newline and backslash as octal sequences.
#[cfg(target_os = "linux")]
fn unescape_octal(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &s[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(digits, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exfat_is_not_mistaken_for_fat() {
        // "exfat" contains "fat"; getting this wrong would refuse a good drive.
        assert_eq!(kind_from_name("exfat", None), FsKind::ExFat);
        assert_eq!(kind_from_name("exFAT", None), FsKind::ExFat);
        assert_eq!(kind_from_name("fuse.exfat", None), FsKind::ExFat);
        assert_eq!(kind_from_name("exfat-fuse", None), FsKind::ExFat);
    }

    #[test]
    fn fat_driver_names_map_to_fat() {
        for n in ["vfat", "msdos", "msdosfs", "FAT32"] {
            assert!(
                kind_from_name(n, None).is_fat(),
                "{n} should be detected as FAT"
            );
        }
    }

    #[test]
    fn common_filesystems_map_correctly() {
        assert_eq!(kind_from_name("ext4", None), FsKind::Ext4);
        assert_eq!(kind_from_name("btrfs", None), FsKind::Btrfs);
        assert_eq!(kind_from_name("apfs", None), FsKind::Apfs);
        assert_eq!(kind_from_name("ntfs3", None), FsKind::Ntfs);
        assert_eq!(kind_from_name("tmpfs", None), FsKind::Tmpfs);
    }

    #[test]
    fn unrecognised_name_is_other_not_fat() {
        match kind_from_name("reiserfs", None) {
            FsKind::Other { name } => assert_eq!(name, "reiserfs"),
            other => panic!("expected Other, got {other:?}"),
        }
        assert_eq!(kind_from_name("", None), FsKind::Unknown);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unescapes_mountinfo_octal() {
        assert_eq!(unescape_octal("/mnt/my\\040drive"), "/mnt/my drive");
        assert_eq!(unescape_octal("/mnt/usb"), "/mnt/usb");
        assert_eq!(unescape_octal("/a\\134b"), "/a\\b");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_finds_root_for_any_path() {
        // Every Linux system has "/" mounted, so this must always resolve.
        let e = mountinfo_for(Path::new("/")).expect("root should be in mountinfo");
        assert_eq!(e.mount_point, PathBuf::from("/"));
        assert!(!e.fstype.is_empty());
    }

    #[test]
    fn space_reports_nonzero_for_root() {
        let (avail, total) = space(Path::new("/")).unwrap();
        assert!(total > 0, "total should be positive");
        assert!(avail <= total, "available must not exceed total");
    }
}
