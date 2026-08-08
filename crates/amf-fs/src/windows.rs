//! Windows filesystem detection via `GetVolumeInformationW`.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetVolumeInformationW, GetVolumePathNameW,
};

use crate::{FsError, FsInfo, FsKind};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn last_error(path: &Path) -> FsError {
    FsError::Syscall {
        path: path.to_path_buf(),
        source: std::io::Error::last_os_error(),
    }
}

pub fn inspect(path: &Path) -> Result<FsInfo, FsError> {
    let root = volume_root(path)?;
    let (fs_name, mount_point) = volume_info(&root, path)?;
    let (available_bytes, total_bytes) = space(&root, path)?;

    // Windows reports the filesystem name directly ("FAT32", "exFAT", "NTFS"),
    // so there is no magic-number guessing here. We still route through the
    // shared name mapping so the FAT-vs-exFAT ordering rule lives in one place.
    let kind = kind_from_windows_name(&fs_name);

    Ok(FsInfo {
        kind,
        raw_type: fs_name,
        mount_point,
        available_bytes,
        total_bytes,
    })
}

/// The volume root for a path, e.g. `D:\` for `D:\almanac\models`.
fn volume_root(path: &Path) -> Result<Vec<u16>, FsError> {
    let input = wide(path);
    let mut buf = vec![0u16; MAX_PATH as usize + 1];
    let ok = unsafe { GetVolumePathNameW(input.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if ok == 0 {
        return Err(last_error(path));
    }
    truncate_at_nul(&mut buf);
    buf.push(0);
    Ok(buf)
}

fn volume_info(root: &[u16], path: &Path) -> Result<(String, PathBuf), FsError> {
    let mut fs_name = vec![0u16; MAX_PATH as usize + 1];
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error(path));
    }
    truncate_at_nul(&mut fs_name);
    let name = String::from_utf16_lossy(&fs_name);

    let mut root_owned = root.to_vec();
    truncate_at_nul(&mut root_owned);
    let mount_point = PathBuf::from(String::from_utf16_lossy(&root_owned));
    Ok((name, mount_point))
}

fn space(root: &[u16], path: &Path) -> Result<(u64, u64), FsError> {
    let mut available: u64 = 0;
    let mut total: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut available,
            &mut total,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(path));
    }
    Ok((available, total))
}

fn truncate_at_nul(buf: &mut Vec<u16>) {
    if let Some(pos) = buf.iter().position(|&c| c == 0) {
        buf.truncate(pos);
    }
}

/// Map a Windows filesystem name to a kind.
///
/// The FAT variant comes straight from the OS here, so unlike the Unix path we
/// never need to sniff a boot sector.
fn kind_from_windows_name(name: &str) -> FsKind {
    let lower = name.to_ascii_lowercase();
    // exFAT must be tested before FAT: "exfat" contains "fat", and misordering
    // these would refuse a perfectly good exFAT drive.
    if lower.contains("exfat") {
        return FsKind::ExFat;
    }
    if lower.starts_with("fat") {
        let variant = match lower.as_str() {
            "fat32" => crate::FatVariant::Fat32,
            "fat16" => crate::FatVariant::Fat16,
            "fat12" => crate::FatVariant::Fat12,
            _ => crate::FatVariant::Unknown,
        };
        return FsKind::Fat { variant };
    }
    match lower.as_str() {
        "ntfs" => FsKind::Ntfs,
        "refs" => FsKind::Other { name: name.into() },
        "" => FsKind::Unknown,
        _ => FsKind::Other { name: name.into() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exfat_is_not_mistaken_for_fat() {
        assert_eq!(kind_from_windows_name("exFAT"), FsKind::ExFat);
        assert_eq!(kind_from_windows_name("exfat"), FsKind::ExFat);
    }

    #[test]
    fn fat32_is_identified_precisely() {
        assert_eq!(
            kind_from_windows_name("FAT32"),
            FsKind::Fat {
                variant: crate::FatVariant::Fat32
            }
        );
        assert_eq!(
            kind_from_windows_name("FAT"),
            FsKind::Fat {
                variant: crate::FatVariant::Unknown
            }
        );
    }

    #[test]
    fn ntfs_and_others() {
        assert_eq!(kind_from_windows_name("NTFS"), FsKind::Ntfs);
        assert!(matches!(
            kind_from_windows_name("ReFS"),
            FsKind::Other { .. }
        ));
        assert_eq!(kind_from_windows_name(""), FsKind::Unknown);
    }

    #[test]
    fn inspect_works_on_the_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let info = inspect(dir.path()).expect("inspect should succeed");
        assert!(info.total_bytes > 0);
    }
}
