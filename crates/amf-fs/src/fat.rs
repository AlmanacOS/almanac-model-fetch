//! FAT variant identification.
//!
//! Linux's `statfs` reports every member of the FAT family under a single magic
//! (`MSDOS_SUPER_MAGIC`), and `/proc/self/mountinfo` says only `vfat`. Neither
//! distinguishes FAT16 from FAT32. Since we refuse all of them, the distinction
//! does not change the verdict — but it does change the error message, and
//! telling an operator "this is FAT32" beats "this is some kind of FAT" when
//! they are trying to work out what they plugged in.
//!
//! So we make a best-effort attempt to read the BPB from the backing device and
//! fall back to [`FatVariant::Unknown`] the moment anything is unreadable. This
//! is decoration on an error path; it must never itself fail a run.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
    /// Known to be FAT, but we could not read the BPB to say which.
    Unknown,
}

impl FatVariant {
    pub fn display_name(&self) -> &'static str {
        match self {
            FatVariant::Fat12 => "FAT12",
            FatVariant::Fat16 => "FAT16",
            FatVariant::Fat32 => "FAT32",
            FatVariant::Unknown => "FAT (vfat)",
        }
    }
}

/// Sniff the FAT variant from a block device's boot sector.
///
/// Returns [`FatVariant::Unknown`] for any problem at all — unreadable device
/// (the common case without root), short read, or an unrecognised BPB.
pub fn variant_from_device(device: &Path) -> FatVariant {
    match read_boot_sector(device) {
        Some(sector) => classify_boot_sector(&sector),
        None => FatVariant::Unknown,
    }
}

fn read_boot_sector(device: &Path) -> Option<[u8; 512]> {
    use std::io::Read;
    let mut file = std::fs::File::open(device).ok()?;
    let mut buf = [0u8; 512];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// Classify a FAT boot sector per the Microsoft EFI FAT32 spec.
///
/// The filesystem-type strings at offsets 0x36 and 0x52 are explicitly *not*
/// authoritative per the spec, so we use the cluster-count computation as the
/// primary signal and fall back to the label strings only when the geometry
/// fields are unusable.
pub fn classify_boot_sector(sector: &[u8]) -> FatVariant {
    if sector.len() < 512 {
        return FatVariant::Unknown;
    }

    let u16_at = |off: usize| u16::from_le_bytes([sector[off], sector[off + 1]]) as u32;
    let u32_at = |off: usize| {
        u32::from_le_bytes([
            sector[off],
            sector[off + 1],
            sector[off + 2],
            sector[off + 3],
        ])
    };

    let bytes_per_sector = u16_at(0x0b);
    let sectors_per_cluster = sector[0x0d] as u32;
    let reserved_sectors = u16_at(0x0e);
    let num_fats = sector[0x10] as u32;
    let root_entries = u16_at(0x11);
    let total_sectors_16 = u16_at(0x13);
    let fat_size_16 = u16_at(0x16);
    let total_sectors_32 = u32_at(0x20);
    let fat_size_32 = u32_at(0x24);

    // Geometry sanity. If these are nonsense we are not looking at a FAT BPB.
    if bytes_per_sector == 0 || sectors_per_cluster == 0 || num_fats == 0 {
        return classify_by_label(sector);
    }

    let fat_size = if fat_size_16 != 0 {
        fat_size_16
    } else {
        fat_size_32
    };
    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };
    if fat_size == 0 || total_sectors == 0 {
        return classify_by_label(sector);
    }

    // Root directory occupies whole sectors; FAT32 has root_entries == 0.
    let root_dir_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
    let data_sectors = total_sectors
        .saturating_sub(reserved_sectors)
        .saturating_sub(num_fats * fat_size)
        .saturating_sub(root_dir_sectors);
    let cluster_count = data_sectors / sectors_per_cluster;

    // Thresholds are from the spec and are exact, not approximate: these precise
    // numbers are what determine the on-disk format.
    if cluster_count < 4085 {
        FatVariant::Fat12
    } else if cluster_count < 65525 {
        FatVariant::Fat16
    } else {
        FatVariant::Fat32
    }
}

fn classify_by_label(sector: &[u8]) -> FatVariant {
    let label16 = &sector[0x36..0x3e];
    let label32 = &sector[0x52..0x5a];
    if label32.starts_with(b"FAT32") {
        FatVariant::Fat32
    } else if label16.starts_with(b"FAT12") {
        FatVariant::Fat12
    } else if label16.starts_with(b"FAT16") {
        FatVariant::Fat16
    } else {
        FatVariant::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic BPB with the given geometry.
    ///
    /// The argument list mirrors the BPB field order so the call sites read like
    /// the on-disk layout; splitting it into a struct would obscure that.
    #[allow(clippy::too_many_arguments)]
    fn bpb(
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        reserved: u16,
        num_fats: u8,
        root_entries: u16,
        total_16: u16,
        fat_16: u16,
        total_32: u32,
        fat_32: u32,
        label16: &[u8],
        label32: &[u8],
    ) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[0x0b..0x0d].copy_from_slice(&bytes_per_sector.to_le_bytes());
        s[0x0d] = sectors_per_cluster;
        s[0x0e..0x10].copy_from_slice(&reserved.to_le_bytes());
        s[0x10] = num_fats;
        s[0x11..0x13].copy_from_slice(&root_entries.to_le_bytes());
        s[0x13..0x15].copy_from_slice(&total_16.to_le_bytes());
        s[0x16..0x18].copy_from_slice(&fat_16.to_le_bytes());
        s[0x20..0x24].copy_from_slice(&total_32.to_le_bytes());
        s[0x24..0x28].copy_from_slice(&fat_32.to_le_bytes());
        s[0x36..0x36 + label16.len()].copy_from_slice(label16);
        s[0x52..0x52 + label32.len()].copy_from_slice(label32);
        s
    }

    #[test]
    fn identifies_fat32_by_cluster_count() {
        // 8 GB volume, 8 sectors/cluster -> well over 65525 clusters.
        let s = bpb(
            512,
            8,
            32,
            2,
            0,
            0,
            0,
            16_777_216,
            16_384,
            b"        ",
            b"FAT32   ",
        );
        assert_eq!(classify_boot_sector(&s), FatVariant::Fat32);
    }

    #[test]
    fn identifies_fat16_by_cluster_count() {
        // ~64 MB volume, 4 sectors/cluster -> between 4085 and 65525 clusters.
        let s = bpb(
            512,
            4,
            1,
            2,
            512,
            0,
            128,
            131_072,
            0,
            b"FAT16   ",
            b"        ",
        );
        assert_eq!(classify_boot_sector(&s), FatVariant::Fat16);
    }

    #[test]
    fn identifies_fat12_by_cluster_count() {
        // A 1.44 MB floppy: 2880 sectors, 1 sector/cluster.
        let s = bpb(512, 1, 1, 2, 224, 2880, 9, 0, 0, b"FAT12   ", b"        ");
        assert_eq!(classify_boot_sector(&s), FatVariant::Fat12);
    }

    #[test]
    fn cluster_count_beats_a_lying_label() {
        // The spec says the label string is not authoritative. A FAT16-geometry
        // volume mislabelled FAT32 must still come back FAT16.
        let s = bpb(
            512,
            4,
            1,
            2,
            512,
            0,
            128,
            131_072,
            0,
            b"        ",
            b"FAT32   ",
        );
        assert_eq!(classify_boot_sector(&s), FatVariant::Fat16);
    }

    #[test]
    fn falls_back_to_label_when_geometry_is_nonsense() {
        let mut s = [0u8; 512];
        s[0x52..0x5a].copy_from_slice(b"FAT32   ");
        assert_eq!(classify_boot_sector(&s), FatVariant::Fat32);
    }

    #[test]
    fn all_zeroes_is_unknown() {
        assert_eq!(classify_boot_sector(&[0u8; 512]), FatVariant::Unknown);
    }

    #[test]
    fn short_sector_is_unknown() {
        assert_eq!(classify_boot_sector(&[0u8; 100]), FatVariant::Unknown);
    }

    #[test]
    fn unreadable_device_is_unknown_not_an_error() {
        assert_eq!(
            variant_from_device(Path::new("/dev/definitely-not-a-device")),
            FatVariant::Unknown
        );
    }
}
