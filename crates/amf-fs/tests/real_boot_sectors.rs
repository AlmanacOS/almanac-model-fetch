//! Classify boot sectors produced by real `mkfs.fat`, not synthetic ones.
//!
//! The unit tests in `fat.rs` build BPBs by hand, which proves the arithmetic
//! but not that the arithmetic matches what a real formatter writes. These
//! fixtures were captured from images created by dosfstools 4.2:
//!
//! ```text
//! truncate -s 64M fat32.img && mkfs.fat -F 32 fat32.img
//! truncate -s 32M fat16.img && mkfs.fat -F 16 fat16.img
//! truncate -s  2M fat12.img && mkfs.fat -F 12 fat12.img
//! dd if=fatNN.img of=fatNN.bs bs=512 count=1
//! ```
//!
//! Only the first 512 bytes are kept, so the fixtures carry no file data.

use amf_fs::{classify_boot_sector, FatVariant};

const FAT32: &[u8] = include_bytes!("fixtures/fat32.bs");
const FAT16: &[u8] = include_bytes!("fixtures/fat16.bs");
const FAT12: &[u8] = include_bytes!("fixtures/fat12.bs");

#[test]
fn classifies_real_mkfs_fat32() {
    assert_eq!(classify_boot_sector(FAT32), FatVariant::Fat32);
}

#[test]
fn classifies_real_mkfs_fat16() {
    assert_eq!(classify_boot_sector(FAT16), FatVariant::Fat16);
}

#[test]
fn classifies_real_mkfs_fat12() {
    assert_eq!(classify_boot_sector(FAT12), FatVariant::Fat12);
}

/// On a real FAT16 image the bytes at 0x52 (where a FAT32 image keeps its type
/// label) are boot code, and on this fixture they happen not to spell anything.
/// The cluster-count path is what gets these right, which is exactly why the
/// spec says the label string is not authoritative.
#[test]
fn real_fat16_label_region_is_not_a_fat32_label() {
    assert_ne!(&FAT16[0x52..0x5a], b"FAT32   ");
    assert_eq!(&FAT16[0x36..0x3e], b"FAT16   ");
}

#[test]
fn fixtures_are_exactly_one_sector() {
    for (name, fixture) in [("fat32", FAT32), ("fat16", FAT16), ("fat12", FAT12)] {
        assert_eq!(fixture.len(), 512, "{name} fixture should be one sector");
    }
}
