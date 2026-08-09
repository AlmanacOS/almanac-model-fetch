//! Variant grouping against real HuggingFace tree listings.
//!
//! The unit tests use hand-built listings, which prove the grouping rules but
//! not that those rules survive contact with how Unsloth actually names things.
//! These fixtures were captured from the live API:
//!
//! ```text
//! curl "https://huggingface.co/api/models/<repo>/tree/main?recursive=true"
//! ```

use amf_source::hf::parse_tree_page;
use amf_source::variant::group;

const LLAMA_1B: &str = include_str!("fixtures/tree_llama32_1b.json");
const DEEPSEEK_R1: &str = include_str!("fixtures/tree_deepseek_r1.json");

#[test]
fn groups_a_flat_quant_repo() {
    let files = parse_tree_page(LLAMA_1B).unwrap();
    let variants = group(&files);

    assert!(
        variants.len() > 20,
        "expected many quants, got {}",
        variants.len()
    );

    let labels: Vec<&str> = variants.iter().map(|v| v.label.as_str()).collect();
    for expected in ["Q4_K_M", "Q8_0", "BF16", "UD-Q4_K_XL", "IQ4_NL"] {
        assert!(
            labels.contains(&expected),
            "expected a {expected} variant, got {labels:?}"
        );
    }

    // The model name must be stripped from every label.
    for label in &labels {
        assert!(
            !label.contains("Llama"),
            "label {label:?} still carries the model name"
        );
    }

    // Every quant in this repo is a single unsharded file.
    assert!(variants.iter().all(|v| !v.is_sharded()));
}

#[test]
fn every_gguf_in_a_real_repo_has_a_verifiable_hash() {
    // This is the property the whole Tier-1 chain rests on: if HuggingFace did
    // not publish a SHA256 for a GGUF, we would have nothing to stream-verify
    // against.
    let files = parse_tree_page(LLAMA_1B).unwrap();
    let ggufs: Vec<_> = files.iter().filter(|f| f.is_gguf()).collect();
    assert!(!ggufs.is_empty());

    for f in &ggufs {
        assert!(f.sha256.is_some(), "{} has no published SHA256", f.path);
        assert_eq!(
            f.sha256.as_ref().unwrap().len(),
            64,
            "{} has a malformed SHA256",
            f.path
        );
        assert!(f.size > 0, "{} has zero size", f.path);
    }

    assert!(group(&files).iter().all(|v| v.fully_verifiable()));
}

#[test]
fn groups_a_sharded_repo_into_whole_variants() {
    let files = parse_tree_page(DEEPSEEK_R1).unwrap();
    let variants = group(&files);

    let sharded: Vec<_> = variants.iter().filter(|v| v.is_sharded()).collect();
    assert!(
        !sharded.is_empty(),
        "DeepSeek-R1 should contain sharded variants"
    );

    for v in &sharded {
        assert!(
            v.missing_shards().is_empty(),
            "variant {} is missing shards {:?}",
            v.label,
            v.missing_shards()
        );

        // Shards must be contiguous and in load order.
        let indices: Vec<u32> = v
            .files
            .iter()
            .filter_map(|f| f.shard.map(|s| s.index))
            .collect();
        let expected: Vec<u32> = (1..=indices.len() as u32).collect();
        assert_eq!(indices, expected, "variant {} shards out of order", v.label);

        // A sharded variant's total dwarfs any single part — this is exactly the
        // case that makes FAT32 untenable and single-file handling wrong.
        assert!(v.total_size() > v.largest_file());
    }

    // No label should retain the model name.
    for v in &variants {
        assert!(
            !v.label.contains("DeepSeek"),
            "label {:?} still carries the model name",
            v.label
        );
    }
}

#[test]
fn sharded_variants_exceed_the_fat32_ceiling() {
    // The motivating fact for refusing FAT32: real variants are far past 4 GiB.
    let files = parse_tree_page(DEEPSEEK_R1).unwrap();
    let variants = group(&files);
    let biggest = variants.iter().map(|v| v.total_size()).max().unwrap();
    assert!(
        biggest > amf_fs::FAT_MAX_FILE_SIZE,
        "expected a variant over 4 GiB, largest was {biggest}"
    );
}

#[test]
fn non_gguf_files_never_become_variants() {
    let files = parse_tree_page(DEEPSEEK_R1).unwrap();
    let variants = group(&files);
    for v in &variants {
        for f in &v.files {
            assert!(f.is_gguf(), "{} is not a GGUF", f.path);
        }
    }
}
