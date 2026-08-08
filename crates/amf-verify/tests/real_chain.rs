//! The evidence chain, re-derived from real HuggingFace git objects.
//!
//! Fixtures captured from `unsloth/Qwen3-8B-GGUF` at commit
//! `a6adef130ffb23ddaf1a62fec9dced968c9bc482`:
//!
//! ```text
//! GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --filter=blob:none \
//!     https://huggingface.co/unsloth/Qwen3-8B-GGUF
//! git cat-file commit HEAD              > commit_signed.raw
//! git cat-file tree  <tree>             > tree_root.raw
//! git cat-file blob  HEAD:<file>.gguf   > lfs_pointer.txt
//! ```
//!
//! This is the test that matters most in the crate: it proves the chain from a
//! genuine GPG-signed HuggingFace commit down to the SHA256 of a 5 GB model
//! file, using only bytes that fit in a bundle and with no network access.

use amf_verify::chain::{derive_expected_hash, Evidence};
use amf_verify::git::{self, ObjectKind};
use amf_verify::lfs;

const COMMIT_RAW: &[u8] = include_bytes!("fixtures/commit_signed.raw");
const TREE_RAW: &[u8] = include_bytes!("fixtures/tree_root.raw");
const POINTER: &[u8] = include_bytes!("fixtures/lfs_pointer.txt");

const COMMIT_OID: &str = "a6adef130ffb23ddaf1a62fec9dced968c9bc482";
const TREE_OID: &str = "116f6efcc6377fce0d8d0917bc15c3126dcec5b9";
const MODEL_PATH: &str = "Qwen3-8B-Q4_K_M.gguf";
const MODEL_SHA256: &str = "120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4";
const MODEL_SIZE: u64 = 5_027_784_512;

#[test]
fn real_commit_object_hashes_to_its_published_id() {
    assert_eq!(git::object_id(ObjectKind::Commit, COMMIT_RAW), COMMIT_OID);
}

#[test]
fn real_tree_object_hashes_to_its_published_id() {
    assert_eq!(git::object_id(ObjectKind::Tree, TREE_RAW), TREE_OID);
}

#[test]
fn real_commit_is_gpg_signed_by_huggingface() {
    let commit = git::parse_commit(COMMIT_RAW).unwrap();

    assert_eq!(commit.tree, TREE_OID);
    assert!(commit.is_signed(), "this HF commit should carry a gpgsig");
    assert!(
        commit.committer.contains("system@huggingface.co"),
        "committer was {:?}",
        commit.committer
    );

    let sig = commit.gpgsig.as_ref().unwrap();
    assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"), "{sig:.40}");
    assert!(sig.trim_end().ends_with("-----END PGP SIGNATURE-----"));
}

#[test]
fn signed_payload_strips_the_signature_and_keeps_everything_else() {
    let payload = amf_verify::git::Commit::signed_payload(COMMIT_RAW);
    let text = String::from_utf8_lossy(&payload);

    assert!(!text.contains("gpgsig"), "signature header must be removed");
    assert!(!text.contains("BEGIN PGP SIGNATURE"));
    assert!(text.starts_with(&format!("tree {TREE_OID}\n")));
    assert!(text.contains("system@huggingface.co"));
    assert!(
        payload.len() < COMMIT_RAW.len(),
        "payload should be smaller than the signed commit"
    );
}

#[test]
fn real_pointer_names_the_model_hash() {
    let p = lfs::parse_pointer(POINTER).unwrap();
    assert_eq!(p.oid_sha256, MODEL_SHA256);
    assert_eq!(p.size, MODEL_SIZE);
}

#[test]
fn tree_entry_matches_the_pointer_blob() {
    // The tree names a blob id; the pointer we captured must be that blob.
    let entries = git::parse_tree(TREE_RAW).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.name == MODEL_PATH)
        .expect("model file should be in the root tree");
    assert_eq!(git::object_id(ObjectKind::Blob, POINTER), entry.oid);
}

#[test]
fn full_chain_from_signed_commit_to_model_hash() {
    // commit -> tree -> pointer blob -> sha256, every arrow content-addressed.
    let mut evidence = Evidence {
        commit: COMMIT_RAW.to_vec(),
        ..Default::default()
    };
    evidence.trees.insert(TREE_OID.to_string(), TREE_RAW.to_vec());
    evidence.pointers.insert(
        git::object_id(ObjectKind::Blob, POINTER),
        POINTER.to_vec(),
    );

    let result = derive_expected_hash(&evidence, COMMIT_OID, MODEL_PATH).unwrap();

    assert_eq!(result.sha256, MODEL_SHA256);
    assert_eq!(result.size, MODEL_SIZE);
    assert_eq!(result.tree_path, vec![TREE_OID.to_string()]);
}

#[test]
fn the_chain_matches_what_the_rest_api_reports() {
    // The REST API's lfs.oid and the pointer inside the signed tree must agree.
    // If they ever diverged, the API would be asserting something the signature
    // does not cover, and we would want to know loudly.
    let from_pointer = lfs::parse_pointer(POINTER).unwrap().oid_sha256;
    assert_eq!(
        from_pointer, MODEL_SHA256,
        "the signed tree and the REST API must name the same hash"
    );
}

#[test]
fn tampering_with_the_real_commit_is_detected() {
    // Flip one byte of the real commit; its object id must no longer match.
    let mut tampered = COMMIT_RAW.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let mut evidence = Evidence {
        commit: tampered,
        ..Default::default()
    };
    evidence.trees.insert(TREE_OID.to_string(), TREE_RAW.to_vec());

    let err = derive_expected_hash(&evidence, COMMIT_OID, MODEL_PATH).unwrap_err();
    assert!(err.is_integrity_failure(), "got {err:?}");
}
