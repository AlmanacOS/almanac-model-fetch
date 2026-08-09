//! Hermetic tests against real captured ModelScope responses.
//!
//! Same principle as the HuggingFace fixtures: parsing is exercised against
//! bytes the live service actually sent, not against something hand-written to
//! match the parser. Captured 2026-08-08 from `unsloth/Qwen3-8B-GGUF`.

use amf_source::{git_http, ms, pack};
use amf_verify::git::ObjectKind;

const FILES_JSON: &str = include_str!("fixtures/ms_files.json");
/// A complete `git-upload-pack` response: sideband framing and all.
const UPLOAD_PACK_RESPONSE: &[u8] = include_bytes!("fixtures/ms_upload_pack_response.bin");

const HEAD_COMMIT: &str = "baaddd6fb19e702c1d54c5bb2a5746012c122619";

#[test]
fn parses_the_real_file_listing() {
    let files = ms::parse_files(FILES_JSON).unwrap();
    assert_eq!(files.len(), 32, "the real listing has 32 blobs");

    let gguf = files
        .iter()
        .find(|f| f.path == "Qwen3-8B-Q4_K_M.gguf")
        .expect("the Q4_K_M quant should be listed");
    assert_eq!(gguf.size, 5_027_784_512);
    // The same hash HuggingFace publishes for this file. Two independent hosts
    // agreeing is the whole basis of corroboration, so it is worth asserting on
    // real data rather than taking it on trust.
    assert_eq!(
        gguf.sha256.as_deref(),
        Some("120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4")
    );
}

#[test]
fn every_file_carries_a_hash_including_the_small_ones() {
    let files = ms::parse_files(FILES_JSON).unwrap();
    let unhashed: Vec<&str> = files
        .iter()
        .filter(|f| f.sha256.is_none())
        .map(|f| f.path.as_str())
        .collect();
    // ModelScope's Tier-1 coverage is broader than HuggingFace's: even
    // `.gitattributes` and `config.json` come with a SHA-256, so nothing in a
    // ModelScope bundle has to go unverified.
    assert!(unhashed.is_empty(), "unhashed files: {unhashed:?}");
}

#[test]
fn reads_the_abbreviated_head_from_the_real_listing() {
    let short = ms::parse_short_head(FILES_JSON).unwrap();
    assert_eq!(short, "baaddd6f");
    // And it is genuinely a prefix of the full id git reports, which is what
    // makes the fallback usable at all.
    assert!(HEAD_COMMIT.starts_with(&short));
}

#[test]
fn parses_the_real_upload_pack_response() {
    let packfile = git_http::extract_pack(UPLOAD_PACK_RESPONSE).unwrap();
    let objects = pack::parse_pack(&packfile).unwrap();

    let commit = objects
        .iter()
        .find(|o| o.kind == ObjectKind::Commit)
        .expect("the response should carry the commit");
    // The oid is recomputed from the bytes, never taken from the wire, so this
    // also proves the object arrived intact.
    assert_eq!(commit.oid, HEAD_COMMIT);

    assert!(
        objects.iter().any(|o| o.kind == ObjectKind::Tree),
        "a shallow fetch should include the root tree"
    );
}

#[test]
fn the_real_modelscope_commit_is_unsigned() {
    // This is the trust claim the tool makes about ModelScope, asserted against
    // a genuine commit rather than assumed: choosing `--source modelscope`
    // trades Tier 2 away entirely, and if that ever stops being true this test
    // should fail and the docs should change.
    let packfile = git_http::extract_pack(UPLOAD_PACK_RESPONSE).unwrap();
    let objects = pack::parse_pack(&packfile).unwrap();
    let commit = objects
        .iter()
        .find(|o| o.kind == ObjectKind::Commit)
        .unwrap();

    let parsed = amf_verify::git::parse_commit(&commit.data).unwrap();
    assert!(
        !parsed.is_signed(),
        "ModelScope commits are expected to be unsigned"
    );
}
