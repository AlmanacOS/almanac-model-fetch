//! Parse a real packfile served by HuggingFace.
//!
//! Captured from a live protocol-v2 fetch of `unsloth/Qwen3-8B-GGUF` at commit
//! `a6adef13…` with `filter blob:none` and `deepen 1` — the exact request the
//! evidence capture makes. Two objects: the GPG-signed commit and its root
//! tree.

use amf_source::pack::parse_pack;
use amf_verify::git::ObjectKind;

const PACK: &[u8] = include_bytes!("fixtures/qwen3_shallow.pack");

#[test]
fn parses_the_real_hf_pack() {
    let objects = parse_pack(PACK).unwrap();
    assert_eq!(objects.len(), 2);

    let commit = objects
        .iter()
        .find(|o| o.kind == ObjectKind::Commit)
        .unwrap();
    assert_eq!(commit.oid, "a6adef130ffb23ddaf1a62fec9dced968c9bc482");

    let tree = objects.iter().find(|o| o.kind == ObjectKind::Tree).unwrap();
    assert_eq!(tree.oid, "116f6efcc6377fce0d8d0917bc15c3126dcec5b9");
}

#[test]
fn the_packed_commit_is_the_signed_commit_we_know() {
    let objects = parse_pack(PACK).unwrap();
    let commit = objects
        .iter()
        .find(|o| o.kind == ObjectKind::Commit)
        .unwrap();

    let parsed = amf_verify::git::parse_commit(&commit.data).unwrap();
    assert!(parsed.is_signed());
    assert!(parsed.committer.contains("system@huggingface.co"));
    assert_eq!(parsed.tree, "116f6efcc6377fce0d8d0917bc15c3126dcec5b9");
}

#[test]
fn a_flipped_byte_in_the_real_pack_is_caught() {
    let mut pack = PACK.to_vec();
    pack[100] ^= 1;
    assert!(parse_pack(&pack).is_err());
}
