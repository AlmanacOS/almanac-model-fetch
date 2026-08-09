//! Live tests against the real HuggingFace API.
//!
//! These are `#[ignore]`d so that an ordinary `cargo test` stays hermetic and
//! works offline — a tool built for airgapped workflows should not have a test
//! suite that requires the network. Run them deliberately:
//!
//! ```text
//! cargo test -p amf-source --test live_huggingface -- --ignored
//! ```

use amf_source::{http_client, hf::HuggingFace, RepoSpec, Source, SourceKind};

fn backend() -> HuggingFace {
    HuggingFace::new(http_client("almanac-model-fetch/0.1.0 (test)").unwrap())
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn resolves_main_to_an_immutable_commit() {
    let spec = RepoSpec::parse("unsloth/Llama-3.2-1B-Instruct-GGUF").unwrap();
    let rev = backend().resolve(&spec).await.unwrap();

    assert_eq!(rev.requested, "main");
    assert_eq!(
        rev.commit.len(),
        40,
        "expected a full commit SHA, got {:?}",
        rev.commit
    );
    assert!(rev.commit.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(rev.source, SourceKind::HuggingFace);
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn a_pinned_revision_resolves_to_itself() {
    let spec = RepoSpec::parse(
        "unsloth/Qwen3-8B-GGUF@a6adef130ffb23ddaf1a62fec9dced968c9bc482",
    )
    .unwrap();
    let rev = backend().resolve(&spec).await.unwrap();
    assert_eq!(rev.commit, "a6adef130ffb23ddaf1a62fec9dced968c9bc482");
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn lists_variants_with_verifiable_hashes() {
    let hf = backend();
    let spec = RepoSpec::parse("unsloth/Llama-3.2-1B-Instruct-GGUF").unwrap();
    let rev = hf.resolve(&spec).await.unwrap();
    let variants = hf.list_variants(&rev).await.unwrap();

    assert!(!variants.is_empty());
    let q4 = variants
        .iter()
        .find(|v| v.label == "Q4_K_M")
        .expect("Q4_K_M should exist");

    assert!(q4.fully_verifiable(), "Q4_K_M must have a published hash");
    assert_eq!(
        q4.files[0].sha256.as_deref(),
        Some("3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1"),
        "the published hash for this pinned file should not change"
    );
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn a_nonexistent_repo_reports_access_denied_not_absence() {
    // HuggingFace answers 401 for unknown repos so as not to confirm what does
    // and does not exist. Our error must not overclaim by saying "not found".
    let spec = RepoSpec::parse("unsloth/definitely-not-a-real-repo-xyzzy").unwrap();
    let err = backend().resolve(&spec).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not accessible"),
        "unexpected error message: {msg}"
    );
    assert!(!err.is_unreachable(), "a 401 is not a connectivity failure");
}

/// A small real file, used so the download tests stay quick.
const SMALL_FILE: &str = "imatrix_unsloth.dat";
const SMALL_SHA: &str = "298a6e562c189ab54daee0bbd5324adf65c7ad248a65f5e1f3feeee28697bc86";
const SMALL_SIZE: u64 = 1_314_435;
const PINNED_COMMIT: &str = "b69aef112e9f895e6f98d7ae0949f72ff09aa401";

fn small_file_url() -> String {
    amf_source::download::file_url(
        amf_source::hf::DEFAULT_ENDPOINT,
        "unsloth/Llama-3.2-1B-Instruct-GGUF",
        PINNED_COMMIT,
        SMALL_FILE,
    )
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn downloads_and_verifies_a_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join(SMALL_FILE);
    let client = http_client("almanac-model-fetch/0.1.0 (test)").unwrap();

    let got = amf_source::download::download_verified(
        &client,
        &small_file_url(),
        &dest,
        SMALL_SHA,
        SMALL_SIZE,
        None,
    )
    .await
    .unwrap();

    assert_eq!(got.sha256, SMALL_SHA);
    assert_eq!(got.bytes_written, SMALL_SIZE);
    assert!(!got.resumed);
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), SMALL_SIZE);
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn resumes_a_partial_download_over_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join(SMALL_FILE);
    let client = http_client("almanac-model-fetch/0.1.0 (test)").unwrap();
    let url = small_file_url();

    // First pass, then truncate to simulate an interrupted transfer.
    amf_source::download::download_verified(&client, &url, &dest, SMALL_SHA, SMALL_SIZE, None)
        .await
        .unwrap();
    let keep = 500_000;
    let f = std::fs::OpenOptions::new().write(true).open(&dest).unwrap();
    f.set_len(keep).unwrap();
    drop(f);

    let got = amf_source::download::download_verified(
        &client, &url, &dest, SMALL_SHA, SMALL_SIZE, None,
    )
    .await
    .unwrap();

    assert!(got.resumed, "should have resumed rather than restarted");
    assert_eq!(got.sha256, SMALL_SHA);
    assert_eq!(
        got.bytes_transferred,
        SMALL_SIZE - keep,
        "should transfer only the missing tail"
    );
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn a_wrong_expected_hash_is_rejected() {
    // Simulates upstream serving different bytes than published.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join(SMALL_FILE);
    let client = http_client("almanac-model-fetch/0.1.0 (test)").unwrap();

    let err = amf_source::download::download_verified(
        &client,
        &small_file_url(),
        &dest,
        &"f".repeat(64),
        SMALL_SIZE,
        None,
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("hash mismatch"), "got: {err}");
}

#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn fetches_the_signed_commit_and_trees_over_smart_http() {
    let client = http_client("almanac-model-fetch/0.1.0 (test)").unwrap();
    let objects = amf_source::git_http::fetch_commit_and_trees(
        &client,
        amf_source::hf::DEFAULT_ENDPOINT,
        "unsloth/Qwen3-8B-GGUF",
        "a6adef130ffb23ddaf1a62fec9dced968c9bc482",
    )
    .await
    .unwrap();

    use amf_verify::git::ObjectKind;
    let commit = objects.iter().find(|o| o.kind == ObjectKind::Commit).unwrap();
    assert_eq!(commit.oid, "a6adef130ffb23ddaf1a62fec9dced968c9bc482");
    let parsed = amf_verify::git::parse_commit(&commit.data).unwrap();
    assert!(parsed.is_signed());
    assert!(objects.iter().any(|o| o.kind == ObjectKind::Tree
        && o.oid == "116f6efcc6377fce0d8d0917bc15c3126dcec5b9"));
}
