//! Live tests against modelscope.cn. Run with `cargo test -- --ignored`.
//!
//! These exist because the interesting failures are wire-level: an edge filter
//! that rejects a user agent, a redirect that drops a `Range` header, a JSON
//! envelope that mangles pointer bytes. None of that is reachable with fixtures.

use amf_source::ms::ModelScope;
use amf_source::{http_client, ms, RepoSpec, Source, SourceKind};

const REPO: &str = "unsloth/Qwen3-8B-GGUF";
const Q4_K_M: &str = "Qwen3-8B-Q4_K_M.gguf";
const Q4_K_M_SHA256: &str = "120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4";

fn backend() -> ModelScope {
    ms::ModelScope::new(http_client("almanac-model-fetch/0.1.0 (test)").unwrap())
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn resolves_a_branch_to_a_full_commit_id() {
    let rev = backend()
        .resolve(&RepoSpec::parse(REPO).unwrap())
        .await
        .unwrap();

    // The REST API cannot do this; it comes from git ls-refs. If ModelScope's
    // edge ever starts filtering our user agent, this drops to an 8-hex short
    // id and the assertion below fails — which is exactly the signal we want,
    // rather than a bundle quietly recording less than it claims.
    assert_eq!(rev.commit.len(), 40, "got {}", rev.commit);
    assert!(rev.precision.is_exact());
    assert_eq!(rev.source, SourceKind::ModelScope);
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn a_pinned_commit_resolves_to_itself() {
    let spec =
        RepoSpec::parse(&format!("{REPO}@baaddd6fb19e702c1d54c5bb2a5746012c122619")).unwrap();
    let rev = backend().resolve(&spec).await.unwrap();
    assert_eq!(rev.commit, "baaddd6fb19e702c1d54c5bb2a5746012c122619");
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn lists_files_with_hashes_for_everything() {
    let b = backend();
    let rev = b.resolve(&RepoSpec::parse(REPO).unwrap()).await.unwrap();
    let files = b.list_files(&rev).await.unwrap();

    assert!(files.len() > 20);
    assert!(
        files.iter().all(|f| f.sha256.is_some()),
        "ModelScope publishes a hash for every file"
    );
    let gguf = files.iter().find(|f| f.path == Q4_K_M).unwrap();
    assert_eq!(gguf.sha256.as_deref(), Some(Q4_K_M_SHA256));
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn fetches_an_lfs_pointer_through_the_json_envelope() {
    let b = backend();
    let rev = b.resolve(&RepoSpec::parse(REPO).unwrap()).await.unwrap();
    let pointer = b.fetch_pointer(&rev, Q4_K_M).await.unwrap();

    assert!(amf_verify::lfs::looks_like_pointer(&pointer));
    let parsed = amf_verify::lfs::parse_pointer(&pointer).unwrap();
    // The pointer is reconstructed from a JSON string rather than received
    // verbatim, so this checks the envelope did not mangle it.
    assert_eq!(parsed.oid_sha256, Q4_K_M_SHA256);
    assert_eq!(parsed.size, 5_027_784_512);
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn captures_the_commit_and_trees_over_git() {
    let b = backend();
    let rev = b.resolve(&RepoSpec::parse(REPO).unwrap()).await.unwrap();
    let repo_url = b.endpoints().git_repo_url(REPO).unwrap();

    let objects = amf_source::git_http::fetch_commit_and_trees(
        &http_client("almanac-model-fetch/0.1.0 (test)").unwrap(),
        &repo_url,
        &rev.commit,
    )
    .await
    .unwrap();

    use amf_verify::git::ObjectKind;
    let commit = objects
        .iter()
        .find(|o| o.kind == ObjectKind::Commit)
        .unwrap();
    assert_eq!(commit.oid, rev.commit);
    assert!(objects.iter().any(|o| o.kind == ObjectKind::Tree));
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn the_range_header_survives_the_cdn_redirect() {
    // Downloads redirect cross-host to a CDN. If the `Range` header were
    // dropped there, resume would silently restart from zero on every retry —
    // on a 5 GB model over a bad link, that is the difference between finishing
    // and never finishing.
    let b = backend();
    let rev = b.resolve(&RepoSpec::parse(REPO).unwrap()).await.unwrap();
    let url = b.endpoints().file_url(REPO, &rev.commit, Q4_K_M);

    let resp = http_client("almanac-model-fetch/0.1.0 (test)")
        .unwrap()
        .get(&url)
        .header("Range", "bytes=1000-1015")
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) if e.is_connect() || e.is_timeout() => {
            // ModelScope's LFS CDN (`cdn-lfs-cn-1.modelscope.cn`) is not
            // reachable from every network — it was not reachable from the
            // machine this was written on, while the API host was. Treating
            // that as a failure would make the suite report a network fact as a
            // code defect. The assertion below still runs wherever the CDN is
            // reachable, which is where the property actually needs enforcing.
            eprintln!("SKIPPED: ModelScope's LFS CDN is unreachable from this network ({e})");
            return;
        }
        Err(e) => panic!("unexpected error: {e}"),
    };

    assert_eq!(
        resp.status().as_u16(),
        206,
        "expected a partial response, got {}",
        resp.status()
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 16);
}

#[tokio::test]
#[ignore = "requires network access to modelscope.cn"]
async fn an_unknown_repo_does_not_claim_the_repo_is_absent() {
    // ModelScope answers 404 for private repos as well as missing ones, so the
    // message must not tell an operator their repo does not exist when the real
    // problem is a missing token.
    let err = backend()
        .resolve(&RepoSpec::parse("unsloth/definitely-not-a-real-repo-xyz").unwrap())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not accessible"), "got: {msg}");
}
