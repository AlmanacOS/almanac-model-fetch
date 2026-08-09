//! ModelScope backend — the fallback for operators who cannot reach HuggingFace.
//!
//! ModelScope is not a peer the tool load-balances across; it is the host an
//! operator behind a firewall that blocks HuggingFace is forced onto, and
//! choosing it trades away Tier 2 (ModelScope does not sign its commits). The
//! backend is otherwise full parity: same trait, same evidence capture, same
//! bundle layout, so the airgapped importer cannot tell which host a bundle came
//! from beyond what the manifest records.
//!
//! Two differences from HuggingFace are structural rather than cosmetic:
//!
//! - **Hashes are published for every file**, not only LFS objects, so Tier-1
//!   coverage here is broader than HF's.
//! - **The REST API cannot name the head commit.** `/revisions` lists branch
//!   names, and the per-file `Revision` field is the last commit to touch that
//!   file, not the repo's head. Resolution therefore goes over git `ls-refs`,
//!   which returns the full 40-hex id; only if that is unreachable does the
//!   backend fall back to the abbreviated `ShortId` and say so.

use crate::model::{RemoteFile, Revision, RevisionPrecision};
use crate::spec::{RepoId, RepoSpec, SourceKind};
use crate::{git_http, HostEndpoints, Source, SourceError};

pub const DEFAULT_ENDPOINT: &str = "https://www.modelscope.cn";

pub struct ModelScope {
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
}

impl ModelScope {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            token: std::env::var("MODELSCOPE_API_TOKEN")
                .or_else(|_| std::env::var("MODELSCOPE_TOKEN"))
                .ok()
                .filter(|t| !t.trim().is_empty()),
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    fn api_base(&self) -> String {
        format!("{}/api/v1/models", self.endpoint.trim_end_matches('/'))
    }

    /// Fetch a response body, refusing anything larger than `cap`.
    ///
    /// Every endpoint here answers with a small JSON envelope, so a hard ceiling
    /// costs nothing and stops a host that answers a pointer request with the
    /// real model file from exhausting memory before the caller can reject it.
    async fn get_capped(
        &self,
        url: &str,
        repo: &RepoId,
        cap: usize,
    ) -> Result<Vec<u8>, SourceError> {
        let req = self.client.get(url);
        let req = match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let resp = req.send().await.map_err(|e| SourceError::Transport {
            host: SourceKind::ModelScope.host().into(),
            source: e,
        })?;

        let status = resp.status();
        // ModelScope answers 404 for a repo that does not exist *and* for one
        // you cannot see, so the message must not claim the repo is absent —
        // the operator may simply need a token.
        if status.as_u16() == 404 || status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(SourceError::AccessDenied {
                repo: repo.to_string(),
                authenticated: self.token.is_some(),
                token_env: "MODELSCOPE_API_TOKEN",
            });
        }
        if !status.is_success() {
            return Err(SourceError::Http {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }

        git_http::read_body_capped(resp, url, cap).await
    }

    async fn get_text(&self, url: &str, repo: &RepoId) -> Result<String, SourceError> {
        let body = self.get_capped(url, repo, MAX_API_RESPONSE_BYTES).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

/// Ceiling on a JSON API response. A recursive listing of a repo with thousands
/// of shards is a few megabytes; anything past this is not a listing.
const MAX_API_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Ceiling on the envelope carrying an LFS pointer, which is ~130 bytes of
/// payload in practice.
const MAX_POINTER_BYTES: usize = 64 * 1024;

/// Unwrap ModelScope's `{Code, Data, Message, Success}` envelope.
fn envelope_data(body: &str) -> Result<serde_json::Value, SourceError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| SourceError::Malformed(format!("ModelScope response was not JSON: {e}")))?;

    // Failures come back as HTTP 200 with `Success: false`, so the envelope has
    // to be checked rather than trusting the status line.
    if value.get("Success").and_then(|s| s.as_bool()) == Some(false) {
        let msg = value
            .get("Message")
            .and_then(|m| m.as_str())
            .unwrap_or("no message");
        return Err(SourceError::Malformed(format!(
            "ModelScope reported failure: {msg}"
        )));
    }
    value
        .get("Data")
        .cloned()
        .ok_or_else(|| SourceError::Malformed("ModelScope response had no Data object".into()))
}

/// Parse a `repo/files` listing.
///
/// Unlike HuggingFace, `Sha256` is present for every blob, LFS or not, so no
/// file in a ModelScope bundle needs to go unverified.
pub fn parse_files(body: &str) -> Result<Vec<RemoteFile>, SourceError> {
    let data = envelope_data(body)?;
    let entries = data
        .get("Files")
        .and_then(|f| f.as_array())
        .ok_or_else(|| SourceError::Malformed("file listing had no Files array".into()))?;

    let mut files = Vec::new();
    for entry in entries {
        if entry.get("Type").and_then(|t| t.as_str()) != Some("blob") {
            continue;
        }
        let Some(path) = entry.get("Path").and_then(|p| p.as_str()) else {
            continue;
        };
        let sha256 = entry
            .get("Sha256")
            .and_then(|s| s.as_str())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|s| s.to_ascii_lowercase());
        let size = entry.get("Size").and_then(|s| s.as_u64()).unwrap_or(0);

        files.push(RemoteFile {
            path: path.to_string(),
            size,
            sha256,
            shard: None,
        });
    }
    Ok(files)
}

/// Extract the abbreviated head id from a file listing's `LatestCommitter`.
///
/// This is the fallback when git is unreachable. `Id` is empty in every response
/// observed, and `ParentIds` names the *parent* — reconstructing a head id from
/// a parent plus a short id would be fabrication, so only `ShortId` is used, and
/// the caller records that the result is abbreviated.
pub fn parse_short_head(body: &str) -> Result<String, SourceError> {
    let data = envelope_data(body)?;
    let committer = data
        .get("LatestCommitter")
        .ok_or_else(|| SourceError::Malformed("file listing had no LatestCommitter".into()))?;

    for field in ["Id", "ShortId"] {
        if let Some(id) = committer.get(field).and_then(|v| v.as_str()) {
            // Same shape test the revision parser uses. A one- or four-character
            // "id" is not a pin at all, and accepting one would put a value in
            // the manifest's `commit` field that names thousands of commits.
            let id = id.trim();
            if looks_like_object_id(id) {
                return Ok(id.to_ascii_lowercase());
            }
        }
    }
    Err(SourceError::Malformed(
        "ModelScope named no commit id for this revision".into(),
    ))
}

/// Extract LFS pointer text from a `repo/raw` response.
///
/// The pointer arrives as a JSON string rather than as the response body, so
/// these bytes are reconstructed rather than received verbatim. That is safe
/// only because the caller checks them against the blob id recorded in the git
/// tree: if the envelope mangled anything, the object id will not match and
/// evidence capture fails loudly instead of storing a corrupted pointer.
pub fn parse_raw_content(body: &str) -> Result<Vec<u8>, SourceError> {
    let data = envelope_data(body)?;
    data.get("Content")
        .and_then(|c| c.as_str())
        .map(|c| c.as_bytes().to_vec())
        .ok_or_else(|| SourceError::Malformed("raw response had no Content field".into()))
}

fn looks_like_object_id(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[async_trait::async_trait]
impl Source for ModelScope {
    fn kind(&self) -> SourceKind {
        SourceKind::ModelScope
    }

    fn endpoints(&self) -> HostEndpoints {
        let base = self.endpoint.trim_end_matches('/').to_string();
        HostEndpoints {
            api_base: format!("{base}/api/v1/models"),
            // Bytes live under `/models/`, unlike the git endpoint.
            resolve_base: format!("{base}/models"),
            git_base: Some(base),
            git_suffix: ".git".into(),
        }
    }

    async fn fetch_pointer(&self, rev: &Revision, path: &str) -> Result<Vec<u8>, SourceError> {
        let url = format!(
            "{}/{}/repo/raw?Revision={}&FilePath={}",
            self.api_base(),
            rev.repo,
            urlencode_query(&rev.commit),
            urlencode_query(path),
        );
        let body = self.get_capped(&url, &rev.repo, MAX_POINTER_BYTES).await?;
        parse_raw_content(&String::from_utf8_lossy(&body))
    }

    async fn resolve(&self, spec: &RepoSpec) -> Result<Revision, SourceError> {
        let requested = spec.revision.clone().unwrap_or_else(|| "master".into());

        // An explicit object id needs no resolution: it is already immutable,
        // and asking the host to confirm it would only invite the host to
        // answer with something else.
        if looks_like_object_id(&requested) {
            return Ok(Revision {
                source: SourceKind::ModelScope,
                repo: spec.repo.clone(),
                precision: RevisionPrecision::of(&requested),
                commit: requested.to_ascii_lowercase(),
                requested,
            });
        }

        // Preferred path: ask the git server, which names the full 40-hex id.
        let endpoints = self.endpoints();
        if let Some(repo_url) = endpoints.git_repo_url(&spec.repo.to_string()) {
            let prefixes = vec![
                format!("refs/heads/{requested}"),
                format!("refs/tags/{requested}"),
            ];
            match git_http::ls_refs(&self.client, &repo_url, &prefixes).await {
                Ok(refs) => {
                    let wanted = [
                        format!("refs/heads/{requested}"),
                        format!("refs/tags/{requested}"),
                    ];
                    if let Some(entry) = refs.iter().find(|r| wanted.contains(&r.name)) {
                        return Ok(Revision {
                            source: SourceKind::ModelScope,
                            repo: spec.repo.clone(),
                            commit: entry.commit().to_string(),
                            precision: RevisionPrecision::of(entry.commit()),
                            requested,
                        });
                    }
                }
                Err(e) if e.is_unreachable() => return Err(e),
                // Any other git failure (a filtered edge, a server that stopped
                // speaking v2) is not fatal: fall through to the REST short id
                // and let the caller see that the result is abbreviated.
                Err(_) => {}
            }
        }

        let url = format!(
            "{}/{}/repo/files?Revision={}&Recursive=False",
            self.api_base(),
            spec.repo,
            urlencode_query(&requested),
        );
        let body = self.get_text(&url, &spec.repo).await?;
        let commit = parse_short_head(&body)?;
        Ok(Revision {
            source: SourceKind::ModelScope,
            repo: spec.repo.clone(),
            precision: RevisionPrecision::of(&commit),
            commit,
            requested,
        })
    }

    async fn list_files(&self, rev: &Revision) -> Result<Vec<RemoteFile>, SourceError> {
        let url = format!(
            "{}/{}/repo/files?Revision={}&Recursive=True",
            self.api_base(),
            rev.repo,
            urlencode_query(&rev.commit),
        );
        let body = self.get_text(&url, &rev.repo).await?;
        parse_files(&body)
    }
}

/// Percent-encode a query-string value.
fn urlencode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = r#"{
      "Code": 200,
      "Data": {
        "Files": [
          {"Type":"blob","Path":"config.json","Size":754,"IsLFS":false,
           "Sha256":"044D62050D8FAD299DAF9F88CC37ED1B4E44C4B0EE7410C14699B71AB5538241"},
          {"Type":"blob","Path":"Qwen3-8B-Q4_K_M.gguf","Size":5027784512,"IsLFS":true,
           "Sha256":"120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4"},
          {"Type":"tree","Path":"subdir"}
        ],
        "LatestCommitter": {"Id":"","ShortId":"baaddd6f","ParentIds":["90c83b81"]}
      },
      "Message": "success",
      "Success": true
    }"#;

    #[test]
    fn parses_hashes_for_every_file_not_just_lfs() {
        let files = parse_files(LISTING).unwrap();
        assert_eq!(files.len(), 2, "trees must be skipped");

        // The point of difference from HuggingFace: a small non-LFS file still
        // carries a content hash here, so it can be verified like any other.
        assert_eq!(
            files[0].sha256.as_deref(),
            Some("044d62050d8fad299daf9f88cc37ed1b4e44c4b0ee7410c14699b71ab5538241"),
            "hashes must be normalised to lowercase"
        );
        assert_eq!(files[1].size, 5_027_784_512);
    }

    #[test]
    fn rejects_a_hash_that_is_not_a_sha256() {
        let body = LISTING.replace(
            "120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4",
            "not-a-hash",
        );
        let files = parse_files(&body).unwrap();
        // Better to report "no hash published" and refuse to verify than to
        // carry a malformed value into a comparison.
        assert_eq!(files[1].sha256, None);
    }

    #[test]
    fn surfaces_an_envelope_level_failure() {
        let body = r#"{"Code":500,"Message":"repo is being indexed","Success":false}"#;
        let err = parse_files(body).unwrap_err().to_string();
        assert!(err.contains("being indexed"), "{err}");
    }

    #[test]
    fn takes_the_short_head_but_never_the_parent() {
        assert_eq!(parse_short_head(LISTING).unwrap(), "baaddd6f");

        // `ParentIds` is a full-length id and it would be tempting to prefer it
        // for looking precise. It names the wrong commit.
        let body = LISTING.replace(r#""ShortId":"baaddd6f","#, "");
        assert!(parse_short_head(&body).is_err());
    }

    #[test]
    fn an_abbreviated_head_is_labelled_as_such() {
        assert_eq!(
            RevisionPrecision::of("baaddd6f"),
            RevisionPrecision::Abbreviated { chars: 8 }
        );
        assert!(RevisionPrecision::of("baaddd6fb19e702c1d54c5bb2a5746012c122619").is_exact());
    }

    #[test]
    fn extracts_pointer_text_from_the_json_envelope() {
        let body = r#"{"Code":200,"Data":{"Content":"version https://git-lfs.github.com/spec/v1\noid sha256:120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4\nsize 5027784512\n","IsBinary":true},"Success":true}"#;
        let bytes = parse_raw_content(body).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("version https://git-lfs.github.com/spec/v1\n"));
        assert!(text.contains("oid sha256:120307ba"));
    }

    #[test]
    fn endpoints_split_the_git_and_bytes_paths() {
        let ms = ModelScope::new(reqwest::Client::new()).with_endpoint("https://example.test");
        let e = ms.endpoints();
        // Bytes live under /models/, git does not — getting these confused
        // yields a 404 on downloads or a 421 on git.
        assert_eq!(
            e.file_url("org/name", "abc", "a b.gguf"),
            "https://example.test/models/org/name/resolve/abc/a%20b.gguf"
        );
        assert_eq!(
            e.git_repo_url("org/name").as_deref(),
            Some("https://example.test/org/name.git")
        );
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(urlencode_query("refs/heads/main"), "refs%2Fheads%2Fmain");
        assert_eq!(urlencode_query("a b#c"), "a%20b%23c");
    }
}
