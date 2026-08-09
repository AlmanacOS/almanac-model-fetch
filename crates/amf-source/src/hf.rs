//! HuggingFace backend — the default source.

use crate::model::{RemoteFile, Revision, RevisionPrecision};
use crate::spec::{RepoId, RepoSpec, SourceKind};
use crate::{HostEndpoints, Source, SourceError};

pub const DEFAULT_ENDPOINT: &str = "https://huggingface.co";

pub struct HuggingFace {
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
}

impl HuggingFace {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            // A token is only needed for gated or private repos. Reading it from
            // the environment matches what every other HF tool does, so an
            // operator who has already logged in elsewhere does not have to
            // re-supply it.
            token: std::env::var("HF_TOKEN")
                .or_else(|_| std::env::var("HUGGING_FACE_HUB_TOKEN"))
                .ok()
                .filter(|t| !t.trim().is_empty()),
        }
    }

    /// Point the backend at a different host — used by tests and by anyone
    /// running an HF-compatible mirror.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.filter(|t| !t.trim().is_empty());
        self
    }

    fn request(&self, url: &str) -> reqwest::RequestBuilder {
        let req = self.client.get(url);
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// Translate a response status into the error it deserves, if any.
    fn status_error(
        &self,
        status: reqwest::StatusCode,
        url: &str,
        repo: &RepoId,
    ) -> Option<SourceError> {
        // HuggingFace answers 401 for repos that do not exist as well as for
        // ones you cannot see, deliberately refusing to confirm existence. We
        // must not translate that into "no such repo" — the operator may simply
        // need a token.
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Some(SourceError::AccessDenied {
                repo: repo.to_string(),
                authenticated: self.token.is_some(),
                token_env: "HF_TOKEN",
            });
        }
        if status.as_u16() == 404 {
            return Some(SourceError::NotFound(repo.to_string()));
        }
        if !status.is_success() {
            return Some(SourceError::Http {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
        None
    }

    async fn get_text(
        &self,
        url: &str,
        repo: &RepoId,
    ) -> Result<(String, Option<String>), SourceError> {
        let resp = self
            .request(url)
            .send()
            .await
            .map_err(|e| SourceError::Transport {
                host: SourceKind::HuggingFace.host().into(),
                source: e,
            })?;

        if let Some(e) = self.status_error(resp.status(), url, repo) {
            return Err(e);
        }

        let next = next_page_url(&resp, &self.endpoint);
        let body = crate::git_http::read_body_capped(resp, url, MAX_API_RESPONSE_BYTES).await?;
        Ok((String::from_utf8_lossy(&body).into_owned(), next))
    }

    /// Fetch a response body that must be small, refusing anything larger.
    async fn get_capped(
        &self,
        url: &str,
        repo: &RepoId,
        cap: usize,
    ) -> Result<Vec<u8>, SourceError> {
        let resp = self
            .request(url)
            .send()
            .await
            .map_err(|e| SourceError::Transport {
                host: SourceKind::HuggingFace.host().into(),
                source: e,
            })?;
        if let Some(e) = self.status_error(resp.status(), url, repo) {
            return Err(e);
        }
        crate::git_http::read_body_capped(resp, url, cap).await
    }
}

/// Extract the `rel="next"` target from a `Link` header, if present.
///
/// The tree endpoint paginates, and a repo with hundreds of shards will run past
/// the first page. Ignoring pagination would silently truncate the file listing
/// and, worse, could make a complete shard set look like it was missing parts.
fn next_page_url(resp: &reqwest::Response, endpoint: &str) -> Option<String> {
    let header = resp.headers().get(reqwest::header::LINK)?.to_str().ok()?;
    parse_link_next(header, endpoint)
}

pub(crate) fn parse_link_next(header: &str, endpoint: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        let (url_part, rest) = part.split_once('>')?;
        if !rest.contains("rel=\"next\"") && !rest.contains("rel=next") {
            continue;
        }
        let url = url_part.trim_start_matches('<').trim();
        if url.is_empty() {
            return None;
        }
        return Some(if url.starts_with("http") {
            url.to_string()
        } else {
            format!("{}{}", endpoint.trim_end_matches('/'), url)
        });
    }
    None
}

/// Parse one page of the tree endpoint into files.
///
/// The SHA256 comes from `lfs.oid`, which is what HuggingFace publishes for
/// LFS-backed files and is the same value that appears in the LFS pointer inside
/// the (GPG-signed) git tree. Small non-LFS files have no `lfs` object and carry
/// only a git blob SHA1, which is not a content hash of the file we download —
/// so those get `None` rather than a hash we cannot verify against.
///
/// Public so integration tests can run it against real captured responses.
pub fn parse_tree_page(body: &str) -> Result<Vec<RemoteFile>, SourceError> {
    let entries: Vec<serde_json::Value> = serde_json::from_str(body)
        .map_err(|e| SourceError::Malformed(format!("tree listing was not a JSON array: {e}")))?;

    let mut files = Vec::new();
    for entry in entries {
        if entry.get("type").and_then(|t| t.as_str()) != Some("file") {
            continue;
        }
        let Some(path) = entry.get("path").and_then(|p| p.as_str()) else {
            continue;
        };
        let lfs = entry.get("lfs");
        let sha256 = lfs
            .and_then(|l| l.get("oid"))
            .and_then(|o| o.as_str())
            .map(|s| s.to_ascii_lowercase());
        // The LFS object's size is the true size of the file we will download;
        // the top-level `size` on an LFS entry is also the real size, but we
        // prefer the LFS one when both are present since it is the one the
        // pointer commits to.
        let size = lfs
            .and_then(|l| l.get("size"))
            .and_then(|s| s.as_u64())
            .or_else(|| entry.get("size").and_then(|s| s.as_u64()))
            .unwrap_or(0);

        files.push(RemoteFile {
            path: path.to_string(),
            size,
            sha256,
            shard: None,
        });
    }
    Ok(files)
}

fn parse_commit_sha(body: &str) -> Result<String, SourceError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| SourceError::Malformed(format!("model info was not JSON: {e}")))?;
    value
        .get("sha")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SourceError::Malformed("model info had no \"sha\" field".into()))
}

#[async_trait::async_trait]
impl Source for HuggingFace {
    fn kind(&self) -> SourceKind {
        SourceKind::HuggingFace
    }

    fn endpoints(&self) -> HostEndpoints {
        let base = self.endpoint.trim_end_matches('/').to_string();
        HostEndpoints {
            api_base: format!("{base}/api"),
            resolve_base: base.clone(),
            git_base: Some(base),
            // HuggingFace serves smart-HTTP straight off the repo path.
            git_suffix: String::new(),
        }
    }

    async fn fetch_pointer(&self, rev: &Revision, path: &str) -> Result<Vec<u8>, SourceError> {
        // `/raw/` serves the pointer text itself for an LFS-backed file, which
        // is exactly the blob the signed tree names.
        let url = format!(
            "{}/{}/raw/{}/{}",
            self.endpoint.trim_end_matches('/'),
            rev.repo,
            rev.commit,
            urlencode_segments(path),
        );
        // Pointers are ~130 bytes. Cap the read so a host that answers `/raw/`
        // with the real model file (or with garbage) cannot balloon memory
        // before `looks_like_pointer` gets a chance to reject it.
        self.get_capped(&url, &rev.repo, MAX_POINTER_BYTES).await
    }

    async fn resolve(&self, spec: &RepoSpec) -> Result<Revision, SourceError> {
        let requested = spec.revision.clone().unwrap_or_else(|| "main".into());
        let url = format!(
            "{}/api/models/{}/revision/{}",
            self.endpoint.trim_end_matches('/'),
            spec.repo,
            urlencode_path(&requested),
        );
        let (body, _) = self.get_text(&url, &spec.repo).await?;
        let commit = parse_commit_sha(&body)?;
        Ok(Revision {
            source: SourceKind::HuggingFace,
            repo: spec.repo.clone(),
            precision: RevisionPrecision::of(&commit),
            commit,
            requested,
        })
    }

    async fn list_files(&self, rev: &Revision) -> Result<Vec<RemoteFile>, SourceError> {
        // Always list against the resolved commit, never the branch name: the
        // branch could move between resolve and listing, and a bundle built from
        // two different tree states would be incoherent.
        let mut url = format!(
            "{}/api/models/{}/tree/{}?recursive=true",
            self.endpoint.trim_end_matches('/'),
            rev.repo,
            rev.commit,
        );

        let mut all = Vec::new();
        let mut pages = 0;
        loop {
            let (body, next) = self.get_text(&url, &rev.repo).await?;
            all.extend(parse_tree_page(&body)?);
            pages += 1;
            match next {
                // A malformed or self-referential Link header could otherwise
                // spin forever against a hostile or buggy endpoint.
                Some(n) if pages < MAX_PAGES => url = n,
                Some(_) => {
                    return Err(SourceError::Malformed(format!(
                        "tree listing for {} exceeded {MAX_PAGES} pages; refusing to continue",
                        rev.repo
                    )))
                }
                None => break,
            }
        }
        Ok(all)
    }
}

const MAX_PAGES: usize = 100;

/// Ceiling on a JSON API response. A tree page for a repo with thousands of
/// shards is a few megabytes; anything past this is not a listing.
const MAX_API_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Ceiling on an LFS pointer, which is ~130 bytes in practice.
const MAX_POINTER_BYTES: usize = 64 * 1024;

/// Percent-encode each segment of a repo-relative file path.
///
/// Unlike a revision, a file path's separators are structural but its segments
/// are arbitrary: a file called `v1#final.gguf` would otherwise truncate the URL
/// at the fragment and silently fetch something else.
pub(crate) fn urlencode_segments(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        for b in seg.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    out
}

/// Percent-encode a revision for use in a URL path.
///
/// Revisions can be refs like `refs/pr/3`, so slashes must survive, but spaces
/// and other oddities must not.
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
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

    #[test]
    fn parses_lfs_hashes_from_a_tree_page() {
        let body = r#"[
          {"type":"file","path":"README.md","size":100,"oid":"abc"},
          {"type":"file","path":"M-Q4_K_M.gguf","size":807694368,
           "lfs":{"oid":"3F5A22426976AB26","size":807694368,"pointerSize":134}},
          {"type":"directory","path":"subdir"}
        ]"#;
        let files = parse_tree_page(body).unwrap();
        assert_eq!(files.len(), 2, "directories must be skipped");

        let readme = &files[0];
        assert_eq!(readme.path, "README.md");
        assert_eq!(
            readme.sha256, None,
            "a non-LFS file has no publishable content hash"
        );

        let gguf = &files[1];
        assert_eq!(gguf.size, 807_694_368);
        assert_eq!(
            gguf.sha256.as_deref(),
            Some("3f5a22426976ab26"),
            "hashes should be normalised to lowercase for comparison"
        );
    }

    #[test]
    fn rejects_a_non_array_tree() {
        assert!(parse_tree_page(r#"{"error":"nope"}"#).is_err());
        assert!(parse_tree_page("not json").is_err());
    }

    #[test]
    fn parses_the_commit_sha() {
        let body = r#"{"id":"unsloth/x","sha":"b69aef112e9f895e6f98d7ae0949f72ff09aa401"}"#;
        assert_eq!(
            parse_commit_sha(body).unwrap(),
            "b69aef112e9f895e6f98d7ae0949f72ff09aa401"
        );
        assert!(parse_commit_sha(r#"{"id":"x"}"#).is_err());
    }

    #[test]
    fn parses_a_next_link() {
        let header = r#"<https://huggingface.co/api/models/x/tree/main?cursor=abc>; rel="next""#;
        assert_eq!(
            parse_link_next(header, "https://huggingface.co").as_deref(),
            Some("https://huggingface.co/api/models/x/tree/main?cursor=abc")
        );
    }

    #[test]
    fn resolves_a_relative_next_link_against_the_endpoint() {
        let header = r#"</api/models/x/tree/main?cursor=abc>; rel="next""#;
        assert_eq!(
            parse_link_next(header, "https://example.test/").as_deref(),
            Some("https://example.test/api/models/x/tree/main?cursor=abc")
        );
    }

    #[test]
    fn ignores_link_headers_without_a_next_relation() {
        let header = r#"<https://huggingface.co/prev>; rel="prev""#;
        assert_eq!(parse_link_next(header, "https://huggingface.co"), None);
    }

    #[test]
    fn urlencodes_revisions_but_keeps_ref_slashes() {
        assert_eq!(urlencode_path("main"), "main");
        assert_eq!(urlencode_path("refs/pr/3"), "refs/pr/3");
        assert_eq!(urlencode_path("weird branch"), "weird%20branch");
    }
}
