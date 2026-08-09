//! Minimal git smart-HTTP protocol-v2 client.
//!
//! One job: fetch the signed commit object and its trees from a repository,
//! without cloning anything. A v2 `fetch` with `want <commit>`, `deepen 1`, and
//! `filter blob:none` returns a packfile a few kilobytes long — the evidence a
//! bundle needs and nothing else.
//!
//! Hand-rolled rather than a git library because the whole exchange is two
//! HTTP requests and some framing, and this code sits on the trust path: a few
//! hundred auditable lines beat a dependency tree here for the same reason
//! `amf-verify` parses git objects itself.

use crate::pack::{parse_pack, PackedObject};
use crate::SourceError;

/// pkt-line special frames.
const FLUSH: &[u8] = b"0000";
const DELIM: &[u8] = b"0001";

/// Upper bound on a capability advertisement — real ones are a few hundred bytes.
const MAX_ADVERT_BYTES: usize = 1024 * 1024;

/// Upper bound on a fetch response. The commit plus every tree of even a very
/// large repo is a few megabytes; anything near this limit means the blob
/// filter was ignored or the server is hostile. The response is buffered in
/// memory, so without a cap a malicious server could OOM the fetcher — the
/// same reasoning as the per-object sanity limit in [`crate::pack`].
const MAX_FETCH_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Read a response body, refusing to buffer more than `cap` bytes.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    url: &str,
    cap: usize,
) -> Result<Vec<u8>, SourceError> {
    if let Some(len) = resp.content_length() {
        if len > cap as u64 {
            return Err(SourceError::Malformed(format!(
                "{url}: response of {len} bytes exceeds the {cap}-byte limit"
            )));
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| transport(url, e))? {
        if out.len() + chunk.len() > cap {
            return Err(SourceError::Malformed(format!(
                "{url}: response exceeds the {cap}-byte limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Encode one pkt-line.
fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Split a pkt-line stream into frames.
///
/// `None` entries are flush/delim markers; `Some` entries are payloads.
pub(crate) fn parse_pkt_lines(mut data: &[u8]) -> Result<Vec<Option<Vec<u8>>>, SourceError> {
    let mut frames = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(malformed("truncated pkt-line length"));
        }
        let len_str = std::str::from_utf8(&data[..4])
            .map_err(|_| malformed("pkt-line length is not ASCII hex"))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| malformed("pkt-line length is not hex"))?;
        match len {
            0..=2 => {
                // 0000 flush, 0001 delim, 0002 response-end: all section marks.
                frames.push(None);
                data = &data[4..];
            }
            3 => return Err(malformed("pkt-line length 3 is invalid")),
            _ => {
                if len > data.len() {
                    return Err(malformed("pkt-line runs past the end of the response"));
                }
                frames.push(Some(data[4..len].to_vec()));
                data = &data[len..];
            }
        }
    }
    Ok(frames)
}

/// Build the protocol-v2 fetch request body for one commit, trees only.
fn fetch_request_body(commit: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(b"command=fetch\n"));
    body.extend_from_slice(&pkt_line(b"object-format=sha1\n"));
    body.extend_from_slice(DELIM);
    body.extend_from_slice(&pkt_line(format!("want {commit}\n").as_bytes()));
    // blob:none keeps model blobs out; the LFS *pointers* are blobs too, so
    // they are also excluded here — they come over `/raw/` instead, where they
    // can be fetched per-path without dragging in every small file in the repo.
    body.extend_from_slice(&pkt_line(b"filter blob:none\n"));
    // History is irrelevant to the evidence chain; one commit deep.
    body.extend_from_slice(&pkt_line(b"deepen 1\n"));
    body.extend_from_slice(&pkt_line(b"no-progress\n"));
    body.extend_from_slice(&pkt_line(b"done\n"));
    body.extend_from_slice(FLUSH);
    body
}

/// Extract the packfile from a v2 fetch response.
///
/// The response is pkt-line framed: a `shallow-info` section, a delimiter, a
/// `packfile` header, then side-band frames — band 1 carries pack data, band 2
/// progress chatter, band 3 a fatal server error.
/// Demultiplex a `git-upload-pack` response down to the raw packfile.
///
/// Public so integration tests can run it against real captured responses.
pub fn extract_pack(response: &[u8]) -> Result<Vec<u8>, SourceError> {
    let frames = parse_pkt_lines(response)?;
    let mut pack = Vec::new();
    let mut in_packfile = false;
    let mut saw_header = false;

    for frame in frames.iter().flatten() {
        if frame.as_slice() == b"packfile\n" {
            in_packfile = true;
            saw_header = true;
            continue;
        }
        if !in_packfile {
            // shallow-info lines and acknowledgements; nothing to keep.
            continue;
        }
        match frame.first() {
            Some(1) => pack.extend_from_slice(&frame[1..]),
            Some(2) => {} // progress; ignored
            Some(3) => {
                return Err(SourceError::Malformed(format!(
                    "git server error: {}",
                    String::from_utf8_lossy(&frame[1..]).trim()
                )))
            }
            _ => return Err(malformed("non-side-band frame inside the packfile section")),
        }
    }

    if !saw_header {
        // The server may have answered with an ERR pkt instead.
        for frame in frames.iter().flatten() {
            if let Some(rest) = frame.strip_prefix(b"ERR ") {
                return Err(SourceError::Malformed(format!(
                    "git server refused: {}",
                    String::from_utf8_lossy(rest).trim()
                )));
            }
        }
        return Err(malformed("response contained no packfile section"));
    }
    if pack.is_empty() {
        return Err(malformed("packfile section was empty"));
    }
    Ok(pack)
}

/// The `User-Agent` sent on git-protocol requests.
///
/// ModelScope's edge rejects requests to `*.git/*` whose agent does not start
/// with `git/` — a bare tool name gets HTTP 421 — so the prefix is load-bearing
/// and must not be "tidied up". It is also accurate: on these requests this tool
/// really is a git client speaking protocol v2, and the suffix says which one.
/// REST requests keep the plain tool agent; only the git path claims to be git.
pub fn git_user_agent() -> String {
    format!(
        "git/2.43.0 (almanac-model-fetch/{})",
        env!("CARGO_PKG_VERSION")
    )
}

/// Fetch the commit object and all reachable trees at `commit`.
///
/// `repo_url` is the full smart-HTTP base for one repository — hosts disagree
/// about whether it ends in `.git`, so the caller supplies the whole thing
/// rather than this module reassembling per-host knowledge it should not hold.
///
/// Requires the server to support protocol v2 with `fetch` filters — verified
/// against the capability advertisement first so an unsupported server produces
/// a clear message rather than a confusing framing error.
pub async fn fetch_commit_and_trees(
    client: &reqwest::Client,
    repo_url: &str,
    commit: &str,
) -> Result<Vec<PackedObject>, SourceError> {
    let base = repo_url.trim_end_matches('/').to_string();

    // Step 1: capability advertisement.
    let advert_bytes = advertise(client, &base).await?;
    check_capabilities(&advert_bytes, "fetch", &["shallow", "filter"])?;

    // Step 2: the fetch itself.
    let body = post_command(&base, client, fetch_request_body(commit)).await?;

    let pack = extract_pack(&body)?;
    parse_pack(&pack)
}

/// Resolve refs to object ids over `ls-refs`.
///
/// This is how a host that publishes no branch→commit endpoint of its own
/// (ModelScope) still names its head commit in full: the answer comes from the
/// git server rather than from a REST field, and it is a complete 40-hex id
/// rather than an abbreviation we would have to hedge about.
pub async fn ls_refs(
    client: &reqwest::Client,
    repo_url: &str,
    prefixes: &[String],
) -> Result<Vec<RefEntry>, SourceError> {
    let base = repo_url.trim_end_matches('/').to_string();
    let advert_bytes = advertise(client, &base).await?;
    check_capabilities(&advert_bytes, "ls-refs", &[])?;

    let body = post_command(&base, client, ls_refs_request_body(prefixes)).await?;
    parse_ls_refs(&body)
}

/// One line of an `ls-refs` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub oid: String,
    pub name: String,
    /// For an annotated tag, the commit it ultimately points at.
    pub peeled: Option<String>,
}

impl RefEntry {
    /// The commit this ref designates: the peeled target for an annotated tag,
    /// otherwise the ref's own object.
    pub fn commit(&self) -> &str {
        self.peeled.as_deref().unwrap_or(&self.oid)
    }
}

pub(crate) fn ls_refs_request_body(prefixes: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(b"command=ls-refs\n"));
    body.extend_from_slice(&pkt_line(b"object-format=sha1\n"));
    body.extend_from_slice(DELIM);
    // `peel` so an annotated tag reports the commit it targets rather than the
    // tag object, which is not something we could walk a tree from.
    body.extend_from_slice(&pkt_line(b"peel\n"));
    for prefix in prefixes {
        body.extend_from_slice(&pkt_line(format!("ref-prefix {prefix}\n").as_bytes()));
    }
    body.extend_from_slice(FLUSH);
    body
}

pub(crate) fn parse_ls_refs(response: &[u8]) -> Result<Vec<RefEntry>, SourceError> {
    let frames = parse_pkt_lines(response)?;
    let mut refs = Vec::new();
    for frame in frames.iter().flatten() {
        let line = String::from_utf8_lossy(frame);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("ERR ") {
            return Err(SourceError::Malformed(format!(
                "git server refused ls-refs: {rest}"
            )));
        }
        let mut parts = line.split(' ');
        let (Some(oid), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !is_hex_oid(oid) {
            continue;
        }
        let peeled = parts
            .find_map(|attr| attr.strip_prefix("peeled:"))
            .filter(|p| is_hex_oid(p))
            .map(|p| p.to_string());
        refs.push(RefEntry {
            oid: oid.to_ascii_lowercase(),
            name: name.to_string(),
            peeled: peeled.map(|p| p.to_ascii_lowercase()),
        });
    }
    Ok(refs)
}

fn is_hex_oid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn advertise(client: &reqwest::Client, base: &str) -> Result<Vec<u8>, SourceError> {
    let refs_url = format!("{base}/info/refs?service=git-upload-pack");
    let advert = client
        .get(&refs_url)
        .header("User-Agent", git_user_agent())
        .header("Git-Protocol", "version=2")
        .send()
        .await
        .map_err(|e| transport(&refs_url, e))?;
    if !advert.status().is_success() {
        return Err(SourceError::Http {
            url: refs_url,
            status: advert.status().as_u16(),
        });
    }
    read_body_capped(advert, &refs_url, MAX_ADVERT_BYTES).await
}

async fn post_command(
    base: &str,
    client: &reqwest::Client,
    body: Vec<u8>,
) -> Result<Vec<u8>, SourceError> {
    let url = format!("{base}/git-upload-pack");
    let response = client
        .post(&url)
        .header("User-Agent", git_user_agent())
        .header("Git-Protocol", "version=2")
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Accept", "application/x-git-upload-pack-result")
        .body(body)
        .send()
        .await
        .map_err(|e| transport(&url, e))?;
    if !response.status().is_success() {
        return Err(SourceError::Http {
            url,
            status: response.status().as_u16(),
        });
    }
    read_body_capped(response, &url, MAX_FETCH_RESPONSE_BYTES).await
}

/// Confirm the server speaks v2 and advertises the command and features we need.
///
/// `command` must appear in the advertisement at all; each of `features` must
/// appear in that command's value (`fetch=shallow wait-for-done filter`).
fn check_capabilities(advert: &[u8], command: &str, features: &[&str]) -> Result<(), SourceError> {
    let frames = parse_pkt_lines(advert)?;
    let mut version2 = false;
    let mut caps: Option<String> = None;
    let prefix = format!("{command}=");

    for frame in frames.iter().flatten() {
        let line = String::from_utf8_lossy(frame);
        let line = line.trim();
        if line == "version 2" {
            version2 = true;
        }
        // A command with no features advertises as a bare word (`server-option`)
        // rather than `name=values`, so accept both spellings.
        if line == command {
            caps = Some(String::new());
        } else if let Some(values) = line.strip_prefix(&prefix) {
            caps = Some(values.to_string());
        }
    }

    if !version2 {
        return Err(SourceError::Unsupported(
            "the git server does not speak protocol v2; evidence capture needs it".into(),
        ));
    }
    let Some(caps) = caps else {
        return Err(SourceError::Unsupported(format!(
            "the git server does not advertise the {command} command; evidence capture needs it"
        )));
    };
    for needed in features {
        if !caps.split_whitespace().any(|c| c == *needed) {
            return Err(SourceError::Unsupported(format!(
                "the git server does not advertise {command}={needed}; evidence capture needs it"
            )));
        }
    }
    Ok(())
}

fn malformed(msg: &str) -> SourceError {
    SourceError::Malformed(format!("git protocol: {msg}"))
}

fn transport(url: &str, e: reqwest::Error) -> SourceError {
    SourceError::Transport {
        host: url.to_string(),
        source: e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_line_round_trips() {
        let encoded = pkt_line(b"command=fetch\n");
        assert_eq!(&encoded[..4], b"0012");
        let frames = parse_pkt_lines(&encoded).unwrap();
        assert_eq!(frames, vec![Some(b"command=fetch\n".to_vec())]);
    }

    #[test]
    fn parses_flush_and_delim_markers() {
        let mut data = Vec::new();
        data.extend_from_slice(&pkt_line(b"a"));
        data.extend_from_slice(DELIM);
        data.extend_from_slice(&pkt_line(b"b"));
        data.extend_from_slice(FLUSH);
        let frames = parse_pkt_lines(&data).unwrap();
        assert_eq!(frames.len(), 4);
        assert!(frames[1].is_none());
        assert!(frames[3].is_none());
    }

    #[test]
    fn rejects_torn_pkt_lines() {
        assert!(parse_pkt_lines(b"00").is_err());
        assert!(parse_pkt_lines(b"00ff too short").is_err());
        assert!(parse_pkt_lines(b"zzzz").is_err());
        assert!(parse_pkt_lines(b"0003").is_err());
    }

    #[test]
    fn fetch_request_contains_the_essentials() {
        let body = fetch_request_body("a6adef13");
        let text = String::from_utf8_lossy(&body);
        for needle in [
            "command=fetch",
            "want a6adef13",
            "filter blob:none",
            "deepen 1",
            "done",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in {text}");
        }
    }

    #[test]
    fn extracts_a_pack_from_side_band_frames() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&pkt_line(b"shallow-info\n"));
        resp.extend_from_slice(&pkt_line(b"shallow abc"));
        resp.extend_from_slice(DELIM);
        resp.extend_from_slice(&pkt_line(b"packfile\n"));
        resp.extend_from_slice(&pkt_line(&[&[1u8][..], b"PACKDATA1"].concat()));
        resp.extend_from_slice(&pkt_line(&[&[2u8][..], b"progress noise"].concat()));
        resp.extend_from_slice(&pkt_line(&[&[1u8][..], b"PACKDATA2"].concat()));
        resp.extend_from_slice(FLUSH);

        let pack = extract_pack(&resp).unwrap();
        assert_eq!(pack, b"PACKDATA1PACKDATA2");
    }

    #[test]
    fn a_band3_error_is_surfaced_with_its_message() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&pkt_line(b"packfile\n"));
        resp.extend_from_slice(&pkt_line(&[&[3u8][..], b"access denied"].concat()));
        let err = extract_pack(&resp).unwrap_err().to_string();
        assert!(err.contains("access denied"), "{err}");
    }

    #[test]
    fn an_err_pkt_is_surfaced() {
        let resp = pkt_line(b"ERR upload-pack: not our ref");
        let err = extract_pack(&resp).unwrap_err().to_string();
        assert!(err.contains("not our ref"), "{err}");
    }

    #[test]
    fn a_response_with_no_pack_is_an_error() {
        let resp = pkt_line(b"shallow-info\n");
        assert!(extract_pack(&resp).is_err());
    }

    #[test]
    fn accepts_the_real_hf_capability_advertisement() {
        // Captured from huggingface.co.
        let mut advert = Vec::new();
        advert.extend_from_slice(&pkt_line(b"# service=git-upload-pack\n"));
        advert.extend_from_slice(FLUSH);
        advert.extend_from_slice(&pkt_line(b"version 2\n"));
        advert.extend_from_slice(&pkt_line(b"agent=git/2.53.0\n"));
        advert.extend_from_slice(&pkt_line(b"ls-refs=unborn\n"));
        advert.extend_from_slice(&pkt_line(b"fetch=shallow wait-for-done filter\n"));
        advert.extend_from_slice(&pkt_line(b"server-option\n"));
        advert.extend_from_slice(&pkt_line(b"object-format=sha1\n"));
        advert.extend_from_slice(FLUSH);
        assert!(check_capabilities(&advert, "fetch", &["shallow", "filter"]).is_ok());
        assert!(check_capabilities(&advert, "ls-refs", &[]).is_ok());
    }

    #[test]
    fn rejects_a_v0_only_server() {
        let mut advert = Vec::new();
        advert.extend_from_slice(&pkt_line(b"# service=git-upload-pack\n"));
        advert.extend_from_slice(FLUSH);
        advert.extend_from_slice(&pkt_line(b"abc123 HEAD\0multi_ack side-band-64k\n"));
        advert.extend_from_slice(FLUSH);
        let err = check_capabilities(&advert, "fetch", &["shallow", "filter"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("protocol v2"), "{err}");
    }

    #[test]
    fn rejects_a_server_that_cannot_list_refs() {
        let mut advert = Vec::new();
        advert.extend_from_slice(&pkt_line(b"version 2\n"));
        advert.extend_from_slice(&pkt_line(b"fetch=shallow filter\n"));
        advert.extend_from_slice(FLUSH);
        let err = check_capabilities(&advert, "ls-refs", &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("ls-refs"), "{err}");
    }

    #[test]
    fn parses_an_ls_refs_response() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&pkt_line(
            b"baaddd6fb19e702c1d54c5bb2a5746012c122619 HEAD symref-target:refs/heads/master\n",
        ));
        resp.extend_from_slice(&pkt_line(
            b"baaddd6fb19e702c1d54c5bb2a5746012c122619 refs/heads/master\n",
        ));
        resp.extend_from_slice(&pkt_line(
            b"1111111111111111111111111111111111111111 refs/tags/v1 \
              peeled:2222222222222222222222222222222222222222\n",
        ));
        resp.extend_from_slice(FLUSH);

        let refs = parse_ls_refs(&resp).unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[1].name, "refs/heads/master");
        assert_eq!(refs[1].commit(), "baaddd6fb19e702c1d54c5bb2a5746012c122619");
        // An annotated tag must report the commit it targets, not the tag object:
        // the tag object is not something a tree walk can start from.
        assert_eq!(refs[2].commit(), "2222222222222222222222222222222222222222");
    }

    #[test]
    fn ls_refs_surfaces_a_server_error() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&pkt_line(b"ERR upload-pack: not our ref\n"));
        resp.extend_from_slice(FLUSH);
        let err = parse_ls_refs(&resp).unwrap_err().to_string();
        assert!(err.contains("not our ref"), "{err}");
    }

    #[test]
    fn ls_refs_ignores_lines_that_are_not_refs() {
        // Never let a non-oid first token become something we might treat as a
        // commit id downstream.
        let mut resp = Vec::new();
        resp.extend_from_slice(&pkt_line(b"unborn HEAD symref-target:refs/heads/main\n"));
        resp.extend_from_slice(&pkt_line(b"short refs/heads/x\n"));
        resp.extend_from_slice(FLUSH);
        assert!(parse_ls_refs(&resp).unwrap().is_empty());
    }

    #[test]
    fn ls_refs_body_is_well_formed() {
        let body = ls_refs_request_body(&["refs/heads/master".to_string()]);
        let frames = parse_pkt_lines(&body).unwrap();
        let payloads: Vec<String> = frames
            .iter()
            .flatten()
            .map(|f| String::from_utf8_lossy(f).trim().to_string())
            .collect();
        assert_eq!(payloads[0], "command=ls-refs");
        assert!(payloads.contains(&"peel".to_string()));
        assert!(payloads.contains(&"ref-prefix refs/heads/master".to_string()));
    }

    #[test]
    fn the_git_user_agent_keeps_its_git_prefix() {
        // ModelScope's edge returns 421 without it; this is a wire requirement,
        // not cosmetics.
        assert!(git_user_agent().starts_with("git/"), "{}", git_user_agent());
        assert!(git_user_agent().contains("almanac-model-fetch"));
    }

    #[test]
    fn rejects_a_server_without_filter_support() {
        let mut advert = Vec::new();
        advert.extend_from_slice(&pkt_line(b"version 2\n"));
        advert.extend_from_slice(&pkt_line(b"fetch=shallow\n"));
        advert.extend_from_slice(FLUSH);
        let err = check_capabilities(&advert, "fetch", &["shallow", "filter"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("filter"), "{err}");
    }
}
