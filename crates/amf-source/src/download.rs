//! Streaming, resumable, verified downloads.

use std::path::Path;

use amf_verify::StreamingVerifier;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::SourceError;

/// Progress callback: `(bytes_done, bytes_total)`.
pub type ProgressFn<'a> = &'a (dyn Fn(u64, u64) + Send + Sync);

/// Outcome of a verified download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub sha256: String,
    pub bytes_written: u64,
    /// Bytes actually transferred over the network — smaller than
    /// `bytes_written` when a partial file was resumed.
    pub bytes_transferred: u64,
    pub resumed: bool,
}

/// Download `url` to `dest`, verifying against `expected_sha256` as it streams.
///
/// If `dest` already holds a partial file, the download resumes with an HTTP
/// Range request. The existing prefix is re-hashed first, so resumed bytes are
/// verified exactly as strictly as freshly downloaded ones — resuming on top of
/// unchecked data would let a corrupted or tampered partial file through under
/// cover of a hash that only covers the new portion.
pub async fn download_verified(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    expected_sha256: &str,
    expected_size: u64,
    progress: Option<ProgressFn<'_>>,
) -> Result<Downloaded, SourceError> {
    let mut verifier = StreamingVerifier::new(expected_sha256, expected_size);
    let mut resumed = false;

    if dest.exists() {
        match amf_verify::resume_from_file(dest, expected_sha256, expected_size) {
            Ok(v) if v.seen() > 0 && v.seen() < expected_size => {
                verifier = v;
                resumed = true;
            }
            Ok(v) if v.seen() == expected_size => {
                // Already complete: confirm the hash and skip the network.
                let sha256 = v.finish()?;
                return Ok(Downloaded {
                    sha256,
                    bytes_written: expected_size,
                    bytes_transferred: 0,
                    resumed: true,
                });
            }
            // A zero-length or oversized partial is not worth resuming from;
            // start clean rather than reasoning about a file we cannot trust.
            _ => {
                let _ = std::fs::remove_file(dest);
            }
        }
    }

    let start_offset = verifier.seen();
    let mut request = client.get(url);
    if start_offset > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={start_offset}-"));
    }

    let response = request.send().await.map_err(|e| SourceError::Transport {
        host: url.to_string(),
        source: e,
    })?;

    if !response.status().is_success() {
        return Err(SourceError::Http {
            url: url.to_string(),
            status: response.status().as_u16(),
        });
    }

    // A server may ignore Range and send the whole file with 200. Detect that
    // and restart from scratch, otherwise we would append a second copy of the
    // file onto the partial one.
    let served_range = response.status().as_u16() == 206;
    let mut file = if start_offset > 0 && served_range {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(dest)
            .await
            .map_err(|e| io_err(dest, e))?
    } else {
        if start_offset > 0 {
            // Range was ignored; discard what we had and re-verify from zero.
            verifier = StreamingVerifier::new(expected_sha256, expected_size);
            resumed = false;
        }
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| io_err(parent, e))?;
        }
        tokio::fs::File::create(dest)
            .await
            .map_err(|e| io_err(dest, e))?
    };

    let mut transferred = 0u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| SourceError::Transport {
            host: url.to_string(),
            source: e,
        })?;

        // Verify before writing. A chunk that overruns the expected size can
        // never produce a matching hash, so there is no reason to commit it to
        // the destination — this is what turns "download 40 GB then discover it
        // is wrong" into an abort at the first bad byte.
        verifier.update(&chunk)?;

        file.write_all(&chunk).await.map_err(|e| io_err(dest, e))?;
        transferred += chunk.len() as u64;

        if let Some(cb) = progress {
            cb(verifier.seen(), expected_size);
        }
    }

    file.flush().await.map_err(|e| io_err(dest, e))?;
    // fsync before declaring success: USB drives get pulled the moment the tool
    // says "done", and data still in the page cache does not survive that.
    file.sync_all().await.map_err(|e| io_err(dest, e))?;

    let sha256 = verifier.finish()?;

    Ok(Downloaded {
        sha256,
        bytes_written: expected_size,
        bytes_transferred: transferred,
        resumed,
    })
}

fn io_err(path: &Path, source: std::io::Error) -> SourceError {
    SourceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Build the download URL for a file at a pinned revision.
pub fn file_url(endpoint: &str, repo: &str, commit: &str, path: &str) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        endpoint.trim_end_matches('/'),
        repo,
        commit,
        path.split('/')
            .map(urlencode_segment)
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn urlencode_segment(s: &str) -> String {
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

    #[test]
    fn builds_a_resolve_url_at_a_pinned_commit() {
        let url = file_url(
            "https://huggingface.co",
            "unsloth/Qwen3-8B-GGUF",
            "a6adef13",
            "Qwen3-8B-Q4_K_M.gguf",
        );
        assert_eq!(
            url,
            "https://huggingface.co/unsloth/Qwen3-8B-GGUF/resolve/a6adef13/Qwen3-8B-Q4_K_M.gguf"
        );
    }

    #[test]
    fn keeps_directory_separators_but_encodes_within_segments() {
        let url = file_url(
            "https://huggingface.co",
            "u/r",
            "abc",
            "DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-UD-IQ1_S-00001-of-00003.gguf",
        );
        assert!(url.ends_with(
            "/resolve/abc/DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-UD-IQ1_S-00001-of-00003.gguf"
        ));
    }

    #[test]
    fn encodes_spaces_in_a_filename() {
        let url = file_url("https://h", "u/r", "c", "my model.gguf");
        assert!(url.ends_with("my%20model.gguf"), "{url}");
    }

    #[test]
    fn trims_a_trailing_slash_on_the_endpoint() {
        assert_eq!(
            file_url("https://h/", "u/r", "c", "f.gguf"),
            file_url("https://h", "u/r", "c", "f.gguf")
        );
    }
}
