//! Streaming SHA256 verification.

use sha2::{Digest, Sha256};

use crate::VerifyError;

/// Hashes a byte stream as it arrives and checks it against an expected digest.
///
/// The size check is what makes this abort *early*. A hash mismatch is only
/// provable once the last byte has arrived, but a stream that has already
/// exceeded the size upstream committed to can never match, so there is no
/// reason to keep writing it to a USB stick. That turns "download 40 GB, then
/// discover it is wrong" into "stop at the first byte past the limit".
#[derive(Debug)]
pub struct StreamingVerifier {
    hasher: Sha256,
    expected_sha256: String,
    expected_size: u64,
    seen: u64,
}

impl StreamingVerifier {
    pub fn new(expected_sha256: &str, expected_size: u64) -> Self {
        Self {
            hasher: Sha256::new(),
            expected_sha256: expected_sha256.to_ascii_lowercase(),
            expected_size,
            seen: 0,
        }
    }

    /// Bytes hashed so far — the resume offset.
    pub fn seen(&self) -> u64 {
        self.seen
    }

    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    /// Feed a chunk. Fails as soon as the stream runs past the expected size.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), VerifyError> {
        self.seen += chunk.len() as u64;
        if self.seen > self.expected_size {
            return Err(VerifyError::SizeOverrun {
                expected: self.expected_size,
                seen: self.seen,
            });
        }
        self.hasher.update(chunk);
        Ok(())
    }

    /// Finish and check both length and digest.
    pub fn finish(self) -> Result<String, VerifyError> {
        if self.seen != self.expected_size {
            return Err(VerifyError::SizeMismatch {
                expected: self.expected_size,
                actual: self.seen,
            });
        }
        let actual = hex::encode(self.hasher.finalize());
        if actual != self.expected_sha256 {
            return Err(VerifyError::HashMismatch {
                expected: self.expected_sha256,
                actual,
            });
        }
        Ok(actual)
    }
}

/// Hash a file already on disk, for resume and for `amf verify`.
///
/// A resumed download re-hashes the bytes already written rather than trusting
/// them: a partial file could have been corrupted, truncated, or tampered with
/// between runs, and resuming on top of unverified bytes would produce a bundle
/// whose hash check passes over data we never actually checked.
pub fn hash_file_prefix(
    path: &std::path::Path,
    limit: Option<u64>,
) -> Result<(Sha256, u64), VerifyError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| VerifyError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;

    loop {
        let cap = match limit {
            Some(l) if total >= l => break,
            Some(l) => ((l - total) as usize).min(buf.len()),
            None => buf.len(),
        };
        let n = file.read(&mut buf[..cap]).map_err(|e| VerifyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher, total))
}

/// Full-file SHA256, used by `amf verify` on the airgapped side.
pub fn hash_file(path: &std::path::Path) -> Result<String, VerifyError> {
    let (hasher, _) = hash_file_prefix(path, None)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Resume a verifier from bytes already on disk.
pub fn resume_from_file(
    path: &std::path::Path,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<StreamingVerifier, VerifyError> {
    // Check the file's real length before hashing anything. A partial file that
    // is *longer* than the target is not a valid prefix to resume from: hashing
    // only the first `expected_size` bytes would match, we would append nothing,
    // and the bundle would end up holding a file with trailing garbage that
    // nonetheless passed verification. Refuse and let the caller discard it.
    let actual_len = std::fs::metadata(path)
        .map_err(|e| VerifyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?
        .len();
    if actual_len > expected_size {
        return Err(VerifyError::SizeOverrun {
            expected: expected_size,
            seen: actual_len,
        });
    }

    let (hasher, seen) = hash_file_prefix(path, Some(expected_size))?;
    Ok(StreamingVerifier {
        hasher,
        expected_sha256: expected_sha256.to_ascii_lowercase(),
        expected_size,
        seen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha256("hello world")
    const HELLO: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn accepts_a_matching_stream() {
        let mut v = StreamingVerifier::new(HELLO, 11);
        v.update(b"hello ").unwrap();
        v.update(b"world").unwrap();
        assert_eq!(v.finish().unwrap(), HELLO);
    }

    #[test]
    fn accepts_an_uppercase_expected_hash() {
        let mut v = StreamingVerifier::new(&HELLO.to_uppercase(), 11);
        v.update(b"hello world").unwrap();
        assert!(v.finish().is_ok());
    }

    #[test]
    fn rejects_altered_content_of_the_same_length() {
        // The substitution attack the hash exists to catch.
        let mut v = StreamingVerifier::new(HELLO, 11);
        v.update(b"hello w0rld").unwrap();
        match v.finish() {
            Err(VerifyError::HashMismatch { .. }) => {}
            other => panic!("expected a hash mismatch, got {other:?}"),
        }
    }

    #[test]
    fn aborts_early_when_the_stream_runs_long() {
        // Must fail on the overrunning chunk, not at finish().
        let mut v = StreamingVerifier::new(HELLO, 11);
        v.update(b"hello ").unwrap();
        let err = v.update(b"world and then some").unwrap_err();
        match err {
            VerifyError::SizeOverrun { expected, seen } => {
                assert_eq!(expected, 11);
                assert_eq!(seen, 25);
            }
            other => panic!("expected a size overrun, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_truncated_stream() {
        let mut v = StreamingVerifier::new(HELLO, 11);
        v.update(b"hello").unwrap();
        match v.finish() {
            Err(VerifyError::SizeMismatch { expected, actual }) => {
                assert_eq!((expected, actual), (11, 5));
            }
            other => panic!("expected a size mismatch, got {other:?}"),
        }
    }

    #[test]
    fn empty_stream_against_empty_expectation() {
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let v = StreamingVerifier::new(empty, 0);
        assert!(v.finish().is_ok());
    }

    #[test]
    fn hashes_and_resumes_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part");
        std::fs::write(&path, b"hello ").unwrap();

        assert_eq!(
            hash_file(&path).unwrap(),
            "5e3235a8346e5a4585f8c58562f5052b8fe26a3bb122e1e96c76784964dfc461",
            "sanity: hashing the partial file itself"
        );

        let mut v = resume_from_file(&path, HELLO, 11).unwrap();
        assert_eq!(v.seen(), 6, "should resume after the existing bytes");
        v.update(b"world").unwrap();
        assert_eq!(v.finish().unwrap(), HELLO);
    }

    #[test]
    fn resuming_over_a_corrupted_prefix_is_caught() {
        // The prefix on disk is the right length but the wrong bytes. Resuming
        // must not paper over that.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part");
        std::fs::write(&path, b"HELLO ").unwrap();

        let mut v = resume_from_file(&path, HELLO, 11).unwrap();
        v.update(b"world").unwrap();
        assert!(matches!(
            v.finish(),
            Err(VerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn resuming_from_an_overlong_file_is_refused() {
        // The nasty case: the first 11 bytes are correct, so hashing a prefix
        // would happily match and we would append nothing — leaving a file with
        // trailing garbage that passed verification. It must be refused outright.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part");
        std::fs::write(&path, b"hello world and more").unwrap();

        match resume_from_file(&path, HELLO, 11) {
            Err(VerifyError::SizeOverrun { expected, seen }) => {
                assert_eq!((expected, seen), (11, 20));
            }
            other => panic!("expected a size overrun, got {other:?}"),
        }
    }

    #[test]
    fn resuming_from_an_exactly_complete_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part");
        std::fs::write(&path, b"hello world").unwrap();

        let v = resume_from_file(&path, HELLO, 11).unwrap();
        assert_eq!(v.seen(), 11, "nothing left to download");
        assert!(v.finish().is_ok());
    }
}
