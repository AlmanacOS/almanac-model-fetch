//! Git-LFS pointer parsing.
//!
//! A pointer is the small text blob that lives in the git tree in place of the
//! real file:
//!
//! ```text
//! version https://git-lfs.github.com/spec/v1
//! oid sha256:120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4
//! size 5027784512
//! ```
//!
//! This is the load-bearing link in the whole trust chain. The commit signature
//! covers the tree, the tree covers this blob, and this blob names the SHA256 we
//! verify the downloaded bytes against — so a correctly parsed pointer is what
//! connects a signature to the model file.

use crate::VerifyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsPointer {
    pub oid_sha256: String,
    pub size: u64,
}

/// The only pointer version we accept.
const SPEC_V1: &str = "https://git-lfs.github.com/spec/v1";

pub fn parse_pointer(raw: &[u8]) -> Result<LfsPointer, VerifyError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| VerifyError::MalformedPointer("pointer is not valid UTF-8".into()))?;

    let mut version = None;
    let mut oid = None;
    let mut size = None;

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "version" => version = Some(value.to_string()),
            "oid" => oid = Some(value.to_string()),
            "size" => size = Some(value.to_string()),
            _ => {}
        }
    }

    let version = version
        .ok_or_else(|| VerifyError::MalformedPointer("pointer has no version line".into()))?;
    if version != SPEC_V1 {
        // An unknown pointer version could mean a different hash algorithm, and
        // guessing would mean verifying against something other than what the
        // tree actually committed to.
        return Err(VerifyError::MalformedPointer(format!(
            "unsupported LFS pointer version {version:?}; expected {SPEC_V1:?}"
        )));
    }

    let oid = oid.ok_or_else(|| VerifyError::MalformedPointer("pointer has no oid".into()))?;
    let hash = oid.strip_prefix("sha256:").ok_or_else(|| {
        VerifyError::MalformedPointer(format!(
            "pointer oid {oid:?} is not sha256; refusing to guess the algorithm"
        ))
    })?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VerifyError::MalformedPointer(format!(
            "pointer oid {hash:?} is not a 64-character hex SHA256"
        )));
    }

    let size = size
        .ok_or_else(|| VerifyError::MalformedPointer("pointer has no size".into()))?
        .parse::<u64>()
        .map_err(|e| VerifyError::MalformedPointer(format!("pointer size is not a number: {e}")))?;

    Ok(LfsPointer {
        oid_sha256: hash.to_ascii_lowercase(),
        size,
    })
}

/// Whether a blob looks like an LFS pointer at all.
///
/// Pointers are tiny; anything large is the real file, which on a
/// `GIT_LFS_SKIP_SMUDGE` clone should never happen but is cheap to rule out.
pub fn looks_like_pointer(raw: &[u8]) -> bool {
    raw.len() <= 1024 && raw.starts_with(b"version https://git-lfs.github.com/spec/v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &[u8] = b"version https://git-lfs.github.com/spec/v1\noid sha256:120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4\nsize 5027784512\n";

    #[test]
    fn parses_a_real_pointer() {
        let p = parse_pointer(REAL).unwrap();
        assert_eq!(
            p.oid_sha256,
            "120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4"
        );
        assert_eq!(p.size, 5_027_784_512);
    }

    #[test]
    fn recognises_a_pointer_blob() {
        assert!(looks_like_pointer(REAL));
        assert!(!looks_like_pointer(b"GGUF\x03\x00\x00\x00"));
        assert!(!looks_like_pointer(&vec![b'x'; 4096]));
    }

    #[test]
    fn tolerates_crlf_and_trailing_whitespace() {
        let crlf = b"version https://git-lfs.github.com/spec/v1\r\noid sha256:120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4\r\nsize 5027784512\r\n";
        assert_eq!(parse_pointer(crlf).unwrap().size, 5_027_784_512);
    }

    #[test]
    fn rejects_a_non_sha256_oid() {
        // Refusing to guess is the point: verifying a SHA256 stream against an
        // MD5 pointer would be a silent downgrade.
        let p = b"version https://git-lfs.github.com/spec/v1\noid md5:abc\nsize 10\n";
        let err = parse_pointer(p).unwrap_err().to_string();
        assert!(err.contains("not sha256"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_spec_version() {
        let p = b"version https://git-lfs.github.com/spec/v2\noid sha256:120307ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4\nsize 10\n";
        assert!(parse_pointer(p).is_err());
    }

    #[test]
    fn rejects_a_malformed_hash() {
        for bad in [
            "oid sha256:tooshort",
            "oid sha256:zzz07ba529eb2439d6c430d94104dabd578497bc7bfe7e322b5d9933b449bd4",
        ] {
            let p = format!("version {SPEC_V1}\n{bad}\nsize 10\n");
            assert!(parse_pointer(p.as_bytes()).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn rejects_missing_fields() {
        for missing in [
            format!("version {SPEC_V1}\nsize 10\n"),
            format!("version {SPEC_V1}\noid sha256:{}\n", "a".repeat(64)),
            "oid sha256:abc\nsize 10\n".to_string(),
        ] {
            assert!(parse_pointer(missing.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_a_non_numeric_size() {
        let p = format!(
            "version {SPEC_V1}\noid sha256:{}\nsize huge\n",
            "a".repeat(64)
        );
        assert!(parse_pointer(p.as_bytes()).is_err());
    }
}
