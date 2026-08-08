//! Minimal git object parsing, enough to re-derive an evidence chain offline.
//!
//! We deliberately do not depend on a full git implementation. The airgapped
//! verifier needs to do exactly three things — confirm an object's identity,
//! walk a path through trees, and pull the signature off a commit — and a
//! few hundred lines that do only that are far easier to audit than a general
//! git library, which matters when this code is the thing standing between an
//! operator and a tampered model.

use sha1::{Digest, Sha1};

use crate::VerifyError;

/// A git object's type, as it appears in the object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tree,
    Blob,
}

impl ObjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Commit => "commit",
            ObjectKind::Tree => "tree",
            ObjectKind::Blob => "blob",
        }
    }
}

/// Compute a git object id over raw (uncompressed, header-less) content.
///
/// Git hashes `"<type> <length>\0<content>"`, so the identity of an object is
/// bound to its type and length as well as its bytes. That framing is what stops
/// a tree from being reinterpreted as a blob of the same bytes.
///
/// Git object ids are SHA-1, which is broken against chosen-prefix collision
/// attacks — so these links are the weakest part of the evidence chain, and the
/// model bytes themselves are deliberately never protected by them: the final
/// content check is always the LFS pointer's SHA-256, cross-checked against the
/// REST API's independently served hash. A future hardening is a
/// collision-detecting SHA-1 (`sha1collisiondetection`) here.
pub fn object_id(kind: ObjectKind, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Check that content really is the object it claims to be.
pub fn verify_object_id(
    kind: ObjectKind,
    content: &[u8],
    expected_oid: &str,
) -> Result<(), VerifyError> {
    let actual = object_id(kind, content);
    if actual.eq_ignore_ascii_case(expected_oid) {
        Ok(())
    } else {
        Err(VerifyError::ObjectIdMismatch {
            kind: kind.as_str(),
            expected: expected_oid.to_ascii_lowercase(),
            actual,
        })
    }
}

/// A parsed commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: String,
    pub parents: Vec<String>,
    pub author: String,
    pub committer: String,
    /// The armored OpenPGP signature, if the commit is signed.
    pub gpgsig: Option<String>,
    pub message: String,
}

impl Commit {
    pub fn is_signed(&self) -> bool {
        self.gpgsig.is_some()
    }

    /// Reconstruct the exact bytes the signature was computed over.
    ///
    /// Git signs the commit object with the `gpgsig` header removed — the
    /// signature cannot cover itself. Verifying a commit signature therefore
    /// means re-serialising the commit *without* that header, byte for byte, and
    /// checking the signature against the result. Any deviation here, including
    /// header ordering or a stray newline, makes a valid signature look invalid.
    pub fn signed_payload(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len());
        let mut rest = raw;
        let mut in_gpgsig = false;
        let mut past_headers = false;

        while !rest.is_empty() {
            let (line, remainder) = split_line(rest);
            rest = remainder;

            if past_headers {
                out.extend_from_slice(line);
                continue;
            }
            if line == b"\n" || line.is_empty() {
                // Blank line ends the header block.
                past_headers = true;
                out.extend_from_slice(line);
                continue;
            }
            if in_gpgsig {
                // Continuation lines of a folded header begin with a space.
                if line.starts_with(b" ") {
                    continue;
                }
                in_gpgsig = false;
            }
            if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
                in_gpgsig = true;
                continue;
            }
            out.extend_from_slice(line);
        }
        out
    }
}

fn split_line(input: &[u8]) -> (&[u8], &[u8]) {
    match input.iter().position(|&b| b == b'\n') {
        Some(i) => (&input[..=i], &input[i + 1..]),
        None => (input, &[][..]),
    }
}

/// Parse a raw commit object.
pub fn parse_commit(raw: &[u8]) -> Result<Commit, VerifyError> {
    let text_end = find_header_end(raw);
    let headers = &raw[..text_end];
    let message = String::from_utf8_lossy(&raw[text_end..]).into_owned();

    let mut tree = None;
    let mut parents = Vec::new();
    let mut author = String::new();
    let mut committer = String::new();
    let mut gpgsig: Option<String> = None;

    let mut rest = headers;
    let mut current_sig: Option<String> = None;

    while !rest.is_empty() {
        let (line_bytes, remainder) = split_line(rest);
        rest = remainder;
        let line = String::from_utf8_lossy(line_bytes);
        let line = line.strip_suffix('\n').unwrap_or(&line);

        if let Some(cont) = line.strip_prefix(' ') {
            // Folded continuation of the signature header.
            if let Some(sig) = current_sig.as_mut() {
                sig.push('\n');
                sig.push_str(cont);
            }
            continue;
        }
        // A non-continuation line ends any folded header.
        if let Some(sig) = current_sig.take() {
            gpgsig = Some(sig);
        }

        if let Some(v) = line.strip_prefix("tree ") {
            tree = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("parent ") {
            parents.push(v.to_string());
        } else if let Some(v) = line.strip_prefix("author ") {
            author = v.to_string();
        } else if let Some(v) = line.strip_prefix("committer ") {
            committer = v.to_string();
        } else if let Some(v) = line.strip_prefix("gpgsig ") {
            current_sig = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("gpgsig-sha256 ") {
            current_sig = Some(v.to_string());
        }
    }
    if let Some(sig) = current_sig.take() {
        gpgsig = Some(sig);
    }

    let tree = tree.ok_or_else(|| {
        VerifyError::MalformedObject("commit object has no \"tree\" header".into())
    })?;

    Ok(Commit {
        tree,
        parents,
        author,
        committer,
        gpgsig,
        message,
    })
}

/// Byte offset just past the header block (i.e. past the blank line).
fn find_header_end(raw: &[u8]) -> usize {
    let mut rest = raw;
    let mut offset = 0;
    while !rest.is_empty() {
        let (line, remainder) = split_line(rest);
        if line == b"\n" {
            return offset + line.len();
        }
        offset += line.len();
        rest = remainder;
    }
    offset
}

/// One entry in a git tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid: String,
}

impl TreeEntry {
    pub fn is_dir(&self) -> bool {
        self.mode == "40000" || self.mode == "040000"
    }
}

/// Parse a raw tree object.
///
/// Trees are binary: repeated `<octal mode> <name>\0<20-byte oid>`.
pub fn parse_tree(raw: &[u8]) -> Result<Vec<TreeEntry>, VerifyError> {
    let mut entries = Vec::new();
    let mut i = 0;

    while i < raw.len() {
        let space = raw[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| VerifyError::MalformedObject("tree entry has no mode".into()))?;
        let mode = String::from_utf8_lossy(&raw[i..i + space]).into_owned();
        i += space + 1;

        let nul = raw[i..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VerifyError::MalformedObject("tree entry name is unterminated".into()))?;
        let name = String::from_utf8_lossy(&raw[i..i + nul]).into_owned();
        i += nul + 1;

        if i + 20 > raw.len() {
            return Err(VerifyError::MalformedObject(
                "tree entry is truncated before its object id".into(),
            ));
        }
        let oid = hex::encode(&raw[i..i + 20]);
        i += 20;

        entries.push(TreeEntry { mode, name, oid });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"tree 116f6efcc6377fce0d8d0917bc15c3126dcec5b9\n");
        v.extend_from_slice(b"parent 672575d5a4634e1c6f2a12b5a05e18f5a86f227f\n");
        v.extend_from_slice(b"author A <a@example.com> 1749370140 +0000\n");
        v.extend_from_slice(b"committer system <system@huggingface.co> 1749370140 +0000\n");
        v.extend_from_slice(b"gpgsig -----BEGIN PGP SIGNATURE-----\n");
        v.extend_from_slice(b" \n");
        v.extend_from_slice(b" wsFzBAEBCAAnBQJoRUUc\n");
        v.extend_from_slice(b" -----END PGP SIGNATURE-----\n");
        v.extend_from_slice(b"\n");
        v.extend_from_slice(b"Update params\n");
        v
    }

    #[test]
    fn computes_a_known_git_object_id() {
        // The canonical example: the empty blob's well-known SHA1.
        assert_eq!(
            object_id(ObjectKind::Blob, b""),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        // "what is up, doc?" as a blob, from the Pro Git book.
        assert_eq!(
            object_id(ObjectKind::Blob, b"what is up, doc?"),
            "bd9dbf5aae1a3862dd1526723246b20206e5fc37"
        );
    }

    #[test]
    fn object_id_is_bound_to_the_type() {
        // Same bytes, different type, different id — the framing matters.
        assert_ne!(
            object_id(ObjectKind::Blob, b""),
            object_id(ObjectKind::Tree, b"")
        );
    }

    #[test]
    fn verify_object_id_accepts_and_rejects() {
        assert!(verify_object_id(
            ObjectKind::Blob,
            b"",
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        )
        .is_ok());
        assert!(verify_object_id(ObjectKind::Blob, b"tampered", "e69de29b").is_err());
    }

    #[test]
    fn parses_a_signed_commit() {
        let c = parse_commit(&commit_bytes()).unwrap();
        assert_eq!(c.tree, "116f6efcc6377fce0d8d0917bc15c3126dcec5b9");
        assert_eq!(c.parents, vec!["672575d5a4634e1c6f2a12b5a05e18f5a86f227f"]);
        assert!(c.committer.contains("system@huggingface.co"));
        assert!(c.is_signed());

        let sig = c.gpgsig.unwrap();
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(sig.ends_with("-----END PGP SIGNATURE-----"));
        assert_eq!(c.message, "Update params\n");
    }

    #[test]
    fn signed_payload_removes_only_the_signature_header() {
        let raw = commit_bytes();
        let payload = Commit::signed_payload(&raw);
        let text = String::from_utf8(payload).unwrap();

        assert!(!text.contains("gpgsig"), "signature header must be stripped");
        assert!(!text.contains("BEGIN PGP"), "and its continuations too");
        assert!(text.contains("tree 116f6efc"));
        assert!(text.contains("parent 672575d5"));
        assert!(text.contains("committer system"));
        assert!(
            text.ends_with("\nUpdate params\n"),
            "message must survive intact: {text:?}"
        );
    }

    #[test]
    fn an_unsigned_commit_parses_with_no_signature() {
        let raw = b"tree abc\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nmsg\n";
        let c = parse_commit(raw).unwrap();
        assert!(!c.is_signed());
        // With no gpgsig header, the payload is the commit unchanged.
        assert_eq!(Commit::signed_payload(raw), raw.to_vec());
    }

    #[test]
    fn a_commit_without_a_tree_is_rejected() {
        assert!(parse_commit(b"author A <a@x> 1 +0000\n\nmsg\n").is_err());
    }

    #[test]
    fn parses_a_tree() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"100644 README.md\0");
        raw.extend_from_slice(&[0xab; 20]);
        raw.extend_from_slice(b"40000 subdir\0");
        raw.extend_from_slice(&[0xcd; 20]);

        let entries = parse_tree(&raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "README.md");
        assert_eq!(entries[0].mode, "100644");
        assert_eq!(entries[0].oid, "ab".repeat(20));
        assert!(!entries[0].is_dir());
        assert!(entries[1].is_dir());
    }

    #[test]
    fn rejects_a_truncated_tree() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"100644 README.md\0");
        raw.extend_from_slice(&[0xab; 10]); // short oid
        assert!(parse_tree(&raw).is_err());
    }

    #[test]
    fn empty_tree_parses_to_nothing() {
        assert!(parse_tree(b"").unwrap().is_empty());
    }
}
