//! The bundle manifest — the signed root of a bundle.
//!
//! `manifest.json` commits to every file's SHA256 and to all captured upstream
//! evidence, so a single signature over this file transitively covers the whole
//! bundle. That is what lets the airgapped importer check one signature instead
//! of trusting a directory tree.
//!
//! Every verification status in here is deliberately explicit about what was
//! *not* established. A field that said only "verified: true" would force a
//! reader to guess whether an absent C2PA manifest meant "upstream has none" or
//! "this tool never looked", and those are very different facts.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub tool: Tool,
    pub source: SourceRecord,
    pub variant: String,
    pub files: Vec<FileEntry>,
    /// SHA256 over the sorted `(path, sha256, size)` triples of `files`.
    pub bundle_digest: String,
    /// RFC3339 UTC.
    pub fetched_at: String,
    pub verification: Verification,
    pub corroboration: Corroboration,
    pub c2pa: C2paRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

impl Default for Tool {
    fn default() -> Self {
        Self {
            name: "almanac-model-fetch".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    /// `huggingface` or `modelscope`.
    pub host: String,
    pub repo: String,
    /// The immutable commit this bundle was built from.
    pub commit: String,
    /// What the operator asked for — `main`, a tag, or a SHA.
    pub requested_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the bundle's `model/` directory.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// The three-tier verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// Tier 1 — content-hash chain.
    pub content_hash: ContentHashStatus,
    /// Tier 2 — upstream commit signature.
    pub upstream_signature: SignatureStatus,
    /// Tier 3 is the detached signature file alongside this manifest; its
    /// presence is a fact about the bundle rather than a claim inside it, so it
    /// is deliberately not recorded here. A manifest cannot vouch for its own
    /// signature.
    pub evidence_captured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ContentHashStatus {
    /// Every file was streamed and verified against the upstream hash.
    Verified {
        /// Where the expected hash came from: `lfs_pointer` (inside the signed
        /// tree) is stronger than `rest_api` (asserted over TLS only).
        via: String,
    },
    /// Some file had no upstream hash to check against.
    Partial { unverified_files: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Signature present and checked against a pinned key.
    Verified { fingerprint: String },
    /// Signature present, but we hold no trusted key to check it against, so no
    /// authenticity claim is made. HuggingFace does not publish its signing key.
    SignaturePresentKeyUnpinned { fingerprint: Option<String> },
    /// Signature present and it did *not* match the pinned key. Serious.
    SignaturePresentKeyMismatch {
        expected_fingerprint: String,
        actual_fingerprint: Option<String>,
    },
    /// The host does not sign commits at all — ModelScope's normal state.
    Unsigned { reason: String },
}

impl SignatureStatus {
    /// Whether this status represents a genuinely verified upstream signature.
    ///
    /// Only `Verified` counts. This exists so no caller can accidentally treat
    /// "a signature exists" as "a signature checked out".
    pub fn is_verified(&self) -> bool {
        matches!(self, SignatureStatus::Verified { .. })
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self, SignatureStatus::SignaturePresentKeyMismatch { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Corroboration {
    /// The counterpart host published the same hash.
    Match { host: String, sha256: String },
    /// The counterpart host published a *different* hash. Serious.
    Mismatch {
        host: String,
        ours: String,
        theirs: String,
    },
    /// Could not check — usually because the other host is unreachable, which is
    /// the expected case for an operator who chose ModelScope precisely because
    /// HuggingFace is blocked.
    Unavailable { host: String, reason: String },
    /// Not attempted (`--no-corroborate`).
    Skipped,
}

/// What we found when looking for C2PA provenance.
///
/// As of this tool's development no Unsloth GGUF repo shipped a C2PA manifest,
/// in any of the three places checked. Recording the absence structurally — with
/// the list of places searched — lets a downstream reader tell "upstream has
/// none" from "an older tool did not look", which a bare `null` could not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum C2paRecord {
    Present { path: String, sha256: String },
    Absent { searched: Vec<String> },
}

impl Manifest {
    /// Serialise deterministically.
    ///
    /// The signature is computed over exactly these bytes, and verification
    /// re-reads the file rather than re-serialising, so byte-stability across
    /// runs is what keeps a signature checkable. Struct field order is fixed by
    /// the type, and `serde_json` preserves it, so pretty-printing is stable.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Total size of the model files.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Compute the digest that content-addresses a bundle.
///
/// Sorted so the digest does not depend on listing order, and length-delimited
/// so that a path containing the separator cannot be crafted to collide with a
/// different file set.
pub fn compute_bundle_digest(files: &[FileEntry]) -> String {
    use sha2::{Digest, Sha256};

    let mut sorted: Vec<&FileEntry> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));

    let mut hasher = Sha256::new();
    for f in sorted {
        hasher.update(f.path.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(f.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(f.sha256.to_ascii_lowercase().as_bytes());
        hasher.update(b"\0");
        hasher.update(f.size.to_string().as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, sha: &str, size: u64) -> FileEntry {
        FileEntry {
            path: path.into(),
            sha256: sha.into(),
            size,
        }
    }

    fn sample() -> Manifest {
        let files = vec![entry("model.gguf", &"a".repeat(64), 100)];
        Manifest {
            schema_version: SCHEMA_VERSION,
            tool: Tool::default(),
            source: SourceRecord {
                host: "huggingface".into(),
                repo: "unsloth/Qwen3-8B-GGUF".into(),
                commit: "a6adef130ffb23ddaf1a62fec9dced968c9bc482".into(),
                requested_revision: "main".into(),
            },
            variant: "Q4_K_M".into(),
            bundle_digest: compute_bundle_digest(&files),
            files,
            fetched_at: "2026-08-08T12:00:00Z".into(),
            verification: Verification {
                content_hash: ContentHashStatus::Verified {
                    via: "lfs_pointer".into(),
                },
                upstream_signature: SignatureStatus::SignaturePresentKeyUnpinned {
                    fingerprint: None,
                },
                evidence_captured: true,
            },
            corroboration: Corroboration::Skipped,
            c2pa: C2paRecord::Absent {
                searched: vec!["sidecar".into(), "gguf_kv".into(), "jumbf_box".into()],
            },
        }
    }

    #[test]
    fn round_trips_through_json() {
        let m = sample();
        let bytes = m.to_canonical_json().unwrap();
        assert_eq!(Manifest::from_json(&bytes).unwrap(), m);
    }

    #[test]
    fn serialisation_is_byte_stable() {
        // The signature is over these bytes; instability would break it.
        let m = sample();
        assert_eq!(
            m.to_canonical_json().unwrap(),
            m.to_canonical_json().unwrap()
        );
    }

    #[test]
    fn digest_is_order_independent() {
        let a = vec![
            entry("b.gguf", &"b".repeat(64), 2),
            entry("a.gguf", &"a".repeat(64), 1),
        ];
        let b = vec![
            entry("a.gguf", &"a".repeat(64), 1),
            entry("b.gguf", &"b".repeat(64), 2),
        ];
        assert_eq!(compute_bundle_digest(&a), compute_bundle_digest(&b));
    }

    #[test]
    fn digest_changes_with_any_field() {
        let base = vec![entry("a.gguf", &"a".repeat(64), 1)];
        let d = compute_bundle_digest(&base);
        assert_ne!(d, compute_bundle_digest(&[entry("b.gguf", &"a".repeat(64), 1)]));
        assert_ne!(d, compute_bundle_digest(&[entry("a.gguf", &"c".repeat(64), 1)]));
        assert_ne!(d, compute_bundle_digest(&[entry("a.gguf", &"a".repeat(64), 2)]));
    }

    #[test]
    fn digest_resists_separator_collisions() {
        // Without length-delimiting, "a\0b" as one path could collide with two
        // files named "a" and "b".
        let one = vec![entry("a\0b.gguf", &"a".repeat(64), 1)];
        let two = vec![
            entry("a", &"a".repeat(64), 1),
            entry("b.gguf", &"a".repeat(64), 1),
        ];
        assert_ne!(compute_bundle_digest(&one), compute_bundle_digest(&two));
    }

    #[test]
    fn digest_is_case_insensitive_in_the_hash() {
        let lower = vec![entry("a.gguf", &"a".repeat(64), 1)];
        let upper = vec![entry("a.gguf", &"A".repeat(64), 1)];
        assert_eq!(compute_bundle_digest(&lower), compute_bundle_digest(&upper));
    }

    #[test]
    fn only_verified_counts_as_verified() {
        assert!(SignatureStatus::Verified {
            fingerprint: "ABC".into()
        }
        .is_verified());

        // The crucial negative: a present-but-unchecked signature is not
        // verification, and must never be reported as such.
        assert!(!SignatureStatus::SignaturePresentKeyUnpinned { fingerprint: None }.is_verified());
        assert!(!SignatureStatus::Unsigned {
            reason: "x".into()
        }
        .is_verified());

        let mismatch = SignatureStatus::SignaturePresentKeyMismatch {
            expected_fingerprint: "A".into(),
            actual_fingerprint: Some("B".into()),
        };
        assert!(!mismatch.is_verified());
        assert!(mismatch.is_mismatch());
    }

    #[test]
    fn c2pa_absence_records_where_we_looked() {
        let json = serde_json::to_string(&C2paRecord::Absent {
            searched: vec!["sidecar".into()],
        })
        .unwrap();
        assert!(json.contains("\"status\":\"absent\""), "{json}");
        assert!(json.contains("sidecar"), "{json}");
    }

    #[test]
    fn manifest_rejects_a_schema_it_does_not_know() {
        let m = sample();
        let mut value: serde_json::Value =
            serde_json::from_slice(&m.to_canonical_json().unwrap()).unwrap();
        value["verification"]["upstream_signature"]["status"] =
            serde_json::json!("some_future_status");
        // An unknown tagged variant must fail loudly rather than silently
        // deserialising into something weaker.
        assert!(Manifest::from_json(value.to_string().as_bytes()).is_err());
    }
}
