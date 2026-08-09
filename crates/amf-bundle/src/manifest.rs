//! The bundle manifest — the signed root of a bundle.
//!
//! `manifest.json` commits to every file's SHA256 and to all captured upstream
//! evidence, so a single signature over this file transitively covers the whole
//! bundle. That is what lets the airgapped importer check one signature instead
//! of trusting a directory tree.
//!
//! Every verification status in here is deliberately explicit about what was
//! *not* established. A field that said only "verified: true" would force a
//! reader to guess whether a signature was checked or merely present, and those
//! are very different facts.

use serde::{Deserialize, Serialize};

/// Schema of the manifest this build writes.
///
/// Bumped to 2 when `evidence_captured`/`chain_rederivable` became the single
/// [`EvidenceKind`] field. Nothing had been released at 1, so no migration
/// exists — but a version-1 bundle still deserves to be told what is wrong with
/// it rather than a missing-field error, which is what [`Manifest::ensure_supported_schema`]
/// is for.
pub const SCHEMA_VERSION: u32 = 2;

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
    /// Digests of everything under `evidence/`, so the bundle signature covers
    /// the evidence transitively just as it covers the model files. Empty in
    /// bundles written before evidence capture existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_files: Vec<FileEntry>,
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
    /// Whether `commit` is a full object id or only a prefix.
    ///
    /// Defaults to `commit` for bundles written before ModelScope existed: every
    /// one of those came from HuggingFace, which always resolves a full id. The
    /// value is redundant with `commit`'s own length on purpose — `amf verify`
    /// cross-checks the two, so a manifest claiming exactness for a short id is
    /// caught rather than believed.
    #[serde(default)]
    pub revision_precision: RevisionPrecision,
}

/// How precisely the revision could be pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionPrecision {
    /// A full 40-hex object id.
    #[default]
    Commit,
    /// Only a prefix — the host could not name its head in full.
    Abbreviated,
}

impl RevisionPrecision {
    /// What the commit id's own shape says it is.
    pub fn of(commit: &str) -> Self {
        if commit.len() == 40 {
            RevisionPrecision::Commit
        } else {
            RevisionPrecision::Abbreviated
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the bundle's `model/` directory.
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// The repo-relative path this file came from, when it differs from
    /// `path` — sharded models live in subdirectories upstream but flat in the
    /// bundle. The offline chain re-derivation walks the git tree by *this*
    /// path. Absent in bundles from tool versions before evidence capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
}

impl FileEntry {
    /// The path to walk in the git tree.
    pub fn tree_path(&self) -> &str {
        self.source_path.as_deref().unwrap_or(&self.path)
    }
}

/// The three-tier verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// Tier 1 — content-hash chain.
    pub content_hash: ContentHashStatus,
    /// Tier 2 — upstream commit signature.
    pub upstream_signature: SignatureStatus,
    /// What upstream evidence this bundle carries.
    ///
    /// Tier 3 is the detached signature file alongside this manifest; its
    /// presence is a fact about the bundle rather than a claim inside it, so it
    /// is deliberately not recorded here. A manifest cannot vouch for its own
    /// signature.
    pub evidence: EvidenceKind,
}

/// What upstream evidence a bundle carries, and therefore what its Tier 1 rests
/// on.
///
/// One field rather than a pair of booleans ("captured?", "re-derivable?"):
/// those admit a fourth, meaningless combination, and nothing would reject a
/// manifest asserting it. These are the three states that actually exist.
///
/// Note that `amf verify` does not *trust* this field — it re-derives the chain
/// from whatever evidence is on disk and reports what it found. The value here
/// is a description for a reader who is not running the verifier, which is
/// exactly the reader who most needs it to be unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Signed commit, trees, and LFS pointers: every file's hash can be
    /// re-derived offline, with no network and no trust in this tool's word.
    Chain,
    /// API responses only, stored verbatim and digest-covered by Tier 3. Tier 1
    /// rests on the fetcher having checked hashes the host asserted over TLS —
    /// a real but weaker claim. The state a host with no git endpoint produces.
    RestOnly,
    /// Nothing was captured.
    Absent,
}

impl EvidenceKind {
    /// Whether the airgapped side can rebuild each hash from the commit itself.
    pub fn is_rederivable(&self) -> bool {
        matches!(self, EvidenceKind::Chain)
    }

    pub fn was_captured(&self) -> bool {
        !matches!(self, EvidenceKind::Absent)
    }
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
    ///
    /// This is a *positive finding*: a commit object was retrieved and examined
    /// and carried no signature. It is not the status for "we never looked".
    Unsigned { reason: String },
    /// No commit object was ever retrieved, so nothing is known either way.
    ///
    /// Deliberately distinct from every other variant. If evidence capture
    /// fails — a proxy that allows the REST API but blocks `/info/refs`, say —
    /// the fetcher has examined no commit at all, and recording either
    /// "signature present" or "unsigned" would state a finding it never made.
    /// The whole point of this enum is that a reader can tell what was checked
    /// from what was merely assumed, and "not checked" needs its own name to
    /// stay tellable.
    Unknown { reason: String },
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

/// One file as the counterpart host reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorroboratedFile {
    pub path: String,
    pub sha256: String,
}

/// One file the two hosts disagreed about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorroborationConflict {
    pub path: String,
    pub ours: String,
    pub theirs: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Corroboration {
    /// The counterpart host published the same hash for every file checked.
    ///
    /// The file list is recorded rather than a count, because "the model
    /// matched" and "the one file we bothered to check matched" are different
    /// claims and a reader must be able to tell which one this is.
    Match {
        host: String,
        repo: String,
        files: Vec<CorroboratedFile>,
    },
    /// The counterpart host published a *different* hash. Serious.
    Mismatch {
        host: String,
        repo: String,
        conflicts: Vec<CorroborationConflict>,
        /// Files that did agree, if any — a partial disagreement is a different
        /// shape of problem from a wholesale one.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        matched: Vec<CorroboratedFile>,
    },
    /// Could not check — usually because the other host is unreachable, which is
    /// the expected case for an operator who chose ModelScope precisely because
    /// HuggingFace is blocked.
    Unavailable { host: String, reason: String },
    /// Not attempted (`--no-corroborate`).
    Skipped,
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

    /// Parse, checking the schema version *before* anything else.
    ///
    /// The order matters and is the whole point. A manifest from another schema
    /// will usually fail to deserialise on some field that moved, and reporting
    /// `missing field \`evidence\`` tells an operator nothing about what to do.
    /// Reading the version from a minimal probe first means the diagnosis comes
    /// out as "this bundle predates the current schema, re-fetch it".
    pub fn from_json_checked(bytes: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Probe {
            schema_version: u32,
        }

        // A manifest without even a readable version is malformed, not merely
        // old; let the full parse produce the detailed error for that case.
        if let Ok(probe) = serde_json::from_slice::<Probe>(bytes) {
            check_schema_version(probe.schema_version)?;
        }
        Self::from_json(bytes).map_err(|e| e.to_string())
    }

    /// Reject a manifest this build does not understand.
    ///
    /// Prefer [`Manifest::from_json_checked`], which applies this before a
    /// field mismatch can turn into a confusing parse error.
    pub fn ensure_supported_schema(&self) -> Result<(), String> {
        check_schema_version(self.schema_version)
    }

    /// Total size of the model files.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

fn check_schema_version(version: u32) -> Result<(), String> {
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    Err(if version > SCHEMA_VERSION {
        format!(
            "this bundle uses manifest schema {version} but this build only understands \
             {SCHEMA_VERSION}. Upgrade amf rather than trusting an older reading of a \
             newer manifest."
        )
    } else {
        format!(
            "this bundle uses manifest schema {version}, which predates the current \
             schema {SCHEMA_VERSION}. Re-fetch it with this build."
        )
    })
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
            source_path: None,
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
                revision_precision: RevisionPrecision::Commit,
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
                evidence: EvidenceKind::Chain,
            },
            corroboration: Corroboration::Skipped,
            evidence_files: Vec::new(),
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
        assert_ne!(
            d,
            compute_bundle_digest(&[entry("b.gguf", &"a".repeat(64), 1)])
        );
        assert_ne!(
            d,
            compute_bundle_digest(&[entry("a.gguf", &"c".repeat(64), 1)])
        );
        assert_ne!(
            d,
            compute_bundle_digest(&[entry("a.gguf", &"a".repeat(64), 2)])
        );
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
        assert!(!SignatureStatus::Unsigned { reason: "x".into() }.is_verified());

        let mismatch = SignatureStatus::SignaturePresentKeyMismatch {
            expected_fingerprint: "A".into(),
            actual_fingerprint: Some("B".into()),
        };
        assert!(!mismatch.is_verified());
        assert!(mismatch.is_mismatch());

        assert!(!SignatureStatus::Unknown { reason: "x".into() }.is_verified());
    }

    #[test]
    fn evidence_states_cannot_contradict_each_other() {
        // The whole reason this is one field and not two booleans: there is no
        // way to express "nothing captured, but re-derivable".
        assert!(EvidenceKind::Chain.is_rederivable());
        assert!(EvidenceKind::Chain.was_captured());

        // Captured, but the hashes are still only the host's assertion.
        assert!(!EvidenceKind::RestOnly.is_rederivable());
        assert!(EvidenceKind::RestOnly.was_captured());

        assert!(!EvidenceKind::Absent.is_rederivable());
        assert!(!EvidenceKind::Absent.was_captured());
    }

    #[test]
    fn an_older_schema_is_diagnosed_before_a_field_mismatch_can_confuse_it() {
        // The realistic case: a schema-1 manifest has no `evidence` field at
        // all, so a plain parse fails with "missing field `evidence`" — true,
        // and useless to whoever has to decide what to do about it. The version
        // check has to happen first or it never runs.
        let mut value: serde_json::Value =
            serde_json::from_slice(&sample().to_canonical_json().unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(1);
        value["verification"]
            .as_object_mut()
            .unwrap()
            .remove("evidence");
        value["verification"]["evidence_captured"] = serde_json::json!(true);

        let bytes = value.to_string();
        assert!(
            Manifest::from_json(bytes.as_bytes()).is_err(),
            "the plain parse should fail — that is what makes the ordering matter"
        );

        let err = Manifest::from_json_checked(bytes.as_bytes()).unwrap_err();
        assert!(err.contains("predates"), "{err}");
        assert!(!err.contains("missing field"), "{err}");
    }

    #[test]
    fn a_manifest_from_another_schema_is_refused_with_a_reason() {
        let mut m = sample();
        assert!(m.ensure_supported_schema().is_ok());

        // Older: the field meanings this build assumes were not in force yet.
        m.schema_version = SCHEMA_VERSION - 1;
        let err = m.ensure_supported_schema().unwrap_err();
        assert!(err.contains("predates"), "{err}");

        // Newer: refuse rather than read new fields under old meanings, which
        // is how a verifier reports the wrong thing with full confidence.
        m.schema_version = SCHEMA_VERSION + 1;
        let err = m.ensure_supported_schema().unwrap_err();
        assert!(err.contains("Upgrade amf"), "{err}");
    }

    #[test]
    fn not_looking_is_a_distinct_status_from_finding_nothing() {
        // These read similarly in prose and mean entirely different things:
        // `unsigned` says a commit was fetched and carried no signature;
        // `unknown` says no commit was fetched at all. Collapsing them would
        // let a failed evidence capture masquerade as a finding.
        let unsigned = serde_json::to_string(&SignatureStatus::Unsigned {
            reason: "the modelscope commit carries no signature".into(),
        })
        .unwrap();
        let unknown = serde_json::to_string(&SignatureStatus::Unknown {
            reason: "evidence capture failed".into(),
        })
        .unwrap();

        assert!(unsigned.contains("\"status\":\"unsigned\""), "{unsigned}");
        assert!(unknown.contains("\"status\":\"unknown\""), "{unknown}");
        assert_ne!(unsigned, unknown);
    }

    #[test]
    fn a_legacy_manifest_carrying_a_c2pa_key_still_parses() {
        // C2PA was removed from the spec, but bundles written before that
        // carry a `c2pa` object. Verification re-reads the manifest *bytes*
        // from disk rather than re-serialising, so those bundles must keep
        // parsing — an unknown field is not a reason to reject a signed
        // manifest that was honest when it was written.
        let m = sample();
        let mut value: serde_json::Value =
            serde_json::from_slice(&m.to_canonical_json().unwrap()).unwrap();
        value["c2pa"] = serde_json::json!({"status": "absent", "searched": ["sidecar"]});

        let parsed = Manifest::from_json(value.to_string().as_bytes())
            .expect("a legacy c2pa key must not break parsing");
        assert_eq!(parsed, m);
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
