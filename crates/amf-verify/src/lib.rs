//! Verification primitives for almanac-model-fetch.
//!
//! This crate is deliberately free of HTTP, TUI, and async dependencies: the
//! airgapped-side importer needs exactly what is here and nothing else, and
//! every dependency it does not have is one fewer thing to audit on a machine
//! that is supposed to be trustworthy.

pub mod chain;
pub mod git;
pub mod hash;
pub mod lfs;
pub mod pgpsig;
pub mod signing;

pub use chain::{derive_expected_hash, ChainResult, Evidence};
pub use hash::{hash_file, resume_from_file, StreamingVerifier};
pub use lfs::LfsPointer;
pub use signing::{generate_keypair, sign_bytes, verify_bytes, VerifiedSignature};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(
        "content hash mismatch: expected {expected}, got {actual} — \
         the bytes received are not the bytes upstream published"
    )]
    HashMismatch { expected: String, actual: String },

    #[error("size mismatch: expected {expected} bytes, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error(
        "stream overran its expected size ({seen} bytes received, expected {expected}) — \
         aborted without writing further"
    )]
    SizeOverrun { expected: u64, seen: u64 },

    #[error("{kind} object id mismatch: expected {expected}, computed {actual}")]
    ObjectIdMismatch {
        kind: &'static str,
        expected: String,
        actual: String,
    },

    #[error("malformed git object: {0}")]
    MalformedObject(String),

    #[error("malformed LFS pointer: {0}")]
    MalformedPointer(String),

    #[error("bundle evidence is incomplete: missing {0}")]
    MissingEvidence(String),

    #[error("path {path:?} not found in tree (no entry {component:?})")]
    PathNotInTree { path: String, component: String },

    #[error("signature did not verify against the supplied public key")]
    BadSignature,

    #[error("a key already exists at {0}; refusing to overwrite it")]
    KeyExists(std::path::PathBuf),

    #[error("{0}")]
    Signing(String),

    #[error("i/o error on {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl VerifyError {
    /// Whether this indicates the data is wrong, as opposed to the bundle being
    /// incomplete or unreadable.
    ///
    /// The distinction matters for what an operator should do: a mismatch means
    /// treat the artifact as suspect, while missing evidence usually means the
    /// bundle was produced by an older tool or copied incompletely.
    pub fn is_integrity_failure(&self) -> bool {
        matches!(
            self,
            VerifyError::HashMismatch { .. }
                | VerifyError::SizeMismatch { .. }
                | VerifyError::SizeOverrun { .. }
                | VerifyError::ObjectIdMismatch { .. }
        )
    }
}
