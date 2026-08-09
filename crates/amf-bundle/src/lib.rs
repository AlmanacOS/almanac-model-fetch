//! Bundle layout, manifest, and atomic construction.
//!
//! Like `amf-verify`, this crate stays free of HTTP and async dependencies so
//! the airgapped-side importer can depend on it without pulling in a network
//! stack it has no use for.

pub mod layout;
pub mod manifest;

pub use layout::{bundle_dir_name, bundle_path, inspect_existing, BundleWriter, Existing};
pub use manifest::{
    compute_bundle_digest, ContentHashStatus, CorroboratedFile, Corroboration,
    CorroborationConflict, EvidenceKind, FileEntry, Manifest, RevisionPrecision, SignatureStatus,
    SourceRecord, Tool, Verification, SCHEMA_VERSION,
};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("i/o error on {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("a bundle already exists at {0}")]
    AlreadyExists(std::path::PathBuf),

    #[error("manifest could not be serialised: {0}")]
    Serialise(#[from] serde_json::Error),

    #[error("verification failed: {0}")]
    Verify(#[from] amf_verify::VerifyError),
}

/// Current UTC time as RFC3339, for `fetched_at`.
pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_is_rfc3339_utc() {
        let ts = super::now_rfc3339();
        assert!(ts.ends_with('Z'), "should be UTC: {ts}");
        assert!(ts.contains('T'), "should be RFC3339: {ts}");
        assert!(
            time::OffsetDateTime::parse(&ts, &time::format_description::well_known::Rfc3339)
                .is_ok(),
            "should re-parse: {ts}"
        );
    }
}
