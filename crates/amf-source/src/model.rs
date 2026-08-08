//! Core data types shared by every source backend.

use crate::spec::{RepoId, SourceKind};

/// A repository pinned to an immutable commit.
///
/// Revisions are always resolved to a commit SHA before anything is fetched. A
/// bundle that recorded `main` would be unreproducible the moment upstream moved,
/// which defeats the point of hand-carrying a verified artifact to an airgap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    pub source: SourceKind,
    pub repo: RepoId,
    /// The resolved commit SHA. Never a branch name.
    pub commit: String,
    /// What the operator asked for, kept for the manifest ("main", a tag, …).
    pub requested: String,
}

/// One file in a remote repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    /// Repo-relative path, e.g. `DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-…-00001-of-00003.gguf`.
    pub path: String,
    pub size: u64,
    /// The upstream-published SHA256, when there is one.
    ///
    /// `None` means the host published no hash for this file — for HuggingFace
    /// that happens on small non-LFS files, which carry a git blob SHA1 instead.
    /// A `None` here is not a soft failure to paper over: it means this file
    /// cannot be verified against upstream and callers must treat it as such.
    pub sha256: Option<String>,
    /// Shard position within a multi-part variant, if this is one part of a set.
    pub shard: Option<Shard>,
}

impl RemoteFile {
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn is_gguf(&self) -> bool {
        self.path.to_ascii_lowercase().ends_with(".gguf")
    }
}

/// `-00002-of-00003` in a sharded GGUF filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Shard {
    pub index: u32,
    pub total: u32,
}

/// A selectable model variant: one quantisation, made of one *or more* files.
///
/// Large models ship as shard sets rather than single files, and those are
/// exactly the models most likely to be hand-carried to an airgapped machine, so
/// a variant is a file set throughout — never a single file with sharding bolted
/// on as a special case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// The quantisation label, e.g. `Q4_K_M`, `UD-IQ1_S`.
    pub label: String,
    /// Files in shard order.
    pub files: Vec<RemoteFile>,
}

impl Variant {
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn largest_file(&self) -> u64 {
        self.files.iter().map(|f| f.size).max().unwrap_or(0)
    }

    pub fn is_sharded(&self) -> bool {
        self.files.len() > 1
    }

    /// Whether every file carries an upstream hash we can verify against.
    pub fn fully_verifiable(&self) -> bool {
        !self.files.is_empty() && self.files.iter().all(|f| f.sha256.is_some())
    }

    /// Shards upstream claims exist but that are missing from the listing.
    ///
    /// A variant advertising `-of-00003` with only two files present is either a
    /// broken upload or a truncated listing. Either way we must not present it
    /// as a complete, fetchable variant.
    pub fn missing_shards(&self) -> Vec<u32> {
        let Some(total) = self.files.iter().find_map(|f| f.shard.map(|s| s.total)) else {
            return Vec::new();
        };
        let present: Vec<u32> = self.files.iter().filter_map(|f| f.shard.map(|s| s.index)).collect();
        (1..=total).filter(|i| !present.contains(i)).collect()
    }
}
