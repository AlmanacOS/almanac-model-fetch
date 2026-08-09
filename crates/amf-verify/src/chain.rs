//! Re-deriving the evidence chain, offline.
//!
//! ```text
//! signed commit ──▶ root tree ──▶ … ──▶ LFS pointer blob ──▶ sha256 ──▶ file bytes
//! ```
//!
//! Every arrow is checked by content address: each object's bytes are hashed and
//! compared against the id the previous link named. That means a bundle carrying
//! these objects can be re-verified on a machine with no network and no access
//! to HuggingFace at all — which is the entire point of the exercise.
//!
//! Note what this does and does not prove. It proves the file you hold is the
//! one the commit names. It does *not* prove who made the commit; that requires
//! checking the signature against a trusted key, which is a separate tier.

use std::collections::HashMap;

use crate::git::{self, ObjectKind};
use crate::lfs;
use crate::VerifyError;

/// The git objects captured into a bundle's `evidence/` directory.
#[derive(Debug, Default, Clone)]
pub struct Evidence {
    /// Raw commit object (header-less content, as `git cat-file commit` emits).
    pub commit: Vec<u8>,
    /// Tree objects by object id.
    pub trees: HashMap<String, Vec<u8>>,
    /// LFS pointer blobs by object id.
    pub pointers: HashMap<String, Vec<u8>>,
}

/// What the chain proved about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResult {
    pub path: String,
    /// The SHA256 the signed commit ultimately commits to.
    pub sha256: String,
    pub size: u64,
    /// Object ids walked, root tree first — recorded so a manifest can show its
    /// working rather than just asserting a conclusion.
    pub tree_path: Vec<String>,
    pub blob_oid: String,
}

/// Walk `path` from the commit's root tree and return the SHA256 it commits to.
pub fn derive_expected_hash(
    evidence: &Evidence,
    commit_oid: &str,
    path: &str,
) -> Result<ChainResult, VerifyError> {
    // 1. The commit must actually be the commit we think it is.
    git::verify_object_id(ObjectKind::Commit, &evidence.commit, commit_oid)?;
    let commit = git::parse_commit(&evidence.commit)?;

    // 2. Walk the path, checking every tree against the id its parent named.
    let mut current_oid = commit.tree;
    let mut tree_path = vec![current_oid.clone()];
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(VerifyError::MalformedObject(format!(
            "cannot walk an empty path {path:?}"
        )));
    }

    for (i, component) in components.iter().enumerate() {
        let raw = evidence.trees.get(&current_oid).ok_or_else(|| {
            VerifyError::MissingEvidence(format!("tree object {current_oid} for path {path:?}"))
        })?;
        git::verify_object_id(ObjectKind::Tree, raw, &current_oid)?;

        let entries = git::parse_tree(raw)?;
        let entry = entries
            .iter()
            .find(|e| e.name == *component)
            .ok_or_else(|| VerifyError::PathNotInTree {
                path: path.to_string(),
                component: component.to_string(),
            })?;

        let last = i == components.len() - 1;
        if last {
            if entry.is_dir() {
                return Err(VerifyError::MalformedObject(format!(
                    "path {path:?} resolves to a directory, not a file"
                )));
            }
            // 3. The blob must be the pointer the tree named.
            let blob = evidence.pointers.get(&entry.oid).ok_or_else(|| {
                VerifyError::MissingEvidence(format!("LFS pointer blob {} for {path:?}", entry.oid))
            })?;
            git::verify_object_id(ObjectKind::Blob, blob, &entry.oid)?;

            // 4. And the pointer names the content hash.
            let pointer = lfs::parse_pointer(blob)?;
            return Ok(ChainResult {
                path: path.to_string(),
                sha256: pointer.oid_sha256,
                size: pointer.size,
                tree_path,
                blob_oid: entry.oid.clone(),
            });
        }

        if !entry.is_dir() {
            return Err(VerifyError::MalformedObject(format!(
                "path component {component:?} in {path:?} is a file, not a directory"
            )));
        }
        current_oid = entry.oid.clone();
        tree_path.push(current_oid.clone());
    }

    unreachable!("loop returns on the final component")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::object_id;

    /// Build a tree object from `(mode, name, oid)` triples.
    fn tree(entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (mode, name, oid) in entries {
            out.extend_from_slice(mode.as_bytes());
            out.push(b' ');
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.extend_from_slice(&hex::decode(oid).unwrap());
        }
        out
    }

    fn pointer(hash: &str, size: u64) -> Vec<u8> {
        format!("version https://git-lfs.github.com/spec/v1\noid sha256:{hash}\nsize {size}\n")
            .into_bytes()
    }

    /// A one-file repo: commit -> root tree -> pointer blob.
    fn flat_fixture() -> (Evidence, String, String) {
        let content_hash = "a".repeat(64);
        let blob = pointer(&content_hash, 1234);
        let blob_oid = object_id(ObjectKind::Blob, &blob);

        let root = tree(&[("100644", "model.gguf", &blob_oid)]);
        let root_oid = object_id(ObjectKind::Tree, &root);

        let commit =
            format!("tree {root_oid}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nmsg\n")
                .into_bytes();
        let commit_oid = object_id(ObjectKind::Commit, &commit);

        let mut ev = Evidence {
            commit,
            ..Default::default()
        };
        ev.trees.insert(root_oid, root);
        ev.pointers.insert(blob_oid, blob);
        (ev, commit_oid, content_hash)
    }

    #[test]
    fn derives_the_hash_for_a_flat_repo() {
        let (ev, commit_oid, expected) = flat_fixture();
        let r = derive_expected_hash(&ev, &commit_oid, "model.gguf").unwrap();
        assert_eq!(r.sha256, expected);
        assert_eq!(r.size, 1234);
        assert_eq!(r.tree_path.len(), 1);
    }

    #[test]
    fn derives_the_hash_through_a_subdirectory() {
        let content_hash = "b".repeat(64);
        let blob = pointer(&content_hash, 99);
        let blob_oid = object_id(ObjectKind::Blob, &blob);

        let sub = tree(&[("100644", "shard-00001-of-00002.gguf", &blob_oid)]);
        let sub_oid = object_id(ObjectKind::Tree, &sub);

        let root = tree(&[("40000", "Q4_K_M", &sub_oid)]);
        let root_oid = object_id(ObjectKind::Tree, &root);

        let commit = format!("tree {root_oid}\ncommitter A <a@x> 1 +0000\n\nm\n").into_bytes();
        let commit_oid = object_id(ObjectKind::Commit, &commit);

        let mut ev = Evidence {
            commit,
            ..Default::default()
        };
        ev.trees.insert(root_oid.clone(), root);
        ev.trees.insert(sub_oid.clone(), sub);
        ev.pointers.insert(blob_oid.clone(), blob);

        let r = derive_expected_hash(&ev, &commit_oid, "Q4_K_M/shard-00001-of-00002.gguf").unwrap();
        assert_eq!(r.sha256, content_hash);
        assert_eq!(r.tree_path, vec![root_oid, sub_oid]);
        assert_eq!(r.blob_oid, blob_oid);
    }

    #[test]
    fn a_tampered_pointer_breaks_the_chain() {
        // Swap the pointer for one naming a different hash, keeping the tree's
        // claimed oid. The blob no longer hashes to what the tree named, so the
        // chain must reject it — this is the substitution the chain exists to
        // catch.
        let (mut ev, commit_oid, _) = flat_fixture();
        let oid = ev.pointers.keys().next().unwrap().clone();
        ev.pointers.insert(oid, pointer(&"c".repeat(64), 1234));

        match derive_expected_hash(&ev, &commit_oid, "model.gguf") {
            Err(VerifyError::ObjectIdMismatch { kind, .. }) => assert_eq!(kind, "blob"),
            other => panic!("expected a blob id mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_tree_breaks_the_chain() {
        let (mut ev, commit_oid, _) = flat_fixture();
        let oid = ev.trees.keys().next().unwrap().clone();
        ev.trees
            .insert(oid, tree(&[("100644", "evil.gguf", &"d".repeat(40))]));

        match derive_expected_hash(&ev, &commit_oid, "model.gguf") {
            Err(VerifyError::ObjectIdMismatch { kind, .. }) => assert_eq!(kind, "tree"),
            other => panic!("expected a tree id mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_commit_oid_is_rejected() {
        let (ev, _, _) = flat_fixture();
        let err = derive_expected_hash(&ev, &"e".repeat(40), "model.gguf").unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ObjectIdMismatch { kind: "commit", .. }
        ));
    }

    #[test]
    fn a_missing_path_is_reported_clearly() {
        let (ev, commit_oid, _) = flat_fixture();
        match derive_expected_hash(&ev, &commit_oid, "nope.gguf") {
            Err(VerifyError::PathNotInTree { component, .. }) => {
                assert_eq!(component, "nope.gguf")
            }
            other => panic!("expected PathNotInTree, got {other:?}"),
        }
    }

    #[test]
    fn missing_evidence_is_distinguished_from_tampering() {
        // An incomplete bundle must not look like an attack.
        let (mut ev, commit_oid, _) = flat_fixture();
        ev.pointers.clear();
        assert!(matches!(
            derive_expected_hash(&ev, &commit_oid, "model.gguf"),
            Err(VerifyError::MissingEvidence(_))
        ));
    }

    #[test]
    fn a_directory_is_not_a_file() {
        let sub = tree(&[("100644", "x", &"f".repeat(40))]);
        let sub_oid = object_id(ObjectKind::Tree, &sub);
        let root = tree(&[("40000", "dir", &sub_oid)]);
        let root_oid = object_id(ObjectKind::Tree, &root);
        let commit = format!("tree {root_oid}\n\nm\n").into_bytes();
        let commit_oid = object_id(ObjectKind::Commit, &commit);

        let mut ev = Evidence {
            commit,
            ..Default::default()
        };
        ev.trees.insert(root_oid, root);
        ev.trees.insert(sub_oid, sub);

        assert!(derive_expected_hash(&ev, &commit_oid, "dir").is_err());
    }

    #[test]
    fn an_empty_path_is_rejected() {
        let (ev, commit_oid, _) = flat_fixture();
        assert!(derive_expected_hash(&ev, &commit_oid, "").is_err());
    }
}
