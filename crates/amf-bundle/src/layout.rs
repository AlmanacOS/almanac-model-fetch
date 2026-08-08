//! Bundle directory naming, layout, and atomic construction.

use std::path::{Path, PathBuf};

use crate::manifest::Manifest;
use crate::BundleError;

/// Where bundles live on a drive.
pub const BUNDLES_SUBPATH: &str = "almanac/models";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const SIGNATURE_FILE: &str = "manifest.json.minisig";
pub const MODEL_DIR: &str = "model";
pub const EVIDENCE_DIR: &str = "evidence";
pub const C2PA_FILE: &str = "provenance.c2pa";
/// In-progress bundles land here and are renamed into place only when complete,
/// so a bundle directory never exists in a half-written state.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// Characters we allow in a bundle directory name.
///
/// exFAT rejects `" * / : < > ? \ |` and control characters, and a repo or
/// variant label is attacker-influenced text from a remote host — so rather than
/// enumerate what to strip, we allow a known-safe set and replace everything
/// else. That also stops a crafted repo name from containing path separators.
fn sanitise(component: &str) -> String {
    let mut out: String = component
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A leading dot would make the bundle hidden on Unix, and a name of nothing
    // but dots is a path-traversal component. Replace the whole leading run, not
    // just the first character, or ".." would become "_." and still look odd.
    let leading = out.chars().take_while(|c| *c == '.').count();
    if leading > 0 {
        out.replace_range(0..leading, &"_".repeat(leading));
    }
    // Windows and exFAT dislike names ending in a dot or a space.
    let trailing = out.chars().rev().take_while(|c| *c == '.').count();
    if trailing > 0 {
        let start = out.len() - trailing;
        out.replace_range(start.., &"_".repeat(trailing));
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// The content-addressed directory name for a bundle.
///
/// `<org>__<repo>__<variant>__<digest12>` — re-fetching the same variant at the
/// same revision produces the same name, which is what makes duplicate
/// detection a directory-existence check rather than a re-download.
pub fn bundle_dir_name(repo: &str, variant: &str, bundle_digest: &str) -> String {
    let (org, name) = repo.split_once('/').unwrap_or(("", repo));
    let digest12: String = bundle_digest.chars().take(12).collect();
    format!(
        "{}__{}__{}__{}",
        sanitise(org),
        sanitise(name),
        sanitise(variant),
        sanitise(&digest12),
    )
}

/// Full path to a bundle on a destination drive.
pub fn bundle_path(usb_root: &Path, repo: &str, variant: &str, bundle_digest: &str) -> PathBuf {
    usb_root
        .join(BUNDLES_SUBPATH)
        .join(bundle_dir_name(repo, variant, bundle_digest))
}

/// What we found at a destination for a bundle we are about to write.
#[derive(Debug, PartialEq, Eq)]
pub enum Existing {
    /// Nothing there.
    Absent,
    /// A complete bundle whose manifest digest matches — nothing to do.
    IdenticalBundle,
    /// A directory exists but its manifest is missing, unreadable, or has a
    /// different digest. Never silently overwritten.
    Conflict(String),
}

/// Decide whether a bundle already exists at `path`.
pub fn inspect_existing(path: &Path, expected_digest: &str) -> Existing {
    if !path.exists() {
        return Existing::Absent;
    }
    let manifest_path = path.join(MANIFEST_FILE);
    let Ok(bytes) = std::fs::read(&manifest_path) else {
        return Existing::Conflict(format!(
            "{} exists but has no readable {MANIFEST_FILE}",
            path.display()
        ));
    };
    let Ok(manifest) = Manifest::from_json(&bytes) else {
        return Existing::Conflict(format!(
            "{} contains a {MANIFEST_FILE} that could not be parsed",
            path.display()
        ));
    };
    if manifest.bundle_digest.eq_ignore_ascii_case(expected_digest) {
        Existing::IdenticalBundle
    } else {
        Existing::Conflict(format!(
            "{} holds a different bundle (digest {}, expected {expected_digest})",
            path.display(),
            manifest.bundle_digest
        ))
    }
}

/// A bundle under construction.
///
/// Everything is written beneath `<final>.partial/` and renamed into place at
/// the end. An interrupted run therefore leaves a `.partial` directory that a
/// later run can resume from, and never a bundle directory that looks complete
/// but is not.
pub struct BundleWriter {
    final_path: PathBuf,
    partial_path: PathBuf,
}

impl BundleWriter {
    pub fn create(final_path: PathBuf) -> Result<Self, BundleError> {
        let partial_path = with_partial_suffix(&final_path);
        for dir in [
            partial_path.join(MODEL_DIR),
            partial_path.join(EVIDENCE_DIR),
        ] {
            std::fs::create_dir_all(&dir).map_err(|e| BundleError::Io {
                path: dir.clone(),
                source: e,
            })?;
        }
        Ok(Self {
            final_path,
            partial_path,
        })
    }

    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    pub fn model_dir(&self) -> PathBuf {
        self.partial_path.join(MODEL_DIR)
    }

    pub fn evidence_dir(&self) -> PathBuf {
        self.partial_path.join(EVIDENCE_DIR)
    }

    /// Write a file into the partial bundle, creating parent directories.
    pub fn write(&self, relative: &str, contents: &[u8]) -> Result<PathBuf, BundleError> {
        let path = self.partial_path.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BundleError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        std::fs::write(&path, contents).map_err(|e| BundleError::Io {
            path: path.clone(),
            source: e,
        })?;
        Ok(path)
    }

    /// Finish: fsync the contents, then rename the partial directory into place.
    ///
    /// The fsync matters more than usual here. USB drives get unplugged, often
    /// immediately after the tool prints "done", and a bundle that is only in
    /// the page cache at that moment arrives at the airgapped machine truncated.
    pub fn finish(self) -> Result<PathBuf, BundleError> {
        fsync_tree(&self.partial_path)?;

        if self.final_path.exists() {
            return Err(BundleError::AlreadyExists(self.final_path.clone()));
        }
        std::fs::rename(&self.partial_path, &self.final_path).map_err(|e| BundleError::Io {
            path: self.final_path.clone(),
            source: e,
        })?;

        // Sync the parent so the rename itself is durable, not just the data.
        if let Some(parent) = self.final_path.parent() {
            let _ = std::fs::File::open(parent).map(|d| d.sync_all());
        }
        Ok(self.final_path)
    }
}

pub fn with_partial_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(PARTIAL_SUFFIX);
    PathBuf::from(s)
}

/// fsync every file in a directory tree, then the directories themselves.
fn fsync_tree(root: &Path) -> Result<(), BundleError> {
    let entries = std::fs::read_dir(root).map_err(|e| BundleError::Io {
        path: root.to_path_buf(),
        source: e,
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            fsync_tree(&path)?;
        } else {
            let file = std::fs::File::open(&path).map_err(|e| BundleError::Io {
                path: path.clone(),
                source: e,
            })?;
            file.sync_all().map_err(|e| BundleError::Io {
                path: path.clone(),
                source: e,
            })?;
        }
    }
    // Directory sync is best-effort: not every filesystem supports it, and
    // failing the whole bundle over it would be worse than the risk.
    let _ = std::fs::File::open(root).map(|d| d.sync_all());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_content_addressed_name() {
        let name = bundle_dir_name("unsloth/Qwen3-8B-GGUF", "Q4_K_M", &"a".repeat(64));
        assert_eq!(name, "unsloth__Qwen3-8B-GGUF__Q4_K_M__aaaaaaaaaaaa");
    }

    #[test]
    fn the_same_inputs_give_the_same_name() {
        let a = bundle_dir_name("o/r", "Q4", "abcdef123456789");
        let b = bundle_dir_name("o/r", "Q4", "abcdef123456789");
        assert_eq!(a, b, "dedup depends on this being stable");
    }

    #[test]
    fn a_different_digest_gives_a_different_name() {
        assert_ne!(
            bundle_dir_name("o/r", "Q4", &"a".repeat(64)),
            bundle_dir_name("o/r", "Q4", &"b".repeat(64))
        );
    }

    #[test]
    fn sanitises_path_traversal_and_exfat_hostile_characters() {
        // A malicious repo name must not escape the bundles directory.
        let name = bundle_dir_name("../../etc", "a/b:c*d", "0123456789ab");
        assert!(!name.contains('/'), "no separators survive: {name}");
        assert!(!name.contains(':'), "no colons survive: {name}");
        assert!(!name.contains('*'));
        assert!(!name.contains(".."), "no traversal survives: {name}");
    }

    #[test]
    fn sanitises_leading_dots() {
        assert!(!sanitise(".hidden").starts_with('.'));
        assert_eq!(sanitise(".."), "__");
        assert_eq!(sanitise(""), "_");
    }

    #[test]
    fn keeps_ordinary_variant_labels_intact() {
        assert_eq!(sanitise("UD-Q4_K_XL"), "UD-Q4_K_XL");
        assert_eq!(sanitise("Q4_K_M"), "Q4_K_M");
    }

    #[test]
    fn detects_an_absent_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nothing-here");
        assert_eq!(inspect_existing(&path, "abc"), Existing::Absent);
    }

    #[test]
    fn writes_atomically_and_only_appears_when_complete() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("bundle");

        let w = BundleWriter::create(final_path.clone()).unwrap();
        w.write("model/a.gguf", b"data").unwrap();

        assert!(!final_path.exists(), "must not appear before finish()");
        assert!(with_partial_suffix(&final_path).exists());

        let done = w.finish().unwrap();
        assert_eq!(done, final_path);
        assert!(final_path.join("model/a.gguf").exists());
        assert!(
            !with_partial_suffix(&final_path).exists(),
            "partial dir should be gone"
        );
    }

    #[test]
    fn refuses_to_overwrite_an_existing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("bundle");
        std::fs::create_dir_all(&final_path).unwrap();

        let w = BundleWriter::create(final_path.clone()).unwrap();
        w.write("model/a.gguf", b"data").unwrap();
        assert!(matches!(w.finish(), Err(BundleError::AlreadyExists(_))));
    }

    #[test]
    fn write_creates_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let w = BundleWriter::create(dir.path().join("b")).unwrap();
        let p = w.write("evidence/tree/deep/obj.bin", b"x").unwrap();
        assert!(p.exists());
    }
}
