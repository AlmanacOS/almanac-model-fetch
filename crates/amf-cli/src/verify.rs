//! `amf verify` — re-verify a bundle with no network.
//!
//! This is the command the airgapped operator runs. It needs no network, no
//! keyserver, and no access to HuggingFace: everything it checks is either in
//! the bundle or in key material provisioned out of band.
//!
//! What gets checked, strongest first:
//! 1. every model file hashes to what the manifest says;
//! 2. the manifest's bundle digest matches the files it lists;
//! 3. every evidence file hashes to what the manifest says;
//! 4. when evidence is present, the git chain is *re-derived*: commit → trees
//!    → LFS pointers → the same SHA256s, all content-addressed;
//! 5. the fetcher's bundle signature (with `--public-key`);
//! 6. the upstream commit signature (with `--upstream-key`).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use amf_bundle::{layout, Manifest};
use amf_verify::chain::Evidence;

use crate::ui;
use crate::VerifyArgs;

pub fn run(args: VerifyArgs) -> Result<()> {
    let bundles = find_bundles(&args.path)?;
    if bundles.is_empty() {
        bail!("no bundles found at {}", args.path.display());
    }

    let public_key = match &args.public_key {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .with_context(|| format!("reading public key {}", p.display()))?,
        ),
        None => None,
    };
    let upstream_key = match &args.upstream_key {
        Some(p) => Some(
            std::fs::read_to_string(p)
                .with_context(|| format!("reading upstream key {}", p.display()))?,
        ),
        None => None,
    };

    let mut failed = 0usize;
    for bundle in &bundles {
        match verify_one(bundle, public_key.as_deref(), upstream_key.as_deref()) {
            Ok(()) => {}
            Err(e) => {
                failed += 1;
                ui::error(&format!("{}: {e:#}", bundle.display()));
            }
        }
    }

    if failed > 0 {
        bail!(
            "{failed} of {} bundle(s) failed verification",
            bundles.len()
        );
    }
    ui::info(&format!("{} bundle(s) verified", bundles.len()));
    Ok(())
}

fn verify_one(
    bundle: &std::path::Path,
    public_key: Option<&str>,
    upstream_key: Option<&str>,
) -> Result<()> {
    ui::step(&format!("verifying {}", bundle.display()));

    let manifest_path = bundle.join(layout::MANIFEST_FILE);
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    // Schema-checked: a manifest from another schema fails on whichever field
    // moved, and "missing field `evidence`" tells an operator nothing about
    // what to do next.
    let manifest = Manifest::from_json_checked(&manifest_bytes)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("reading {}", manifest_path.display()))?;

    // 1. Every model file must hash to what the manifest says.
    let model_dir = bundle.join(layout::MODEL_DIR);
    for entry in &manifest.files {
        ensure_inside_bundle(&entry.path)?;
        let path = model_dir.join(&entry.path);
        let actual =
            amf_verify::hash_file(&path).map_err(|e| anyhow!("hashing {}: {e}", path.display()))?;
        if !actual.eq_ignore_ascii_case(&entry.sha256) {
            bail!(
                "{} does not match the manifest (expected {}, got {actual})",
                entry.path,
                entry.sha256
            );
        }
    }
    ui::info(&format!(
        "  {} file(s) match the manifest",
        manifest.files.len()
    ));

    // 2. The manifest's own digest must match the files it lists — otherwise a
    //    file could be added or removed without the per-file checks noticing.
    let recomputed = amf_bundle::compute_bundle_digest(&manifest.files);
    if !recomputed.eq_ignore_ascii_case(&manifest.bundle_digest) {
        bail!(
            "bundle digest mismatch: manifest says {}, files give {recomputed}",
            manifest.bundle_digest
        );
    }

    // 3. Evidence files are covered by the manifest (and so by its signature).
    for entry in &manifest.evidence_files {
        ensure_inside_bundle(&entry.path)?;
        let path = bundle.join(&entry.path);
        let actual = amf_verify::hash_file(&path)
            .map_err(|e| anyhow!("hashing evidence {}: {e}", path.display()))?;
        if !actual.eq_ignore_ascii_case(&entry.sha256) {
            bail!(
                "evidence file {} does not match the manifest (expected {}, got {actual})",
                entry.path,
                entry.sha256
            );
        }
    }

    // 4. Re-derive the git chain from the evidence, fully offline.
    let evidence_dir = bundle.join(layout::EVIDENCE_DIR);
    let commit_path = evidence_dir.join("commit.obj");
    if commit_path.exists() {
        let evidence = load_evidence(&evidence_dir)?;

        // The commit in the bundle must be the commit the manifest names.
        amf_verify::git::verify_object_id(
            amf_verify::git::ObjectKind::Commit,
            &evidence.commit,
            &manifest.source.commit,
        )
        .map_err(|e| anyhow!("evidence commit: {e}"))?;

        for entry in &manifest.files {
            let result = amf_verify::derive_expected_hash(
                &evidence,
                &manifest.source.commit,
                entry.tree_path(),
            )
            .map_err(|e| anyhow!("chain re-derivation for {}: {e}", entry.path))?;
            if !result.sha256.eq_ignore_ascii_case(&entry.sha256) {
                bail!(
                    "{}: the signed tree commits to {} but the manifest (and file) \
                     carry {} — the chain does not vouch for this file",
                    entry.path,
                    result.sha256,
                    entry.sha256
                );
            }
        }
        ui::info(&format!(
            "  evidence chain re-derived: commit {} → {} file hash(es), all content-addressed",
            &manifest.source.commit[..12],
            manifest.files.len()
        ));

        // 6. Upstream commit signature, if the operator holds the signer's key.
        if let Some(key) = upstream_key {
            let v = amf_verify::pgpsig::verify_commit_signature(&evidence.commit, key)
                .map_err(|e| anyhow!("upstream signature: {e}"))?;
            ui::info(&format!(
                "  upstream commit signature VERIFIED against {}",
                v.fingerprint
            ));
        }
    } else {
        if upstream_key.is_some() {
            bail!(
                "--upstream-key was given but this bundle carries no evidence/commit.obj \
                 to verify"
            );
        }
        ui::warn(
            "this bundle carries no git evidence; the chain cannot be re-derived \
             offline. Contents still match the manifest.",
        );
    }

    // 5. The fetcher's bundle signature.
    let sig_path = bundle.join(layout::SIGNATURE_FILE);
    match (public_key, sig_path.exists()) {
        (Some(key), true) => {
            let sig = std::fs::read_to_string(&sig_path)
                .with_context(|| format!("reading {}", sig_path.display()))?;
            let verified = amf_verify::verify_bytes(key, &sig, &manifest_bytes)
                .map_err(|e| anyhow!("bundle signature: {e}"))?;
            if !verified.covers_digest(&manifest.bundle_digest) {
                bail!(
                    "the signature is valid but was made for a different bundle \
                     (trusted comment: {:?})",
                    verified.trusted_comment
                );
            }
            ui::info("  bundle signature verified");
        }
        (Some(_), false) => bail!(
            "a public key was supplied but this bundle has no {}",
            layout::SIGNATURE_FILE
        ),
        (None, true) => ui::warn(
            "this bundle is signed, but no --public-key was given, so the signature \
             was not checked. Contents match the manifest; who produced it is unconfirmed.",
        ),
        (None, false) => ui::warn(
            "this bundle carries no signature. Contents match the manifest, but there \
             is nothing to confirm who produced it.",
        ),
    }

    // Report, without overclaiming, what upstream verification was recorded.
    if manifest.verification.upstream_signature.is_mismatch() {
        ui::alarm(
            "UPSTREAM SIGNATURE MISMATCH RECORDED",
            "This bundle was fetched when the upstream signing key did not match the \
             pinned one. Treat this artifact as suspect.",
        );
    }
    if let amf_bundle::SignatureStatus::Unknown { reason } =
        &manifest.verification.upstream_signature
    {
        // Not an alarm — nothing here is wrong — but the airgapped operator
        // should not have to infer from silence that Tier 2 was never reached.
        ui::warn(&format!(
            "Tier 2 was never established for this bundle: {reason}. Nothing is \
             claimed about the upstream commit signature either way."
        ));
    }
    match &manifest.corroboration {
        amf_bundle::Corroboration::Mismatch {
            host,
            repo,
            conflicts,
            ..
        } => {
            let detail = conflicts
                .iter()
                .map(|c| {
                    format!(
                        "    {}\n      here:  {}\n      {host}: {}",
                        c.path, c.ours, c.theirs
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            ui::alarm(
                "CROSS-SOURCE HASH DISAGREEMENT RECORDED",
                &format!(
                    "When this bundle was fetched, {host}/{repo} published different \
                     bytes for {} file(s):\n{detail}",
                    conflicts.len()
                ),
            );
        }
        amf_bundle::Corroboration::Match { host, files, .. } => {
            ui::info(&format!(
                "corroboration recorded: {host} published the same hash for {} file(s)",
                files.len()
            ));
        }
        amf_bundle::Corroboration::Unavailable { .. } | amf_bundle::Corroboration::Skipped => {}
    }

    // Say plainly what this bundle's Tier 1 actually rests on.
    if !manifest.verification.evidence.is_rederivable() {
        ui::warn(
            "this bundle carries no re-derivable evidence chain: its file hashes were \
             taken from the host's API over TLS rather than from a signed git tree. \
             The contents match what the manifest records, and the bundle signature \
             (if any) covers that record — but nothing here independently ties those \
             hashes to the upstream repository.",
        );
    }

    // The precision field is redundant with the commit id's own length, on
    // purpose: a manifest that claims exactness for a short id is lying about
    // the one field an auditor would most want to trust.
    let claimed = manifest.source.revision_precision;
    let actual = amf_bundle::RevisionPrecision::of(&manifest.source.commit);
    if claimed != actual {
        bail!(
            "manifest claims revision precision {claimed:?} but the recorded commit \
             {} is {actual:?}",
            manifest.source.commit
        );
    }
    if actual == amf_bundle::RevisionPrecision::Abbreviated {
        ui::warn(&format!(
            "this bundle records an abbreviated revision ({}); the host could not name \
             its head commit in full, so the revision is a prefix rather than an \
             immutable id.",
            manifest.source.commit
        ));
    }

    Ok(())
}

/// Refuse manifest paths that could escape the bundle.
///
/// Until the bundle signature is checked, every path in the manifest is
/// attacker-suppliable; joining one containing `..` (or an absolute path)
/// would make the verifier read — and echo the hash of — arbitrary files.
fn ensure_inside_bundle(path: &str) -> Result<()> {
    use std::path::Component;
    let ok = !path.is_empty()
        && std::path::Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
    if !ok {
        bail!("manifest path {path:?} is not a plain relative path inside the bundle");
    }
    Ok(())
}

/// Load the evidence directory into the structure the chain walker wants.
///
/// Objects are keyed by their *computed* ids — the filenames are convenience,
/// not authority, so a renamed or swapped file changes nothing.
fn load_evidence(evidence_dir: &std::path::Path) -> Result<Evidence> {
    let commit = std::fs::read(evidence_dir.join("commit.obj"))
        .with_context(|| "reading evidence/commit.obj".to_string())?;

    let mut trees = HashMap::new();
    let tree_dir = evidence_dir.join("tree");
    if let Ok(entries) = std::fs::read_dir(&tree_dir) {
        for e in entries.flatten() {
            let bytes = std::fs::read(e.path())
                .with_context(|| format!("reading {}", e.path().display()))?;
            let oid = amf_verify::git::object_id(amf_verify::git::ObjectKind::Tree, &bytes);
            trees.insert(oid, bytes);
        }
    }

    let mut pointers = HashMap::new();
    let lfs_dir = evidence_dir.join("lfs");
    if let Ok(entries) = std::fs::read_dir(&lfs_dir) {
        for e in entries.flatten() {
            let bytes = std::fs::read(e.path())
                .with_context(|| format!("reading {}", e.path().display()))?;
            let oid = amf_verify::git::object_id(amf_verify::git::ObjectKind::Blob, &bytes);
            pointers.insert(oid, bytes);
        }
    }

    Ok(Evidence {
        commit,
        trees,
        pointers,
    })
}

/// Accept either a bundle directory or a drive holding many.
fn find_bundles(path: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    if path.join(layout::MANIFEST_FILE).exists() {
        return Ok(vec![path.to_path_buf()]);
    }
    let root = if path.join(layout::BUNDLES_SUBPATH).is_dir() {
        path.join(layout::BUNDLES_SUBPATH)
    } else {
        path.to_path_buf()
    };
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() && p.join(layout::MANIFEST_FILE).exists() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}
