//! `amf verify` — re-verify a bundle with no network.
//!
//! This is the command the airgapped operator runs. It needs no network, no
//! keyserver, and no access to HuggingFace: everything it checks is either in
//! the bundle or in a public key provisioned out of band.

use anyhow::{anyhow, bail, Context, Result};

use amf_bundle::{layout, Manifest};

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

    let mut failed = 0usize;
    for bundle in &bundles {
        match verify_one(bundle, public_key.as_deref()) {
            Ok(()) => {}
            Err(e) => {
                failed += 1;
                ui::error(&format!("{}: {e:#}", bundle.display()));
            }
        }
    }

    if failed > 0 {
        bail!("{failed} of {} bundle(s) failed verification", bundles.len());
    }
    ui::info(&format!("{} bundle(s) verified", bundles.len()));
    Ok(())
}

fn verify_one(bundle: &std::path::Path, public_key: Option<&str>) -> Result<()> {
    ui::step(&format!("verifying {}", bundle.display()));

    let manifest_path = bundle.join(layout::MANIFEST_FILE);
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = Manifest::from_json(&manifest_bytes)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    // 1. Every file must hash to what the manifest says.
    let model_dir = bundle.join(layout::MODEL_DIR);
    for entry in &manifest.files {
        let path = model_dir.join(&entry.path);
        let actual = amf_verify::hash_file(&path)
            .map_err(|e| anyhow!("hashing {}: {e}", path.display()))?;
        if !actual.eq_ignore_ascii_case(&entry.sha256) {
            bail!(
                "{} does not match the manifest (expected {}, got {actual})",
                entry.path,
                entry.sha256
            );
        }
    }
    ui::info(&format!("  {} file(s) match the manifest", manifest.files.len()));

    // 2. The manifest's own digest must match the files it lists — otherwise a
    //    file could be added or removed without the per-file checks noticing.
    let recomputed = amf_bundle::compute_bundle_digest(&manifest.files);
    if !recomputed.eq_ignore_ascii_case(&manifest.bundle_digest) {
        bail!(
            "bundle digest mismatch: manifest says {}, files give {recomputed}",
            manifest.bundle_digest
        );
    }

    // 3. The signature, if we were given a key to check it with.
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
            ui::info("  signature verified");
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

    // 4. Report, without overclaiming, what upstream verification was recorded.
    if manifest.verification.upstream_signature.is_mismatch() {
        ui::alarm(
            "UPSTREAM SIGNATURE MISMATCH RECORDED",
            "This bundle was fetched when the upstream signing key did not match the \
             pinned one. Treat this artifact as suspect.",
        );
    }
    if let amf_bundle::Corroboration::Mismatch { host, ours, theirs } = &manifest.corroboration {
        ui::alarm(
            "CROSS-SOURCE HASH DISAGREEMENT RECORDED",
            &format!("{host} published {theirs} but this bundle holds {ours}."),
        );
    }

    Ok(())
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
