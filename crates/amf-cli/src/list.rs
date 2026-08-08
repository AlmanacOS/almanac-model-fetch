//! `amf list` — inventory the bundles on a drive.

use anyhow::Result;

use amf_bundle::{layout, Manifest};

use crate::ui;
use crate::ListArgs;

pub fn run(args: ListArgs) -> Result<()> {
    let root = if args.path.join(layout::BUNDLES_SUBPATH).is_dir() {
        args.path.join(layout::BUNDLES_SUBPATH)
    } else {
        args.path.clone()
    };

    let mut rows = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for e in entries.flatten() {
            let manifest_path = e.path().join(layout::MANIFEST_FILE);
            let Ok(bytes) = std::fs::read(&manifest_path) else {
                continue;
            };
            match Manifest::from_json(&bytes) {
                Ok(m) => rows.push(m),
                // A directory that looks like a bundle but has an unreadable
                // manifest is worth mentioning rather than silently hiding.
                Err(err) => ui::warn(&format!("{}: {err}", manifest_path.display())),
            }
        }
    }

    if rows.is_empty() {
        ui::info(&format!("no bundles at {}", root.display()));
        return Ok(());
    }

    rows.sort_by(|a, b| (&a.source.repo, &a.variant).cmp(&(&b.source.repo, &b.variant)));

    ui::info(&format!("{} bundle(s) at {}", rows.len(), root.display()));
    ui::info("");
    for m in &rows {
        ui::info(&format!("{}  :{}", m.source.repo, m.variant));
        ui::info(&format!(
            "    {} in {} file(s), fetched {} from {}",
            ui::human_bytes(m.total_size()),
            m.files.len(),
            m.fetched_at,
            m.source.host,
        ));
        ui::info(&format!("    commit {}", m.source.commit));
        ui::info(&format!(
            "    upstream signature: {}",
            describe_signature(&m.verification.upstream_signature)
        ));
        ui::info("");
    }
    Ok(())
}

/// Describe a signature status in words that do not overclaim.
fn describe_signature(status: &amf_bundle::SignatureStatus) -> String {
    use amf_bundle::SignatureStatus as S;
    match status {
        S::Verified { fingerprint } => format!("verified against {fingerprint}"),
        S::SignaturePresentKeyUnpinned { .. } => {
            "present, but not checked (no pinned key)".into()
        }
        S::SignaturePresentKeyMismatch { .. } => "MISMATCH — treat as suspect".into(),
        S::Unsigned { reason } => format!("none ({reason})"),
    }
}
