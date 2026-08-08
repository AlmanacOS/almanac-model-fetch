//! `amf fetch` — the main pipeline.

use anyhow::{anyhow, bail, Context, Result};

use amf_bundle::{
    layout, manifest, BundleWriter, C2paRecord, ContentHashStatus, Corroboration, Existing,
    FileEntry, Manifest, SignatureStatus, SourceRecord, Tool, Verification,
};
use amf_source::{download, RepoSpec, Source, SourceKind, Variant};

use crate::ui;
use crate::FetchArgs;

pub async fn run(args: FetchArgs) -> Result<()> {
    let source_kind: SourceKind = args
        .source
        .parse()
        .map_err(|e| anyhow!("{e}"))
        .context("parsing --source")?;

    if source_kind == SourceKind::ModelScope && args.require_signature {
        // ModelScope does not sign commits at all, so this combination can never
        // be satisfied. Saying so up front beats failing after a 40 GB download.
        bail!(
            "--require-signature cannot be satisfied with --source modelscope: \
             ModelScope does not sign its commits. Use HuggingFace, or drop \
             --require-signature and accept that this bundle rests on TLS plus \
             the fetcher's own signature."
        );
    }

    let specs: Vec<RepoSpec> = args
        .specs
        .iter()
        .map(|s| RepoSpec::parse(s).map_err(|e| anyhow!("{e}")))
        .collect::<Result<_>>()?;

    let client = amf_source::http_client(crate::USER_AGENT).map_err(|e| anyhow!("{e}"))?;
    let backend = amf_source::backend(source_kind, client.clone()).map_err(|e| anyhow!("{e}"))?;

    std::fs::create_dir_all(&args.usb)
        .with_context(|| format!("creating destination {}", args.usb.display()))?;

    let mut failures = 0usize;
    let total = specs.len();

    for (i, spec) in specs.iter().enumerate() {
        if total > 1 {
            ui::step(&format!("[{}/{}] {}", i + 1, total, spec));
        }
        match fetch_one(&args, &*backend, &client, spec).await {
            Ok(Outcome::Written(path)) => {
                ui::info(&format!("  bundle: {}", path.display()));
            }
            Ok(Outcome::AlreadyPresent(path)) => {
                ui::info(&format!("  already present, skipped: {}", path.display()));
            }
            Err(e) => {
                failures += 1;
                ui::error(&format!("{spec}: {e:#}"));
            }
        }
    }

    if failures > 0 {
        bail!("{failures} of {total} model(s) failed");
    }
    Ok(())
}

enum Outcome {
    Written(std::path::PathBuf),
    AlreadyPresent(std::path::PathBuf),
}

async fn fetch_one(
    args: &FetchArgs,
    backend: &dyn Source,
    client: &amf_source::reqwest::Client,
    spec: &RepoSpec,
) -> Result<Outcome> {
    // 1. Pin the revision. Everything after this refers to an immutable commit.
    ui::step(&format!("resolving {spec}"));
    let revision = backend.resolve(spec).await.map_err(|e| {
        if e.is_unreachable() && backend.kind() == SourceKind::HuggingFace {
            anyhow!(
                "{e}\n\nIf HuggingFace is not reachable from this network, retry with \
                 --source modelscope. Note that ModelScope does not sign its commits, \
                 so that bundle will rest on TLS plus this tool's own signature."
            )
        } else {
            anyhow!("{e}")
        }
    })?;
    ui::info(&format!("  commit: {}", revision.commit));

    // 2. Pick a variant.
    let variants = backend
        .list_variants(&revision)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    if variants.is_empty() {
        bail!("no GGUF variants found in {}", revision.repo);
    }
    let wanted = args.variant.clone().or_else(|| spec.variant.clone());
    let variant = select_variant(&variants, wanted.as_deref(), args.yes)?;

    let missing = variant.missing_shards();
    if !missing.is_empty() {
        bail!(
            "variant {} is missing shard(s) {:?} upstream; refusing to fetch an \
             incomplete model",
            variant.label,
            missing
        );
    }
    if !variant.fully_verifiable() {
        bail!(
            "variant {} has files with no upstream hash; refusing to fetch what \
             cannot be verified",
            variant.label
        );
    }

    ui::info(&format!(
        "  variant: {} ({} file(s), {})",
        variant.label,
        variant.files.len(),
        ui::human_bytes(variant.total_size())
    ));

    // 3. Work out where it goes, and whether it is already there.
    let files: Vec<FileEntry> = variant
        .files
        .iter()
        .map(|f| FileEntry {
            path: f.file_name().to_string(),
            sha256: f.sha256.clone().unwrap_or_default(),
            size: f.size,
        })
        .collect();
    let bundle_digest = manifest::compute_bundle_digest(&files);
    let bundle_path = layout::bundle_path(
        &args.usb,
        &revision.repo.to_string(),
        &variant.label,
        &bundle_digest,
    );

    match layout::inspect_existing(&bundle_path, &bundle_digest) {
        Existing::IdenticalBundle => return Ok(Outcome::AlreadyPresent(bundle_path)),
        Existing::Conflict(why) => bail!("{why}"),
        Existing::Absent => {}
    }

    // 4. Preflight the destination *before* downloading anything.
    preflight(args, variant)?;

    // 5. Download, verifying as we stream.
    let writer = BundleWriter::create(bundle_path.clone()).map_err(|e| anyhow!("{e}"))?;
    let model_dir = writer.model_dir();

    for file in &variant.files {
        let expected = file
            .sha256
            .as_deref()
            .ok_or_else(|| anyhow!("{} has no upstream hash", file.path))?;
        let url = download::file_url(
            amf_source::hf::DEFAULT_ENDPOINT,
            &revision.repo.to_string(),
            &revision.commit,
            &file.path,
        );
        let dest = model_dir.join(file.file_name());

        let bar = ui::progress_bar(file.size, file.file_name());
        let cb = {
            let bar = bar.clone();
            move |done: u64, _total: u64| bar.set_position(done)
        };
        let got = download::download_verified(client, &url, &dest, expected, file.size, Some(&cb))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        bar.finish_and_clear();

        ui::info(&format!(
            "  verified {} ({}{})",
            file.file_name(),
            ui::human_bytes(got.bytes_written),
            if got.resumed { ", resumed" } else { "" }
        ));
    }

    // 6. Capture what evidence we can reach.
    let evidence = capture_evidence(client, &writer, &revision, variant).await;

    // 7. Write and sign the manifest.
    let manifest = Manifest {
        schema_version: manifest::SCHEMA_VERSION,
        tool: Tool::default(),
        source: SourceRecord {
            host: backend.kind().to_string(),
            repo: revision.repo.to_string(),
            commit: revision.commit.clone(),
            requested_revision: revision.requested.clone(),
        },
        variant: variant.label.clone(),
        bundle_digest: bundle_digest.clone(),
        files,
        fetched_at: amf_bundle::now_rfc3339(),
        verification: Verification {
            content_hash: ContentHashStatus::Verified {
                via: "rest_api".into(),
            },
            upstream_signature: upstream_signature_status(backend.kind()),
            evidence_captured: evidence,
        },
        corroboration: if args.no_corroborate {
            Corroboration::Skipped
        } else {
            Corroboration::Unavailable {
                host: "modelscope".into(),
                reason: "cross-source corroboration is not implemented yet".into(),
            }
        },
        c2pa: C2paRecord::Absent {
            searched: vec!["sidecar".into()],
        },
    };

    if args.require_signature && !manifest.verification.upstream_signature.is_verified() {
        bail!(
            "--require-signature was given but the upstream signature could not be \
             verified (status: {:?}). Refusing to write the bundle.",
            manifest.verification.upstream_signature
        );
    }

    let manifest_bytes = manifest.to_canonical_json().map_err(|e| anyhow!("{e}"))?;
    writer
        .write(layout::MANIFEST_FILE, &manifest_bytes)
        .map_err(|e| anyhow!("{e}"))?;

    if let Some(key) = &args.key {
        let comment =
            amf_verify::signing::trusted_comment(&manifest.source.repo, &manifest.variant, &bundle_digest);
        let sig = amf_verify::sign_bytes(key, None, &manifest_bytes, &comment)
            .map_err(|e| anyhow!("signing the manifest: {e}"))?;
        writer
            .write(layout::SIGNATURE_FILE, sig.as_bytes())
            .map_err(|e| anyhow!("{e}"))?;
        ui::info("  manifest signed");
    } else {
        ui::warn(
            "no --key given, so this bundle carries no signature of its own. The \
             airgapped side can check its contents against the manifest, but cannot \
             confirm who produced it.",
        );
    }

    let final_path = writer.finish().map_err(|e| anyhow!("{e}"))?;
    Ok(Outcome::Written(final_path))
}

/// Upstream signature status.
///
/// Capturing and checking the commit signature needs the raw git objects, which
/// requires a git smart-HTTP client this build does not have yet. Until then we
/// report exactly that rather than implying anything was checked.
fn upstream_signature_status(kind: SourceKind) -> SignatureStatus {
    match kind {
        SourceKind::HuggingFace => SignatureStatus::SignaturePresentKeyUnpinned {
            fingerprint: None,
        },
        SourceKind::ModelScope => SignatureStatus::Unsigned {
            reason: "ModelScope does not sign commits".into(),
        },
    }
}

/// Capture the LFS pointer blobs, which are reachable over plain HTTPS.
///
/// The full chain also wants the signed commit and the tree objects; those need
/// the git protocol and are not captured yet, so this returns false to keep the
/// manifest honest about how complete the evidence is.
async fn capture_evidence(
    client: &amf_source::reqwest::Client,
    writer: &BundleWriter,
    revision: &amf_source::Revision,
    variant: &Variant,
) -> bool {
    let mut captured_any = false;
    for file in &variant.files {
        let url = format!(
            "{}/{}/raw/{}/{}",
            amf_source::hf::DEFAULT_ENDPOINT,
            revision.repo,
            revision.commit,
            file.path
        );
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.bytes().await else { continue };
        if amf_verify::lfs::looks_like_pointer(&body) {
            let rel = format!("{}/lfs/{}.pointer", layout::EVIDENCE_DIR, file.file_name());
            if writer.write(&rel, &body).is_ok() {
                captured_any = true;
            }
        }
    }
    // Deliberately not `captured_any`: pointers alone are not the full chain.
    let _ = captured_any;
    false
}

fn preflight(args: &FetchArgs, variant: &Variant) -> Result<()> {
    let info = amf_fs::inspect(&args.usb).map_err(|e| anyhow!("{e}"))?;
    ui::info(&format!(
        "  destination: {} ({}, {} free)",
        info.mount_point.display(),
        info.kind,
        ui::human_bytes(info.available_bytes)
    ));

    match amf_fs::assess(&info, variant.total_size(), variant.largest_file()) {
        amf_fs::Suitability::Ok => Ok(()),
        amf_fs::Suitability::Warn(msg) => {
            ui::warn(&msg);
            Ok(())
        }
        amf_fs::Suitability::Refuse(msg) => {
            // --force deliberately does not apply: see amf_fs::assess.
            let _ = args.force;
            Err(anyhow!(msg))
        }
    }
}

fn select_variant<'a>(
    variants: &'a [Variant],
    wanted: Option<&str>,
    assume_yes: bool,
) -> Result<&'a Variant> {
    if let Some(label) = wanted {
        return variants
            .iter()
            .find(|v| v.label.eq_ignore_ascii_case(label))
            .ok_or_else(|| {
                let available: Vec<&str> = variants.iter().map(|v| v.label.as_str()).collect();
                anyhow!("no variant {label:?}; available: {}", available.join(", "))
            });
    }

    if assume_yes || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!(
            "no variant selected. Pass --variant, or use `org/name:VARIANT`. \
             Available: {}",
            variants
                .iter()
                .map(|v| v.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let items: Vec<String> = variants
        .iter()
        .map(|v| {
            format!(
                "{:<16} {:>10}{}",
                v.label,
                ui::human_bytes(v.total_size()),
                if v.is_sharded() {
                    format!("  ({} shards)", v.files.len())
                } else {
                    String::new()
                }
            )
        })
        .collect();

    let choice = dialoguer::Select::new()
        .with_prompt("Select a quantisation")
        .items(&items)
        .default(0)
        .interact()
        .context("selecting a variant")?;
    Ok(&variants[choice])
}
