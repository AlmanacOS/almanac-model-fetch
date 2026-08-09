//! `amf fetch` — the main pipeline.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use amf_bundle::{
    layout, manifest, BundleWriter, ContentHashStatus, Corroboration, Existing, FileEntry,
    Manifest, SignatureStatus, SourceRecord, Tool, Verification,
};
use amf_source::{download, git_http, RepoSpec, Source, SourceKind, Variant};
use amf_verify::chain::Evidence;
use amf_verify::git::ObjectKind;

use crate::trust::{Observation, TrustStore};
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

/// Everything the evidence capture produced for one model.
struct CapturedEvidence {
    /// Raw signed commit object.
    commit: Vec<u8>,
    /// Tree objects by oid.
    trees: HashMap<String, Vec<u8>>,
    /// LFS pointer blobs by *repo path* (keyed by path for writing; the chain
    /// walk looks them up by oid via [`Evidence`]).
    pointers_by_path: HashMap<String, Vec<u8>>,
    /// Chain-derived expected hash per repo path.
    chain_hashes: HashMap<String, String>,
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
    if !revision.precision.is_exact() {
        // Say this once, plainly. A short id is fine against accident and
        // useless against an adversary who can grind commits, and the operator
        // is the one who gets to decide whether that matters here.
        ui::warn(&format!(
            "{} could not name its head commit in full; this bundle records the \
             abbreviated id {}. To pin exactly, fetch {}@<full-40-hex>.",
            backend.kind(),
            revision.commit,
            revision.repo,
        ));
    }

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

    // 3. Capture the evidence chain BEFORE downloading: signed commit, trees,
    //    LFS pointers. The chain-derived hash then anchors the download itself,
    //    and any disagreement with the REST API surfaces before 40 GB move.
    let captured = capture_evidence(backend, client, &revision, variant).await;
    let captured = match captured {
        Ok(c) => {
            // Cross-check every chain-derived hash against what the REST API
            // reported. These come over the same TLS origin but through
            // different code paths; disagreement means either upstream is
            // inconsistent or something is interfering — never fetch through it.
            for file in &variant.files {
                let rest = file.sha256.as_deref().unwrap_or_default();
                let chain = c
                    .chain_hashes
                    .get(&file.path)
                    .map(String::as_str)
                    .unwrap_or_default();
                if !rest.eq_ignore_ascii_case(chain) {
                    ui::alarm(
                        "SIGNED TREE AND REST API DISAGREE",
                        &format!(
                            "{}: the GPG-signed git tree commits to {chain} but the \
                             REST API reports {rest}. One of them is wrong, and \
                             there is no safe way to pick. Aborting this fetch.",
                            file.path
                        ),
                    );
                    bail!("evidence chain and REST API disagree on {}", file.path);
                }
            }
            // Do not call an unsigned commit "signed": on ModelScope this line
            // would otherwise describe the exact property that host lacks.
            let signed = amf_verify::git::parse_commit(&c.commit)
                .map(|p| p.is_signed())
                .unwrap_or(false);
            ui::info(&format!(
                "  evidence: {} + {} tree(s) + {} pointer(s), chain matches API",
                if signed {
                    "signed commit"
                } else {
                    "commit (unsigned)"
                },
                c.trees.len(),
                c.pointers_by_path.len(),
            ));
            Some(c)
        }
        Err(e) => {
            ui::warn(&format!(
                "could not capture the git evidence chain ({e:#}); continuing with \
                 REST-reported hashes only. This bundle will not be re-derivable \
                 offline."
            ));
            None
        }
    };

    // 4. Tier 2: what does the signature on that commit actually establish?
    let upstream_signature = match &captured {
        Some(c) => {
            assess_upstream_signature(backend.kind(), &c.commit, args.trust_store.as_deref())?
        }
        // No commit object was retrieved, so no finding about a signature was
        // made — not "present", and not "unsigned" either, even for a host we
        // are confident never signs. Both of those are claims about a specific
        // commit, and this fetch examined none.
        None => SignatureStatus::Unknown {
            reason: format!(
                "evidence capture from {} failed, so no commit object was examined",
                backend.kind()
            ),
        },
    };
    if upstream_signature.is_mismatch() {
        // The operator explicitly pinned a key, and the signature fails against
        // it. That is the strongest attack signal this tool can see, and it is
        // not overridable with --force: if the host genuinely rotated its key,
        // the correct path is to re-confirm out of band and re-pin, not to
        // shrug past a failed verification.
        bail!(
            "the upstream signature does not verify against the pinned key. Refusing \
             to write a bundle. If you have re-confirmed the new key out of band, \
             re-pin it: `amf trust remove {kind}` then `amf trust add {kind} <key.asc>`.",
            kind = backend.kind(),
        );
    }
    if args.require_signature && !upstream_signature.is_verified() {
        bail!(
            "--require-signature was given but the upstream signature could not be \
             verified (status: {upstream_signature:?}). Pin HuggingFace's public key \
             with `amf trust add huggingface <key.asc>` to enable verification."
        );
    }

    // 5. Work out where the bundle goes, and whether it is already there.
    let files: Vec<FileEntry> = variant
        .files
        .iter()
        .map(|f| FileEntry {
            path: f.file_name().to_string(),
            sha256: f.sha256.clone().unwrap_or_default(),
            size: f.size,
            source_path: if f.path != f.file_name() {
                Some(f.path.clone())
            } else {
                None
            },
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

    // 6. Corroborate against the other host — after the already-present check,
    //    so re-running over a populated USB stick does not make a round trip to
    //    a host we are not fetching from, but before the download, because a
    //    disagreement is worth knowing about now and not at the end of an hour
    //    of transfer.
    let hashed_files = variant.files.iter().filter(|f| f.sha256.is_some()).count();
    let corroboration = if args.no_corroborate {
        Corroboration::Skipped
    } else {
        match crate::corroborate::target(
            backend.kind(),
            &revision.repo.to_string(),
            args.corroborate_with.as_deref(),
        ) {
            Ok(t) => {
                let result = crate::corroborate::run(client, &t, variant).await;
                report_corroboration(&result, hashed_files);
                result
            }
            Err(e) => bail!("{e}"),
        }
    };

    // A partial confirmation is not a confirmation: a mirror that happens to
    // publish one of three shards under a matching name tells us nothing about
    // the other two, so the gate demands the whole variant.
    let corroborated = matches!(
        &corroboration,
        Corroboration::Match { files, .. } if files.len() == hashed_files
    );
    if args.require_corroboration && !corroborated {
        bail!(
            "--require-corroboration was given but the other host did not confirm \
             all {hashed_files} file(s) (result: {corroboration:?}). Point at the \
             mirror explicitly with --corroborate-with <host>:<org/name> if it \
             exists under another name."
        );
    }

    // 7. Preflight the destination *before* downloading anything.
    preflight(args, variant)?;

    // 8. Download, verifying as we stream — against the chain-derived hash when
    //    we have one (it equals the REST hash; the cross-check above enforced
    //    that), so the bytes are anchored to the signed tree.
    let writer = BundleWriter::create(bundle_path.clone()).map_err(|e| anyhow!("{e}"))?;
    let model_dir = writer.model_dir();
    let endpoints = backend.endpoints();
    let repo = revision.repo.to_string();

    for file in &variant.files {
        let expected = file
            .sha256
            .as_deref()
            .ok_or_else(|| anyhow!("{} has no upstream hash", file.path))?;
        let url = endpoints.file_url(&repo, &revision.commit, &file.path);
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

    // 9. Write the evidence into the bundle and digest it for the manifest.
    let mut evidence_files: Vec<FileEntry> = Vec::new();
    if let Some(c) = &captured {
        let mut write_evidence = |rel: String, bytes: &[u8]| -> Result<()> {
            writer.write(&rel, bytes).map_err(|e| anyhow!("{e}"))?;
            evidence_files.push(FileEntry {
                path: rel,
                sha256: sha256_hex(bytes),
                size: bytes.len() as u64,
                source_path: None,
            });
            Ok(())
        };

        write_evidence(format!("{}/commit.obj", layout::EVIDENCE_DIR), &c.commit)?;
        if let Ok(commit) = amf_verify::git::parse_commit(&c.commit) {
            if let Some(sig) = commit.gpgsig {
                write_evidence(
                    format!("{}/commit.sig.asc", layout::EVIDENCE_DIR),
                    sig.as_bytes(),
                )?;
            }
        }
        for (oid, tree) in &c.trees {
            write_evidence(format!("{}/tree/{oid}.obj", layout::EVIDENCE_DIR), tree)?;
        }
        // Pointer files are named by blob oid, like the trees: repo basenames
        // can collide across subdirectories (which would silently overwrite an
        // evidence file and leave the manifest listing conflicting digests for
        // one path), and identical blobs dedupe naturally. The verifier keys
        // objects by recomputed id, so the filename carries no authority.
        let pointer_blobs: std::collections::BTreeMap<String, &[u8]> = c
            .pointers_by_path
            .values()
            .map(|p| {
                (
                    amf_verify::git::object_id(ObjectKind::Blob, p),
                    p.as_slice(),
                )
            })
            .collect();
        for (oid, pointer) in &pointer_blobs {
            write_evidence(
                format!("{}/lfs/{oid}.pointer", layout::EVIDENCE_DIR),
                pointer,
            )?;
        }
        evidence_files.sort_by(|a, b| a.path.cmp(&b.path));
    }

    // 10. Write and sign the manifest.
    let manifest = Manifest {
        schema_version: manifest::SCHEMA_VERSION,
        tool: Tool::default(),
        source: SourceRecord {
            host: backend.kind().to_string(),
            repo: revision.repo.to_string(),
            // Derived from the id's own shape rather than passed alongside it,
            // so the two can never disagree.
            revision_precision: amf_bundle::RevisionPrecision::of(&revision.commit),
            commit: revision.commit.clone(),
            requested_revision: revision.requested.clone(),
        },
        variant: variant.label.clone(),
        bundle_digest: bundle_digest.clone(),
        files,
        fetched_at: amf_bundle::now_rfc3339(),
        verification: Verification {
            content_hash: ContentHashStatus::Verified {
                via: if captured.is_some() {
                    "lfs_pointer".into()
                } else {
                    "rest_api".into()
                },
            },
            upstream_signature,
            // `RestOnly` is unreachable today: both hosts serve git, so a
            // capture either yields the full chain or fails outright. It is the
            // state a host with no git endpoint would produce (ARCHITECTURE.md §7),
            // and `HostEndpoints::git_repo_url` returning `None` is what would
            // select it.
            evidence: if captured.is_some() {
                amf_bundle::EvidenceKind::Chain
            } else {
                amf_bundle::EvidenceKind::Absent
            },
        },
        corroboration,
        evidence_files,
    };

    let manifest_bytes = manifest.to_canonical_json().map_err(|e| anyhow!("{e}"))?;
    writer
        .write(layout::MANIFEST_FILE, &manifest_bytes)
        .map_err(|e| anyhow!("{e}"))?;

    if let Some(key) = &args.key {
        let comment = amf_verify::signing::trusted_comment(
            &manifest.source.repo,
            &manifest.variant,
            &bundle_digest,
        );
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

/// Report what the other host said.
///
/// A mismatch is loud but not fatal, and the asymmetry with the chain-vs-REST
/// check is deliberate. That check catches one host contradicting *itself*,
/// which is always wrong, so it aborts. Two independent hosts can legitimately
/// differ — a re-quantisation or a re-upload produces different bytes for the
/// same name — so the operator is told prominently and decides. Anyone who wants
/// it to gate has `--require-corroboration`.
///
/// `checked` is how many files we *asked* about, so a partial confirmation reads
/// as one. "the same hash for 1 file(s)" on a three-shard variant would otherwise
/// look like full agreement.
fn report_corroboration(result: &Corroboration, checked: usize) {
    match result {
        Corroboration::Match { host, files, .. } => {
            if files.len() == checked {
                ui::info(&format!(
                    "  corroborated: {host} publishes the same hash for all {checked} file(s)"
                ));
            } else {
                ui::warn(&format!(
                    "{host} publishes the same hash for only {} of {checked} file(s); it \
                     named nothing matching the rest, so they rest on one host alone.",
                    files.len()
                ));
            }
        }
        Corroboration::Mismatch {
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
                "TWO HOSTS DISAGREE ABOUT THIS MODEL",
                &format!(
                    "{host}/{repo} publishes different bytes for {} of {checked} file(s) \
                     checked:\n{detail}\n\n  This is not automatically an attack — a \
                     re-quantisation or re-upload can do it — but it means the two \
                     copies are not the same artifact. The bundle records the \
                     disagreement.",
                    conflicts.len(),
                ),
            );
        }
        // Silent by design: an operator who chose ModelScope because HuggingFace
        // is blocked would otherwise get a warning on every single fetch for a
        // condition they already know about and cannot fix.
        Corroboration::Unavailable { .. } | Corroboration::Skipped => {}
    }
}

/// Fetch the signed commit, its trees, and each file's LFS pointer, then walk
/// the chain to derive every expected hash.
async fn capture_evidence(
    backend: &dyn Source,
    client: &amf_source::reqwest::Client,
    revision: &amf_source::Revision,
    variant: &Variant,
) -> Result<CapturedEvidence> {
    // Commit and trees over git smart-HTTP, blobs filtered. A host with no git
    // endpoint says so here rather than at request time, and the caller degrades
    // to REST-reported hashes.
    let repo_url = backend
        .endpoints()
        .git_repo_url(&revision.repo.to_string())
        .ok_or_else(|| anyhow!("{} serves no git endpoint", backend.kind()))?;
    let objects = git_http::fetch_commit_and_trees(client, &repo_url, &revision.commit)
        .await
        .map_err(|e| anyhow!("git fetch: {e}"))?;

    let mut commit_bytes: Option<Vec<u8>> = None;
    let mut trees: HashMap<String, Vec<u8>> = HashMap::new();
    for obj in objects {
        match obj.kind {
            ObjectKind::Commit if obj.oid == revision.commit => {
                commit_bytes = Some(obj.data);
            }
            ObjectKind::Tree => {
                trees.insert(obj.oid, obj.data);
            }
            _ => {}
        }
    }
    let commit = commit_bytes
        .ok_or_else(|| anyhow!("the pack did not contain commit {}", revision.commit))?;

    // LFS pointers per file over plain HTTPS (/raw/ serves the pointer text).
    let mut pointers_by_path = HashMap::new();
    let mut evidence = Evidence {
        commit: commit.clone(),
        trees: trees.clone(),
        ..Default::default()
    };
    for file in &variant.files {
        // How a host serves pointer text differs (a `/raw/` path on one, a JSON
        // envelope on the other), so the backend owns the retrieval. Whatever
        // comes back is checked against the blob id in the signed tree below,
        // which is what makes trusting the transport unnecessary.
        let body = backend
            .fetch_pointer(revision, &file.path)
            .await
            .map_err(|e| anyhow!("fetching pointer for {}: {e}", file.path))?;
        if !amf_verify::lfs::looks_like_pointer(&body) {
            bail!("{} did not serve an LFS pointer", file.path);
        }
        let oid = amf_verify::git::object_id(ObjectKind::Blob, &body);
        evidence.pointers.insert(oid, body.clone());
        pointers_by_path.insert(file.path.clone(), body);
    }

    // Walk the chain for every file. This verifies each object against the id
    // its parent named, so a bad tree or swapped pointer fails here.
    let mut chain_hashes = HashMap::new();
    for file in &variant.files {
        let result = amf_verify::derive_expected_hash(&evidence, &revision.commit, &file.path)
            .map_err(|e| anyhow!("chain derivation for {}: {e}", file.path))?;
        if result.size != file.size {
            bail!(
                "{}: signed tree says {} bytes, REST API says {}",
                file.path,
                result.size,
                file.size
            );
        }
        chain_hashes.insert(file.path.clone(), result.sha256);
    }

    Ok(CapturedEvidence {
        commit,
        trees,
        pointers_by_path,
        chain_hashes,
    })
}

/// Tier-2 assessment of the captured commit, per the continuity-vs-verification
/// split: a pinned key gets real verification; otherwise the issuer fingerprint
/// is recorded as an observation and the status never claims more than that.
fn assess_upstream_signature(
    kind: SourceKind,
    raw_commit: &[u8],
    trust_store: Option<&std::path::Path>,
) -> Result<SignatureStatus> {
    let commit = amf_verify::git::parse_commit(raw_commit).map_err(|e| anyhow!("{e}"))?;
    let Some(armored_sig) = commit.gpgsig.as_deref() else {
        // Worth stating rather than leaving as silence: an operator reading this
        // output should be able to see that Tier 2 established nothing here,
        // not infer it from the absence of a line.
        ui::info(&format!(
            "  upstream signature: none — the {kind} commit is unsigned, so this \
             bundle rests on the content chain plus its own signature"
        ));
        return Ok(SignatureStatus::Unsigned {
            reason: format!("the {kind} commit carries no signature"),
        });
    };

    let issuer = amf_verify::pgpsig::issuer_fingerprint(armored_sig).ok();
    let issuer_id = issuer.as_ref().and_then(|i| i.best().map(str::to_string));

    // Honor the same override `amf trust` takes, so a pin made with
    // --trust-store is actually consulted here rather than silently missed.
    let store_path = trust_store
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(TrustStore::default_path);
    let mut store = TrustStore::load(&store_path)?;
    let host = kind.to_string();

    if let Some(pinned) = store.pinned_key(&host) {
        // A key is pinned: verify for real. Any failure here is a mismatch, and
        // a mismatch is the loudest thing this tool can say.
        match amf_verify::pgpsig::verify_commit_signature(raw_commit, &pinned.armored) {
            Ok(v) => {
                ui::info(&format!(
                    "  upstream signature VERIFIED against pinned key {}",
                    v.fingerprint
                ));
                return Ok(SignatureStatus::Verified {
                    fingerprint: v.fingerprint,
                });
            }
            Err(_) => {
                ui::alarm(
                    "UPSTREAM SIGNATURE DOES NOT MATCH THE PINNED KEY",
                    &format!(
                        "The commit's signature failed verification against the pinned \
                         key {} for {host}. Either the host rotated its key, or someone \
                         is signing commits who should not be. Do not trust this fetch \
                         until you have re-confirmed the key out of band.",
                        pinned.fingerprint
                    ),
                );
                return Ok(SignatureStatus::SignaturePresentKeyMismatch {
                    expected_fingerprint: pinned.fingerprint.clone(),
                    actual_fingerprint: issuer_id,
                });
            }
        }
    }

    // No pinned key: observation only.
    if let Some(fp) = &issuer_id {
        match store.record_observation(&host, fp) {
            Observation::First => ui::info(&format!(
                "  upstream signature present; claimed signer {fp} recorded \
                 (first sighting, not verified — no key is pinned for {host})"
            )),
            Observation::Consistent => {}
            Observation::Changed { previous } => ui::alarm(
                "CLAIMED SIGNING KEY CHANGED",
                &format!(
                    "Signatures from {host} previously claimed key {previous}; this \
                     commit claims {fp}. Without a pinned key this cannot be \
                     verified either way — it may be a legitimate rotation or an \
                     attack. Confirm out of band before trusting this fetch."
                ),
            ),
        }
        store.save(&store_path)?;
    }

    Ok(SignatureStatus::SignaturePresentKeyUnpinned {
        fingerprint: issuer_id,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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
