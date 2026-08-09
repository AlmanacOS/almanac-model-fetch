//! Cross-source corroboration — asking the *other* host whether it publishes
//! the same hashes.
//!
//! Two independent hosts agreeing on a file's SHA-256 is cheap, real evidence:
//! a substitution would have to have happened in both places. It is deliberately
//! never blocking. A miss is the *expected* case for an operator who chose
//! ModelScope precisely because HuggingFace is unreachable, so an unreachable
//! counterpart is recorded without so much as a warning.
//!
//! A mismatch is different, and is treated differently — see [`run`].

use std::time::Duration;

use amf_bundle::{CorroboratedFile, Corroboration, CorroborationConflict};
use amf_source::{RepoSpec, SourceKind, Variant};

/// How long the counterpart host gets before we give up on it.
///
/// No retries. Corroboration is a bonus check on the way to a download that may
/// take an hour; it must never be the reason a fetch feels slow.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Where to look for the same model on the other host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: SourceKind,
    pub repo: String,
}

/// Decide which host and repo to corroborate against.
///
/// The default is the counterpart host under the *identical* `org/name`, which
/// is how mirrors of the repos this tool targets are actually named. There is no
/// built-in alias table: a stale mapping would corroborate against the wrong
/// model, and a false assurance is worse than none. An operator who knows the
/// mirror's real name passes `--corroborate-with`.
pub fn target(
    fetched_from: SourceKind,
    repo: &str,
    override_spec: Option<&str>,
) -> Result<Target, String> {
    match override_spec {
        Some(raw) => parse_override(raw),
        None => Ok(Target {
            kind: match fetched_from {
                SourceKind::HuggingFace => SourceKind::ModelScope,
                SourceKind::ModelScope => SourceKind::HuggingFace,
            },
            repo: repo.to_string(),
        }),
    }
}

/// Parse `--corroborate-with <host>:<org/name>`.
fn parse_override(raw: &str) -> Result<Target, String> {
    let (host, repo) = raw
        .split_once(':')
        .ok_or_else(|| format!("--corroborate-with expects <host>:<org/name>, got {raw:?}"))?;
    let kind: SourceKind = host
        .trim()
        .parse()
        .map_err(|e| format!("--corroborate-with: {e}"))?;
    let repo = repo.trim();
    // Reuse the repo-spec parser so a malformed id fails here rather than as a
    // confusing 404 later.
    RepoSpec::parse(repo).map_err(|e| format!("--corroborate-with: {e}"))?;
    Ok(Target {
        kind,
        repo: repo.to_string(),
    })
}

/// Ask the counterpart host about every file in the variant.
///
/// Never returns an error: every failure mode is a recorded [`Corroboration`],
/// because a fetch must not fail on account of a host it was not fetching from.
pub async fn run(
    client: &amf_source::reqwest::Client,
    target: &Target,
    variant: &Variant,
) -> Corroboration {
    let host = target.kind.to_string();

    let backend = match amf_source::backend(target.kind, client.clone()) {
        Ok(b) => b,
        Err(e) => return unavailable(&host, &target.repo, &e.to_string()),
    };

    let spec = match RepoSpec::parse(&target.repo) {
        Ok(s) => s,
        Err(e) => return unavailable(&host, &target.repo, &e.to_string()),
    };

    // Resolve on the *other* host independently. Its head commit will not equal
    // ours — these are separate repositories that happen to mirror the same
    // artifacts — so only content hashes are ever compared, never object ids.
    let their_rev = match tokio::time::timeout(TIMEOUT, backend.resolve(&spec)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return unavailable(&host, &target.repo, &e.to_string()),
        Err(_) => return unavailable(&host, &target.repo, "timed out"),
    };

    let their_files = match tokio::time::timeout(TIMEOUT, backend.list_files(&their_rev)).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => return unavailable(&host, &target.repo, &e.to_string()),
        Err(_) => return unavailable(&host, &target.repo, "timed out"),
    };

    let mut matched = Vec::new();
    let mut conflicts = Vec::new();
    let mut missing = 0usize;

    for file in &variant.files {
        let Some(ours) = file.sha256.as_deref() else {
            continue;
        };
        // Prefer the identical path; fall back to the file name, because mirrors
        // reorganise directories and the artifact is the same artifact either
        // way. An *ambiguous* basename — the same name under two quant
        // directories — is treated as no match rather than resolved by listing
        // order, which would otherwise compare two different quantisations and
        // raise a disagreement alarm about nothing.
        let theirs = match their_files.iter().find(|f| f.path == file.path) {
            Some(exact) => exact.sha256.as_deref(),
            None => {
                let mut by_name = their_files
                    .iter()
                    .filter(|f| file_name(&f.path) == file_name(&file.path));
                match (by_name.next(), by_name.next()) {
                    (Some(only), None) => only.sha256.as_deref(),
                    _ => None,
                }
            }
        };

        match theirs {
            Some(t) if t.eq_ignore_ascii_case(ours) => matched.push(CorroboratedFile {
                path: file.path.clone(),
                sha256: ours.to_ascii_lowercase(),
            }),
            Some(t) => conflicts.push(CorroborationConflict {
                path: file.path.clone(),
                ours: ours.to_ascii_lowercase(),
                theirs: t.to_ascii_lowercase(),
            }),
            None => missing += 1,
        }
    }

    if !conflicts.is_empty() {
        return Corroboration::Mismatch {
            host,
            repo: target.repo.clone(),
            conflicts,
            matched,
        };
    }
    if matched.is_empty() {
        return unavailable(
            &host,
            &target.repo,
            &format!(
                "the repository exists but published no matching file names ({missing} unmatched)"
            ),
        );
    }
    Corroboration::Match {
        host,
        repo: target.repo.clone(),
        files: matched,
    }
}

fn unavailable(host: &str, repo: &str, reason: &str) -> Corroboration {
    Corroboration::Unavailable {
        host: host.to_string(),
        reason: format!("{repo}: {reason}"),
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_counterpart_host_under_the_same_name() {
        let t = target(SourceKind::HuggingFace, "unsloth/Qwen3-8B-GGUF", None).unwrap();
        assert_eq!(t.kind, SourceKind::ModelScope);
        assert_eq!(t.repo, "unsloth/Qwen3-8B-GGUF");

        let back = target(SourceKind::ModelScope, "unsloth/Qwen3-8B-GGUF", None).unwrap();
        assert_eq!(back.kind, SourceKind::HuggingFace);
    }

    #[test]
    fn parses_an_explicit_override() {
        let t = target(
            SourceKind::HuggingFace,
            "unsloth/Qwen3-8B-GGUF",
            Some("modelscope:AI-ModelScope/Qwen3-8B-GGUF"),
        )
        .unwrap();
        assert_eq!(t.kind, SourceKind::ModelScope);
        assert_eq!(t.repo, "AI-ModelScope/Qwen3-8B-GGUF");
    }

    #[test]
    fn rejects_a_malformed_override_rather_than_guessing() {
        assert!(target(SourceKind::HuggingFace, "a/b", Some("no-colon")).is_err());
        assert!(target(SourceKind::HuggingFace, "a/b", Some("nosuchhost:a/b")).is_err());
        // A repo id that is not `org/name` must fail here, not as a 404 later.
        assert!(target(SourceKind::HuggingFace, "a/b", Some("modelscope:justaname")).is_err());
    }

    #[test]
    fn compares_by_file_name_so_mirrors_may_reorganise_directories() {
        assert_eq!(
            file_name("UD-IQ1_S/model-00001-of-00003.gguf"),
            "model-00001-of-00003.gguf"
        );
        assert_eq!(file_name("model.gguf"), "model.gguf");
    }
}
