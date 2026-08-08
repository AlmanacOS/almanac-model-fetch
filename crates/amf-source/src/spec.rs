//! Parsing for repo specs like `unsloth/Llama-3-8B-GGUF@a6adef13:Q4_K_M`.

use std::fmt;
use std::str::FromStr;

use crate::SourceError;

/// Which host a fetch targets.
///
/// HuggingFace is the default. ModelScope exists for operators who cannot reach
/// HuggingFace — primarily from mainland China — and must be selected
/// explicitly; the tool never silently fails over to it, because that would
/// change the trust properties of a fetch (HF signs its commits, ModelScope does
/// not) without the operator consciously accepting the downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    #[default]
    HuggingFace,
    ModelScope,
}

impl SourceKind {
    pub fn host(&self) -> &'static str {
        match self {
            SourceKind::HuggingFace => "huggingface.co",
            SourceKind::ModelScope => "modelscope.cn",
        }
    }

    /// Whether this host cryptographically signs its commits.
    pub fn signs_commits(&self) -> bool {
        match self {
            SourceKind::HuggingFace => true,
            SourceKind::ModelScope => false,
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceKind::HuggingFace => f.write_str("huggingface"),
            SourceKind::ModelScope => f.write_str("modelscope"),
        }
    }
}

impl FromStr for SourceKind {
    type Err = SourceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hf" | "huggingface" | "huggingface.co" => Ok(SourceKind::HuggingFace),
            "ms" | "modelscope" | "modelscope.cn" => Ok(SourceKind::ModelScope),
            other => Err(SourceError::BadSpec(format!(
                "unknown source {other:?}; expected \"hf\" or \"modelscope\""
            ))),
        }
    }
}

/// A repository identifier: `namespace/name`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoId {
    pub namespace: String,
    pub name: String,
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// A parsed `org/name[@revision][:variant]` spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSpec {
    pub repo: RepoId,
    /// A branch, tag, or commit SHA. Always resolved to an immutable commit SHA
    /// before anything is fetched.
    pub revision: Option<String>,
    /// The quantisation/variant label, if the operator pinned one.
    pub variant: Option<String>,
}

impl RepoSpec {
    pub fn parse(input: &str) -> Result<Self, SourceError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SourceError::BadSpec("empty repo spec".into()));
        }

        // Split off `@revision` and `:variant`. Neither a revision nor a variant
        // may contain '@' or ':', so scanning left to right after the repo path
        // is unambiguous. We accept the two orderings people actually type.
        let (repo_part, rest) = match trimmed.find(['@', ':']) {
            Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
            None => (trimmed, ""),
        };

        let mut revision = None;
        let mut variant = None;
        let mut cursor = rest;
        while !cursor.is_empty() {
            let marker = cursor.as_bytes()[0];
            let body = &cursor[1..];
            let end = body.find(['@', ':']).unwrap_or(body.len());
            let value = &body[..end];
            cursor = &body[end..];

            if value.is_empty() {
                return Err(SourceError::BadSpec(format!(
                    "empty {} in spec {input:?}",
                    if marker == b'@' { "revision" } else { "variant" }
                )));
            }
            match marker {
                b'@' if revision.is_some() => {
                    return Err(SourceError::BadSpec(format!(
                        "repeated revision in spec {input:?}"
                    )))
                }
                b':' if variant.is_some() => {
                    return Err(SourceError::BadSpec(format!(
                        "repeated variant in spec {input:?}"
                    )))
                }
                b'@' => revision = Some(value.to_string()),
                _ => variant = Some(value.to_string()),
            }
        }

        let repo = parse_repo_id(repo_part, input)?;
        Ok(RepoSpec {
            repo,
            revision,
            variant,
        })
    }
}

fn parse_repo_id(part: &str, full: &str) -> Result<RepoId, SourceError> {
    let mut segments = part.split('/');
    let namespace = segments.next().unwrap_or_default();
    let name = segments.next().unwrap_or_default();
    if segments.next().is_some() {
        return Err(SourceError::BadSpec(format!(
            "repo {part:?} in spec {full:?} has too many '/' segments; \
             expected \"namespace/name\""
        )));
    }
    if namespace.is_empty() || name.is_empty() {
        return Err(SourceError::BadSpec(format!(
            "repo {part:?} in spec {full:?} must be \"namespace/name\""
        )));
    }
    Ok(RepoId {
        namespace: namespace.to_string(),
        name: name.to_string(),
    })
}

impl fmt::Display for RepoSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.repo)?;
        if let Some(r) = &self.revision {
            write!(f, "@{r}")?;
        }
        if let Some(v) = &self.variant {
            write!(f, ":{v}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_repo() {
        let s = RepoSpec::parse("unsloth/Llama-3-8B-GGUF").unwrap();
        assert_eq!(s.repo.namespace, "unsloth");
        assert_eq!(s.repo.name, "Llama-3-8B-GGUF");
        assert_eq!(s.revision, None);
        assert_eq!(s.variant, None);
    }

    #[test]
    fn parses_the_variant_form_from_the_spec() {
        let s = RepoSpec::parse("unsloth/Llama-3-8B-GGUF:Q4_K_M").unwrap();
        assert_eq!(s.variant.as_deref(), Some("Q4_K_M"));
        assert_eq!(s.revision, None);
    }

    #[test]
    fn parses_revision_and_variant_in_either_order() {
        let a = RepoSpec::parse("unsloth/Qwen3-8B-GGUF@a6adef13:UD-Q4_K_XL").unwrap();
        let b = RepoSpec::parse("unsloth/Qwen3-8B-GGUF:UD-Q4_K_XL@a6adef13").unwrap();
        assert_eq!(a.revision.as_deref(), Some("a6adef13"));
        assert_eq!(a.variant.as_deref(), Some("UD-Q4_K_XL"));
        assert_eq!(a, b, "both orderings should parse identically");
    }

    #[test]
    fn round_trips_through_display() {
        for input in [
            "unsloth/Qwen3-8B-GGUF",
            "unsloth/Qwen3-8B-GGUF:Q4_K_M",
            "unsloth/Qwen3-8B-GGUF@main",
            "unsloth/Qwen3-8B-GGUF@main:Q4_K_M",
        ] {
            let parsed = RepoSpec::parse(input).unwrap();
            assert_eq!(parsed.to_string(), input);
        }
    }

    #[test]
    fn rejects_malformed_specs() {
        for bad in [
            "",
            "   ",
            "noslash",
            "/name",
            "org/",
            "a/b/c",
            "org/name@",
            "org/name:",
            "org/name@x@y",
            "org/name:a:b",
        ] {
            assert!(
                RepoSpec::parse(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn variant_labels_with_underscores_and_dashes_survive() {
        let s = RepoSpec::parse("unsloth/DeepSeek-R1-GGUF:UD-IQ1_S").unwrap();
        assert_eq!(s.variant.as_deref(), Some("UD-IQ1_S"));
    }

    #[test]
    fn source_kind_parses_short_and_long_names() {
        assert_eq!(
            "hf".parse::<SourceKind>().unwrap(),
            SourceKind::HuggingFace
        );
        assert_eq!(
            "modelscope".parse::<SourceKind>().unwrap(),
            SourceKind::ModelScope
        );
        assert!("ollama".parse::<SourceKind>().is_err());
    }

    #[test]
    fn default_source_is_huggingface() {
        // ModelScope must never be reached by accident.
        assert_eq!(SourceKind::default(), SourceKind::HuggingFace);
    }

    #[test]
    fn only_huggingface_signs_commits() {
        assert!(SourceKind::HuggingFace.signs_commits());
        assert!(!SourceKind::ModelScope.signs_commits());
    }
}
