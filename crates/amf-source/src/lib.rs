//! Model source backends for almanac-model-fetch.
//!
//! Everything downstream of the [`Source`] trait is host-agnostic, so a bundle
//! built from ModelScope is structurally identical to one built from
//! HuggingFace. The airgapped importer neither knows nor cares which host a
//! bundle came from, beyond what the manifest records about it.

pub mod download;
pub mod git_http;
pub mod hf;
pub mod model;
pub mod ms;
pub mod pack;
pub mod spec;
pub mod variant;

pub use model::{RemoteFile, Revision, RevisionPrecision, Shard, Variant};
pub use spec::{RepoId, RepoSpec, SourceKind};

/// Re-exported so downstream crates share this crate's exact reqwest version
/// and TLS feature set rather than linking a second, differently-configured one.
pub use reqwest;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{0}")]
    BadSpec(String),

    #[error(
        "repository {repo} is not accessible{}",
        if *.authenticated {
            " with the token supplied (it may not exist, or the token may lack access)".to_string()
        } else {
            format!(" (it may not exist, or it may be gated/private — try setting {token_env})")
        }
    )]
    AccessDenied {
        repo: String,
        authenticated: bool,
        /// The env var that supplies a token *for this host* — telling a
        /// ModelScope user to set HF_TOKEN is worse than saying nothing.
        token_env: &'static str,
    },

    #[error("repository {0} was not found")]
    NotFound(String),

    #[error("could not reach {host}: {source}")]
    Transport {
        host: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("{url} returned HTTP {status}")]
    Http { url: String, status: u16 },

    #[error("unexpected response from the source: {0}")]
    Malformed(String),

    #[error("{0}")]
    Unsupported(String),

    #[error("i/o error on {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Verify(#[from] amf_verify::VerifyError),
}

impl SourceError {
    /// Whether this looks like "the host is unreachable" rather than "the host
    /// said no".
    ///
    /// The CLI uses this to decide whether to suggest `--source modelscope`: an
    /// operator behind a firewall that blocks HuggingFace should be pointed at
    /// the fallback, but someone who merely typo'd a repo name should not.
    pub fn is_unreachable(&self) -> bool {
        match self {
            SourceError::Transport { source, .. } => {
                source.is_connect() || source.is_timeout() || source.is_request()
            }
            _ => false,
        }
    }
}

/// Where a host serves each kind of thing.
///
/// Evidence capture and downloading need URLs, and they used to build them from
/// a hardcoded `huggingface.co`. Putting them here means a second host cannot be
/// added without stating its endpoints, and a host that has no git endpoint at
/// all says so structurally (`git_repo_url` returns `None`) rather than by
/// failing at request time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEndpoints {
    /// Base for the host's REST API.
    pub api_base: String,
    /// Base such that `{resolve_base}/{repo}/resolve/{commit}/{path}` serves bytes.
    pub resolve_base: String,
    /// Base for git smart-HTTP, or `None` where the host serves no git endpoint.
    pub git_base: Option<String>,
    /// Suffix a repo needs on the git path — hosts disagree about `.git`.
    pub git_suffix: String,
}

impl HostEndpoints {
    /// URL for a file's bytes at a pinned revision.
    pub fn file_url(&self, repo: &str, commit: &str, path: &str) -> String {
        download::file_url(&self.resolve_base, repo, commit, path)
    }

    /// Smart-HTTP base for one repository, if this host has one.
    pub fn git_repo_url(&self, repo: &str) -> Option<String> {
        self.git_base
            .as_ref()
            .map(|base| format!("{}/{}{}", base.trim_end_matches('/'), repo, self.git_suffix))
    }
}

/// A place models can be fetched from.
#[async_trait::async_trait]
pub trait Source: Send + Sync {
    fn kind(&self) -> SourceKind;

    /// Where this host serves its API, bytes, and git objects.
    fn endpoints(&self) -> HostEndpoints;

    /// Resolve a spec's revision to an immutable commit SHA.
    async fn resolve(&self, spec: &RepoSpec) -> Result<Revision, SourceError>;

    /// List every file at a resolved revision.
    async fn list_files(&self, rev: &Revision) -> Result<Vec<RemoteFile>, SourceError>;

    /// Fetch the LFS pointer *text* for a file — not the file's contents.
    ///
    /// Deliberately a trait method rather than another URL template: hosts do
    /// not agree on how to serve it. HuggingFace has a `/raw/` path that returns
    /// the pointer verbatim; ModelScope's `/raw/` is a web-app route and its
    /// pointer arrives wrapped in a JSON envelope. The caller checks whatever
    /// comes back against the blob id in the signed tree, so a host that
    /// mangles the bytes fails loudly rather than quietly.
    async fn fetch_pointer(&self, rev: &Revision, path: &str) -> Result<Vec<u8>, SourceError>;

    /// List the selectable model variants at a revision.
    async fn list_variants(&self, rev: &Revision) -> Result<Vec<Variant>, SourceError> {
        let files = self.list_files(rev).await?;
        Ok(variant::group(&files))
    }
}

/// Build the shared HTTP client.
///
/// One client for the whole run so connections are pooled across the many
/// requests a multi-model fetch makes.
pub fn http_client(user_agent: &str) -> Result<reqwest::Client, SourceError> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        // Applies to establishing the connection, not to the body transfer — a
        // 40 GB download must not be cut off by a global timeout.
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| SourceError::Transport {
            host: "client".into(),
            source: e,
        })
}

/// Construct a backend for a source kind.
pub fn backend(kind: SourceKind, client: reqwest::Client) -> Result<Box<dyn Source>, SourceError> {
    match kind {
        SourceKind::HuggingFace => Ok(Box::new(hf::HuggingFace::new(client))),
        SourceKind::ModelScope => Ok(Box::new(ms::ModelScope::new(client))),
    }
}
