//! Model source backends for almanac-model-fetch.
//!
//! Everything downstream of the [`Source`] trait is host-agnostic, so a bundle
//! built from ModelScope is structurally identical to one built from
//! HuggingFace. The airgapped importer neither knows nor cares which host a
//! bundle came from, beyond what the manifest records about it.

pub mod download;
pub mod hf;
pub mod model;
pub mod spec;
pub mod variant;

pub use model::{RemoteFile, Revision, Shard, Variant};
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
            " with the token supplied (it may not exist, or the token may lack access)"
        } else {
            " (it may not exist, or it may be gated/private — try setting HF_TOKEN)"
        }
    )]
    AccessDenied { repo: String, authenticated: bool },

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

/// A place models can be fetched from.
#[async_trait::async_trait]
pub trait Source: Send + Sync {
    fn kind(&self) -> SourceKind;

    /// Resolve a spec's revision to an immutable commit SHA.
    async fn resolve(&self, spec: &RepoSpec) -> Result<Revision, SourceError>;

    /// List every file at a resolved revision.
    async fn list_files(&self, rev: &Revision) -> Result<Vec<RemoteFile>, SourceError>;

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
        SourceKind::ModelScope => Err(SourceError::Unsupported(
            "the ModelScope backend is not wired up yet".into(),
        )),
    }
}
