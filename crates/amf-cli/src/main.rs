//! almanac-model-fetch — fetch a model, verify it, bundle it for an airgap.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod corroborate;
mod fetch;
mod keys;
mod list;
mod trust;
mod ui;
mod verify;

pub const USER_AGENT: &str = concat!("almanac-model-fetch/", env!("CARGO_PKG_VERSION"));

#[derive(Parser)]
#[command(
    name = "amf",
    version,
    about = "Fetch, verify, and bundle models for airgapped import",
    long_about = "Downloads a model from HuggingFace (or ModelScope), verifies it \
                  against upstream-published hashes as it streams, captures what \
                  provenance exists, and writes a self-contained bundle that an \
                  airgapped machine can import and re-verify with no network."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch one or more models onto a drive.
    Fetch(FetchArgs),
    /// Re-verify a bundle. Requires no network — this is the airgapped-side command.
    Verify(VerifyArgs),
    /// List the bundles on a drive.
    List(ListArgs),
    /// Generate the fetcher's signing keypair.
    Keygen(KeygenArgs),
    /// Manage pinned upstream signing keys and observed-fingerprint history.
    Trust(TrustArgs),
}

#[derive(Parser)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommand,

    /// Trust store location (default: the user config dir, or $AMF_TRUST_STORE).
    #[arg(long, value_name = "PATH")]
    pub trust_store: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum TrustCommand {
    /// Show pinned keys and every fingerprint ever observed.
    List,
    /// Pin a host's public key, enabling Tier-2 verification for it.
    Add {
        /// Host the key belongs to, e.g. "huggingface".
        host: String,
        /// Path to the armored public key file.
        key_file: PathBuf,
    },
    /// Remove a host's pinned key.
    Remove { host: String },
}

#[derive(Parser)]
pub struct FetchArgs {
    /// Repo specs: `org/name[@revision][:variant]`. Multiple are fetched in one run.
    #[arg(required = true, value_name = "REPO_SPEC")]
    pub specs: Vec<String>,

    /// Destination drive or directory.
    #[arg(long, value_name = "PATH")]
    pub usb: PathBuf,

    /// Quantisation to fetch, if not given in the spec.
    #[arg(long)]
    pub variant: Option<String>,

    /// Source host. ModelScope is for operators who cannot reach HuggingFace;
    /// the tool never falls back to it automatically.
    #[arg(long, default_value = "hf")]
    pub source: String,

    /// Take the default variant without prompting.
    #[arg(long, short)]
    pub yes: bool,

    /// Proceed past warnings. Does not override the FAT refusal.
    #[arg(long)]
    pub force: bool,

    /// Refuse to write a bundle unless the upstream commit signature verified.
    #[arg(long)]
    pub require_signature: bool,

    /// Skip cross-checking the file hash against the other host.
    #[arg(long)]
    pub no_corroborate: bool,

    /// Corroborate against a specific repo: `<host>:<org/name>`.
    ///
    /// Mirrors are not always named identically; this points at the real one.
    #[arg(long, value_name = "HOST:REPO", conflicts_with = "no_corroborate")]
    pub corroborate_with: Option<String>,

    /// Refuse to write a bundle unless the other host confirms the hashes.
    #[arg(long, conflicts_with = "no_corroborate")]
    pub require_corroboration: bool,

    /// Secret key used to sign the bundle manifest.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Trust store location (default: the user config dir, or $AMF_TRUST_STORE).
    /// Must match the store `amf trust` was pointed at, or pinned keys will not
    /// be found.
    #[arg(long, value_name = "PATH")]
    pub trust_store: Option<PathBuf>,
}

#[derive(Parser)]
pub struct VerifyArgs {
    /// Bundle directory, or a drive to verify every bundle on.
    pub path: PathBuf,

    /// Public key to check the bundle signature against.
    #[arg(long, value_name = "PATH")]
    pub public_key: Option<PathBuf>,

    /// Armored PGP public key to verify the captured upstream commit signature
    /// against (e.g. HuggingFace's signing key, obtained out of band).
    #[arg(long, value_name = "PATH")]
    pub upstream_key: Option<PathBuf>,
}

#[derive(Parser)]
pub struct ListArgs {
    /// Drive or directory to inventory.
    pub path: PathBuf,
}

#[derive(Parser)]
pub struct KeygenArgs {
    /// Where to write the secret key.
    #[arg(long, default_value = "amf.key")]
    pub secret: PathBuf,

    /// Where to write the public key.
    #[arg(long, default_value = "amf.pub")]
    pub public: PathBuf,

    /// Comment identifying this fetcher.
    #[arg(long, default_value = "almanac-model-fetch signing key")]
    pub comment: String,

    /// Password-protect the secret key.
    #[arg(long)]
    pub password: Option<String>,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Fetch(args) => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    ui::error(&format!("could not start the async runtime: {e}"));
                    return std::process::ExitCode::FAILURE;
                }
            };
            runtime.block_on(fetch::run(args))
        }
        Command::Verify(args) => verify::run(args),
        Command::List(args) => list::run(args),
        Command::Keygen(args) => keys::run(args),
        Command::Trust(args) => trust::run(args),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            ui::error(&format!("{e:#}"));
            std::process::ExitCode::FAILURE
        }
    }
}
