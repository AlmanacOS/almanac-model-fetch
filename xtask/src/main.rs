//! Build and release automation.
//!
//! `cargo xtask dist` produces the release artifacts, a `SHA256SUMS` over them,
//! and (given a key) a minisign signature of that file — so the tool's own
//! distribution follows the trust model the tool implements. A plain
//! `cargo build` remains sufficient for development; nothing here is a
//! prerequisite for working on the code.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

/// Targets built unattended in the container.
///
/// Apple targets are deliberately absent: they need an SDK this project will
/// not vendor. `--target` adds them when `--sdkroot` supplies one.
const DEFAULT_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-gnu",
];

const IMAGE_TAG: &str = "amf-dist:latest";

#[derive(Parser)]
#[command(name = "xtask", about = "Build and release automation")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build release artifacts, hash them, and optionally sign the hashes.
    Dist(DistArgs),
    /// Build the pinned container image used by `dist`.
    Image,
    /// Sign a file with the release key.
    ///
    /// Exists for the release job, which assembles artifacts built by several
    /// jobs and so cannot sign as part of `dist`. Deliberately here rather than
    /// in `amf` itself: signing releases is a maintainer task, not something
    /// the shipped tool needs to offer.
    Sign(SignArgs),
}

#[derive(Parser)]
struct SignArgs {
    /// File to sign.
    #[arg(long, value_name = "PATH")]
    file: PathBuf,

    /// Release secret key.
    #[arg(long, value_name = "PATH")]
    key: PathBuf,

    /// Where the detached signature goes. Defaults to `<file>.minisig`.
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Parser)]
struct DistArgs {
    /// Targets to build. Defaults to the three that need no external SDK.
    #[arg(long)]
    target: Vec<String>,

    /// Path to a macOS SDK, which Apple targets cannot link without.
    #[arg(long, value_name = "PATH")]
    sdkroot: Option<PathBuf>,

    /// Where the artifacts land.
    #[arg(long, default_value = "dist/out")]
    out: PathBuf,

    /// Secret key used to sign SHA256SUMS.
    #[arg(long, value_name = "PATH")]
    sign: Option<PathBuf>,

    /// Build on this machine instead of in the pinned container.
    ///
    /// Faster when the toolchain is already present, but the result is only as
    /// reproducible as the local environment — do not cut releases this way.
    #[arg(long)]
    no_docker: bool,

    /// Build everything twice and fail if the bytes differ.
    #[arg(long)]
    verify_reproducible: bool,

    /// Which cargo subcommand builds the targets.
    ///
    /// `zigbuild` is the release path: zig supplies the cross C toolchain that
    /// ring's assembly needs, and the container pins its version. `cargo` is
    /// for a machine that already has a working cross toolchain of its own.
    /// Explicit rather than auto-detected, because silently swapping build
    /// tools would silently change what "reproducible" means.
    #[arg(long, value_name = "TOOL", default_value = "zigbuild")]
    builder: Builder,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Builder {
    Zigbuild,
    Cargo,
}

impl Builder {
    fn subcommand(self) -> &'static str {
        match self {
            Builder::Zigbuild => "zigbuild",
            Builder::Cargo => "build",
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Image => build_image(),
        Cmd::Dist(args) => dist(args),
        Cmd::Sign(args) => sign_file(args),
    }
}

fn sign_file(args: SignArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let comment = format!(
        "almanac-model-fetch release {} {}",
        env!("CARGO_PKG_VERSION"),
        args.file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    );
    let sig = amf_verify::sign_bytes(&args.key, None, &bytes, &comment)
        .map_err(|e| anyhow!("signing {}: {e}", args.file.display()))?;

    let out = args.out.unwrap_or_else(|| {
        let mut p = args.file.clone().into_os_string();
        p.push(".minisig");
        PathBuf::from(p)
    });
    std::fs::write(&out, sig).with_context(|| format!("writing {}", out.display()))?;
    println!("signed {} -> {}", args.file.display(), out.display());
    Ok(())
}

fn repo_root() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("running git rev-parse")?;
    if !out.status.success() {
        bail!("not inside a git repository");
    }
    Ok(PathBuf::from(
        String::from_utf8(out.stdout)?.trim().to_string(),
    ))
}

/// Commit timestamp, used as `SOURCE_DATE_EPOCH`.
///
/// Anchoring to the commit rather than to wall-clock time is what lets two
/// builds of the same source agree.
fn source_date_epoch(root: &Path) -> Result<String> {
    let out = Command::new("git")
        .current_dir(root)
        .args(["log", "-1", "--pretty=%ct"])
        .output()
        .context("reading the commit timestamp")?;
    if !out.status.success() {
        // A shallow or empty checkout still deserves a deterministic value.
        return Ok("0".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn build_image() -> Result<()> {
    let root = repo_root()?;
    let status = Command::new("docker")
        .current_dir(&root)
        .args(["build", "-t", IMAGE_TAG, "-f", "dist/Dockerfile", "dist"])
        .status()
        .context("running docker build")?;
    if !status.success() {
        bail!("docker build failed");
    }
    println!("built {IMAGE_TAG}");
    Ok(())
}

fn dist(args: DistArgs) -> Result<()> {
    let root = repo_root()?;
    let targets: Vec<String> = if args.target.is_empty() {
        DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect()
    } else {
        args.target.clone()
    };

    for t in &targets {
        if t.contains("apple") && args.sdkroot.is_none() {
            bail!(
                "{t} needs a macOS SDK, which is not vendored here: pass \
                 --sdkroot <path> to use your own copy, or build Apple targets \
                 on a macOS runner. See ARCHITECTURE.md §12."
            );
        }
    }

    let out = root.join(&args.out);
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;

    let epoch = source_date_epoch(&root)?;
    let mut artifacts = Vec::new();

    for target in &targets {
        println!("==> building {target}");
        build_target(&root, target, &args, &epoch)?;
        let produced = collect_artifact(&root, target, &out)?;
        artifacts.push(produced);
    }

    if args.verify_reproducible {
        verify_reproducible(&root, &targets, &args, &epoch, &artifacts)?;
    }

    let sums_path = out.join("SHA256SUMS");
    let sums = write_sha256sums(&artifacts, &sums_path)?;
    println!("==> wrote {}", sums_path.display());
    print!("{sums}");

    match &args.sign {
        Some(key) => {
            let bytes = std::fs::read(&sums_path)?;
            let comment = format!(
                "almanac-model-fetch release {} sha256sums",
                env!("CARGO_PKG_VERSION")
            );
            let sig = amf_verify::sign_bytes(key, None, &bytes, &comment)
                .map_err(|e| anyhow!("signing SHA256SUMS: {e}"))?;
            let sig_path = out.join("SHA256SUMS.minisig");
            std::fs::write(&sig_path, sig)?;
            println!("==> signed {}", sig_path.display());
        }
        None => {
            // Loud, because an unsigned SHA256SUMS is exactly as trustworthy as
            // the channel it travels over — which is the problem it exists to
            // solve.
            println!(
                "\nWARNING: SHA256SUMS is unsigned. Pass --sign <release-secret-key> \
                 to produce SHA256SUMS.minisig; a downloader cannot otherwise tell \
                 this file from one an attacker substituted."
            );
        }
    }

    Ok(())
}

fn build_target(root: &Path, target: &str, args: &DistArgs, epoch: &str) -> Result<()> {
    // Path remapping keeps the builder's directory layout out of the binary,
    // which is both a reproducibility and a privacy matter.
    let rustflags = "--remap-path-prefix=/work=. --remap-path-prefix=/usr/local/cargo=cargo";

    let status = if args.no_docker {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .env("SOURCE_DATE_EPOCH", epoch)
            .env("RUSTFLAGS", rustflags)
            .args([
                args.builder.subcommand(),
                "--release",
                "--locked",
                "-p",
                "amf-cli",
                "--target",
                target,
            ]);
        if let Some(sdk) = &args.sdkroot {
            cmd.env("SDKROOT", sdk);
        }
        cmd.status().context("running cargo zigbuild")?
    } else {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "-v"])
            .arg(format!("{}:/work", root.display()))
            .args(["-w", "/work", "-e"])
            .arg(format!("SOURCE_DATE_EPOCH={epoch}"))
            .arg("-e")
            .arg(format!("RUSTFLAGS={rustflags}"));
        if let Some(sdk) = &args.sdkroot {
            cmd.arg("-v")
                .arg(format!("{}:/sdk:ro", sdk.display()))
                .args(["-e", "SDKROOT=/sdk"]);
        }
        cmd.arg(IMAGE_TAG).args([
            "cargo",
            args.builder.subcommand(),
            "--release",
            "--locked",
            "-p",
            "amf-cli",
            "--target",
            target,
        ]);
        cmd.status().context("running the build container")?
    };

    if !status.success() {
        bail!("build failed for {target}");
    }
    Ok(())
}

struct Artifact {
    name: String,
    sha256: String,
}

fn collect_artifact(root: &Path, target: &str, out: &Path) -> Result<Artifact> {
    let exe = if target.contains("windows") {
        "amf.exe"
    } else {
        "amf"
    };
    let built = root.join("target").join(target).join("release").join(exe);
    if !built.exists() {
        bail!("expected {} to exist after the build", built.display());
    }

    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let name = format!("amf-{}-{target}{suffix}", env!("CARGO_PKG_VERSION"));
    let dest = out.join(&name);
    std::fs::copy(&built, &dest)
        .with_context(|| format!("copying {} to {}", built.display(), dest.display()))?;

    let sha256 = sha256_file(&dest)?;
    println!("    {name}  {sha256}");
    Ok(Artifact { name, sha256 })
}

/// Build everything a second time and compare.
///
/// The tool asks operators to trust binaries it signs, so "it built on my
/// laptop" is not an adequate provenance story for the tool itself.
fn verify_reproducible(
    root: &Path,
    targets: &[String],
    args: &DistArgs,
    epoch: &str,
    first: &[Artifact],
) -> Result<()> {
    println!("==> rebuilding to check reproducibility");

    for (target, previous) in targets.iter().zip(first) {
        // Force a genuine rebuild rather than a cache hit, or this proves
        // nothing at all.
        let stale = root.join("target").join(target).join("release");
        let _ = std::fs::remove_dir_all(stale.join("build"));
        let exe = if target.contains("windows") {
            "amf.exe"
        } else {
            "amf"
        };
        let _ = std::fs::remove_file(stale.join(exe));

        build_target(root, target, args, epoch)?;
        let rebuilt = sha256_file(&stale.join(exe))?;
        if rebuilt != previous.sha256 {
            bail!(
                "{target} is not reproducible: {} then {rebuilt}. Do not cut a \
                 release from this build.",
                previous.sha256
            );
        }
        println!("    {target} reproduced identically");
    }
    Ok(())
}

fn write_sha256sums(artifacts: &[Artifact], path: &Path) -> Result<String> {
    let mut sorted: Vec<&Artifact> = artifacts.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    // sha256sum's own format, so `sha256sum -c SHA256SUMS` just works for
    // someone who would rather not take our word for the checking either.
    let body: String = sorted
        .iter()
        .map(|a| format!("{}  {}\n", a.sha256, a.name))
        .collect();
    std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
    Ok(body)
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(name: &str, sha: &str) -> Artifact {
        Artifact {
            name: name.into(),
            sha256: sha.into(),
        }
    }

    #[test]
    fn sha256sums_matches_the_coreutils_format() {
        let dir = std::env::temp_dir().join("amf-xtask-test-sums");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("SHA256SUMS");

        let body = write_sha256sums(
            &[
                artifact("amf-0.1.0-x86_64-pc-windows-gnu.exe", &"b".repeat(64)),
                artifact("amf-0.1.0-aarch64-unknown-linux-musl", &"a".repeat(64)),
            ],
            &path,
        )
        .unwrap();

        // Two spaces, hash first, sorted by name: exactly what `sha256sum -c`
        // expects, so a downloader who would rather not trust our verifier can
        // use theirs.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines[0],
            format!("{}  amf-0.1.0-aarch64-unknown-linux-musl", "a".repeat(64))
        );
        assert!(lines[1].ends_with("amf-0.1.0-x86_64-pc-windows-gnu.exe"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hashes_a_file_the_same_way_the_rest_of_the_tool_does() {
        let dir = std::env::temp_dir().join("amf-xtask-test-hash");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, b"hello ").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "5e3235a8346e5a4585f8c58562f5052b8fe26a3bb122e1e96c76784964dfc461"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apple_targets_are_not_in_the_unattended_set() {
        // They cannot be built without an SDK this project will not vendor, so
        // a default `dist` must not try and fail halfway through a release.
        assert!(!DEFAULT_TARGETS.iter().any(|t| t.contains("apple")));
        assert!(DEFAULT_TARGETS.contains(&"x86_64-unknown-linux-musl"));
    }
}
