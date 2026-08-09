#!/usr/bin/env bash
#
# Build the source RPM: source tarball, vendored-crate tarball, then rpmbuild -bs.
#
# This is plain shell rather than a `cargo xtask` subcommand on purpose. COPR
# runs it inside a minimal chroot to *produce* the SRPM, and compiling a Rust
# helper there just to tar two directories would add a toolchain dependency to
# the one step that has to work before any toolchain is guaranteed.
#
# Both tarballs are byte-for-byte reproducible from a given commit: entries are
# sorted, ownership is zeroed, and every mtime is the commit timestamp, the
# same SOURCE_DATE_EPOCH convention `cargo xtask dist` uses.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: make-srpm.sh [--outdir DIR] [--filter-platforms] [--keep-workdir]

  --outdir DIR         Where the .src.rpm lands (default: packaging/rpm/out).
  --filter-platforms   Vendor only crates reachable on Linux, using
                       cargo-vendor-filterer. Cuts the vendor tarball from
                       ~47M to ~15M by dropping Windows, wasm, and Redox
                       crates. Off by default: it needs a tool that is not in
                       every chroot, and it produces a different tarball from
                       the same commit, so a release should be cut without it.
  --keep-workdir       Leave the scratch directory in place for inspection.
EOF
}

outdir=""
filter_platforms=0
keep_workdir=0

while [ $# -gt 0 ]; do
    case "$1" in
        --outdir) outdir="${2:?--outdir needs a directory}"; shift 2 ;;
        --outdir=*) outdir="${1#*=}"; shift ;;
        --filter-platforms) filter_platforms=1; shift ;;
        --keep-workdir) keep_workdir=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "make-srpm.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$root" ]; then
    echo "make-srpm.sh: not inside a git checkout; the source tarball comes from git archive" >&2
    exit 1
fi

name=almanac-model-fetch
spec="$script_dir/$name.spec"
outdir=${outdir:-$script_dir/out}

for tool in git cargo rpmbuild tar gzip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "make-srpm.sh: $tool is required but not installed" >&2; exit 1; }
done

# Version comes from the workspace manifest; the spec must agree with it, or
# the tarball rpmbuild looks for is not the one this script wrote.
version=$(awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/                     { in_section = 0 }
    in_section && /^version *=/ {
        gsub(/^version *= *"|"$/, "")
        print
        exit
    }' "$root/Cargo.toml")
[ -n "$version" ] || { echo "make-srpm.sh: could not read version from Cargo.toml" >&2; exit 1; }

spec_version=$(sed -n 's/^Version: *//p' "$spec" | head -1)
if [ "$spec_version" != "$version" ]; then
    echo "make-srpm.sh: Cargo.toml says $version but the spec says $spec_version." >&2
    echo "               Update Version: in $(basename "$spec") before packaging." >&2
    exit 1
fi

# git archive packages HEAD, not the working tree. Say so rather than quietly
# building something that does not match what is checked out.
if [ -n "$(git -C "$root" status --porcelain)" ]; then
    echo "make-srpm.sh: warning: the working tree is dirty; packaging HEAD, not your uncommitted changes" >&2
fi

commit=$(git -C "$root" rev-parse --short=9 HEAD)
epoch=$(git -C "$root" log -1 --pretty=%ct)
commit_date=$(git -C "$root" log -1 --pretty=%cd --date=format-local:%Y%m%d)

# A tagged commit is release 1. Anything else is a snapshot, versioned so that
# it sorts below the release it precedes and names the commit it came from.
if [ "$(git -C "$root" describe --exact-match --tags HEAD 2>/dev/null || true)" = "v$version" ]; then
    baserelease=1
else
    baserelease="0.${commit_date}.git${commit}"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/amf-srpm.XXXXXXXX")
cleanup() { [ "$keep_workdir" -eq 1 ] || rm -rf "$work"; }
trap cleanup EXIT
[ "$keep_workdir" -eq 1 ] && echo "==> work directory: $work"

sources="$work/sources"
mkdir -p "$sources" "$outdir"

# Deterministic tar of a directory: sorted, unowned, fixed mtimes.
tar_reproducibly() {
    local parent=$1 dir=$2 dest=$3
    tar --format=gnu \
        --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@$epoch" \
        -C "$parent" -cf - "$dir" | gzip -9n > "$dest"
}

echo "==> source tarball ($name-$version, $commit)"
git -C "$root" archive --format=tar --prefix="$name-$version/" HEAD \
    | gzip -9n > "$sources/$name-$version.tar.gz"

# Vendor from the *archived* tree, not the working tree, so the vendored crates
# are guaranteed to match the Cargo.lock that ships in the source tarball even
# when the checkout is dirty.
echo "==> unpacking the source tarball to vendor against"
mkdir -p "$work/src"
tar -C "$work/src" -xf "$sources/$name-$version.tar.gz"
srcdir="$work/src/$name-$version"

echo "==> vendoring crates from Cargo.lock"
mkdir -p "$work/vendorroot"
if [ "$filter_platforms" -eq 1 ]; then
    command -v cargo-vendor-filterer >/dev/null 2>&1 \
        || { echo "make-srpm.sh: --filter-platforms needs cargo-vendor-filterer" >&2; exit 1; }
    ( cd "$srcdir" && cargo vendor-filterer \
        --platform=x86_64-unknown-linux-gnu \
        --platform=aarch64-unknown-linux-gnu \
        --platform=powerpc64le-unknown-linux-gnu \
        --platform=s390x-unknown-linux-gnu \
        --platform=riscv64gc-unknown-linux-gnu \
        "$work/vendorroot/vendor" >/dev/null )
else
    cargo vendor --manifest-path "$srcdir/Cargo.toml" --locked --versioned-dirs \
        "$work/vendorroot/vendor" > /dev/null
fi

echo "==> vendor tarball"
tar_reproducibly "$work/vendorroot" vendor "$sources/$name-$version-vendor.tar.gz"

cp "$script_dir/amf.1" "$sources/"

# Bake the release into the spec that goes into the SRPM. A --define would not
# survive: rpmbuild -bs stores the spec verbatim, so whoever builds the binary
# package from this SRPM — COPR, mock, anyone — re-parses it with none of this
# script's definitions, and every snapshot would rebuild as release 1.
staged_spec="$work/$(basename "$spec")"
sed "s|^%global baserelease .*|%global baserelease $baserelease|" "$spec" > "$staged_spec"
grep -qF "%global baserelease $baserelease" "$staged_spec" \
    || { echo "make-srpm.sh: failed to set the release in the staged spec" >&2; exit 1; }

echo "==> rpmbuild -bs (release $baserelease)"
rpmbuild -bs \
    --define "_topdir $work/rpm" \
    --define "_sourcedir $sources" \
    --define "_srcrpmdir $outdir" \
    "$staged_spec"

echo
echo "==> wrote:"
ls -lh "$outdir"/$name-$version-"$baserelease"*.src.rpm
