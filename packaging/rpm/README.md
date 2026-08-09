# RPM packaging

Builds `almanac-model-fetch` as an RPM, aimed at [COPR][copr]. The package
installs one binary, `amf`, plus its man page and the two design documents.

| File | What it is |
| --- | --- |
| `almanac-model-fetch.spec` | The spec. Bundled crates, offline build, tests run in `%check`. |
| `make-srpm.sh` | Builds the source RPM: both tarballs, then `rpmbuild -bs`. |
| `amf.1` | Hand-written man page. Update it when the CLI changes. |
| `../../.copr/Makefile` | What COPR invokes to produce the SRPM. |

## Build an SRPM locally

```bash
packaging/rpm/make-srpm.sh                     # -> packaging/rpm/out/*.src.rpm
```

Needs `git`, `cargo`, `rpm-build`, and network access for the vendoring step.
The SRPM is built from `HEAD`, not from your working tree — the script warns if
those differ. Then, to build the binary package:

```bash
mock -r fedora-42-x86_64 packaging/rpm/out/almanac-model-fetch-*.src.rpm
```

`rpmbuild --rebuild` works too, but mock is what actually proves the offline
build: it isolates the build from your populated `~/.cargo` registry, which is
the thing most likely to hide a missing vendored crate.

## Set up the COPR project

COPR builds straight from git using `.copr/Makefile`; there is nothing to
upload by hand.

```bash
copr-cli create almanac-model-fetch \
    --chroot fedora-42-x86_64 --chroot fedora-43-x86_64 \
    --chroot fedora-rawhide-x86_64 \
    --description "Fetch, verify, and bundle AI models for airgapped import"

copr-cli add-package-scm almanac-model-fetch \
    --name almanac-model-fetch \
    --clone-url https://github.com/clemperorpenguin/almanac-model-fetch.git \
    --commit main \
    --method make_srpm \
    --webhook-rebuild on

copr-cli build-package almanac-model-fetch --name almanac-model-fetch
```

`--method make_srpm` is the part that matters: it runs `.copr/Makefile` in a
chroot **with** network access, which is where the crates are fetched. The
build of the binary package that follows has no network, and does not need one.

Leave the package's **Subdirectory** field empty. It is tempting to point it at
`packaging/rpm` because that is where the spec lives, but this build method
only needs `.copr/Makefile`, and the field changes the working directory make
is invoked from. The makefile locates the checkout from its own path precisely
so that either setting works — a subdirectory used to produce a bare
`packaging/rpm/make-srpm.sh: No such file or directory` — but empty is what
this is meant to be.

Adding aarch64 chroots costs nothing but build time — the package is
`ExclusiveArch: %{rust_arches}` and has no architecture-specific code beyond
what rustc handles.

## Versions and releases

`Version:` in the spec must match `[workspace.package] version` in
`Cargo.toml`; `make-srpm.sh` refuses to run if they have drifted. Bump both in
the same commit.

`Release:` is computed. A commit tagged `v<version>` builds as release `1`;
anything else builds as `0.<commit-date>.git<sha>`, which sorts below the
release it precedes, so a snapshot never shadows the real thing. The committed
spec says `%global baserelease 1`; `make-srpm.sh` rewrites that line in the
copy it puts into the SRPM, because `rpmbuild -bs` stores the spec verbatim and
a `--define` would not survive into whoever builds the binary package.

COPR's checkout usually has no tags, so builds from it are normally snapshots
even at a tagged commit — untidy, not wrong.

## Decisions worth knowing about

**Crates are bundled.** Source1 is a `cargo vendor` tree built from the
committed `Cargo.lock`, and the build runs `--offline --locked` against it.
This is what Fedora's Rust *application* packaging does, and it is also the
only version of this package that means anything: a tool whose entire purpose
is that its output can be re-derived from pinned inputs should not resolve its
own dependencies from the network at build time.

The tarball is ~47M, most of it Windows and wasm crates that this package will
never compile. `make-srpm.sh --filter-platforms` cuts it to ~15M using
`cargo-vendor-filterer`, but it is off by default: it needs a tool that is not
in every chroot, and it produces a different tarball from the same commit. Use
it while iterating, not for a release.

**No debuginfo package.** `[profile.release]` sets `strip = true`, so there is
nothing for `find-debuginfo` to extract and the subpackage would be empty —
which fails the build rather than warning. The spec therefore sets
`%global debug_package %{nil}`. Keeping parity with the reproducible signed
binaries upstream ships matters more here than shipping debuginfo. To trade it
back, override the profile in `%build` with
`RUSTFLAGS="-Cstrip=none -Cdebuginfo=2"` and drop the `debug_package` line.

**`%{build_rustflags}` is not used.** Fedora's macro sets debuginfo and strip
options that contradict the release profile, so using it would silently change
what this package ships relative to the upstream binaries. The spec sets the
distribution's link hardening (`-z relro -z now`) explicitly instead.

**`%check` runs the full workspace suite.** It needs no network: every test
that touches `huggingface.co` or `modelscope.cn` is `#[ignore]`d upstream. If
that ever stops being true, `%check` is where it will show up first.

## Before this could go to Fedora proper

COPR does not require these; a Fedora package review would.

- **`Provides: bundled(crate(<name>)) = <version>`, one per vendored crate.**
  Generate them with `%cargo_vendor_manifest` from `cargo-rpm-macros` rather
  than by hand. The spec currently ships the same information as a
  `%license cargo-vendor.txt` manifest generated during `%build`, which is
  useful for auditing but is not the tag a reviewer looks for.
- **A `License:` expression covering the bundled crates**, not just the
  `Apache-2.0` of this source tree. `cargo-vendor.txt` in the built package
  lists what each crate declares.
- **Building with `cargo-rpm-macros`** (`%cargo_prep`, `%cargo_build`,
  `%cargo_install`) instead of calling cargo directly. That is the reviewed
  path; it was avoided here because those macros' availability varies across
  the EPEL chroots this package should keep building on.

## EPEL

The workspace needs Rust ≥ 1.80. EPEL 10 and current Fedora are fine. EPEL 9
depends on which RHEL 9 minor the chroot tracks — recent ones ship a new enough
`rust-toolset`, older ones fail in `%build` with a clear rustc error. Only the
Fedora chroots are tested.

[copr]: https://copr.fedorainfracloud.org/
