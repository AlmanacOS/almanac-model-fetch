# RPM packaging for almanac-model-fetch, aimed at COPR.
#
# The Rust dependencies are bundled: Source1 is a `cargo vendor` tree built
# from the committed Cargo.lock, and the build runs fully offline against it.
# That is deliberate. The whole point of this tool is that what it ships can be
# re-derived from a pinned, recorded set of inputs, and a build resolving
# dependencies from the network at package time would not have that property.
# It is also what Fedora's own Rust *application* packaging does; only library
# crates are expected to unbundle. See packaging/rpm/README.md for what this
# spec would still need before it could go to Fedora proper rather than COPR.

%global bin_name amf

# `[profile.release]` in Cargo.toml sets `strip = true`, so the binary carries
# no debuginfo and the -debuginfo subpackage would be empty — which is a build
# failure, not a warning. Upstream strips because the release artifacts are
# reproducible and signed, and unstripped binaries embed build paths. Keeping
# parity with those artifacts matters more here than shipping debuginfo; see
# the README for how to trade it back.
%global debug_package %{nil}

# Rewritten in place by make-srpm.sh, which computes a snapshot release for
# untagged commits. It has to be a literal line rather than a --define, because
# rpmbuild -bs stores this spec verbatim: anything defined only on the SRPM
# build's command line is gone by the time COPR builds the binary package from
# it, and every snapshot would come out as release 1.
%global baserelease 1

Name:           almanac-model-fetch
Version:        0.1.0
Release:        %{baserelease}%{?dist}
Summary:        Fetch, verify, and bundle AI models for airgapped import

License:        Apache-2.0
URL:            https://github.com/clemperorpenguin/almanac-model-fetch
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz
Source2:        amf.1

# Wherever rustc itself is built. The fallback list keeps the spec parseable on
# a chroot without rust-srpm-macros instead of failing obscurely.
ExclusiveArch:  %{?rust_arches}%{!?rust_arches:x86_64 aarch64 ppc64le s390x riscv64}

# 1.80 is the workspace rust-version; older toolchains fail late and unhelpfully.
BuildRequires:  rust >= 1.80
BuildRequires:  cargo
# ring compiles C shims for its cryptographic primitives.
BuildRequires:  gcc

%description
almanac-model-fetch downloads a model you choose, verifies it against
upstream-published hashes as it streams, captures what provenance exists,
signs the result, and writes a self-contained bundle that a USB drive can
carry to an airgapped machine with no network at all.

Before downloading anything it asks the other host (HuggingFace or ModelScope)
whether it publishes the same SHA-256, so two independent hosts agreeing is
recorded as evidence. Revisions always resolve to an immutable commit SHA
before any bytes are fetched, and the bundle records that SHA rather than a
branch name. On the airgapped side, `amf verify` re-checks every hash and the
bundle signature with no network, no keyserver, and no correct clock.

%prep
%autosetup -n %{name}-%{version} -p1

# Bundled crates, unpacked as ./vendor.
tar -xf %{SOURCE1}

# Point cargo at them. Appended rather than written fresh so the repository's
# own `cargo xtask` alias survives; a relative `directory` resolves against the
# directory holding .cargo, i.e. the source root.
mkdir -p .cargo
cat >> .cargo/config.toml <<'EOF'

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
# Keep cargo inside the build tree: no writes to $HOME, no registry lookups.
export CARGO_HOME="$PWD/.cargo"
export CARGO_NET_OFFLINE=true

# Distribution link hardening. Fedora's %%build_rustflags is deliberately not
# used: it sets debuginfo and strip options that would contradict the release
# profile above and silently change what this package ships relative to the
# upstream signed binaries.
export RUSTFLAGS="-Clink-arg=-Wl,-z,relro,-z,now ${RUSTFLAGS:-}"

cargo build %{?_smp_build_ncpus:-j%{_smp_build_ncpus}} \
    --release --locked --offline -p amf-cli

# License manifest for the bundled crates. Anyone auditing what is inside this
# binary should not have to unpack the SRPM to find out.
{
    echo "# Rust crates bundled into %{name}-%{version}-%{release}."
    echo "# Generated at build time from the vendored sources."
    echo "#"
    echo "# columns: crate, version, license -- tab separated"
    for dir in vendor/*/; do
        crate_dir=$(basename "$dir")
        name=$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)
        version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)
        license=$(sed -n 's/^license *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)
        if [ -z "$license" ]; then
            # A few crates ship license-file instead of an SPDX expression.
            license_file=$(sed -n 's/^license-file *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)
            if [ -n "$license_file" ]; then
                license="see $crate_dir/$license_file"
            else
                license="UNDECLARED (see $crate_dir)"
            fi
        fi
        printf '%s\t%s\t%s\n' "${name:-$crate_dir}" "${version:-unknown}" "$license"
    done | LC_ALL=C sort
} > cargo-vendor.txt

%install
install -Dpm 0755 target/release/%{bin_name} %{buildroot}%{_bindir}/%{bin_name}
install -Dpm 0644 %{SOURCE2} %{buildroot}%{_mandir}/man1/%{bin_name}.1

%check
export CARGO_HOME="$PWD/.cargo"
export CARGO_NET_OFFLINE=true

# The suite is hermetic by construction: every test that touches huggingface.co
# or modelscope.cn is #[ignore]d upstream, so this needs no network. --release
# reuses the artifacts from %%build rather than compiling the tree a second time.
cargo test %{?_smp_build_ncpus:-j%{_smp_build_ncpus}} \
    --release --locked --offline --workspace

# The packaged binary must at least be able to introduce itself.
%{buildroot}%{_bindir}/%{bin_name} --version

%files
%license LICENSE
%license cargo-vendor.txt
%doc README.md
%doc ARCHITECTURE.md
%{_bindir}/%{bin_name}
%{_mandir}/man1/%{bin_name}.1*

%changelog
* Sun Aug 09 2026 clem <clem@pendragon.systems> - 0.1.0-1
- Initial package
