# Build image for `cargo xtask dist`.
#
# The toolchain is pinned by content, not by tag: the base image carries a
# digest, zig and cargo-zigbuild carry exact versions, and cargo-zigbuild is
# installed --locked. A tag like `rust:1.97.1-bookworm` is mutable and gets
# rebuilt for base-image security updates, so pinning only the tag would let the
# compiler change under a "reproducible" build without anything noticing.
#
# What is *not* pinned, stated plainly rather than papered over: the two apt
# packages below resolve to whatever Debian ships that day. They supply the venv
# that carries zig, not anything linked into the binary, so the exposure is
# small — but `--verify-reproducible` rebuilds inside the *same* container and
# therefore cannot detect drift here. Only rebuilding the image and comparing
# would. See ARCHITECTURE.md §12.
#
# No macOS SDK is vendored here. Apple licenses it for use on Apple hardware,
# and `cargo xtask dist --sdkroot <path>` exists so a developer can point at
# their own copy instead. See ARCHITECTURE.md §12.

# Digest for rust:1.97.1-bookworm, resolved 2026-08-09. Update the version and
# the digest together, never one alone.
ARG RUST_VERSION=1.97.1
ARG RUST_DIGEST=sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3
FROM rust:${RUST_VERSION}-bookworm@${RUST_DIGEST}

ARG ZIG_VERSION=0.13.0
ARG CARGO_ZIGBUILD_VERSION=0.19.8

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# PEP 668 marks the system Python as externally managed; a venv keeps the pinned
# zig out of the way of anything else in the image.
RUN python3 -m venv /opt/zig-venv \
    && /opt/zig-venv/bin/pip install --no-cache-dir "ziglang==${ZIG_VERSION}"
ENV PATH="/opt/zig-venv/bin:${PATH}"

RUN cargo install cargo-zigbuild --version "${CARGO_ZIGBUILD_VERSION}" --locked

RUN rustup target add \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-pc-windows-gnu \
    x86_64-apple-darwin \
    aarch64-apple-darwin

WORKDIR /work
