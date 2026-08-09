# almanac-model-fetch

Runs on a networked machine. Downloads a model you choose, verifies it against
upstream-published hashes as it streams, captures what provenance exists, signs
the result, and writes a self-contained bundle a USB drive can carry to an
airgapped machine that has no network at all.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and the trust model.

## Usage

```bash
# One-time: create the signing key. The public half goes to the airgapped box.
amf keygen --secret amf.key --public amf.pub

# Fetch. Multiple models per run; each is bundled separately.
amf fetch unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M --usb /mnt/usb --key amf.key
amf fetch unsloth/Qwen3-8B-GGUF:UD-Q4_K_XL unsloth/DeepSeek-R1-GGUF:UD-IQ1_S \
    --usb /mnt/usb --key amf.key

# From a network that cannot reach HuggingFace (mainland China, typically).
# Never automatic: switching hosts changes what the bundle can prove, so it is
# always the operator's decision.
amf fetch unsloth/Qwen3-8B-GGUF:UD-Q4_K_XL --source modelscope \
    --usb /mnt/usb --key amf.key

# On the airgapped machine — no network, no keyserver, no clock needed.
amf verify /mnt/usb --public-key amf.pub
amf list /mnt/usb

# If you have obtained the upstream host's signing key out of band, pin it
# (enables real Tier-2 verification on every subsequent fetch) and use it to
# check the captured commit signature on the airgapped side too:
amf trust add huggingface hf-signing-key.asc
amf verify /mnt/usb --public-key amf.pub --upstream-key hf-signing-key.asc
```

Repo specs are `org/name[@revision][:variant]`. Omit the variant to get an
interactive picker; pass `--variant` for scripts. A revision always resolves to
an immutable commit SHA before anything is fetched, and the bundle records that
SHA rather than the branch name. If a host cannot name its head commit in full,
the bundle records the abbreviated id *as* abbreviated and says so — it never
presents a prefix as an immutable revision.

## Cross-source corroboration

Every fetch asks the *other* host whether it publishes the same SHA-256, before
downloading anything. Two independent hosts agreeing is cheap, real evidence.

```bash
amf fetch … --no-corroborate                              # skip the check
amf fetch … --corroborate-with modelscope:Org/Mirror-Name # non-identical mirror
amf fetch … --require-corroboration                       # refuse without it
```

A miss is silent — an operator who chose ModelScope because HuggingFace is
blocked cannot be expected to reach it, and warning every time would be noise. A
*disagreement* is loud, and recorded in the manifest, but does not by itself
abort: two hosts can legitimately differ after a re-quantisation, unlike a
single host contradicting its own signed tree, which always aborts.

## Bundle layout

```
<usb>/almanac/models/<org>__<repo>__<variant>__<digest12>/
├── model/…                     the GGUF file, or the whole shard set
├── manifest.json               the signed root — commits to every file hash,
│                               including every evidence file's
├── manifest.json.minisig       ed25519 detached signature
└── evidence/
    ├── commit.obj              the GPG-signed commit, byte-for-byte
    ├── commit.sig.asc          its signature, extracted
    ├── tree/<oid>.obj          tree objects on the path to each file
    └── lfs/<oid>.pointer       the LFS pointers naming each SHA256
```

The directory name is content-addressed, so re-fetching the same variant at the
same revision lands on the same path and is skipped without re-downloading.

## Trust model, in short

Three tiers, each reported honestly in `manifest.json`, and none of them ever
claimed more strongly than what was actually checked:

1. **Content hash** — every byte is verified against upstream's published SHA256
   as it streams. Overruns abort immediately rather than at the end of a 40 GB
   transfer, and resumed downloads re-hash the existing prefix so resumed bytes
   are checked exactly as strictly as fresh ones.
2. **Upstream signature** — HuggingFace GPG-signs its commits, and that signature
   covers the tree, which covers the LFS pointer, which names the SHA256 we
   verify against. The signed commit and trees are captured into the bundle over
   git smart-HTTP, the chain is cross-checked against the REST API before any
   bytes download, and `amf verify` re-derives it offline. Without key material
   the signature is *observed* (issuer fingerprint recorded, changes alarmed),
   never claimed verified; pin the host's public key with `amf trust add` to get
   real verification, and a pinned-key mismatch hard-fails the fetch.
3. **Bundle signature** — the fetcher signs the manifest with minisign. This is
   the tier an airgapped importer should gate on, and the only trust root fully
   under your control.

## FAT32 is refused

GGUF files routinely exceed FAT32's 4 GiB per-file ceiling. The destination
filesystem is checked at preflight — before any bytes are downloaded — and FAT is
refused outright, even when the current selection would fit, because a drive
accumulates bundles over time and the next model will not fit. `--force` does not
override this.

## Status

Working and exercised against live HuggingFace:

- Repo resolution, variant listing, shard grouping (a variant is a file *set*).
- Streaming verified download with HTTP Range resume.
- Content-addressed bundles, dedup, atomic writes, fsync.
- minisign keygen / signing / offline verification.
- FAT refusal and free-space preflight.
- Offline `verify` that detects both a flipped byte in a model and an edited
  manifest.

Also working, since the Tier-2 milestone:

- **Full git evidence capture**: signed commit + trees over a hand-rolled git
  protocol-v2 smart-HTTP client (`filter blob:none`, `deepen 1`, own packfile
  parser with delta support), LFS pointers over `/raw/`; every object verified
  against its OID; `content_hash.via` is `lfs_pointer` and the chain-derived
  hash anchors the download. Chain-vs-REST disagreement aborts the fetch loudly.
- **Tier-2 signature handling** per the continuity/verification split: issuer
  fingerprints observed and alarmed on change; `amf trust add` pins a real key
  and enables cryptographic verification (rpgp); pinned-key mismatch hard-fails.
- **Offline chain re-derivation** in `amf verify`, plus `--upstream-key` to
  check the captured commit signature airgapped.

And since the ModelScope milestone:

- **ModelScope**, at full parity: same trait, same evidence capture over git,
  same bundle layout. It publishes a SHA-256 for *every* file — even the small
  ones HuggingFace leaves unhashed — so its Tier-1 coverage is broader. Its
  commits are unsigned, and the manifest records that rather than glossing it.
- **Cross-source corroboration**, on by default and never blocking.
- **`cargo xtask dist`** for reproducible cross-compiled release artifacts with
  a signed `SHA256SUMS`.

Known limits, stated rather than buried:

- **HF's signing key remains unpublished**, so Tier 2 on a fresh install is
  observation-only until you obtain and pin the key out of band.
- **ModelScope's LFS CDN was unreachable from the development machine**, so its
  download path is the one part of that backend not exercised end-to-end here.
  Everything up to the bytes is covered by live tests.
- **macOS artifacts are built but never executed** by the Linux release job;
  only a macOS runner can smoke-test them.

C2PA is **out of scope**: no repo checked ships a C2PA manifest in any form —
not as a sidecar, not in GGUF metadata — so the tool does not claim to look for
one. See ARCHITECTURE.md §1.

## Releases

```bash
cargo xtask image                      # build the pinned toolchain container
cargo xtask dist --verify-reproducible # musl + windows, built twice and diffed
cargo xtask dist --sign release.key    # emits SHA256SUMS + SHA256SUMS.minisig
```

Apple targets need `--sdkroot <path>` pointing at your own macOS SDK; none is
vendored here, because Apple licenses it for use on Apple hardware. The release
key is deliberately **separate from any bundle-signing key** — different
lifetime, different blast radius — and its public half belongs in the repository
so that a first-time downloader can check a binary without already having one.

`SHA256SUMS` is in coreutils format, so `sha256sum -c SHA256SUMS` works for
anyone who would rather not take this tool's word for the checking either, and
`SHA256SUMS.minisig` is standard minisign, verifiable with the `minisign` CLI.

What has actually been run: the musl artifact was built and verified static.
The container image and the aarch64/Windows targets are **written but not yet
exercised** — see ARCHITECTURE.md §14 for exactly what was and was not proven.

## RPM packaging

For Fedora and friends, `packaging/rpm/` builds an RPM carrying `amf`, its man
page, and these documents. Crates are bundled from `Cargo.lock` and the build
runs `--offline --locked` against them, for the same reason the rest of this
tool exists: dependencies resolved from the network at build time are not
pinned inputs.

```bash
packaging/rpm/make-srpm.sh                     # -> packaging/rpm/out/*.src.rpm
mock -r fedora-42-x86_64 packaging/rpm/out/*.src.rpm
```

COPR builds it straight from git through `.copr/Makefile`; see
[packaging/rpm/README.md](packaging/rpm/README.md) for the project setup and
for what this spec would still need before Fedora proper would take it.

What has actually been run: the SRPM builds, and rebuilding it locally passes
`%prep`, `%build`, `%check`, and `%install`. **No COPR build has been
submitted**, and no mock build has been run.

## Tests

```bash
cargo test --workspace              # hermetic; works offline
cargo test --workspace -- --ignored # live tests against huggingface.co
```

Tests run against real captured data wherever it matters: real `mkfs.fat` boot
sectors, real HuggingFace tree listings, and a real GPG-signed HuggingFace commit
whose chain down to a 5 GB model's SHA256 is re-derived offline.
