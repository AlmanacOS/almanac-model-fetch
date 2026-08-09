# almanac-model-fetch — Architecture

Packaging CLI. Runs on a networked machine, fetches a model the operator chooses,
verifies it against upstream-published hashes as it streams, captures the
provenance that actually exists, signs the result, and writes a self-contained
bundle to a USB drive that an airgapped box can import and independently
re-verify with no network at all.

This document describes the system as built and why it is built that way. It is
a reference, not a plan; the sequence the work happened in lives in git history.

---

## 1. What the reconnaissance established

The original spec assumed C2PA manifests ship alongside Unsloth models. They do
not — not as sidecar files, not embedded in GGUF metadata, on any repo checked
(`unsloth/Llama-3.2-1B-Instruct-GGUF`, `Qwen3-8B-GGUF`, `gpt-oss-20b-GGUF`,
`DeepSeek-R1-GGUF`). Building around `provenance.c2pa` as the trust anchor would
have produced a tool that either always fails or always writes an empty file, so
**C2PA is out of scope entirely** (§11).

What does exist is better, and the design is built on it:

| Layer | HuggingFace | ModelScope |
|---|---|---|
| Commit GPG signature | **Yes** — `system@huggingface.co`, key `C8A81786 0F8BA646 BF061291 6A528E38 E0733467` | No — unsigned |
| Signing key published | **No** — absent from keyservers, docs, and API | n/a |
| LFS pointer `oid sha256` inside the tree | Yes | Yes |
| Per-file SHA256 via REST | LFS objects only (`lfs.oid`) | **Every file** (`Sha256`) |
| Branch → commit SHA over REST | Yes | No — resolved over git `ls-refs` instead |
| C2PA | None found | None found |

The critical structural fact: **the HuggingFace commit signature covers the tree,
the tree contains the LFS pointer blob, and the pointer contains the
`oid sha256:` the download is stream-verified against.** That is a cryptographic
chain from HF's signing key to the model bytes — with one caveat, that the
internal commit→tree→blob links are git SHA-1 (§12). Confirmed by hand:

```
commit a6adef13 (gpgsig present)  →  tree 116f6efc
  → blob Qwen3-8B-Q4_K_M.gguf = "oid sha256:120307ba…449bd4, size 5027784512"
```

Two consequences drive the architecture:

1. **Integrity is provable without HF's key.** Capturing the signed commit
   object and the tree path lets the airgapped verifier re-derive the hash chain
   offline.
2. **Authenticity is not provable with HF's key** — it is unpublished. So the
   tool supplies its own trust root by signing the bundle (§3, Tier 3).

Also confirmed: `Qwen3-8B-Q4_K_M.gguf` has SHA256 `120307ba…449bd4` on *both*
hosts. Independent hosts agreeing is cheap, real corroboration (§8).

---

## 2. The governing principle

**The tool never reports a stronger status than it actually established.**

Almost every design decision below follows from that one sentence, and most of
the subtle bugs found during development were violations of it: a fingerprint
comparison described as "verification", an unsigned commit described as
"signed", a failed evidence capture recorded as "signature present", a partial
corroboration match satisfying a flag that promises a full one. The manifest's
job is to let a reader tell what was checked from what was assumed, and the
status vocabulary is designed so that distinction survives contact with a
hurried reader.

---

## 3. Trust model

Three tiers, each independently useful, each honestly labelled in the manifest.

### Tier 1 — Content-hash chain (always, no key material required)

The streamed bytes are verified against the `sha256` in the LFS pointer that
lives in the commit-signed tree. The bundle carries the raw git objects, so this
is re-derivable offline. Defeats CDN tampering, corrupted transfer, truncated
download, and substitution of any file the host's own signed index does not
name.

### Tier 2 — Upstream signature (captured always, verified only with key material)

The `gpgsig` commit object is captured byte-for-byte. Two operations here are
distinct and must never be conflated:

- **Continuity observation** — possible today, without HF's key. Record the
  issuer fingerprint the signature names on first contact; flag loudly if a
  later fetch shows a different one. This detects a key *change* mid-history; it
  proves nothing about identity, because a fingerprint is a claim inside
  attacker-suppliable data, not key material. Comparing fingerprints is string
  comparison, not cryptography.
- **Verification** — possible only once the host's actual public key is obtained
  out of band. Only then is the signature mathematically checked, only then is
  `verified` ever emitted, and what gets pinned is the **key**, not its
  fingerprint.

Manifest status is exactly one of:

| Status | Means |
|---|---|
| `verified` | Checked against a pinned public key. The only status that claims authenticity. |
| `signature_present_key_unpinned` | A signature exists and names an issuer; no key was held, so nothing was checked. |
| `signature_present_key_mismatch` | A signature exists and failed against the pinned key. Hard-fails the fetch. |
| `unsigned` | A commit object *was* retrieved and examined, and carried no signature. ModelScope's normal state. |
| `unknown` | No commit object was retrieved at all, so no finding was made. |

The last two are kept apart deliberately. "We looked and found nothing" and "we
never looked" read alike in prose and are entirely different facts; collapsing
them would let a failed evidence capture pass for a finding.

The trust store pins **keys**; observed-fingerprint history is kept as a
separate, explicitly weaker record. A pinned-key mismatch is not overridable by
`--force`: if a host genuinely rotated its key, the correct path is to
re-confirm out of band and re-pin, not to shrug past a failed verification.

### Tier 3 — Bundle signature (the tier that closes the airgap)

The fetcher signs `manifest.json` with ed25519 in minisign format. The signed
trusted-comment also names the bundle digest, so a signature cannot be lifted
onto a different bundle. The manifest commits to every model file's hash and to
every `evidence/` file's hash, so one signature covers the whole bundle
transitively. The airgapped box holds only the public key, provisioned out of
band. No PKI, no network, no transparency log.

**Tier 3 is what an importer should gate on.** Tiers 1 and 2 are the evidence
that the fetcher was not itself deceived, preserved so it can be audited later.

---

## 4. Repository layout

```
almanac-model-fetch/
├── Cargo.toml                    workspace root
├── crates/
│   ├── amf-cli/                  arg parsing, prompts, progress, main()  [bin: amf]
│   ├── amf-source/               Source trait + backends, git protocol, downloads
│   ├── amf-verify/               streaming hash, git objects, LFS, OpenPGP, minisign
│   ├── amf-bundle/               bundle layout, manifest, dedup, atomic writes
│   └── amf-fs/                   filesystem detection (exFAT/FAT32), free space
├── xtask/                        build and release automation
└── dist/Dockerfile               pinned cross-compilation toolchain
```

Splitting `amf-verify` and `amf-bundle` out of the CLI matters because the
airgapped-side importer (a later tool) needs exactly those two crates and must
not drag in HTTP or TUI dependencies. `xtask` is a workspace member but never
part of a shipped binary — a plain `cargo build` remains sufficient for
development.

### Key dependencies

`clap` (derive) · `tokio` + `reqwest` (rustls on **ring**, streaming, range
requests) · `sha2`/`sha1`/`hex` · `serde`/`serde_json` (manifest byte-stability
comes from fixed struct field order, so no `preserve_order` feature is needed) ·
`indicatif` · `dialoguer` · `minisign` · `flate2` (rust backend, for packfile
inflation) · `libc`/`windows-sys` for §9 · `thiserror`/`anyhow`.

OpenPGP is `pgp` (rpgp) — pure Rust, so it does not fight the static-musl goal
the way sequoia's default C-nettle backend would. Either way, no shelling out to
`gpg`: a static binary, no external dependency on the target, and parsing
signatures in-process avoids the classic "trusted the exit code of a program
that wasn't there" failure.

The git protocol client and packfile parser are hand-rolled rather than taken
from a dependency. They sit directly on the trust path, they are small, and
auditable code beats convenience there.

---

## 5. Source abstraction

```rust
#[async_trait]
pub trait Source: Send + Sync {
    fn kind(&self) -> SourceKind;
    /// Where this host serves its API, bytes, and git objects.
    fn endpoints(&self) -> HostEndpoints;
    /// Resolve a spec's revision to an immutable commit SHA.
    async fn resolve(&self, spec: &RepoSpec) -> Result<Revision, SourceError>;
    /// List every file at a resolved revision.
    async fn list_files(&self, rev: &Revision) -> Result<Vec<RemoteFile>, SourceError>;
    /// Fetch the LFS pointer *text* for a file — not the file's contents.
    async fn fetch_pointer(&self, rev: &Revision, path: &str) -> Result<Vec<u8>, SourceError>;
    /// Provided: group files into selectable variants.
    async fn list_variants(&self, rev: &Revision) -> Result<Vec<Variant>, SourceError> { … }
}
```

`HostEndpoints` carries `api_base`, `resolve_base`, `git_base`, and `git_suffix`
(hosts disagree about whether a smart-HTTP path ends in `.git`). Every URL is
built through it, including one `file_url` that percent-encodes path segments —
a repo file named `v1#final.gguf` would otherwise truncate at the fragment and
silently fetch something else. A `git_base` of `None` means the host serves no
git endpoint, which structurally selects REST-only evidence rather than failing
at request time.

`fetch_pointer` is a trait method rather than another URL template because hosts
do not agree on how to serve pointer text: HuggingFace has a `/raw/` path that
returns the pointer verbatim, while ModelScope's `/raw/` is a web-app route and
its pointer arrives wrapped in a JSON envelope. Whatever comes back is checked
against the blob id recorded in the signed tree, so a host that mangles the
bytes fails loudly rather than quietly.

Downloading is deliberately *not* a trait method: both hosts serve bytes over
plain HTTPS, so one free function (`amf_source::download::download_verified`)
handles streaming, hashing, and Range-based resume for every backend.

### Revisions

```rust
pub enum RevisionPrecision { Commit, Abbreviated { chars: usize } }
```

Both hosts normally yield `Commit` — HuggingFace over REST, ModelScope over git
`ls-refs`. `Abbreviated` is the degraded path: a host whose git endpoint is
unreachable, leaving only a short id from a REST field. An 8-hex prefix is about
four billion possibilities — adequate against accident, meaningless against an
adversary who can grind commits — so the fetch warns once, names the remedy
(`org/name@<full-40-hex>`), and the manifest records which case happened. A
head SHA is never reconstructed from a parent id plus a short id; that would put
a fabricated value where an attested one belongs.

Repo spec grammar: `org/name[@revision][:variant]`, e.g.
`unsloth/Llama-3-8B-GGUF:Q4_K_M`, `unsloth/Qwen3-8B-GGUF@a6adef13:UD-Q4_K_XL`.

### Variants are file *sets*

Sharded quants (`DeepSeek-R1-UD-IQ1_S/…-00001-of-00003.gguf`) are the norm for
large models, and are exactly the models most likely to be hand-carried to an
airgap. Grouping rule: strip the `-\d{5}-of-\d{5}` suffix and cluster; a
directory of shards presents as one selectable variant with a summed size. A
variant missing a shard upstream is refused rather than partially fetched.

### HuggingFace — the default source

`/api/models/{id}/tree/{rev}?recursive=true` for listing (paginated via the
`Link` header, bounded by `MAX_PAGES`); `/resolve/{rev}/{path}` for model bytes;
`/raw/{commit}/{path}` for pointer text; git smart-HTTP for the signed commit
and trees. Unknown repos answer **401**, not 404 — HuggingFace deliberately
refuses to confirm existence — so the error says the repo may not exist *or* may
be gated, and names `HF_TOKEN`.

### ModelScope — secondary, explicitly selected

`/api/v1/models/{id}/repo/files?Revision=&Recursive=True` supplies `Sha256` for
*every* file, LFS or not, so ModelScope's Tier-1 coverage is strictly broader
than HuggingFace's. Its REST API cannot name a branch's head commit
(`/revisions` returns names only; `LatestCommitter.Id` is empty), so revision
resolution goes over git `ls-refs`, which returns the full 40-hex id. Tier 2 is
always `unsigned` — asserted by a test against a real captured commit, not
assumed. Unknown repos answer **404**, and since that is also the answer for
private repos, the error names `MODELSCOPE_API_TOKEN` rather than claiming the
repo is absent.

> **ModelScope's edge filters by User-Agent.** Requests to `*.git/*` whose
> `User-Agent` does not begin with `git/` are rejected with **HTTP 421
> `mirror self-forwarded loop detected`** — which reads like a proxy fault and
> is not. Every other header, host, and path shape is irrelevant. Git-protocol
> requests therefore send
> `User-Agent: git/2.43.0 (almanac-model-fetch/<version>)`, which is accurate
> rather than an impersonation: on those requests this tool genuinely is a git
> client speaking protocol v2, and the suffix names it. A bare tool name is
> rejected, so **the `git/` prefix is load-bearing and must not be tidied up.**

**ModelScope is a fallback for operators who cannot reach HuggingFace** —
primarily from mainland China — not a peer the tool load-balances across:

- HuggingFace is the default; ModelScope requires an explicit `--source modelscope`.
- **No automatic failover.** If HuggingFace is unreachable the tool fails with a
  message naming `--source modelscope` as the remedy, and stops. Silently
  switching hosts would change the trust properties of a fetch (signed →
  unsigned commits) without the operator deciding to accept that, which is
  precisely the decision they should be making consciously.
- Everything downstream of `Source` is host-agnostic, so both paths produce an
  identically-structured bundle. The airgapped importer neither knows nor cares
  which host a bundle came from, beyond what the manifest records.

---

## 6. Evidence capture

Evidence is captured **before** any bytes are downloaded, so a problem surfaces
before an hour of transfer rather than after it.

1. The commit object and all reachable trees come over git smart-HTTP: protocol
   v2, `command=fetch`, `want <commit>`, `filter blob:none`, `deepen 1`. The
   whole exchange is around 2 KB.
2. LFS pointer blobs come per-file through `Source::fetch_pointer`.
3. Every object's id is **recomputed from its bytes**. Nothing from the network
   is trusted by its claimed name.
4. The chain is walked — commit → tree → … → pointer → `sha256` — deriving an
   expected hash for every selected file.
5. That chain-derived hash is **cross-checked against the REST API's
   independently served hash**. Disagreement aborts the fetch loudly: it means a
   single host is contradicting itself, which is always wrong, and there is no
   safe way to pick a side.
6. The chain-derived hash then anchors the download itself.

If capture fails, the fetch degrades to REST-reported hashes with a warning, and
the manifest records that honestly (`evidence: absent`, `content_hash.via:
rest_api`, `upstream_signature: unknown`).

The packfile parser is written against hostile input: a bounded object count
(the wire-supplied count is checked against the pack's byte budget before any
allocation), a 64 MiB per-object ceiling, truncated-zlib detection, trailer
verification before parsing, and ofs/ref-delta resolution. Response bodies are
read through a capped reader — 1 MiB for a capability advert, 256 MiB for a
fetch response, 64 KiB for a pointer, 16 MiB for a JSON listing — so a host that
answers a pointer request with a 5 GB model cannot exhaust memory before the
caller rejects it.

---

## 7. Bundle format

```
<usb>/almanac/models/<org>__<repo>__<variant>__<digest12>/
├── model/
│   ├── Qwen3-8B-Q4_K_M.gguf              (or the shard set)
│   └── …
├── manifest.json                          canonical JSON, the signed root
├── manifest.json.minisig                  ed25519 detached signature
└── evidence/
    ├── commit.obj                         raw commit object, byte-for-byte
    ├── commit.sig.asc                     extracted gpgsig, armored
    ├── tree/<oid>.obj                     tree objects on the path
    ├── lfs/<oid>.pointer                  LFS pointer blobs, named by blob id
    └── api/<endpoint>.json                REST responses as received
```

Evidence files are named by their git object id, not by repo path: two files
with the same basename in different directories would otherwise collide,
silently overwriting an evidence file and leaving the manifest listing
conflicting digests for one path. A filename carries no authority anyway — the
verifier keys every object by the id it recomputes from the bytes.

`<digest12>` is the first 12 hex of the bundle digest: SHA256 over the sorted,
length-delimited list of `(relative_path, sha256, size)` for every file under
`model/`. Length-delimited so a path containing the separator cannot be crafted
to collide with a different file set. Content-addressed, so re-fetching the same
variant at the same revision lands on the same directory name and dedup is a
directory-existence check plus a digest comparison — no re-download, no re-hash
of tens of gigabytes.

### Manifest schema (version 2)

`manifest.json` records the tool name and version, source host, repo ID,
resolved commit SHA and its precision, requested revision, variant label,
per-file `{path, sha256, size}`, bundle digest, UTC fetch timestamp, the Tier-1
and Tier-2 verification statuses, the evidence kind, corroboration results, and
digests of every evidence file.

```rust
pub enum EvidenceKind {
    Chain,      // signed commit + trees + pointers: hashes re-derivable offline
    RestOnly,   // API responses only: hashes are the host's word over TLS
    Absent,     // nothing captured
}
```

One field rather than a pair of booleans (`evidence_captured`,
`chain_rederivable`): those admit a fourth, meaningless combination that nothing
would reject, and these are the three states that actually exist. Note that
`amf verify` does not *trust* this field — it re-derives from whatever evidence
is on disk and reports what it found. The value is a description for a reader
who is not running the verifier, which is exactly the reader who most needs it
unambiguous.

`revision_precision` is deliberately redundant with the commit id's own length;
`amf verify` cross-checks the two, so a manifest claiming exactness for a short
id is caught rather than believed.

**Tier 3 is deliberately not a manifest field.** The signature's presence is a
fact about the bundle, not a claim inside it — a manifest cannot vouch for its
own signature — so the `.minisig` file alongside it is the only place that tier
lives.

The schema version is checked **before** any other field is read, by parsing a
minimal probe struct first. A manifest from another schema usually fails on
whichever field moved, and `missing field 'evidence'` tells an operator nothing
about what to do; reading the version first yields "this bundle uses manifest
schema 1, which predates the current schema 2. Re-fetch it with this build."

---

## 8. Fetch pipeline

1. Parse the repo spec; resolve the revision to an immutable commit SHA.
2. List files; group into variants; if no `:variant` was given, present an
   interactive picker (size, quant, shard count) — `--variant`/`--yes` for
   scripting. Refuse a variant with missing shards or unhashed files.
3. **Capture evidence** and cross-check the chain against the REST API (§6).
4. **Tier 2 assessment** per the §3 split: parse `gpgsig`, record the issuer
   fingerprint against the continuity history, and *verify* only if a pinned
   public key is held. A mismatch hard-fails here.
5. **Dedup check** — if the content-addressed bundle already exists and matches,
   stop. This precedes corroboration so that re-running a fetch over a populated
   drive costs nothing and cannot fail on account of an unreachable third party.
6. **Corroboration** (§9), before the download so a disagreement reaches the
   operator early.
7. **Preflight** the destination: filesystem type (§10), free space against the
   summed size.
8. **Download** into a *sibling* staging directory, `<bundle>.partial/`, hashing
   the stream as it lands. Sibling, not inside the bundle: the bundle directory
   must never exist until it is complete. Abort the moment the running hash
   cannot match — an overrun is caught mid-stream, not at the end of a 40 GB
   transfer. Resume via HTTP Range re-hashes the existing prefix, so resumed
   bytes are verified exactly as strictly as fresh ones; a partial file *longer*
   than the target is discarded, not trusted; a server that ignores `Range` and
   answers 200 restarts cleanly.
9. Write the evidence files and their digests, then `manifest.json`, then sign
   it.
10. `fsync` files and directory, atomically rename `<bundle>.partial/` into
    place, and report the path and digest.

Interrupted runs leave `.partial/` and are resumable; the bundle directory only
ever appears complete. Repo specs are variadic (`amf fetch A B C --usb /mnt/usb`),
sharing one destination preflight, processed sequentially with a per-model
summary and a non-zero exit if any failed.

---

## 9. Cross-source corroboration

Every fetch asks the counterpart host whether it publishes the same SHA-256,
under a 5-second timeout with no retries. It never gates the fetch by default
and never extends it by more than that timeout.

- **Repo mapping**: the identical `org/name` first — mirrors of the repos this
  tool targets are in fact named identically. On a miss, `--corroborate-with
  <host>:<org/name>` lets an operator who knows the mirror name point at it.
  There is no built-in alias table: a stale entry would corroborate against the
  wrong model, and a false assurance is worse than none.
- **Every file** in the variant is compared, not just the largest, and the
  manifest records the file list rather than a count — "the model matched" and
  "the one file we bothered to check matched" are different claims. Paths are
  matched exactly first, falling back to basename only when unambiguous, so two
  quantisations sharing a shard name are never compared against each other.
- **Object ids are never compared across hosts.** ModelScope repos are mirrors;
  their git object ids need not match HuggingFace's for identical content. Only
  content hashes are comparable.
- **A miss is silent.** An operator who chose ModelScope because HuggingFace is
  blocked cannot reach it, and warning on every fetch for a condition they
  already know about and cannot fix is noise.
- **A mismatch is loud but not fatal.** Two independent hosts can legitimately
  differ after a re-quantisation or re-upload — unlike a single host
  contradicting its own signed tree, which always aborts. `--require-corroboration`
  is available for operators who want it to gate, and requires *all* hashed
  files to agree.

---

## 10. USB filesystem check

GGUF files routinely exceed FAT32's 4 GiB single-file ceiling, and the failure
mode is a truncated write partway through a 40 GB download.

- **Linux** needs three layers, because no single one suffices: `statfs`
  `f_type` magic for in-kernel filesystems (all of FAT12/16/32 share the one
  `MSDOS` magic `0x4d44`, so the magic alone cannot name the variant);
  `/proc/self/mountinfo` driver names, without which a FUSE-mounted exFAT or
  NTFS drive reports only the FUSE magic and would be misclassified; and a
  best-effort read of the FAT boot sector's BPB (cluster-count computation per
  the Microsoft spec) to tell FAT32 from FAT16 in the refusal message. The BPB
  read is decoration on an error path — it degrades to "FAT (vfat)" without
  root, and never fails a run.
- **macOS**: `statfs` `f_fstypename` (`"exfat"`, `"msdos"`).
- **Windows**: `GetVolumeInformationW`, which names the variant directly.

**FAT is refused outright** — regardless of whether the current selection happens
to fit under 4 GiB, and `--force` does not override it. The error names the exact
reformat command for the platform (`mkfs.exfat` / `diskutil eraseVolume ExFAT` /
`format /FS:exFAT`).

Refusing even the fits-today case is deliberate. A drive is a long-lived object:
it accumulates bundles across many runs, and the tool explicitly supports
multiple models per invocation. A FAT32 drive that accepts a 2 GB Q2_K today is
a drive someone writes a 40 GB Q8_0 to next month. Refusing at the filesystem
level makes the property hold for the life of the drive rather than for one
lucky invocation. `--force` exists for warnings an operator can reason about,
not for a limit the filesystem will enforce regardless of consent.

An unrecognised filesystem warns and proceeds: we cannot prove it unsuitable, so
refusing would block legitimate exotic setups.

The check runs at **preflight**, before any bytes are downloaded — discovering
this after a 40 GB transfer is the outcome the check exists to prevent.

---

## 11. CLI surface

```
amf fetch <repo-spec>... --usb <path> [--variant Q4_K_M]
                                     [--source hf|modelscope]   # default: hf
                                     [--key <secret-key>]       # signs the bundle
                                     [--trust-store <path>]     # must match `amf trust`
                                     [--yes] [--force]
                                     [--require-signature]
                                     [--no-corroborate]
                                     [--corroborate-with <host>:<org/name>]
                                     [--require-corroboration]
amf verify <path> [--public-key <pub>] [--upstream-key <asc>]
amf list <usb-path>
amf keygen [--secret …] [--public …] [--password …]
amf trust list | add <host> <key.asc> | remove <host>  [--trust-store <path>]
```

A revision is pinned in the spec itself (`org/name@<rev>`); there is no separate
`--revision` flag. Without `--key` the bundle is written unsigned, with a loud
warning that the airgapped side can then check contents but not origin.

`amf trust` manages pinned **keys** and shows, separately, the
observed-fingerprint history (stored in the user config dir, or
`$AMF_TRUST_STORE`). Re-pinning over an existing different key requires an
explicit `remove` first. Observation history is bounded, so a host alternating
between two keys cannot grow the store without limit — while still alarming on
every switch.

`amf verify` requires no network and no upstream key: it re-derives the Tier-1
chain and checks the Tier-3 signature. It is the command the airgapped operator
runs, shipped in the same binary so the drive can carry its own verifier. In
order it checks: every model file's hash; the bundle digest against the file
list; every evidence file's hash; the offline chain re-derivation; optionally
the upstream commit signature (`--upstream-key`); and the bundle signature,
including that its trusted comment covers *this* bundle's digest.

Manifest-supplied paths are refused unless they are plain relative paths inside
the bundle. Until the bundle signature is checked, every path in the manifest is
attacker-suppliable, and joining one containing `..` would make the verifier
read — and echo the hash of — arbitrary files.

---

## 12. Build and release

`cargo xtask dist` builds `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, and `x86_64-pc-windows-gnu` unattended in a pinned
container (`dist/Dockerfile`, base image pinned by digest, zig and
cargo-zigbuild pinned by version). musl gives genuinely static Linux binaries;
`rustls` on `ring` means there is no OpenSSL anywhere to link.

Apple targets build **only** against an operator-supplied macOS SDK
(`--sdkroot`). No SDK is vendored — Apple licenses it for use on Apple hardware,
and a licensing problem checked into the repo is still a licensing problem. The
clean path is a macOS CI runner, which builds them natively.

Reproducibility: the toolchain is pinned, builds use `--locked`,
`SOURCE_DATE_EPOCH` comes from the commit timestamp, and `--remap-path-prefix`
keeps the builder's directory layout out of the binary.
`--verify-reproducible` builds twice and fails the release on any difference.
(It rebuilds inside the *same* container, so it cannot detect drift in the
image's own apt packages; only rebuilding the image and comparing would.)

`dist` emits `SHA256SUMS` in coreutils format — so `sha256sum -c` works for
anyone who would rather not trust this tool's checking either — plus
`SHA256SUMS.minisig`. The release key is **separate from any bundle-signing
key**: different lifetime, different blast radius, and a compromised release key
is a much worse event than a compromised fetch key. Its public half belongs in
the repository so a first-time downloader can check a binary without already
having one. Unsigned `dist` output is allowed for local builds and says so
loudly.

---

## 13. Testing

Hermetic tests run against **real captured data** wherever it matters: genuine
`mkfs.fat` boot sectors, real HuggingFace tree listings, a real GPG-signed
HuggingFace commit whose chain down to a 5 GB model's SHA256 is re-derived
offline, and a real ModelScope file listing and `git-upload-pack` response. That
last one asserts ModelScope commits are genuinely unsigned, so the trust claim is
checked rather than assumed — if it ever stops being true, the test fails and the
documentation changes.

Live tests against both hosts are `#[ignore]`d and cover resolve, listing,
pointer retrieval through the JSON envelope, git evidence capture, Range resume,
and hash-mismatch rejection (`cargo test --workspace -- --ignored`). CI runs the
hermetic suite on every change; the live suite runs separately and is allowed to
fail, because CI must not go red because someone else's service had a bad
minute.

Regression tests exist specifically for the failure modes that produced silent
wrongness during development: a truncated zlib stream that would spin forever, a
wire-supplied object count that would trigger a vast allocation, a manifest path
escaping the bundle, an overlong resume that would hash-match its prefix, and a
schema check that ran too late to fire.

---

## 14. Known limits and open risks

- **HuggingFace's signing key is unpublished.** Without the key material, Tier 2
  can only observe fingerprint continuity, never verify. Obtaining the key out of
  band — or persuading HuggingFace to publish it — is the single change that
  would upgrade Tier 2 to real verification.
- **Key rotation is indistinguishable from attack** under a pin. The tool refuses
  and requires explicit operator re-pinning. Correct, and it will one day
  interrupt someone at an inconvenient moment.
- **ModelScope commits are unsigned**, so a ModelScope-only fetch rests on TLS
  plus the Tier-3 fetcher signature. This is the weakest configuration the tool
  supports, and it is also the one an operator behind the Great Firewall is
  forced into — the mitigation (corroborate against HuggingFace) is usually
  unavailable to exactly the people who need it most. `--source modelscope`
  trades away Tier 2, the manifest says so plainly, and the docs must not pretend
  otherwise. `--require-signature` refuses ModelScope by design.
- **The chain's internal links are SHA-1.** Git object ids — commit→tree→blob —
  are SHA-1, which is broken against chosen-prefix collision attacks. An attacker
  who could plant two colliding pointer blobs could make the signed tree vouch
  for either. Mitigations, in order: the final content check is always the
  pointer's SHA-256, so the model bytes themselves are never SHA-1-protected; the
  fetcher cross-checks the pointer hash against the REST API's independently
  served hash, so both channels would have to agree on the substituted blob; and
  a future hardening is swapping the plain `sha1` for a collision-detecting
  implementation (`sha1collisiondetection`). Until then, Tier 1's substitution
  guarantee at the tree/pointer links is as strong as SHA-1's collision
  resistance, and readers of the trust model should know that.
- **ModelScope revision resolution depends on an edge filter** (§5). If
  ModelScope ever tightens it, revisions degrade to an 8-hex `ShortId` and the
  tool says so rather than inventing precision. `org/name@<full-sha>` is
  unaffected either way.
- **ModelScope's LFS CDN is not reachable from every network.** Its API host
  answered normally from the development machine while
  `cdn-lfs-cn-1.modelscope.cn` timed out, so everything up to the bytes is
  exercised live but a complete ModelScope *download* is not. The failure is a
  plain transport error naming the URL, which is the right behaviour; it is
  nonetheless an untested path end-to-end, and the live Range test says so
  rather than passing quietly.
- **The container image and the aarch64/Windows targets are unexercised.** The
  musl artifact is built and verified static, but the registry pull for the base
  image stalled on the development machine, so `dist/Dockerfile` and the release
  workflow are written and not yet run. First CI run is where that gets proven;
  until then treat the container path as unverified rather than assumed good.
- **macOS artifacts will be built but not executed** by the Linux release job.
  `SHA256SUMS` covers them either way, so the risk is "this artifact was never
  run", not "this artifact is unattested" — and release notes must not blur the
  two.
- **C2PA may land later** in a form not yet specified. It is out of scope as of
  this revision; the re-entry path, if it materialises, is capture-and-record
  first (bytes stored verbatim with a digest in `evidence_files`), with
  validation as a separate decision when there is something real to point it at.
- **A hex-looking branch name is taken as an object id.** `@deadbeef` is treated
  as an abbreviated commit without asking the host whether it is a branch. The
  abbreviated-precision warning does fire, so the ambiguity is visible.

### Deliberate non-goals

- No automatic host failover: switching hosts silently changes a fetch's trust
  properties, so it stays an operator decision.
- No cross-host object-id comparison.
- No C2PA validation, and no status field for it.
- Shipping `amf` itself onto the USB drive, so an airgapped box has its own
  verifier without a second transfer, is an obvious follow-on — but it belongs
  with the importer tool, not the dist work.
