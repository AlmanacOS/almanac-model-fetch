# almanac-model-fetch — Implementation Plan

Packaging CLI. Runs on a networked machine, fetches a model the operator chooses,
verifies it against upstream-published hashes, captures every scrap of provenance
that actually exists, signs the result, and writes a self-contained bundle to a USB
drive that an airgapped box can import and independently re-verify with no network.

---

## 1. What the reconnaissance changed

The spec assumed C2PA manifests ship alongside Unsloth models. They do not — not as
sidecar files, not embedded in GGUF metadata, on any repo checked
(`unsloth/Llama-3.2-1B-Instruct-GGUF`, `Qwen3-8B-GGUF`, `gpt-oss-20b-GGUF`,
`DeepSeek-R1-GGUF`). Planning around `provenance.c2pa` as the trust anchor would
have produced a tool that either always fails or always writes an empty file.

What *does* exist is better, and the design is built on it:

| Layer | HuggingFace | ModelScope |
|---|---|---|
| Commit GPG signature | **Yes** — `system@huggingface.co`, key `C8A81786 0F8BA646 BF061291 6A528E38 E0733467` | No — unsigned |
| Signing key published | **No** — absent from keyservers, docs, and API | n/a |
| LFS pointer `oid sha256` inside the tree | Yes | Yes |
| Per-file SHA256 via REST | Yes (`lfs.oid`) | Yes (`Sha256`, all files) |
| C2PA | None found | None found |

The critical structural fact: **the HF commit signature covers the tree, the tree
contains the LFS pointer blob, and the pointer contains the `oid sha256:` we
stream-verify the download against.** That is an unbroken cryptographic chain from
HF's signing key to the model bytes. Confirmed by hand:

```
commit a6adef13 (gpgsig present)  →  tree 116f6efc
  → blob Qwen3-8B-Q4_K_M.gguf = "oid sha256:120307ba…449bd4, size 5027784512"
```

Two consequences drive the architecture:

1. **We can prove integrity without HF's key.** Capturing the signed commit object
   and the tree path lets the airgapped verifier re-derive the hash chain offline.
2. **We cannot prove authenticity with HF's key** — it is unpublished. So the tool
   supplies its own trust root by signing the bundle (§5).

Also confirmed: `Qwen3-8B-Q4_K_M.gguf` has SHA256 `120307ba…449bd4` on *both* HF and
ModelScope. Independent hosts agreeing is cheap, real corroboration — §6.

---

## 2. Trust model

Three tiers, each independently useful, each honestly labelled in the manifest. The
tool never reports a stronger status than it actually verified.

**Tier 1 — Content-hash chain (always, no key material required).**
Verify the streamed bytes against the `sha256` in the LFS pointer that lives in the
commit-signed tree. Bundle carries the raw git objects so this is re-derivable
offline. Defeats: CDN tampering, corrupted transfer, truncated download, and
substitution of any file that HF's own index does not name.

**Tier 2 — Upstream signature (captured always, verified when possible).**
Capture the `gpgsig` commit object byte-for-byte. On first encounter, present HF's
key fingerprint to the operator and TOFU-pin it to a local trust store; verify
against it thereafter. Manifest status is one of `verified`,
`signature_present_key_unpinned`, `signature_present_key_mismatch` (loud failure),
or `unsigned` (ModelScope's normal state). Never `verified` without a real check.

**Tier 3 — Bundle signature (the one that closes the airgap).**
The fetcher signs `manifest.json` with ed25519 in minisign format. The manifest
commits to every file hash and all captured upstream evidence, so one signature
covers the whole bundle transitively. The airgapped box holds only the public key,
pre-provisioned out of band. No PKI, no network, no transparency log.

Tier 3 is what an importer should actually gate on. Tiers 1 and 2 are the evidence
that the fetcher was not itself deceived, preserved so it can be audited later.

---

## 3. Repository layout

```
almanac-model-fetch/
├── Cargo.toml                    workspace root
├── crates/
│   ├── amf-cli/                  arg parsing, TUI prompts, progress, main()
│   ├── amf-source/               Source trait + HF and ModelScope backends
│   ├── amf-verify/               streaming hash, git object parsing, GPG, minisign
│   ├── amf-bundle/               bundle layout, manifest, dedup, atomic writes
│   └── amf-fs/                   filesystem detection (exFAT/FAT32), free space
└── xtask/                        cross-compilation driver (cargo-zigbuild)
```

Splitting `amf-verify` and `amf-bundle` out of the CLI matters because the
airgapped-side importer (a later tool) needs exactly those two crates and must not
drag in HTTP or TUI dependencies.

### Key dependencies

`clap` (derive) · `tokio` + `reqwest` (streaming, range requests) · `sha2` ·
`serde`/`serde_json` (`preserve_order`) · `indicatif` · `dialoguer` ·
`sequoia-openpgp` (pure-Rust OpenPGP — no gpg binary shell-out) ·
`minisign` · `sysinfo` + platform syscalls for §7 · `thiserror`.

`sequoia-openpgp` over shelling out to `gpg`: static binary, no external
dependency on the target, and parsing signatures in-process avoids the classic
"trusted the exit code of a program that wasn't there" failure.

---

## 4. Source abstraction

```rust
#[async_trait]
pub trait Source {
    async fn resolve(&self, repo: &RepoId, rev: Option<&str>) -> Result<Revision>;
    async fn list_variants(&self, rev: &Revision) -> Result<Vec<Variant>>;
    async fn evidence(&self, rev: &Revision) -> Result<Evidence>;
    async fn open_stream(&self, f: &RemoteFile, offset: u64) -> Result<ByteStream>;
}
```

`Variant` is **a set of files, not one file** — sharded quants
(`DeepSeek-R1-UD-IQ1_S/…-00001-of-00003.gguf`) are the norm for large models and are
exactly the models most likely to be hand-carried to an airgap. Grouping rule:
strip the `-\d{5}-of-\d{5}` suffix and cluster; a directory of shards presents as one
selectable variant with a summed size.

`Evidence` carries the raw signed commit object, the tree objects on the path to each
selected file, and the LFS pointer blobs — the material for offline re-derivation.

- **HuggingFace — the default source.** `/api/models/{id}/tree/{rev}?recursive=true`
  for listing; git smart-HTTP (`--depth 1 --filter=blob:none`, LFS smudge disabled)
  for the signed commit and tree objects; `/resolve/{rev}/{path}` for bytes.
- **ModelScope — secondary, explicitly selected.**
  `/api/v1/models/{id}/repo/files?Revision=&Recursive=True` supplies `Sha256` for
  every file directly. Same git-object capture, which records `unsigned` at Tier 2.

**ModelScope is a fallback for operators who cannot reach HuggingFace** — primarily
from mainland China — not a peer the tool load-balances across. Therefore:

- HF is the default; ModelScope requires an explicit `--source modelscope`.
- **No automatic failover.** If HF is unreachable the tool fails with a message
  naming `--source modelscope` as the remedy, and stops. Silently switching hosts
  would change the trust properties of the fetch (signed → unsigned commits) without
  the operator deciding to accept that, which is precisely the decision they should
  be making consciously.
- Everything downstream of `Source` is host-agnostic, so the fallback path produces
  an identically-structured bundle — the airgapped importer neither knows nor cares
  which host it came from, beyond what the manifest records.

Repo spec grammar: `org/name[@revision][:variant]`, e.g.
`unsloth/Llama-3-8B-GGUF:Q4_K_M`, `unsloth/Qwen3-8B-GGUF@a6adef13:UD-Q4_K_XL`.
Revision always resolves to an immutable commit SHA before anything is fetched;
`main` is recorded as the SHA it pointed to, never as `main`.

---

## 5. Bundle format

```
<usb>/almanac/models/<org>__<repo>__<variant>__<digest12>/
├── model/
│   ├── Qwen3-8B-Q4_K_M.gguf              (or the shard set)
│   └── …
├── manifest.json                          canonical JSON, the signed root
├── manifest.json.minisig                  ed25519 detached signature
├── evidence/
│   ├── commit.obj                         raw signed commit, byte-for-byte
│   ├── commit.sig.asc                     extracted gpgsig, armored
│   ├── tree/<oid>.obj                     tree objects on the path
│   ├── lfs/<path>.pointer                 LFS pointer blobs
│   └── api/<endpoint>.json                REST responses as received
└── provenance.c2pa                        only when C2PA actually exists
```

`provenance.c2pa` is written **only if a manifest is found**. Absence is recorded
explicitly in `manifest.json` as `{"c2pa": {"status": "absent", "searched":
["sidecar", "gguf_kv", "jumbf_box"]}}`, so a downstream reader can tell "not present
upstream" from "this tool didn't look". Silently writing an empty file would be worse
than useless — it would look like provenance.

`<digest12>` is the first 12 hex of the bundle digest: SHA256 over the sorted list of
`(relative_path, sha256, size)` for every file under `model/`. Content-addressed, so
re-fetching the same variant at the same revision lands on the same directory name
and dedup is a directory-existence check plus a manifest hash comparison — no
re-download, no re-hash of tens of gigabytes.

`manifest.json` records: tool name/version/build, source host, repo ID, resolved
commit SHA, variant label, per-file `{path, sha256, size}`, bundle digest, UTC fetch
timestamp, the three-tier verification statuses, corroboration results, and the
C2PA-absence record.

---

## 6. Fetch pipeline

1. Parse repo spec; resolve revision to an immutable commit SHA.
2. Fetch tree listing; group into variants; if no `:variant` given, present an
   interactive picker (size, quant, shard count) — `--variant`/`--yes` for scripting.
3. Capture evidence: signed commit object, tree path, LFS pointers, API responses.
4. Tier 2 check: parse `gpgsig`, TOFU-pin or verify the fingerprint, record status.
5. **Corroboration (best-effort, never blocking)**: query the counterpart host for
   the same repo/file under a short timeout (~5 s, no retries). Three outcomes:
   *match* → recorded as corroboration; *unreachable or absent* → recorded as
   `unavailable` with the reason, no warning, no delay — an operator on the
   ModelScope path generally cannot reach HF, and that is the expected case, not a
   problem; *mismatch* → loud, prominent warning, because two hosts disagreeing on
   the same artifact is a serious signal and must not scroll past in a progress bar.
   Corroboration never gates the fetch and never extends it by more than the timeout.
6. Preflight the destination: filesystem type (§7), free space against summed size.
7. Download to `<bundle>/.partial/`, hashing the stream as it lands. Abort the moment
   the running hash cannot match. Resume via HTTP Range against the partial file,
   re-hashing the existing prefix on resume so a resumed download is verified exactly
   as strictly as a fresh one.
8. On success, atomically rename `.partial/` into place.
9. Write `manifest.json`, sign it, write `manifest.json.minisig`.
10. `fsync` files and directory, then report the bundle path and digest.

Interrupted runs leave `.partial/` and are resumable; the bundle directory only ever
appears complete. Multiple models per run: repo specs are variadic
(`amf fetch A B C --usb /mnt/usb`), sharing one destination preflight, processed
sequentially with a per-model summary and a non-zero exit if any failed.

---

## 7. USB filesystem check

GGUF files routinely exceed FAT32's 4 GiB single-file ceiling, and the failure mode
is a truncated write partway through a 40 GB download.

- **Linux**: `statfs` `f_type` magic (`0x5346544e` NTFS, exFAT, `0x4d44` MSDOS/FAT).
- **macOS**: `statfs` `f_fstypename` string (`"exfat"`, `"msdos"`).
- **Windows**: `GetVolumeInformationW` filesystem name buffer.

**FAT32 is refused outright** — regardless of whether the current selection happens
to fit under 4 GiB, and `--force` does not override it. The error names the exact
reformat command for the platform (`mkfs.exfat` / `diskutil eraseVolume ExFAT` /
`format /FS:exFAT`).

Refusing even the fits-today case is deliberate. A drive is a long-lived object: it
accumulates bundles across many runs, and the tool explicitly supports multiple
models per invocation. A FAT32 drive that accepts a 2 GB Q2_K today is a drive
someone writes a 40 GB Q8_0 to next month, and the failure then is a truncated model
partway through a long download. Refusing at the filesystem level makes the property
hold for the life of the drive rather than for one lucky invocation. `--force`
deliberately has no effect here: the flag exists for warnings the operator can
reason about, not for a limit the filesystem will enforce regardless of consent.

Unrecognised filesystem → warn and proceed (`--force` not required); we cannot prove
it is unsuitable, so refusing would block legitimate exotic setups.

The check runs at **preflight**, before any bytes are downloaded — discovering this
after a 40 GB transfer is the outcome the check exists to prevent.

---

## 8. CLI surface

```
amf fetch <repo-spec>... --usb <path> [--variant Q4_K_M]
                                     [--source hf|modelscope]   # default: hf
                                     [--revision <sha>] [--yes] [--force]
                                     [--require-signature] [--no-corroborate]
amf verify <bundle-path>            re-verify a bundle in place (works airgapped)
amf list <usb-path>                 inventory bundles on a drive
amf keygen                          generate the fetcher's ed25519 signing key
amf trust list|add|remove           manage the TOFU key store
```

`amf verify` deliberately requires no network and no HF key: it re-derives the
Tier-1 chain and checks the Tier-3 signature. It is the command the airgapped
operator runs, shipped in the same binary so the drive can carry its own verifier.

---

## 9. Cross-compilation

`cargo-zigbuild` in Docker (already available on this machine) for
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-gnu`.
musl for genuinely static Linux binaries; `rustls` throughout so there is no OpenSSL
to link. `cargo xtask dist` builds all targets and emits a `SHA256SUMS` — signed with
the same minisign key, so the tool's own distribution follows the trust model it
implements.

---

## 10. Build order

1. Workspace skeleton, error types, `amf-fs` filesystem detection (self-contained,
   testable immediately).
2. `amf-source`: HF backend — resolve, tree listing, variant grouping incl. shards.
3. `amf-verify`: streaming SHA256, LFS pointer parsing, git object parsing.
4. `amf-bundle`: manifest schema, content-addressed naming, atomic write, dedup.
5. Download pipeline: streaming verify, resume, progress.
6. Tier 2: OpenPGP signature capture, TOFU trust store.
7. Tier 3: minisign keygen, sign, verify; `amf verify` subcommand.
8. ModelScope backend against the same trait; corroboration.
9. C2PA detection (sidecar / GGUF KV / JUMBF box) with honest absence recording.
10. Cross-compilation via xtask; `SHA256SUMS`.

Testing: unit tests on hash/pointer/manifest logic; a `wiremock` HTTP fixture for
source backends including truncation, hash-mismatch, and mid-stream disconnect;
end-to-end against a real small model (`unsloth/Llama-3.2-1B-Instruct-GGUF:Q2_K`,
554 MB) writing to a loopback exFAT image, plus a FAT32 loopback to exercise the
refusal path.

---

## 11. Open risks

- **HF's signing key is unpublished.** Tier 2 is TOFU on first contact. Getting the
  fingerprint confirmed by HF out of band would upgrade this materially, and is worth
  an email to them.
- **HF may rotate the system key.** Rotation is indistinguishable from an attack
  under TOFU; the tool will refuse and require explicit operator re-pinning. Correct,
  but it will one day interrupt someone at an inconvenient moment.
- **ModelScope commits are unsigned**, so a ModelScope-only fetch rests on TLS plus
  the Tier-3 fetcher signature. This is the weakest configuration the tool supports,
  and it is also the one an operator behind the Great Firewall is forced into — the
  mitigation (corroborate against HF) is usually unavailable to exactly the people
  who need it most. The honest answer is that `--source modelscope` trades away
  Tier 2, the manifest says so plainly, and the docs must not pretend otherwise.
  `--require-signature` will refuse ModelScope fetches by design.
- **C2PA may land later** in a form not yet specified. The detection layer is written
  to be extended, and absence is recorded structurally rather than as a bare null.
- **Sequoia's build** pulls a nontrivial dependency tree; if it fights the musl or
  Windows targets, the fallback is `pgp` (rpgp), which is lighter but less complete.
