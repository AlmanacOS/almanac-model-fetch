//! Tier 3 — the fetcher's own signature over a bundle manifest.
//!
//! This is the tier an airgapped importer should actually gate on. The other two
//! tiers describe what the *fetcher* was able to establish about upstream; this
//! one is a claim by a key the operator controls, checkable with nothing but a
//! public key file that was provisioned out of band.
//!
//! We sign the manifest, and the manifest commits to every file's SHA256 and to
//! all captured evidence — so one signature covers the whole bundle
//! transitively, and the importer checks one thing rather than walking a tree
//! and hoping it did not miss a file.
//!
//! Format is minisign: small, no PKI, no transparency log, no network. Sigstore
//! would be a better ecosystem fit if the verifier were online, but it is not.

use std::path::Path;

use crate::VerifyError;

/// The trusted comment embedded in a bundle signature.
///
/// minisign signs the trusted comment along with the payload, so anything here
/// is covered by the signature. Putting the bundle digest in it means a
/// signature file names the bundle it belongs to, and cannot be lifted onto a
/// different bundle without detection.
pub fn trusted_comment(repo: &str, variant: &str, bundle_digest: &str) -> String {
    format!("almanac-model-fetch bundle {repo} {variant} digest:{bundle_digest}")
}

/// Generate a new signing keypair and write it to disk.
///
/// The secret key is written with mode 0600 on Unix. It is the trust root for
/// every bundle this fetcher produces: anyone holding it can forge a bundle an
/// airgapped importer would accept.
pub fn generate_keypair(
    secret_path: &Path,
    public_path: &Path,
    password: Option<String>,
    comment: &str,
) -> Result<String, VerifyError> {
    if secret_path.exists() {
        return Err(VerifyError::KeyExists(secret_path.to_path_buf()));
    }

    let kp = match password {
        Some(p) => minisign::KeyPair::generate_encrypted_keypair(Some(p)),
        None => minisign::KeyPair::generate_unencrypted_keypair(),
    }
    .map_err(|e| VerifyError::Signing(format!("could not generate a keypair: {e}")))?;

    let sk_box = kp
        .sk
        .to_box(Some(comment))
        .map_err(|e| VerifyError::Signing(format!("could not serialise the secret key: {e}")))?;
    // minisign's `.pub` format is a comment line followed by the base64 key. We
    // build it directly rather than using `to_box()`, which would discard the
    // operator's comment — and the comment is how someone identifies which
    // fetcher a public key belongs to months later.
    let pk_file = format!("untrusted comment: {comment}\n{}\n", kp.pk.to_base64());

    write_private(secret_path, sk_box.into_string().as_bytes())?;
    std::fs::write(public_path, pk_file).map_err(|e| VerifyError::Io {
        path: public_path.to_path_buf(),
        source: e,
    })?;

    Ok(kp.pk.to_base64())
}

/// Write a file readable only by its owner.
fn write_private(path: &Path, contents: &[u8]) -> Result<(), VerifyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Create with 0600 from the outset rather than chmod-ing afterwards —
        // otherwise the key exists world-readable for a moment, and that window
        // is enough on a shared machine.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| VerifyError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        f.write_all(contents).map_err(|e| VerifyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        f.sync_all().map_err(|e| VerifyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).map_err(|e| VerifyError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

/// Sign `data` with the secret key at `secret_path`.
pub fn sign_bytes(
    secret_path: &Path,
    password: Option<String>,
    data: &[u8],
    trusted_comment: &str,
) -> Result<String, VerifyError> {
    // Load the key box ourselves rather than using `SecretKey::from_file`, which
    // prompts for a password interactively when none is supplied. This tool runs
    // unattended in scripted fetches, and a hidden stdin prompt there would hang
    // the run with no indication of why.
    let text = std::fs::read_to_string(secret_path).map_err(|e| VerifyError::Io {
        path: secret_path.to_path_buf(),
        source: e,
    })?;
    let sk_box = minisign::SecretKeyBox::from_string(&text).map_err(|e| {
        VerifyError::Signing(format!(
            "could not parse the signing key {}: {e}",
            secret_path.display()
        ))
    })?;
    let sk = match password {
        Some(p) => minisign::SecretKey::from_box(sk_box, Some(p)),
        None => minisign::SecretKey::from_unencrypted_box(sk_box),
    }
    .map_err(|e| {
        VerifyError::Signing(format!(
            "could not load the signing key {}: {e} \
             (if the key is password-protected, supply the password)",
            secret_path.display()
        ))
    })?;

    let sig = minisign::sign(
        None,
        &sk,
        std::io::Cursor::new(data),
        Some(trusted_comment),
        None,
    )
    .map_err(|e| VerifyError::Signing(format!("could not sign: {e}")))?;

    Ok(sig.into_string())
}

/// Verify a detached signature over `data` against a public key.
///
/// This is the check the airgapped importer runs. It needs no network, no
/// keyserver, and no clock.
pub fn verify_bytes(
    public_key: &str,
    signature: &str,
    data: &[u8],
) -> Result<VerifiedSignature, VerifyError> {
    let pk = parse_public_key(public_key)?;

    let sig_box = minisign::SignatureBox::from_string(signature)
        .map_err(|e| VerifyError::Signing(format!("malformed signature: {e}")))?;

    let trusted = sig_box.trusted_comment().unwrap_or_default();

    minisign::verify(
        &pk,
        &sig_box,
        std::io::Cursor::new(data),
        true,  // quiet
        false, // do not echo the data
        false, // no legacy signatures
    )
    .map_err(|_| VerifyError::BadSignature)?;

    Ok(VerifiedSignature {
        trusted_comment: trusted,
        key_id: pk.to_base64(),
    })
}

/// Accept a public key as either a bare base64 key or a full `.pub` file body.
fn parse_public_key(input: &str) -> Result<minisign::PublicKey, VerifyError> {
    let trimmed = input.trim();
    if trimmed.contains('\n') {
        if let Ok(b) = minisign::PublicKeyBox::from_string(trimmed) {
            if let Ok(pk) = b.into_public_key() {
                return Ok(pk);
            }
        }
    }
    // A key file's last non-empty line is the key itself.
    let candidate = trimmed.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(trimmed);
    minisign::PublicKey::from_base64(candidate.trim())
        .map_err(|e| VerifyError::Signing(format!("malformed public key: {e}")))
}

/// A signature that checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The signed trusted comment — carries the bundle digest.
    pub trusted_comment: String,
    pub key_id: String,
}

impl VerifiedSignature {
    /// Confirm the signature was made over the bundle we think it was.
    ///
    /// A valid signature is not enough on its own: without this check, a
    /// signature legitimately produced for one bundle could be dropped next to
    /// another bundle's manifest. In practice the manifest bytes would not match
    /// either, but binding the digest here makes the intent explicit rather than
    /// incidental.
    pub fn covers_digest(&self, bundle_digest: &str) -> bool {
        self.trusted_comment
            .contains(&format!("digest:{bundle_digest}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(dir: &Path) -> (std::path::PathBuf, String) {
        let sk = dir.join("amf.key");
        let pk_path = dir.join("amf.pub");
        generate_keypair(&sk, &pk_path, None, "test key").unwrap();
        let pk = std::fs::read_to_string(&pk_path).unwrap();
        (sk, pk)
    }

    #[test]
    fn signs_and_verifies_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = keypair(dir.path());

        let data = b"{\"schema_version\":1}";
        let comment = trusted_comment("unsloth/X-GGUF", "Q4_K_M", &"a".repeat(64));
        let sig = sign_bytes(&sk, None, data, &comment).unwrap();

        let verified = verify_bytes(&pk, &sig, data).unwrap();
        assert!(verified.covers_digest(&"a".repeat(64)));
        assert!(verified.trusted_comment.contains("unsloth/X-GGUF"));
    }

    #[test]
    fn rejects_tampered_data() {
        // The attack the whole tier exists to stop: edit the manifest after
        // signing.
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = keypair(dir.path());

        let sig = sign_bytes(&sk, None, b"original", "c").unwrap();
        assert!(matches!(
            verify_bytes(&pk, &sig, b"tampered"),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn rejects_a_signature_from_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let (sk_a, _) = keypair(dir.path());

        let other = tempfile::tempdir().unwrap();
        let (_, pk_b) = keypair(other.path());

        let sig = sign_bytes(&sk_a, None, b"data", "c").unwrap();
        assert!(verify_bytes(&pk_b, &sig, b"data").is_err());
    }

    #[test]
    fn detects_a_signature_lifted_from_another_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = keypair(dir.path());

        let comment = trusted_comment("o/r", "Q4", &"a".repeat(64));
        let sig = sign_bytes(&sk, None, b"data", &comment).unwrap();

        let verified = verify_bytes(&pk, &sig, b"data").unwrap();
        assert!(verified.covers_digest(&"a".repeat(64)));
        assert!(
            !verified.covers_digest(&"b".repeat(64)),
            "must not claim to cover a different bundle"
        );
    }

    #[test]
    fn accepts_a_bare_base64_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk_file) = keypair(dir.path());
        let bare = pk_file.lines().last().unwrap().to_string();

        let sig = sign_bytes(&sk, None, b"data", "c").unwrap();
        assert!(verify_bytes(&bare, &sig, b"data").is_ok());
    }

    #[test]
    fn refuses_to_clobber_an_existing_secret_key() {
        // Silently overwriting a signing key would orphan every bundle already
        // signed with it.
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = keypair(dir.path());
        let err = generate_keypair(&sk, &dir.path().join("other.pub"), None, "x").unwrap_err();
        assert!(matches!(err, VerifyError::KeyExists(_)));
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = keypair(dir.path());
        let mode = std::fs::metadata(&sk).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "secret key mode was {mode:o}");
    }

    #[test]
    fn an_encrypted_key_needs_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let sk = dir.path().join("enc.key");
        generate_keypair(&sk, &dir.path().join("enc.pub"), Some("hunter2".into()), "enc").unwrap();

        assert!(
            sign_bytes(&sk, None, b"data", "c").is_err(),
            "signing without the password must fail"
        );
        assert!(sign_bytes(&sk, Some("hunter2".into()), b"data", "c").is_ok());
    }

    #[test]
    fn malformed_inputs_are_rejected_cleanly() {
        assert!(verify_bytes("not a key", "not a sig", b"d").is_err());
    }
}
