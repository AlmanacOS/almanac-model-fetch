//! Tier 2 — OpenPGP handling for upstream commit signatures.
//!
//! Two operations, kept deliberately distinct because they carry very
//! different weight (see PLAN.md §2):
//!
//! - [`issuer_fingerprint`] reads which key a signature *claims* to come from.
//!   That claim lives inside attacker-suppliable bytes; comparing it to a
//!   stored value is continuity observation, not cryptography. It can detect a
//!   change of claimed signer across fetches — nothing more.
//! - [`verify_commit_signature`] does the real check: the signature verifies
//!   mathematically against a supplied public key, over the exact payload git
//!   signed. Only this path may ever produce a `verified` status, and it is
//!   only possible once the operator has obtained the signer's public key out
//!   of band (HuggingFace does not publish theirs).

use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};
use pgp::types::PublicKeyTrait as _;

use crate::git::Commit;
use crate::VerifyError;

/// The key a signature claims as its issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerInfo {
    /// Full 20-byte fingerprint, uppercase hex, when the signature carries the
    /// issuer-fingerprint subpacket (anything signed by modern git does).
    pub fingerprint: Option<String>,
    /// 8-byte key id, uppercase hex — older signatures may carry only this.
    pub key_id: Option<String>,
}

impl IssuerInfo {
    /// The best available identifier for display and continuity records.
    pub fn best(&self) -> Option<&str> {
        self.fingerprint.as_deref().or(self.key_id.as_deref())
    }
}

/// Extract the claimed issuer from an armored signature.
pub fn issuer_fingerprint(armored_sig: &str) -> Result<IssuerInfo, VerifyError> {
    let (sig, _) = StandaloneSignature::from_string(armored_sig)
        .map_err(|e| VerifyError::Signing(format!("could not parse the PGP signature: {e}")))?;

    let fingerprint = sig
        .signature
        .issuer_fingerprint()
        .first()
        .map(|fp| hex::encode_upper(fp.as_bytes()));
    let key_id = sig
        .signature
        .issuer()
        .first()
        .map(|id| hex::encode_upper(id.as_ref()));

    Ok(IssuerInfo {
        fingerprint,
        key_id,
    })
}

/// Outcome of a real verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpVerified {
    /// Fingerprint of the primary key that verified the signature.
    pub fingerprint: String,
}

/// Verify a commit's signature against a trusted public key.
///
/// `raw_commit` is the full commit object; the signed payload (the commit with
/// its `gpgsig` header removed) is reconstructed here, so callers hand over
/// exactly what they captured and nothing pre-chewed.
pub fn verify_commit_signature(
    raw_commit: &[u8],
    armored_pubkey: &str,
) -> Result<PgpVerified, VerifyError> {
    let commit = crate::git::parse_commit(raw_commit)?;
    let armored_sig = commit.gpgsig.as_deref().ok_or_else(|| {
        VerifyError::Signing("commit carries no gpgsig to verify".into())
    })?;

    let (sig, _) = StandaloneSignature::from_string(armored_sig)
        .map_err(|e| VerifyError::Signing(format!("could not parse the PGP signature: {e}")))?;
    let (key, _) = SignedPublicKey::from_string(armored_pubkey)
        .map_err(|e| VerifyError::Signing(format!("could not parse the public key: {e}")))?;

    let payload = Commit::signed_payload(raw_commit);

    // Try the primary key first, then signing-capable subkeys — git signatures
    // in the wild come from both.
    let mut verified = sig.verify(&key, &payload).is_ok();
    if !verified {
        for sub in &key.public_subkeys {
            if sig.verify(sub, &payload).is_ok() {
                verified = true;
                break;
            }
        }
    }
    if !verified {
        return Err(VerifyError::BadSignature);
    }

    Ok(PgpVerified {
        fingerprint: hex::encode_upper(key.fingerprint().as_bytes()),
    })
}

/// The fingerprint of an armored public key, for pin displays.
pub fn pubkey_fingerprint(armored_pubkey: &str) -> Result<String, VerifyError> {
    let (key, _) = SignedPublicKey::from_string(armored_pubkey)
        .map_err(|e| VerifyError::Signing(format!("could not parse the public key: {e}")))?;
    Ok(hex::encode_upper(key.fingerprint().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::{PublicKeyTrait, SecretKeyTrait};
    #[allow(unused_imports)]
    use pgp::types::KeyId;

    /// The real signed commit captured from unsloth/Qwen3-8B-GGUF.
    const REAL_COMMIT: &[u8] = include_bytes!("../tests/fixtures/commit_signed.raw");

    /// HF's system key fingerprint as observed in that commit's signature.
    const HF_FINGERPRINT: &str = "C8A817860F8BA646BF0612916A528E38E0733467";

    #[test]
    fn extracts_the_issuer_from_the_real_hf_signature() {
        let commit = crate::git::parse_commit(REAL_COMMIT).unwrap();
        let info = issuer_fingerprint(commit.gpgsig.as_deref().unwrap()).unwrap();

        assert_eq!(info.fingerprint.as_deref(), Some(HF_FINGERPRINT));
        assert_eq!(
            info.key_id.as_deref(),
            Some("6A528E38E0733467"),
            "the key id is the fingerprint's low 8 bytes"
        );
        assert_eq!(info.best(), Some(HF_FINGERPRINT));
    }

    #[test]
    fn garbage_is_not_a_signature() {
        assert!(issuer_fingerprint("not armor at all").is_err());
    }

    fn test_key() -> pgp::composed::SignedSecretKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSALegacy)
            .can_sign(true)
            .primary_user_id("amf test <test@example.invalid>".into())
            .build()
            .unwrap();
        let secret = params.generate(rand::thread_rng()).unwrap();
        secret.sign(rand::thread_rng(), String::new).unwrap()
    }

    fn sign_commit_payload(
        key: &pgp::composed::SignedSecretKey,
        payload: &[u8],
    ) -> String {
        let mut config = SignatureConfig::v4(
            SignatureType::Binary,
            key.algorithm(),
            HashAlgorithm::SHA2_256,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())),
            Subpacket::regular(SubpacketData::Issuer(key.key_id())),
        ];
        let sig = config
            .sign(key, String::new, payload)
            .unwrap();
        StandaloneSignature::new(sig)
            .to_armored_string(Default::default())
            .unwrap()
    }

    /// Build a commit signed by our own key, gpgsig folded git-style.
    fn signed_commit(key: &pgp::composed::SignedSecretKey, message: &str) -> Vec<u8> {
        let payload = format!(
            "tree 116f6efcc6377fce0d8d0917bc15c3126dcec5b9\n\
             author T <t@x> 1 +0000\n\
             committer T <t@x> 1 +0000\n\
             \n{message}\n"
        );
        let armor = sign_commit_payload(key, payload.as_bytes());

        let mut folded = String::from("gpgsig ");
        for (i, line) in armor.lines().enumerate() {
            if i > 0 {
                folded.push(' ');
            }
            folded.push_str(line);
            folded.push('\n');
        }

        let (headers, body) = payload.split_once("\n\n").unwrap();
        format!("{headers}\n{folded}\n{body}").into_bytes()
    }

    #[test]
    fn verifies_a_commit_signed_by_a_known_key() {
        let key = test_key();
        let pubkey = key
            .public_key()
            .sign(rand::thread_rng(), &key, String::new)
            .unwrap()
            .to_armored_string(Default::default())
            .unwrap();

        let commit = signed_commit(&key, "verified message");
        let result = verify_commit_signature(&commit, &pubkey).unwrap();
        assert_eq!(result.fingerprint, pubkey_fingerprint(&pubkey).unwrap());
    }

    #[test]
    fn a_tampered_commit_fails_verification() {
        // The exact attack Tier 2 exists to catch: the signature is genuine but
        // the commit content changed after signing.
        let key = test_key();
        let pubkey = key
            .public_key()
            .sign(rand::thread_rng(), &key, String::new)
            .unwrap()
            .to_armored_string(Default::default())
            .unwrap();

        let commit = signed_commit(&key, "original");
        let tampered = String::from_utf8(commit).unwrap().replace("original", "evilware");
        let err = verify_commit_signature(tampered.as_bytes(), &pubkey).unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature));
    }

    #[test]
    fn the_wrong_key_fails_verification() {
        let signer = test_key();
        let other = test_key();
        let wrong_pub = other
            .public_key()
            .sign(rand::thread_rng(), &other, String::new)
            .unwrap()
            .to_armored_string(Default::default())
            .unwrap();

        let commit = signed_commit(&signer, "msg");
        assert!(matches!(
            verify_commit_signature(&commit, &wrong_pub),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn an_unsigned_commit_cannot_be_verified() {
        let raw = b"tree abc\ncommitter A <a@x> 1 +0000\n\nmsg\n";
        let err = verify_commit_signature(raw, "whatever").unwrap_err().to_string();
        assert!(err.contains("no gpgsig"), "{err}");
    }

    #[test]
    fn the_real_hf_commit_fails_against_the_wrong_key() {
        // We do not hold HF's public key, so the real commit must fail against
        // any key we can produce — and it must fail *cryptographically*, not by
        // parse error.
        let other = test_key();
        let wrong_pub = other
            .public_key()
            .sign(rand::thread_rng(), &other, String::new)
            .unwrap()
            .to_armored_string(Default::default())
            .unwrap();

        assert!(matches!(
            verify_commit_signature(REAL_COMMIT, &wrong_pub),
            Err(VerifyError::BadSignature)
        ));
    }
}
