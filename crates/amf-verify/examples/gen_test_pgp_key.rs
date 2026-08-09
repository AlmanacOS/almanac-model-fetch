//! Emit a throwaway armored PGP public key on stdout (test tooling only).
use pgp::composed::{KeyType, SecretKeyParamsBuilder};
use pgp::types::SecretKeyTrait as _;

fn main() {
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::EdDSALegacy)
        .can_sign(true)
        .primary_user_id("Not HF <nothf@example.invalid>".into())
        .build()
        .unwrap();
    let secret = params.generate(rand::thread_rng()).unwrap();
    let signed = secret.sign(rand::thread_rng(), String::new).unwrap();
    let public = signed
        .public_key()
        .sign(rand::thread_rng(), &signed, String::new)
        .unwrap();
    print!("{}", public.to_armored_string(Default::default()).unwrap());
}
