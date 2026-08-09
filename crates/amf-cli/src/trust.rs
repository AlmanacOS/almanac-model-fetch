//! The trust store: pinned upstream signing keys, and — separately — the
//! history of issuer fingerprints we have merely *observed*.
//!
//! The separation is the point (PLAN.md §2). A pinned key enables real
//! cryptographic verification and is added only by explicit operator action
//! (`amf trust add`). Observed fingerprints accumulate automatically and prove
//! nothing; they exist so that a *change* in the claimed signer — which is
//! either a key rotation or an attack — never passes silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::ui;
use crate::TrustArgs;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    /// Host → operator-pinned armored public key. Presence enables Tier-2
    /// verification for that host.
    #[serde(default)]
    pub pinned: BTreeMap<String, PinnedKey>,
    /// Host → fingerprints seen in signatures, in order of first appearance.
    /// Observation only; never a basis for a `verified` claim.
    #[serde(default)]
    pub observed: BTreeMap<String, Vec<ObservedFingerprint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedKey {
    pub armored: String,
    pub fingerprint: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedFingerprint {
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    pub times_seen: u64,
}

/// What recording an observation revealed.
#[derive(Debug, PartialEq, Eq)]
pub enum Observation {
    /// First signature ever seen from this host.
    First,
    /// Same fingerprint as before.
    Consistent,
    /// The claimed signer changed. Rotation or attack — indistinguishable
    /// here, and always worth an alarm.
    Changed { previous: String },
}

impl TrustStore {
    /// Default on-disk location, overridable with `AMF_TRUST_STORE`.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("AMF_TRUST_STORE") {
            return PathBuf::from(p);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("almanac-model-fetch")
            .join("trust.json")
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing trust store {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow!("reading trust store {}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
    }

    pub fn pinned_key(&self, host: &str) -> Option<&PinnedKey> {
        self.pinned.get(host)
    }

    /// Record a fingerprint sighting and report what it means.
    ///
    /// The comparison is against the *most recently seen* fingerprint, and a
    /// re-sighting updates its existing entry rather than appending a new one:
    /// a host that alternates between two known keys still flags every switch,
    /// but must not grow the history without bound.
    pub fn record_observation(&mut self, host: &str, fingerprint: &str) -> Observation {
        let now = amf_bundle::now_rfc3339();
        let entries = self.observed.entry(host.to_string()).or_default();

        let current = entries
            .iter()
            .max_by(|a, b| a.last_seen.cmp(&b.last_seen))
            .map(|e| e.fingerprint.clone());
        let outcome = match &current {
            None => Observation::First,
            Some(fp) if fp == fingerprint => Observation::Consistent,
            Some(fp) => Observation::Changed {
                previous: fp.clone(),
            },
        };

        if let Some(existing) = entries.iter_mut().find(|e| e.fingerprint == fingerprint) {
            existing.last_seen = now;
            existing.times_seen += 1;
        } else {
            entries.push(ObservedFingerprint {
                fingerprint: fingerprint.to_string(),
                first_seen: now.clone(),
                last_seen: now,
                times_seen: 1,
            });
        }
        outcome
    }
}

pub fn run(args: TrustArgs) -> Result<()> {
    let path = args
        .trust_store
        .clone()
        .unwrap_or_else(TrustStore::default_path);
    let mut store = TrustStore::load(&path)?;

    match args.command {
        crate::TrustCommand::List => {
            if store.pinned.is_empty() && store.observed.is_empty() {
                ui::info(&format!("trust store {} is empty", path.display()));
                return Ok(());
            }
            for (host, key) in &store.pinned {
                ui::info(&format!("{host}: PINNED {}", key.fingerprint));
                ui::info(&format!("    added {}", key.added_at));
            }
            for (host, seen) in &store.observed {
                for o in seen {
                    ui::info(&format!(
                        "{host}: observed {} ({}×, first {}, last {})",
                        o.fingerprint, o.times_seen, o.first_seen, o.last_seen
                    ));
                }
            }
            Ok(())
        }
        crate::TrustCommand::Add { host, key_file } => {
            let armored = std::fs::read_to_string(&key_file)
                .with_context(|| format!("reading {}", key_file.display()))?;
            let fingerprint = amf_verify::pgpsig::pubkey_fingerprint(&armored)
                .map_err(|e| anyhow!("{key_file:?} is not a usable public key: {e}"))?;

            if let Some(existing) = store.pinned.get(&host) {
                if existing.fingerprint == fingerprint {
                    ui::info(&format!("{host}: already pinned to {fingerprint}"));
                    return Ok(());
                }
                // Re-pinning to a different key orphans the judgement behind
                // every earlier verification; make the operator do it in two
                // explicit steps.
                bail!(
                    "{host} is already pinned to {}. Remove it first with \
                     `amf trust remove {host}` if you really mean to replace it.",
                    existing.fingerprint
                );
            }

            store.pinned.insert(
                host.clone(),
                PinnedKey {
                    armored,
                    fingerprint: fingerprint.clone(),
                    added_at: amf_bundle::now_rfc3339(),
                },
            );
            store.save(&path)?;
            ui::step(&format!("pinned {fingerprint} for {host}"));
            ui::info(
                "Tier-2 verification is now possible for this host. Confirm this \
                 fingerprint against a second, independent channel before relying on it.",
            );
            Ok(())
        }
        crate::TrustCommand::Remove { host } => {
            if store.pinned.remove(&host).is_none() {
                bail!("{host} has no pinned key");
            }
            store.save(&path)?;
            ui::step(&format!("removed the pinned key for {host}"));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_then_consistent() {
        let mut s = TrustStore::default();
        assert_eq!(s.record_observation("huggingface", "AAAA"), Observation::First);
        assert_eq!(
            s.record_observation("huggingface", "AAAA"),
            Observation::Consistent
        );
        let seen = &s.observed["huggingface"];
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].times_seen, 2);
    }

    #[test]
    fn a_changed_fingerprint_is_flagged_and_history_kept() {
        let mut s = TrustStore::default();
        s.record_observation("huggingface", "AAAA");
        match s.record_observation("huggingface", "BBBB") {
            Observation::Changed { previous } => assert_eq!(previous, "AAAA"),
            other => panic!("expected Changed, got {other:?}"),
        }
        // Both fingerprints stay in the record: the history is the evidence.
        assert_eq!(s.observed["huggingface"].len(), 2);
    }

    #[test]
    fn alternating_fingerprints_flag_each_switch_without_growing_the_history() {
        let mut s = TrustStore::default();
        s.record_observation("huggingface", "AAAA");
        s.record_observation("huggingface", "BBBB");
        match s.record_observation("huggingface", "AAAA") {
            Observation::Changed { previous } => assert_eq!(previous, "BBBB"),
            other => panic!("expected Changed, got {other:?}"),
        }
        // The switch alarms, but the re-sighting updates the existing entry.
        let seen = &s.observed["huggingface"];
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].times_seen, 2);
    }

    #[test]
    fn hosts_do_not_share_observations() {
        let mut s = TrustStore::default();
        s.record_observation("huggingface", "AAAA");
        assert_eq!(s.record_observation("modelscope", "AAAA"), Observation::First);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("trust.json");

        let mut s = TrustStore::default();
        s.record_observation("huggingface", "AAAA");
        s.save(&path).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        assert_eq!(loaded.observed["huggingface"][0].fingerprint, "AAAA");
    }

    #[test]
    fn a_missing_store_loads_empty() {
        let s = TrustStore::load(Path::new("/definitely/not/here.json")).unwrap();
        assert!(s.pinned.is_empty());
    }
}
