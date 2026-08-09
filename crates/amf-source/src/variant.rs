//! Grouping a flat file listing into selectable variants.
//!
//! Upstream repos present GGUF quantisations three different ways:
//!
//! - one file per quant at the repo root (`Model-Q4_K_M.gguf`);
//! - a shard set at the root (`Model-Q4_K_M-00001-of-00002.gguf`);
//! - a directory per quant, holding the shard set (`Model-UD-IQ1_S/…`).
//!
//! All three must collapse to the same thing: a labelled set of files the
//! operator can pick in one go.

use std::collections::BTreeMap;

use crate::model::{RemoteFile, Shard, Variant};

/// Split a `-00001-of-00003` suffix off a filename stem.
///
/// Returns the base stem and the shard position. The shard count is fixed at
/// five digits by llama.cpp's splitter; we accept any run of digits rather than
/// hard-coding the width, since being liberal here costs nothing and a future
/// six-digit shard set would otherwise be silently mis-grouped.
pub fn split_shard_suffix(stem: &str) -> (String, Option<Shard>) {
    // Pattern: <base>-<digits>-of-<digits>
    let Some(of_at) = stem.rfind("-of-") else {
        return (stem.to_string(), None);
    };
    let total_str = &stem[of_at + 4..];
    if total_str.is_empty() || !total_str.bytes().all(|b| b.is_ascii_digit()) {
        return (stem.to_string(), None);
    }
    let head = &stem[..of_at];
    let Some(dash_at) = head.rfind('-') else {
        return (stem.to_string(), None);
    };
    let index_str = &head[dash_at + 1..];
    if index_str.is_empty() || !index_str.bytes().all(|b| b.is_ascii_digit()) {
        return (stem.to_string(), None);
    }
    let (Ok(index), Ok(total)) = (index_str.parse::<u32>(), total_str.parse::<u32>()) else {
        return (stem.to_string(), None);
    };
    (head[..dash_at].to_string(), Some(Shard { index, total }))
}

/// Group GGUF files into variants and derive a short label for each.
pub fn group(files: &[RemoteFile]) -> Vec<Variant> {
    let mut groups: BTreeMap<String, Vec<RemoteFile>> = BTreeMap::new();

    for file in files.iter().filter(|f| f.is_gguf()) {
        let name = file.file_name();
        let stem = name.strip_suffix(".gguf").unwrap_or(name);
        let stem = stem.strip_suffix(".GGUF").unwrap_or(stem);
        let (base, shard) = split_shard_suffix(stem);

        let mut entry = file.clone();
        entry.shard = shard;
        groups.entry(base).or_default().push(entry);
    }

    let keys: Vec<String> = groups.keys().cloned().collect();
    let prefix_len = common_token_prefix_len(&keys);

    let mut variants: Vec<Variant> = groups
        .into_iter()
        .map(|(key, mut files)| {
            // Shard order is what the model loader needs; sort by index where we
            // have one and fall back to path order otherwise.
            files.sort_by(|a, b| match (a.shard, b.shard) {
                (Some(x), Some(y)) => x.index.cmp(&y.index),
                _ => a.path.cmp(&b.path),
            });
            Variant {
                label: label_for(&key, prefix_len),
                files,
            }
        })
        .collect();

    variants.sort_by(|a, b| a.label.cmp(&b.label));
    variants
}

/// Number of leading `-`-separated tokens shared by every key.
///
/// Token-level rather than character-level, because a character-level common
/// prefix of `…-Q4_K_M` and `…-Q4_K_S` ends mid-token and would label the
/// variants `M` and `S`.
fn common_token_prefix_len(keys: &[String]) -> usize {
    if keys.len() < 2 {
        return 0;
    }
    let tokenised: Vec<Vec<&str>> = keys.iter().map(|k| k.split('-').collect()).collect();
    let shortest = tokenised.iter().map(|t| t.len()).min().unwrap_or(0);
    let mut common = 0;
    'outer: for i in 0..shortest {
        let candidate = tokenised[0][i];
        for t in &tokenised[1..] {
            if t[i] != candidate {
                break 'outer;
            }
        }
        common = i + 1;
    }
    // Never consume every token: that would leave an empty label.
    common.min(shortest.saturating_sub(1))
}

fn label_for(key: &str, prefix_len: usize) -> String {
    let tokens: Vec<&str> = key.split('-').collect();
    if prefix_len == 0 || prefix_len >= tokens.len() {
        // Single-variant repo, or the prefix would eat the whole name: fall back
        // to the last token, which is the quant label in every naming scheme
        // seen in the wild.
        return tokens
            .last()
            .map(|s| s.to_string())
            .unwrap_or_else(|| key.to_string());
    }
    tokens[prefix_len..].join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, size: u64) -> RemoteFile {
        RemoteFile {
            path: path.to_string(),
            size,
            sha256: Some("deadbeef".into()),
            shard: None,
        }
    }

    #[test]
    fn splits_a_shard_suffix() {
        let (base, shard) = split_shard_suffix("DeepSeek-R1-UD-IQ1_S-00002-of-00003");
        assert_eq!(base, "DeepSeek-R1-UD-IQ1_S");
        assert_eq!(shard, Some(Shard { index: 2, total: 3 }));
    }

    #[test]
    fn leaves_unsharded_names_alone() {
        let (base, shard) = split_shard_suffix("Llama-3.2-1B-Instruct-Q4_K_M");
        assert_eq!(base, "Llama-3.2-1B-Instruct-Q4_K_M");
        assert_eq!(shard, None);
    }

    #[test]
    fn does_not_mistake_similar_names_for_shards() {
        // "-of-" appearing in a model name must not trigger shard splitting.
        for stem in [
            "Model-out-of-the-box",
            "Model-1-of-",
            "Model--of-2",
            "Model-x-of-y",
        ] {
            let (base, shard) = split_shard_suffix(stem);
            assert_eq!(base, stem, "{stem} should not be treated as sharded");
            assert_eq!(shard, None);
        }
    }

    #[test]
    fn groups_flat_quants_and_strips_the_common_prefix() {
        let files = vec![
            f("Llama-3.2-1B-Instruct-Q4_K_M.gguf", 807_694_368),
            f("Llama-3.2-1B-Instruct-Q4_K_S.gguf", 775_647_264),
            f("Llama-3.2-1B-Instruct-Q8_0.gguf", 1_321_082_528),
        ];
        let variants = group(&files);
        let labels: Vec<&str> = variants.iter().map(|v| v.label.as_str()).collect();
        assert_eq!(labels, vec!["Q4_K_M", "Q4_K_S", "Q8_0"]);
        assert!(variants.iter().all(|v| !v.is_sharded()));
    }

    #[test]
    fn groups_a_directory_of_shards_into_one_variant() {
        let files = vec![
            f(
                "DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-UD-IQ1_S-00001-of-00003.gguf",
                10,
            ),
            f(
                "DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-UD-IQ1_S-00003-of-00003.gguf",
                30,
            ),
            f(
                "DeepSeek-R1-UD-IQ1_S/DeepSeek-R1-UD-IQ1_S-00002-of-00003.gguf",
                20,
            ),
            f("DeepSeek-R1-BF16/DeepSeek-R1-BF16-00001-of-00001.gguf", 5),
        ];
        let variants = group(&files);
        assert_eq!(variants.len(), 2);

        let iq1 = variants.iter().find(|v| v.label == "UD-IQ1_S").unwrap();
        assert_eq!(iq1.files.len(), 3);
        assert_eq!(iq1.total_size(), 60);
        assert_eq!(iq1.largest_file(), 30);
        assert!(iq1.is_sharded());

        // Shards must come back in load order, not listing order.
        let indices: Vec<u32> = iq1.files.iter().map(|f| f.shard.unwrap().index).collect();
        assert_eq!(indices, vec![1, 2, 3]);
    }

    #[test]
    fn ignores_non_gguf_files() {
        let files = vec![
            f("README.md", 100),
            f("config.json", 50),
            f("imatrix_unsloth.dat", 1000),
            f("Model-Q4_K_M.gguf", 10),
        ];
        let variants = group(&files);
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].files.len(), 1);
    }

    #[test]
    fn a_single_variant_repo_still_gets_a_label() {
        let files = vec![f("Llama-3.2-1B-Instruct-Q4_K_M.gguf", 10)];
        let variants = group(&files);
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].label, "Q4_K_M");
    }

    #[test]
    fn detects_missing_shards() {
        let files = vec![
            f("M-Q4/M-Q4-00001-of-00003.gguf", 10),
            f("M-Q4/M-Q4-00003-of-00003.gguf", 30),
        ];
        let variants = group(&files);
        assert_eq!(variants[0].missing_shards(), vec![2]);
    }

    #[test]
    fn complete_shard_sets_report_nothing_missing() {
        let files = vec![
            f("M-Q4/M-Q4-00001-of-00002.gguf", 10),
            f("M-Q4/M-Q4-00002-of-00002.gguf", 20),
        ];
        assert!(group(&files)[0].missing_shards().is_empty());
    }

    #[test]
    fn a_file_without_a_hash_makes_the_variant_unverifiable() {
        let mut files = vec![f("M-Q4_K_M.gguf", 10)];
        files[0].sha256 = None;
        assert!(!group(&files)[0].fully_verifiable());
    }

    #[test]
    fn empty_listing_yields_no_variants() {
        assert!(group(&[]).is_empty());
    }

    #[test]
    fn token_prefix_never_consumes_the_whole_label() {
        // Keys that are identical up to the last token must still be labelled.
        let keys = vec!["A-B-Q4".to_string(), "A-B-Q5".to_string()];
        let n = common_token_prefix_len(&keys);
        assert_eq!(n, 2);
        assert_eq!(label_for("A-B-Q4", n), "Q4");
    }
}
