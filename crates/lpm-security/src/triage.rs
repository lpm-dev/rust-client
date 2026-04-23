//! Phase 46 triage types — static-tier classification.
//!
//! These types live here so `lpm-cli`'s `build_state.rs` can persist
//! them on `BlockedPackage`. All persisted occurrences are
//! `Option<T>` so Phase 46 additions are mutually compatible with
//! pre-46 on-disk state (see the schema comment in `build_state.rs`
//! and Phase 46 plan §6 for the no-version-bump rationale).
//!
//! **P4 relocation (2026-04-21):** `ProvenanceSnapshot` moved to
//! `lpm-workspace` so that `TrustedDependencyBinding.provenance_at_approval`
//! can reference it without inducing a
//! `lpm-workspace → lpm-security` dependency cycle. See the struct's
//! doc comment in `lpm-workspace/src/lib.rs` for the full rationale.
//!
//! Ownership of populating these fields is split across phases — see
//! the plan's §11 field-ownership table. P1 defines the types and
//! wires them into the persisted structs; later phases populate them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Classification produced by the Phase 46 static-gate matcher (Layer 1
/// of the four-layer tiered gate).
///
/// Four tiers, ordered by decreasing trust:
///
/// - [`StaticTier::Green`] — script exactly matches a hand-curated
///   allowlist of pure local build steps (`node-gyp rebuild`, `tsc`,
///   `prisma generate`, `husky install`, etc.). Under
///   `script-policy = "triage"`, greens are eligible for auto-execution
///   in the sandbox. Classification is populated in P2; auto-execution
///   lands in P6 (hard-gated on the sandbox in P5).
/// - [`StaticTier::Amber`] — script did not fit a green pattern and
///   did not match a red pattern. Deferred to layers 2/3/4 (trust
///   manifest, provenance + cooldown, LLM triage). Network binary
///   downloaders (`puppeteer`, `playwright install`, `cypress install`,
///   `electron-builder install-app-deps`) land here by design (D18).
/// - [`StaticTier::AmberLlm`] — an amber that was approved by an LLM
///   advisor (P8). Persisted with the approver identity so teammates
///   on a different model family re-review (D17).
/// - [`StaticTier::Red`] — script matches the hand-curated blocklist
///   (pipe-to-shell, base64 decode to execution, nested
///   package-manager installs, etc.). Blocks unconditionally; never
///   reaches the LLM.
///
/// Wire format is kebab-case: `"green"`, `"amber"`, `"amber-llm"`,
/// `"red"`. The kebab form keeps JSON payloads human-readable in
/// `build-state.json` and stable across platforms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum StaticTier {
    Green,
    Amber,
    AmberLlm,
    Red,
}

impl StaticTier {
    /// Worst-wins reducer over two tiers: `Red > AmberLlm > Amber > Green`.
    ///
    /// Used by [`crate::static_gate`] callers that classify multiple
    /// lifecycle phases of the same package (e.g. `preinstall` +
    /// `postinstall`) and need one tier to annotate the whole
    /// package. Aggregating "worst-wins" means a single red phase
    /// pulls the whole package into [`StaticTier::Red`], regardless
    /// of whether the other phases look benign — the user still has
    /// to review the red phase, so the package-level annotation
    /// should reflect that.
    ///
    /// The precedence is deliberately defined here (not at the
    /// classifier call site) so the same rule applies to every
    /// downstream aggregation, including future places that compose
    /// a static-gate result with an `AmberLlm` verdict from P8.
    pub fn worse_of(self, other: Self) -> Self {
        use StaticTier::{Amber, AmberLlm, Green, Red};
        match (self, other) {
            (Red, _) | (_, Red) => Red,
            (AmberLlm, _) | (_, AmberLlm) => AmberLlm,
            (Amber, _) | (_, Amber) => Amber,
            (Green, Green) => Green,
        }
    }
}

/// Deterministic hash of the sorted set of `true` behavioral-analysis
/// tag names for a package version.
///
/// Phase 46 P1 populates this on `BlockedPackage` so the version-diff
/// UI (P7) can detect "behavioral tags gained `network` / `eval`
/// since last approval" without re-fetching metadata. The input is
/// expected to be sorted lexicographically — the caller (the
/// `BehavioralTags::active_tag_names` extraction in `lpm-registry`)
/// guarantees that invariant, so we do not re-sort here.
///
/// Format: `sha256-<hex>`, matching the convention used by
/// [`crate::script_hash::compute_script_hash`] and the SRI-style
/// prefix pattern throughout LPM. A NUL (`\0`) separator between tag
/// names ensures `["net", "work"]` and `["netw", "ork"]` hash
/// differently (adjacency-collision defense).
///
/// Empty input (no `true` tags) produces a stable, non-empty hash
/// distinct from "no metadata" — callers should pass `None` for the
/// whole field when the server did not analyze the package, rather
/// than calling this with an empty slice.
pub fn hash_behavioral_tag_set(sorted_active_tags: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for (i, tag) in sorted_active_tags.iter().enumerate() {
        if i > 0 {
            hasher.update([0u8]);
        }
        hasher.update(tag.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(7 + 64);
    hex.push_str("sha256-");
    const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";
    for &b in &digest[..] {
        hex.push(HEX_TABLE[(b >> 4) as usize] as char);
        hex.push(HEX_TABLE[(b & 0x0f) as usize] as char);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── StaticTier ────────────────────────────────────────────────

    #[test]
    fn static_tier_serializes_as_kebab_case() {
        assert_eq!(
            serde_json::to_string(&StaticTier::Green).unwrap(),
            "\"green\""
        );
        assert_eq!(
            serde_json::to_string(&StaticTier::Amber).unwrap(),
            "\"amber\""
        );
        assert_eq!(
            serde_json::to_string(&StaticTier::AmberLlm).unwrap(),
            "\"amber-llm\"",
            "AmberLlm MUST serialize as kebab-case 'amber-llm' — this \
             is the wire contract consumed by `approve-scripts --json` \
             and by teammate readers; breaking it silently breaks \
             downstream agents"
        );
        assert_eq!(serde_json::to_string(&StaticTier::Red).unwrap(), "\"red\"");
    }

    #[test]
    fn static_tier_deserializes_from_kebab_case() {
        assert_eq!(
            serde_json::from_str::<StaticTier>("\"green\"").unwrap(),
            StaticTier::Green,
        );
        assert_eq!(
            serde_json::from_str::<StaticTier>("\"amber-llm\"").unwrap(),
            StaticTier::AmberLlm,
        );
    }

    #[test]
    fn static_tier_roundtrips() {
        for tier in [
            StaticTier::Green,
            StaticTier::Amber,
            StaticTier::AmberLlm,
            StaticTier::Red,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: StaticTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn static_tier_rejects_camel_case() {
        // Wire contract is kebab-case only. If someone hand-writes
        // `"amberLlm"` or `"AmberLlm"` into a file, we refuse to parse
        // it rather than silently misinterpret.
        assert!(serde_json::from_str::<StaticTier>("\"amberLlm\"").is_err());
        assert!(serde_json::from_str::<StaticTier>("\"AmberLlm\"").is_err());
    }

    #[test]
    fn static_tier_rejects_unknown_variant() {
        assert!(serde_json::from_str::<StaticTier>("\"purple\"").is_err());
    }

    // ── worse_of (worst-wins precedence) ──────────────────────────

    #[test]
    fn worse_of_is_symmetric() {
        // Precedence: Red > AmberLlm > Amber > Green — and order of
        // arguments must not matter.
        let all = [
            StaticTier::Green,
            StaticTier::Amber,
            StaticTier::AmberLlm,
            StaticTier::Red,
        ];
        for a in all {
            for b in all {
                assert_eq!(
                    a.worse_of(b),
                    b.worse_of(a),
                    "worse_of must be commutative; failed for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn worse_of_is_idempotent() {
        for t in [
            StaticTier::Green,
            StaticTier::Amber,
            StaticTier::AmberLlm,
            StaticTier::Red,
        ] {
            assert_eq!(t.worse_of(t), t);
        }
    }

    #[test]
    fn worse_of_precedence_red_wins_everything() {
        assert_eq!(StaticTier::Red.worse_of(StaticTier::Green), StaticTier::Red);
        assert_eq!(StaticTier::Red.worse_of(StaticTier::Amber), StaticTier::Red);
        assert_eq!(
            StaticTier::Red.worse_of(StaticTier::AmberLlm),
            StaticTier::Red
        );
    }

    #[test]
    fn worse_of_precedence_amber_llm_over_amber_and_green() {
        assert_eq!(
            StaticTier::AmberLlm.worse_of(StaticTier::Amber),
            StaticTier::AmberLlm
        );
        assert_eq!(
            StaticTier::AmberLlm.worse_of(StaticTier::Green),
            StaticTier::AmberLlm
        );
    }

    #[test]
    fn worse_of_precedence_amber_over_green() {
        assert_eq!(
            StaticTier::Amber.worse_of(StaticTier::Green),
            StaticTier::Amber
        );
    }

    #[test]
    fn worse_of_reduces_with_iterator() {
        // Shape used by the callers (fold via `Iterator::reduce`).
        let tiers = [StaticTier::Green, StaticTier::Amber, StaticTier::Green];
        let worst = tiers.into_iter().reduce(StaticTier::worse_of);
        assert_eq!(worst, Some(StaticTier::Amber));
    }

    #[test]
    fn worse_of_empty_iterator_reduces_to_none() {
        let empty: [StaticTier; 0] = [];
        assert_eq!(empty.into_iter().reduce(StaticTier::worse_of), None);
    }

    // ── ProvenanceSnapshot moved to lpm-workspace in Phase 46 P4 ────
    //
    // The struct + its tests now live in `lpm-workspace/src/lib.rs`
    // because `TrustedDependencyBinding.provenance_at_approval` needs
    // to reference it, and `lpm-security` already depends on
    // `lpm-workspace` (reverse edge would cycle). See the struct's
    // doc comment in lpm-workspace for the full rationale.

    // ── hash_behavioral_tag_set ───────────────────────────────────

    #[test]
    fn behavioral_hash_has_sha256_prefix_and_fixed_length() {
        let h = hash_behavioral_tag_set(&[]);
        assert!(h.starts_with("sha256-"));
        // "sha256-" (7) + 64 hex chars = 71
        assert_eq!(h.len(), 71);
    }

    #[test]
    fn behavioral_hash_empty_is_stable() {
        // Pinned: the hash of empty input is the SHA-256 of the empty
        // string. Callers distinguish "no active tags" (this hash)
        // from "no metadata" (Option::None for the whole field) at
        // the call site; both are legitimate states.
        let h = hash_behavioral_tag_set(&[]);
        assert_eq!(
            h, "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty active-tag set must hash deterministically to \
             SHA-256 of the empty string — downstream storage relies \
             on this invariant across runs"
        );
    }

    #[test]
    fn behavioral_hash_order_sensitive() {
        // Caller promises sorted input; we don't re-sort. Swapping the
        // order SHOULD produce a different hash so a misuse by the
        // caller is detectable in tests (rather than silently hashing
        // the same value).
        let h_sorted = hash_behavioral_tag_set(&["eval", "network"]);
        let h_rev = hash_behavioral_tag_set(&["network", "eval"]);
        assert_ne!(
            h_sorted, h_rev,
            "hash must be input-order-sensitive so misuse is \
             detectable — callers are contracted to sort",
        );
    }

    #[test]
    fn behavioral_hash_separator_prevents_adjacency_collision() {
        // Without the NUL separator, ["net", "work"] and ["netw", "ork"]
        // would concatenate to the same byte string. The separator
        // forecloses that adjacency-collision class.
        let h_split_1 = hash_behavioral_tag_set(&["net", "work"]);
        let h_split_2 = hash_behavioral_tag_set(&["netw", "ork"]);
        assert_ne!(h_split_1, h_split_2);
    }

    #[test]
    fn behavioral_hash_deterministic_across_calls() {
        let a = hash_behavioral_tag_set(&["childProcess", "eval", "network"]);
        let b = hash_behavioral_tag_set(&["childProcess", "eval", "network"]);
        assert_eq!(a, b);
    }

    #[test]
    fn behavioral_hash_distinct_from_subset() {
        let all = hash_behavioral_tag_set(&["childProcess", "eval", "network"]);
        let subset = hash_behavioral_tag_set(&["eval", "network"]);
        assert_ne!(all, subset);
    }
}
