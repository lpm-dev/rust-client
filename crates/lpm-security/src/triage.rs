//! Phase 46 triage types — static-tier classification + provenance
//! snapshots.
//!
//! These types live here so `lpm-cli`'s `build_state.rs` can persist
//! them on `BlockedPackage` and `lpm-workspace`'s
//! `TrustedDependencyBinding` can persist them on approval entries.
//! All persisted occurrences are `Option<T>` so Phase 46 additions are
//! mutually compatible with pre-46 on-disk state (see the schema
//! comment in `build_state.rs` and Phase 46 plan §6 for the
//! no-version-bump rationale).
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

/// Publisher-identity snapshot captured from a package version's
/// Sigstore attestation bundle.
///
/// Phase 46 uses this to detect **provenance drift** between a
/// previously-approved version and a candidate version. The axios
/// 1.14.1 compromise is the motivating case: every legitimate v1
/// release shipped with GitHub OIDC + Sigstore provenance; the
/// malicious v1.14.1 did not. The drift check (§7.2 of the plan)
/// compares the tuple field-by-field.
///
/// Populated from the Sigstore bundle's leaf-cert SAN. P1 defines the
/// type and the `Option<ProvenanceSnapshot>` field placements. P4
/// wires the actual fetch + parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ProvenanceSnapshot {
    /// `true` iff the registry returned a non-empty attestations
    /// bundle for this version. `false` indicates "registry has no
    /// provenance for this version" — which is the exact axios-case
    /// signal when compared against a prior-approved version that had
    /// provenance.
    pub present: bool,
    /// Publisher identity extracted from the Sigstore cert SAN.
    /// Typically of the form
    /// `github:<org>/<repo>/.github/workflows/<workflow>@refs/tags/<tag>`.
    /// `None` when `present == false` OR when SAN parse degraded
    /// (degraded but non-fatal; the rest of the drift check still
    /// runs on available fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Workflow file path + ref. Split from `publisher` because the
    /// identity cert can name the same repo with a different workflow
    /// (e.g., a PR-triggered workflow masquerading as the main publish
    /// workflow). `None` when not extractable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// SHA-256 of the leaf attestation certificate (DER-encoded).
    /// Tie-breaker when `publisher` alone is insufficient — e.g., same
    /// org + repo but different ephemeral cert chain. `None` when the
    /// cert bytes were not retained (default until P4 wires it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_cert_sha256: Option<String>,
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
             is the wire contract consumed by `approve-builds --json` \
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

    // ── ProvenanceSnapshot ────────────────────────────────────────

    #[test]
    fn provenance_snapshot_full_roundtrips() {
        let snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios/.github/workflows/publish.yml".into()),
            workflow: Some(".github/workflows/publish.yml@refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-abc123".into()),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ProvenanceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn provenance_snapshot_absent_minimal_json() {
        // When `present == false` and the extraction path didn't fill
        // in any optional fields, the serialized form should be minimal
        // (no `null` keys for the optionals, thanks to
        // skip_serializing_if).
        let snap = ProvenanceSnapshot {
            present: false,
            publisher: None,
            workflow: None,
            attestation_cert_sha256: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(
            json, r#"{"present":false}"#,
            "absent snapshot should not emit null keys for optional \
             fields — smaller JSON + less noise in build-state.json"
        );
    }

    #[test]
    fn provenance_snapshot_partial_parse() {
        // Real-world path: attestation bundle parses but the SAN
        // extractor only got the publisher, not the workflow or cert
        // SHA. The type must accept this degraded input.
        let json = r#"{
            "present": true,
            "publisher": "github:axios/axios/.github/workflows/publish.yml"
        }"#;
        let snap: ProvenanceSnapshot = serde_json::from_str(json).unwrap();
        assert!(snap.present);
        assert_eq!(
            snap.publisher.as_deref(),
            Some("github:axios/axios/.github/workflows/publish.yml")
        );
        assert!(snap.workflow.is_none());
        assert!(snap.attestation_cert_sha256.is_none());
    }

    #[test]
    fn provenance_snapshot_equality_is_tuple_strict() {
        // Drift detection (§7.2) hinges on strict tuple equality.
        // Any field differing means "drifted."
        let base = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow: Some("publish.yml@v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-aaa".into()),
        };
        let differ_publisher = ProvenanceSnapshot {
            publisher: Some("github:someone-else/axios".into()),
            ..base.clone()
        };
        let differ_workflow = ProvenanceSnapshot {
            workflow: Some("publish.yml@v1.14.1".into()),
            ..base.clone()
        };
        let differ_cert = ProvenanceSnapshot {
            attestation_cert_sha256: Some("sha256-bbb".into()),
            ..base.clone()
        };
        assert_ne!(base, differ_publisher);
        assert_ne!(base, differ_workflow);
        assert_ne!(base, differ_cert);
        assert_eq!(base, base.clone());
    }

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
