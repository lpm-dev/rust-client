//! Phase 48 P0 slice 6 — per-package capability set + canonical hashing.
//!
//! Introduces the pure data model and canonical-hash primitive for the
//! three per-package capability knobs defined in
//! [phase48.md §6 "Per-package capability knobs"](../../../../../../a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase48.md):
//!
//! - `passEnv` — sorted, deduplicated set of env-var names a package
//!   wants passed through to its lifecycle scripts.
//! - `readProject` — whether the package needs `full` project-tree
//!   read access or `narrow` (baseline) is enough.
//! - `sandboxLimits` — per-limit numeric ceilings a package is asking
//!   the user to allow above the user-global ceiling.
//!
//! # Scope of this slice
//!
//! **Pure, heavily tested** per reviewer guidance. No I/O, no approval-
//! record wiring, no enforcement-path integration. The next slices
//! in this lane will:
//!
//! - (next) Extend the approval record to carry `canonical_hash()` of
//!   a [`CapabilitySet`] so old approvals continue to mean "approved
//!   with no extra capabilities" and new approvals bind the granted
//!   set.
//! - Wire [`CapabilitySet::is_at_baseline`] and a to-be-added
//!   `loosens_beyond` helper into [`evaluate_trust`] so tighter-than-
//!   user-bound requests auto-apply, looser-than-bound requests
//!   require approval, and drift on the approval-hash invalidates.
//! - Surface capability deltas in `lpm approve-scripts` so the user
//!   sees *which* env vars / rlimits / read mode they're granting
//!   and the exact granted hash is persisted.
//!
//! # Canonicalization contract
//!
//! The central invariant is: **two semantically-equivalent
//! capability sets produce the same hash.** Specifically:
//!
//! - `pass_env` is a [`BTreeSet`], so insertion order is irrelevant
//!   and duplicates collapse.
//! - `sandbox_limits` is a [`BTreeMap`] on [`RlimitKey`], same
//!   property on both count and key-ordering.
//! - `read_project` is an enum variant, so the only semantically
//!   meaningful states are [`ReadProjectMode::Narrow`] (baseline)
//!   and [`ReadProjectMode::Full`] (loosening).
//!
//! Tests in this module pin all three invariants against deliberate
//! permutations.
//!
//! # Hash format
//!
//! `sha256-<hex>`, matching
//! [`lpm_security::triage::hash_behavioral_tag_set`] and
//! [`lpm_security::script_hash::compute_script_hash`]. The pre-image
//! is a deterministic byte stream with:
//!
//! 1. A two-byte version prefix `"v1\0"`. Future format evolution
//!    gets a new version number so old approval hashes can be
//!    explicitly migrated rather than silently colliding.
//! 2. Fixed-byte section headers (`"pass_env\0"`,
//!    `"read_project\0"`, `"sandbox_limits\0"`). These are literal
//!    constants, not derived from content — a user with
//!    `passEnv = ["read_project"]` cannot craft their set to hash
//!    the same as a set with an actual `read_project` change.
//! 3. Record separator (byte `0x1e`) between sections. Combined
//!    with the fixed section headers, prevents a value in one
//!    section from being confused with content in the next.
//! 4. NUL separator between elements within a section — same
//!    adjacency-collision defense the behavioral-tag hash uses.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ── ReadProjectMode ───────────────────────────────────────────────

/// Per-package request for project-tree read access.
///
/// The §6 single-semantic rule applies: `Narrow` matches the user
/// floor (no approval needed); `Full` is a loosening that requires
/// an approval binding the [`CapabilitySet::canonical_hash`] of the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ReadProjectMode {
    /// Baseline reads only: `node_modules/`, `tsconfig*.json`,
    /// `package.json`, `package-lock.json`, `lpm.lock*`. This is
    /// the default when the project does not declare
    /// `package.json > lpm > scripts > readProject`.
    #[default]
    Narrow,
    /// Full project tree, including source files, `.env*`,
    /// `.git/config`, `*.pem`, etc.
    Full,
}

impl ReadProjectMode {
    /// Canonical kebab-case wire form used in the hash pre-image
    /// and in `package.json`. Stable — a future variant would
    /// require a hash-format version bump.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Narrow => "narrow",
            Self::Full => "full",
        }
    }
}

// ── RlimitKey ─────────────────────────────────────────────────────

/// The four rlimits Phase 48 P2 wires into the sandbox backend.
///
/// Ordering of variants defines the canonical sort order used by
/// [`CapabilitySet::canonical_hash`]. Adding a new variant appends
/// to the end and requires a hash-format version bump in the
/// module-doc contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RlimitKey {
    /// `RLIMIT_AS` — address-space ceiling.
    As,
    /// `RLIMIT_NPROC` — process-count ceiling.
    Nproc,
    /// `RLIMIT_NOFILE` — file-descriptor ceiling.
    Nofile,
    /// `RLIMIT_CPU` — CPU-seconds ceiling.
    Cpu,
}

impl RlimitKey {
    /// Canonical wire form. Matches the C macro names so logs and
    /// error messages are greppable against libc docs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::As => "RLIMIT_AS",
            Self::Nproc => "RLIMIT_NPROC",
            Self::Nofile => "RLIMIT_NOFILE",
            Self::Cpu => "RLIMIT_CPU",
        }
    }
}

// ── CapabilitySet ─────────────────────────────────────────────────

/// Per-package capability request: the three Phase 48 per-package
/// knobs the project can declare in `package.json > lpm > scripts`.
///
/// Stores the canonical (sorted, deduplicated) form. Callers
/// building a set from arbitrary input can push into the inner
/// collections directly — the [`BTreeSet`] / [`BTreeMap`] choice
/// enforces the canonical-form invariant automatically.
///
/// The empty set (`CapabilitySet::default()`) represents "no
/// capability beyond baseline" — [`Self::is_at_baseline`] returns
/// `true`. Approval for such a set is trivially available because
/// there's nothing to widen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    /// Requested env-var names. Empty = no passthrough requested;
    /// matches the minimal allowlist baseline.
    pub pass_env: BTreeSet<String>,
    /// Requested project-tree read mode.
    pub read_project: ReadProjectMode,
    /// Requested rlimit ceilings — only entries strictly above the
    /// user ceiling require approval; entries at-or-below auto-
    /// apply at enforcement time.
    pub sandbox_limits: BTreeMap<RlimitKey, u64>,
}

impl CapabilitySet {
    /// Returns `true` iff the set requests nothing beyond baseline.
    ///
    /// "Baseline" here means the structural minimum: no env-var
    /// passthrough, narrow read mode, no rlimit bumps. The
    /// enforcement path uses this as a short-circuit — a baseline
    /// request never requires approval, so there's no need to
    /// consult the approval record.
    ///
    /// NOTE: "at baseline" is weaker than "does not loosen
    /// beyond the user bound." A future enforcement helper will
    /// answer the latter question by comparing each field against
    /// the user's configured floor/ceiling; that helper is
    /// introduced in the enforcement-path sub-slice, not here.
    pub fn is_at_baseline(&self) -> bool {
        self.pass_env.is_empty()
            && matches!(self.read_project, ReadProjectMode::Narrow)
            && self.sandbox_limits.is_empty()
    }

    /// Canonical hash over a deterministic wire-format.
    ///
    /// Format version 1 (see module doc for the byte-level layout).
    /// Bumping the version invalidates every approval hash computed
    /// at the prior version — plan migrations accordingly.
    pub fn canonical_hash(&self) -> String {
        let mut hasher = Sha256::new();

        // v1 prefix. A future `v2` would change the byte sequence
        // and produce non-overlapping hashes from v1 for the same
        // logical content.
        hasher.update(b"v1\0");

        // Section 1: pass_env. BTreeSet iteration is already
        // sorted and dedup'd so we don't re-canonicalize here.
        hasher.update(b"pass_env\0");
        for name in &self.pass_env {
            hasher.update(name.as_bytes());
            hasher.update([0u8]);
        }
        hasher.update([0x1e]); // RS (ASCII record separator)

        // Section 2: read_project. Fixed-length token from the
        // kebab-case wire form; can't collide with a pass_env
        // value because of the section-header + record-separator
        // framing.
        hasher.update(b"read_project\0");
        hasher.update(self.read_project.as_str().as_bytes());
        hasher.update([0x1e]);

        // Section 3: sandbox_limits. BTreeMap iteration is sorted
        // by RlimitKey's Ord impl (As < Nproc < Nofile < Cpu).
        hasher.update(b"sandbox_limits\0");
        for (key, val) in &self.sandbox_limits {
            hasher.update(key.as_str().as_bytes());
            hasher.update(b"=");
            hasher.update(val.to_string().as_bytes());
            hasher.update([0u8]);
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
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a CapabilitySet from raw inputs, sorting /
    // dedup'ing via BTreeSet / BTreeMap on the way in.
    fn set_from(
        pass_env: &[&str],
        read_project: ReadProjectMode,
        sandbox_limits: &[(RlimitKey, u64)],
    ) -> CapabilitySet {
        CapabilitySet {
            pass_env: pass_env.iter().map(|s| s.to_string()).collect(),
            read_project,
            sandbox_limits: sandbox_limits.iter().copied().collect(),
        }
    }

    // ── Hash-format contract ──────────────────────────────────────

    #[test]
    fn hash_has_sha256_prefix_and_64_hex_chars() {
        let h = CapabilitySet::default().canonical_hash();
        assert!(h.starts_with("sha256-"), "prefix: {h}");
        let hex_part = h.strip_prefix("sha256-").unwrap();
        assert_eq!(hex_part.len(), 64, "64 hex chars: {h}");
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "lowercase hex: {h}"
        );
    }

    #[test]
    fn empty_set_has_stable_nonempty_hash() {
        // Empty / baseline CapabilitySet MUST produce a stable,
        // non-zero hash — it's the "approved with no extra
        // capabilities" state, distinct from "no approval record
        // exists at all." Approval records carrying this hash
        // mean "user reviewed and approved the package with
        // nothing extra requested."
        let h1 = CapabilitySet::default().canonical_hash();
        let h2 = CapabilitySet::default().canonical_hash();
        assert_eq!(h1, h2);
        // The hash is deterministic; pin it so a format-version
        // bump can't silently regress approval records computed
        // under v1. If v2 ships, this literal changes in the same
        // commit as the version bump.
        assert_eq!(
            h1, "sha256-c7d2926445217fe6756192e619b4379db0917d2757fdaa2cd4dbb6d68ca0a5e9",
            "v1 empty-set hash — load-bearing across approval storage; \
             a change here means approvals from prior versions won't match"
        );
    }

    // ── Sorted / dedup invariants ─────────────────────────────────

    #[test]
    fn pass_env_permutations_hash_identically() {
        // BTreeSet iteration order is sorted, so two CapabilitySets
        // built from different-order input arrays MUST hash the same.
        let a = set_from(&["FOO", "BAR", "BAZ"], ReadProjectMode::Narrow, &[]);
        let b = set_from(&["BAZ", "FOO", "BAR"], ReadProjectMode::Narrow, &[]);
        let c = set_from(&["BAR", "BAZ", "FOO"], ReadProjectMode::Narrow, &[]);
        assert_eq!(a.canonical_hash(), b.canonical_hash());
        assert_eq!(a.canonical_hash(), c.canonical_hash());
    }

    #[test]
    fn pass_env_duplicates_collapse_before_hashing() {
        // Inserting a name twice into a BTreeSet is a no-op, so
        // the hash matches the single-insertion version.
        let with_dup = set_from(&["FOO", "FOO", "BAR"], ReadProjectMode::Narrow, &[]);
        let without = set_from(&["FOO", "BAR"], ReadProjectMode::Narrow, &[]);
        assert_eq!(with_dup.pass_env.len(), 2, "BTreeSet dedups");
        assert_eq!(with_dup.canonical_hash(), without.canonical_hash());
    }

    #[test]
    fn sandbox_limits_permutations_hash_identically() {
        let a = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::Cpu, 600), (RlimitKey::As, 4096)],
        );
        let b = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 4096), (RlimitKey::Cpu, 600)],
        );
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn sandbox_limits_duplicate_keys_keep_last_value() {
        // BTreeMap collect() keeps the LAST value for a duplicate
        // key. This is an implementation detail of BTreeMap; if
        // callers want deliberate replacement semantics they should
        // insert explicitly. Test pins the behavior so a future
        // refactor to iter-and-fold can't silently reverse it.
        let pairs = [(RlimitKey::As, 1024), (RlimitKey::As, 2048)];
        let set = set_from(&[], ReadProjectMode::Narrow, &pairs);
        assert_eq!(set.sandbox_limits.get(&RlimitKey::As), Some(&2048));
        assert_eq!(set.sandbox_limits.len(), 1);
    }

    // ── Cross-field distinctness ──────────────────────────────────

    #[test]
    fn differing_pass_env_changes_hash() {
        let a = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        let b = set_from(&["BAR"], ReadProjectMode::Narrow, &[]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn adding_pass_env_entry_changes_hash() {
        let before = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        let after = set_from(&["FOO", "BAR"], ReadProjectMode::Narrow, &[]);
        assert_ne!(before.canonical_hash(), after.canonical_hash());
    }

    #[test]
    fn removing_pass_env_entry_changes_hash() {
        let before = set_from(&["FOO", "BAR"], ReadProjectMode::Narrow, &[]);
        let after = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        assert_ne!(before.canonical_hash(), after.canonical_hash());
    }

    #[test]
    fn toggling_read_project_changes_hash() {
        let narrow = set_from(&[], ReadProjectMode::Narrow, &[]);
        let full = set_from(&[], ReadProjectMode::Full, &[]);
        assert_ne!(narrow.canonical_hash(), full.canonical_hash());
    }

    #[test]
    fn changing_a_sandbox_limit_value_changes_hash() {
        let a = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        let b = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 2048)]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn changing_a_sandbox_limit_key_changes_hash() {
        let a = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        let b = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Cpu, 1024)]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    // ── Section-framing bypass resistance ─────────────────────────

    #[test]
    fn pass_env_value_cannot_spoof_read_project_section() {
        // A crafty pass_env value of "read_project" must NOT hash
        // the same as an actual read_project = Full set. The
        // section headers are literal `"pass_env\0"` /
        // `"read_project\0"` + record separators, which a pass_env
        // string payload can't reproduce in-framing.
        let spoof = set_from(&["read_project", "full"], ReadProjectMode::Narrow, &[]);
        let real = set_from(&[], ReadProjectMode::Full, &[]);
        assert_ne!(spoof.canonical_hash(), real.canonical_hash());
    }

    #[test]
    fn pass_env_adjacency_collision_resistance() {
        // NUL separators between elements prevent the classic
        // concatenation collision: `["net", "work"]` and `["netw",
        // "ork"]` both reduce to "network" if separators were
        // missing. The behavioral-tag hash has the same defense;
        // we mirror it here.
        let a = set_from(&["net", "work"], ReadProjectMode::Narrow, &[]);
        let b = set_from(&["netw", "ork"], ReadProjectMode::Narrow, &[]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn sandbox_limits_key_value_adjacency_resistance() {
        // `RLIMIT_AS=10` followed by `RLIMIT_CPU=20` must not
        // collide with `RLIMIT_AS=10RLIMIT_CPU` = `20` or similar
        // adversarial splits. The `=` in the key=value encoding
        // plus the NUL between pairs handles this.
        let a = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 10), (RlimitKey::Cpu, 20)],
        );
        // There's no way to construct a "collision sibling" via
        // the typed API (RlimitKey is an enum; we can't smuggle
        // arbitrary strings through it). This test pins that the
        // two non-empty-limit pairs produce a distinct hash from
        // a single-pair `RLIMIT_AS = 1020` (the digits-merged
        // form) — confirming the framing includes a boundary
        // between value and next key.
        let b = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1020)]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    // ── is_at_baseline ────────────────────────────────────────────

    #[test]
    fn default_capability_set_is_at_baseline() {
        assert!(CapabilitySet::default().is_at_baseline());
    }

    #[test]
    fn non_empty_pass_env_is_not_at_baseline() {
        let s = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        assert!(!s.is_at_baseline());
    }

    #[test]
    fn full_read_project_is_not_at_baseline() {
        let s = set_from(&[], ReadProjectMode::Full, &[]);
        assert!(!s.is_at_baseline());
    }

    #[test]
    fn non_empty_sandbox_limits_is_not_at_baseline() {
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        assert!(!s.is_at_baseline());
    }

    // ── Wire-form stability for the inner enum as_str() ──

    #[test]
    fn read_project_mode_wire_strings_are_kebab_case_stable() {
        // These strings feed the hash pre-image and MUST stay
        // stable across refactors — changing them is a hash-
        // format v2 event.
        assert_eq!(ReadProjectMode::Narrow.as_str(), "narrow");
        assert_eq!(ReadProjectMode::Full.as_str(), "full");
    }

    #[test]
    fn rlimit_key_wire_strings_match_libc_macro_names() {
        // Match the C macro names so logs stay greppable against
        // libc docs. Stability requirement same as ReadProjectMode.
        assert_eq!(RlimitKey::As.as_str(), "RLIMIT_AS");
        assert_eq!(RlimitKey::Nproc.as_str(), "RLIMIT_NPROC");
        assert_eq!(RlimitKey::Nofile.as_str(), "RLIMIT_NOFILE");
        assert_eq!(RlimitKey::Cpu.as_str(), "RLIMIT_CPU");
    }

    #[test]
    fn rlimit_key_ord_matches_canonical_sort_order() {
        // BTreeMap iteration = Ord on the key. The hash
        // canonicalization relies on this ordering being stable;
        // a refactor that reordered the variants would silently
        // change every sandbox_limits hash. Test pins the
        // invariant from the comparison side.
        use std::cmp::Ordering;
        let keys = [
            RlimitKey::As,
            RlimitKey::Nproc,
            RlimitKey::Nofile,
            RlimitKey::Cpu,
        ];
        for pair in keys.windows(2) {
            assert_eq!(
                pair[0].cmp(&pair[1]),
                Ordering::Less,
                "{:?} must sort before {:?}",
                pair[0],
                pair[1],
            );
        }
    }
}
