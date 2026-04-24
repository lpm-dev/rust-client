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
//! - (sub-slice 6b, this commit) extends the approval record
//!   ([`lpm_workspace::TrustedDependencyBinding::capability_hash`]) to
//!   carry the `canonical_hash` of the approved
//!   [`CapabilitySet`]; adds the match method
//!   [`CapabilitySet::is_approved_by`] with the single invariant
//!   "legacy approval approves baseline only; new approval
//!   requires exact hash equality."
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
use std::fmt;

// ── CapabilityParseError ──────────────────────────────────────────

/// Error from [`CapabilitySet::from_package_json`].
///
/// Distinct variants so the caller can render different messages
/// (and drive different CI exit codes) for I/O errors, malformed
/// JSON, shape mismatches, and unknown enum values.
///
/// Absent fields in the manifest are NOT errors — they yield the
/// baseline (default) value silently. The errors here cover cases
/// where the user tried to declare something but got the shape or
/// value wrong; silently ignoring those would hide a widening
/// request from the user's review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityParseError {
    /// The manifest file existed but could not be read.
    Io { path: String, source: String },
    /// The manifest file wasn't valid JSON.
    Json { path: String, source: String },
    /// A declared field had the wrong shape (e.g., `passEnv`
    /// declared as a string instead of an array).
    ShapeMismatch {
        path: String,
        field: String,
        expected: String,
    },
    /// A declared enum-like field used an unrecognized variant
    /// (e.g., `readProject = "widen"` instead of `narrow` / `full`).
    UnknownVariant {
        path: String,
        field: String,
        got: String,
        expected: String,
    },
}

impl fmt::Display for CapabilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {path}: {source}")
            }
            Self::Json { path, source } => {
                write!(f, "{path}: not valid JSON: {source}")
            }
            Self::ShapeMismatch {
                path,
                field,
                expected,
            } => {
                write!(f, "{path}: `{field}` must be {expected}")
            }
            Self::UnknownVariant {
                path,
                field,
                got,
                expected,
            } => {
                write!(f, "{path}: `{field}` got {got:?}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for CapabilityParseError {}

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

// ── UserBound ─────────────────────────────────────────────────────

/// The user-level upper bounds that gate per-package capability
/// requests at enforcement time.
///
/// Phase 48 P0 sub-slice 6c wires this through [`evaluate_trust`].
/// Only the [`sandbox_limits`] field is user-configurable right now
/// — `pass_env` and `read_project` have fixed floors (empty /
/// `Narrow`) that aren't user-extensible in P0. A future sub-slice
/// could extend `UserBound` with `pass_env_allowlist` to match the
/// phase48 §6 Gap-5 env-allowlist model if user-level passthrough
/// becomes desirable; the enforcement code already handles "empty
/// allowlist = no widening allowed without approval" correctly.
///
/// # Reading from `~/.lpm/config.toml`
///
/// [`Self::from_global_config`] consumes the nested `sandbox.limits`
/// table. Keys use the canonical [`RlimitKey::as_str`] form
/// (`RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`, `RLIMIT_CPU`).
/// Example:
///
/// ```toml
/// [sandbox.limits]
/// RLIMIT_AS = 4294967296      # 4 GiB
/// RLIMIT_NPROC = 512
/// RLIMIT_NOFILE = 4096
/// RLIMIT_CPU = 600            # seconds
/// ```
///
/// Missing keys yield no ceiling for that rlimit — the enforcement
/// rule below treats "no user ceiling set" as "any request for this
/// rlimit counts as a widening that requires approval." This is the
/// conservative default: a package asking for an rlimit the user
/// hasn't reviewed at all cannot auto-apply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserBound {
    /// Per-rlimit ceilings the user has set globally.
    ///
    /// At enforcement time a request with value ≤ ceiling for a
    /// given rlimit auto-applies (tighter than the user already
    /// permits). A request > ceiling — OR a request for an rlimit
    /// the user hasn't configured at all — counts as widening and
    /// requires approval via the capability-hash path.
    pub sandbox_limits_ceiling: BTreeMap<RlimitKey, u64>,
}

impl UserBound {
    /// Read user-configured rlimit ceilings from a loaded
    /// [`lpm_cli::commands::config::GlobalConfig`]. Missing keys
    /// and type-mismatches are silently skipped — the stricter
    /// "no ceiling configured" rule applies, which fails closed
    /// (any request for that rlimit triggers the approval gate).
    ///
    /// Lives on `UserBound` rather than in `GlobalConfig::get_*`
    /// because the RLIMIT_* key set is capability-specific; a
    /// generic `get_u64_map` would widen GlobalConfig's API for
    /// one caller.
    pub fn from_global_config(global: &crate::commands::config::GlobalConfig) -> Self {
        // Walk `sandbox` → `limits` as two nested tables. If either
        // is absent or not a table, return the default (empty
        // ceiling map → every rlimit request triggers the approval
        // gate, the conservative fail-closed default).
        let Some(sandbox) = global.get_table("sandbox") else {
            return Self::default();
        };
        let Some(limits) = sandbox.get("limits").and_then(|v| v.as_table()) else {
            return Self::default();
        };
        let mut map = BTreeMap::new();
        for key in [
            RlimitKey::As,
            RlimitKey::Nproc,
            RlimitKey::Nofile,
            RlimitKey::Cpu,
        ] {
            if let Some(v) = limits.get(key.as_str()).and_then(extract_u64) {
                map.insert(key, v);
            }
        }
        Self {
            sandbox_limits_ceiling: map,
        }
    }
}

/// Extract a `u64` from a toml Value. Accepts native integers and
/// strings that parse as non-negative u64 (matching the "string
/// coercion" pattern established in `GlobalConfig::get_u64` for
/// values written via `lpm config set`).
fn extract_u64(v: &toml::Value) -> Option<u64> {
    match v {
        toml::Value::Integer(i) => u64::try_from(*i).ok(),
        toml::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    }
}

// ── CapabilityDelta ───────────────────────────────────────────────

/// **Phase 48 P0 sub-slice 6d.** Structured description of how a
/// [`CapabilitySet`] widens beyond a [`UserBound`].
///
/// Produced by [`CapabilitySet::delta_vs_user_bound`]. Consumed by
/// `lpm approve-scripts` to render the capabilities a user is
/// being asked to grant in human terms. Enumerates ONLY the
/// widening fields — empty `pass_env`, `read_project_widened =
/// false`, and empty `sandbox_limits_bumps` together mean "no
/// widening" (i.e., [`CapabilityDelta::is_empty`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityDelta {
    /// Env-var names the package requests passthrough for. Since
    /// the user floor is empty (Phase 48 §6), every entry here
    /// is a widening.
    pub pass_env: BTreeSet<String>,
    /// True iff the package requests
    /// [`ReadProjectMode::Full`] project reads. The floor is
    /// [`ReadProjectMode::Narrow`] so `false` means no widening.
    pub read_project_widened: bool,
    /// Rlimit bumps, keyed by [`RlimitKey`] with the requested
    /// value + the user's currently-configured ceiling (if any).
    /// Entries appear here only when the request exceeds the
    /// ceiling OR when no ceiling is configured for that rlimit.
    pub sandbox_limits_bumps: BTreeMap<RlimitKey, SandboxLimitDelta>,
}

/// Per-rlimit widening detail surfaced in [`CapabilityDelta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxLimitDelta {
    /// What the package asked for.
    pub requested: u64,
    /// The user's currently-configured ceiling for this rlimit.
    /// `None` means the user hasn't configured one — the
    /// enforcement rule treats that as "any request widens," so
    /// the prompt message explains "no user ceiling configured"
    /// as the reason.
    pub current_ceiling: Option<u64>,
}

impl CapabilityDelta {
    /// `true` iff no widening is requested. Symmetric with
    /// `!CapabilitySet::loosens_beyond(&bound)` for the same
    /// `(set, bound)` pair.
    pub fn is_empty(&self) -> bool {
        self.pass_env.is_empty()
            && !self.read_project_widened
            && self.sandbox_limits_bumps.is_empty()
    }

    /// Produce a multi-line human-readable description of the
    /// widening request. Indented two spaces per line so callers
    /// can render inside a bulleted approve-scripts prompt
    /// without further decoration. Returns an empty string when
    /// the delta is empty (caller should short-circuit).
    pub fn render_human_readable(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        if !self.pass_env.is_empty() {
            out.push_str("  env vars:   ");
            let names: Vec<&str> = self.pass_env.iter().map(|s| s.as_str()).collect();
            out.push_str(&names.join(", "));
            out.push('\n');
        }
        if self.read_project_widened {
            out.push_str(
                "  reads:      full project tree (source, .env, .git/config, and similar)\n",
            );
        }
        if !self.sandbox_limits_bumps.is_empty() {
            out.push_str("  rlimits:\n");
            for (key, d) in &self.sandbox_limits_bumps {
                let ceiling_phrase = match d.current_ceiling {
                    Some(c) => format!("exceeds your ceiling of {c}"),
                    None => "no user ceiling configured".to_string(),
                };
                out.push_str(&format!(
                    "              {key} = {req} ({phrase})\n",
                    key = key.as_str(),
                    req = d.requested,
                    phrase = ceiling_phrase,
                ));
            }
        }
        out
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

    /// **Phase 48 P0 sub-slice 6d.** Compute the human-readable
    /// delta between this request and the user's bound.
    ///
    /// Returned [`CapabilityDelta`] enumerates ONLY the fields that
    /// widen beyond the user bound — callers render it for the
    /// `lpm approve-scripts` prompt so the user sees what they're
    /// being asked to grant in concrete terms (env-var names, read-
    /// mode, rlimit bumps), not just a hash.
    ///
    /// Parity with [`Self::loosens_beyond`]: if `delta_vs_user_bound`
    /// returns a delta where `is_empty() == false`, `loosens_beyond`
    /// returns `true`. This is the same condition computed two ways
    /// — tests in the module pin the invariant.
    pub fn delta_vs_user_bound(&self, user: &UserBound) -> CapabilityDelta {
        let pass_env = self.pass_env.clone();
        let read_project_widened = matches!(self.read_project, ReadProjectMode::Full);
        let mut sandbox_limits_bumps = BTreeMap::new();
        for (key, requested) in &self.sandbox_limits {
            let ceiling = user.sandbox_limits_ceiling.get(key).copied();
            let widens = match ceiling {
                Some(c) => *requested > c,
                None => true,
            };
            if widens {
                sandbox_limits_bumps.insert(
                    *key,
                    SandboxLimitDelta {
                        requested: *requested,
                        current_ceiling: ceiling,
                    },
                );
            }
        }
        CapabilityDelta {
            pass_env,
            read_project_widened,
            sandbox_limits_bumps,
        }
    }

    /// Returns `true` iff this request widens beyond what the
    /// user's configured [`UserBound`] permits, so the approval
    /// gate must fire. Returns `false` when every field is at or
    /// tighter than the user bound — in that case the request
    /// auto-applies without needing a capability-hash approval.
    ///
    /// **Per-field rule (phase48.md §6 "Per-package capability
    /// knobs — single semantic"):**
    ///
    /// - `pass_env` — user floor is empty (no extras). Any
    ///   declared name is a widening. Non-empty → `true`.
    /// - `read_project` — user floor is `Narrow`. `Full` is a
    ///   widening; `Narrow` matches the floor → `false`.
    /// - `sandbox_limits` — user ceiling is numeric and per-rlimit
    ///   (or absent = no ceiling configured = fail-closed). For
    ///   each requested `(key, value)`:
    ///   - If `user.sandbox_limits_ceiling.get(key) == Some(c)` and
    ///     `value <= c`, this entry is tighter-or-equal → no
    ///     widening.
    ///   - If `value > c` OR the user hasn't configured a ceiling
    ///     for this rlimit, this entry widens → `true`.
    ///
    /// The function short-circuits on the first widening it finds
    /// (any single widened field is enough to require approval).
    pub fn loosens_beyond(&self, user: &UserBound) -> bool {
        if !self.pass_env.is_empty() {
            return true;
        }
        if matches!(self.read_project, ReadProjectMode::Full) {
            return true;
        }
        for (key, requested) in &self.sandbox_limits {
            match user.sandbox_limits_ceiling.get(key) {
                Some(ceiling) if requested <= ceiling => continue,
                _ => return true,
            }
        }
        false
    }

    /// Read the capability request out of a project's
    /// `package.json > lpm > scripts > {passEnv, readProject,
    /// sandboxLimits}` block.
    ///
    /// Returns the baseline [`CapabilitySet`] when any of the
    /// following is true: the file is missing; the file is not
    /// valid JSON; the `lpm.scripts` block is missing; any of
    /// the three fields is absent. Malformed values (wrong type,
    /// unknown enum variant, non-u64 rlimit value, etc.) are
    /// surfaced as `Err` so the user sees a clear config error
    /// instead of a silent "no capability request" that would
    /// erroneously auto-approve a widening the user couldn't see.
    ///
    /// `package_json` is the path to the manifest; typically
    /// `<project_dir>/package.json`.
    pub fn from_package_json(package_json: &std::path::Path) -> Result<Self, CapabilityParseError> {
        let raw = match std::fs::read_to_string(package_json) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(CapabilityParseError::Io {
                    path: package_json.display().to_string(),
                    source: e.to_string(),
                });
            }
        };
        let json: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| CapabilityParseError::Json {
                path: package_json.display().to_string(),
                source: e.to_string(),
            })?;
        let Some(scripts) = json.get("lpm").and_then(|l| l.get("scripts")) else {
            return Ok(Self::default());
        };

        let mut out = Self::default();

        // passEnv — must be an array of strings if present.
        if let Some(pass_env) = scripts.get("passEnv") {
            let arr = pass_env
                .as_array()
                .ok_or_else(|| CapabilityParseError::ShapeMismatch {
                    path: package_json.display().to_string(),
                    field: "lpm.scripts.passEnv".to_string(),
                    expected: "array of strings".to_string(),
                })?;
            for (i, entry) in arr.iter().enumerate() {
                let s = entry
                    .as_str()
                    .ok_or_else(|| CapabilityParseError::ShapeMismatch {
                        path: package_json.display().to_string(),
                        field: format!("lpm.scripts.passEnv[{i}]"),
                        expected: "string".to_string(),
                    })?;
                // BTreeSet insertion de-dups automatically.
                out.pass_env.insert(s.to_string());
            }
        }

        // readProject — must be one of the kebab-case variants.
        if let Some(rp) = scripts.get("readProject") {
            let s = rp
                .as_str()
                .ok_or_else(|| CapabilityParseError::ShapeMismatch {
                    path: package_json.display().to_string(),
                    field: "lpm.scripts.readProject".to_string(),
                    expected: "\"narrow\" or \"full\"".to_string(),
                })?;
            out.read_project = match s {
                "narrow" => ReadProjectMode::Narrow,
                "full" => ReadProjectMode::Full,
                other => {
                    return Err(CapabilityParseError::UnknownVariant {
                        path: package_json.display().to_string(),
                        field: "lpm.scripts.readProject".to_string(),
                        got: other.to_string(),
                        expected: "\"narrow\" or \"full\"".to_string(),
                    });
                }
            };
        }

        // sandboxLimits — object of RLIMIT_* → non-negative integer.
        if let Some(sl) = scripts.get("sandboxLimits") {
            let obj = sl
                .as_object()
                .ok_or_else(|| CapabilityParseError::ShapeMismatch {
                    path: package_json.display().to_string(),
                    field: "lpm.scripts.sandboxLimits".to_string(),
                    expected: "object of RLIMIT_* → non-negative integer".to_string(),
                })?;
            for (key_str, value) in obj {
                let key = match key_str.as_str() {
                    "RLIMIT_AS" => RlimitKey::As,
                    "RLIMIT_NPROC" => RlimitKey::Nproc,
                    "RLIMIT_NOFILE" => RlimitKey::Nofile,
                    "RLIMIT_CPU" => RlimitKey::Cpu,
                    other => {
                        return Err(CapabilityParseError::UnknownVariant {
                            path: package_json.display().to_string(),
                            field: format!("lpm.scripts.sandboxLimits[{other}]"),
                            got: other.to_string(),
                            expected: "one of: RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_CPU"
                                .to_string(),
                        });
                    }
                };
                let val = value
                    .as_u64()
                    .ok_or_else(|| CapabilityParseError::ShapeMismatch {
                        path: package_json.display().to_string(),
                        field: format!("lpm.scripts.sandboxLimits.{key_str}"),
                        expected: "non-negative integer".to_string(),
                    })?;
                out.sandbox_limits.insert(key, val);
            }
        }

        Ok(out)
    }

    /// Returns `true` iff `binding` currently approves this
    /// capability set.
    ///
    /// **Match rule (phase48.md §6 "Per-package capability knobs"):**
    ///
    /// - `binding.capability_hash == None` (legacy approval from
    ///   before sub-slice 6b, or a new approval whose granted set
    ///   was baseline): matches iff `self.is_at_baseline()` —
    ///   nothing beyond baseline was ever reviewed, so nothing
    ///   beyond baseline is approved.
    /// - `binding.capability_hash == Some(stored_hash)`: matches iff
    ///   `stored_hash == self.canonical_hash()`. Any field change in
    ///   the requested set produces a different canonical hash and
    ///   the match fails — this is the drift-invalidates-approval
    ///   rule from phase48.md §6.
    ///
    /// # Why this method lives on `CapabilitySet`, not on the binding
    ///
    /// [`lpm_workspace::TrustedDependencyBinding`] can't import
    /// `CapabilitySet` (lpm-cli → lpm-workspace, not the other
    /// way) and cannot import the sha2-backed hash primitive
    /// without a cycle. Routing the match through the capability
    /// side keeps the dep graph acyclic. Enforcement code (6c)
    /// should call this method exclusively, not compare
    /// `binding.capability_hash` directly.
    pub fn is_approved_by(&self, binding: &lpm_workspace::TrustedDependencyBinding) -> bool {
        match &binding.capability_hash {
            None => self.is_at_baseline(),
            Some(stored) => stored == &self.canonical_hash(),
        }
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

    // ── Phase 48 P0 sub-slice 6b — is_approved_by match semantics ──
    //
    // Reviewer's acceptance list for this sub-slice:
    //
    // 1. Old record without capability_hash loads successfully.
    //    → `binding_without_capability_hash_loads_as_legacy_approval`
    //      in lpm-workspace/src/lib.rs.
    //
    // 2. Old record matches the no-extra-capability case only.
    //    → `legacy_binding_approves_baseline_request` below.
    //
    // 3. Old record does NOT satisfy widened passEnv / readProject =
    //    "full" / above-ceiling sandboxLimits.
    //    → `legacy_binding_rejects_widened_pass_env`,
    //      `legacy_binding_rejects_full_read_project`,
    //      `legacy_binding_rejects_non_empty_sandbox_limits`.
    //
    // 4. New record with a matching hash round-trips cleanly.
    //    → `binding_with_matching_hash_approves_set` (plus the
    //      round-trip test on the lpm-workspace side for the
    //      storage shape).
    //
    // 5. New record with a mismatched hash stays distinguishable from
    //    legacy-missing-hash behavior.
    //    → `binding_with_mismatched_hash_rejects_non_baseline`,
    //      `binding_with_mismatched_hash_rejects_baseline`
    //      (demonstrates the different semantic vs. legacy-None).

    use lpm_workspace::TrustedDependencyBinding;

    fn legacy_binding() -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: Some("sha512-legacy-integrity".into()),
            script_hash: Some("sha256-legacy-scripthash".into()),
            capability_hash: None,
            ..Default::default()
        }
    }

    fn binding_with_hash(hash: &str) -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: Some("sha512-integrity".into()),
            script_hash: Some("sha256-scripthash".into()),
            capability_hash: Some(hash.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn legacy_binding_approves_baseline_request() {
        // Reviewer acceptance #2: legacy approval approves the
        // baseline (no extras) request.
        let baseline = CapabilitySet::default();
        assert!(baseline.is_at_baseline());
        assert!(baseline.is_approved_by(&legacy_binding()));
    }

    #[test]
    fn legacy_binding_rejects_widened_pass_env() {
        // Reviewer acceptance #3a: a legacy approval must NOT
        // satisfy a request with non-empty passEnv. Widening the
        // env-var passthrough requires a user review the legacy
        // approval never performed.
        let widened = set_from(&["SSH_AUTH_SOCK"], ReadProjectMode::Narrow, &[]);
        assert!(!widened.is_approved_by(&legacy_binding()));
    }

    #[test]
    fn legacy_binding_rejects_full_read_project() {
        // Reviewer acceptance #3b: readProject = Full is a
        // loosening, not covered by a legacy approval.
        let widened = set_from(&[], ReadProjectMode::Full, &[]);
        assert!(!widened.is_approved_by(&legacy_binding()));
    }

    #[test]
    fn legacy_binding_rejects_non_empty_sandbox_limits() {
        // Reviewer acceptance #3c: any sandboxLimits entry
        // (regardless of value) is a loosening request not
        // covered by a legacy approval. Enforcement-time logic in
        // sub-slice 6c will further distinguish at-or-below-
        // ceiling from above-ceiling; for the storage-level match
        // in 6b, ANY non-baseline capability invalidates a
        // legacy approval.
        let widened = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 8_000_000_000)],
        );
        assert!(!widened.is_approved_by(&legacy_binding()));
    }

    #[test]
    fn binding_with_matching_hash_approves_set() {
        // Reviewer acceptance #4: new-record approval with the
        // exact granted hash authorizes the matching request.
        let requested = set_from(
            &["NODE_AUTH_TOKEN"],
            ReadProjectMode::Full,
            &[(RlimitKey::Nproc, 1024)],
        );
        let binding = binding_with_hash(&requested.canonical_hash());
        assert!(requested.is_approved_by(&binding));
    }

    #[test]
    fn binding_with_mismatched_hash_rejects_non_baseline() {
        // Reviewer acceptance #5: new-record approval whose stored
        // hash DOESN'T match the current request is distinguishable
        // from a legacy-None approval. Both reject the request,
        // but the diagnostic reason differs (the former is "drift,"
        // the latter is "legacy approval doesn't cover extras").
        // Sub-slice 6c will surface the difference to users.
        let requested = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        let binding = binding_with_hash("sha256-some-other-hash");
        assert!(!requested.is_approved_by(&binding));
        // Sanity: the legacy binding also rejects — but for a
        // different reason. Both return false, and that's the
        // storage-level outcome we're pinning here.
        assert!(!requested.is_approved_by(&legacy_binding()));
    }

    #[test]
    fn binding_with_mismatched_hash_rejects_baseline() {
        // Critical distinction vs. legacy: a stored hash that
        // isn't the baseline hash does NOT approve a baseline
        // request. This is the case where the package was
        // approved WITH extras in the past, and now the package
        // has dropped its request to baseline — the user should
        // still see re-review because the reviewed set changed.
        //
        // Contrast with `legacy_binding_approves_baseline_request`:
        // a None stored hash approves baseline (since the legacy
        // approval was implicitly for baseline-only). A Some(h)
        // stored hash approves ONLY the set whose canonical hash
        // is h.
        let baseline = CapabilitySet::default();
        let binding = binding_with_hash("sha256-some-non-baseline-hash");
        assert!(
            !baseline.is_approved_by(&binding),
            "Some(non-baseline-hash) does NOT approve a baseline \
             request — the user approved a different (wider) set, \
             the package has now narrowed, and that drift itself \
             requires re-review"
        );
    }

    #[test]
    fn drift_invalidates_previously_approved_set() {
        // Full drift scenario: the user approves a specific set,
        // then the package changes its request (even slightly).
        // The match must fail.
        let originally_approved =
            set_from(&["FOO"], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        let binding = binding_with_hash(&originally_approved.canonical_hash());

        // Same binding should still approve the unchanged set.
        assert!(originally_approved.is_approved_by(&binding));

        // Now the package adds one env var — drift.
        let drift_add = set_from(
            &["FOO", "BAR"],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 1024)],
        );
        assert!(!drift_add.is_approved_by(&binding));

        // Or it flips readProject — drift.
        let drift_read = set_from(&["FOO"], ReadProjectMode::Full, &[(RlimitKey::As, 1024)]);
        assert!(!drift_read.is_approved_by(&binding));

        // Or it bumps a limit — drift.
        let drift_limit = set_from(&["FOO"], ReadProjectMode::Narrow, &[(RlimitKey::As, 2048)]);
        assert!(!drift_limit.is_approved_by(&binding));
    }

    #[test]
    fn baseline_hash_storage_approves_baseline_request() {
        // Edge case: a 6b+ approval flow might choose to store
        // Some(baseline_hash) rather than None for a baseline
        // approval. Both forms MUST approve a baseline request
        // (they're semantically equivalent — "user reviewed and
        // approved with no extras"), but the storage side knows
        // one produced a hash and one did not. Test both paths.
        let baseline = CapabilitySet::default();
        let baseline_hash = baseline.canonical_hash();

        // Stored-as-None:
        assert!(baseline.is_approved_by(&legacy_binding()));

        // Stored-as-Some(baseline_hash):
        let explicit_baseline_binding = binding_with_hash(&baseline_hash);
        assert!(baseline.is_approved_by(&explicit_baseline_binding));
    }

    // ── Phase 48 P0 sub-slice 6c — loosens_beyond ────────────────

    fn ub_with(ceilings: &[(RlimitKey, u64)]) -> UserBound {
        UserBound {
            sandbox_limits_ceiling: ceilings.iter().copied().collect(),
        }
    }

    // passEnv semantics: user floor is empty, so ANY declared name
    // is a widening.

    #[test]
    fn loosens_baseline_never_widens() {
        let baseline = CapabilitySet::default();
        assert!(!baseline.loosens_beyond(&UserBound::default()));
        // Adding a non-empty user bound (rlimit ceiling) does not
        // change the baseline verdict — baseline requests nothing
        // at all, so there's nothing that could widen.
        assert!(!baseline.loosens_beyond(&ub_with(&[(RlimitKey::As, 1024)])));
    }

    #[test]
    fn loosens_any_declared_pass_env_name_is_widening() {
        let s = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        assert!(s.loosens_beyond(&UserBound::default()));
        let s2 = set_from(
            &["SSH_AUTH_SOCK", "CI_JOB_JWT_V2"],
            ReadProjectMode::Narrow,
            &[],
        );
        assert!(s2.loosens_beyond(&UserBound::default()));
    }

    // readProject semantics: Narrow matches floor, Full widens.

    #[test]
    fn loosens_read_project_narrow_is_at_floor() {
        let s = set_from(&[], ReadProjectMode::Narrow, &[]);
        assert!(!s.loosens_beyond(&UserBound::default()));
    }

    #[test]
    fn loosens_read_project_full_is_widening() {
        let s = set_from(&[], ReadProjectMode::Full, &[]);
        assert!(s.loosens_beyond(&UserBound::default()));
    }

    // sandboxLimits semantics: per-rlimit ceiling comparison. No
    // user ceiling = fail-closed (any request triggers widening).

    #[test]
    fn loosens_sandbox_limit_below_ceiling_is_tighter() {
        // User permits 4096 NPROC; package requests 2048. Tighter.
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 2048)]);
        assert!(!s.loosens_beyond(&ub_with(&[(RlimitKey::Nproc, 4096)])));
    }

    #[test]
    fn loosens_sandbox_limit_equal_to_ceiling_matches() {
        // Equal is allowed — "≤ ceiling" is the rule, not "< ceiling".
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 4096)]);
        assert!(!s.loosens_beyond(&ub_with(&[(RlimitKey::Nproc, 4096)])));
    }

    #[test]
    fn loosens_sandbox_limit_above_ceiling_is_widening() {
        // User permits 4096; package asks for 8192.
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 8192)]);
        assert!(s.loosens_beyond(&ub_with(&[(RlimitKey::Nproc, 4096)])));
    }

    #[test]
    fn loosens_sandbox_limit_no_user_ceiling_is_widening() {
        // User hasn't configured RLIMIT_AS at all. Any request for
        // it triggers the approval gate — conservative fail-closed
        // default per phase48.md §6.
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        assert!(s.loosens_beyond(&UserBound::default()));
        // Even with OTHER ceilings set — still widens for the
        // unconfigured one.
        assert!(s.loosens_beyond(&ub_with(&[(RlimitKey::Nproc, 9999)])));
    }

    #[test]
    fn loosens_short_circuits_on_first_widening_field() {
        // Mixed-field request: passEnv widens (always), rlimits
        // irrelevant. Result is widening regardless of rlimit state.
        let s = set_from(
            &["FOO"],
            ReadProjectMode::Narrow,
            &[(RlimitKey::Nproc, 2048)],
        );
        assert!(s.loosens_beyond(&ub_with(&[(RlimitKey::Nproc, 4096)])));
    }

    #[test]
    fn loosens_mixed_set_all_fields_at_floor_does_not_widen() {
        // Non-baseline (sandbox_limits has an entry) but every
        // field is at-or-below the user bound. This exercises the
        // distinction between `is_at_baseline` (structural empty)
        // and `loosens_beyond(user)` (at or tighter than user
        // config) — a non-baseline set CAN still not-widen if the
        // user's ceiling accommodates it.
        let s = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 1024), (RlimitKey::Nproc, 512)],
        );
        let bound = ub_with(&[(RlimitKey::As, 4096), (RlimitKey::Nproc, 4096)]);
        assert!(!s.is_at_baseline(), "has sandbox_limits entries");
        assert!(!s.loosens_beyond(&bound), "but all at-or-below ceiling");
    }

    #[test]
    fn loosens_mixed_set_one_field_above_ceiling_widens() {
        // Same as above but one rlimit exceeds the user ceiling.
        let s = set_from(
            &[],
            ReadProjectMode::Narrow,
            &[(RlimitKey::As, 9999), (RlimitKey::Nproc, 512)],
        );
        let bound = ub_with(&[(RlimitKey::As, 4096), (RlimitKey::Nproc, 4096)]);
        assert!(s.loosens_beyond(&bound));
    }

    // ── Phase 48 P0 sub-slice 6c — UserBound::from_global_config ──
    //
    // End-to-end UserBound tests require either injecting a
    // GlobalConfig (whose `table` field is private) or a serial-
    // test HOME-redirect harness. For 6c scope, we test the
    // mechanism by mirroring from_global_config's nested-table
    // navigation against a parsed toml::Value below. If this path
    // ever needs a different navigation rule, a #[cfg(test)] raw-
    // table constructor on GlobalConfig would let us close the
    // duplication.

    /// UserBound's navigation of `sandbox.limits.*` is tested
    /// directly against a parsed `toml::Value` shape here. An
    /// end-to-end test that writes to a temp HOME is out of scope
    /// for 6c (would require serial-test infra); the mechanism
    /// tested here matches `from_global_config` line-for-line.
    #[test]
    fn user_bound_parses_nested_sandbox_limits_table() {
        let toml_body = r#"
            [sandbox.limits]
            RLIMIT_AS = 4294967296
            RLIMIT_NPROC = 512
            RLIMIT_NOFILE = 4096
            RLIMIT_CPU = 600
        "#;
        let parsed: toml::Value = toml::from_str(toml_body).unwrap();
        let sandbox = parsed.as_table().unwrap().get("sandbox").unwrap();
        let limits = sandbox
            .as_table()
            .unwrap()
            .get("limits")
            .unwrap()
            .as_table()
            .unwrap();

        // Replicate from_global_config's inner loop.
        let mut map = BTreeMap::new();
        for key in [
            RlimitKey::As,
            RlimitKey::Nproc,
            RlimitKey::Nofile,
            RlimitKey::Cpu,
        ] {
            if let Some(v) = limits.get(key.as_str()).and_then(extract_u64) {
                map.insert(key, v);
            }
        }
        let ub = UserBound {
            sandbox_limits_ceiling: map,
        };

        assert_eq!(
            ub.sandbox_limits_ceiling.get(&RlimitKey::As),
            Some(&4294967296)
        );
        assert_eq!(ub.sandbox_limits_ceiling.get(&RlimitKey::Nproc), Some(&512));
        assert_eq!(
            ub.sandbox_limits_ceiling.get(&RlimitKey::Nofile),
            Some(&4096)
        );
        assert_eq!(ub.sandbox_limits_ceiling.get(&RlimitKey::Cpu), Some(&600));
    }

    #[test]
    fn user_bound_extract_u64_accepts_integer_and_string() {
        let t_int = toml::Value::Integer(42);
        assert_eq!(extract_u64(&t_int), Some(42));
        let t_str = toml::Value::String("42".to_string());
        assert_eq!(extract_u64(&t_str), Some(42));
        // Negative integer: i64::try_into u64 fails → None.
        let t_neg = toml::Value::Integer(-1);
        assert_eq!(extract_u64(&t_neg), None);
        // Non-parseable string: None.
        let t_bad = toml::Value::String("abc".to_string());
        assert_eq!(extract_u64(&t_bad), None);
        // Wrong type (bool): None.
        let t_bool = toml::Value::Boolean(true);
        assert_eq!(extract_u64(&t_bool), None);
    }

    #[test]
    fn user_bound_default_is_empty_ceiling_map() {
        let ub = UserBound::default();
        assert!(ub.sandbox_limits_ceiling.is_empty());
        // Default UserBound → every rlimit request triggers
        // widening (the fail-closed rule).
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1)]);
        assert!(s.loosens_beyond(&ub));
    }

    // ── Phase 48 P0 sub-slice 6c — from_package_json parser ──

    fn pkg_json_fixture(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("package.json");
        std::fs::write(&path, body).unwrap();
        (tmp, path)
    }

    #[test]
    fn parse_missing_package_json_returns_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("package.json"); // does not exist
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert!(s.is_at_baseline());
    }

    #[test]
    fn parse_missing_lpm_scripts_block_returns_baseline() {
        let (_tmp, path) = pkg_json_fixture(r#"{"name":"x","version":"1.0.0"}"#);
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert!(s.is_at_baseline());
    }

    #[test]
    fn parse_pass_env_array() {
        let (_tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"passEnv":["FOO","BAR"]}}}"#);
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert_eq!(s.pass_env.len(), 2);
        assert!(s.pass_env.contains("FOO"));
        assert!(s.pass_env.contains("BAR"));
    }

    #[test]
    fn parse_pass_env_dedups_on_insert() {
        let (_tmp, path) =
            pkg_json_fixture(r#"{"lpm":{"scripts":{"passEnv":["FOO","FOO","FOO"]}}}"#);
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert_eq!(s.pass_env.len(), 1);
    }

    #[test]
    fn parse_read_project_full() {
        let (_tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"readProject":"full"}}}"#);
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert_eq!(s.read_project, ReadProjectMode::Full);
    }

    #[test]
    fn parse_read_project_narrow() {
        let (_tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"readProject":"narrow"}}}"#);
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert_eq!(s.read_project, ReadProjectMode::Narrow);
    }

    #[test]
    fn parse_read_project_unknown_variant_errors() {
        let (_tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"readProject":"open"}}}"#);
        match CapabilitySet::from_package_json(&path) {
            Err(CapabilityParseError::UnknownVariant { field, got, .. }) => {
                assert!(field.ends_with("readProject"));
                assert_eq!(got, "open");
            }
            other => panic!("expected UnknownVariant error, got {other:?}"),
        }
    }

    #[test]
    fn parse_sandbox_limits_full_set() {
        let (_tmp, path) = pkg_json_fixture(
            r#"{"lpm":{"scripts":{"sandboxLimits":{"RLIMIT_AS":1024,"RLIMIT_CPU":60}}}}"#,
        );
        let s = CapabilitySet::from_package_json(&path).unwrap();
        assert_eq!(s.sandbox_limits.get(&RlimitKey::As), Some(&1024));
        assert_eq!(s.sandbox_limits.get(&RlimitKey::Cpu), Some(&60));
    }

    #[test]
    fn parse_sandbox_limits_unknown_key_errors() {
        let (_tmp, path) =
            pkg_json_fixture(r#"{"lpm":{"scripts":{"sandboxLimits":{"RLIMIT_STACK":1024}}}}"#);
        match CapabilitySet::from_package_json(&path) {
            Err(CapabilityParseError::UnknownVariant { got, .. }) => {
                assert_eq!(got, "RLIMIT_STACK");
            }
            other => panic!("expected UnknownVariant error, got {other:?}"),
        }
    }

    #[test]
    fn parse_sandbox_limits_non_integer_errors() {
        let (_tmp, path) =
            pkg_json_fixture(r#"{"lpm":{"scripts":{"sandboxLimits":{"RLIMIT_AS":"lots"}}}}"#);
        match CapabilitySet::from_package_json(&path) {
            Err(CapabilityParseError::ShapeMismatch {
                field, expected, ..
            }) => {
                assert!(field.ends_with("sandboxLimits.RLIMIT_AS"));
                assert!(expected.contains("non-negative integer"));
            }
            other => panic!("expected ShapeMismatch error, got {other:?}"),
        }
    }

    #[test]
    fn parse_pass_env_wrong_shape_errors() {
        let (_tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"passEnv":"FOO"}}}"#);
        match CapabilitySet::from_package_json(&path) {
            Err(CapabilityParseError::ShapeMismatch { field, .. }) => {
                assert!(field.ends_with("passEnv"));
            }
            other => panic!("expected ShapeMismatch error, got {other:?}"),
        }
    }

    #[test]
    fn parse_malformed_json_surfaces_json_error() {
        let (_tmp, path) = pkg_json_fixture("{invalid");
        match CapabilitySet::from_package_json(&path) {
            Err(CapabilityParseError::Json { .. }) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn parse_full_capability_set_round_trips_to_hash() {
        // A realistic "package requests all three widenings" input
        // — parsed, hashed, and the hash matches a manually-built
        // CapabilitySet of the same shape.
        let (_tmp, path) = pkg_json_fixture(
            r#"{"lpm":{"scripts":{
                "passEnv":["SSH_AUTH_SOCK"],
                "readProject":"full",
                "sandboxLimits":{"RLIMIT_AS":8192,"RLIMIT_NPROC":4096}
            }}}"#,
        );
        let parsed = CapabilitySet::from_package_json(&path).unwrap();
        let manual = set_from(
            &["SSH_AUTH_SOCK"],
            ReadProjectMode::Full,
            &[(RlimitKey::As, 8192), (RlimitKey::Nproc, 4096)],
        );
        assert_eq!(parsed, manual);
        assert_eq!(parsed.canonical_hash(), manual.canonical_hash());
    }

    // ── Phase 48 P0 sub-slice 6d — delta_vs_user_bound ────────────

    #[test]
    fn delta_baseline_is_empty() {
        let s = CapabilitySet::default();
        let d = s.delta_vs_user_bound(&UserBound::default());
        assert!(d.is_empty());
        assert_eq!(d.render_human_readable(), "");
    }

    #[test]
    fn delta_non_widening_is_empty_even_when_not_at_baseline() {
        // Request has non-empty sandbox_limits but every entry is
        // ≤ user ceiling → no widening → empty delta. Mirrors the
        // loosens_beyond rule.
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 512)]);
        let bound = ub_with(&[(RlimitKey::Nproc, 4096)]);
        let d = s.delta_vs_user_bound(&bound);
        assert!(d.is_empty());
    }

    #[test]
    fn delta_pass_env_lists_requested_names() {
        let s = set_from(
            &["SSH_AUTH_SOCK", "NODE_AUTH_TOKEN"],
            ReadProjectMode::Narrow,
            &[],
        );
        let d = s.delta_vs_user_bound(&UserBound::default());
        assert_eq!(d.pass_env.len(), 2);
        assert!(d.pass_env.contains("SSH_AUTH_SOCK"));
        assert!(d.pass_env.contains("NODE_AUTH_TOKEN"));
        let rendered = d.render_human_readable();
        assert!(rendered.contains("env vars"));
        assert!(rendered.contains("SSH_AUTH_SOCK"));
        assert!(rendered.contains("NODE_AUTH_TOKEN"));
    }

    #[test]
    fn delta_full_read_project_surfaces_reads_line() {
        let s = set_from(&[], ReadProjectMode::Full, &[]);
        let d = s.delta_vs_user_bound(&UserBound::default());
        assert!(d.read_project_widened);
        let rendered = d.render_human_readable();
        assert!(rendered.contains("reads"));
        assert!(rendered.contains("full project tree"));
    }

    #[test]
    fn delta_sandbox_limits_shows_above_ceiling_entries_with_ceiling_phrase() {
        // User ceiling set, request exceeds it.
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 8192)]);
        let bound = ub_with(&[(RlimitKey::Nproc, 4096)]);
        let d = s.delta_vs_user_bound(&bound);
        assert_eq!(d.sandbox_limits_bumps.len(), 1);
        let detail = &d.sandbox_limits_bumps[&RlimitKey::Nproc];
        assert_eq!(detail.requested, 8192);
        assert_eq!(detail.current_ceiling, Some(4096));
        let rendered = d.render_human_readable();
        assert!(rendered.contains("RLIMIT_NPROC"));
        assert!(rendered.contains("8192"));
        assert!(rendered.contains("exceeds your ceiling of 4096"));
    }

    #[test]
    fn delta_sandbox_limits_shows_no_ceiling_phrase_when_user_unconfigured() {
        let s = set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::As, 1024)]);
        let d = s.delta_vs_user_bound(&UserBound::default());
        assert_eq!(d.sandbox_limits_bumps.len(), 1);
        let detail = &d.sandbox_limits_bumps[&RlimitKey::As];
        assert_eq!(detail.current_ceiling, None);
        let rendered = d.render_human_readable();
        assert!(rendered.contains("RLIMIT_AS"));
        assert!(rendered.contains("no user ceiling configured"));
    }

    #[test]
    fn delta_emptiness_matches_loosens_beyond_complement() {
        // Invariant: delta.is_empty() ⇔ !loosens_beyond(bound). Pin
        // from both directions via parameterized cases so a future
        // refactor that introduces asymmetry is caught.
        let cases = [
            (CapabilitySet::default(), UserBound::default(), true),
            (
                set_from(&["A"], ReadProjectMode::Narrow, &[]),
                UserBound::default(),
                false,
            ),
            (
                set_from(&[], ReadProjectMode::Full, &[]),
                UserBound::default(),
                false,
            ),
            (
                set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 512)]),
                ub_with(&[(RlimitKey::Nproc, 4096)]),
                true, // tighter than ceiling → no widening → delta empty
            ),
            (
                set_from(&[], ReadProjectMode::Narrow, &[(RlimitKey::Nproc, 8192)]),
                ub_with(&[(RlimitKey::Nproc, 4096)]),
                false,
            ),
        ];
        for (cs, ub, expected_empty) in cases {
            assert_eq!(cs.delta_vs_user_bound(&ub).is_empty(), expected_empty);
            assert_eq!(cs.loosens_beyond(&ub), !expected_empty);
        }
    }

    // ── Phase 48 P0 sub-slice 6d — round-trip: written hash == enforced hash ──
    //
    // The load-bearing invariant this slice ships: the hash
    // written by approve-scripts is byte-for-byte identical to
    // the hash evaluate_trust enforces against. This test pins
    // the invariant via the shared parsing path — any future
    // refactor that introduces a divergent normalization on
    // either side (or a second parser) must update this test to
    // prove the equivalence, which keeps the invariant visible.
    #[test]
    fn round_trip_hash_written_equals_hash_enforced() {
        // Simulate what approve-scripts does at write time.
        let (_tmp, path) = pkg_json_fixture(
            r#"{"lpm":{"scripts":{
                "passEnv":["SSH_AUTH_SOCK"],
                "readProject":"full",
                "sandboxLimits":{"RLIMIT_AS":8192,"RLIMIT_NPROC":4096}
            }}}"#,
        );
        let cs_at_approve = CapabilitySet::from_package_json(&path).unwrap();
        let persisted_hash = cs_at_approve.canonical_hash();

        // Simulate what evaluate_trust does at enforcement time:
        // re-parse the SAME package.json via the SAME helper.
        let cs_at_enforce = CapabilitySet::from_package_json(&path).unwrap();
        let enforcement_hash = cs_at_enforce.canonical_hash();

        assert_eq!(
            persisted_hash, enforcement_hash,
            "approve-time hash and enforce-time hash must be \
             byte-for-byte identical for the same package.json"
        );

        // And the binding produced by persisted_hash must satisfy
        // the enforce-time request via is_approved_by.
        let binding = lpm_workspace::TrustedDependencyBinding {
            capability_hash: Some(persisted_hash.clone()),
            ..Default::default()
        };
        assert!(
            cs_at_enforce.is_approved_by(&binding),
            "the round-tripped hash must satisfy is_approved_by"
        );
    }

    #[test]
    fn round_trip_hash_drifts_when_package_json_mutates() {
        // Approve against one package.json; package.json changes
        // between approve and enforce; hash differs; approval
        // does NOT satisfy the new request. Pins the "drift at
        // the manifest level invalidates the approval" rule from
        // 6b/6c through the 6d write path.
        let (tmp, path) = pkg_json_fixture(r#"{"lpm":{"scripts":{"passEnv":["FOO"]}}}"#);
        let cs_at_approve = CapabilitySet::from_package_json(&path).unwrap();
        let persisted_hash = cs_at_approve.canonical_hash();
        let binding = lpm_workspace::TrustedDependencyBinding {
            capability_hash: Some(persisted_hash),
            ..Default::default()
        };

        // Manifest changes between approve and enforce.
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"lpm":{"scripts":{"passEnv":["FOO","BAR"]}}}"#,
        )
        .unwrap();
        let cs_at_enforce = CapabilitySet::from_package_json(&path).unwrap();

        assert!(
            !cs_at_enforce.is_approved_by(&binding),
            "manifest drift between approve and enforce must \
             invalidate the approval — the stored hash was for \
             the old request shape"
        );
    }

    #[test]
    fn approval_with_none_hash_still_grants_baseline_request_post_6d() {
        // Legacy-preservation: an approval written without a
        // capability hash (either pre-6d or a 6d baseline
        // approval where loosens_beyond returned false) still
        // satisfies a baseline request at enforcement. Pins the
        // invariant that 6d's write path produces records
        // interchangeable with the pre-6d state for the baseline
        // path — no behavior change for projects that don't
        // widen.
        let baseline = CapabilitySet::default();
        let legacy_style_binding = lpm_workspace::TrustedDependencyBinding {
            capability_hash: None,
            ..Default::default()
        };
        assert!(baseline.is_approved_by(&legacy_style_binding));

        // And the widening-via-legacy rejection still holds.
        let widened = set_from(&["FOO"], ReadProjectMode::Narrow, &[]);
        assert!(!widened.is_approved_by(&legacy_style_binding));
    }
}
