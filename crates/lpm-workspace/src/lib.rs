//! Monorepo/workspace discovery and filtering for LPM.
//!
//! Detects workspace configurations from:
//! - `package.json` `"workspaces"` field (npm/yarn)
//! - `pnpm-workspace.yaml`
//!
//! Discovers member packages and reads their package.json for dependencies.
//!
//! Protocols: `workspace:*` (Phase 17), `catalog:` / `catalog:{name}` (Phase 20).
//! `--filter` and workspace-aware `run` implemented (Phase 13).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A discovered workspace root with its member packages.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// Path to the workspace root (where the root package.json lives).
    pub root: PathBuf,
    /// Root package.json data.
    pub root_package: PackageJson,
    /// Discovered member packages.
    pub members: Vec<WorkspaceMember>,
}

/// A single workspace member package.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Path to the member's directory.
    pub path: PathBuf,
    /// Parsed package.json.
    pub package: PackageJson,
}

/// Minimal package.json fields needed for dependency resolution.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageJson {
    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// npm overrides / yarn resolutions — force specific versions for transitive deps.
    #[serde(default)]
    pub overrides: HashMap<String, String>,

    /// Yarn-style resolutions (same purpose as overrides).
    #[serde(default)]
    pub resolutions: HashMap<String, String>,

    #[serde(default)]
    pub workspaces: Option<WorkspacesConfig>,

    /// LPM-specific config section (decided: config goes in package.json "lpm" key).
    #[serde(default)]
    pub lpm: Option<LpmConfig>,

    /// Engine version constraints (e.g., `{"node": ">=22.0.0"}`).
    #[serde(default)]
    pub engines: HashMap<String, String>,

    /// Scripts defined in package.json (e.g., "build": "tsup", "dev": "vite dev").
    #[serde(default)]
    pub scripts: HashMap<String, String>,

    /// Binary executables exposed by this package.
    #[serde(default)]
    pub bin: Option<BinConfig>,

    /// Centralized version catalogs for monorepos.
    /// Root defines versions, members use `"catalog:"` or `"catalog:{name}"`.
    ///
    /// Example:
    /// ```json
    /// {
    ///   "catalogs": {
    ///     "default": { "react": "^18.2.0", "react-dom": "^18.2.0" },
    ///     "testing": { "jest": "^29.0.0", "vitest": "^1.0.0" }
    ///   }
    /// }
    /// ```
    #[serde(default)]
    pub catalogs: HashMap<String, HashMap<String, String>>,
}

/// The `"bin"` field in package.json can be a string or an object.
///
/// - String form: `"bin": "./cli.js"` — name defaults to package name
/// - Object form: `"bin": { "my-cmd": "./cli.js", "other": "./other.js" }`
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BinConfig {
    /// Single binary: `"bin": "./cli.js"` — command name = package name.
    Single(String),
    /// Multiple binaries: `"bin": { "cmd": "./path.js" }`.
    Map(HashMap<String, String>),
}

impl BinConfig {
    /// Resolve bin entries into (command_name, script_path) pairs.
    /// For the `Single` variant, `package_name` is used as the command name.
    pub fn entries(&self, package_name: &str) -> Vec<(String, String)> {
        match self {
            BinConfig::Single(path) => {
                if path.is_empty() {
                    return Vec::new();
                }
                // Strip scope from package name for bin command name
                // e.g., "@scope/foo" → "foo"
                let cmd_name = package_name.rsplit('/').next().unwrap_or(package_name);
                vec![(cmd_name.to_string(), path.clone())]
            }
            BinConfig::Map(map) => map
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

/// Workspaces field can be an array of globs or an object with "packages" field.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum WorkspacesConfig {
    /// Simple array of glob patterns: `["packages/*", "apps/*"]`
    Globs(Vec<String>),
    /// Object form: `{ "packages": ["packages/*"] }`
    Object { packages: Vec<String> },
}

/// LPM-specific config in package.json `"lpm"` key.
#[derive(Debug, Clone, Deserialize)]
pub struct LpmConfig {
    /// Dependency isolation strictness: "strict", "warn", or "loose".
    #[serde(default, rename = "strictDeps")]
    pub strict_deps: Option<String>,

    /// node_modules linker mode: "symlink" or "hoisted".
    #[serde(default)]
    pub linker: Option<String>,

    /// Packages trusted to run lifecycle scripts (postinstall, etc).
    ///
    /// **Phase 32 Phase 4** schema migration: this field accepts BOTH the
    /// legacy `Vec<String>` form (`["esbuild", "sharp"]`) AND the new rich
    /// map form (`{"esbuild@0.25.1": {"integrity": "...", "scriptHash": "..."}}`).
    /// See [`TrustedDependencies`] for the discriminant rules and
    /// migration semantics.
    #[serde(default, rename = "trustedDependencies")]
    pub trusted_dependencies: TrustedDependencies,

    /// Minimum release age in seconds before install is allowed (default: 86400 = 24h).
    #[serde(default, rename = "minimumReleaseAge")]
    pub minimum_release_age: Option<u64>,

    /// **Phase 32 Phase 5** — LPM-native overrides location. Mirrors
    /// pnpm's `pnpm.overrides` and npm's top-level `overrides`, but
    /// declared inside the `"lpm"` section so package authors can
    /// keep all LPM-aware config grouped together.
    ///
    /// Map of selector → target version/range. Selectors support:
    /// - `"foo"` — every instance of `foo`
    /// - `"foo@<1.0.0"` — instances whose natural version satisfies the range
    /// - `"baz>foo"` / `"baz>foo@1"` — instances reached through `baz`
    ///
    /// On conflict with the top-level `overrides` / `resolutions`
    /// fields, `lpm.overrides` wins. Multi-segment paths
    /// (`a>b>c`) are rejected at parse time as a hard error — see
    /// [`lpm_resolver::OverrideError`] for the full validation rules.
    #[serde(default)]
    pub overrides: HashMap<String, String>,

    /// **Phase 32 Phase 6** — local-only patches applied to packages
    /// after install (the `patch-package` workflow). Map of selector →
    /// patch metadata.
    ///
    /// Selector format: `"<name>@<exact-version>"` (e.g.,
    /// `"lodash@4.17.21"`). Phase 6 accepts only exact-version pins;
    /// range selectors are reserved for Phase 6.1.
    ///
    /// The patch metadata records the path to the `.patch` file (under
    /// `patches/` next to this `package.json`) and the SRI integrity
    /// hash of the original store entry the patch was authored against.
    /// On every install, the patch engine verifies the store entry's
    /// `.integrity` matches `originalIntegrity` — any drift is a hard
    /// install error.
    ///
    /// See [`PatchedDependencyEntry`] for the on-disk shape.
    #[serde(default, rename = "patchedDependencies")]
    pub patched_dependencies: HashMap<String, PatchedDependencyEntry>,
}

/// `package.json :: lpm.patchedDependencies` map value.
///
/// **Phase 32 Phase 6.** Records the patch file path (relative to the
/// `package.json` directory) and the integrity binding to the store
/// baseline the patch was generated against.
///
/// On disk:
///
/// ```json
/// "lpm": {
///   "patchedDependencies": {
///     "lodash@4.17.21": {
///       "path": "patches/lodash@4.17.21.patch",
///       "originalIntegrity": "sha512-aBcDeFg=="
///     }
///   }
/// }
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PatchedDependencyEntry {
    /// Path to the `.patch` file, relative to the directory of the
    /// `package.json` that declares this entry. Always uses
    /// forward-slash separators on disk for cross-platform stability —
    /// the patch engine joins it with the project dir using
    /// [`std::path::Path::join`], which handles forward slashes on
    /// Windows correctly.
    pub path: String,

    /// SRI integrity hash (`sha512-<base64>`) of the store entry the
    /// patch was authored against. Read from `<store_dir>/.integrity`
    /// at `lpm patch-commit` time, recorded into `package.json`, and
    /// re-verified on every subsequent `lpm install`.
    ///
    /// If the store entry's `.integrity` no longer matches this value
    /// (e.g., the user re-installed lodash from a different upstream
    /// version), the patch engine refuses to apply and emits a hard
    /// install error naming the package and both fingerprints.
    #[serde(rename = "originalIntegrity")]
    pub original_integrity: String,
}

/// `package.json :: lpm.trustedDependencies` — accepts BOTH the legacy
/// `Vec<String>` form and the Phase 32 Phase 4 rich-map form.
///
/// ## Forms
///
/// **Legacy** (pre-Phase-4):
///
/// ```json
/// "trustedDependencies": ["esbuild", "sharp"]
/// ```
///
/// **Rich** (Phase 4+):
///
/// ```json
/// "trustedDependencies": {
///   "esbuild@0.25.1": {
///     "integrity": "sha512-...",
///     "scriptHash": "sha256-..."
///   }
/// }
/// ```
///
/// ## Migration semantics (read-permissive, write-strict)
///
/// - **Read:** both forms deserialize cleanly via `serde(untagged)`. Order
///   matters — the array form is tried first because it's strictly more
///   restrictive (an array can never be confused for a map).
/// - **Write:** Phase 4's `lpm approve-builds` command upgrades any Legacy
///   variant to Rich on the first new approval. The `lpm build` strict
///   gate accepts both forms; legacy bare-name entries match by name only
///   and produce a deprecation warning.
/// - **Coexistence:** a manifest stays in the Legacy form until the first
///   approval is made through `lpm approve-builds`, at which point it
///   migrates to the Rich form and stays there. There is no downgrade
///   path. Existing entries in a Legacy array are preserved during the
///   upgrade — they become Rich entries with `binding: None` (i.e., name
///   only, no integrity, no script hash).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TrustedDependencies {
    /// Pre-Phase-4 form: `["esbuild", "sharp"]`. Bare package names with
    /// no version, integrity, or script hash binding. Phase 4's strict
    /// gate accepts these as `LegacyNameOnly` matches with a deprecation
    /// warning.
    Legacy(Vec<String>),
    /// Phase 4+ form: `{"esbuild@0.25.1": {integrity, scriptHash}}`. The
    /// key is `name@version` (the Phase 4 trust binding key); the value
    /// is the integrity + scriptHash binding metadata.
    Rich(HashMap<String, TrustedDependencyBinding>),
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
/// Populated from the Sigstore bundle's leaf-cert SAN. P1 defined the
/// type's shape and the `Option<ProvenanceSnapshot>` field placements
/// on [`crate::TrustedDependencyBinding`] (added by P4) and
/// `BlockedPackage` (added by P1). P4 wires the actual fetch + parse
/// in the CLI.
///
/// **Schema-crate placement (P4 relocation):** this type lives in
/// `lpm-workspace` because it's pure schema consumed by two other
/// schema types in this crate (`TrustedDependencyBinding`) and in
/// `lpm-cli/src/build_state.rs` (`BlockedPackage`). Putting it here
/// avoids a dependency cycle — `lpm-security` already depends on
/// `lpm-workspace`, so `TrustedDependencyBinding.provenance_at_approval`
/// could not reference a `ProvenanceSnapshot` owned by `lpm-security`
/// without cycling.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ProvenanceSnapshot {
    /// `true` iff the registry returned a non-empty attestations
    /// bundle for this version. `false` indicates "registry has no
    /// provenance for this version" — which is the exact axios-case
    /// signal when compared against a prior-approved version that had
    /// provenance.
    pub present: bool,
    /// Publisher identity extracted from the Sigstore cert SAN —
    /// `github:<org>/<repo>`. Stable across releases from the same
    /// repo. **Part of the drift-check identity tuple** (see
    /// `lpm_security::provenance::check_provenance_drift`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Workflow file path: `.github/workflows/<filename>`. Stable
    /// across releases from the same workflow. **Part of the
    /// drift-check identity tuple.** Split from the full SAN URI so
    /// the per-release ref (which IS captured in [`workflow_ref`])
    /// does not falsely trigger identity drift between legitimate
    /// releases.
    ///
    /// [`workflow_ref`]: ProvenanceSnapshot::workflow_ref
    #[serde(
        default,
        rename = "workflowPath",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_path: Option<String>,
    /// Git ref the workflow ran against: `refs/tags/<tag>`,
    /// `refs/heads/<branch>`, or `refs/pull/<n>/merge`. **Varies per
    /// release** — excluded from the identity tuple. Retained for
    /// audit / UX: the drift-gate renders it in the "last approved
    /// via X at REF" line so reviewers can see which specific
    /// release produced the approved reference.
    ///
    /// **Why this is NOT part of identity equality:** axios v1.14.0
    /// and v1.14.1 from the same repo + workflow carry the same
    /// publisher and workflow_path but necessarily different refs.
    /// Comparing refs would falsely mark every patch bump as
    /// "identity changed" — the exact "reviewer finding: drift
    /// comparator flags normal provenance-preserving releases" bug
    /// this field split prevents.
    #[serde(
        default,
        rename = "workflowRef",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_ref: Option<String>,
    /// SHA-256 of the leaf attestation certificate (DER-encoded).
    /// **Ephemeral** — Fulcio issues a fresh leaf per signing, so
    /// the cert SHA rotates every release. **Excluded from identity
    /// equality** for the same reason as `workflow_ref`; retained
    /// for audit (the approved reference's cert SHA is surfaced in
    /// verbose drift diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_cert_sha256: Option<String>,
}

/// Binding metadata for one entry in a Rich `trustedDependencies` map.
///
/// Both fields are `Option<String>` because:
/// - `integrity` may be unknown if the package was approved before Phase 4
///   schema awareness reached the resolver path (legacy upgrade case)
/// - `script_hash` may be unknown for the same reason
///
/// In the post-Phase-4 happy path, both fields are populated by the
/// `lpm approve-builds` command from the install-time blocked-set captured
/// in `<project_dir>/.lpm/build-state.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedDependencyBinding {
    /// SRI integrity hash from the lockfile (e.g., `"sha512-..."`).
    /// Mirrors `LockedPackage::integrity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    /// Deterministic script hash computed by
    /// `lpm_security::script_hash::compute_script_hash`. Format: `"sha256-<hex>"`.
    #[serde(
        default,
        rename = "scriptHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub script_hash: Option<String>,
    /// **Phase 46 P4 §6.2 field ownership.** Snapshot of the publisher
    /// identity tuple captured at the moment this binding was
    /// approved. Used by the install-time drift check (§7.2) to detect
    /// publisher-identity drift between the approved version and a
    /// candidate version of the same package.
    ///
    /// `None` means the binding pre-dates provenance capture (legacy
    /// upgrade path) OR the approved version had no provenance
    /// attestation in the first place. Both cases degrade to "cannot
    /// detect drift" — the other three §7.2 branches still fire on
    /// their own (cooldown, script hash, integrity).
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]` keeps
    /// pre-P4 `trustedDependencies` entries round-tripping unchanged.
    #[serde(
        default,
        rename = "provenanceAtApproval",
        skip_serializing_if = "Option::is_none"
    )]
    pub provenance_at_approval: Option<ProvenanceSnapshot>,
}

impl Default for TrustedDependencies {
    fn default() -> Self {
        // Default to the LEGACY form so a missing field deserializes
        // identically to the pre-Phase-4 default. This matters for
        // existing manifests with no `trustedDependencies` key at all
        // — they keep round-tripping as `Vec::new()` and never accidentally
        // get migrated to the Rich form on a no-op read.
        TrustedDependencies::Legacy(Vec::new())
    }
}

/// The result of looking up a package in `trustedDependencies`.
/// Phase 4 strict-gate query type — see [`TrustedDependencies::matches_strict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMatch {
    /// Rich entry with all four fields equal to the queried values.
    /// `lpm build` runs the script.
    Strict,
    /// Name appears in a Legacy `Vec<String>` entry. `lpm build` runs the
    /// script with a deprecation warning suggesting `lpm approve-builds` to
    /// upgrade to a strict binding.
    LegacyNameOnly,
    /// Rich entry exists for this `name@version` but at least one of
    /// `integrity` / `script_hash` differs from the queried values.
    /// `lpm build` SKIPS the script and surfaces the drift to the user.
    BindingDrift {
        /// The binding currently stored in `package.json` (so callers can
        /// show a diff).
        stored: TrustedDependencyBinding,
    },
    /// No matching entry in either form.
    NotTrusted,
}

impl TrustedDependencies {
    /// Trust-store key format used by the Rich variant: `"name@version"`.
    /// Centralized so any new code path produces the same key without
    /// re-implementing the format.
    pub fn rich_key(name: &str, version: &str) -> String {
        format!("{name}@{version}")
    }

    /// Strict trust query — the Phase 4 default gate.
    ///
    /// Returns:
    /// - [`TrustMatch::Strict`] if the Rich variant has a `name@version`
    ///   entry whose stored `integrity` and `script_hash` BOTH equal the
    ///   queried values. `None` integrity/script_hash on either side
    ///   counts as "no constraint" (matches anything) for that field —
    ///   this is intentional for the legacy-upgrade path where a Rich
    ///   entry was inserted before the binding fields were known.
    /// - [`TrustMatch::BindingDrift`] if a Rich entry exists for the
    ///   `name@version` key but at least one binding field is set on
    ///   BOTH sides and they differ.
    /// - [`TrustMatch::LegacyNameOnly`] if the Legacy variant contains
    ///   the bare `name` string, OR if the Rich variant contains a
    ///   `<name>@*` preserve key (the migration sentinel from
    ///   [`Self::upgrade_to_rich`]). Caller should warn about deprecation.
    /// - [`TrustMatch::NotTrusted`] otherwise.
    ///
    /// **Phase 4 audit fix (D-impl-1, 2026-04-11):** the `<name>@*`
    /// preserve key path was missing pre-fix. Without it, a manifest like
    /// `["esbuild"]` would lose esbuild's approval on the first
    /// `lpm approve-builds --yes` upgrade because the upgrade rewrote it
    /// to `esbuild@*` and `matches_strict` only matched concrete keys.
    /// The audit reproduced the regression end-to-end. The fix preserves
    /// the legacy semantic AND keeps the deprecation signal.
    ///
    /// **Lookup precedence:** the concrete `name@version` key is preferred
    /// over the `name@*` preserve key when both exist for the same name.
    /// This protects the case where a user explicitly approved
    /// `esbuild@0.25.1` AND there's a leftover legacy `esbuild@*` — the
    /// strict binding wins (and produces drift correctly if it diverges).
    pub fn matches_strict(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustMatch {
        match self {
            TrustedDependencies::Legacy(names) => {
                if names.iter().any(|n| n == name) {
                    TrustMatch::LegacyNameOnly
                } else {
                    TrustMatch::NotTrusted
                }
            }
            TrustedDependencies::Rich(map) => {
                // Step 1: try the concrete `name@version` key first.
                let concrete_key = Self::rich_key(name, version);
                if let Some(stored) = map.get(&concrete_key) {
                    // Field-by-field check. A None field on either side is
                    // a wildcard — only mismatches between two SET values
                    // count as drift. Legacy-upgrade-friendly contract.
                    let integrity_drift = matches!(
                        (stored.integrity.as_deref(), integrity),
                        (Some(s), Some(q)) if s != q
                    );
                    let script_hash_drift = matches!(
                        (stored.script_hash.as_deref(), script_hash),
                        (Some(s), Some(q)) if s != q
                    );

                    if integrity_drift || script_hash_drift {
                        return TrustMatch::BindingDrift {
                            stored: stored.clone(),
                        };
                    }
                    return TrustMatch::Strict;
                }

                // Step 2 (Phase 4 D-impl-1 audit fix): fall back to the
                // `<name>@*` preserve key if no concrete entry was found.
                // This is the legacy-upgrade migration path. The bindings
                // on these entries are intentionally None — they encode
                // "trust this name only" without integrity/script_hash
                // constraints, so they MUST NOT be checked for drift.
                let star_key = format!("{name}@*");
                if map.contains_key(&star_key) {
                    return TrustMatch::LegacyNameOnly;
                }

                TrustMatch::NotTrusted
            }
        }
    }

    /// Lenient name-only check. Used by the existing `lpm build` code
    /// path before M5 swaps to `matches_strict`, and by post-M5 logic that
    /// just wants to know "does this name appear at all?" (e.g., the
    /// stale-trustedDependencies warning).
    pub fn contains_name_lenient(&self, name: &str) -> bool {
        match self {
            TrustedDependencies::Legacy(names) => names.iter().any(|n| n == name),
            TrustedDependencies::Rich(map) => map.keys().any(|k| {
                // Match the part before `@version`, handling scoped
                // packages (`@scope/name@version`) by finding the LAST `@`.
                k.rfind('@')
                    .map(|at| &k[..at] == name)
                    .unwrap_or_else(|| k == name)
            }),
        }
    }

    /// Iterate over (name, optional binding). Legacy entries yield `None`
    /// for the binding. Used by introspection paths like
    /// `lpm approve-builds --list`.
    pub fn iter(
        &self,
    ) -> Box<dyn Iterator<Item = (String, Option<&TrustedDependencyBinding>)> + '_> {
        match self {
            TrustedDependencies::Legacy(names) => Box::new(names.iter().map(|n| (n.clone(), None))),
            TrustedDependencies::Rich(map) => Box::new(map.iter().map(|(k, v)| {
                // For Rich entries, the user-facing "name" is the part
                // BEFORE the `@version` so callers can group by package.
                let name = k
                    .rfind('@')
                    .map(|at| k[..at].to_string())
                    .unwrap_or_else(|| k.clone());
                (name, Some(v))
            })),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        match self {
            TrustedDependencies::Legacy(names) => names.len(),
            TrustedDependencies::Rich(map) => map.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert any Legacy variant into a Rich variant. Idempotent on Rich.
    /// Used by `lpm approve-builds` BEFORE inserting any new approval so
    /// that the manifest write path is uniform.
    ///
    /// Existing legacy entries are preserved as Rich entries with no
    /// version pin (key = `<name>@*`) and no binding metadata. The next
    /// install will continue to honor them via `LegacyNameOnly` because
    /// `contains_name_lenient` walks the keys correctly. New approvals
    /// inserted after the upgrade get full `name@version` keys with
    /// integrity + script_hash bindings.
    pub fn upgrade_to_rich(&mut self) {
        if matches!(self, TrustedDependencies::Rich(_)) {
            return;
        }
        let TrustedDependencies::Legacy(names) = self else {
            unreachable!("matched Rich above")
        };
        let mut map = HashMap::new();
        for name in names.drain(..) {
            // Use `<name>@*` as the legacy-preserve key. The `*` is a
            // sentinel — `matches_strict` won't match it (because the
            // queried version is always concrete) but `contains_name_lenient`
            // walks the keys and strips the `@*` correctly.
            let key = format!("{name}@*");
            map.insert(
                key,
                TrustedDependencyBinding {
                    integrity: None,
                    script_hash: None,
                    provenance_at_approval: None,
                },
            );
        }
        *self = TrustedDependencies::Rich(map);
    }

    /// Insert a new approval entry, upgrading the variant to Rich if
    /// needed. The key is `name@version`; an existing entry for the same
    /// key is OVERWRITTEN (the new binding wins). Returns whether the
    /// previous entry existed.
    ///
    /// Provenance-agnostic variant — persists
    /// `provenance_at_approval: None`. Production callers (the
    /// `lpm approve-builds` flow) use
    /// [`Self::approve_with_provenance`] so the drift-check reference
    /// is populated from the install-time capture.
    pub fn approve(
        &mut self,
        name: &str,
        version: &str,
        integrity: Option<String>,
        script_hash: Option<String>,
    ) -> bool {
        self.approve_with_provenance(name, version, integrity, script_hash, None)
    }

    /// **Phase 46 P4 §6.2 write-path.** Insert / overwrite an approval
    /// entry with an explicit provenance snapshot captured at install
    /// time. Equivalent to [`Self::approve`] but carries the
    /// `provenance_at_approval` field through to the binding.
    ///
    /// The caller — `lpm approve-builds` — reads the snapshot from
    /// the install-time `BlockedPackage::provenance_at_capture` (which
    /// was populated from `lpm-cli`'s provenance fetcher). This
    /// closes the P4 round-trip: install-time snapshot → BlockedPackage
    /// → binding → next install's drift check.
    ///
    /// Passing `provenance_at_approval: None` is identical to
    /// [`Self::approve`] (legacy / degraded-fetch paths).
    pub fn approve_with_provenance(
        &mut self,
        name: &str,
        version: &str,
        integrity: Option<String>,
        script_hash: Option<String>,
        provenance_at_approval: Option<ProvenanceSnapshot>,
    ) -> bool {
        self.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = self else {
            unreachable!("upgrade_to_rich left us in Rich state")
        };
        let key = Self::rich_key(name, version);
        map.insert(
            key,
            TrustedDependencyBinding {
                integrity,
                script_hash,
                provenance_at_approval,
            },
        )
        .is_some()
    }

    /// **Phase 46 P4 Chunk 3.** Find the provenance-bearing approval
    /// entry for this package name whose version sorts highest, and
    /// return `(version, binding)` as the reference point for the
    /// install-time drift check.
    ///
    /// The drift gate prefers provenance-bearing approvals over
    /// provenance-less ones: if a user has `axios@1.14.0` approved
    /// WITH provenance AND `axios@1.13.5` approved WITHOUT provenance,
    /// comparing `axios@1.14.1` against the 1.13.5 binding
    /// (`provenance_at_approval = None`) would short-circuit to
    /// `NoDrift` and mask the axios signal. Filtering to
    /// provenance-bearing entries only is the safer default.
    ///
    /// The returned version string is the part after the LAST `@`
    /// in the rich-map key, so scoped names like `@scope/pkg@1.0.0`
    /// correctly split into `@scope/pkg` + `1.0.0`. Used by the
    /// drift gate's §7.3 UX to render "last approved: v<VERSION>".
    ///
    /// ## Determinism (reviewer finding — Finding 2)
    ///
    /// `TrustedDependencies::Rich` wraps a [`HashMap`], whose
    /// iteration order is non-deterministic per `HashMap`'s
    /// contract. The original Chunk 3 implementation picked "the
    /// first match from `map.iter()`" which meant:
    /// - the UX line "last approved: v<VERSION>" could show a
    ///   different version across runs of the same install;
    /// - when multiple provenance-bearing approvals for the same
    ///   package carry **different** identities (legitimate
    ///   publisher migration, or prior attack + cleanup), the drift
    ///   verdict itself could flip across runs.
    ///
    /// Fixed here by selecting the entry with the lexicographically-
    /// maximum version string. That's deterministic and a decent
    /// proxy for "latest" in the common case of consistent-digit-
    /// width version components; it IS wrong for e.g. `1.10.0` vs
    /// `1.9.0` (lex picks `1.9.0` as max). A future phase can
    /// tighten to proper semver ordering — that's a scope decision,
    /// not a soundness one; what matters here is **determinism
    /// first**. The lex-max choice is documented so the follow-up
    /// phase knows exactly what semantics it's replacing.
    pub fn provenance_reference_for_name(
        &self,
        name: &str,
    ) -> Option<(&str, &TrustedDependencyBinding)> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        map.iter()
            .filter_map(|(key, binding)| {
                let (n, v) = key.rsplit_once('@')?;
                if n == name && binding.provenance_at_approval.is_some() {
                    Some((v, binding))
                } else {
                    None
                }
            })
            .max_by(|(v1, _), (v2, _)| v1.cmp(v2))
    }

    /// Remove an approval entry by exact `name@version` key. Returns
    /// `true` if the entry existed and was removed.
    ///
    /// Does NOT touch Legacy entries — revoking from a Legacy `Vec<String>`
    /// is a separate concern that callers should handle by upgrading
    /// first if they want strict semantics.
    pub fn revoke(&mut self, name: &str, version: &str) -> bool {
        match self {
            TrustedDependencies::Legacy(_) => false,
            TrustedDependencies::Rich(map) => {
                let key = Self::rich_key(name, version);
                map.remove(&key).is_some()
            }
        }
    }
}

/// Discover the workspace from a starting directory.
///
/// Walks up from `start_dir` looking for a root package.json with workspaces,
/// or a pnpm-workspace.yaml.
///
/// Returns `None` if no workspace root is found (single-package project).
pub fn discover_workspace(start_dir: &Path) -> Result<Option<Workspace>, WorkspaceError> {
    let original_start = start_dir.to_path_buf();
    let mut current = start_dir.to_path_buf();

    loop {
        let pkg_json_path = current.join("package.json");
        if pkg_json_path.exists() {
            let root_package = read_package_json(&pkg_json_path)?;

            // Check for workspace globs in package.json
            let workspace_globs = match &root_package.workspaces {
                Some(WorkspacesConfig::Globs(globs)) => Some(globs.clone()),
                Some(WorkspacesConfig::Object { packages }) => Some(packages.clone()),
                None => None,
            };

            // Also check for pnpm-workspace.yaml
            let pnpm_workspace_path = current.join("pnpm-workspace.yaml");
            let pnpm_globs = if pnpm_workspace_path.exists() {
                read_pnpm_workspace(&pnpm_workspace_path)?
            } else {
                None
            };

            let globs = workspace_globs.or(pnpm_globs);

            if let Some(globs) = globs {
                let members = discover_members(&current, &globs)?;
                let workspace = Workspace {
                    root: current.clone(),
                    root_package,
                    members,
                };

                let start_is_root = original_start == workspace.root;
                let start_within_root = original_start.starts_with(&workspace.root);
                let start_is_member = workspace
                    .members
                    .iter()
                    .any(|member| original_start.starts_with(&member.path));
                let has_nested_non_member_package = start_within_root
                    && has_intermediate_non_member_package_json(
                        &original_start,
                        &workspace.root,
                        &workspace.members,
                    );

                if start_is_root
                    || start_is_member
                    || (start_within_root && !has_nested_non_member_package)
                {
                    return Ok(Some(workspace));
                }
            }
        }

        // Walk up to parent
        if !current.pop() {
            break;
        }
    }

    Ok(None)
}

/// Read and parse a package.json file.
pub fn read_package_json(path: &Path) -> Result<PackageJson, WorkspaceError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| WorkspaceError::Io(format!("failed to read {}: {e}", path.display())))?;

    serde_json::from_str(&content)
        .map_err(|e| WorkspaceError::Parse(format!("failed to parse {}: {e}", path.display())))
}

/// Read pnpm-workspace.yaml and extract package globs.
fn read_pnpm_workspace(path: &Path) -> Result<Option<Vec<String>>, WorkspaceError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| WorkspaceError::Io(format!("failed to read {}: {e}", path.display())))?;

    // pnpm-workspace.yaml is simple enough to parse with basic string matching
    // rather than pulling in a full YAML parser.
    // Format: packages:\n  - "glob1"\n  - "glob2"
    let mut packages = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if in_packages {
            if let Some(rest) = trimmed.strip_prefix("- ") {
                let glob = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !glob.is_empty() {
                    packages.push(glob);
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                // New top-level key, stop parsing packages
                break;
            }
        }
    }

    if packages.is_empty() {
        Ok(None)
    } else {
        Ok(Some(packages))
    }
}

/// Discover workspace member packages matching the given glob patterns.
fn discover_members(root: &Path, globs: &[String]) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let mut members = Vec::new();

    for pattern in globs {
        // Resolve glob pattern relative to workspace root
        let full_pattern = root.join(pattern).join("package.json");
        let pattern_str = full_pattern.to_string_lossy().to_string();

        let paths = glob::glob(&pattern_str)
            .map_err(|e| WorkspaceError::Parse(format!("invalid glob pattern '{pattern}': {e}")))?;

        for entry in paths {
            let pkg_json_path =
                entry.map_err(|e| WorkspaceError::Io(format!("glob error: {e}")))?;

            let member_dir = pkg_json_path.parent().unwrap().to_path_buf();
            let package = read_package_json(&pkg_json_path)?;

            members.push(WorkspaceMember {
                path: member_dir,
                package,
            });
        }
    }

    // Sort by path for deterministic ordering
    members.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(members)
}

fn has_intermediate_non_member_package_json(
    start: &Path,
    root: &Path,
    members: &[WorkspaceMember],
) -> bool {
    let mut current = Some(start);

    while let Some(dir) = current {
        if dir == root {
            return false;
        }

        if dir.join("package.json").exists() && !members.iter().any(|member| member.path == dir) {
            return true;
        }

        current = dir.parent();
    }

    false
}

/// Collect all production dependencies across the workspace.
///
/// Merges root + member dependencies. For overlapping deps, the root's
/// version range takes precedence.
pub fn collect_all_dependencies(workspace: &Workspace) -> HashMap<String, String> {
    let mut all_deps: HashMap<String, String> = HashMap::new();

    // Members first (root overrides)
    for member in &workspace.members {
        for (name, range) in &member.package.dependencies {
            all_deps.insert(name.clone(), range.clone());
        }
    }

    // Root overrides members
    for (name, range) in &workspace.root_package.dependencies {
        all_deps.insert(name.clone(), range.clone());
    }

    all_deps
}

/// Resolve `workspace:*`, `workspace:^`, `workspace:~` protocol in dependencies.
///
/// Replaces workspace protocol references with actual versions from workspace members.
/// Must be called before passing dependencies to the resolver.
///
/// # Supported workspace protocols
/// - `"workspace:*"` → exact version from member's package.json (e.g., `"1.2.3"`)
/// - `"workspace:^"` → caret range (e.g., `"^1.2.3"`)
/// - `"workspace:~"` → tilde range (e.g., `"~1.2.3"`)
/// - `"workspace:<range>"` → passthrough as-is (e.g., `"workspace:>=1.0.0"` → `">=1.0.0"`)
///   This matches pnpm's behavior where any valid semver range after `workspace:` is kept.
///
/// Returns a list of (package_name, original_protocol, resolved_version) for logging.
/// Returns an error if a `workspace:` dependency references a package that is not a workspace member.
pub fn resolve_workspace_protocol(
    deps: &mut HashMap<String, String>,
    workspace: &Workspace,
) -> Result<Vec<(String, String, String)>, String> {
    let mut resolved = Vec::new();

    // Build member name → version mapping
    let member_versions: HashMap<&str, &str> = workspace
        .members
        .iter()
        .filter_map(|m| {
            let name = m.package.name.as_deref()?;
            let version = m.package.version.as_deref().unwrap_or("0.0.0");
            Some((name, version))
        })
        .collect();

    for (name, range) in deps.iter_mut() {
        if !range.starts_with("workspace:") {
            continue;
        }

        let protocol = &range["workspace:".len()..];

        if let Some(&member_version) = member_versions.get(name.as_str()) {
            let original = range.clone();
            *range = match protocol {
                "*" | "" => member_version.to_string(),
                "^" => format!("^{member_version}"),
                "~" => format!("~{member_version}"),
                // workspace:>=1.0.0 → passthrough as-is (matches pnpm behavior)
                exact => exact.to_string(),
            };
            resolved.push((name.clone(), original, range.clone()));
        } else {
            let mut available: Vec<&str> = member_versions.keys().copied().collect();
            available.sort();
            let available_str = if available.is_empty() {
                "(none)".to_string()
            } else {
                available.join(", ")
            };
            return Err(format!(
                "workspace:{protocol} references package '{name}' which is not a workspace member. \
				 Available members: {available_str}"
            ));
        }
    }

    Ok(resolved)
}

/// Resolve `catalog:` and `catalog:{name}` protocol references in dependencies.
///
/// - `"catalog:"` resolves from `catalogs["default"]`
/// - `"catalog:testing"` resolves from `catalogs["testing"]`
///
/// Must be called before passing dependencies to the resolver.
///
/// Returns a list of `(package_name, original_protocol, resolved_version)` for logging.
pub fn resolve_catalog_protocol(
    deps: &mut HashMap<String, String>,
    catalogs: &HashMap<String, HashMap<String, String>>,
) -> Result<Vec<(String, String, String)>, String> {
    let mut resolved = Vec::new();

    for (name, range) in deps.iter_mut() {
        if !range.starts_with("catalog:") {
            continue;
        }

        let catalog_ref = &range["catalog:".len()..];
        let catalog_name = if catalog_ref.is_empty() {
            "default"
        } else {
            catalog_ref
        };

        let catalog = catalogs.get(catalog_name).ok_or_else(|| {
            let available = if catalogs.is_empty() {
                "(none)".to_string()
            } else {
                let mut keys: Vec<&str> = catalogs.keys().map(|s| s.as_str()).collect();
                keys.sort();
                keys.join(", ")
            };
            format!(
                "catalog '{}' not found for dependency '{}'. Available catalogs: {}",
                catalog_name, name, available
            )
        })?;

        let version = catalog.get(name.as_str()).ok_or_else(|| {
            let available = if catalog.is_empty() {
                "(none)".to_string()
            } else {
                let mut keys: Vec<&str> = catalog.keys().map(|s| s.as_str()).collect();
                keys.sort();
                keys.join(", ")
            };
            format!(
                "dependency '{}' not found in catalog '{}'. Available: {}",
                name, catalog_name, available
            )
        })?;

        let original = range.clone();
        *range = version.clone();
        resolved.push((name.clone(), original, range.clone()));
    }

    Ok(resolved)
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn read_simple_package_json() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "@lpm.dev/neo.highlight": "^1.0.0",
                    "react": "^19.0.0"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        assert_eq!(pkg.name.as_deref(), Some("my-app"));
        assert_eq!(pkg.dependencies.len(), 2);
        assert_eq!(pkg.dependencies.get("react").unwrap(), "^19.0.0");
    }

    #[test]
    fn read_package_json_with_lpm_config() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "lpm": {
                    "strictDeps": "strict",
                    "linker": "symlink"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.strict_deps.as_deref(), Some("strict"));
        assert_eq!(lpm.linker.as_deref(), Some("symlink"));
    }

    /// **Phase 32 Phase 5** — `lpm.overrides` field deserializes as a
    /// `HashMap<String, String>`. The downstream parser
    /// (`lpm_resolver::OverrideSet::parse`) does the validation.
    #[test]
    fn read_package_json_with_lpm_overrides() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "lpm": {
                    "overrides": {
                        "foo": "^2.0.0",
                        "bar@<1.0.0": "1.0.0",
                        "baz>qar@1": "2.0.0"
                    }
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.overrides.len(), 3);
        assert_eq!(lpm.overrides.get("foo").unwrap(), "^2.0.0");
        assert_eq!(lpm.overrides.get("bar@<1.0.0").unwrap(), "1.0.0");
        assert_eq!(lpm.overrides.get("baz>qar@1").unwrap(), "2.0.0");
    }

    /// **Phase 32 Phase 5** — `lpm.overrides` defaults to an empty
    /// map when absent. Round-trips to a default `LpmConfig` correctly.
    #[test]
    fn read_package_json_with_lpm_no_overrides() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "lpm": {
                    "strictDeps": "strict"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert!(lpm.overrides.is_empty());
    }

    #[test]
    fn discover_no_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name": "single-package", "dependencies": {}}"#,
        );

        let result = discover_workspace(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn discover_npm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        // Create a member package
        let member_dir = dir.path().join("packages/my-lib");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "@lpm.dev/test.my-lib", "dependencies": {"react": "^19.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(
            ws.members[0].package.name.as_deref(),
            Some("@lpm.dev/test.my-lib")
        );
    }

    #[test]
    fn discover_workspace_object_form() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": { "packages": ["apps/*"] }
            }"#,
        );

        let app_dir = dir.path().join("apps/web");
        fs::create_dir_all(&app_dir).unwrap();
        create_package_json(&app_dir, r#"{"name": "web"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn discover_pnpm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name": "monorepo"}"#);

        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n",
        )
        .unwrap();

        let member_dir = dir.path().join("packages/utils");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "utils"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn discover_workspace_from_member_directory_walks_past_member_package_json() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        let nested_dir = member_dir.join("src/components");
        fs::create_dir_all(&nested_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let ws = discover_workspace(&nested_dir)
            .unwrap()
            .expect("expected workspace root discovery from member subdirectory");

        assert_eq!(ws.root, dir.path());
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("app"));
    }

    #[test]
    fn discover_workspace_does_not_attach_unlisted_nested_package_to_outer_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let unrelated_dir = dir.path().join("tools/local-project");
        fs::create_dir_all(&unrelated_dir).unwrap();
        create_package_json(&unrelated_dir, r#"{"name": "local-project"}"#);

        let result = discover_workspace(&unrelated_dir).unwrap();
        assert!(
            result.is_none(),
            "nested package not matched by workspace globs should not attach to outer workspace"
        );
    }

    #[test]
    fn discover_workspace_from_non_member_subdirectory_under_root_returns_root() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let tooling_dir = dir.path().join("tools/scripts");
        fs::create_dir_all(&tooling_dir).unwrap();

        let ws = discover_workspace(&tooling_dir)
            .unwrap()
            .expect("workspace root should still be discoverable from non-member subdirectories");

        assert_eq!(ws.root, dir.path());
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("app"));
    }

    #[test]
    fn collect_all_deps_merges() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "dependencies": {"shared": "^2.0.0"}
            }"#,
        );

        let member_dir = dir.path().join("packages/a");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "a", "dependencies": {"shared": "^1.0.0", "only-a": "^1.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        let all = collect_all_dependencies(&ws);

        // Root's version wins for "shared"
        assert_eq!(all.get("shared").unwrap(), "^2.0.0");
        // Member-only dep is included
        assert!(all.contains_key("only-a"));
    }
}

#[cfg(test)]
mod workspace_protocol_tests {
    use super::*;

    fn make_workspace(members: Vec<(&str, &str)>) -> Workspace {
        let root = std::path::PathBuf::from("/test");
        let root_package = PackageJson {
            name: Some("root".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let members = members
            .into_iter()
            .map(|(name, version)| WorkspaceMember {
                path: root.join(format!("packages/{name}")),
                package: PackageJson {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    ..Default::default()
                },
            })
            .collect();
        Workspace {
            root,
            root_package,
            members,
        }
    }

    #[test]
    fn workspace_star_resolves_to_exact() {
        let ws = make_workspace(vec![("@scope/ui", "2.3.1")]);
        let mut deps = HashMap::from([("@scope/ui".to_string(), "workspace:*".to_string())]);
        let resolved = resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["@scope/ui"], "2.3.1");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn workspace_caret() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:^".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "^1.0.0");
    }

    #[test]
    fn workspace_tilde() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:~".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "~1.0.0");
    }

    #[test]
    fn workspace_missing_member_errors() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("missing".to_string(), "workspace:*".to_string())]);
        let err = resolve_workspace_protocol(&mut deps, &ws).unwrap_err();
        assert!(
            err.contains("not a workspace member"),
            "expected 'not a workspace member' in error, got: {err}"
        );
        assert!(
            err.contains("utils"),
            "expected available member 'utils' in error, got: {err}"
        );
    }

    #[test]
    fn non_workspace_deps_unchanged() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("utils".to_string(), "workspace:*".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["utils"], "1.0.0"); // resolved
    }

    #[test]
    fn multiple_members() {
        let ws = make_workspace(vec![("@scope/ui", "2.0.0"), ("@scope/utils", "1.5.0")]);
        let mut deps = HashMap::from([
            ("@scope/ui".to_string(), "workspace:^".to_string()),
            ("@scope/utils".to_string(), "workspace:~".to_string()),
        ]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["@scope/ui"], "^2.0.0");
        assert_eq!(deps["@scope/utils"], "~1.5.0");
    }

    #[test]
    fn workspace_empty_protocol_resolves_to_exact() {
        let ws = make_workspace(vec![("utils", "3.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "3.0.0");
    }

    #[test]
    fn workspace_explicit_version() {
        let ws = make_workspace(vec![("utils", "1.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:1.2.3".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["utils"], "1.2.3"); // exact passthrough
    }

    /// Finding #6: workspace: with arbitrary semver range is a passthrough (matches pnpm behavior).
    /// e.g., "workspace:>=1.0.0" for a member with version "2.0.0" → resolves to ">=1.0.0".
    #[test]
    fn workspace_semver_range_passthrough() {
        let ws = make_workspace(vec![("utils", "2.0.0")]);
        let mut deps = HashMap::from([("utils".to_string(), "workspace:>=1.0.0".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        // The range after "workspace:" is kept as-is — the member's actual version is irrelevant
        assert_eq!(deps["utils"], ">=1.0.0");
    }

    #[test]
    fn member_without_version_defaults_to_0_0_0() {
        let root = std::path::PathBuf::from("/test");
        let ws = Workspace {
            root: root.clone(),
            root_package: PackageJson {
                name: Some("root".to_string()),
                ..Default::default()
            },
            members: vec![WorkspaceMember {
                path: root.join("packages/no-ver"),
                package: PackageJson {
                    name: Some("no-ver".to_string()),
                    version: None,
                    ..Default::default()
                },
            }],
        };
        let mut deps = HashMap::from([("no-ver".to_string(), "workspace:*".to_string())]);
        resolve_workspace_protocol(&mut deps, &ws).unwrap();
        assert_eq!(deps["no-ver"], "0.0.0");
    }

    /// Lockfile assertion: after resolve_workspace_protocol, no values contain
    /// "workspace:" prefix. This guarantees the lockfile (and published tarball)
    /// will contain concrete semver, not protocol references.
    #[test]
    fn no_workspace_protocol_survives_resolution() {
        let ws = make_workspace(vec![
            ("@scope/ui", "2.3.1"),
            ("@scope/core", "1.0.0"),
            ("utils", "3.5.0"),
        ]);
        let mut deps = HashMap::from([
            ("@scope/ui".to_string(), "workspace:*".to_string()),
            ("@scope/core".to_string(), "workspace:^".to_string()),
            ("utils".to_string(), "workspace:~".to_string()),
            ("lodash".to_string(), "^4.17.0".to_string()),
            ("react".to_string(), "^18.0.0".to_string()),
        ]);

        resolve_workspace_protocol(&mut deps, &ws).unwrap();

        for (name, range) in &deps {
            assert!(
                !range.starts_with("workspace:"),
                "{name} still has workspace: protocol after resolution: {range}"
            );
        }

        // Verify concrete values
        assert_eq!(deps["@scope/ui"], "2.3.1");
        assert_eq!(deps["@scope/core"], "^1.0.0");
        assert_eq!(deps["utils"], "~3.5.0");
        // Non-workspace deps unchanged
        assert_eq!(deps["lodash"], "^4.17.0");
        assert_eq!(deps["react"], "^18.0.0");
    }
}

#[cfg(test)]
mod catalog_protocol_tests {
    use super::*;

    #[test]
    fn catalog_default_resolves() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
    }

    #[test]
    fn catalog_named_resolves() {
        let mut deps = HashMap::from([("jest".to_string(), "catalog:testing".to_string())]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["jest"], "^29.0.0");
    }

    #[test]
    fn catalog_missing_catalog_errors() {
        let mut deps = HashMap::from([("react".to_string(), "catalog:nonexistent".to_string())]);
        let catalogs = HashMap::new();
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("catalog 'nonexistent' not found")
        );
    }

    #[test]
    fn catalog_missing_entry_errors() {
        let mut deps = HashMap::from([("vue".to_string(), "catalog:".to_string())]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
        )]);
        let result = resolve_catalog_protocol(&mut deps, &catalogs);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("dependency 'vue' not found in catalog")
        );
    }

    #[test]
    fn non_catalog_deps_unchanged() {
        let mut deps = HashMap::from([
            ("react".to_string(), "^18.2.0".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "testing".to_string(),
            HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0"); // unchanged
        assert_eq!(deps["jest"], "^29.0.0"); // resolved
    }

    #[test]
    fn catalog_returns_resolved_log() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("jest".to_string(), "catalog:testing".to_string()),
        ]);
        let catalogs = HashMap::from([
            (
                "default".to_string(),
                HashMap::from([("react".to_string(), "^18.2.0".to_string())]),
            ),
            (
                "testing".to_string(),
                HashMap::from([("jest".to_string(), "^29.0.0".to_string())]),
            ),
        ]);
        let resolved = resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn catalog_multiple_entries_in_default() {
        let mut deps = HashMap::from([
            ("react".to_string(), "catalog:".to_string()),
            ("react-dom".to_string(), "catalog:".to_string()),
        ]);
        let catalogs = HashMap::from([(
            "default".to_string(),
            HashMap::from([
                ("react".to_string(), "^18.2.0".to_string()),
                ("react-dom".to_string(), "^18.2.0".to_string()),
            ]),
        )]);
        resolve_catalog_protocol(&mut deps, &catalogs).unwrap();
        assert_eq!(deps["react"], "^18.2.0");
        assert_eq!(deps["react-dom"], "^18.2.0");
    }
}

#[cfg(test)]
mod bin_config_tests {
    use super::*;

    #[test]
    fn test_bin_config_single() {
        let json = r#"{"bin": "./cli.js"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let bin = pkg.bin.unwrap();
        assert!(matches!(bin, BinConfig::Single(ref p) if p == "./cli.js"));
        let entries = bin.entries("mypackage");
        assert_eq!(
            entries,
            vec![("mypackage".to_string(), "./cli.js".to_string())]
        );
    }

    #[test]
    fn test_bin_config_map() {
        let json = r#"{"bin": {"cmd1": "./a.js", "cmd2": "./b.js"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let bin = pkg.bin.unwrap();
        assert!(matches!(bin, BinConfig::Map(_)));
        let mut entries = bin.entries("ignored");
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("cmd1".to_string(), "./a.js".to_string()));
        assert_eq!(entries[1], ("cmd2".to_string(), "./b.js".to_string()));
    }

    #[test]
    fn test_bin_config_scoped_package() {
        let bin = BinConfig::Single("./cli.js".to_string());
        let entries = bin.entries("@scope/pkg");
        assert_eq!(entries, vec![("pkg".to_string(), "./cli.js".to_string())]);
    }

    #[test]
    fn test_bin_config_missing() {
        let json = r#"{"name": "no-bin"}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert!(pkg.bin.is_none());
    }

    #[test]
    fn test_bin_config_single_empty_path_filtered() {
        let bin = BinConfig::Single("".to_string());
        let entries = bin.entries("pkg");
        assert!(
            entries.is_empty(),
            "empty path should be filtered out, got: {:?}",
            entries
        );
    }

    #[test]
    fn test_bin_config_map_empty_path_filtered() {
        let bin = BinConfig::Map(HashMap::from([
            ("valid".to_string(), "./ok.js".to_string()),
            ("empty".to_string(), "".to_string()),
        ]));
        let entries = bin.entries("pkg");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ("valid".to_string(), "./ok.js".to_string()));
    }
}

#[cfg(test)]
mod package_json_field_tests {
    use super::*;

    #[test]
    fn test_scripts_deserialization() {
        let json = r#"{"scripts": {"build": "tsc", "test": "vitest"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.scripts.len(), 2);
        assert_eq!(pkg.scripts.get("build").unwrap(), "tsc");
        assert_eq!(pkg.scripts.get("test").unwrap(), "vitest");
    }

    #[test]
    fn test_trusted_dependencies() {
        // Phase 4 M2: trusted_dependencies is now a TrustedDependencies enum.
        // The legacy array form must still deserialize cleanly into the
        // Legacy variant (this is the backwards-compat contract).
        let json = r#"{"lpm": {"trustedDependencies": ["pkg-a"]}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        match lpm.trusted_dependencies {
            TrustedDependencies::Legacy(names) => {
                assert_eq!(names, vec!["pkg-a".to_string()]);
            }
            other => panic!("expected legacy array form to deserialize as Legacy, got: {other:?}"),
        }
    }

    #[test]
    fn test_minimum_release_age() {
        let json = r#"{"lpm": {"minimumReleaseAge": 86400}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.minimum_release_age, Some(86400u64));
    }
}

// ── Phase 32 Phase 4 M2: TrustedDependencies schema migration tests ──
//
// These tests live in their own module so they don't get lost in the
// workspace_protocol/catalog_protocol/bin_config noise above. The
// invariant being locked: the deserializer accepts BOTH the legacy array
// form AND the rich map form, and the helper methods (matches_strict,
// contains_name_lenient, upgrade_to_rich, approve, revoke) compose into
// the M4 / M5 flows correctly.

#[cfg(test)]
mod trusted_dependencies_tests {
    use super::*;

    #[test]
    fn legacy_array_form_deserializes_to_legacy_variant() {
        let json = r#"["esbuild", "sharp"]"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        match td {
            TrustedDependencies::Legacy(names) => {
                assert_eq!(names, vec!["esbuild".to_string(), "sharp".to_string()])
            }
            other => panic!("expected Legacy, got {other:?}"),
        }
    }

    #[test]
    fn rich_map_form_deserializes_to_rich_variant() {
        let json = r#"{
            "esbuild@0.25.1": {
                "integrity": "sha512-foo",
                "scriptHash": "sha256-bar"
            }
        }"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        match td {
            TrustedDependencies::Rich(map) => {
                assert_eq!(map.len(), 1);
                let entry = map.get("esbuild@0.25.1").expect("entry must exist");
                assert_eq!(entry.integrity.as_deref(), Some("sha512-foo"));
                assert_eq!(entry.script_hash.as_deref(), Some("sha256-bar"));
            }
            other => panic!("expected Rich, got {other:?}"),
        }
    }

    #[test]
    fn rich_map_form_with_missing_optional_fields_deserializes() {
        // Both integrity and scriptHash are #[serde(default)] Option<String>
        // so an entry with neither should still parse successfully — this
        // is the legacy-upgrade path where binding metadata is unknown.
        let json = r#"{ "esbuild@0.25.1": {} }"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        let TrustedDependencies::Rich(map) = td else {
            panic!("expected Rich");
        };
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert!(binding.integrity.is_none());
        assert!(binding.script_hash.is_none());
    }

    #[test]
    fn empty_array_deserializes_as_legacy_empty() {
        let td: TrustedDependencies = serde_json::from_str("[]").unwrap();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Legacy(_)));
    }

    #[test]
    fn empty_map_deserializes_as_rich_empty() {
        let td: TrustedDependencies = serde_json::from_str("{}").unwrap();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Rich(_)));
    }

    #[test]
    fn default_value_is_empty_legacy() {
        let td = TrustedDependencies::default();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Legacy(_)));
    }

    #[test]
    fn missing_field_in_lpm_config_uses_default() {
        // No `trustedDependencies` key at all → field defaults to empty Legacy
        let json = r#"{"lpm": {}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert!(lpm.trusted_dependencies.is_empty());
        assert!(matches!(
            lpm.trusted_dependencies,
            TrustedDependencies::Legacy(_)
        ));
    }

    // ── matches_strict ──────────────────────────────────────────────

    fn rich_with(
        key: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustedDependencies {
        let mut map = HashMap::new();
        map.insert(
            key.to_string(),
            TrustedDependencyBinding {
                integrity: integrity.map(String::from),
                script_hash: script_hash.map(String::from),
                ..Default::default()
            },
        );
        TrustedDependencies::Rich(map)
    }

    #[test]
    fn matches_strict_returns_strict_for_full_match() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
    }

    #[test]
    fn matches_strict_returns_legacy_name_only_for_legacy_entry() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".to_string()]);
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::LegacyNameOnly
        );
    }

    #[test]
    fn matches_strict_returns_binding_drift_when_script_hash_differs() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-old"));
        let result = td.matches_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-new"), // drifted
        );
        match result {
            TrustMatch::BindingDrift { stored } => {
                assert_eq!(stored.script_hash.as_deref(), Some("sha256-old"));
            }
            other => panic!("expected BindingDrift, got {other:?}"),
        }
    }

    #[test]
    fn matches_strict_returns_binding_drift_when_integrity_differs() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-old"), Some("sha256-y"));
        let result = td.matches_strict("esbuild", "0.25.1", Some("sha512-new"), Some("sha256-y"));
        assert!(matches!(result, TrustMatch::BindingDrift { .. }));
    }

    #[test]
    fn matches_strict_returns_not_trusted_for_unknown_package() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("unknown", "1.0.0", None, None),
            TrustMatch::NotTrusted
        );
    }

    #[test]
    fn matches_strict_returns_not_trusted_for_known_name_different_version() {
        // Rich keys are name@version — a different version key is a
        // different entry. The package must be re-approved at the new version.
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.2", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::NotTrusted
        );
    }

    #[test]
    fn matches_strict_none_query_field_is_wildcard_against_set_stored_field() {
        // If the caller doesn't know the query value (None), and the stored
        // value is set, that's NOT drift — it's "no constraint on the
        // caller side". This is the legacy-upgrade-friendly contract.
        // The stored value continues to constrain SET caller queries.
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", None, Some("sha256-y")),
            TrustMatch::Strict,
            "None query integrity should not produce drift against a set stored integrity"
        );
    }

    #[test]
    fn matches_strict_none_stored_field_is_wildcard_against_set_query_field() {
        // Mirror image: stored binding has no integrity (legacy-upgrade
        // case), caller queries with a concrete integrity. This should
        // be Strict, not Drift, because there's no stored value to drift
        // FROM.
        let td = rich_with("esbuild@0.25.1", None, Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
    }

    // ── contains_name_lenient ───────────────────────────────────────

    #[test]
    fn contains_name_lenient_finds_legacy_entry() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".to_string()]);
        assert!(td.contains_name_lenient("esbuild"));
        assert!(!td.contains_name_lenient("sharp"));
    }

    #[test]
    fn contains_name_lenient_finds_rich_entry_strips_at_version() {
        let td = rich_with("esbuild@0.25.1", None, None);
        assert!(td.contains_name_lenient("esbuild"));
        assert!(!td.contains_name_lenient("sharp"));
    }

    #[test]
    fn contains_name_lenient_handles_scoped_packages_in_rich_keys() {
        // Scoped name `@scope/pkg` plus version `1.0.0` → key `@scope/pkg@1.0.0`.
        // The lenient matcher must split on the LAST `@`, not the first,
        // so the leading `@` of the scope is preserved.
        let td = rich_with("@scope/pkg@1.0.0", None, None);
        assert!(td.contains_name_lenient("@scope/pkg"));
        assert!(!td.contains_name_lenient("scope/pkg"));
    }

    // ── upgrade_to_rich ─────────────────────────────────────────────

    #[test]
    fn upgrade_to_rich_converts_legacy_entries_with_no_binding() {
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into(), "sharp".into()]);
        td.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich after upgrade");
        };
        assert_eq!(map.len(), 2);
        // The legacy preserve key is `<name>@*`
        assert!(map.contains_key("esbuild@*"));
        assert!(map.contains_key("sharp@*"));
        // Bindings are None because the legacy form had no binding metadata
        for binding in map.values() {
            assert!(binding.integrity.is_none());
            assert!(binding.script_hash.is_none());
        }
    }

    #[test]
    fn upgrade_to_rich_is_idempotent_on_rich_variant() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        td.upgrade_to_rich();
        td.upgrade_to_rich();
        td.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich");
        };
        assert_eq!(map.len(), 1);
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.integrity.as_deref(), Some("sha512-x"));
        assert_eq!(binding.script_hash.as_deref(), Some("sha256-y"));
    }

    #[test]
    fn upgrade_to_rich_then_lenient_lookup_still_finds_legacy_names() {
        // After upgrade, contains_name_lenient must still find pre-upgrade
        // entries because their preserve key is `<name>@*` and the lenient
        // matcher strips on the last `@`.
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        td.upgrade_to_rich();
        assert!(td.contains_name_lenient("esbuild"));
    }

    // ── approve / revoke ────────────────────────────────────────────

    #[test]
    fn approve_inserts_new_entry_and_upgrades_to_rich() {
        let mut td = TrustedDependencies::Legacy(vec![]);
        let was_present = td.approve(
            "esbuild",
            "0.25.1",
            Some("sha512-x".to_string()),
            Some("sha256-y".to_string()),
        );
        assert!(!was_present);
        let TrustedDependencies::Rich(map) = &td else {
            panic!("approve must upgrade to Rich");
        };
        assert_eq!(map.len(), 1);
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.integrity.as_deref(), Some("sha512-x"));
        assert_eq!(binding.script_hash.as_deref(), Some("sha256-y"));
    }

    #[test]
    fn approve_overwrites_existing_entry_with_same_key() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-old"), Some("sha256-old"));
        let was_present = td.approve(
            "esbuild",
            "0.25.1",
            Some("sha512-new".to_string()),
            Some("sha256-new".to_string()),
        );
        assert!(was_present);
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich");
        };
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.integrity.as_deref(), Some("sha512-new"));
        assert_eq!(binding.script_hash.as_deref(), Some("sha256-new"));
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-1):** the previous version of this
    /// test codified the WRONG invariant — it asserted that legacy `@*`
    /// preserve keys did NOT satisfy the strict gate. That meant a manifest
    /// like `["esbuild"]` would silently re-block esbuild on the next install
    /// after any unrelated `lpm approve-builds --yes` upgrade. The audit
    /// reproduced this end-to-end. The fix is to make `matches_strict`
    /// honor `<name>@*` keys as wildcard version matches that produce
    /// `LegacyNameOnly` (which the build pipeline accepts as trusted, with
    /// a deprecation warning). This test now locks in the FIXED behavior.
    #[test]
    fn approve_legacy_then_approve_new_preserves_legacy_via_starkey() {
        let mut td = TrustedDependencies::Legacy(vec!["sharp".to_string()]);
        td.approve(
            "esbuild",
            "0.25.1",
            Some("sha512-x".into()),
            Some("sha256-y".into()),
        );

        // Both entries reachable via lenient lookup
        assert!(td.contains_name_lenient("sharp"));
        assert!(td.contains_name_lenient("esbuild"));

        // Strict lookup finds esbuild as Strict (full binding)
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
        // Strict lookup finds sharp as LegacyNameOnly via the `@*` preserve
        // key — the audit fix. Pre-fix this returned `NotTrusted` and the
        // build pipeline re-blocked sharp on the next install.
        assert_eq!(
            td.matches_strict("sharp", "0.33.0", Some("sha512-z"), Some("sha256-z")),
            TrustMatch::LegacyNameOnly,
            "legacy `@*` preserve keys MUST satisfy the strict gate as \
             LegacyNameOnly so users keep their pre-Phase-4 approvals \
             through the upgrade. The build pipeline emits a deprecation \
             warning so users still get nudged to upgrade to a strict binding."
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-1) — direct.** A `<name>@*`
    /// preserve key in a Rich variant must match ANY version of the named
    /// package as `LegacyNameOnly`. Tests the matcher in isolation.
    #[test]
    fn matches_strict_handles_at_star_preserve_key_as_legacy_wildcard() {
        // Construct a Rich variant directly with a `@*` preserve key
        // (the upgrade_to_rich migration sentinel).
        let mut map = HashMap::new();
        map.insert(
            "esbuild@*".to_string(),
            TrustedDependencyBinding {
                integrity: None,
                script_hash: None,
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        // Any concrete version matches as LegacyNameOnly
        for version in &["0.25.1", "0.25.2", "1.0.0", "0.0.0-beta.1"] {
            assert_eq!(
                td.matches_strict("esbuild", version, None, None),
                TrustMatch::LegacyNameOnly,
                "version {version} must match the @* preserve key"
            );
        }
        // A different name must NOT match
        assert_eq!(
            td.matches_strict("sharp", "0.33.0", None, None),
            TrustMatch::NotTrusted,
            "@* keys are still scoped by name"
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-1).** A scoped package preserved
    /// as `@scope/pkg@*` must also be matched as `LegacyNameOnly`. The
    /// `@*` parser must split on the LAST `@`, not the first.
    #[test]
    fn matches_strict_at_star_preserve_key_handles_scoped_package_names() {
        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@*".to_string(),
            TrustedDependencyBinding::default(),
        );
        let td = TrustedDependencies::Rich(map);
        assert_eq!(
            td.matches_strict("@scope/pkg", "1.2.3", None, None),
            TrustMatch::LegacyNameOnly
        );
    }

    /// **AUDIT REGRESSION (Phase 4 D-impl-1).** A concrete `name@version`
    /// rich entry must be preferred over a `name@*` legacy preserve key
    /// if both exist for the same name. This protects the case where the
    /// user approved esbuild@0.25.1 specifically AND there's a leftover
    /// legacy `esbuild@*` entry — the strict binding wins.
    #[test]
    fn matches_strict_prefers_concrete_version_key_over_at_star_for_same_name() {
        let mut map = HashMap::new();
        map.insert("esbuild@*".to_string(), TrustedDependencyBinding::default());
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                integrity: Some("sha512-x".into()),
                script_hash: Some("sha256-y".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        // Concrete version + matching binding → Strict
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
        // Different version → falls through to the @* preserve key
        assert_eq!(
            td.matches_strict("esbuild", "0.25.2", None, None),
            TrustMatch::LegacyNameOnly
        );
        // Concrete version + DRIFTED binding → still BindingDrift on the
        // concrete entry (the @* key does NOT silently mask drift on the
        // entry the user explicitly approved).
        assert!(matches!(
            td.matches_strict(
                "esbuild",
                "0.25.1",
                Some("sha512-x"),
                Some("sha256-DRIFTED")
            ),
            TrustMatch::BindingDrift { .. }
        ));
    }

    #[test]
    fn revoke_removes_entry_and_returns_true() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert!(td.revoke("esbuild", "0.25.1"));
        assert!(td.is_empty());
    }

    #[test]
    fn revoke_returns_false_for_missing_entry() {
        let mut td = rich_with("esbuild@0.25.1", None, None);
        assert!(!td.revoke("sharp", "0.33.0"));
        assert!(!td.is_empty()); // unchanged
    }

    #[test]
    fn revoke_on_legacy_variant_is_a_noop() {
        // Documented contract: revoke does NOT touch Legacy entries.
        // Callers must upgrade first if they want strict semantics.
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        assert!(!td.revoke("esbuild", "0.25.1"));
        assert!(td.contains_name_lenient("esbuild"));
    }

    // ── iter ────────────────────────────────────────────────────────

    #[test]
    fn iter_yields_names_with_none_for_legacy_entries() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".into(), "sharp".into()]);
        let mut entries: Vec<(String, bool)> = td.iter().map(|(n, b)| (n, b.is_some())).collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![("esbuild".to_string(), false), ("sharp".to_string(), false)]
        );
    }

    #[test]
    fn iter_yields_names_with_some_binding_for_rich_entries() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let entries: Vec<(String, bool)> = td.iter().map(|(n, b)| (n, b.is_some())).collect();
        assert_eq!(entries, vec![("esbuild".to_string(), true)]);
    }

    #[test]
    fn iter_yields_scoped_names_correctly() {
        let td = rich_with("@scope/pkg@1.0.0", None, None);
        let names: Vec<String> = td.iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["@scope/pkg".to_string()]);
    }

    // ── rich_key format ─────────────────────────────────────────────

    #[test]
    fn rich_key_format_uses_at_separator() {
        assert_eq!(
            TrustedDependencies::rich_key("esbuild", "0.25.1"),
            "esbuild@0.25.1"
        );
    }

    #[test]
    fn rich_key_format_handles_scoped_names() {
        assert_eq!(
            TrustedDependencies::rich_key("@scope/pkg", "1.0.0"),
            "@scope/pkg@1.0.0"
        );
    }

    // ── ProvenanceSnapshot (moved from lpm-security/src/triage.rs) ─
    //
    // P4 relocated the struct into lpm-workspace so that
    // `TrustedDependencyBinding.provenance_at_approval` can reference
    // it without inducing a lpm-workspace → lpm-security dependency
    // cycle. These tests came with the struct; behavioural contract
    // is unchanged from the pre-P4 tests that lived in triage.rs.

    #[test]
    fn provenance_snapshot_full_roundtrips() {
        let snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
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
            ..Default::default()
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
            "publisher": "github:axios/axios"
        }"#;
        let snap: ProvenanceSnapshot = serde_json::from_str(json).unwrap();
        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());
        assert!(snap.attestation_cert_sha256.is_none());
    }

    /// Field-by-field equality of the full snapshot is used by the
    /// cache round-trip paths (serialize → read back, assert equal)
    /// and by the schema-test round-trips here. The DRIFT comparator
    /// in `lpm-security::provenance` uses a narrower identity-only
    /// equality (publisher + workflow_path) — see that crate's
    /// `identity_equal` helper + its regression guards for
    /// release-varying fields.
    #[test]
    fn provenance_snapshot_full_equality_is_tuple_strict() {
        let base = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-aaa".into()),
        };
        let differ_publisher = ProvenanceSnapshot {
            publisher: Some("github:someone-else/axios".into()),
            ..base.clone()
        };
        let differ_workflow_path = ProvenanceSnapshot {
            workflow_path: Some(".github/workflows/pr-workflow.yml".into()),
            ..base.clone()
        };
        let differ_workflow_ref = ProvenanceSnapshot {
            workflow_ref: Some("refs/tags/v1.14.1".into()),
            ..base.clone()
        };
        let differ_cert = ProvenanceSnapshot {
            attestation_cert_sha256: Some("sha256-bbb".into()),
            ..base.clone()
        };
        assert_ne!(base, differ_publisher);
        assert_ne!(base, differ_workflow_path);
        assert_ne!(base, differ_workflow_ref);
        assert_ne!(base, differ_cert);
        assert_eq!(base, base.clone());
    }

    // ── TrustedDependencyBinding.provenance_at_approval (P4 §6.2) ──

    /// Pre-P4 `trustedDependencies` entries — with only `integrity`
    /// and `scriptHash` — must keep round-tripping through serde
    /// without the new `provenanceAtApproval` field surfacing as a
    /// `null` key. A live manifest should never grow a `null` key on
    /// read/write cycles.
    #[test]
    fn trusted_binding_pre_p4_shape_roundtrips_cleanly() {
        let pre_p4 = r#"{
            "integrity": "sha512-abc",
            "scriptHash": "sha256-deadbeef"
        }"#;
        let parsed: TrustedDependencyBinding = serde_json::from_str(pre_p4).unwrap();
        assert_eq!(parsed.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(parsed.script_hash.as_deref(), Some("sha256-deadbeef"));
        assert!(parsed.provenance_at_approval.is_none());

        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("provenanceAtApproval"),
            "pre-P4 binding must NOT emit a provenanceAtApproval key when None; \
             got {reserialized}"
        );
    }

    /// P4 happy path: an entry approved in a provenance-aware install
    /// captures the `ProvenanceSnapshot` and round-trips through
    /// serde without field drift. The `provenanceAtApproval` JSON
    /// key name matches the plan doc's §6.2 wire spec.
    #[test]
    fn trusted_binding_with_provenance_roundtrips() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-deadbeef".into()),
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some("github:axios/axios".into()),
                workflow_path: Some(".github/workflows/publish.yml".into()),
                workflow_ref: Some("refs/tags/v1.14.0".into()),
                attestation_cert_sha256: Some("sha256-aaa".into()),
            }),
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains(r#""provenanceAtApproval":"#),
            "wire key must be camelCase `provenanceAtApproval`, got {json}"
        );

        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
    }

    // ── provenance_reference_for_name (P4 Chunk 3 selector) ───────
    //
    // Reviewer finding — Finding 2: the drift gate's reference
    // selector must be deterministic across runs. HashMap iteration
    // order isn't, so a `map.iter().find(...)` shape would pick
    // different entries on different runs when multiple matches
    // exist. Deterministic selection policy: lexicographic-max on
    // the version string. Documented simplification; semver-correct
    // ordering deferred to a later phase.

    fn trusted_dep_binding_with_provenance(publisher: &str) -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: None,
            script_hash: None,
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some(publisher.into()),
                ..Default::default()
            }),
        }
    }

    fn trusted_dep_binding_no_provenance() -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: Some("sha512-x".into()),
            script_hash: Some("sha256-y".into()),
            provenance_at_approval: None,
        }
    }

    #[test]
    fn provenance_reference_returns_none_for_legacy_variant() {
        let trusted = TrustedDependencies::Legacy(vec!["axios".into()]);
        assert!(trusted.provenance_reference_for_name("axios").is_none());
    }

    #[test]
    fn provenance_reference_returns_none_for_absent_name() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        assert!(trusted.provenance_reference_for_name("express").is_none());
    }

    #[test]
    fn provenance_reference_returns_none_when_no_entries_have_provenance() {
        // Name matches, but every entry's provenance_at_approval is
        // None — must NOT mask subsequent provenance-bearing
        // approvals by returning a legacy binding. See the
        // reviewer's Finding 1 discussion.
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        let trusted = TrustedDependencies::Rich(map);
        assert!(trusted.provenance_reference_for_name("axios").is_none());
    }

    #[test]
    fn provenance_reference_returns_single_provenance_bearing_entry() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, binding) = trusted
            .provenance_reference_for_name("axios")
            .expect("entry exists");
        assert_eq!(version, "1.14.0");
        assert_eq!(
            binding
                .provenance_at_approval
                .as_ref()
                .unwrap()
                .publisher
                .as_deref(),
            Some("github:axios/axios"),
        );
    }

    #[test]
    fn provenance_reference_filters_out_legacy_entries_in_mixed_map() {
        // Mix of provenance-bearing and legacy entries for the same
        // name. The selector must pick the provenance-bearing one
        // regardless of insertion order — a legacy v1.13.5 must
        // never be chosen over a provenance-bearing v1.14.0.
        let mut map = HashMap::new();
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, _) = trusted
            .provenance_reference_for_name("axios")
            .expect("provenance-bearing entry exists");
        assert_eq!(version, "1.14.0");
    }

    /// **Reviewer finding — Finding 2 primary regression guard.** With
    /// multiple provenance-bearing approvals for the same name, the
    /// selector MUST return a deterministic choice. Sensible
    /// deterministic rule: lexicographic-max version string. Without
    /// determinism the drift verdict itself can flip across runs
    /// when the matched entries carry different identities.
    #[test]
    fn provenance_reference_picks_lex_max_version_deterministically() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        map.insert(
            "axios@2.0.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios-next"),
        );
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);

        // Run the selector multiple times — must always pick
        // `2.0.0` (lex-max). In the pre-fix HashMap-order impl this
        // would be non-deterministic across runs (and even within a
        // run given `#[repr(...)]`-induced hash-state changes).
        for _ in 0..8 {
            let (version, binding) = trusted
                .provenance_reference_for_name("axios")
                .expect("at least one match");
            assert_eq!(
                version, "2.0.0",
                "selector must always pick lex-max; got {version}",
            );
            assert_eq!(
                binding
                    .provenance_at_approval
                    .as_ref()
                    .unwrap()
                    .publisher
                    .as_deref(),
                Some("github:axios/axios-next"),
                "binding returned must correspond to the lex-max key",
            );
        }
    }

    /// Scoped package names (`@scope/pkg`) must split cleanly at the
    /// LAST `@` — the leading `@` in the scope must not be confused
    /// with the version delimiter.
    #[test]
    fn provenance_reference_handles_scoped_name_correctly() {
        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@1.0.0".to_string(),
            trusted_dep_binding_with_provenance("github:scope/pkg"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, _) = trusted
            .provenance_reference_for_name("@scope/pkg")
            .expect("scoped entry resolves");
        assert_eq!(version, "1.0.0");
    }

    /// An approval flow that captures "no provenance present" (the
    /// approved version had no attestation in the first place) must
    /// still serialize the `present: false` snapshot. This matters
    /// for the §7.2 drift rule's `(None, Some(_)) → block` branch,
    /// which distinguishes "approved version had provenance, this
    /// one doesn't" (block) from "neither side had provenance"
    /// (layers 1/2/4 decide).
    #[test]
    fn trusted_binding_preserves_absent_provenance_marker() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-deadbeef".into()),
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: false,
                ..Default::default()
            }),
        };
        let json = serde_json::to_string(&binding).unwrap();
        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
        assert!(!back.provenance_at_approval.as_ref().unwrap().present);
    }
}
