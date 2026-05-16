//! Monorepo/workspace discovery and filtering for LPM.
//!
//! Detects workspace configurations from:
//! - `package.json` `"workspaces"` field (npm/yarn)
//! - `pnpm-workspace.yaml`
//!
//! Discovers member packages and reads their package.json for dependencies.
//!
//! Protocols: `workspace:*`, `catalog:`, and `catalog:{name}`.
//! `--filter` and workspace-aware `run` are supported.

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

    /// `peerDependenciesMeta` — per-peer typed metadata.
    ///
    /// Today only the `optional` flag is read. npm's contract: when
    /// `optional: true`, an unresolved peer is a silent skip; when
    /// `optional: false` (or absent), an unresolved peer is a
    /// resolution error. LPM's existing `check_unmet_peers` enforces
    /// this at the resolver, and the v2 linker's peer-edge synthesis
    /// (`augment_with_peer_edges`) needs the same distinction so it
    /// can emit a clearer trace for the truly-optional case versus
    /// the "resolver should have caught this" case.
    ///
    /// Lossy parse: any nested shape we don't model is silently
    /// dropped. The Default flag for an entry is `false`, which
    /// matches the implicit npm contract (peer is required unless
    /// declared otherwise).
    #[serde(default, rename = "peerDependenciesMeta")]
    pub peer_dependencies_meta: HashMap<String, PeerDependencyMeta>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// npm overrides / yarn resolutions — force specific versions for
    /// transitive deps.
    ///
    /// **Lossy deserialization.** The npm spec allows override values to
    /// be EITHER a string (`"axios": "^1.15.2"` — simple version pin) OR
    /// a nested object (`"path-scurry": {"lru-cache": "^11.3.5"}` —
    /// "only override `lru-cache` to ^11.3.5 when `path-scurry` is in
    /// scope"). LPM's resolver does not currently apply nested overrides,
    /// but a strict `HashMap<String, String>` deserializer would fail to
    /// parse the entire `package.json` of any dep that ships nested
    /// overrides — including [rollup](https://github.com/rollup/rollup)
    /// which has them in its lockfile-fence overrides block. That broke
    /// `lpm-linker::create_bin_links` (no rollup CLI in
    /// `node_modules/.bin/`) plus any other read-`package.json`
    /// consumer (security analysis, lifecycle scripts, etc.).
    ///
    /// The custom deserializer here keeps the simple `String`-valued
    /// entries (which LPM CAN apply) and silently drops the
    /// nested-object ones with a debug-level trace. When LPM's resolver
    /// gains nested-override support, this can be promoted to a typed
    /// `OverrideValue` enum and the readers updated. Until then,
    /// "permissive parse + drop unsupported shapes" is the right
    /// trade-off because it preserves the rest of the manifest's value.
    #[serde(default, deserialize_with = "deserialize_lossy_string_map")]
    pub overrides: HashMap<String, String>,

    /// Yarn-style resolutions (same purpose as overrides). Same
    /// lossy-string-map handling as `overrides`: yarn also supports
    /// nested resolution objects, which we drop with a trace.
    #[serde(default, deserialize_with = "deserialize_lossy_string_map")]
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

    /// Captures the `pnpm` namespace from `package.json` as raw JSON.
    ///
    /// Stays untyped so unsupported shapes (e.g. an object-valued
    /// `pnpm.overrides` entry, an unknown subfield) don't break
    /// unrelated commands that just read `package.json`. Compatibility
    /// gaps are surfaced through [`PackageJson::manifest_compat_issues`]
    /// — install-time warnings, `lpm doctor` checks, and structured
    /// migrate-time errors when the planner encounters a value LPM
    /// can't translate.
    #[serde(default)]
    pub pnpm: Option<PnpmRaw>,
}

/// Per-peer metadata from `peerDependenciesMeta`.
///
/// npm spec: each key in `peerDependenciesMeta` mirrors a key in
/// `peerDependencies` (or, less commonly, declares a peer that's
/// purely optional and not listed in `peerDependencies`). The value
/// is an object with optional flags. Today LPM only reads `optional`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PeerDependencyMeta {
    /// `true` iff this peer is optional — an unresolved peer is a
    /// silent skip rather than a resolution error.
    #[serde(default)]
    pub optional: bool,
}

/// Untyped capture of the `pnpm` namespace in `package.json`.
///
/// Each subfield is `serde_json::Value` so the parser is permissive:
/// any shape pnpm supports today (object-of-strings for overrides,
/// nested catalog refs, etc.) deserializes successfully and is
/// classified later by the planner / compat-gap helper.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PnpmRaw {
    /// `pnpm.overrides` — string values are translatable to LPM's
    /// override grammar; other shapes are surfaced as structured
    /// migrate-time errors.
    #[serde(default)]
    pub overrides: serde_json::Value,

    /// `pnpm.patchedDependencies` — captured raw so the install-time
    /// detection helper can warn "you have pnpm patches that LPM isn't
    /// honoring." The migrate translator reads this field to produce
    /// `lpm.patchedDependencies` entries.
    #[serde(default, rename = "patchedDependencies")]
    pub patched_dependencies: serde_json::Value,

    /// `pnpm.peerDependencyRules` — captured raw so the migrate
    /// translator can parse the three sub-keys (`ignoreMissing`,
    /// `allowedVersions`, `allowAny`) and so the install-time +
    /// `lpm doctor` drift detection can warn when entries here
    /// aren't mirrored under `lpm.peerDependencyRules`.
    #[serde(default, rename = "peerDependencyRules")]
    pub peer_dependency_rules: serde_json::Value,
}

/// Severity of a [`ManifestCompatIssue`].
///
/// `Warn` — user has a config knob that LPM is silently dropping or
/// ignoring. The user should act (run `lpm migrate`, remove the field,
/// etc.) or accept the gap.
///
/// `Info` — purely informational. No silent drop is happening; LPM is
/// doing the right thing and just surfacing the divergence so the
/// user knows what's going on. Reserved for future detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestCompatSeverity {
    Warn,
    Info,
}

impl ManifestCompatSeverity {
    /// Stable string form for CLI / JSON consumers.
    pub fn as_str(&self) -> &'static str {
        match self {
            ManifestCompatSeverity::Warn => "warn",
            ManifestCompatSeverity::Info => "info",
        }
    }
}

/// One concrete drift / silent-drop / ignored-field finding in a
/// `package.json`. Returned by [`PackageJson::manifest_compat_issues`]
/// as the structured output that both the install-time warning loop
/// and `lpm doctor` consume — so the two surfaces can never disagree
/// on whether a field is dropped, what to call it, or how to fix it.
///
/// The `code` is the load-bearing identifier; consumers (CI, MCP
/// servers, the doctor JSON contract) match on it. Wording in
/// `detail` and `remediation` may evolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCompatIssue {
    /// Stable snake_case identifier. Matches the `code` field on the
    /// corresponding `lpm doctor` check entry.
    pub code: &'static str,
    /// Severity. `Warn` is the common case; `Info` is for fields LPM
    /// legitimately ignores by design.
    pub severity: ManifestCompatSeverity,
    /// Human-readable summary. One line.
    pub detail: String,
    /// Suggested fix. May be a CLI command (`lpm migrate`), a
    /// pointer ("see /docs/..."), or "remove the field".
    pub remediation: String,
    /// Specific entries (keys) that drifted. Empty when the issue is
    /// about a single named field with no enumeration (e.g.,
    /// `engines.pnpm` ignored — there's no list to enumerate). Sorted
    /// for deterministic output.
    pub entries: Vec<String>,
}

/// Other-PM `engines.<key>` keys that LPM does not enforce. Each one
/// produces a separate [`ManifestCompatIssue`] with its own stable
/// `code` (`engines_npm_ignored`, `engines_pnpm_ignored`, etc.) so
/// consumers can branch on the exact field that drifted.
const OTHER_PM_ENGINE_KEYS: &[(&str, &str)] = &[
    ("npm", "engines_npm_ignored"),
    ("pnpm", "engines_pnpm_ignored"),
    ("yarn", "engines_yarn_ignored"),
    ("bun", "engines_bun_ignored"),
];

/// Static catalog metadata for one manifest-compatibility code.
///
/// Pairs with [`ManifestCompatIssue`] (the runtime row): the runtime
/// row carries the per-package `entries` list and the prose computed
/// from the diff, while this struct carries the static description /
/// when-fires / remediation that document the check itself.
///
/// `lpm doctor list` (in `lpm-cli`) consumes this catalog through an
/// adapter so the inventory surface speaks one shape for both
/// CLI-side codes and workspace-owned codes — without duplicating
/// the prose.
#[derive(Debug, Clone, Copy)]
pub struct ManifestCompatCatalogEntry {
    /// Stable snake_case identifier. Matches the corresponding
    /// [`ManifestCompatIssue::code`] emitted at runtime.
    pub code: &'static str,
    /// Human-readable label suitable for a check name column.
    pub name: &'static str,
    /// One-line description of what this code expresses.
    pub description: &'static str,
    /// Conditions under which the issue actually fires.
    pub when_fires: &'static str,
    /// Suggested remediation. CLI command, doc pointer, or
    /// "remove the field". Stable across emissions; detail
    /// strings on individual rows may evolve.
    pub remediation: &'static str,
    /// Severities this code can emit, as the stable strings used
    /// in `lpm doctor --json` (`pass | warn | fail`). Strings rather
    /// than an enum so the cross-crate boundary stays free of an
    /// `lpm-cli` type dependency.
    pub possible_severities: &'static [&'static str],
}

// Individual catalog constants — exposed so downstream crates
// (`lpm-cli`'s doctor catalog) can build typed `CheckEntry` statics
// that point at this prose without duplicating it. The slice
// [`MANIFEST_COMPAT_CATALOG`] iterates these in stable order.

/// Catalog entry for `pnpm_overrides_drift`.
pub const PNPM_OVERRIDES_DRIFT_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "pnpm_overrides_drift",
    name: "Manifest compat: pnpm.overrides",
    description: "Entries in `pnpm.overrides` that LPM is not honoring through `lpm.overrides`, top-level `overrides`, or `resolutions`.",
    when_fires: "Any `pnpm.overrides` entry is missing from the LPM-readable mirrors, has a different target version, or uses a value shape LPM does not support (object form, etc.).",
    remediation: "Run `lpm migrate` to translate, or mirror the entries verbatim in `lpm.overrides`.",
    possible_severities: &["warn"],
};

/// Catalog entry for `pnpm_patches_drift`.
pub const PNPM_PATCHES_DRIFT_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "pnpm_patches_drift",
    name: "Manifest compat: pnpm.patchedDependencies",
    description: "Entries in `pnpm.patchedDependencies` whose patch files LPM cannot bind to via `lpm.patchedDependencies`.",
    when_fires: "Any `pnpm.patchedDependencies` entry is missing from `lpm.patchedDependencies` or points at a different patch path.",
    remediation: "Re-author with `lpm patch` or mirror the entries into `lpm.patchedDependencies` after verifying the patch applies cleanly under LPM's stricter integrity binding.",
    possible_severities: &["warn"],
};

/// Catalog entry for `pnpm_peer_rules_drift`.
pub const PNPM_PEER_RULES_DRIFT_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "pnpm_peer_rules_drift",
    name: "Manifest compat: pnpm.peerDependencyRules",
    description: "Sub-key entries (`ignoreMissing`, `allowedVersions`, `allowAny`) that LPM is not honoring via `lpm.peerDependencyRules`.",
    when_fires: "Any `pnpm.peerDependencyRules.*` entry is missing from `lpm.peerDependencyRules.*`. Coverage is checked per sub-key with selector parity.",
    remediation: "Run `lpm migrate` (the planner translates selector keys 1:1) or mirror the rules under `lpm.peerDependencyRules`.",
    possible_severities: &["warn"],
};

/// Catalog entry for `engines_npm_ignored`.
pub const ENGINES_NPM_IGNORED_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "engines_npm_ignored",
    name: "Manifest compat: engines.npm",
    description: "`engines.npm` is declared but LPM is not the npm CLI and does not enforce its constraint.",
    when_fires: "`engines.npm` is set on the (workspace root) `package.json`.",
    remediation: "Remove the field, or accept that LPM ignores it. `engines.node` and `engines.lpm` are enforced.",
    possible_severities: &["warn"],
};

/// Catalog entry for `engines_pnpm_ignored`.
pub const ENGINES_PNPM_IGNORED_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "engines_pnpm_ignored",
    name: "Manifest compat: engines.pnpm",
    description: "`engines.pnpm` is declared but LPM does not enforce pnpm's version constraint.",
    when_fires: "`engines.pnpm` is set on the (workspace root) `package.json`.",
    remediation: "Remove the field, or accept that LPM ignores it. `engines.node` and `engines.lpm` are enforced.",
    possible_severities: &["warn"],
};

/// Catalog entry for `engines_yarn_ignored`.
pub const ENGINES_YARN_IGNORED_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "engines_yarn_ignored",
    name: "Manifest compat: engines.yarn",
    description: "`engines.yarn` is declared but LPM does not enforce yarn's version constraint.",
    when_fires: "`engines.yarn` is set on the (workspace root) `package.json`.",
    remediation: "Remove the field, or accept that LPM ignores it. `engines.node` and `engines.lpm` are enforced.",
    possible_severities: &["warn"],
};

/// Catalog entry for `engines_bun_ignored`.
pub const ENGINES_BUN_IGNORED_META: ManifestCompatCatalogEntry = ManifestCompatCatalogEntry {
    code: "engines_bun_ignored",
    name: "Manifest compat: engines.bun",
    description: "`engines.bun` is declared but LPM does not enforce bun's version constraint.",
    when_fires: "`engines.bun` is set on the (workspace root) `package.json`.",
    remediation: "Remove the field, or accept that LPM ignores it. `engines.node` and `engines.lpm` are enforced.",
    possible_severities: &["warn"],
};

/// Static catalog of every code emitted by
/// [`PackageJson::manifest_compat_issues`]. Exposed for
/// `lpm doctor list` so the inventory surface and the runtime
/// detectors can never disagree on which codes exist.
///
/// Order mirrors the runtime emission order from
/// `manifest_compat_issues()` so a side-by-side comparison stays
/// reviewable.
pub static MANIFEST_COMPAT_CATALOG: &[ManifestCompatCatalogEntry] = &[
    PNPM_OVERRIDES_DRIFT_META,
    PNPM_PATCHES_DRIFT_META,
    PNPM_PEER_RULES_DRIFT_META,
    ENGINES_NPM_IGNORED_META,
    ENGINES_PNPM_IGNORED_META,
    ENGINES_YARN_IGNORED_META,
    ENGINES_BUN_IGNORED_META,
];

impl PackageJson {
    /// Run every manifest-side compatibility detector against this
    /// `PackageJson`. The returned vec is the single source of truth
    /// consumed by:
    ///
    /// - [`crate::commands::install`] (in `lpm-cli`) for the human
    ///   stderr warnings emitted on every install run.
    /// - [`crate::commands::doctor`] (in `lpm-cli`) for the
    ///   `lpm doctor --json` contract — each issue lands as a
    ///   `Check::warn(issue.code, ...)` so automation can match on
    ///   the code without parsing wording.
    ///
    /// Issues are returned in stable order:
    /// 1. `pnpm_overrides_drift`
    /// 2. `pnpm_patches_drift`
    /// 3. `engines_<pm>_ignored` (npm, pnpm, yarn, bun in that order)
    ///
    /// Detectors are diff-aware where it makes sense (`pnpm_overrides`
    /// stays silent once `lpm.overrides` covers every entry) and
    /// always-fires where the field is intrinsically unhonored
    /// (`engines.<pm>` — LPM never enforces those by design).
    pub fn manifest_compat_issues(&self) -> Vec<ManifestCompatIssue> {
        let mut issues = Vec::new();
        if let Some(i) = detect_pnpm_overrides_drift(self) {
            issues.push(i);
        }
        if let Some(i) = detect_pnpm_patches_drift(self) {
            issues.push(i);
        }
        if let Some(i) = detect_pnpm_peer_rules_drift(self) {
            issues.push(i);
        }
        issues.extend(detect_engines_other_pm_ignored(self));
        issues
    }
}

/// Detector: `pnpm.overrides` has entries (or value shapes) whose
/// effect LPM doesn't honor.
///
/// Returns `Some(issue)` when at least one entry in `pnpm.overrides`
/// is **not** mirrored verbatim by `lpm.overrides`, top-level
/// `overrides`, or `resolutions`. Coverage requires both sides to
/// agree on the target — same key with a different target is
/// exactly the "pnpm intent vs LPM behavior diverged" case the
/// detector exists to surface.
///
/// Object-valued and other unsupported pnpm shapes can never be
/// "covered" by an LPM-readable string source, so they always count
/// as dropped. The migrate planner surfaces a structured error for
/// the same shape; this detector is the install-side / doctor-side
/// finger-pointer.
fn detect_pnpm_overrides_drift(pkg: &PackageJson) -> Option<ManifestCompatIssue> {
    let pnpm = pkg.pnpm.as_ref()?;
    let map = pnpm.overrides.as_object()?;
    if map.is_empty() {
        return None;
    }

    let lpm_overrides = pkg.lpm.as_ref().map(|l| &l.overrides);
    let mut entries: Vec<String> = map
        .iter()
        .filter(|(k, v)| {
            let Some(pnpm_target) = v.as_str() else {
                // Non-string pnpm value can't be matched by any
                // LPM-readable string source.
                return true;
            };
            let covered = lpm_overrides
                .and_then(|m| m.get(*k))
                .is_some_and(|t| t == pnpm_target)
                || pkg.overrides.get(*k).is_some_and(|t| t == pnpm_target)
                || pkg.resolutions.get(*k).is_some_and(|t| t == pnpm_target);
            !covered
        })
        .map(|(k, _)| k.clone())
        .collect();
    if entries.is_empty() {
        return None;
    }
    entries.sort();

    Some(ManifestCompatIssue {
        code: "pnpm_overrides_drift",
        severity: ManifestCompatSeverity::Warn,
        detail: format!(
            "package.json has {} `pnpm.overrides` entr{} that LPM doesn't honor: {}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            preview(&entries),
        ),
        remediation:
            "run `lpm migrate` to translate them to `lpm.overrides`, or copy them across by hand. \
             LPM reads `lpm.overrides`, top-level `overrides`, and `resolutions` — not the \
             `pnpm.overrides` namespace."
                .into(),
        entries,
    })
}

/// Detector: `pnpm.patchedDependencies` has entries whose patch
/// integrity / path isn't mirrored by `lpm.patchedDependencies`.
///
/// The lpm value shape is `{ "path": "...", "originalIntegrity": "..." }`,
/// so this detector compares against `path` specifically — pnpm only
/// stores the path string. Non-string pnpm values count as dropped.
fn detect_pnpm_patches_drift(pkg: &PackageJson) -> Option<ManifestCompatIssue> {
    let pnpm = pkg.pnpm.as_ref()?;
    let map = pnpm.patched_dependencies.as_object()?;
    if map.is_empty() {
        return None;
    }

    let lpm_patches = pkg.lpm.as_ref().map(|l| &l.patched_dependencies);
    let mut entries: Vec<String> = map
        .iter()
        .filter(|(k, v)| {
            let Some(pnpm_path) = v.as_str() else {
                return true;
            };
            lpm_patches
                .and_then(|m| m.get(*k))
                .is_none_or(|entry| entry.path != pnpm_path)
        })
        .map(|(k, _)| k.clone())
        .collect();
    if entries.is_empty() {
        return None;
    }
    entries.sort();

    Some(ManifestCompatIssue {
        code: "pnpm_patches_drift",
        severity: ManifestCompatSeverity::Warn,
        detail: format!(
            "package.json has {} `pnpm.patchedDependencies` entr{} that LPM doesn't honor: {}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            preview(&entries),
        ),
        remediation:
            "run `lpm migrate` to auto-translate (binds patch integrity from your lockfile), \
             or re-author with `lpm patch`. LPM reads `lpm.patchedDependencies` (with required \
             `originalIntegrity`) — not the `pnpm.patchedDependencies` namespace."
                .into(),
        entries,
    })
}

/// Detector: `pnpm.peerDependencyRules` has entries not mirrored in
/// `lpm.peerDependencyRules`.
///
/// Each of the three sub-keys is checked independently;
/// the issue lists every drifting entry across all three. Coverage
/// requires verbatim equality (same name in both ignoreMissing /
/// allowAny lists; same name + same range in allowedVersions). Same
/// raw key with a different range = drift, which fires the warning so
/// the user notices the divergent intent.
///
/// `entries` enumerate the drifting items, prefixed by which sub-key
/// they belong to so the doctor output is unambiguous:
/// `ignoreMissing:react`, `allowAny:@babel/*`, `allowedVersions:react`.
fn detect_pnpm_peer_rules_drift(pkg: &PackageJson) -> Option<ManifestCompatIssue> {
    let pnpm = pkg.pnpm.as_ref()?;
    let block = pnpm.peer_dependency_rules.as_object()?;
    if block.is_empty() {
        return None;
    }

    let lpm_rules = pkg
        .lpm
        .as_ref()
        .map(|l| &l.peer_dependency_rules)
        .cloned()
        .unwrap_or_default();

    let mut entries: Vec<String> = Vec::new();

    // ignoreMissing — list of names. Drifts when a pnpm-side name
    // isn't present (verbatim) in the lpm-side list. Non-string
    // entries always count as drift.
    if let Some(value) = block.get("ignoreMissing") {
        match value.as_array() {
            Some(arr) => {
                let lpm_set: std::collections::BTreeSet<&String> =
                    lpm_rules.ignore_missing.iter().collect();
                for item in arr {
                    match item.as_str() {
                        Some(name) => {
                            if !lpm_set.contains(&name.to_string()) {
                                entries.push(format!("ignoreMissing:{name}"));
                            }
                        }
                        None => entries.push("ignoreMissing:<non-string>".into()),
                    }
                }
            }
            None => entries.push("ignoreMissing:<wrong-shape>".into()),
        }
    }

    // allowAny — list of patterns. Same shape as ignoreMissing.
    if let Some(value) = block.get("allowAny") {
        match value.as_array() {
            Some(arr) => {
                let lpm_set: std::collections::BTreeSet<&String> =
                    lpm_rules.allow_any.iter().collect();
                for item in arr {
                    match item.as_str() {
                        Some(name) => {
                            if !lpm_set.contains(&name.to_string()) {
                                entries.push(format!("allowAny:{name}"));
                            }
                        }
                        None => entries.push("allowAny:<non-string>".into()),
                    }
                }
            }
            None => entries.push("allowAny:<wrong-shape>".into()),
        }
    }

    // allowedVersions — name → range map. Drifts when the name is
    // missing from the lpm side OR present with a different range.
    if let Some(value) = block.get("allowedVersions") {
        match value.as_object() {
            Some(map) => {
                for (name, range_value) in map {
                    let pnpm_range = match range_value.as_str() {
                        Some(s) => s,
                        None => {
                            entries.push(format!("allowedVersions:{name}"));
                            continue;
                        }
                    };
                    let covered = lpm_rules
                        .allowed_versions
                        .get(name)
                        .is_some_and(|r| r == pnpm_range);
                    if !covered {
                        entries.push(format!("allowedVersions:{name}"));
                    }
                }
            }
            None => entries.push("allowedVersions:<wrong-shape>".into()),
        }
    }

    if entries.is_empty() {
        return None;
    }
    entries.sort();

    Some(ManifestCompatIssue {
        code: "pnpm_peer_rules_drift",
        severity: ManifestCompatSeverity::Warn,
        detail: format!(
            "package.json has {} `pnpm.peerDependencyRules` entr{} that LPM doesn't honor: {}",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            preview(&entries),
        ),
        remediation:
            "run `lpm migrate` to translate them to `lpm.peerDependencyRules`, or copy entries \
             across by hand. LPM reads `lpm.peerDependencyRules` (same shape as \
             `pnpm.peerDependencyRules`) — not the `pnpm.peerDependencyRules` namespace."
                .into(),
        entries,
    })
}

/// Detector: `engines.npm` / `pnpm` / `yarn` / `bun` are present.
///
/// LPM does not enforce these constraints. This was previously a
/// one-line stderr warning emitted directly from the install pipeline
/// — moved here so `lpm doctor --json` exposes the same signal under
/// a stable code (`engines_<pm>_ignored`). One issue per declared
/// other-PM engine key, in the order documented by
/// [`OTHER_PM_ENGINE_KEYS`].
fn detect_engines_other_pm_ignored(pkg: &PackageJson) -> Vec<ManifestCompatIssue> {
    let mut out = Vec::new();
    for (key, code) in OTHER_PM_ENGINE_KEYS {
        if let Some(constraint) = pkg.engines.get(*key) {
            out.push(ManifestCompatIssue {
                code,
                severity: ManifestCompatSeverity::Warn,
                detail: format!(
                    "package.json has `engines.{key}` set ({constraint:?}) but LPM does not \
                     enforce it"
                ),
                remediation: "remove the field or use `engines.lpm` to constrain the LPM CLI \
                              version. LPM enforces `engines.lpm` and `engines.node` only."
                    .into(),
                entries: vec![(*key).to_string()],
            });
        }
    }
    out
}

/// Truncate a sorted entry list for embedding in a single-line
/// detail string. Shows up to five names; "+N more" tail beyond.
fn preview(entries: &[String]) -> String {
    const MAX: usize = 5;
    if entries.len() <= MAX {
        return entries.join(", ");
    }
    let head: Vec<&str> = entries.iter().take(MAX).map(String::as_str).collect();
    format!("{}, +{} more", head.join(", "), entries.len() - MAX)
}

/// Permissive `HashMap<String, String>` deserializer that accepts a
/// JSON object with mixed string / non-string values, keeps only the
/// `String`-valued entries, and silently drops the rest with a
/// debug-level trace. Used for `package.json > overrides` and
/// `package.json > resolutions` where the npm/yarn specs allow nested
/// object values (e.g. `"path-scurry": {"lru-cache": "^11.3.5"}`) that
/// LPM doesn't currently apply.
///
/// **Why drop instead of fail.** A transitive dep's `package.json` may
/// contain override shapes LPM doesn't support; failing the whole parse
/// blocks `lpm-linker::create_bin_links` (and every other consumer of
/// `read_package_json`) for that dep. The lossy parse preserves the
/// supported entries while letting the rest of the manifest be read.
///
/// Pinned by the rollup-plugins audit fixture: pre-fix, rollup's
/// `"overrides": { "path-scurry": {"lru-cache": "^11.3.5"}, ... }` made
/// `read_package_json` return `Err(parse error: invalid type: map,
/// expected a string at line 246 column 19)`, which made the linker's
/// bin-link step skip rollup, leaving `node_modules/.bin/rollup`
/// unwritten and `rollup --version` failing.
fn deserialize_lossy_string_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: HashMap<String, serde_json::Value> = HashMap::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::String(s) => Some((k, s)),
            // Non-string values (nested override objects) are silently
            // dropped — LPM does not currently apply nested overrides,
            // and erroring here would block the entire `read_package_json`
            // call (used far more broadly than override application).
            _ => None,
        })
        .collect())
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

    /// node_modules linker mode: `"isolated"` (default, pnpm-style) or
    /// `"hoisted"` (npm-style). Validated against
    /// `lpm_linker::LinkerMode::parse_str` at install time — unknown values
    /// fail loudly rather than silently falling back.
    #[serde(default)]
    pub linker: Option<String>,

    /// Packages trusted to run lifecycle scripts (postinstall, etc).
    ///
    /// Schema migration: this field accepts BOTH the legacy `Vec<String>` form
    /// (`["esbuild", "sharp"]`) AND the rich map form
    /// (`{"esbuild@0.25.1": {"integrity": "...", "scriptHash": "..."}}`).
    /// See [`TrustedDependencies`] for the discriminant rules and migration semantics.
    #[serde(default, rename = "trustedDependencies")]
    pub trusted_dependencies: TrustedDependencies,

    /// Minimum release age in seconds before install is allowed (default: 86400 = 24h).
    #[serde(default, rename = "minimumReleaseAge")]
    pub minimum_release_age: Option<u64>,

    /// Whether `engines.lpm` and `engines.node` constraints from the
    /// workspace root are enforced. Default `true` (enforced) when
    /// unset.
    ///
    /// Read by [`crate::engine_check`] in `lpm-cli` (via the workspace
    /// root manifest only — member values are not consulted, matching
    /// the "root manifest is the gate" model documented in the
    /// `engines enforcement` section of the install docs).
    #[serde(default, rename = "engineStrict")]
    pub engine_strict: Option<bool>,

    /// LPM-native overrides location. Mirrors pnpm's `pnpm.overrides` and
    /// npm's top-level `overrides`, but declared inside the `"lpm"` section
    /// so package authors can keep all LPM-aware config grouped together.
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

    /// Local-only patches applied to packages after install (the
    /// `patch-package` workflow). Map of selector → patch metadata.
    ///
    /// Selector format: `"<name>@<exact-version>"` (e.g.,
    /// `"lodash@4.17.21"`). Only exact-version pins are accepted today;
    /// range selectors are not supported yet.
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

    /// Peer-dependency rules for the resolver. Mirrors pnpm's
    /// `pnpm.peerDependencyRules` shape verbatim so `lpm migrate` can
    /// move pnpm authors over without surgery.
    ///
    /// Three independent sub-keys; each addresses a distinct
    /// peer-dependency complaint:
    ///
    /// - **`ignoreMissing`** — names (or glob patterns) whose
    ///   missing-peer warnings are suppressed. Use when a peer is
    ///   intentionally optional.
    /// - **`allowedVersions`** — selector → widened version range.
    ///   When the resolved peer's version doesn't satisfy the
    ///   package's declared `peerDependencies` range, this widened
    ///   range is tested as a fallback. **Selector grammar mirrors
    ///   [`LpmConfig::overrides`]:** `"react"` (any consumer),
    ///   `"foo>react"` (peer of foo), `"foo@^2>react"` (peer of foo
    ///   whose version satisfies `^2`), and the scoped variants.
    ///   Multi-segment paths and ambiguous bare-name-with-version
    ///   forms (`"foo@2"` without `>`) are rejected at compile
    ///   time. Glob patterns are NOT accepted here — use the
    ///   structured selector grammar instead.
    /// - **`allowAny`** — names (or glob patterns). When the resolved
    ///   peer is in the tree at any version, the version-mismatch
    ///   warning for matched names is suppressed. Does NOT suppress
    ///   missing-peer warnings (use `ignoreMissing` for that).
    ///
    /// **Fail-closed at install time.** Any unparseable selector key
    /// or widened range in `allowedVersions` aborts the install with
    /// `LpmError::Script`, naming the offending entry — same posture
    /// as `lpm.overrides`. Migrate validates pnpm-side keys via the
    /// same parser before any disk mutation, so the two surfaces
    /// can never disagree on what's accepted.
    ///
    /// See [`PeerDependencyRules`] for the on-disk shape and
    /// [`lpm_resolver::CompiledPeerRules`] for the runtime matcher.
    #[serde(default, rename = "peerDependencyRules")]
    pub peer_dependency_rules: PeerDependencyRules,

    /// Eager peer auto-install opt-out.
    ///
    /// When `true` (or unset), missing non-optional peer dependencies
    /// are automatically promoted to ambient root-scoped installs by
    /// the resolver — bun-parity behavior. When `false`, missing peers
    /// fall back to pre-R2 warn-only semantics: the post-resolve
    /// [`lpm_resolver::check_unmet_peers`] pass surfaces them as
    /// `PeerWarning`s and the user manually adds them to
    /// `dependencies`.
    ///
    /// **Default is `true` (auto-install on)** — beta-default favors
    /// the eager model so peer-declaring packages "just work" without
    /// the user having to re-read the install log to find missing
    /// names. Set to `false` for the pnpm-classic / npm-classic
    /// experience.
    ///
    /// Precedence (resolved in `install.rs`):
    ///   `package.json > lpm > autoInstallPeers`
    ///   → `~/.lpm/config.toml > auto-install-peers`
    ///   → default (`true`).
    ///
    /// Optional peers (`peerDependenciesMeta.<name>.optional = true`)
    /// are NEVER auto-installed regardless of this flag — the manifest
    /// author opted out of the dependency entirely.
    #[serde(default, rename = "autoInstallPeers")]
    pub auto_install_peers: Option<bool>,
}

/// `package.json :: lpm.peerDependencyRules` — peer-dep behavior
/// rules consumed by the resolver's post-resolution peer-warning
/// pass.
///
/// Shape mirrors pnpm's `pnpm.peerDependencyRules` exactly so
/// `lpm migrate` can translate without value transformation. See the
/// [`LpmConfig::peer_dependency_rules`] field doc for per-sub-key
/// semantics.
///
/// All three fields default to empty — a missing
/// `lpm.peerDependencyRules` block is the same as one with all
/// three lists/maps empty (no rules applied).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerDependencyRules {
    /// Names (or glob patterns) whose missing-peer warnings are
    /// suppressed. `["@babel/*", "react"]` suppresses missing
    /// warnings for any package in the `@babel` scope plus the
    /// literal `react`.
    #[serde(default, rename = "ignoreMissing")]
    pub ignore_missing: Vec<String>,

    /// Map of selector → widened version range. When the declared
    /// peer range isn't satisfied by the resolved version, this
    /// widened range is tried as a fallback.
    ///
    /// **Selector grammar (same as [`LpmConfig::overrides`])**:
    ///
    /// | Key form | Matches |
    /// | --- | --- |
    /// | `"react"` | any peer named `react`, regardless of consumer |
    /// | `"@scope/foo"` | scoped peer name, any consumer |
    /// | `"foo>react"` | `react` peer of `foo` (any version of foo) |
    /// | `"foo@^2>react"` | `react` peer of `foo` whose version satisfies `^2` |
    /// | `"@scope/foo@^2>react"` | scoped parent + version range |
    ///
    /// Examples:
    ///
    /// - `"react": "16 || 17 || 18"` widens every react peer to
    ///   accept those three majors.
    /// - `"foo@^2>react": "17"` only widens the rule for foo@^2's
    ///   react peer; foo@1 keeps the original range.
    ///
    /// Multi-segment paths (`a>b>c`) and standalone version
    /// qualifiers on bare keys (`"foo@2"` without `>`) are rejected
    /// at compile time. Glob patterns (`@scope/*`) are NOT accepted
    /// here — use the structured selector grammar above.
    #[serde(default, rename = "allowedVersions")]
    pub allowed_versions: HashMap<String, String>,

    /// Names (or glob patterns) whose version-mismatch warnings are
    /// suppressed when the peer is in the tree. The peer must
    /// still be present — `allowAny` does NOT suppress missing-peer
    /// warnings (combine with `ignoreMissing` if you want both).
    ///
    /// Example: `allowAny: ["@babel/*"]` suppresses every
    /// "@babel/foo declares peer @babel/core@^7.20 but @babel/core@7.5
    /// resolved" warning across the babel ecosystem.
    #[serde(default, rename = "allowAny")]
    pub allow_any: Vec<String>,
}

impl PeerDependencyRules {
    /// `true` iff every list/map is empty — a no-op rule set.
    pub fn is_empty(&self) -> bool {
        self.ignore_missing.is_empty()
            && self.allowed_versions.is_empty()
            && self.allow_any.is_empty()
    }
}

/// `package.json :: lpm.patchedDependencies` map value.
///
/// Records the patch file path (relative to the `package.json` directory)
/// and the integrity binding to the store baseline the patch was generated
/// against.
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
/// bare-name array form and the rich version-bound map form.
///
/// ## Forms
///
/// **Legacy** (bare-name array):
///
/// ```json
/// "trustedDependencies": ["esbuild", "sharp"]
/// ```
///
/// **Rich** (version-bound map):
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
/// - **Write:** `lpm approve-scripts` upgrades any Legacy variant to Rich on
///   the first new approval. The `lpm rebuild` strict gate accepts both forms;
///   legacy bare-name entries match by name only and produce a deprecation warning.
/// - **Coexistence:** a manifest stays in the Legacy form until the first
///   approval is made through `lpm approve-scripts`, at which point it
///   migrates to the Rich form and stays there. There is no downgrade path.
///   Existing entries in a Legacy array are preserved during the upgrade —
///   they become Rich entries with `binding: None` (name only, no integrity,
///   no script hash).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TrustedDependencies {
    /// Legacy form: `["esbuild", "sharp"]`. Bare package names with no
    /// version, integrity, or script hash binding. The strict gate accepts
    /// these as `LegacyNameOnly` matches with a deprecation warning.
    Legacy(Vec<String>),
    /// Rich form: `{"esbuild@0.25.1": {integrity, scriptHash}}`. The key
    /// is `name@version`; the value is the integrity + scriptHash binding
    /// metadata.
    Rich(HashMap<String, TrustedDependencyBinding>),
}

// `ProvenanceSnapshot` lives in `lpm-common` so `lpm-global` (which
// deliberately does not depend on `lpm-workspace`) can share the canonical
// serde shape with project-level `TrustedDependencyBinding`. Callers that
// already import from `lpm_workspace` continue to work via this re-export.
pub use lpm_common::ProvenanceSnapshot;

/// Binding metadata for one entry in a Rich `trustedDependencies` map.
///
/// Both fields are `Option<String>` because approvals from the legacy upgrade
/// path carry no integrity or script hash (the user approved by name only).
/// When `lpm approve-scripts` writes a new approval, both fields are populated
/// from the install-time blocked-set in `<project_dir>/.lpm/build-state.json`.
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
    /// Snapshot of the publisher identity tuple captured at approval time.
    /// Used by the install-time drift check to detect publisher-identity
    /// drift between the approved version and a candidate version.
    ///
    /// `None` means the binding predates provenance capture (legacy upgrade
    /// path) OR the approved version had no provenance attestation. Both
    /// cases degrade to "cannot detect drift" — the script-hash and
    /// integrity checks still fire independently.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]` keeps
    /// older `trustedDependencies` entries round-tripping unchanged.
    #[serde(
        default,
        rename = "provenanceAtApproval",
        skip_serializing_if = "Option::is_none"
    )]
    pub provenance_at_approval: Option<ProvenanceSnapshot>,
    /// SHA-256 over the sorted canonical names of the active behavioral
    /// tags (per `lpm_security::triage::hash_behavioral_tag_set`) at
    /// approval time. Stored alongside the candidate-side hash on
    /// `BlockedPackage` so the version-diff UI can detect behavioral-tag
    /// drift with a single equality check, without re-fetching metadata.
    ///
    /// `None` for approvals without behavioral analysis (offline, registry
    /// fetch error, or the registry carried no analysis). Two `None`s are
    /// treated as "no signal, don't claim drift" by `compute_version_diff`.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]`.
    #[serde(
        default,
        rename = "behavioralTagsHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavioral_tags_hash: Option<String>,
    /// Sorted canonical names of the active behavioral tags whose hash is
    /// `behavioral_tags_hash`. Persisted so the version-diff UI can render
    /// the delta ("gained network, eval") rather than just "tags changed".
    ///
    /// Both fields are populated from one `active_tag_names()` call so the
    /// hash and the names cannot drift apart. `None` whenever
    /// `behavioral_tags_hash` is `None`; `Some(vec![])` when the version
    /// had analysis but every tag was false.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]`.
    #[serde(
        default,
        rename = "behavioralTags",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavioral_tags: Option<Vec<String>>,
    /// SHA-256 (`sha256-<hex>` SRI form) over the canonical serialization
    /// of the per-package capability set the user granted at approval time.
    /// Canonicalization is owned by `lpm_cli::capability::CapabilitySet::
    /// canonical_hash`; this field only stores the result.
    ///
    /// # Semantic when `None`
    ///
    /// `None` means a legacy approval — the user never reviewed a specific
    /// capability request. Such approvals grant the baseline capability set
    /// only: empty `passEnv`, `readProject = Narrow`, no `sandboxLimits`
    /// bumps. A request that loosens any of those MUST NOT be satisfied by
    /// a legacy approval.
    ///
    /// The match decision lives in
    /// [`lpm_cli::capability::CapabilitySet::is_approved_by`]
    /// (this crate intentionally does not import the capability types to keep
    /// the dep graph acyclic). Callers must route through that method; do NOT
    /// compare this field directly against a hash string in enforcement code.
    ///
    /// # Semantic when `Some(hash)`
    ///
    /// Binds the approval to the **exact** capability set whose
    /// `canonical_hash()` equals `hash`. Any drift produces a different hash
    /// and invalidates the approval — forcing a re-review before the widened
    /// request takes effect.
    ///
    /// Non-breaking via `#[serde(default, skip_serializing_if)]`: old records
    /// deserialize with `None` and never silently widen.
    #[serde(
        default,
        rename = "capabilityHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_hash: Option<String>,
}

impl Default for TrustedDependencies {
    fn default() -> Self {
        // Default to the LEGACY form so a missing field deserializes as an
        // empty approval list. Existing manifests with no `trustedDependencies`
        // key round-trip as `Vec::new()` and are never accidentally migrated
        // to the Rich form on a no-op read.
        TrustedDependencies::Legacy(Vec::new())
    }
}

/// Bundle of install-time-captured metadata that `lpm approve-scripts`
/// persists onto a [`TrustedDependencyBinding`] via
/// [`TrustedDependencies::approve_with_metadata`].
///
/// All fields are `Option` because each degrades independently to "not
/// captured" under offline or fetch-error conditions; downstream gates
/// treat `None` as "no signal, don't claim drift."
///
/// All fields are sourced from the matching candidate `BlockedPackage`.
#[derive(Debug, Clone, Default)]
pub struct ApprovalMetadata {
    /// SRI integrity hash from the lockfile.
    pub integrity: Option<String>,
    /// Deterministic script hash from
    /// `lpm_security::script_hash::compute_script_hash`.
    pub script_hash: Option<String>,
    /// Publisher-identity snapshot from the registry's Sigstore attestation.
    pub provenance_at_approval: Option<ProvenanceSnapshot>,
    /// SHA-256 over the sorted active behavioral-tag names.
    pub behavioral_tags_hash: Option<String>,
    /// Sorted active behavioral-tag names — the rendering input for the
    /// version-diff "gained / lost" delta.
    pub behavioral_tags: Option<Vec<String>>,
    /// Canonical hash of the per-package `CapabilitySet` the user granted
    /// at approval time. Persists into [`TrustedDependencyBinding::capability_hash`];
    /// enforcement consults it via `CapabilitySet::is_approved_by`.
    ///
    /// `None` means the package requested no extras (baseline) OR the approval
    /// was written by a legacy path. Both degrade to "approved with no extra
    /// capabilities" — they cannot silently widen.
    ///
    /// The hash MUST come from the same `CapabilitySet` object the runtime
    /// will later enforce against. Callers must parse the capability set once
    /// per `approve-scripts` invocation and thread the same object through to
    /// both the prompt renderer and this field.
    pub capability_hash: Option<String>,
}

/// The result of looking up a package in `trustedDependencies`.
/// See [`TrustedDependencies::matches_strict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMatch {
    /// Rich entry with all four fields equal to the queried values.
    /// `lpm rebuild` runs the script.
    Strict,
    /// Name appears in a Legacy `Vec<String>` entry. `lpm rebuild` runs the
    /// script with a deprecation warning suggesting `lpm approve-scripts` to
    /// upgrade to a strict binding.
    LegacyNameOnly,
    /// Rich entry exists for this `name@version` but at least one of
    /// `integrity` / `script_hash` differs from the queried values.
    /// `lpm rebuild` SKIPS the script and surfaces the drift to the user.
    BindingDrift {
        /// The binding currently stored in `package.json` (so callers
        /// can show a diff). Boxed because `TrustedDependencyBinding` grew
        /// past clippy's `large_enum_variant` threshold; boxing the drift
        /// variant keeps the no-data sibling variants cheap.
        stored: Box<TrustedDependencyBinding>,
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

    /// Strict trust query — the default gate for `lpm rebuild`.
    ///
    /// Returns:
    /// - [`TrustMatch::Strict`] if the Rich variant has a `name@version`
    ///   entry whose stored `integrity` and `script_hash` BOTH equal the
    ///   queried values. `None` on either side counts as "no constraint" —
    ///   intentional for the legacy-upgrade path where a Rich entry was
    ///   inserted before the binding fields were known.
    /// - [`TrustMatch::BindingDrift`] if a Rich entry exists for the
    ///   `name@version` key but at least one binding field is set on BOTH
    ///   sides and they differ.
    /// - [`TrustMatch::LegacyNameOnly`] if the Legacy variant contains the
    ///   bare `name` string, OR if the Rich variant contains a `<name>@*`
    ///   preserve key (the migration sentinel from [`Self::upgrade_to_rich`]).
    ///   Caller should warn about deprecation.
    /// - [`TrustMatch::NotTrusted`] otherwise.
    ///
    /// The `<name>@*` preserve-key path is essential: without it, a manifest
    /// like `["esbuild"]` would lose esbuild's approval on the first
    /// `lpm approve-scripts --yes` upgrade (which rewrites it to `esbuild@*`)
    /// because the strict gate would only match concrete version keys.
    ///
    /// **Lookup precedence:** the concrete `name@version` key wins over the
    /// `name@*` preserve key when both exist for the same name.
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
                            stored: Box::new(stored.clone()),
                        };
                    }
                    return TrustMatch::Strict;
                }

                // Step 2: fall back to the `<name>@*` preserve key. This is
                // the legacy-upgrade migration path. The bindings on these
                // entries are intentionally None — they encode "trust this
                // name only" without integrity/script_hash constraints, so
                // they MUST NOT be checked for drift.
                let star_key = format!("{name}@*");
                if map.contains_key(&star_key) {
                    return TrustMatch::LegacyNameOnly;
                }

                TrustMatch::NotTrusted
            }
        }
    }

    /// Lenient name-only check. Used by the existing `lpm rebuild` code
    /// path before `matches_strict` was introduced, and by logic that
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

    /// Look up the rich binding for a specific `name@version`.
    ///
    /// Used by the capability-hash enforcement path to obtain the
    /// [`TrustedDependencyBinding`] whose
    /// [`TrustedDependencyBinding::capability_hash`] the caller feeds to
    /// `lpm_cli::capability::CapabilitySet::is_approved_by`.
    ///
    /// Lookup precedence mirrors [`Self::matches_strict`]:
    /// - Rich entries: concrete `{name}@{version}` key wins; the
    ///   `{name}@*` preserve-key fallback is the secondary match.
    /// - Legacy entries: returns `None` — the legacy form has no binding.
    ///   Callers treat `None` as "legacy approval, no capability hash stored,"
    ///   which collapses via `is_approved_by` to the baseline-only semantic.
    pub fn get_binding(&self, name: &str, version: &str) -> Option<&TrustedDependencyBinding> {
        match self {
            TrustedDependencies::Legacy(_) => None,
            TrustedDependencies::Rich(map) => {
                let concrete_key = Self::rich_key(name, version);
                if let Some(b) = map.get(&concrete_key) {
                    return Some(b);
                }
                let star_key = format!("{name}@*");
                map.get(&star_key)
            }
        }
    }

    /// Iterate over (name, optional binding). Legacy entries yield `None`
    /// for the binding. Used by introspection paths like
    /// `lpm approve-scripts --list`.
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
    /// Used by `lpm approve-scripts` BEFORE inserting any new approval so
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
                    behavioral_tags_hash: None,
                    behavioral_tags: None,
                    // The `<name>@*` migration sentinel carries no capability
                    // grant: None = "legacy approval, baseline only".
                    capability_hash: None,
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
    /// Metadata-agnostic variant — persists `provenance_at_approval`,
    /// `behavioral_tags_hash`, and `behavioral_tags` as `None`. Production
    /// callers (the `lpm approve-scripts` flow) use
    /// [`Self::approve_with_metadata`] so the drift-check and version-
    /// diff references are populated from the install-time capture.
    pub fn approve(
        &mut self,
        name: &str,
        version: &str,
        integrity: Option<String>,
        script_hash: Option<String>,
    ) -> bool {
        self.approve_with_metadata(
            name,
            version,
            ApprovalMetadata {
                integrity,
                script_hash,
                provenance_at_approval: None,
                behavioral_tags_hash: None,
                behavioral_tags: None,
                capability_hash: None,
            },
        )
    }

    /// Insert / overwrite an approval entry with the install-time-captured
    /// metadata bundle. Equivalent to [`Self::approve`] but carries provenance,
    /// behavioral-tag hash, and capability-hash fields through to the binding so
    /// subsequent installs can compare against them.
    ///
    /// The caller (`lpm approve-scripts`) reads the metadata from the
    /// install-time `BlockedPackage`. This closes the round-trip: capture →
    /// `BlockedPackage` → binding → next install's drift / version-diff check.
    ///
    /// Passing all-`None` metadata is identical to [`Self::approve`].
    pub fn approve_with_metadata(
        &mut self,
        name: &str,
        version: &str,
        meta: ApprovalMetadata,
    ) -> bool {
        self.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = self else {
            unreachable!("upgrade_to_rich left us in Rich state")
        };
        let key = Self::rich_key(name, version);
        map.insert(
            key,
            TrustedDependencyBinding {
                integrity: meta.integrity,
                script_hash: meta.script_hash,
                provenance_at_approval: meta.provenance_at_approval,
                behavioral_tags_hash: meta.behavioral_tags_hash,
                behavioral_tags: meta.behavioral_tags,
                // `None` is valid: baseline approval with no extras requested.
                // The match rule interprets `None` as "approved baseline only."
                capability_hash: meta.capability_hash,
            },
        )
        .is_some()
    }

    /// Find the provenance-bearing approval entry for this package name whose
    /// version sorts highest. Returns `(version, binding)` as the reference
    /// point for the install-time drift check.
    ///
    /// Filtering to provenance-bearing entries only is the safer default:
    /// if `axios@1.14.0` was approved WITH provenance and `axios@1.13.5`
    /// WITHOUT, comparing a candidate against the 1.13.5 binding would
    /// short-circuit to `NoDrift` and mask the signal.
    ///
    /// The returned version string is the part after the LAST `@` in the
    /// rich-map key, so scoped names like `@scope/pkg@1.0.0` correctly
    /// split into `@scope/pkg` + `1.0.0`.
    ///
    /// ## Determinism
    ///
    /// `HashMap` iteration order is non-deterministic. Selecting "the first
    /// match" would make the drift verdict flip across runs when multiple
    /// provenance-bearing approvals for the same package carry different
    /// identities. Instead, this selects the entry with the lexicographically-
    /// maximum version string — deterministic and correct for consistent-digit-
    /// width versions; wrong for `1.10.0` vs `1.9.0` (lex picks `1.9.0`).
    /// Proper semver ordering can replace this later; determinism is the
    /// load-bearing property here.
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

    /// Find the approved binding for this package name whose version is the
    /// lexicographic-max STRICTLY LESS THAN the given candidate version.
    /// Returns `(version, binding)` as the reference point for the version-diff UI.
    ///
    /// Differences from [`Self::provenance_reference_for_name`]:
    /// - Not filtered by provenance presence — script-hash and behavioral-tag
    ///   drift can be rendered even without a provenance capture.
    /// - Strictly less than `candidate_version`: on re-install of the same
    ///   version there is nothing to diff, so returns `None`.
    /// - Skips `@*` legacy preserve-key entries — they're migration sentinels,
    ///   not concrete prior approvals with binding metadata to diff.
    ///
    /// Lex-max selection (same as [`Self::provenance_reference_for_name`])
    /// keeps the diff UI and the drift gate in sync on which version is the
    /// "prior approval."
    pub fn latest_binding_for_name(
        &self,
        name: &str,
        candidate_version: &str,
    ) -> Option<(&str, &TrustedDependencyBinding)> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        map.iter()
            .filter_map(|(key, binding)| {
                let (n, v) = key.rsplit_once('@')?;
                // Skip the `@*` legacy preserve key: it's a migration
                // sentinel, not a real approval, and `*` would out-sort
                // every concrete version under lex-max (`*` > any
                // digit). Pre-filter so the preserve key can't poison
                // the reduction.
                if n == name && v != "*" && v < candidate_version {
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

/// Pair of maps returned by [`read_peer_dependencies`].
pub type PeerDepsResult = (HashMap<String, String>, HashMap<String, PeerDependencyMeta>);

/// Read only `peerDependencies` and `peerDependenciesMeta` from a `package.json`.
///
/// Uses a minimal deserialization struct — serde_json skips all other fields
/// (dependencies, devDependencies, name, version, scripts, …) without allocating
/// strings for their keys or values. Saves ~30-40 allocs per package on warm
/// installs where `ensure_peer_context` reads every store object's manifest.
pub fn read_peer_dependencies(path: &Path) -> Result<PeerDepsResult, WorkspaceError> {
    let content = std::fs::read(path)
        .map_err(|e| WorkspaceError::Io(format!("failed to read {}: {e}", path.display())))?;
    parse_peer_dependencies(&content)
        .map_err(|e| WorkspaceError::Parse(format!("failed to parse {}: {e}", path.display())))
}

/// Parse peer-dependency info from already-read JSON bytes.
///
/// Callers that first byte-scan for `b"peerDependencies"` before calling
/// this can skip the full `serde_json` parse for packages with no peer
/// deps — the common case for the majority of packages in any install set.
/// See `ensure_peer_context` in `lpm-linker` for the canonical call site.
pub fn parse_peer_dependencies(content: &[u8]) -> Result<PeerDepsResult, WorkspaceError> {
    #[derive(serde::Deserialize, Default)]
    struct PeerDepsOnly {
        #[serde(default, rename = "peerDependencies")]
        peer_dependencies: HashMap<String, String>,
        #[serde(default, rename = "peerDependenciesMeta")]
        peer_dependencies_meta: HashMap<String, PeerDependencyMeta>,
    }
    let parsed: PeerDepsOnly = serde_json::from_slice(content)
        .map_err(|e| WorkspaceError::Parse(format!("parse error: {e}")))?;
    Ok((parsed.peer_dependencies, parsed.peer_dependencies_meta))
}

/// Parse only the `bin` field from already-read `package.json` bytes.
///
/// Uses a one-field deserialization struct so serde_json skips every other
/// field (`dependencies`, `scripts`, `peerDependencies`, …) without
/// allocating strings for their keys or values. Callers that additionally
/// byte-scan for `b"\"bin\""` before calling this can skip the parse
/// entirely for packages that declare no binary — the common case.
///
/// See `create_bin_links_v2` in `lpm-linker` for the canonical call site.
pub fn parse_bin_field(content: &[u8]) -> Result<Option<BinConfig>, WorkspaceError> {
    #[derive(serde::Deserialize, Default)]
    struct BinOnly {
        #[serde(default)]
        bin: Option<BinConfig>,
    }
    let parsed: BinOnly = serde_json::from_slice(content)
        .map_err(|e| WorkspaceError::Parse(format!("parse error: {e}")))?;
    Ok(parsed.bin)
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

    /// Regression test for the rollup-plugins audit fixture. rollup's
    /// `package.json` ships `overrides` with a nested-object value
    /// (`"path-scurry": {"lru-cache": "^11.3.5"}`) — valid npm syntax for
    /// "only override `lru-cache` when `path-scurry` is in scope." The
    /// pre-fix `HashMap<String, String>` deserializer errored on this
    /// shape ("invalid type: map, expected a string"), making the entire
    /// `read_package_json` call fail and silently breaking
    /// `lpm-linker::create_bin_links` (no `node_modules/.bin/rollup`).
    ///
    /// Post-fix, `read_package_json` succeeds: simple string-valued
    /// overrides are kept, nested-object ones are dropped (LPM's
    /// resolver doesn't apply them yet).
    #[test]
    fn read_package_json_keeps_string_overrides_drops_nested_objects() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "fixture-with-nested-overrides",
                "version": "1.0.0",
                "bin": {"some-cli": "./bin/cli.js"},
                "overrides": {
                    "axios": "^1.15.2",
                    "esbuild": ">0.24.2",
                    "path-scurry": {"lru-cache": "^11.3.5"},
                    "vite": "$vite"
                },
                "resolutions": {
                    "lodash": "^4.17.21",
                    "deeply-nested": {"transitive": "1.0.0"}
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json"))
            .expect("nested-object overrides must not block the parse");

        // String-valued overrides are kept.
        assert_eq!(
            pkg.overrides.get("axios").map(String::as_str),
            Some("^1.15.2"),
            "simple overrides must round-trip"
        );
        assert_eq!(
            pkg.overrides.get("esbuild").map(String::as_str),
            Some(">0.24.2")
        );
        assert_eq!(pkg.overrides.get("vite").map(String::as_str), Some("$vite"));

        // Nested-object override is silently dropped (LPM doesn't apply nested overrides yet).
        assert!(
            !pkg.overrides.contains_key("path-scurry"),
            "nested-object override entry must be dropped"
        );

        // Same handling for resolutions.
        assert_eq!(
            pkg.resolutions.get("lodash").map(String::as_str),
            Some("^4.17.21")
        );
        assert!(!pkg.resolutions.contains_key("deeply-nested"));

        // Crucially, the rest of the manifest survives — the bin field
        // is what the audit fixture cares about, and pre-fix the entire
        // parse failed before reaching this point.
        let bin = pkg.bin.as_ref().expect("bin must be parsed");
        let entries = bin.entries(pkg.name.as_deref().unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "some-cli");
    }

    /// Drift-guard: every code emitted by `manifest_compat_issues()`
    /// in production must have a matching entry in
    /// [`MANIFEST_COMPAT_CATALOG`]. Asserted across a fixture that
    /// exercises every detector. Catches "added a new detector,
    /// forgot to register it in the catalog" at review time.
    #[test]
    fn manifest_compat_catalog_covers_every_emitted_code() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "drift-guard",
                "version": "1.0.0",
                "engines": {"node": ">=22", "npm": ">=10", "pnpm": ">=9", "yarn": ">=4", "bun": ">=1"},
                "pnpm": {
                    "overrides": {"lodash": "^4.17.21"},
                    "patchedDependencies": {"react@18.0.0": "patches/react.patch"},
                    "peerDependencyRules": {
                        "ignoreMissing": ["react"]
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(
            !issues.is_empty(),
            "fixture must trigger at least one detector"
        );

        for issue in &issues {
            let in_catalog = MANIFEST_COMPAT_CATALOG
                .iter()
                .any(|entry| entry.code == issue.code);
            assert!(
                in_catalog,
                "manifest-compat code `{}` is emitted but missing from MANIFEST_COMPAT_CATALOG",
                issue.code
            );
        }

        // Also assert every catalog entry has a unique code (catches
        // duplicated rows with identical codes that would confuse the
        // doctor list output).
        let codes: Vec<&str> = MANIFEST_COMPAT_CATALOG.iter().map(|e| e.code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            codes.len(),
            sorted.len(),
            "MANIFEST_COMPAT_CATALOG has duplicate codes"
        );
    }

    #[test]
    fn manifest_compat_catalog_entries_declare_known_severities() {
        // Every catalog entry's possible_severities must be drawn from
        // the {pass, warn, fail} set so cross-crate consumers don't
        // need to special-case unknown values.
        for entry in MANIFEST_COMPAT_CATALOG {
            for sev in entry.possible_severities {
                assert!(
                    matches!(*sev, "pass" | "warn" | "fail"),
                    "catalog entry `{}` declares unknown severity `{}`",
                    entry.code,
                    sev
                );
            }
            assert!(
                !entry.possible_severities.is_empty(),
                "catalog entry `{}` declares no severities",
                entry.code
            );
        }
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
                    "linker": "isolated"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.strict_deps.as_deref(), Some("strict"));
        assert_eq!(lpm.linker.as_deref(), Some("isolated"));
    }

    /// `lpm.linker` is read as `Option<String>` at deserialization time so
    /// every command that touches `package.json` can be tolerant — the
    /// install pipeline runs `lpm_linker::LinkerMode::parse_str` and rejects
    /// unknown values (including the legacy `"symlink"` alias) loudly. This
    /// test pins that the deserialize layer doesn't enforce, so a stricter
    /// future seam can't accidentally drop the install-time validator and
    /// land a silent fallback again.
    #[test]
    fn lpm_linker_accepts_arbitrary_strings_at_deserialize_layer() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "lpm": { "linker": "symlink" }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let lpm = pkg.lpm.unwrap();
        // Deserialize: tolerant. Validation: install-time.
        assert_eq!(lpm.linker.as_deref(), Some("symlink"));
    }

    /// `lpm.overrides` deserializes as a `HashMap<String, String>`.
    /// The downstream parser (`lpm_resolver::OverrideSet::parse`) does
    /// the validation.
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

    /// `lpm.overrides` defaults to an empty map when absent.
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

    // ── pnpm-compat detection ────────────────────────────────────────────

    /// `pnpm.overrides` deserializes successfully even when LPM has no
    /// equivalent fields. The struct stays tolerant — we don't reject
    /// unknown shapes at parse time.
    #[test]
    fn read_package_json_captures_pnpm_overrides() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": {
                        "lodash": "^4.17.21",
                        "foo>bar": "1.0.0"
                    }
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let pnpm = pkg.pnpm.expect("pnpm field should deserialize");
        let overrides = pnpm
            .overrides
            .as_object()
            .expect("overrides should be an object");
        assert_eq!(
            overrides.get("lodash").and_then(|v| v.as_str()),
            Some("^4.17.21")
        );
        assert_eq!(
            overrides.get("foo>bar").and_then(|v| v.as_str()),
            Some("1.0.0")
        );
    }

    /// Unknown / object-shaped pnpm.overrides values must not break
    /// parsing. They're surfaced as structured errors at migrate /
    /// install time, not at deserialization.
    #[test]
    fn read_package_json_tolerates_unsupported_pnpm_shapes() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": {
                        "lodash": { "version": "^4.17.21" },
                        "react": null,
                        "vue": ["3.0.0"]
                    },
                    "unknownFutureField": "anything"
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json"))
            .expect("unsupported shapes must not fail parsing");
        let pnpm = pkg.pnpm.expect("pnpm field should still deserialize");
        let overrides = pnpm.overrides.as_object().unwrap();
        assert!(overrides.get("lodash").unwrap().is_object());
        assert!(overrides.get("react").unwrap().is_null());
        assert!(overrides.get("vue").unwrap().is_array());
    }

    /// Helper: convenience to filter manifest-compat issues by code.
    fn issue_with_code<'a>(
        issues: &'a [ManifestCompatIssue],
        code: &str,
    ) -> Option<&'a ManifestCompatIssue> {
        issues.iter().find(|i| i.code == code)
    }

    /// `manifest_compat_issues()` returns an empty vec when there's no
    /// pnpm namespace and no other-PM engine pins.
    #[test]
    fn manifest_compat_no_issues_when_clean_manifest() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name": "plain"}"#);

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(
            issues.is_empty(),
            "expected no compat issues for a plain manifest; got {issues:?}"
        );
    }

    /// `pnpm.overrides` populated, no LPM-side equivalent → drift
    /// issue fires with the divergent keys enumerated.
    #[test]
    fn pnpm_overrides_drift_when_no_lpm_side_lists_uncovered_keys() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21", "react": "^18.0.0" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_overrides_drift")
            .expect("expected pnpm_overrides_drift when only pnpm.overrides is set");
        assert_eq!(drift.severity, ManifestCompatSeverity::Warn);
        // Entries enumerated, sorted, and complete.
        assert_eq!(
            drift.entries,
            vec!["lodash".to_string(), "react".to_string()]
        );
        // Detail surfaces the actual keys so users see what's drifting.
        assert!(drift.detail.contains("lodash"));
        assert!(drift.detail.contains("react"));
        // Remediation points at lpm migrate.
        assert!(drift.remediation.contains("lpm migrate"));
    }

    /// Diff-aware semantics: same key in pnpm.overrides AND in any
    /// LPM-readable source → NO drift issue (post-migrate steady state).
    #[test]
    fn pnpm_overrides_silent_when_lpm_side_covers_pnpm_keys() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                },
                "lpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(
            issue_with_code(&issues, "pnpm_overrides_drift").is_none(),
            "expected no drift issue when lpm.overrides covers the pnpm keys; got {issues:?}"
        );
    }

    /// Partial coverage: pnpm has two keys, lpm covers only one →
    /// drift issue lists ONLY the uncovered key (the new structured
    /// shape lets us pin this — the old boolean couldn't).
    #[test]
    fn pnpm_overrides_drift_enumerates_only_partially_covered_keys() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": {
                        "lodash": "^4.17.21",
                        "react": "^18.0.0"
                    }
                },
                "lpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_overrides_drift")
            .expect("react isn't in lpm.overrides — drift issue should fire");
        assert_eq!(drift.entries, vec!["react".to_string()]);
    }

    /// Coverage check is by raw key string only — `lodash@>=1.0.0`
    /// (NameRange selector) is a different raw key from `lodash` (Name
    /// selector), so they don't satisfy each other. Predictable
    /// semantics; the user reconciles manually. The legacy boolean
    /// helper documented this; the new structured detector inherits it.
    #[test]
    fn pnpm_overrides_drift_uses_raw_key_equality_not_canonical_match() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                },
                "lpm": {
                    "overrides": { "lodash@>=0.0.0": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_overrides_drift")
            .expect("different raw keys must not silence each other even when targets match");
        assert_eq!(drift.entries, vec!["lodash".to_string()]);
    }

    /// Divergent-target case via `lpm.overrides`: same raw key, different
    /// targets → drift fires (silencing would hide real intent loss).
    #[test]
    fn pnpm_overrides_drift_when_lpm_target_differs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                },
                "lpm": {
                    "overrides": { "lodash": "^4.18.0" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_overrides_drift")
            .expect("diverging targets must be flagged");
        assert_eq!(drift.entries, vec!["lodash".to_string()]);
    }

    /// Divergent-target case via top-level `overrides` (npm-style).
    #[test]
    fn pnpm_overrides_drift_when_top_level_target_differs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "overrides": { "lodash": "^4.18.0" },
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(issue_with_code(&issues, "pnpm_overrides_drift").is_some());
    }

    /// Divergent-target case via Yarn-style `resolutions`.
    #[test]
    fn pnpm_overrides_drift_when_resolutions_target_differs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "resolutions": { "lodash": "^4.18.0" },
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(issue_with_code(&issues, "pnpm_overrides_drift").is_some());
    }

    /// Mixed coverage: one key fully covered, a second key has a
    /// divergent target. Drift fires with only the divergent key.
    #[test]
    fn pnpm_overrides_drift_lists_only_diverging_key() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": {
                        "lodash": "^4.17.21",
                        "react": "18.2.0"
                    }
                },
                "lpm": {
                    "overrides": {
                        "lodash": "^4.17.21",
                        "react": "18.3.0"
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_overrides_drift")
            .expect("react's divergent target must fire even though lodash is fully covered");
        assert_eq!(drift.entries, vec!["react".to_string()]);
    }

    /// Top-level `overrides` (npm-style) coverage silences the issue.
    #[test]
    fn pnpm_overrides_silent_when_top_level_overrides_match() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "overrides": { "lodash": "^4.17.21" },
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(issue_with_code(&issues, "pnpm_overrides_drift").is_none());
    }

    /// Yarn-style `resolutions` coverage silences the issue.
    #[test]
    fn pnpm_overrides_silent_when_resolutions_match() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "resolutions": { "lodash": "^4.17.21" },
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(issue_with_code(&issues, "pnpm_overrides_drift").is_none());
    }

    /// `pnpm.patchedDependencies` populated, no LPM-side equivalent →
    /// patches drift fires with the entries enumerated.
    #[test]
    fn pnpm_patches_drift_when_no_lpm_side() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "patchedDependencies": {
                        "react@18.0.0": "patches/react@18.0.0.patch"
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_patches_drift")
            .expect("expected pnpm_patches_drift when no lpm side mirrors the entry");
        assert_eq!(drift.entries, vec!["react@18.0.0".to_string()]);
    }

    /// Non-object pnpm.overrides shapes don't fire the drift issue —
    /// the migrate planner is the right surface for shape errors.
    #[test]
    fn pnpm_overrides_silent_for_non_object_shape() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "overrides": ["this is not how pnpm.overrides works"]
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(
            issue_with_code(&issues, "pnpm_overrides_drift").is_none(),
            "non-object pnpm.overrides shape should not trigger the drift issue; \
             the migrate planner is the right surface for that error"
        );
    }

    /// `engines.npm` / `pnpm` / `yarn` / `bun` each fire as their own
    /// stable-coded issue. LPM doesn't enforce these so the issue
    /// always fires when present (no diff-aware silencing).
    #[test]
    fn engines_other_pm_each_fires_under_distinct_code() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "engines": {
                    "node": ">=22",
                    "lpm": ">=0.1",
                    "npm": ">=10",
                    "pnpm": ">=9",
                    "yarn": ">=4",
                    "bun": ">=1"
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();

        // node + lpm are honored; the other four each fire.
        for code in [
            "engines_npm_ignored",
            "engines_pnpm_ignored",
            "engines_yarn_ignored",
            "engines_bun_ignored",
        ] {
            let issue = issue_with_code(&issues, code)
                .unwrap_or_else(|| panic!("expected {code} issue to fire"));
            assert_eq!(issue.severity, ManifestCompatSeverity::Warn);
            // `entries` carries the single key name so consumers can
            // render `engines.<name>` consistently.
            assert_eq!(issue.entries.len(), 1);
        }
    }

    /// Only-node + only-lpm engines pins are honored — no other-PM
    /// issue fires.
    #[test]
    fn engines_node_and_lpm_alone_do_not_fire_issues() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "engines": { "node": ">=22", "lpm": ">=0.1" }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        for code in [
            "engines_npm_ignored",
            "engines_pnpm_ignored",
            "engines_yarn_ignored",
            "engines_bun_ignored",
        ] {
            assert!(
                issue_with_code(&issues, code).is_none(),
                "{code} should not fire"
            );
        }
    }

    /// Issue ordering is stable for deterministic doctor output:
    /// pnpm overrides → patches → peer rules → engines (npm, pnpm,
    /// yarn, bun).
    #[test]
    fn manifest_compat_issues_are_emitted_in_stable_order() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "engines": {
                    "npm": ">=10",
                    "pnpm": ">=9",
                    "yarn": ">=4",
                    "bun": ">=1"
                },
                "pnpm": {
                    "overrides": { "lodash": "^4.17.21" },
                    "patchedDependencies": { "react@18.0.0": "patches/r.patch" },
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"]
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let codes: Vec<&str> = pkg
            .manifest_compat_issues()
            .iter()
            .map(|i| i.code)
            .collect();
        assert_eq!(
            codes,
            vec![
                "pnpm_overrides_drift",
                "pnpm_patches_drift",
                "pnpm_peer_rules_drift",
                "engines_npm_ignored",
                "engines_pnpm_ignored",
                "engines_yarn_ignored",
                "engines_bun_ignored",
            ]
        );
    }

    /// `pnpm.peerDependencyRules` populated, no LPM-side equivalent
    /// → drift issue fires with the divergent entries enumerated.
    /// Each entry is prefixed by its sub-key (`ignoreMissing:`,
    /// `allowAny:`, `allowedVersions:`) so consumers can tell which
    /// rule is drifting without re-parsing.
    #[test]
    fn pnpm_peer_rules_drift_when_no_lpm_side_lists_per_subkey() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"],
                        "allowAny": ["@babel/*"],
                        "allowedVersions": { "react": "16 || 17" }
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift = issue_with_code(&issues, "pnpm_peer_rules_drift")
            .expect("expected pnpm_peer_rules_drift");
        assert_eq!(drift.severity, ManifestCompatSeverity::Warn);
        assert_eq!(
            drift.entries,
            vec![
                "allowAny:@babel/*".to_string(),
                "allowedVersions:react".to_string(),
                "ignoreMissing:fsevents".to_string(),
            ]
        );
    }

    /// Diff-aware: full coverage on the LPM side silences the issue.
    #[test]
    fn pnpm_peer_rules_silent_when_lpm_side_covers_pnpm_entries() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"],
                        "allowedVersions": { "react": "16 || 17" }
                    }
                },
                "lpm": {
                    "peerDependencyRules": {
                        "ignoreMissing": ["fsevents"],
                        "allowedVersions": { "react": "16 || 17" }
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        assert!(issue_with_code(&issues, "pnpm_peer_rules_drift").is_none());
    }

    /// Divergent allowedVersions range — same name in both, different
    /// range. Drift fires because LPM is honoring a different range
    /// than the pnpm side intended.
    #[test]
    fn pnpm_peer_rules_drift_when_allowed_versions_range_differs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "my-app",
                "pnpm": {
                    "peerDependencyRules": {
                        "allowedVersions": { "react": "16 || 17" }
                    }
                },
                "lpm": {
                    "peerDependencyRules": {
                        "allowedVersions": { "react": "17 || 18" }
                    }
                }
            }"#,
        );
        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let drift =
            issue_with_code(&issues, "pnpm_peer_rules_drift").expect("divergent ranges must drift");
        assert_eq!(drift.entries, vec!["allowedVersions:react".to_string()]);
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

    /// `workspace:` with arbitrary semver range is a passthrough (matches pnpm behavior).
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
        // The legacy array form must still deserialize cleanly into the
        // Legacy variant (backwards-compat contract).
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

// TrustedDependencies schema migration tests — the deserializer accepts
// BOTH the legacy array form AND the rich map form, and the helper methods
// (matches_strict, contains_name_lenient, upgrade_to_rich, approve, revoke)
// compose into the install-gate flows correctly.

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

    /// Regression guard: legacy `@*` preserve keys MUST satisfy the strict gate.
    /// Without this, a manifest like `["esbuild"]` would silently re-block
    /// esbuild on the next install after any unrelated `lpm approve-scripts
    /// --yes` upgrade (which rewrites it to `esbuild@*`). `matches_strict`
    /// honors `<name>@*` as a wildcard version match producing `LegacyNameOnly`.
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
             LegacyNameOnly so users keep their legacy approvals through \
             the upgrade. The build pipeline emits a deprecation warning so \
             users still get nudged to upgrade to a strict binding."
        );
    }

    /// A `<name>@*` preserve key in a Rich variant must match ANY version of
    /// the named package as `LegacyNameOnly`. Tests the matcher in isolation.
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

    /// A scoped package preserved as `@scope/pkg@*` must be matched as
    /// `LegacyNameOnly`. The `@*` parser must split on the LAST `@`, not
    /// the first.
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

    /// A concrete `name@version` rich entry must be preferred over a `name@*`
    /// legacy preserve key when both exist: the strict binding wins.
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

    // ── ProvenanceSnapshot tests live in crates/lpm-common/src/provenance.rs;
    //    see the re-export above.

    // ── TrustedDependencyBinding.provenance_at_approval ─────────────

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
    /// key name matches the wire spec.
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
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains(r#""provenanceAtApproval":"#),
            "wire key must be camelCase `provenanceAtApproval`, got {json}"
        );

        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
    }

    // ── provenance_reference_for_name ─────────────────────────────
    //
    // The selector must be deterministic: HashMap iteration order isn't,
    // so `map.iter().find(...)` would pick different entries across runs
    // when multiple matches exist. Policy: lexicographic-max on version.

    fn trusted_dep_binding_with_provenance(publisher: &str) -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some(publisher.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn trusted_dep_binding_no_provenance() -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: Some("sha512-x".into()),
            script_hash: Some("sha256-y".into()),
            ..Default::default()
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
    /// for the drift rule's `(None, Some(_)) → block` branch,
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
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
        assert!(!back.provenance_at_approval.as_ref().unwrap().present);
    }

    // ── capabilityHash serde ─────────────────────────────────────

    /// Old binding records (without `capabilityHash`) deserialize with
    /// `capability_hash = None`. Every existing approval in every user's
    /// `package.json > trustedDependencies` must round-trip unchanged.
    #[test]
    fn binding_without_capability_hash_loads_as_legacy_approval() {
        // Three plausible forms: bare legacy (only integrity/scriptHash),
        // full binding (plus provenance + behavioral tags), and empty-object.
        let cases = [
            r#"{}"#,
            r#"{"integrity":"sha512-xyz","scriptHash":"sha256-abc"}"#,
            r#"{
                "integrity":"sha512-xyz",
                "scriptHash":"sha256-abc",
                "provenanceAtApproval":{"present":true},
                "behavioralTagsHash":"sha256-def",
                "behavioralTags":["eval","network"]
            }"#,
        ];
        for raw in cases {
            let binding: TrustedDependencyBinding = serde_json::from_str(raw).unwrap();
            assert_eq!(
                binding.capability_hash, None,
                "pre-6b record {raw:?} must load with capability_hash = None; \
                 any other value would silently widen legacy approvals to \
                 cover capabilities they never approved"
            );
        }
    }

    /// Record WITH `capabilityHash` round-trips cleanly: serialize
    /// emits the key, deserialize restores the value.
    #[test]
    fn binding_with_capability_hash_round_trips() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-def".into()),
            capability_hash: Some("sha256-capset-v1-deadbeef".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains("\"capabilityHash\":\"sha256-capset-v1-deadbeef\""),
            "serialized form includes the camelCase key: {json}"
        );
        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
        assert_eq!(
            back.capability_hash.as_deref(),
            Some("sha256-capset-v1-deadbeef")
        );
    }

    /// `None` in the struct serializes to ABSENT key in JSON —
    /// matches the sibling Option fields (provenanceAtApproval,
    /// behavioralTagsHash, etc.). Absent key ≡ legacy approval,
    /// and the serialized form should reflect that clearly rather
    /// than emitting `"capabilityHash":null` (which would be
    /// semantically equivalent but inconsistent with the rest of
    /// the struct).
    #[test]
    fn binding_with_none_capability_hash_omits_key_in_json() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            capability_hash: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            !json.contains("capabilityHash"),
            "None should serialize as absent key, not null: {json}"
        );
    }

    /// Old record → new record: a binding with no capabilityHash
    /// that serializes, then deserializes on the new code, then
    /// re-serializes MUST NOT gain a capabilityHash. This protects
    /// the invariant "we never silently upgrade a legacy approval
    /// to bind a specific capability set."
    #[test]
    fn legacy_binding_stays_legacy_after_round_trip_on_new_code() {
        let raw = r#"{"integrity":"sha512-abc","scriptHash":"sha256-def"}"#;
        let binding: TrustedDependencyBinding = serde_json::from_str(raw).unwrap();
        assert_eq!(binding.capability_hash, None);
        let reserialized = serde_json::to_string(&binding).unwrap();
        assert!(
            !reserialized.contains("capabilityHash"),
            "re-serialization of a legacy binding must not introduce \
             a capabilityHash key (doing so would change the semantic \
             from 'legacy approval, baseline only' to 'approval bound \
             to a specific hash' — silent widening if that hash \
             doesn't match what the package now requests). Got: {reserialized}"
        );
    }

    /// Default impl produces `capability_hash = None` — same as the
    /// pre-6b default. Pinning this from the Default side so a
    /// future "let's default to some sentinel" refactor fails
    /// loudly.
    #[test]
    fn default_binding_has_no_capability_hash() {
        let b = TrustedDependencyBinding::default();
        assert_eq!(b.capability_hash, None);
    }
}

// ── parse_peer_dependencies ───────────────────────────────────────────────────

#[cfg(test)]
mod peer_deps_parse_tests {
    use super::*;

    #[test]
    fn parse_returns_empty_for_no_peer_deps() {
        let json =
            br#"{"name":"react","version":"18.3.0","dependencies":{"loose-envify":"^1.1.0"}}"#;
        let (deps, meta) = parse_peer_dependencies(json).unwrap();
        assert!(deps.is_empty(), "expected no peerDependencies");
        assert!(meta.is_empty(), "expected no peerDependenciesMeta");
    }

    #[test]
    fn parse_extracts_peer_deps_and_meta() {
        let json = br#"{
            "name": "react-dom",
            "version": "18.3.0",
            "peerDependencies": {
                "react": "^18.3.0"
            },
            "peerDependenciesMeta": {
                "react": { "optional": false }
            }
        }"#;
        let (deps, meta) = parse_peer_dependencies(json).unwrap();
        assert_eq!(deps.get("react").map(|s| s.as_str()), Some("^18.3.0"));
        assert!(!meta.get("react").unwrap().optional);
    }

    #[test]
    fn parse_marks_optional_peer() {
        let json = br#"{
            "name": "some-plugin",
            "peerDependencies": {
                "webpack": "^5.0.0"
            },
            "peerDependenciesMeta": {
                "webpack": { "optional": true }
            }
        }"#;
        let (deps, meta) = parse_peer_dependencies(json).unwrap();
        assert_eq!(deps.get("webpack").map(|s| s.as_str()), Some("^5.0.0"));
        assert!(meta.get("webpack").unwrap().optional);
    }

    /// Verify that the byte pre-scan needle "peerDependencies" correctly
    /// matches packages with the key present — no false negatives.
    #[test]
    fn byte_scan_needle_is_present_when_peer_deps_exist() {
        let json = br#"{"peerDependencies":{"react":"^18.0.0"}}"#;
        const NEEDLE: &[u8] = b"peerDependencies";
        assert!(json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    /// Verify the byte pre-scan correctly shows absence when there are no
    /// peer deps — no false negatives mean no unnecessary parses.
    #[test]
    fn byte_scan_needle_is_absent_when_no_peer_deps() {
        let json = br#"{"name":"lodash","version":"4.17.21","dependencies":{}}"#;
        const NEEDLE: &[u8] = b"peerDependencies";
        assert!(!json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    /// peerDependenciesMeta alone (without peerDependencies) still
    /// triggers the scan — we don't miss any peer context.
    #[test]
    fn byte_scan_matches_peer_deps_meta_alone() {
        let json = br#"{"peerDependenciesMeta":{"react":{"optional":true}}}"#;
        const NEEDLE: &[u8] = b"peerDependencies";
        assert!(json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    // ── parse_bin_field ───────────────────────────────────────────────────

    #[test]
    fn parse_bin_field_returns_none_for_no_bin() {
        let json = br#"{"name":"lodash","version":"4.17.21","dependencies":{"some":"1.0.0"}}"#;
        let result = parse_bin_field(json).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_bin_field_returns_single_bin() {
        let json = br#"{"name":"my-cli","version":"1.0.0","bin":"./cli.js","dependencies":{"dep":"1.0.0"}}"#;
        let result = parse_bin_field(json).unwrap().unwrap();
        match result {
            BinConfig::Single(path) => assert_eq!(path, "./cli.js"),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn parse_bin_field_returns_map_bin() {
        let json = br#"{"name":"eslint","bin":{"eslint":"./bin/eslint.js"}}"#;
        let result = parse_bin_field(json).unwrap().unwrap();
        match result {
            BinConfig::Map(map) => {
                assert_eq!(
                    map.get("eslint").map(|s| s.as_str()),
                    Some("./bin/eslint.js")
                )
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    /// The `"bin"` byte-scan needle correctly identifies packages with a
    /// bin field — no false negatives.
    #[test]
    fn bin_byte_scan_matches_when_bin_present() {
        let json = br#"{"name":"eslint","bin":{"eslint":"./bin/eslint.js"},"dependencies":{}}"#;
        const NEEDLE: &[u8] = b"\"bin\"";
        assert!(json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    /// The `"bin"` byte-scan needle correctly shows absence when there is
    /// no bin field — no unnecessary parse passes.
    #[test]
    fn bin_byte_scan_absent_when_no_bin() {
        let json =
            br#"{"name":"lodash","version":"4.17.21","dependencies":{},"scripts":{"test":"jest"}}"#;
        const NEEDLE: &[u8] = b"\"bin\"";
        assert!(!json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    /// Packages without bin but whose other fields contain the word "bin"
    /// in values (e.g., script paths) do NOT trigger a false-positive
    /// match on the quoted-key needle `"\"bin\""`.
    #[test]
    fn bin_byte_scan_no_false_positive_from_bin_in_value() {
        // The scripts values contain the word "bin" but the JSON key
        // `"bin"` (with quotes) is absent.
        let json =
            br#"{"name":"tool","scripts":{"start":"node dist/bin/index.js"},"dependencies":{}}"#;
        const NEEDLE: &[u8] = b"\"bin\"";
        assert!(!json.windows(NEEDLE.len()).any(|w| w == NEEDLE));
    }

    /// parse_bin_field must return the same result as read_package_json
    /// for the bin field — the minimal struct and the full struct produce
    /// identical outputs.
    #[test]
    fn parse_bin_field_parity_with_read_package_json() {
        let json = br#"{"name":"next","version":"14.0.0","bin":{"next":"./dist/bin/next"},"dependencies":{"react":"^18.0.0"}}"#;
        let tmp = std::env::temp_dir().join(format!(
            "lpm-t30-parity-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&tmp, json).unwrap();

        let from_full = read_package_json(&tmp).unwrap().bin;
        let from_minimal = parse_bin_field(json).unwrap();

        match (from_full, from_minimal) {
            (Some(BinConfig::Map(a)), Some(BinConfig::Map(b))) => assert_eq!(a, b),
            (None, None) => {}
            (a, b) => panic!("mismatch: full={a:?}, minimal={b:?}"),
        }
        let _ = std::fs::remove_file(&tmp);
    }
}
