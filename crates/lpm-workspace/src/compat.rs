use crate::package_json::PackageJson;

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

/// Catalog entry for `unsupported_override_values`.
pub const UNSUPPORTED_OVERRIDE_VALUES_META: ManifestCompatCatalogEntry =
    ManifestCompatCatalogEntry {
        code: "unsupported_override_values",
        name: "Manifest compat: override value shapes",
        description: "Top-level `overrides` or `resolutions` values that LPM cannot apply because they are not version strings.",
        when_fires: "A top-level override field is not an object, or an entry uses a nested object, array, number, boolean, or null value.",
        remediation: "Use string targets and parent selectors such as `parent>dependency`; LPM does not apply npm's nested-object override values.",
        possible_severities: &["warn"],
    };

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
    remediation: "LPM does not enforce `engines.bun`; use `lpm.json > runtime.bun` when the project needs a managed Bun binary on PATH. `engines.node` and `engines.lpm` are enforced.",
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
    UNSUPPORTED_OVERRIDE_VALUES_META,
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
    /// 1. `unsupported_override_values`
    /// 2. `pnpm_overrides_drift`
    /// 3. `pnpm_patches_drift`
    /// 4. `pnpm_peer_rules_drift`
    /// 5. `engines_<pm>_ignored` (npm, pnpm, yarn, bun in that order)
    ///
    /// Detectors are diff-aware where it makes sense (`pnpm_overrides`
    /// stays silent once `lpm.overrides` covers every entry) and
    /// always-fires where the field is intrinsically unhonored
    /// (`engines.<pm>` — LPM never enforces those by design).
    pub fn manifest_compat_issues(&self) -> Vec<ManifestCompatIssue> {
        let mut issues = Vec::new();
        if let Some(i) = detect_unsupported_override_values(self) {
            issues.push(i);
        }
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

fn detect_unsupported_override_values(pkg: &PackageJson) -> Option<ManifestCompatIssue> {
    if pkg.unsupported_override_values.is_empty() {
        return None;
    }
    let mut entries = pkg.unsupported_override_values.clone();
    entries.sort();

    Some(ManifestCompatIssue {
        code: "unsupported_override_values",
        severity: ManifestCompatSeverity::Warn,
        detail: format!(
            "package.json has {} top-level `overrides` or `resolutions` value{} that LPM ignores: {}",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" },
            preview(&entries),
        ),
        remediation: "use string targets and parent selectors such as `parent>dependency`. \
                      LPM does not apply npm's nested-object override values."
            .into(),
        entries,
    })
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
            let remediation = if *key == "bun" {
                "use `lpm.json > runtime.bun` when the project needs a managed Bun binary on PATH. \
                 LPM does not enforce `engines.bun`; `engines.node` and `engines.lpm` are enforced."
            } else {
                "remove the field or use `engines.lpm` to constrain the LPM CLI \
                 version. LPM enforces `engines.lpm` and `engines.node` only."
            };
            out.push(ManifestCompatIssue {
                code,
                severity: ManifestCompatSeverity::Warn,
                detail: format!(
                    "package.json has `engines.{key}` set ({constraint:?}) but LPM does not \
                     enforce it"
                ),
                remediation: remediation.into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_json::read_package_json;
    use std::fs;
    use std::path::Path;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
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

    #[test]
    fn unsupported_override_values_list_ignored_keys_and_shapes() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "nested-overrides",
                "overrides": {
                    "path-scurry": { "lru-cache": "^11.0.0" }
                },
                "resolutions": {
                    "react": ["18.0.0"]
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let issues = pkg.manifest_compat_issues();
        let issue = issue_with_code(&issues, "unsupported_override_values")
            .expect("unsupported override values must produce a compatibility warning");

        assert_eq!(
            issue.entries,
            vec![
                "`overrides.path-scurry` (nested object)".to_string(),
                "`resolutions.react` (array)".to_string(),
            ]
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
        let bun_issue = issue_with_code(&issues, "engines_bun_ignored").unwrap();
        assert!(bun_issue.remediation.contains("runtime.bun"));
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
}
