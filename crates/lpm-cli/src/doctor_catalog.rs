//! Canonical catalog of every check `lpm doctor` can emit.
//!
//! Pairs with the `Check` struct in [`crate::commands::doctor`]: the
//! emitted row carries the runtime severity + dynamic detail, while
//! a [`CheckEntry`] in this module carries the static metadata —
//! description, when-fires, remediation, possible severities,
//! optional auto-fix command.
//!
//! ## Drift posture
//!
//! Two layers of guarantee, with different strengths:
//!
//! 1. **Call site → catalog reference (by construction).**
//!    The `Check::pass / fail / warn` constructors take
//!    `&'static CheckEntry`, not `&str`. Code that runs at runtime
//!    must point at a registered static — there is no path to emit
//!    a `Check` whose code is not a static defined in this module.
//!
//! 2. **Catalog static → inventory list (test-guarded).**
//!    The [`CLI_CATALOG`] and [`MANIFEST_COMPAT_ENTRIES`] slices
//!    that drive `lpm doctor list` are **hand-maintained**. A new
//!    `pub static FOO: CheckEntry` can compile and run perfectly
//!    without being registered into either slice — in which case
//!    the inventory would silently miss it. The drift-guard test
//!    `every_pub_static_check_entry_is_registered_for_listing`
//!    closes that gap by parsing this file's source and asserting
//!    every `pub static <NAME>: CheckEntry` declaration appears as
//!    `&NAME,` in one of the registration slices.
//!
//! Together these mean: the runtime cannot emit an unregistered
//! code, and a catalog static cannot be declared without showing up
//! in `lpm doctor list`. Drift is caught at unit-test time before it
//! can land.
//!
//! `lpm doctor list [--json]` reads this catalog plus the workspace-
//! owned [`lpm_workspace::MANIFEST_COMPAT_CATALOG`] and emits the
//! unified inventory.
//!
//! ## Adding a new check
//!
//! 1. Add a new `pub static FOO: CheckEntry = CheckEntry { ... }` in
//!    this module, in the matching category section.
//! 2. Add `&FOO,` to [`CLI_CATALOG`] (or [`MANIFEST_COMPAT_ENTRIES`])
//!    so the listing surface picks it up. The drift-guard test
//!    `every_pub_static_check_entry_is_registered_for_listing` will
//!    fail loudly if you forget.
//! 3. Use it at the emission site as `Check::pass(&FOO, detail)` /
//!    `Check::fail` / `Check::warn`. The constructor `debug_assert!`s
//!    that the chosen severity is in `entry.possible_severities`.
//! 4. Add an integration test (e.g.
//!    `tests/workflows/tests/check_typescript.rs`) that pins the
//!    new code's emission contract end-to-end.

use std::fmt;

/// Severity of a single check row. Mirrors the runtime `Severity`
/// enum in [`crate::commands::doctor`] but lives here because the
/// catalog is the canonical declaration of which severities a code
/// can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Fail,
    Warn,
}

impl Severity {
    /// Stable string form for `--json` output. Match against this in
    /// downstream tooling — never against the human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Fail => "fail",
            Severity::Warn => "warn",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Doctor execution tier. Drives the `lpm doctor` vs `lpm doctor --all`
/// split: fast-mode runs only `Tier::Fast` rows (zero network, zero
/// subprocess except `node --version` for runtime detection), while
/// `--all` runs the full catalog. Orthogonal to [`Category`] — any
/// category can contain rows of either tier (e.g. `Infrastructure`
/// holds `GLOBAL_STORE_*` in `Fast` and `REGISTRY_*` in `Extended`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Core-health rows that explain "why is this project broken
    /// right now?" — local-only, no network, no subprocess spawn
    /// except `node --version` (2s-bounded) for runtime detection.
    Fast,
    /// Everything else: registry / auth probes, tunnel diagnostics,
    /// lint / fmt subprocesses, TypeScript / plugin reachability,
    /// global-install hygiene, sandbox probe, manifest-compat sweep,
    /// project-maintenance rows (`.gitattributes` lockb hygiene,
    /// v2 store orphan counts).
    Extended,
}

impl Tier {
    /// Stable string form for `--json` output and the `tier` field on
    /// `lpm doctor list --json`. Match against this in downstream
    /// tooling.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Tier::Fast => "fast",
            Tier::Extended => "extended",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level grouping of checks. Drives section headings in the
/// human-mode `lpm doctor list` output and the `category` field in
/// `--json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Infrastructure,
    Auth,
    ProjectState,
    LpmJson,
    Runtime,
    Tunnel,
    CodeQuality,
    TypeScript,
    Plugin,
    Workspace,
    Globals,
    Sandbox,
    ManifestCompat,
}

impl Category {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Category::Infrastructure => "Infrastructure",
            Category::Auth => "Auth",
            Category::ProjectState => "Project state",
            Category::LpmJson => "lpm.json",
            Category::Runtime => "Runtime",
            Category::Tunnel => "Tunnel",
            Category::CodeQuality => "Code quality",
            Category::TypeScript => "TypeScript",
            Category::Plugin => "Plugin",
            Category::Workspace => "Workspace",
            Category::Globals => "Global installs",
            Category::Sandbox => "Sandbox + scripts",
            Category::ManifestCompat => "Manifest compat",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One canonical entry in the doctor catalog.
#[derive(Debug, Clone, Copy)]
pub struct CheckEntry {
    /// Stable snake_case identifier emitted as `code` in
    /// `lpm doctor --json`. Match on this in automation. Never
    /// changes once shipped.
    pub code: &'static str,
    /// Short human-readable label. Goes into `check` in the doctor
    /// JSON. Wording can change.
    pub name: &'static str,
    /// Top-level grouping for inventory display.
    pub category: Category,
    /// Execution tier — drives `lpm doctor` (fast) vs `lpm doctor
    /// --all` (full). Orthogonal to [`Category`]: any category can
    /// hold rows of either tier.
    pub tier: Tier,
    /// Short description of what this code expresses. Typically one
    /// sentence; up to two for codes whose context needs a clarifier.
    pub description: &'static str,
    /// Conditions under which the row actually fires at runtime.
    pub when_fires: &'static str,
    /// Suggested remediation. CLI command, doc pointer, or a
    /// short instruction. The `detail` on the emitted row may
    /// echo this verbatim or expand on it.
    pub remediation: &'static str,
    /// Severities this code can take. Most entries have exactly
    /// one; the field is plural to express codes that may pass or
    /// warn depending on transient state.
    pub possible_severities: &'static [Severity],
    /// `lpm doctor --fix` action, if there is one. None means the
    /// remediation is the user's call — e.g. logging in.
    pub auto_fix: Option<&'static str>,
}

impl CheckEntry {
    /// True when `severity` is one of the entry's declared
    /// `possible_severities`. Drives the `debug_assert!` inside the
    /// `Check` constructors.
    pub fn permits(&self, severity: Severity) -> bool {
        self.possible_severities.contains(&severity)
    }
}

// ──────────────────────────────────────────────────────────────────
// Infrastructure
// ──────────────────────────────────────────────────────────────────

pub static REGISTRY_REACHABLE: CheckEntry = CheckEntry {
    code: "registry_reachable",
    name: "Registry",
    category: Category::Infrastructure,
    tier: Tier::Extended,
    description: "The configured registry responds to its health endpoint.",
    when_fires: "Registry health check returned 2xx within the timeout.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static REGISTRY_UNREACHABLE: CheckEntry = CheckEntry {
    code: "registry_unreachable",
    name: "Registry",
    category: Category::Infrastructure,
    tier: Tier::Extended,
    description: "The configured registry could not be reached.",
    when_fires: "Registry health endpoint timed out, returned non-2xx, or DNS failed.",
    remediation: "Check network connectivity, firewall rules, or the registry status page.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static GLOBAL_STORE_ACCESSIBLE: CheckEntry = CheckEntry {
    code: "global_store_accessible",
    name: "Global store",
    category: Category::Infrastructure,
    tier: Tier::Fast,
    description: "The shared content-addressable store at `~/.lpm/store/` resolves.",
    when_fires: "Default store location is readable.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_STORE_INACCESSIBLE: CheckEntry = CheckEntry {
    code: "global_store_inaccessible",
    name: "Global store",
    category: Category::Infrastructure,
    tier: Tier::Fast,
    description: "The shared content-addressable store could not be located or read.",
    when_fires: "`PackageStore::default_location()` errored out (HOME unset, permissions, missing dir).",
    remediation: "Verify `$HOME` is set and that `~/.lpm/store/` is writable. Re-run `lpm install` to recreate.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────────────────────

pub static AUTH_VALID: CheckEntry = CheckEntry {
    code: "auth_valid",
    name: "Authentication",
    category: Category::Auth,
    tier: Tier::Extended,
    description: "A registry auth token is present and `whoami` succeeds.",
    when_fires: "Stored token authenticated against the registry within the timeout.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static AUTH_INVALID: CheckEntry = CheckEntry {
    code: "auth_invalid",
    name: "Authentication",
    category: Category::Auth,
    tier: Tier::Extended,
    description: "A token is stored but the registry rejected it.",
    when_fires: "`whoami` returned 401 / 403 against the stored token.",
    remediation: "Re-authenticate with `lpm login`.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static AUTH_MISSING: CheckEntry = CheckEntry {
    code: "auth_missing",
    name: "Authentication",
    category: Category::Auth,
    tier: Tier::Extended,
    description: "No registry auth token is configured.",
    when_fires: "No token in keychain / file backend for the configured registry origin.",
    remediation: "Run `lpm login`.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Project state
// ──────────────────────────────────────────────────────────────────

pub static PACKAGE_JSON_PRESENT: CheckEntry = CheckEntry {
    code: "package_json_present",
    name: "package.json",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A readable `package.json` exists in the project directory.",
    when_fires: "`<project>/package.json` is a regular file.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static PACKAGE_JSON_MISSING: CheckEntry = CheckEntry {
    code: "package_json_missing",
    name: "package.json",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "No `package.json` exists in the project directory.",
    when_fires: "`<project>/package.json` is missing.",
    remediation: "Run `lpm init`, or `cd` into your project root before running doctor.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LINKER_MODE_RESOLVED: CheckEntry = CheckEntry {
    code: "linker_mode_resolved",
    name: "Linker mode",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "Reports the LinkerMode the install pipeline would resolve to plus which surface in the precedence chain produced it (CLI flag / global config / env var / package.json / workspace auto-detected / default).",
    when_fires: "Always — runs after `package.json` is read so the resolution chain reflects the manifest's `lpm.linker` setting.",
    remediation: "No action — informational. To change the result, set one of the higher-precedence surfaces (e.g. `--linker=isolated`, `LPM_LINKER`, `package.json > lpm > linker`).",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static NODE_MODULES_ISOLATED_HEALTHY: CheckEntry = CheckEntry {
    code: "node_modules_isolated_healthy",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`node_modules/` exists and is backed by an isolated `.lpm/wrappers/` store.",
    when_fires: "Default linker layout is intact.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static NODE_MODULES_HOISTED_HEALTHY: CheckEntry = CheckEntry {
    code: "node_modules_hoisted_healthy",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`node_modules/` exists and uses the hoisted layout.",
    when_fires: "User opted into `--linker=hoisted` and the layout is intact.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static NODE_MODULES_VIRTUAL_HEALTHY: CheckEntry = CheckEntry {
    code: "node_modules_virtual_healthy",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`node_modules/` symlinks point into the virtual store at `~/.lpm/store/v2/links/`.",
    when_fires: "User opted into `LPM_STORE_VERSION=v2` (dev-only flag) and the virtual-store layout is intact.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static V2_STORE_ORPHANS: CheckEntry = CheckEntry {
    code: "v2_store_orphans",
    name: "v2 virtual store",
    category: Category::ProjectState,
    tier: Tier::Extended,
    description: "v2 store at `~/.lpm/store/v2/` has link entries or objects no longer reachable from any registered project.",
    when_fires: "After projects are deleted or move on disk; the v2 store grows monotonically across all projects on the machine until pruned.",
    remediation: "Run `lpm cache prune` for a dry-run preview, then `lpm cache prune --apply` to remove orphans.",
    possible_severities: &[Severity::Pass, Severity::Warn],
    auto_fix: Some("lpm cache prune --apply"),
};

pub static NODE_MODULES_MIXED_LAYOUT: CheckEntry = CheckEntry {
    code: "node_modules_mixed_layout",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "Both isolated and hoisted layout state are present in `node_modules/`.",
    when_fires: "A linker mode switch left stale state behind.",
    remediation: "Re-run `lpm install` to converge on the configured linker layout.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm install"),
};

pub static NODE_MODULES_NO_STORE: CheckEntry = CheckEntry {
    code: "node_modules_no_store",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`node_modules/` exists but no LPM-owned store is present.",
    when_fires: "A non-LPM tool wrote `node_modules/` (npm / pnpm / yarn / bun).",
    remediation: "Run `lpm install` to rebuild the layout under LPM ownership.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm install"),
};

pub static NODE_MODULES_LEGACY_LAYOUT: CheckEntry = CheckEntry {
    code: "node_modules_legacy_layout",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "An older LPM layout is on disk and a one-time migration is pending.",
    when_fires: "Legacy `node_modules/.lpm/` or `node_modules/.lpm-metadata.json` populated; the new `.lpm/wrappers/` is empty.",
    remediation: "Run `lpm install` to migrate to the current layout.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm install"),
};

pub static NODE_MODULES_MISSING: CheckEntry = CheckEntry {
    code: "node_modules_missing",
    name: "node_modules",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`node_modules/` is missing — dependencies have not been installed.",
    when_fires: "The project has `package.json` but no `node_modules/`.",
    remediation: "Run `lpm install`.",
    possible_severities: &[Severity::Fail],
    auto_fix: Some("lpm install"),
};

pub static LOCKFILE_PRESENT: CheckEntry = CheckEntry {
    code: "lockfile_present",
    name: "Lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lock` is present at the project root.",
    when_fires: "TOML lockfile is on disk.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LOCKFILE_MISSING: CheckEntry = CheckEntry {
    code: "lockfile_missing",
    name: "Lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "No `lpm.lock` was found at the project root.",
    when_fires: "Project has dependencies declared but no lockfile generated.",
    remediation: "Run `lpm install` — it generates the lockfile alongside `node_modules/`.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm install"),
};

pub static LOCKFILE_BINARY_VALID: CheckEntry = CheckEntry {
    code: "lockfile_binary_valid",
    name: "Binary lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lockb` matches `lpm.lock` and parses cleanly.",
    when_fires: "Both lockfiles agree.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LOCKFILE_BINARY_MISSING: CheckEntry = CheckEntry {
    code: "lockfile_binary_missing",
    name: "Binary lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lockb` is missing while `lpm.lock` is present.",
    when_fires: "Only the TOML lockfile is on disk.",
    remediation: "Run `lpm doctor --fix` to regenerate, or run `lpm install`.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("regenerate lpm.lockb"),
};

pub static LOCKFILE_BINARY_STALE: CheckEntry = CheckEntry {
    code: "lockfile_binary_stale",
    name: "Binary lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lockb` does not match the contents of `lpm.lock`.",
    when_fires: "TOML lockfile changed but the binary mirror was not regenerated.",
    remediation: "Run `lpm doctor --fix` to regenerate, or run `lpm install`.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("regenerate lpm.lockb"),
};

pub static LOCKFILE_BINARY_CORRUPT: CheckEntry = CheckEntry {
    code: "lockfile_binary_corrupt",
    name: "Binary lockfile",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lockb` does not parse as a valid binary lockfile.",
    when_fires: "Binary lockfile bytes are truncated, mis-versioned, or otherwise unreadable.",
    remediation: "Run `lpm doctor --fix` to regenerate from `lpm.lock`.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("regenerate lpm.lockb"),
};

pub static GITATTRIBUTES_LOCKB_MARKED: CheckEntry = CheckEntry {
    code: "gitattributes_lockb_marked",
    name: ".gitattributes",
    category: Category::ProjectState,
    tier: Tier::Extended,
    description: "`.gitattributes` marks `lpm.lockb` as binary.",
    when_fires: "Repo has the recommended `lpm.lockb binary` rule.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GITATTRIBUTES_LOCKB_UNMARKED: CheckEntry = CheckEntry {
    code: "gitattributes_lockb_unmarked",
    name: ".gitattributes",
    category: Category::ProjectState,
    tier: Tier::Extended,
    description: "`.gitattributes` exists but does not mark `lpm.lockb` as binary.",
    when_fires: "Repo has `.gitattributes` without the LPM lockb rule.",
    remediation: "Add `lpm.lockb binary` to `.gitattributes` so git diffs treat the file correctly.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static GITATTRIBUTES_MISSING: CheckEntry = CheckEntry {
    code: "gitattributes_missing",
    name: ".gitattributes",
    category: Category::ProjectState,
    tier: Tier::Extended,
    description: "No `.gitattributes` found — `lpm.lockb` may be diffed as text.",
    when_fires: "`<project>/.gitattributes` is missing.",
    remediation: "Run `lpm init` or add `lpm.lockb binary` to a new `.gitattributes`.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static DEPS_SYNC_CLEAN: CheckEntry = CheckEntry {
    code: "deps_sync_clean",
    name: "Dependencies",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lock` and `package.json` agree on the declared dependency set.",
    when_fires: "No drift between manifest deps and lockfile entries.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static DEPS_SYNC_DRIFT: CheckEntry = CheckEntry {
    code: "deps_sync_drift",
    name: "Dependencies",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "`lpm.lock` and `package.json` disagree — manifest changes have not been resolved.",
    when_fires: "Declared deps were added or removed without rerunning `lpm install`.",
    remediation: "Run `lpm install` to reconcile.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm install"),
};

pub static LOCAL_SOURCE_DIR_OK: CheckEntry = CheckEntry {
    code: "local_source_dir_ok",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `file:` / `link:` dependency points at a directory with a readable `package.json`.",
    when_fires: "All resolved local source paths are healthy directories.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LOCAL_SOURCE_TARBALL_OK: CheckEntry = CheckEntry {
    code: "local_source_tarball_ok",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `file:` dependency points at a readable tarball.",
    when_fires: "Tarball file exists and is readable.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LOCAL_SOURCE_DIR_NO_PKG: CheckEntry = CheckEntry {
    code: "local_source_dir_no_pkg",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `file:` / `link:` dependency points at a directory with no `package.json`.",
    when_fires: "Resolved local source path lacks the manifest LPM needs to install it.",
    remediation: "Add `package.json` to the local path or update the dep target.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LOCAL_SOURCE_INVALID_TYPE: CheckEntry = CheckEntry {
    code: "local_source_invalid_type",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `file:` / `link:` dependency points at an unexpected file type.",
    when_fires: "Resolved path is e.g. a socket or device — neither a tarball nor a directory.",
    remediation: "Re-target the dependency at a directory or a tarball file.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LOCAL_SOURCE_LINK_TO_FILE: CheckEntry = CheckEntry {
    code: "local_source_link_to_file",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `link:` dependency points at a regular file rather than a directory.",
    when_fires: "`link:` resolved to a non-directory target.",
    remediation: "`link:` must reference a project directory; switch to `file:` for tarballs.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LOCAL_SOURCE_UNREADABLE: CheckEntry = CheckEntry {
    code: "local_source_unreadable",
    name: "Local sources",
    category: Category::ProjectState,
    tier: Tier::Fast,
    description: "A `file:` / `link:` dependency target could not be read.",
    when_fires: "Permission denied, broken symlink, or the path was deleted between resolution and probe.",
    remediation: "Restore the target path or fix permissions; rerun `lpm install`.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// lpm.json
// ──────────────────────────────────────────────────────────────────

pub static LPM_JSON_VALID: CheckEntry = CheckEntry {
    code: "lpm_json_valid",
    name: "lpm.json",
    category: Category::LpmJson,
    tier: Tier::Fast,
    description: "`lpm.json` exists and parses against the strict schema.",
    when_fires: "Schema validation succeeded.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LPM_JSON_SCHEMA_WARNINGS: CheckEntry = CheckEntry {
    code: "lpm_json_schema_warnings",
    name: "lpm.json",
    category: Category::LpmJson,
    tier: Tier::Fast,
    description: "`lpm.json` parsed but contained unknown or off-schema fields.",
    when_fires: "Validator surfaced warnings — typo, removed field, or undocumented key.",
    remediation: "Inspect the listed fields and align with the documented schema.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static LPM_JSON_INVALID_SYNTAX: CheckEntry = CheckEntry {
    code: "lpm_json_invalid_syntax",
    name: "lpm.json",
    category: Category::LpmJson,
    tier: Tier::Fast,
    description: "`lpm.json` is not valid JSON.",
    when_fires: "JSON parser raised a syntax error.",
    remediation: "Fix the JSON syntax error reported in `detail`.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LPM_JSON_NOT_OBJECT: CheckEntry = CheckEntry {
    code: "lpm_json_not_object",
    name: "lpm.json",
    category: Category::LpmJson,
    tier: Tier::Fast,
    description: "`lpm.json`'s top-level value is not an object.",
    when_fires: "Top level is an array, scalar, or null.",
    remediation: "Replace with a JSON object literal `{ ... }`.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LPM_JSON_UNREADABLE: CheckEntry = CheckEntry {
    code: "lpm_json_unreadable",
    name: "lpm.json",
    category: Category::LpmJson,
    tier: Tier::Fast,
    description: "`lpm.json` could not be read from disk.",
    when_fires: "Permission denied or unexpected I/O error.",
    remediation: "Fix file permissions; rerun doctor.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Runtime
// ──────────────────────────────────────────────────────────────────

pub static NODE_MANAGED_MATCH: CheckEntry = CheckEntry {
    code: "node_managed_match",
    name: "Node.js",
    category: Category::Runtime,
    tier: Tier::Fast,
    description: "A managed Node install matches the pinned spec.",
    when_fires: "`lpm.json > runtime.node` (or `.nvmrc`, `engines.node`) resolves to an installed version.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static NODE_PINNED_UNMET: CheckEntry = CheckEntry {
    code: "node_pinned_unmet",
    name: "Node.js",
    category: Category::Runtime,
    tier: Tier::Fast,
    description: "Project pins a Node version but only a system Node satisfies (or none does).",
    when_fires: "Pin found, but no managed install matches; system Node may differ in patch / minor.",
    remediation: "Run `lpm use node@<version>` to install and pin the managed version.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm use node@<spec>"),
};

pub static NODE_MISSING_PINNED: CheckEntry = CheckEntry {
    code: "node_missing_pinned",
    name: "Node.js",
    category: Category::Runtime,
    tier: Tier::Fast,
    description: "Project pins a Node version and no Node is reachable.",
    when_fires: "Pin found; no system or managed Node available.",
    remediation: "Run `lpm use node@<version>` to install the pinned version.",
    possible_severities: &[Severity::Fail],
    auto_fix: Some("lpm use node@<spec>"),
};

pub static NODE_SYSTEM_UNPINNED: CheckEntry = CheckEntry {
    code: "node_system_unpinned",
    name: "Node.js",
    category: Category::Runtime,
    tier: Tier::Fast,
    description: "No Node version is pinned; a system Node was found.",
    when_fires: "Project does not declare `runtime.node` / `engines.node` / `.nvmrc`.",
    remediation: "Optional: pin a Node version via `lpm.json > runtime.node` for reproducibility.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static NODE_MISSING_UNPINNED: CheckEntry = CheckEntry {
    code: "node_missing_unpinned",
    name: "Node.js",
    category: Category::Runtime,
    tier: Tier::Fast,
    description: "No Node version is pinned and no Node is reachable.",
    when_fires: "Neither a managed nor a system Node was found.",
    remediation: "Install Node via `lpm use node@22` (or your preferred version).",
    possible_severities: &[Severity::Fail],
    auto_fix: Some("lpm use node@22"),
};

// ──────────────────────────────────────────────────────────────────
// Tunnel
// ──────────────────────────────────────────────────────────────────

pub static TUNNEL_ACTIVE: CheckEntry = CheckEntry {
    code: "tunnel_active",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "A tunnel domain is configured and the registry confirms ownership.",
    when_fires: "User authenticated, claim verified.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static TUNNEL_IDLE: CheckEntry = CheckEntry {
    code: "tunnel_idle",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "No tunnel domain is configured for this project.",
    when_fires: "`lpm.json > tunnel.domain` is not set.",
    remediation: "No action — informational pass. Configure a domain to enable `lpm dev --tunnel`.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static TUNNEL_UNAUTHENTICATED: CheckEntry = CheckEntry {
    code: "tunnel_unauthenticated",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "A tunnel domain is configured but the user is not authenticated to verify ownership.",
    when_fires: "Tunnel domain set, no auth token available — informational only.",
    remediation: "Run `lpm login` to verify ownership.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static TUNNEL_UNVERIFIED: CheckEntry = CheckEntry {
    code: "tunnel_unverified",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Ownership of the tunnel domain could not be verified due to a transient registry error.",
    when_fires: "Registry returned an unexpected status when checking the claim.",
    remediation: "Retry; check `lpm health`.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static TUNNEL_NOT_CLAIMED: CheckEntry = CheckEntry {
    code: "tunnel_not_claimed",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "The configured tunnel domain is not claimed by this account.",
    when_fires: "Registry reports no claim for the domain on this user.",
    remediation: "Run `lpm tunnel claim <domain>` (Pro/Org) or change the domain.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_OWNED_BY_OTHER: CheckEntry = CheckEntry {
    code: "tunnel_owned_by_other",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "The configured tunnel domain is claimed by a different account.",
    when_fires: "Registry reports the domain belongs to another user.",
    remediation: "Choose a different domain; the current claim is held elsewhere.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_UNREACHABLE: CheckEntry = CheckEntry {
    code: "tunnel_unreachable",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "The registry could not be reached to verify the tunnel claim.",
    when_fires: "Network timeout / DNS failure during claim probe.",
    remediation: "Check network; retry `lpm doctor`.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_UNKNOWN_BASE: CheckEntry = CheckEntry {
    code: "tunnel_unknown_base",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Configured tunnel domain uses a base domain LPM does not recognize.",
    when_fires: "`lpm.json > tunnel.domain` ends in a base other than `lpm.fyi` / `lpm.llc`.",
    remediation: "Use one of the supported base domains, or contact the LPM team to add a new one.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_DOMAIN_NO_DOT: CheckEntry = CheckEntry {
    code: "tunnel_domain_no_dot",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Configured tunnel domain has no dot separating subdomain from base.",
    when_fires: "Domain has no `.` (e.g. `myapp` instead of `myapp.lpm.fyi`).",
    remediation: "Set the full domain: `<subdomain>.lpm.fyi` or `<subdomain>.lpm.llc`.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_DOMAIN_EMPTY_LABEL: CheckEntry = CheckEntry {
    code: "tunnel_domain_empty_label",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Configured tunnel domain has an empty label (e.g., `..lpm.fyi`).",
    when_fires: "Adjacent dots in the configured domain.",
    remediation: "Remove the empty label.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_DOMAIN_LABEL_TOO_LONG: CheckEntry = CheckEntry {
    code: "tunnel_domain_label_too_long",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "A label in the configured tunnel domain exceeds 63 characters (DNS limit).",
    when_fires: "DNS label too long.",
    remediation: "Shorten the offending label.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_DOMAIN_TOO_LONG: CheckEntry = CheckEntry {
    code: "tunnel_domain_too_long",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Total tunnel domain length exceeds the DNS limit.",
    when_fires: "Domain longer than 253 characters.",
    remediation: "Shorten the domain.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_SUBDOMAIN_LENGTH: CheckEntry = CheckEntry {
    code: "tunnel_subdomain_length",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Tunnel subdomain length is outside the allowed range.",
    when_fires: "Subdomain too short or too long for the LPM regex.",
    remediation: "Pick a subdomain between the documented bounds.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_SUBDOMAIN_CHARS: CheckEntry = CheckEntry {
    code: "tunnel_subdomain_chars",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Tunnel subdomain contains characters outside the allowed alphabet.",
    when_fires: "Non-`[a-z0-9-]` characters in the subdomain.",
    remediation: "Use only lowercase letters, digits, and hyphens.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TUNNEL_SUBDOMAIN_HYPHEN: CheckEntry = CheckEntry {
    code: "tunnel_subdomain_hyphen",
    name: "Tunnel",
    category: Category::Tunnel,
    tier: Tier::Extended,
    description: "Tunnel subdomain starts or ends with a hyphen.",
    when_fires: "Leading or trailing `-` in the subdomain.",
    remediation: "Subdomains must start and end with an alphanumeric character.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Code quality
// ──────────────────────────────────────────────────────────────────

pub static LINT_CLEAN: CheckEntry = CheckEntry {
    code: "lint_clean",
    name: "Lint (oxlint)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Oxlint reports no issues for the project.",
    when_fires: "Oxlint installed and exited with no errors or warnings.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static LINT_WARNINGS: CheckEntry = CheckEntry {
    code: "lint_warnings",
    name: "Lint (oxlint)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Oxlint reported warnings for the project.",
    when_fires: "Lint run produced warning-level findings.",
    remediation: "Run `lpm lint` to inspect, then address.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static LINT_ERRORS: CheckEntry = CheckEntry {
    code: "lint_errors",
    name: "Lint (oxlint)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Oxlint reported errors for the project.",
    when_fires: "Lint run produced error-level findings.",
    remediation: "Run `lpm lint` and fix the reported errors.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static LINT_UNPARSEABLE: CheckEntry = CheckEntry {
    code: "lint_unparseable",
    name: "Lint (oxlint)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Oxlint output could not be parsed by doctor.",
    when_fires: "Doctor's output parser failed on the lint result.",
    remediation: "Run `lpm lint` directly to see the raw output.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static FMT_CLEAN: CheckEntry = CheckEntry {
    code: "fmt_clean",
    name: "Format (biome)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Biome reports the project formatting is clean.",
    when_fires: "`biome format --check` exited cleanly.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static FMT_UNFORMATTED: CheckEntry = CheckEntry {
    code: "fmt_unformatted",
    name: "Format (biome)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Biome found files that need reformatting.",
    when_fires: "`biome format --check` exited non-zero with formatting issues.",
    remediation: "Run `lpm fmt` to apply formatting.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm fmt"),
};

pub static FMT_OTHER_ISSUE: CheckEntry = CheckEntry {
    code: "fmt_other_issue",
    name: "Format (biome)",
    category: Category::CodeQuality,
    tier: Tier::Extended,
    description: "Biome reported a non-format issue (parse error, config error, etc.).",
    when_fires: "Biome exited with an error not classified as plain unformatted code.",
    remediation: "Run `lpm fmt --check` to see the raw biome output.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm fmt"),
};

// ──────────────────────────────────────────────────────────────────
// TypeScript
// ──────────────────────────────────────────────────────────────────

pub static TYPESCRIPT_HEALTHY: CheckEntry = CheckEntry {
    code: "typescript_healthy",
    name: "TypeScript",
    category: Category::TypeScript,
    tier: Tier::Extended,
    description: "Project-local `tsc` resolves through the `node_modules/.bin` chain.",
    when_fires: "A `tsconfig.json`-owning directory has the local typescript install reachable.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static TYPESCRIPT_MISSING_FOR_TSCONFIG: CheckEntry = CheckEntry {
    code: "typescript_missing_for_tsconfig",
    name: "TypeScript",
    category: Category::TypeScript,
    tier: Tier::Extended,
    description: "`tsc` is reachable only via the system `PATH`; no project-local install.",
    when_fires: "A `tsconfig.json`-owning directory has no `node_modules/.bin/tsc` but the system `PATH` provides one.",
    remediation: "Run `lpm install -D typescript` so editor + CI use the same version.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static TYPESCRIPT_UNAVAILABLE: CheckEntry = CheckEntry {
    code: "typescript_unavailable",
    name: "TypeScript",
    category: Category::TypeScript,
    tier: Tier::Extended,
    description: "`tsc` is not reachable for a `tsconfig.json`-owning directory.",
    when_fires: "Neither `node_modules/.bin/tsc` nor a system `tsc` is present.",
    remediation: "Run `lpm install -D typescript` (or `lpm install` if `typescript` is already declared).",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Plugin
// ──────────────────────────────────────────────────────────────────

pub static PLUGIN_UP_TO_DATE: CheckEntry = CheckEntry {
    code: "plugin_up_to_date",
    name: "Plugin",
    category: Category::Plugin,
    tier: Tier::Extended,
    description: "An installed plugin is at the latest known version.",
    when_fires: "Latest probe matched the installed version.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static PLUGIN_UPDATE_AVAILABLE: CheckEntry = CheckEntry {
    code: "plugin_update_available",
    name: "Plugin",
    category: Category::Plugin,
    tier: Tier::Extended,
    description: "A newer version of an installed plugin is available upstream.",
    when_fires: "Upstream probe returned a higher version than the installed one.",
    remediation: "Run `lpm plugin update <name>` to update.",
    possible_severities: &[Severity::Warn],
    auto_fix: Some("lpm plugin update <name>"),
};

// ──────────────────────────────────────────────────────────────────
// Workspace
// ──────────────────────────────────────────────────────────────────

pub static WORKSPACE_ACYCLIC: CheckEntry = CheckEntry {
    code: "workspace_acyclic",
    name: "Workspace",
    category: Category::Workspace,
    tier: Tier::Fast,
    description: "No dependency cycles among workspace members.",
    when_fires: "Topological order computed cleanly.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static WORKSPACE_CYCLE: CheckEntry = CheckEntry {
    code: "workspace_cycle",
    name: "Workspace",
    category: Category::Workspace,
    tier: Tier::Fast,
    description: "A dependency cycle exists among workspace members.",
    when_fires: "Topology computation detected a cycle.",
    remediation: "Break the cycle by removing or restructuring the offending workspace dep.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Global installs
// ──────────────────────────────────────────────────────────────────

pub static GLOBAL_MANIFEST_VALID: CheckEntry = CheckEntry {
    code: "global_manifest_valid",
    name: "Global manifest",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "`~/.lpm/global/manifest.json` parses and is structurally valid.",
    when_fires: "Manifest exists and is well-formed.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_MANIFEST_ABSENT: CheckEntry = CheckEntry {
    code: "global_manifest_absent",
    name: "Global manifest",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "No global install manifest is present (no global installs yet).",
    when_fires: "`~/.lpm/global/` is empty or missing.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_MANIFEST_CORRUPT: CheckEntry = CheckEntry {
    code: "global_manifest_corrupt",
    name: "Global manifest",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "`~/.lpm/global/manifest.json` is unreadable or malformed.",
    when_fires: "JSON parse error or schema mismatch.",
    remediation: "Inspect and repair, or reinstall affected globals.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

pub static GLOBAL_BIN_ON_PATH: CheckEntry = CheckEntry {
    code: "global_bin_on_path",
    name: "Global bin on PATH",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "`~/.lpm/bin` is on the user's `PATH`.",
    when_fires: "Shell `PATH` contains the global bin dir.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_BIN_OFF_PATH: CheckEntry = CheckEntry {
    code: "global_bin_off_path",
    name: "Global bin on PATH",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "`~/.lpm/bin` is not on the user's `PATH`.",
    when_fires: "Global installs exist but their shims won't be found.",
    remediation: "Add `~/.lpm/bin` to your shell PATH (see `lpm install --global` notes).",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static GLOBAL_SHIMS_CLEAN: CheckEntry = CheckEntry {
    code: "global_shims_clean",
    name: "Orphaned shims",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "Every shim in `~/.lpm/bin` belongs to a recorded global install.",
    when_fires: "No orphan shim files.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_SHIMS_NO_DIR: CheckEntry = CheckEntry {
    code: "global_shims_no_dir",
    name: "Orphaned shims",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "Global bin directory does not yet exist.",
    when_fires: "No globals installed.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_SHIMS_ORPHANS: CheckEntry = CheckEntry {
    code: "global_shims_orphans",
    name: "Orphaned shims",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "Files exist in `~/.lpm/bin` without a matching manifest entry.",
    when_fires: "Shim file present but no global install owns it.",
    remediation: "Remove the orphan files, or run `lpm install --global` to re-register.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static GLOBAL_SHIMS_UNREADABLE: CheckEntry = CheckEntry {
    code: "global_shims_unreadable",
    name: "Orphaned shims",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "Global bin directory could not be enumerated.",
    when_fires: "Permission denied or filesystem error reading `~/.lpm/bin`.",
    remediation: "Fix permissions; rerun doctor.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static GLOBAL_INSTALL_ROOTS_EMPTY: CheckEntry = CheckEntry {
    code: "global_install_roots_empty",
    name: "Global install roots",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "No global installs are recorded.",
    when_fires: "Manifest empty or missing.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_INSTALL_ROOTS_HEALTHY: CheckEntry = CheckEntry {
    code: "global_install_roots_healthy",
    name: "Global install roots",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "Every global install root exists and carries a ready marker.",
    when_fires: "All recorded global installs are intact.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

pub static GLOBAL_INSTALL_ROOTS_UNHEALTHY: CheckEntry = CheckEntry {
    code: "global_install_roots_unhealthy",
    name: "Global install roots",
    category: Category::Globals,
    tier: Tier::Extended,
    description: "One or more global install roots are missing or incomplete.",
    when_fires: "Manifest entry references a path that does not exist or has no ready marker.",
    remediation: "Reinstall the affected globals (`lpm install --global <pkg>`).",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Sandbox + script policy
// ──────────────────────────────────────────────────────────────────

pub static SANDBOX_AVAILABLE: CheckEntry = CheckEntry {
    code: "sandbox_available",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "The OS sandbox backend used by lifecycle scripts is available. The default posture is filesystem-write containment + env scrubbing; outbound network denial is the opt-in `strict` mode. Strict-mode coverage is platform-asymmetric: full denial on macOS Seatbelt (every socket family); on Linux, landlock V4 covers outbound TCP and the seccomp-bpf layer covers direct UDP / raw / AF_PACKET / AF_NETLINK socket() — AF_UNIX intentionally allowed for legitimate IPC.",
    when_fires: "Seatbelt (macOS) or Landlock (Linux) is reachable on this host. strict-mode outbound network denial engages only when the user has opted in via `--strict-sandbox` / `--paranoid`, `[sandbox] mode = \"strict\"`, or `LPM_STRICT_SANDBOX=1`.",
    remediation: "No action — informational pass.",
    possible_severities: &[Severity::Pass],
    auto_fix: None,
};

/// on Windows, the
/// `lpm-sandbox-helper.exe` companion binary that delivers
/// AppContainer strict-mode (filesystem-write + outbound-network
/// containment via WFP) is not located next to `lpm.exe`. The
/// sandbox is still active via the Low IL fallback —
/// filesystem-write is contained — but **strict mode is
/// unreachable until the helper is restored**. Distinct catalog
/// entry from [`SANDBOX_AVAILABLE`] so JSON consumers can detect
/// the helper-missing case without prose parsing. Severity is
/// `Warn`: containment is still active for default mode, but the
/// user has lost the strict-mode upgrade path; reinstalling lpm
/// restores it.
pub static SANDBOX_HELPER_MISSING: CheckEntry = CheckEntry {
    code: "sandbox_helper_missing",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "On Windows, the `lpm-sandbox-helper.exe` companion binary that delivers AppContainer strict-mode (filesystem-write + outbound-network containment) is not located next to `lpm.exe`. The sandbox falls back to the Low IL backend, which contains filesystem writes but does NOT deny outbound network — so `--strict-sandbox` / `[sandbox] mode = \"strict\"` cannot be honored on this install.",
    when_fires: "Windows host running a  build of `lpm.exe` but missing the companion `lpm-sandbox-helper.exe` in the same directory. Typical causes: corrupted npm install of `@lpm-registry/cli-win32-x64`, manual binary fetch that skipped the helper, or running a dev build that didn't bundle the helper alongside the test binary.",
    remediation: "Reinstall `@lpm-registry/cli` via your package manager to restore the helper, or set `LPM_SANDBOX_HELPER=<absolute path>` if the helper lives elsewhere on the host. To drop the strict request and silence this warning without restoring the helper, run `lpm config sandbox --set default`.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

/// doctor surface: strict mode is engaged but the host
/// kernel forced the V1 fallback (landlock V1, filesystem-only — no
/// outbound network denial). Distinct catalog entry from
/// [`SANDBOX_AVAILABLE`] so JSON consumers can detect "containment
/// partially enforced" without parsing the detail prose. Severity is
/// `Warn`: the user opted into strict AND opted into the degraded
/// fallback, so this is a chosen state, not a failure — but it IS a
/// posture they should be aware of on every doctor run.
pub static SANDBOX_DEGRADED: CheckEntry = CheckEntry {
    code: "sandbox_degraded",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "The sandbox is running in the degraded posture (landlock V1 fallback). Filesystem containment is active; the strict-mode outbound network denial the user opted into is NOT enforced because the host kernel is below the V4 floor.",
    when_fires: "User has set `[sandbox] mode = \"strict\"` (or `--strict-sandbox` / `LPM_STRICT_SANDBOX=1`) AND `[sandbox] allow-degraded = true` AND the host kernel is below the landlock V4 floor (6.7).",
    remediation: "Pick one: (a) upgrade the host kernel to 6.7+ and unset `[sandbox] allow-degraded` to get the strict posture you asked for; (b) drop back to the default posture via `lpm config sandbox --set default` (filesystem + env containment, no network denial — the recommended default).",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

/// rework GPT-5 audit follow-up : the user
/// has persistently disabled the sandbox via
/// `[sandbox] mode = "none"` in `~/.lpm/config.toml` / `./lpm.toml`
/// (typically set by `lpm config sandbox --set none`). Distinct
/// catalog entry from [`SANDBOX_AVAILABLE`] so JSON consumers can
/// detect the disabled state without prose parsing, and distinct
/// from [`SANDBOX_DEGRADED`] which reports a strict-but-fallen-back
/// state. Severity is `Warn`: the user chose this knowingly, so
/// it's not a failure — but it IS a posture they should see on
/// every doctor run.
pub static SANDBOX_DISABLED_BY_USER: CheckEntry = CheckEntry {
    code: "sandbox_disabled_by_user",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "The sandbox is persistently disabled by user config — `[sandbox] mode = \"none\"` in `~/.lpm/config.toml` or `./lpm.toml`. Lifecycle scripts run with no filesystem / env / network containment.",
    when_fires: "User has set `[sandbox] mode = \"none\"` (typically via `lpm config sandbox --set none`).",
    remediation: "If this is unintended, restore the recommended default via `lpm config sandbox --set default` (or `--set strict` for paranoid mode). The disabled posture is the npm-default experience — every lifecycle script gets full host access, including credential env vars.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static SANDBOX_KERNEL_TOO_OLD: CheckEntry = CheckEntry {
    code: "sandbox_kernel_too_old",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "Linux kernel is too old to support Landlock at the strict floor (V4 / kernel 6.7+).",
    when_fires: "User has opted into strict mode (via `--strict-sandbox` / `--paranoid` / `[sandbox] mode = \"strict\"` / `LPM_STRICT_SANDBOX=1`) but the host kernel cannot support V4. refuses to run lifecycle scripts under strict on kernels below this floor unless the user has explicitly opted into the degraded posture.",
    remediation: "Pick one: (1) `[sandbox] allow-degraded = true` in `~/.lpm/config.toml` or `./lpm.toml` for the V1 filesystem-only fallback (no outbound network containment); (2) `lpm config sandbox --set default` to drop back to the recommended default posture (filesystem + env containment, network allowed); (3) add the package to `package.json > lpm > trustedDependencies` to skip the sandbox for that dependency; (4) `lpm install --no-sandbox` for a one-shot escape (or `lpm config sandbox --set none` to persist); (5) upgrade the host kernel to 6.7+.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static SANDBOX_UNSUPPORTED_PLATFORM: CheckEntry = CheckEntry {
    code: "sandbox_unsupported_platform",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "No supported sandbox backend exists for this platform.",
    when_fires: "Running on a host where neither Seatbelt nor Landlock is available.",
    remediation: "Lifecycle scripts will not be sandboxed on this platform — review with `lpm approve-scripts`.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static SANDBOX_PROBE_FAILED: CheckEntry = CheckEntry {
    code: "sandbox_probe_failed",
    name: "Sandbox",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "The sandbox probe errored unexpectedly.",
    when_fires: "Backend reported an error not covered by the more specific codes.",
    remediation: "File a bug with the `detail` text.",
    possible_severities: &[Severity::Fail],
    auto_fix: None,
};

// `POLICY_SCOPE_PROJECT_ONLY` was removed — `lpm install -g`
// now honors the same script-policy / sandbox / cooldown / drift gates
// as project installs, so the boundary it described no longer exists.

pub static POLICY_FORCE_SECURITY_FLOOR: CheckEntry = CheckEntry {
    code: "policy_force_security_floor",
    name: "Script policy",
    category: Category::Sandbox,
    tier: Tier::Extended,
    description: "An override is in effect that lowers the default script-policy floor.",
    when_fires: "User opted into a less-strict policy via flag, env, or config.",
    remediation: "Review the override and confirm it matches the project's threat model.",
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

// ──────────────────────────────────────────────────────────────────
// Manifest compat (workspace-owned; thin adapter)
// ──────────────────────────────────────────────────────────────────
//
// These statics carry typed `CheckEntry` references so the runtime
// emission site can call `Check::warn(&PNPM_OVERRIDES_DRIFT, detail)`
// — but their prose fields point at the workspace's `pub const`s, so
// the underlying description / when-fires / remediation strings are
// owned by `lpm-workspace`. No duplication; updates to the workspace
// const flow through automatically.

pub static PNPM_OVERRIDES_DRIFT: CheckEntry = CheckEntry {
    code: lpm_workspace::PNPM_OVERRIDES_DRIFT_META.code,
    name: lpm_workspace::PNPM_OVERRIDES_DRIFT_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::PNPM_OVERRIDES_DRIFT_META.description,
    when_fires: lpm_workspace::PNPM_OVERRIDES_DRIFT_META.when_fires,
    remediation: lpm_workspace::PNPM_OVERRIDES_DRIFT_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static PNPM_PATCHES_DRIFT: CheckEntry = CheckEntry {
    code: lpm_workspace::PNPM_PATCHES_DRIFT_META.code,
    name: lpm_workspace::PNPM_PATCHES_DRIFT_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::PNPM_PATCHES_DRIFT_META.description,
    when_fires: lpm_workspace::PNPM_PATCHES_DRIFT_META.when_fires,
    remediation: lpm_workspace::PNPM_PATCHES_DRIFT_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static PNPM_PEER_RULES_DRIFT: CheckEntry = CheckEntry {
    code: lpm_workspace::PNPM_PEER_RULES_DRIFT_META.code,
    name: lpm_workspace::PNPM_PEER_RULES_DRIFT_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::PNPM_PEER_RULES_DRIFT_META.description,
    when_fires: lpm_workspace::PNPM_PEER_RULES_DRIFT_META.when_fires,
    remediation: lpm_workspace::PNPM_PEER_RULES_DRIFT_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static ENGINES_NPM_IGNORED: CheckEntry = CheckEntry {
    code: lpm_workspace::ENGINES_NPM_IGNORED_META.code,
    name: lpm_workspace::ENGINES_NPM_IGNORED_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::ENGINES_NPM_IGNORED_META.description,
    when_fires: lpm_workspace::ENGINES_NPM_IGNORED_META.when_fires,
    remediation: lpm_workspace::ENGINES_NPM_IGNORED_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static ENGINES_PNPM_IGNORED: CheckEntry = CheckEntry {
    code: lpm_workspace::ENGINES_PNPM_IGNORED_META.code,
    name: lpm_workspace::ENGINES_PNPM_IGNORED_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::ENGINES_PNPM_IGNORED_META.description,
    when_fires: lpm_workspace::ENGINES_PNPM_IGNORED_META.when_fires,
    remediation: lpm_workspace::ENGINES_PNPM_IGNORED_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static ENGINES_YARN_IGNORED: CheckEntry = CheckEntry {
    code: lpm_workspace::ENGINES_YARN_IGNORED_META.code,
    name: lpm_workspace::ENGINES_YARN_IGNORED_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::ENGINES_YARN_IGNORED_META.description,
    when_fires: lpm_workspace::ENGINES_YARN_IGNORED_META.when_fires,
    remediation: lpm_workspace::ENGINES_YARN_IGNORED_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

pub static ENGINES_BUN_IGNORED: CheckEntry = CheckEntry {
    code: lpm_workspace::ENGINES_BUN_IGNORED_META.code,
    name: lpm_workspace::ENGINES_BUN_IGNORED_META.name,
    category: Category::ManifestCompat,
    tier: Tier::Extended,
    description: lpm_workspace::ENGINES_BUN_IGNORED_META.description,
    when_fires: lpm_workspace::ENGINES_BUN_IGNORED_META.when_fires,
    remediation: lpm_workspace::ENGINES_BUN_IGNORED_META.remediation,
    possible_severities: &[Severity::Warn],
    auto_fix: None,
};

/// Manifest-compat catalog entries in stable order (mirrors
/// `lpm_workspace::MANIFEST_COMPAT_CATALOG`). Used by the runtime
/// adapter in `commands::doctor` to look up the typed entry by code.
pub static MANIFEST_COMPAT_ENTRIES: &[&CheckEntry] = &[
    &PNPM_OVERRIDES_DRIFT,
    &PNPM_PATCHES_DRIFT,
    &PNPM_PEER_RULES_DRIFT,
    &ENGINES_NPM_IGNORED,
    &ENGINES_PNPM_IGNORED,
    &ENGINES_YARN_IGNORED,
    &ENGINES_BUN_IGNORED,
];

/// Look up the typed catalog entry for a manifest-compat code.
/// Used by the runtime emission path in `commands::doctor` so the
/// [`crate::commands::doctor::Check`] constructor can take a
/// `&'static CheckEntry` for codes whose runtime row comes from a
/// workspace-side detector.
pub fn manifest_compat_entry(code: &str) -> Option<&'static CheckEntry> {
    MANIFEST_COMPAT_ENTRIES
        .iter()
        .copied()
        .find(|entry| entry.code == code)
}

// ──────────────────────────────────────────────────────────────────
// Catalog enumeration
// ──────────────────────────────────────────────────────────────────

/// Every CLI-side `CheckEntry`, in display order. Manifest-compat
/// entries are pulled in separately at runtime via the adapter in
/// [`all_entries`] so each catalog stays editable from one file.
pub static CLI_CATALOG: &[&CheckEntry] = &[
    // Infrastructure
    &REGISTRY_REACHABLE,
    &REGISTRY_UNREACHABLE,
    &GLOBAL_STORE_ACCESSIBLE,
    &GLOBAL_STORE_INACCESSIBLE,
    // Auth
    &AUTH_VALID,
    &AUTH_INVALID,
    &AUTH_MISSING,
    // Project state
    &PACKAGE_JSON_PRESENT,
    &PACKAGE_JSON_MISSING,
    &LINKER_MODE_RESOLVED,
    &NODE_MODULES_ISOLATED_HEALTHY,
    &NODE_MODULES_HOISTED_HEALTHY,
    &NODE_MODULES_VIRTUAL_HEALTHY,
    &NODE_MODULES_MIXED_LAYOUT,
    &NODE_MODULES_NO_STORE,
    &NODE_MODULES_LEGACY_LAYOUT,
    &NODE_MODULES_MISSING,
    &V2_STORE_ORPHANS,
    &LOCKFILE_PRESENT,
    &LOCKFILE_MISSING,
    &LOCKFILE_BINARY_VALID,
    &LOCKFILE_BINARY_MISSING,
    &LOCKFILE_BINARY_STALE,
    &LOCKFILE_BINARY_CORRUPT,
    &GITATTRIBUTES_LOCKB_MARKED,
    &GITATTRIBUTES_LOCKB_UNMARKED,
    &GITATTRIBUTES_MISSING,
    &DEPS_SYNC_CLEAN,
    &DEPS_SYNC_DRIFT,
    &LOCAL_SOURCE_DIR_OK,
    &LOCAL_SOURCE_TARBALL_OK,
    &LOCAL_SOURCE_DIR_NO_PKG,
    &LOCAL_SOURCE_INVALID_TYPE,
    &LOCAL_SOURCE_LINK_TO_FILE,
    &LOCAL_SOURCE_UNREADABLE,
    // lpm.json
    &LPM_JSON_VALID,
    &LPM_JSON_SCHEMA_WARNINGS,
    &LPM_JSON_INVALID_SYNTAX,
    &LPM_JSON_NOT_OBJECT,
    &LPM_JSON_UNREADABLE,
    // Runtime
    &NODE_MANAGED_MATCH,
    &NODE_PINNED_UNMET,
    &NODE_MISSING_PINNED,
    &NODE_SYSTEM_UNPINNED,
    &NODE_MISSING_UNPINNED,
    // Tunnel
    &TUNNEL_ACTIVE,
    &TUNNEL_IDLE,
    &TUNNEL_UNAUTHENTICATED,
    &TUNNEL_UNVERIFIED,
    &TUNNEL_NOT_CLAIMED,
    &TUNNEL_OWNED_BY_OTHER,
    &TUNNEL_UNREACHABLE,
    &TUNNEL_UNKNOWN_BASE,
    &TUNNEL_DOMAIN_NO_DOT,
    &TUNNEL_DOMAIN_EMPTY_LABEL,
    &TUNNEL_DOMAIN_LABEL_TOO_LONG,
    &TUNNEL_DOMAIN_TOO_LONG,
    &TUNNEL_SUBDOMAIN_LENGTH,
    &TUNNEL_SUBDOMAIN_CHARS,
    &TUNNEL_SUBDOMAIN_HYPHEN,
    // Code quality
    &LINT_CLEAN,
    &LINT_WARNINGS,
    &LINT_ERRORS,
    &LINT_UNPARSEABLE,
    &FMT_CLEAN,
    &FMT_UNFORMATTED,
    &FMT_OTHER_ISSUE,
    // TypeScript
    &TYPESCRIPT_HEALTHY,
    &TYPESCRIPT_MISSING_FOR_TSCONFIG,
    &TYPESCRIPT_UNAVAILABLE,
    // Plugin
    &PLUGIN_UP_TO_DATE,
    &PLUGIN_UPDATE_AVAILABLE,
    // Workspace
    &WORKSPACE_ACYCLIC,
    &WORKSPACE_CYCLE,
    // Globals
    &GLOBAL_MANIFEST_VALID,
    &GLOBAL_MANIFEST_ABSENT,
    &GLOBAL_MANIFEST_CORRUPT,
    &GLOBAL_BIN_ON_PATH,
    &GLOBAL_BIN_OFF_PATH,
    &GLOBAL_SHIMS_CLEAN,
    &GLOBAL_SHIMS_NO_DIR,
    &GLOBAL_SHIMS_ORPHANS,
    &GLOBAL_SHIMS_UNREADABLE,
    &GLOBAL_INSTALL_ROOTS_EMPTY,
    &GLOBAL_INSTALL_ROOTS_HEALTHY,
    &GLOBAL_INSTALL_ROOTS_UNHEALTHY,
    // Sandbox + script policy
    &SANDBOX_AVAILABLE,
    &SANDBOX_HELPER_MISSING,
    &SANDBOX_DEGRADED,
    &SANDBOX_DISABLED_BY_USER,
    &SANDBOX_KERNEL_TOO_OLD,
    &SANDBOX_UNSUPPORTED_PLATFORM,
    &SANDBOX_PROBE_FAILED,
    &POLICY_FORCE_SECURITY_FLOOR,
];

/// One row in the unified inventory surface used by `lpm doctor list`.
/// Workspace-owned codes (manifest-compat) get adapted into this
/// shape from [`lpm_workspace::ManifestCompatCatalogEntry`] without
/// duplicating their prose — the workspace crate stays the source
/// of truth for that subset.
#[derive(Debug, Clone)]
pub struct InventoryRow {
    pub code: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub tier: Tier,
    pub description: &'static str,
    pub when_fires: &'static str,
    pub remediation: &'static str,
    pub possible_severities: Vec<&'static str>,
    pub auto_fix: Option<&'static str>,
}

impl InventoryRow {
    fn from_cli(entry: &'static CheckEntry) -> Self {
        // Convert each typed-Severity variant to its stable `as_str()`.
        // ~96 catalog entries with 1–2 severities each — negligible work
        // on a non-hot path. Owned `Vec` keeps the row self-contained
        // (no static pools, no leak path, multi-severity Just Works
        // when the catalog grows to support it).
        let possible_severities = entry
            .possible_severities
            .iter()
            .map(|s| s.as_str())
            .collect();
        Self {
            code: entry.code,
            name: entry.name,
            category: entry.category,
            tier: entry.tier,
            description: entry.description,
            when_fires: entry.when_fires,
            remediation: entry.remediation,
            possible_severities,
            auto_fix: entry.auto_fix,
        }
    }
}

/// Unified inventory: every CLI-side entry plus every manifest-compat
/// entry, in stable order. The manifest-compat rows come from typed
/// `&'static CheckEntry` wrappers whose prose fields point at the
/// workspace-owned `pub const` originals — single source of truth.
pub fn all_entries() -> Vec<InventoryRow> {
    let mut rows: Vec<InventoryRow> = CLI_CATALOG
        .iter()
        .copied()
        .chain(MANIFEST_COMPAT_ENTRIES.iter().copied())
        .map(InventoryRow::from_cli)
        .collect();
    rows.shrink_to_fit();
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Catalog completeness drift-guard. Closes the second-hop gap
    /// the constructor signature alone cannot enforce.
    ///
    /// `Check::pass / fail / warn` already require `&'static CheckEntry`
    /// at the call site, so an emitted code is, by construction, a
    /// registered static. But [`CLI_CATALOG`] and [`MANIFEST_COMPAT_ENTRIES`]
    /// are still hand-maintained slices — a `pub static FOO: CheckEntry`
    /// can be defined and used at a call site without being added to
    /// those lists, in which case `lpm doctor list` would silently miss
    /// it AND the JSON inventory would be incomplete.
    ///
    /// This test parses this module's own source via `include_str!`,
    /// extracts every `pub static <NAME>: CheckEntry` declaration, and
    /// asserts each `<NAME>` appears as `&NAME,` in the source — the
    /// substring used by both registration slices. Define-but-don't-
    /// register fails the test with a pointer to the offending name.
    #[test]
    fn every_pub_static_check_entry_is_registered_for_listing() {
        const SRC: &str = include_str!("doctor_catalog.rs");

        // Walk the file and pull every `pub static <NAME>: CheckEntry`
        // declaration. rustfmt keeps the declaration on a single line
        // (the `=` opens a struct literal across many lines), so a
        // line-based scan is robust.
        let mut declared: Vec<&str> = Vec::new();
        for line in SRC.lines() {
            let trim = line.trim_start();
            if let Some(rest) = trim.strip_prefix("pub static ")
                && let Some(idx) = rest.find(": CheckEntry =")
            {
                declared.push(&rest[..idx]);
            }
        }

        assert!(
            !declared.is_empty(),
            "scanner found no `pub static` CheckEntry declarations — \
             the source layout changed; update this test rather than \
             skipping it"
        );

        // Each declared name must appear in the source as `&NAME,`,
        // which is the literal form used inside both registration
        // slices. The trailing comma anchors the match so a
        // substring-prefix collision (`&FOO_BAR` vs `&FOO`) cannot
        // false-pass.
        let mut unregistered: Vec<&str> = Vec::new();
        for name in &declared {
            let needle = format!("&{name},");
            if !SRC.contains(&needle) {
                unregistered.push(name);
            }
        }

        assert!(
            unregistered.is_empty(),
            "catalog static(s) defined but not registered in CLI_CATALOG \
             or MANIFEST_COMPAT_ENTRIES — `lpm doctor list` would miss \
             them. Add `&{first},` (and the rest) to the appropriate \
             slice in `doctor_catalog.rs`. Unregistered: {unregistered:?}",
            first = unregistered[0]
        );

        // Sanity floor: the catalog has many entries; if this number
        // ever drops sharply, something else is wrong.
        assert!(
            declared.len() >= 50,
            "expected at least 50 `pub static CheckEntry` declarations; \
             found {}. Has the catalog been gutted?",
            declared.len()
        );
    }

    #[test]
    fn every_catalog_entry_has_unique_code() {
        let mut codes: Vec<&str> = CLI_CATALOG.iter().map(|e| e.code).collect();
        let len = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), len, "duplicate code(s) in CLI_CATALOG");
    }

    #[test]
    fn every_catalog_entry_declares_at_least_one_severity() {
        for entry in CLI_CATALOG {
            assert!(
                !entry.possible_severities.is_empty(),
                "entry `{}` declares no severities",
                entry.code
            );
        }
    }

    #[test]
    fn every_catalog_entry_has_non_empty_metadata() {
        for entry in CLI_CATALOG {
            assert!(!entry.code.is_empty(), "entry has empty code");
            assert!(
                !entry.name.is_empty(),
                "entry `{}` has empty name",
                entry.code
            );
            assert!(
                !entry.description.is_empty(),
                "entry `{}` has empty description",
                entry.code
            );
            assert!(
                !entry.when_fires.is_empty(),
                "entry `{}` has empty when_fires",
                entry.code
            );
            assert!(
                !entry.remediation.is_empty(),
                "entry `{}` has empty remediation",
                entry.code
            );
        }
    }

    /// Tier drift-guard. Every `pub static <NAME>: CheckEntry`
    /// declaration in this module MUST explicitly assign a `tier:`
    /// field — leaving it to a struct-literal default is impossible
    /// (the field has no default), but a copy-paste of an old entry
    /// shape that pre-dates the tier field would fail to compile at
    /// the field-init level. This test is the belt-and-braces:
    /// every declaration has a `tier:` line between the opening `{`
    /// and the closing `};`. Catches the case where someone reorders
    /// fields or splits a declaration across helpers in a way that
    /// confuses the compiler about which entry the tier belongs to.
    ///
    /// Also asserts the fast-tier population stays bounded — sharp
    /// changes here are worth a second look, since the fast preset
    /// is the user-visible default surface of `lpm doctor`.
    #[test]
    fn every_pub_static_check_entry_declares_a_tier() {
        const SRC: &str = include_str!("doctor_catalog.rs");

        let mut current_entry: Option<&str> = None;
        let mut tier_seen_in_current = false;
        let mut missing: Vec<&str> = Vec::new();

        for line in SRC.lines() {
            let trim = line.trim_start();
            if let Some(rest) = trim.strip_prefix("pub static ")
                && let Some(idx) = rest.find(": CheckEntry =")
            {
                // Close out the previous entry before opening the new one.
                if let Some(name) = current_entry
                    && !tier_seen_in_current
                {
                    missing.push(name);
                }
                current_entry = Some(&rest[..idx]);
                tier_seen_in_current = false;
                continue;
            }
            if current_entry.is_some() && trim.starts_with("tier:") {
                tier_seen_in_current = true;
            }
            if current_entry.is_some() && trim == "};" {
                if !tier_seen_in_current && let Some(name) = current_entry {
                    missing.push(name);
                }
                current_entry = None;
                tier_seen_in_current = false;
            }
        }
        // Trailing entry, in case the file ends without a closing `};`
        // line (shouldn't happen, but guard against scanner drift).
        if let Some(name) = current_entry
            && !tier_seen_in_current
        {
            missing.push(name);
        }

        assert!(
            missing.is_empty(),
            "catalog static(s) missing a `tier:` field — every \
             `pub static <NAME>: CheckEntry = CheckEntry {{ ... }}` \
             MUST assign a tier explicitly. Missing: {missing:?}"
        );

        // Population sanity floors: at least one entry in each tier.
        // Catches the case where someone bulk-edits to a single tier.
        let fast = CLI_CATALOG
            .iter()
            .chain(MANIFEST_COMPAT_ENTRIES.iter())
            .filter(|e| matches!(e.tier, Tier::Fast))
            .count();
        let extended = CLI_CATALOG
            .iter()
            .chain(MANIFEST_COMPAT_ENTRIES.iter())
            .filter(|e| matches!(e.tier, Tier::Extended))
            .count();
        assert!(
            fast > 0 && extended > 0,
            "both tiers must have at least one entry; got fast={fast} extended={extended}"
        );
    }

    #[test]
    fn all_entries_includes_manifest_compat_codes() {
        let rows = all_entries();
        let codes: HashSet<&str> = rows.iter().map(|r| r.code).collect();
        for entry in lpm_workspace::MANIFEST_COMPAT_CATALOG {
            assert!(
                codes.contains(entry.code),
                "all_entries() missing manifest-compat code `{}`",
                entry.code
            );
        }
    }

    #[test]
    fn all_entries_is_unique_across_cli_and_manifest_compat() {
        let rows = all_entries();
        let mut codes: Vec<&str> = rows.iter().map(|r| r.code).collect();
        let len = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(
            codes.len(),
            len,
            "duplicate code(s) across CLI_CATALOG and MANIFEST_COMPAT_CATALOG"
        );
    }

    /// Cross-crate parity drift-guard.
    ///
    /// `lpm_workspace::MANIFEST_COMPAT_CATALOG` is the source of truth
    /// for manifest-compat code prose; `lpm_cli` declares a typed
    /// `&'static CheckEntry` wrapper per code in
    /// [`MANIFEST_COMPAT_ENTRIES`]. Both lists are hand-maintained.
    /// Adding a code to the workspace catalog without adding the CLI
    /// wrapper would compile fine, pass the workspace-side guard, AND
    /// pass the CLI-side `every_pub_static_check_entry_is_registered_for_listing`
    /// guard — but the runtime adapter at
    /// [`crate::commands::doctor::check_manifest_compat`] would
    /// silently drop the issue (no matching `&'static CheckEntry`
    /// resolves), and `lpm doctor list` would not list the new code.
    ///
    /// This test asserts every workspace-declared code resolves to a
    /// CLI-side wrapper via [`manifest_compat_entry`]. Adding a code
    /// to one list without the other fails this test before merge.
    #[test]
    fn manifest_compat_entries_cover_workspace_catalog() {
        for entry in lpm_workspace::MANIFEST_COMPAT_CATALOG {
            let resolved = manifest_compat_entry(entry.code);
            assert!(
                resolved.is_some(),
                "lpm_workspace::MANIFEST_COMPAT_CATALOG declares code `{}` but \
                 lpm_cli::doctor_catalog::MANIFEST_COMPAT_ENTRIES has no matching \
                 `pub static CheckEntry` wrapper. Add a wrapper that references \
                 `lpm_workspace::{}_META` (or the equivalent const) and register \
                 it into `MANIFEST_COMPAT_ENTRIES`.",
                entry.code,
                entry.code.to_uppercase(),
            );
        }

        // Symmetric check: no CLI wrapper exists for a code the
        // workspace doesn't declare. Catches stale wrappers left behind
        // when a workspace code gets removed.
        let workspace_codes: HashSet<&str> = lpm_workspace::MANIFEST_COMPAT_CATALOG
            .iter()
            .map(|e| e.code)
            .collect();
        for entry in MANIFEST_COMPAT_ENTRIES {
            assert!(
                workspace_codes.contains(entry.code),
                "lpm_cli::doctor_catalog::MANIFEST_COMPAT_ENTRIES carries `{}` but \
                 the workspace catalog no longer declares it. Remove the stale \
                 wrapper from `MANIFEST_COMPAT_ENTRIES`.",
                entry.code,
            );
        }
    }

    #[test]
    fn permits_returns_true_for_declared_severity() {
        assert!(REGISTRY_REACHABLE.permits(Severity::Pass));
        assert!(REGISTRY_UNREACHABLE.permits(Severity::Fail));
        assert!(NODE_MODULES_LEGACY_LAYOUT.permits(Severity::Warn));
    }

    #[test]
    fn permits_returns_false_for_undeclared_severity() {
        assert!(!REGISTRY_REACHABLE.permits(Severity::Fail));
        assert!(!REGISTRY_UNREACHABLE.permits(Severity::Pass));
        assert!(!NODE_MODULES_LEGACY_LAYOUT.permits(Severity::Fail));
    }
}
