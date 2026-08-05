use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::path::Path;

use crate::error::WorkspaceError;
use crate::trust::TrustedDependencies;
use lpm_common::{
    BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, read_file_capped, read_text_file_capped,
    strip_utf8_bom_bytes, strip_utf8_bom_str,
};

#[derive(Debug, Clone, Default)]
pub struct PackageJson {
    pub name: Option<String>,

    pub version: Option<String>,

    pub dependencies: HashMap<String, String>,

    pub dev_dependencies: HashMap<String, String>,

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
    pub peer_dependencies_meta: HashMap<String, PeerDependencyMeta>,

    pub optional_dependencies: HashMap<String, String>,

    /// npm overrides / yarn resolutions — force specific versions for
    /// direct and transitive dependencies.
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
    /// The manifest normalizer keeps the simple `String`-valued
    /// entries and records unsupported shapes for install and doctor
    /// compatibility warnings.
    pub overrides: HashMap<String, String>,

    /// Yarn-style resolutions (same purpose as overrides). Same
    /// lossy-string-map handling as `overrides`: yarn also supports
    /// nested resolution objects, which we drop during normalization.
    pub resolutions: HashMap<String, String>,

    /// Top-level `overrides` and `resolutions` entries whose values are
    /// not strings. The supported entries remain usable; compatibility
    /// checks surface these ignored entries without rejecting the manifest.
    pub unsupported_override_values: Vec<String>,

    pub workspaces: Option<WorkspacesConfig>,

    /// Publish-time package projection. Workspace consumers link to
    /// `directory` when it is declared, matching pnpm's local-package view.
    pub publish_config: PublishConfig,

    /// LPM-specific config section (decided: config goes in package.json "lpm" key).
    pub lpm: Option<LpmConfig>,

    /// Engine version constraints (e.g., `{"node": ">=22.0.0"}`).
    pub engines: HashMap<String, String>,

    /// Scripts defined in package.json (e.g., "build": "tsup", "dev": "vite dev").
    pub scripts: HashMap<String, String>,

    /// Binary executables exposed by this package.
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
    pub pnpm: Option<PnpmRaw>,
}

impl<'de> Deserialize<'de> for PackageJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        package_json_from_value(&value).map_err(serde::de::Error::custom)
    }
}

fn package_json_from_value(value: &serde_json::Value) -> Result<PackageJson, String> {
    let Some(obj) = value.as_object() else {
        return Err("expected package.json object".to_string());
    };

    let (overrides, mut unsupported_override_values) =
        override_map_from_value("overrides", obj.get("overrides"));
    let (resolutions, unsupported_resolutions) =
        override_map_from_value("resolutions", obj.get("resolutions"));
    unsupported_override_values.extend(unsupported_resolutions);

    Ok(PackageJson {
        name: string_field(obj, "name"),
        version: string_field(obj, "version"),
        dependencies: lossy_string_map_from_value(obj.get("dependencies")),
        dev_dependencies: lossy_string_map_from_value(obj.get("devDependencies")),
        peer_dependencies: lossy_string_map_from_value(obj.get("peerDependencies")),
        peer_dependencies_meta: peer_meta_map_from_value(obj.get("peerDependenciesMeta")),
        optional_dependencies: lossy_string_map_from_value(obj.get("optionalDependencies")),
        overrides,
        resolutions,
        unsupported_override_values,
        workspaces: optional_typed_field(obj, "workspaces")?,
        publish_config: publish_config_from_value(obj.get("publishConfig")),
        lpm: optional_typed_field(obj, "lpm")?,
        engines: lossy_string_map_from_value(obj.get("engines")),
        scripts: lossy_string_map_from_value(obj.get("scripts")),
        bin: obj.get("bin").and_then(bin_config_from_value),
        catalogs: lossy_nested_string_map_from_value(obj.get("catalogs")),
        pnpm: optional_typed_field(obj, "pnpm")?,
    })
}

fn string_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn optional_typed_field<T>(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<T>, String>
where
    T: DeserializeOwned,
{
    obj.get(key)
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|e| format!("failed to parse package.json field `{key}`: {e}"))
        })
        .transpose()
}

fn lossy_string_map_from_value(value: Option<&serde_json::Value>) -> HashMap<String, String> {
    let Some(obj) = value.and_then(serde_json::Value::as_object) else {
        return HashMap::new();
    };

    obj.iter()
        .filter_map(|(key, value)| {
            value
                .as_str()
                .map(|string| (key.clone(), string.to_string()))
        })
        .collect()
}

fn override_map_from_value(
    field: &str,
    value: Option<&serde_json::Value>,
) -> (HashMap<String, String>, Vec<String>) {
    let Some(value) = value else {
        return (HashMap::new(), Vec::new());
    };
    let Some(obj) = value.as_object() else {
        return (
            HashMap::new(),
            vec![format!("`{field}` ({})", json_value_kind(value))],
        );
    };

    let mut supported = HashMap::with_capacity(obj.len());
    let mut unsupported = Vec::new();
    for (key, value) in obj {
        if let Some(target) = value.as_str() {
            supported.insert(key.clone(), target.to_string());
        } else {
            unsupported.push(format!("`{field}.{key}` ({})", json_value_kind(value)));
        }
    }
    (supported, unsupported)
}

fn json_value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "nested object",
    }
}

fn lossy_nested_string_map_from_value(
    value: Option<&serde_json::Value>,
) -> HashMap<String, HashMap<String, String>> {
    let Some(obj) = value.and_then(serde_json::Value::as_object) else {
        return HashMap::new();
    };

    obj.iter()
        .filter_map(|(key, value)| {
            let nested = value.as_object()?;
            let map = nested
                .iter()
                .filter_map(|(entry_key, entry_value)| {
                    entry_value
                        .as_str()
                        .map(|entry_value| (entry_key.clone(), entry_value.to_string()))
                })
                .collect();
            Some((key.clone(), map))
        })
        .collect()
}

fn peer_meta_map_from_value(
    value: Option<&serde_json::Value>,
) -> HashMap<String, PeerDependencyMeta> {
    let Some(obj) = value.and_then(serde_json::Value::as_object) else {
        return HashMap::new();
    };

    obj.iter()
        .filter_map(|(key, value)| {
            serde_json::from_value(value.clone())
                .ok()
                .map(|meta| (key.clone(), meta))
        })
        .collect()
}

fn bin_config_from_value(value: &serde_json::Value) -> Option<BinConfig> {
    if let Some(path) = value.as_str() {
        return Some(BinConfig::Single(path.to_string()));
    }

    value
        .as_object()
        .map(|_| BinConfig::Map(lossy_string_map_from_value(Some(value))))
}

fn publish_config_from_value(value: Option<&serde_json::Value>) -> PublishConfig {
    PublishConfig {
        directory: value
            .and_then(serde_json::Value::as_object)
            .and_then(|config| config.get("directory"))
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    }
}

/// The package directory exposed to registry consumers and local workspace links.
#[derive(Debug, Clone, Default)]
pub struct PublishConfig {
    /// Path relative to the package root that contains the publishable package tree.
    pub directory: Option<String>,
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

/// The `"bin"` field in package.json can be a string or an object.
///
/// - String form: `"bin": "./cli.js"` — name defaults to package name
/// - Object form: `"bin": { "my-cmd": "./cli.js", "other": "./other.js" }`
#[derive(Debug, Clone)]
pub enum BinConfig {
    /// Single binary: `"bin": "./cli.js"` — command name = package name.
    Single(String),
    /// Multiple binaries: `"bin": { "cmd": "./path.js" }`.
    Map(HashMap<String, String>),
}

impl<'de> Deserialize<'de> for BinConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        bin_config_from_value(&value)
            .ok_or_else(|| serde::de::Error::custom("expected string or object for bin"))
    }
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
    Object {
        #[serde(default)]
        packages: Vec<String>,
    },
}

/// LPM-specific config in package.json `"lpm"` key.
#[derive(Debug, Clone, Default, Deserialize)]
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

    /// Exact package names exempted from the minimum release age gate.
    #[serde(default, rename = "minimumReleaseAgeExclude")]
    pub minimum_release_age_exclude: Vec<String>,

    /// Scope of the minimum release age gate: `"direct"` (default) or
    /// `"strict"` (direct and transitive dependencies).
    #[serde(default, rename = "minimumReleaseAgePolicy")]
    pub minimum_release_age_policy: Option<String>,

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

    /// LPM-native overrides location, declared inside the `"lpm"` section
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

    /// Peer-dependency rules for the resolver. Uses the
    /// `pnpm.peerDependencyRules` shape verbatim so `lpm migrate` can
    /// translate without value transformation.
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
    /// the resolver. When `false`, missing peers use warn-only semantics:
    /// the post-resolve
    /// [`lpm_resolver::check_unmet_peers`] pass surfaces them as
    /// `PeerWarning`s and the user manually adds them to
    /// `dependencies`.
    ///
    /// **Default is `true` (auto-install on)** — beta-default favors
    /// the eager model so peer-declaring packages "just work" without
    /// the user having to re-read the install log to find missing
    /// names. Set to `false` for warn-only peer handling.
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

    /// Fail installs when peer-dependency warnings or best-effort peer
    /// conflicts are detected.
    ///
    /// Default is `false`, preserving LPM's warn-only behavior. Set `true`
    /// for CI or strict compatibility runs that should reject missing peers,
    /// incompatible resolved peer versions, and peer-conflict fallback
    /// selections.
    ///
    /// Precedence (resolved in `install.rs`):
    ///   CLI `--strict-peer-dependencies` / `--no-strict-peer-dependencies`
    ///   → `package.json > lpm > strictPeerDependencies`
    ///   → `~/.lpm/config.toml > strict-peer-dependencies`
    ///   → default (`false`).
    #[serde(default, rename = "strictPeerDependencies")]
    pub strict_peer_dependencies: Option<bool>,

    /// Controls whether `lpm install <pkg>` saves matching dependencies
    /// through the root default catalog.
    #[serde(default, rename = "catalogMode")]
    pub catalog_mode: Option<CatalogMode>,

    /// Removes catalog entries no root/member manifest references after install.
    #[serde(default, rename = "cleanupUnusedCatalogs")]
    pub cleanup_unused_catalogs: Option<bool>,
}

/// Save policy for dependencies that have a matching default catalog entry.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CatalogMode {
    Manual,
    Prefer,
    Strict,
}

/// `package.json :: lpm.peerDependencyRules` — peer-dep behavior
/// rules consumed by the resolver's post-resolution peer-warning
/// pass.
///
/// Uses the `pnpm.peerDependencyRules` shape so `lpm migrate` can translate
/// without value transformation. See the
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

pub fn read_package_json(path: &Path) -> Result<PackageJson, WorkspaceError> {
    let content =
        read_text_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES).map_err(map_manifest_read_error)?;

    serde_json::from_str(strip_utf8_bom_str(&content))
        .map_err(|e| WorkspaceError::Parse(format!("failed to parse {}: {e}", path.display())))
}

/// Pair of maps returned by [`read_peer_dependencies`].
pub type PeerDepsResult = (HashMap<String, String>, HashMap<String, PeerDependencyMeta>);

/// Read only `peerDependencies` and `peerDependenciesMeta` from a `package.json`.
///
/// Parses through `serde_json::Value` so duplicate keys and non-string
/// peer-dependency values in third-party manifests don't reject the whole
/// scan. Callers should byte-scan first when they are on hot paths.
pub fn read_peer_dependencies(path: &Path) -> Result<PeerDepsResult, WorkspaceError> {
    let content =
        read_file_capped(path, CONFIG_FILE_SIZE_CAP_BYTES).map_err(map_manifest_read_error)?;
    parse_peer_dependencies(&content)
        .map_err(|e| WorkspaceError::Parse(format!("failed to parse {}: {e}", path.display())))
}

fn map_manifest_read_error(error: BoundedReadError) -> WorkspaceError {
    match error {
        BoundedReadError::NotFound { path } => WorkspaceError::NotFound(path.display().to_string()),
        other => WorkspaceError::Io(other.to_string()),
    }
}

/// Parse peer-dependency info from already-read JSON bytes.
///
/// Callers that first byte-scan for `b"peerDependencies"` before calling
/// this can skip the full `serde_json` parse for packages with no peer
/// deps — the common case for the majority of packages in any install set.
/// See `ensure_peer_context` in `lpm-linker` for the canonical call site.
pub fn parse_peer_dependencies(content: &[u8]) -> Result<PeerDepsResult, WorkspaceError> {
    let parsed: serde_json::Value = serde_json::from_slice(strip_utf8_bom_bytes(content))
        .map_err(|e| WorkspaceError::Parse(format!("parse error: {e}")))?;
    let Some(obj) = parsed.as_object() else {
        return Ok((HashMap::new(), HashMap::new()));
    };
    Ok((
        lossy_string_map_from_value(obj.get("peerDependencies")),
        peer_meta_map_from_value(obj.get("peerDependenciesMeta")),
    ))
}

/// Parse only the `bin` field from already-read `package.json` bytes.
///
/// Parses through `serde_json::Value` so duplicate keys and non-string map
/// entries in third-party manifests don't reject the whole scan. Callers that
/// byte-scan for `b"\"bin\""` before calling this can skip the parse entirely
/// for packages that declare no binary — the common case.
///
/// See `create_bin_links_v2` in `lpm-linker` for the canonical call site.
pub fn parse_bin_field(content: &[u8]) -> Result<Option<BinConfig>, WorkspaceError> {
    let parsed: serde_json::Value = serde_json::from_slice(strip_utf8_bom_bytes(content))
        .map_err(|e| WorkspaceError::Parse(format!("parse error: {e}")))?;
    Ok(parsed.get("bin").and_then(bin_config_from_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn read_package_json_accepts_utf8_bom_prefixed_manifest() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            "\u{feff}{\"name\":\"bom-prefixed\",\"version\":\"1.0.0\"}",
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();

        assert_eq!(pkg.name.as_deref(), Some("bom-prefixed"));
    }

    #[test]
    fn read_package_json_captures_publish_directory() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"published-projection","publishConfig":{"directory":"build"}}"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();

        assert_eq!(pkg.publish_config.directory.as_deref(), Some("build"));
    }

    /// Regression test for the rollup plugins fixture. rollup's
    /// `package.json` ships `overrides` with a nested-object value
    /// (`"path-scurry": {"lru-cache": "^11.3.5"}`) — valid npm syntax for
    /// "only override `lru-cache` when `path-scurry` is in scope." The
    /// strict `HashMap<String, String>` deserialization errored on this
    /// shape ("invalid type: map, expected a string"), making the entire
    /// `read_package_json` call fail and silently breaking
    /// `lpm-linker::create_bin_links` (no `node_modules/.bin/rollup`).
    ///
    /// `read_package_json` succeeds: simple string-valued
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

        // Nested-object overrides are excluded from the applied string map.
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
        assert_eq!(
            pkg.unsupported_override_values,
            vec![
                "`overrides.path-scurry` (nested object)".to_string(),
                "`resolutions.deeply-nested` (nested object)".to_string(),
            ]
        );

        // Crucially, the rest of the manifest survives — strict parsing
        // rejected the entire manifest before reaching this point.
        let bin = pkg.bin.as_ref().expect("bin must be parsed");
        let entries = bin.entries(pkg.name.as_deref().unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "some-cli");
    }

    #[test]
    fn read_package_json_tolerates_real_world_duplicate_maps_and_weird_values() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "weird-real-world-manifest",
                "version": "1.0.0",
                "dependencies": {
                    "old-copy": "0.0.1"
                },
                "dependencies": {
                    "react": "^19.0.0",
                    "skip-boolean": false,
                    "skip-object": {"nested": "1.0.0"}
                },
                "devDependencies": {
                    "typescript": "5.9.2",
                    "skip-number": 42
                },
                "peerDependencies": {
                    "@types/node": ">=18",
                    "skip-null": null
                },
                "optionalDependencies": {
                    "fsevents": "^2.3.3",
                    "skip-array": ["^1.0.0"]
                },
                "scripts": {
                    "postinstall": "node setup.js",
                    "skip-script": ["node", "setup.js"]
                },
                "engines": {
                    "node": ">=18",
                    "npm": 10
                },
                "types": ["./dist/index.d.ts"]
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json"))
            .expect("weird but valid npm manifests must not fail the whole parse");

        assert_eq!(pkg.dependencies.len(), 1);
        assert_eq!(
            pkg.dependencies.get("react").map(String::as_str),
            Some("^19.0.0")
        );
        assert!(!pkg.dependencies.contains_key("old-copy"));
        assert!(!pkg.dependencies.contains_key("skip-boolean"));
        assert!(!pkg.dependencies.contains_key("skip-object"));
        assert_eq!(
            pkg.dev_dependencies.get("typescript").map(String::as_str),
            Some("5.9.2")
        );
        assert!(!pkg.dev_dependencies.contains_key("skip-number"));
        assert_eq!(
            pkg.peer_dependencies.get("@types/node").map(String::as_str),
            Some(">=18")
        );
        assert!(!pkg.peer_dependencies.contains_key("skip-null"));
        assert_eq!(
            pkg.optional_dependencies
                .get("fsevents")
                .map(String::as_str),
            Some("^2.3.3")
        );
        assert!(!pkg.optional_dependencies.contains_key("skip-array"));
        assert_eq!(
            pkg.scripts.get("postinstall").map(String::as_str),
            Some("node setup.js")
        );
        assert!(!pkg.scripts.contains_key("skip-script"));
        assert_eq!(pkg.engines.get("node").map(String::as_str), Some(">=18"));
        assert!(!pkg.engines.contains_key("npm"));
    }

    #[test]
    fn read_package_json_preserves_empty_named_catalogs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "empty-catalog-fixture",
                "version": "1.0.0",
                "catalogs": {
                    "testing": {}
                }
            }"#,
        );

        let pkg = read_package_json(&dir.path().join("package.json")).unwrap();
        let testing = pkg
            .catalogs
            .get("testing")
            .expect("empty named catalog must still exist");
        assert!(testing.is_empty());
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

    #[test]
    fn test_minimum_release_age_exclude() {
        let json = r#"{"lpm": {"minimumReleaseAgeExclude": ["react", "@scope/pkg"]}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(
            lpm.minimum_release_age_exclude,
            vec!["react".to_string(), "@scope/pkg".to_string()]
        );
    }

    #[test]
    fn test_minimum_release_age_policy() {
        let json = r#"{"lpm": {"minimumReleaseAgePolicy": "strict"}}"#;
        let pkg: PackageJson = serde_json::from_str(json).unwrap();
        let lpm = pkg.lpm.unwrap();
        assert_eq!(lpm.minimum_release_age_policy.as_deref(), Some("strict"));
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

    #[test]
    fn catalog_mode_deserializes_supported_lpm_values() {
        for (raw, expected) in [
            ("manual", CatalogMode::Manual),
            ("prefer", CatalogMode::Prefer),
            ("strict", CatalogMode::Strict),
        ] {
            let json = format!(r#"{{"lpm": {{"catalogMode": "{raw}"}}}}"#);
            let pkg: PackageJson = serde_json::from_str(&json).unwrap();
            assert_eq!(pkg.lpm.unwrap().catalog_mode, Some(expected));
        }
    }

    #[test]
    fn catalog_mode_rejects_unknown_lpm_value() {
        let err = serde_json::from_str::<PackageJson>(r#"{"lpm": {"catalogMode": "loose"}}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "unknown catalogMode must fail manifest parsing, got: {err}"
        );
    }

    #[test]
    fn cleanup_unused_catalogs_deserializes_lpm_config() {
        let pkg: PackageJson =
            serde_json::from_str(r#"{"lpm": {"cleanupUnusedCatalogs": true}}"#).unwrap();
        assert_eq!(
            pkg.lpm.unwrap().cleanup_unused_catalogs,
            Some(true),
            "lpm.cleanupUnusedCatalogs should parse as an optional boolean"
        );
    }

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
    fn parse_peer_dependencies_accepts_utf8_bom_prefixed_json() {
        let json = b"\xEF\xBB\xBF{\"peerDependencies\":{\"react\":\"^19.0.0\"}}";

        let (deps, meta) = parse_peer_dependencies(json).unwrap();

        assert_eq!(deps.get("react").map(String::as_str), Some("^19.0.0"));
        assert!(meta.is_empty());
    }

    #[test]
    fn parse_skips_non_string_peer_dependency_values() {
        let json = br#"{
            "name": "loose-peer-fixture",
            "peerDependencies": {
                "react": "^19.0.0",
                "skip-bool": false,
                "skip-object": {"range": "^1.0.0"}
            },
            "peerDependenciesMeta": {
                "react": { "optional": true }
            }
        }"#;
        let (deps, meta) = parse_peer_dependencies(json).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps.get("react").map(|s| s.as_str()), Some("^19.0.0"));
        assert!(meta.get("react").unwrap().optional);
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

    #[test]
    fn parse_bin_field_accepts_utf8_bom_prefixed_json() {
        let json = b"\xEF\xBB\xBF{\"name\":\"eslint\",\"bin\":{\"eslint\":\"./bin/eslint.js\"}}";

        let result = parse_bin_field(json).unwrap().unwrap();

        match result {
            BinConfig::Map(map) => {
                assert_eq!(
                    map.get("eslint").map(String::as_str),
                    Some("./bin/eslint.js")
                );
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
            "lpm-bin-parity-{}-{:?}.json",
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
