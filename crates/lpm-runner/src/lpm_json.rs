//! `lpm.json` configuration reader.
//!
//! `lpm.json` sits alongside `package.json` and provides LPM-specific config:
//! - `runtime` — pinned runtime versions (e.g., `{"node": ">=22.0.0"}`)
//! - `env` — env file mapping per script (e.g., `{"dev": ".env.development"}`)
//! - `tasks` — task configuration with caching, dependencies, outputs
//! - `remoteCache` — hosted cache settings for cache-enabled tasks
//!
//! This file is optional. Falls back to `package.json` fields when absent.

use lpm_common::{BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, read_text_file_capped};
use lpm_env::{EnvSchema, EnvironmentsConfig};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::LazyLock;

const LPM_JSON_SCHEMA_URL: &str = "https://cli.lpm.dev/schemas/lpm.json";

/// Configuration from `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct LpmJsonConfig {
    /// Optional JSON Schema URI used by editors.
    #[serde(default, rename = "$schema")]
    #[schemars(extend("format" = "uri"))]
    pub schema: Option<String>,

    /// Stable project identifier for encrypted environment storage.
    #[serde(default)]
    pub vault: Option<String>,

    /// Project-local cloud sync metadata maintained by `lpm env`.
    #[serde(default, rename = "vaultSync")]
    pub vault_sync: Option<VaultSyncConfig>,

    /// Pinned runtime versions.
    /// e.g., `{"node": ">=22.0.0", "deno": ">=2.0.0"}`
    #[serde(default)]
    pub runtime: HashMap<String, String>,

    /// Env file mapping per script name.
    /// e.g., `{"dev": ".env.development", "staging": ".env.staging"}`
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Task configuration for caching, dependency ordering, and outputs.
    #[serde(default)]
    pub tasks: HashMap<String, TaskConfig>,

    /// Hosted task cache configuration.
    #[serde(default, rename = "remoteCache")]
    pub remote_cache: Option<RemoteCacheConfig>,

    /// Pinned managed tool versions.
    /// e.g., `{"oxlint": "1.57.0", "biome": "2.4.8", "rolldown": "1.0.2"}`
    #[serde(default)]
    pub tools: HashMap<String, String>,

    /// Dev services for multi-process orchestration.
    /// e.g., `{"web": {"command": "next dev", "port": 3000}}`
    #[serde(default, deserialize_with = "deserialize_unique_services")]
    pub services: HashMap<String, ServiceConfig>,

    /// Dev reverse-proxy configuration for friendly local hostnames.
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    /// Enable local HTTPS for `lpm dev`.
    /// When `true`, `lpm dev` auto-generates and trusts a local certificate.
    /// Overridden by `--no-https` CLI flag.
    #[serde(default)]
    pub https: Option<bool>,

    /// Tunnel configuration for `lpm dev --tunnel`.
    /// e.g., `{"domain": "acme-api.lpm.llc"}`
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,

    /// Publish configuration for multi-registry publishing.
    /// e.g., `{"registries": ["lpm", "npm"], "npm": {"name": "@scope/pkg"}}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<PublishConfig>,

    /// Environment variable schema for validation.
    /// Defines required vars, formats, patterns, defaults, and secrets.
    /// e.g., `{"envSchema": {"vars": {"DATABASE_URL": {"required": true, "format": "url"}}}}`
    #[serde(default, rename = "envSchema")]
    pub env_schema: Option<EnvSchema>,

    /// Named environment definitions with inheritance.
    /// e.g., `{"environments": {"staging": {"extends": "base", "file": ".env.staging"}}}`
    #[serde(default)]
    pub environments: Option<EnvironmentsConfig>,

    /// Local-HTTPS certificate configuration.
    ///
    /// `extra_permitted_dns` entries are validated at parse time and can be
    /// consumed by project-scoped certificate-chain generation.
    #[serde(default)]
    pub cert: Option<CertBlock>,
}

fn deserialize_unique_services<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, ServiceConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueServicesVisitor;

    impl<'de> Visitor<'de> for UniqueServicesVisitor {
        type Value = HashMap<String, ServiceConfig>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique service names")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut services = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((name, service)) = access.next_entry::<String, ServiceConfig>()? {
                if services.insert(name.clone(), service).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate service `{name}`"
                    )));
                }
            }
            Ok(services)
        }
    }

    deserializer.deserialize_map(UniqueServicesVisitor)
}

/// Cloud sync metadata maintained by `lpm env`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct VaultSyncConfig {
    #[serde(default)]
    pub personal_version: Option<i32>,

    #[serde(default)]
    pub personal_synced_at: Option<String>,

    #[serde(default)]
    pub org_versions: HashMap<String, i32>,

    #[serde(default)]
    pub org_synced_at: HashMap<String, String>,
}

/// Hosted cache configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct RemoteCacheConfig {
    /// Enable hosted task cache reads and writes for cache-enabled tasks.
    #[serde(default)]
    pub enabled: bool,

    /// Organization slug/team namespace. Omit for the authenticated personal namespace.
    #[serde(default)]
    pub team: Option<String>,

    /// Remote cache service URL. Defaults to the configured LPM registry plus `/v8`.
    #[serde(default)]
    pub url: Option<String>,

    /// Require HMAC tags on downloads and attach them to uploads.
    #[serde(default)]
    pub signature: bool,

    /// Read remote artifacts but do not upload newly produced artifacts.
    #[serde(default, rename = "readOnly")]
    pub read_only: bool,

    /// Controls which loaded environment variables may be used with remote uploads.
    #[serde(default)]
    pub env: RemoteCacheEnvConfig,
}

/// Env safety controls for hosted task cache uploads.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct RemoteCacheEnvConfig {
    /// Variable-name patterns explicitly allowed for remote uploads.
    #[serde(default)]
    pub include: Vec<String>,

    /// Variable-name patterns that block remote uploads.
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Permit secret-looking variable names after explicit project opt-in.
    #[serde(default, rename = "allowSecrets")]
    pub allow_secrets: bool,
}

/// `cert` configuration block in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct CertBlock {
    /// Additional DNS subtrees the project-scoped intermediate may permit.
    /// Each entry must be a bare multi-label hostname. Wildcards, leading dots,
    /// and non-local TLDs are rejected at parse time.
    #[serde(default, rename = "extraPermittedDns")]
    pub extra_permitted_dns: Vec<String>,

    /// Permit non-local TLDs (e.g. `staging.example.com`) in
    /// `extraPermittedDns`. Off by default — public-internet hostnames widen
    /// the CA's authority and require explicit opt-in.
    #[serde(default, rename = "allowPublicDns")]
    pub allow_public_dns: bool,
}

/// Tunnel configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct TunnelConfig {
    /// Full tunnel domain (e.g., "acme-api.lpm.llc").
    /// Pro/Org only — free users get ephemeral random domains.
    #[serde(default)]
    pub domain: Option<String>,
}

/// Dev reverse-proxy configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Top-level host routed by the local dev proxy.
    #[serde(default)]
    pub host: Option<String>,

    /// Listen port for the HTTPS proxy. Defaults to 443.
    #[serde(default)]
    pub port: Option<u16>,

    /// Also listen on :80 and redirect to HTTPS. Defaults to true.
    #[serde(default, rename = "httpRedirect")]
    pub http_redirect: Option<bool>,
}

/// Publish configuration in `lpm.json`.
///
/// Controls which registries `lpm publish` targets and per-registry settings.
/// CLI flags (`--npm`, `--lpm`) override these values.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublishConfig {
    /// Target registries. e.g., `["lpm", "npm"]`.
    /// If absent, defaults to `["lpm"]` (backward compatible).
    #[serde(default = "default_publish_registries")]
    pub registries: Vec<String>,

    /// LPM registry publish settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lpm: Option<LpmPublishConfig>,

    /// npm-specific publish settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm: Option<NpmPublishConfig>,

    /// GitHub Packages publish settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubPublishConfig>,

    /// GitLab Packages publish settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab: Option<GitlabPublishConfig>,
}

fn default_publish_registries() -> Vec<String> {
    vec!["lpm".to_string()]
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            registries: default_publish_registries(),
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        }
    }
}

/// LPM registry publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct LpmPublishConfig {
    /// Override package name for LPM (must be `@lpm.dev/owner.pkg` format).
    #[serde(default)]
    pub name: Option<String>,
}

/// npm-specific publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct NpmPublishConfig {
    /// Override package name for npm (e.g., `"@scope/pkg"`).
    /// Required if the package.json name starts with `@lpm.dev/`.
    #[serde(default)]
    pub name: Option<String>,

    /// Access level: `"public"` or `"restricted"`.
    /// Defaults to `"public"` for npm-compatible publishes unless configured.
    #[serde(default)]
    pub access: Option<String>,

    /// dist-tag for the published version (default: `"latest"`).
    #[serde(default)]
    pub tag: Option<String>,

    /// Custom npm registry URL (default: `https://registry.npmjs.org`).
    #[serde(default)]
    pub registry: Option<String>,

    /// Prompt for OTP before the first publish attempt (saves a round-trip).
    #[serde(default)]
    pub otp_required: Option<bool>,
}

/// GitHub Packages publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct GithubPublishConfig {
    /// Override package name for GitHub Packages (must be scoped: `@owner/pkg`).
    #[serde(default)]
    pub name: Option<String>,

    /// Access level: `"public"` or `"restricted"`.
    #[serde(default)]
    pub access: Option<String>,
}

/// GitLab Packages publish configuration in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct GitlabPublishConfig {
    /// Override package name for GitLab Packages.
    #[serde(default)]
    pub name: Option<String>,

    /// Access level: `"public"` or `"restricted"`.
    #[serde(default)]
    pub access: Option<String>,

    /// GitLab project ID (required for GitLab npm registry URL).
    pub project_id: Option<String>,

    /// GitLab instance URL (default: `https://gitlab.com`).
    #[serde(default)]
    pub registry: Option<String>,
}

/// Configuration for a dev service in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Shell command to run.
    pub command: String,

    /// Port this service listens on; omitted host-only services get a stable auto-assigned port.
    #[serde(default)]
    pub port: Option<u16>,

    /// Services that must be ready before this one starts.
    #[serde(default, rename = "dependsOn")]
    pub depends_on: Vec<String>,

    /// TCP port to check for readiness (defaults to `port` if set).
    #[serde(default, rename = "readyPort")]
    pub ready_port: Option<u16>,

    /// HTTP URL to poll for readiness (2xx = ready).
    #[serde(default, rename = "readyUrl")]
    pub ready_url: Option<String>,

    /// Seconds to wait for readiness (default: 30).
    #[serde(default = "default_ready_timeout", rename = "readyTimeout")]
    pub ready_timeout: u64,

    /// Extra environment variables for this service.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Auto-restart on crash with exponential backoff.
    #[serde(default)]
    pub restart: bool,

    /// This is the primary service (receives --https/--tunnel/--network).
    #[serde(default)]
    pub primary: bool,

    /// Friendly local hostname routed to this service by the dev proxy.
    #[serde(default)]
    pub host: Option<String>,

    /// Working directory relative to project root.
    #[serde(default)]
    pub cwd: Option<String>,
}

fn default_ready_timeout() -> u64 {
    30
}

impl ServiceConfig {
    /// Get the port to use for readiness checking.
    /// Priority: readyPort > port > None
    pub fn effective_ready_port(&self) -> Option<u16> {
        self.ready_port.or(self.port)
    }
}

/// Configuration for a single task in `lpm.json`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct TaskConfig {
    /// Command to run (overrides package.json scripts).
    #[serde(default)]
    pub command: Option<String>,

    /// Task dependencies. `"build"` = same package, `"^build"` = upstream workspace deps.
    #[serde(default, rename = "dependsOn")]
    pub depends_on: Vec<String>,

    /// Enable local task caching for this task.
    #[serde(default)]
    pub cache: bool,

    /// Output file globs to cache (e.g., `["dist/**"]`). Required for caching.
    #[serde(default)]
    pub outputs: Vec<String>,

    /// Input globs that invalidate cache. Empty lists use the documented project defaults.
    #[serde(default)]
    pub inputs: Vec<String>,

    /// Env mode for this task (e.g., `"development"` → loads `.env.development`).
    #[serde(default)]
    pub env: Option<String>,
}

impl TaskConfig {
    /// Get the effective inputs globs (defaults to common source dirs + config files if empty).
    pub fn effective_inputs(&self) -> Vec<String> {
        if self.inputs.is_empty() {
            vec![
                "src/**".into(),
                "lib/**".into(),
                "app/**".into(),
                "pages/**".into(),
                "components/**".into(),
                "scripts/**".into(),
                "bin/**".into(),
                "*.js".into(),
                "*.cjs".into(),
                "*.mjs".into(),
                "*.ts".into(),
                "*.tsx".into(),
                "*.jsx".into(),
                "package.json".into(),
                "lpm.json".into(),
                "tsconfig.json".into(),
                "tsconfig.*.json".into(),
                "*.config.js".into(),
                "*.config.ts".into(),
                "*.config.mjs".into(),
            ]
        } else {
            self.inputs.clone()
        }
    }

    /// Whether this task has upstream dependencies (`^` prefix).
    pub fn has_upstream_deps(&self) -> bool {
        self.depends_on.iter().any(|d| d.starts_with('^'))
    }

    /// Get upstream task names (strips `^` prefix).
    ///
    /// Filters out malformed entries: bare `"^"` (empty after strip) and
    /// double-prefixed `"^^build"` (still starts with `^` after strip).
    pub fn upstream_tasks(&self) -> Vec<&str> {
        self.depends_on
            .iter()
            .filter_map(|d| d.strip_prefix('^'))
            .filter(|d| !d.is_empty() && !d.starts_with('^'))
            .collect()
    }

    /// Get same-package task dependencies (no `^` prefix).
    pub fn local_deps(&self) -> Vec<&str> {
        self.depends_on
            .iter()
            .filter(|d| !d.starts_with('^'))
            .map(|d| d.as_str())
            .collect()
    }
}

/// Generate the JSON Schema (Draft 2020-12) for `lpm.json`.
///
/// Auto-derived from the [`LpmJsonConfig`] struct + its nested types
/// via `schemars`. Sets a stable `$id` so editors can recognize the
/// schema by URL even without a `$schema` field on the document.
///
/// Consumed by:
/// - The `lpm schema lpm.json` CLI subcommand for stdout / file
///   emission.
/// - The drift-guard test that diffs the generated bytes against
///   checked-in public copies.
pub fn generate_schema() -> serde_json::Value {
    let mut schema = derived_schema();
    let obj = schema.as_object_mut().expect("schema root is an object");
    obj.insert(
        "$id".to_string(),
        serde_json::Value::String(LPM_JSON_SCHEMA_URL.to_string()),
    );
    obj.insert(
        "title".to_string(),
        serde_json::Value::String("lpm.json".to_string()),
    );
    obj.insert(
        "description".to_string(),
        serde_json::Value::String(
            "Project-level LPM configuration. Sits alongside package.json and \
             provides runtime pinning, env file mapping, task runner config, \
             hosted task cache settings, dev services, local-domain proxy \
             settings, env vault metadata, publish targets, and tunnel/HTTPS settings."
                .to_string(),
        ),
    );
    serde_json::to_value(&schema).expect("schema serializes to JSON")
}

/// Return unknown object fields using the same generated contract served to editors.
/// Parsing remains forward-compatible; callers such as Doctor can surface these as warnings.
pub fn unknown_field_paths(document: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_unknown_field_paths(
        document,
        &UNKNOWN_FIELD_SCHEMA,
        &UNKNOWN_FIELD_SCHEMA,
        "",
        &mut paths,
    );
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn collect_unknown_field_paths(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    root_schema: &serde_json::Value,
    path: &str,
    paths: &mut Vec<String>,
) {
    let schema = resolve_schema(schema, root_schema);
    let schema = select_shape_schema(value, schema, root_schema);

    if let Some(object) = value.as_object() {
        let properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object);
        let additional = schema.get("additionalProperties");
        for (key, nested_value) in object {
            let nested_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            if let Some(nested_schema) = properties.and_then(|known| known.get(key)) {
                collect_unknown_field_paths(
                    nested_value,
                    nested_schema,
                    root_schema,
                    &nested_path,
                    paths,
                );
            } else if additional == Some(&serde_json::Value::Bool(false)) {
                paths.push(nested_path);
            } else if let Some(nested_schema) = additional.filter(|value| value.is_object()) {
                collect_unknown_field_paths(
                    nested_value,
                    nested_schema,
                    root_schema,
                    &nested_path,
                    paths,
                );
            }
        }
    } else if let Some(array) = value.as_array()
        && let Some(item_schema) = schema.get("items")
    {
        for (index, nested_value) in array.iter().enumerate() {
            let nested_path = format!("{path}[{index}]");
            collect_unknown_field_paths(
                nested_value,
                item_schema,
                root_schema,
                &nested_path,
                paths,
            );
        }
    }
}

fn resolve_schema<'a>(
    schema: &'a serde_json::Value,
    root_schema: &'a serde_json::Value,
) -> &'a serde_json::Value {
    let Some(reference) = schema.get("$ref").and_then(serde_json::Value::as_str) else {
        return schema;
    };
    let Some(pointer) = reference.strip_prefix('#') else {
        return schema;
    };
    root_schema.pointer(pointer).unwrap_or(schema)
}

fn select_shape_schema<'a>(
    value: &serde_json::Value,
    schema: &'a serde_json::Value,
    root_schema: &'a serde_json::Value,
) -> &'a serde_json::Value {
    for variants_key in ["anyOf", "oneOf"] {
        if let Some(variants) = schema
            .get(variants_key)
            .and_then(serde_json::Value::as_array)
            && let Some(selected) = variants.iter().find(|candidate| {
                schema_accepts_value_shape(value, resolve_schema(candidate, root_schema))
            })
        {
            return resolve_schema(selected, root_schema);
        }
    }
    schema
}

fn schema_accepts_value_shape(value: &serde_json::Value, schema: &serde_json::Value) -> bool {
    let accepts = |kind: &str| match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    };
    match schema.get("type") {
        Some(serde_json::Value::String(kind)) => accepts(kind),
        Some(serde_json::Value::Array(kinds)) => kinds
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(accepts),
        _ => schema.get("properties").is_some() && value.is_object(),
    }
}

fn derived_schema() -> schemars::Schema {
    schemars::schema_for!(LpmJsonConfig)
}

static UNKNOWN_FIELD_SCHEMA: LazyLock<serde_json::Value> =
    LazyLock::new(|| serde_json::to_value(derived_schema()).expect("schema serializes to JSON"));

/// Read `lpm.json` from a project directory.
///
/// Returns `None` if the file doesn't exist (not an error).
/// Returns `Err` if the file exists but is malformed.
pub fn read_lpm_json(project_dir: &Path) -> Result<Option<LpmJsonConfig>, String> {
    let path = project_dir.join("lpm.json");
    let content = match read_text_file_capped(&path, CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => content,
        Err(BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(format!("failed to read lpm.json: {error}")),
    };

    parse_lpm_json(&content).map(Some)
}

/// Parse and validate an `lpm.json` document that was read by the caller.
pub fn parse_lpm_json(content: &str) -> Result<LpmJsonConfig, String> {
    let mut config: LpmJsonConfig =
        serde_json::from_str(content).map_err(|error| match error.classify() {
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                format!("failed to parse lpm.json: {error}")
            }
            serde_json::error::Category::Data => {
                format!("invalid lpm.json data: {error}")
            }
            serde_json::error::Category::Io => {
                format!("failed to read lpm.json: {error}")
            }
        })?;

    validate_task_cache_globs(&config)?;

    if let Some(vault_id) = config.vault.as_deref()
        && !lpm_vault::vault_id::is_safe_vault_id(vault_id)
    {
        return Err(format!(
            "invalid lpm.json data: vault id {vault_id:?} contains path-traversal or non-portable characters"
        ));
    }

    validated_cert_extra_permitted_dns(&config)?;

    validate_and_normalize_local_domain_hosts(&mut config)?;

    Ok(config)
}

fn validate_task_cache_globs(config: &LpmJsonConfig) -> Result<(), String> {
    let mut task_names: Vec<_> = config.tasks.keys().collect();
    task_names.sort_unstable();
    for task_name in task_names {
        let task = &config.tasks[task_name];
        for (field, patterns) in [("inputs", &task.inputs), ("outputs", &task.outputs)] {
            for pattern in patterns {
                lpm_common::validate_project_glob(pattern).map_err(|reason| {
                    format!(
                        "invalid lpm.json data: tasks.{task_name}.{field} contains invalid glob {pattern:?}: {reason}"
                    )
                })?;
            }
        }
    }
    Ok(())
}

pub fn validated_cert_extra_permitted_dns(
    config: &LpmJsonConfig,
) -> Result<Vec<lpm_cert::name_constraints::AcceptedDnsEntry>, String> {
    let Some(cert) = config.cert.as_ref() else {
        return Ok(Vec::new());
    };
    if cert.extra_permitted_dns.is_empty() {
        return Ok(Vec::new());
    }
    lpm_cert::name_constraints::validate_extra_permitted_dns(
        &cert.extra_permitted_dns,
        cert.allow_public_dns,
    )
    .map_err(|e| format!("lpm.json `cert.extraPermittedDns` rejected: {e}"))
}

fn validate_and_normalize_local_domain_hosts(config: &mut LpmJsonConfig) -> Result<(), String> {
    let allow_public_dns = config
        .cert
        .as_ref()
        .is_some_and(|cert| cert.allow_public_dns);
    let mut seen: HashMap<String, String> = HashMap::new();

    let mut service_names: Vec<String> = config.services.keys().cloned().collect();
    service_names.sort();
    for service_name in service_names {
        let Some(raw_host) = config
            .services
            .get(&service_name)
            .and_then(|service| service.host.as_deref())
        else {
            continue;
        };
        let field = format!("services.{service_name}.host");
        let normalized = validate_local_domain_host_field(&field, raw_host, allow_public_dns)?;
        let service = config
            .services
            .get_mut(&service_name)
            .expect("service key collected from same map");
        service.host = Some(normalized.clone());
        insert_unique_local_domain_host(&mut seen, &normalized, &field)?;
    }

    if let Some(proxy) = config.proxy.as_mut()
        && let Some(raw_host) = proxy.host.as_deref()
    {
        let field = "proxy.host";
        let normalized = validate_local_domain_host_field(field, raw_host, allow_public_dns)?;
        proxy.host = Some(normalized.clone());
        insert_unique_local_domain_host(&mut seen, &normalized, field)?;
    }

    Ok(())
}

fn validate_local_domain_host_field(
    field: &str,
    host: &str,
    allow_public_dns: bool,
) -> Result<String, String> {
    let entries = [host.to_string()];
    let accepted =
        lpm_cert::name_constraints::validate_extra_permitted_dns(&entries, allow_public_dns)
            .map_err(|e| {
                e.to_string()
                    .replace("cert.extra_permitted_dns", field)
                    .replace("cert.extraPermittedDns", field)
            })?;
    let accepted = accepted
        .into_iter()
        .next()
        .ok_or_else(|| format!("{field} entry is empty"))?;
    Ok(accepted.host)
}

fn insert_unique_local_domain_host(
    seen: &mut HashMap<String, String>,
    host: &str,
    field: &str,
) -> Result<(), String> {
    if let Some(existing) = seen.insert(host.to_string(), field.to_string()) {
        return Err(format!(
            "lpm.json local domain host {host:?} is declared by both `{existing}` and `{field}`"
        ));
    }
    Ok(())
}

/// Resolve the `.env` file path for a given script name.
///
/// Checks `lpm.json` `env` mapping first. Returns the mapped file name
/// (e.g., `"dev"` → `".env.development"`) or `None` if no mapping exists.
pub fn resolve_env_mode(config: &LpmJsonConfig, script_name: &str) -> Option<String> {
    config.env.get(script_name).cloned()
}

/// Extract the env mode from a `.env.{mode}` filename.
///
/// e.g., `.env.development` → `Some("development")`
/// e.g., `.env` → `None`
///
/// Re-exported from `lpm_env::resolver` — canonical definition lives there.
pub fn extract_mode_from_env_path(env_path: &str) -> Option<&str> {
    lpm_env::extract_mode_from_env_path(env_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn generated_schema_contains_documented_env_metadata_fields() {
        let schema = generate_schema();
        let properties = schema["properties"]
            .as_object()
            .expect("lpm.json schema must have root properties");

        assert!(properties["$schema"]["type"].is_array());
        assert_eq!(properties["$schema"]["format"], "uri");
        assert!(properties["vault"]["type"].is_array());
        assert!(properties["vaultSync"]["anyOf"].is_array());

        let env_rule = &schema["$defs"]["EnvVarRule"]["properties"];
        for field in [
            "required",
            "format",
            "pattern",
            "enum",
            "default",
            "secret",
            "client",
            "description",
        ] {
            assert!(
                env_rule.get(field).is_some(),
                "generated envSchema rule is missing `{field}`"
            );
        }
        assert_eq!(
            schema["$defs"]["EnvSchema"]["properties"]["vars"]["propertyNames"]["pattern"],
            "^[A-Za-z_][A-Za-z0-9_]{0,255}$"
        );
    }

    #[test]
    fn generated_schema_publish_default_matches_effective_default() {
        let schema = generate_schema();

        assert_eq!(
            schema["$defs"]["PublishConfig"]["properties"]["registries"]["default"],
            serde_json::json!(["lpm"])
        );
        assert_eq!(PublishConfig::default().registries, vec!["lpm"]);
    }

    #[test]
    fn unknown_field_paths_reports_nested_typos_consistently_across_calls() {
        let document = serde_json::json!({"proxy": {"httpRediect": true}});

        assert_eq!(
            unknown_field_paths(&document),
            vec!["proxy.httpRediect".to_string()]
        );
        assert_eq!(
            unknown_field_paths(&document),
            vec!["proxy.httpRediect".to_string()]
        );
    }

    #[test]
    fn read_missing_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_lpm_json(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn read_minimal_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), "{}").unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert!(config.runtime.is_empty());
        assert!(config.env.is_empty());
    }

    #[test]
    fn read_lpm_json_rejects_unsafe_vault_id() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"vault":"../escape"}"#).unwrap();

        let error = read_lpm_json(dir.path()).expect_err("unsafe vault id must be rejected");

        assert!(error.contains("vault id"), "{error}");
        assert!(error.contains("path-traversal"), "{error}");
    }

    #[test]
    fn read_lpm_json_accepts_valid_cert_extra_permitted_dns() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{ "cert": { "extraPermittedDns": ["myapp.local", "api.test"] } }"#,
        )
        .unwrap();
        let cfg = read_lpm_json(dir.path()).unwrap().unwrap();
        let entries = cfg
            .cert
            .as_ref()
            .expect("cert block parsed")
            .extra_permitted_dns
            .clone();
        assert_eq!(
            entries,
            vec!["myapp.local".to_string(), "api.test".to_string()]
        );
        let accepted = validated_cert_extra_permitted_dns(&cfg).unwrap();
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].exact_subtree, "myapp.local");
        assert_eq!(accepted[0].suffix_subtree, ".myapp.local");
    }

    #[test]
    fn read_lpm_json_rejects_wildcard_cert_entry() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{ "cert": { "extraPermittedDns": ["*.myapp.local"] } }"#,
        )
        .unwrap();
        let err = read_lpm_json(dir.path()).unwrap_err();
        assert!(
            err.contains("'*'"),
            "expected wildcard rejection, got {err}"
        );
        assert!(
            err.contains("cert.extraPermittedDns"),
            "error should name the offending config key, got {err}"
        );
    }

    #[test]
    fn read_lpm_json_rejects_public_tld_without_allow_flag() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{ "cert": { "extraPermittedDns": ["staging.example.com"] } }"#,
        )
        .unwrap();
        let err = read_lpm_json(dir.path()).unwrap_err();
        assert!(err.contains("non-local TLD"), "got {err}");
    }

    #[test]
    fn read_lpm_json_permits_public_tld_with_allow_flag() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{ "cert": { "extraPermittedDns": ["staging.example.com"], "allowPublicDns": true } }"#,
        )
        .unwrap();
        let cfg = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.cert.unwrap().extra_permitted_dns,
            vec!["staging.example.com".to_string()]
        );
    }

    #[test]
    fn read_full_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
				"runtime": { "node": ">=22.0.0" },
				"env": {
					"dev": ".env.development",
					"staging": ".env.staging",
					"prod": ".env.production"
				}
			}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.runtime.get("node").unwrap(), ">=22.0.0");
        assert_eq!(config.env.get("dev").unwrap(), ".env.development");
        assert_eq!(config.env.len(), 3);
    }

    #[test]
    fn resolve_env_mode_found() {
        let config = LpmJsonConfig {
            env: [("dev".into(), ".env.development".into())].into(),
            ..Default::default()
        };
        assert_eq!(
            resolve_env_mode(&config, "dev"),
            Some(".env.development".into())
        );
    }

    #[test]
    fn resolve_env_mode_not_found() {
        let config = LpmJsonConfig::default();
        assert_eq!(resolve_env_mode(&config, "dev"), None);
    }

    #[test]
    fn extract_mode_from_path() {
        assert_eq!(
            extract_mode_from_env_path(".env.development"),
            Some("development")
        );
        assert_eq!(extract_mode_from_env_path(".env.staging"), Some("staging"));
        assert_eq!(extract_mode_from_env_path(".env"), None);
    }

    #[test]
    fn read_lpm_json_with_tasks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
				"tasks": {
					"build": {
						"dependsOn": ["^build"],
						"cache": true,
						"outputs": ["dist/**"],
						"inputs": ["src/**", "package.json"]
					},
					"dev": {
						"command": "vite dev",
						"env": "development"
					},
					"test": {
						"cache": true
					}
				}
			}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.tasks.len(), 3);

        let build = &config.tasks["build"];
        assert!(build.cache);
        assert_eq!(build.outputs, vec!["dist/**"]);
        assert_eq!(build.depends_on, vec!["^build"]);
        assert!(build.has_upstream_deps());
        assert_eq!(build.upstream_tasks(), vec!["build"]);

        let dev = &config.tasks["dev"];
        assert_eq!(dev.command.as_deref(), Some("vite dev"));
        assert_eq!(dev.env.as_deref(), Some("development"));
        assert!(!dev.cache);
    }

    #[test]
    fn read_lpm_json_with_remote_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "remoteCache": {
                    "enabled": true,
                    "team": "acme",
                    "url": "http://localhost:3000/v8",
                    "signature": true,
                    "readOnly": true,
                    "env": {
                        "include": ["CI"],
                        "exclude": ["*_TOKEN"],
                        "allowSecrets": true
                    }
                }
            }"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let remote = config.remote_cache.expect("remote cache parsed");
        assert!(remote.enabled);
        assert_eq!(remote.team.as_deref(), Some("acme"));
        assert_eq!(remote.url.as_deref(), Some("http://localhost:3000/v8"));
        assert!(remote.signature);
        assert!(remote.read_only);
        assert_eq!(remote.env.include, vec!["CI"]);
        assert_eq!(remote.env.exclude, vec!["*_TOKEN"]);
        assert!(remote.env.allow_secrets);
    }

    #[test]
    fn task_config_effective_inputs_default() {
        let t = TaskConfig::default();
        let inputs = t.effective_inputs();
        assert!(inputs.contains(&"src/**".to_string()));
        assert!(inputs.contains(&"package.json".to_string()));
        assert!(inputs.contains(&"*.js".to_string()));
        assert!(inputs.contains(&"lpm.json".to_string()));
    }

    #[test]
    fn task_config_effective_inputs_custom() {
        let t = TaskConfig {
            inputs: vec!["custom/**".into()],
            ..Default::default()
        };
        let inputs = t.effective_inputs();
        assert_eq!(inputs, vec!["custom/**"]);
    }

    #[test]
    fn read_lpm_json_with_services() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
				"services": {
					"web": {
						"command": "next dev",
						"port": 3000
					},
					"api": {
						"command": "node server.js",
						"port": 4000,
						"dependsOn": ["db"],
						"env": { "DATABASE_URL": "postgres://localhost:5432/myapp" }
					},
					"db": {
						"command": "docker compose up postgres",
						"readyPort": 5432,
						"readyTimeout": 60
					}
				}
			}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.services.len(), 3);

        let web = &config.services["web"];
        assert_eq!(web.command, "next dev");
        assert_eq!(web.port, Some(3000));
        assert!(web.depends_on.is_empty());

        let api = &config.services["api"];
        assert_eq!(api.command, "node server.js");
        assert_eq!(api.depends_on, vec!["db"]);
        assert_eq!(
            api.env.get("DATABASE_URL").unwrap(),
            "postgres://localhost:5432/myapp"
        );

        let db = &config.services["db"];
        assert_eq!(db.ready_port, Some(5432));
        assert_eq!(db.ready_timeout, 60);
        assert_eq!(db.effective_ready_port(), Some(5432));
    }

    #[test]
    fn read_lpm_json_rejects_duplicate_service_keys() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "web": { "command": "node first.js" },
                    "web": { "command": "node second.js" }
                }
            }"#,
        )
        .unwrap();

        let error = read_lpm_json(dir.path()).unwrap_err();

        assert!(
            error.contains("duplicate service `web`"),
            "duplicate service error was not actionable: {error}"
        );
    }

    #[test]
    fn read_lpm_json_accepts_and_normalizes_local_domain_hosts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "web": {
                        "command": "next dev",
                        "port": 3000,
                        "host": "Web.App.Localhost"
                    }
                },
                "proxy": {
                    "host": "App.Localhost",
                    "port": 443,
                    "httpRedirect": false
                }
            }"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(
            config.services["web"].host.as_deref(),
            Some("web.app.localhost")
        );
        let proxy = config.proxy.unwrap();
        assert_eq!(proxy.host.as_deref(), Some("app.localhost"));
        assert_eq!(proxy.port, Some(443));
        assert_eq!(proxy.http_redirect, Some(false));
    }

    #[test]
    fn read_lpm_json_rejects_duplicate_service_hosts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "api": { "command": "node api.js", "port": 4000, "host": "app.localhost" },
                    "web": { "command": "next dev", "port": 3000, "host": "APP.localhost" }
                }
            }"#,
        )
        .unwrap();

        let err = read_lpm_json(dir.path()).unwrap_err();
        assert!(err.contains("app.localhost"), "got {err}");
        assert!(err.contains("services.api.host"), "got {err}");
        assert!(err.contains("services.web.host"), "got {err}");
    }

    #[test]
    fn read_lpm_json_rejects_duplicate_service_and_proxy_host() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "web": { "command": "next dev", "port": 3000, "host": "app.localhost" }
                },
                "proxy": { "host": "app.localhost" }
            }"#,
        )
        .unwrap();

        let err = read_lpm_json(dir.path()).unwrap_err();
        assert!(err.contains("services.web.host"), "got {err}");
        assert!(err.contains("proxy.host"), "got {err}");
    }

    #[test]
    fn read_lpm_json_accepts_service_host_without_port_for_auto_assignment() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "web": { "command": "next dev", "host": "web.app.localhost" }
                }
            }"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let web = &config.services["web"];
        assert_eq!(web.host.as_deref(), Some("web.app.localhost"));
        assert_eq!(web.port, None);
    }

    #[test]
    fn read_lpm_json_rejects_public_local_domain_host_without_allow_flag() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "services": {
                    "web": { "command": "next dev", "port": 3000, "host": "staging.example.com" }
                }
            }"#,
        )
        .unwrap();

        let err = read_lpm_json(dir.path()).unwrap_err();
        assert!(err.contains("non-local TLD"), "got {err}");
        assert!(err.contains("services.web.host"), "got {err}");
    }

    #[test]
    fn read_lpm_json_permits_public_local_domain_host_with_allow_flag() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "cert": { "allowPublicDns": true },
                "services": {
                    "web": { "command": "next dev", "port": 3000, "host": "staging.example.com" }
                }
            }"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(
            config.services["web"].host.as_deref(),
            Some("staging.example.com")
        );
    }

    #[test]
    fn service_config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"services": {"web": {"command": "npm run dev"}}}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let web = &config.services["web"];
        assert_eq!(web.port, None);
        assert!(web.depends_on.is_empty());
        assert!(!web.restart);
        assert!(!web.primary);
        assert_eq!(web.ready_timeout, 30);
        assert_eq!(web.effective_ready_port(), None);
    }

    #[test]
    fn read_lpm_json_with_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"tunnel": {"domain": "acme-api.lpm.llc"}}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let tunnel = config.tunnel.unwrap();
        assert_eq!(tunnel.domain.as_deref(), Some("acme-api.lpm.llc"));
    }

    #[test]
    fn read_lpm_json_no_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"runtime":{"node":"22"}}"#).unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert!(config.tunnel.is_none());
    }

    #[test]
    fn read_lpm_json_invalid_json_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), "{ invalid json !!!").unwrap();

        let result = read_lpm_json(dir.path());
        assert!(
            result.is_err(),
            "malformed lpm.json should return Err, not be silently swallowed"
        );
    }

    #[test]
    fn task_config_dep_parsing() {
        let t = TaskConfig {
            depends_on: vec!["^build".into(), "lint".into(), "^test".into()],
            ..Default::default()
        };
        assert!(t.has_upstream_deps());
        assert_eq!(t.upstream_tasks(), vec!["build", "test"]);
        assert_eq!(t.local_deps(), vec!["lint"]);
    }

    // bare "^" and double-prefix "^^build" edge cases
    #[test]
    fn upstream_tasks_filters_bare_caret_and_double_prefix() {
        let t = TaskConfig {
            depends_on: vec![
                "^build".into(),
                "^".into(),      // bare caret → should be filtered out
                "^^test".into(), // double prefix → should be filtered out
                "lint".into(),   // local dep → not in upstream
            ],
            ..Default::default()
        };
        assert_eq!(t.upstream_tasks(), vec!["build"]);
    }

    #[test]
    fn read_lpm_json_with_publish_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{
				"publish": {
					"registries": ["lpm", "npm"],
					"npm": {
						"name": "@tolga/highlight",
						"access": "public",
						"tag": "latest",
						"registry": "https://registry.npmjs.org",
						"otpRequired": true
					}
				}
			}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let publish = config.publish.unwrap();
        assert_eq!(publish.registries, vec!["lpm", "npm"]);

        let npm = publish.npm.unwrap();
        assert_eq!(npm.name.as_deref(), Some("@tolga/highlight"));
        assert_eq!(npm.access.as_deref(), Some("public"));
        assert_eq!(npm.tag.as_deref(), Some("latest"));
        assert_eq!(npm.registry.as_deref(), Some("https://registry.npmjs.org"));
        assert_eq!(npm.otp_required, Some(true));
    }

    #[test]
    fn read_lpm_json_publish_config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"publish": {"registries": ["npm"]}}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let publish = config.publish.unwrap();
        assert_eq!(publish.registries, vec!["npm"]);
        assert!(publish.npm.is_none());
    }

    #[test]
    fn cli_flags_override_lpm_json_config() {
        // Simulates the merge logic: CLI flags take precedence over lpm.json
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"publish": {"registries": ["lpm"]}}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        let config_registries = config.publish.as_ref().map(|p| &p.registries);

        // CLI --npm flag overrides config
        let cli_npm = true;
        let cli_lpm = false;

        let targets: Vec<&str> = if cli_npm || cli_lpm {
            // CLI flags present — use them, ignore config
            let mut t = Vec::new();
            if cli_lpm {
                t.push("lpm");
            }
            if cli_npm {
                t.push("npm");
            }
            t
        } else if let Some(regs) = config_registries {
            regs.iter().map(|s| s.as_str()).collect()
        } else {
            vec!["lpm"]
        };

        assert_eq!(targets, vec!["npm"], "CLI --npm should override config");
    }

    #[test]
    fn default_to_lpm_when_no_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{}"#).unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert!(config.publish.is_none());
    }

    #[test]
    fn local_deps_filters_bare_caret_and_double_prefix() {
        let t = TaskConfig {
            depends_on: vec![
                "^build".into(),
                "^".into(),      // bare caret → should be filtered out
                "^^test".into(), // double prefix → should be filtered out
                "lint".into(),
            ],
            ..Default::default()
        };
        // "^" and "^^test" start with '^' so they are NOT local deps,
        // but they should not appear as valid upstream either.
        // local_deps should only return "lint"
        assert_eq!(t.local_deps(), vec!["lint"]);
    }

    // effective_inputs() should include config files
    #[test]
    fn effective_inputs_includes_config_files() {
        let t = TaskConfig::default();
        let inputs = t.effective_inputs();
        assert!(
            inputs.contains(&"tsconfig.json".to_string()),
            "missing tsconfig.json"
        );
        assert!(
            inputs.contains(&"tsconfig.*.json".to_string()),
            "missing tsconfig.*.json"
        );
        assert!(
            inputs.contains(&"*.config.js".to_string()),
            "missing *.config.js"
        );
        assert!(
            inputs.contains(&"*.config.ts".to_string()),
            "missing *.config.ts"
        );
        assert!(
            inputs.contains(&"*.config.mjs".to_string()),
            "missing *.config.mjs"
        );
    }

    // ── HTTPS auto-detection from lpm.json ──

    #[test]
    fn read_lpm_json_with_https_true() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"https": true}"#).unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.https, Some(true));
    }

    #[test]
    fn read_lpm_json_with_https_false() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), r#"{"https": false}"#).unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.https, Some(false));
    }

    #[test]
    fn read_lpm_json_without_https_defaults_none() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.json"), "{}").unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.https, None);
    }

    #[test]
    fn read_lpm_json_with_https_and_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"https": true, "tunnel": {"domain": "acme.lpm.llc"}}"#,
        )
        .unwrap();

        let config = read_lpm_json(dir.path()).unwrap().unwrap();
        assert_eq!(config.https, Some(true));
        assert_eq!(
            config.tunnel.as_ref().and_then(|t| t.domain.as_deref()),
            Some("acme.lpm.llc")
        );
    }
}
