use super::InstallPackage;
use crate::commands::config::GlobalConfig;
use crate::output;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const POLICY_CONFIG_SECTION: &str = "policy";
const POLICY_EXTENSIONS_KEY: &str = "extensions";
pub(crate) const POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE: &str = "package.candidate";
pub(crate) const POLICY_EXTENSION_SCHEMA_VERSION: u64 = 1;
const DEFAULT_POLICY_EXTENSION_TIMEOUT_MS: u64 = 5_000;
const MAX_POLICY_EXTENSION_TIMEOUT_MS: u64 = 120_000;
const MAX_POLICY_EXTENSION_ARGS: usize = 64;
const MAX_POLICY_EXTENSION_STDOUT_BYTES: usize = 64 * 1024;
const MAX_POLICY_EXTENSION_STDERR_BYTES: usize = 16 * 1024;
const MAX_POLICY_EXTENSION_CODE_CHARS: usize = 128;
const MAX_POLICY_EXTENSION_REASON_CHARS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyExtensionMode {
    Report,
    Enforce,
}

impl PolicyExtensionMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "report" | "warn" => Some(Self::Report),
            "enforce" | "deny" | "block" => Some(Self::Enforce),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Enforce => "enforce",
        }
    }

    fn default_on_error(self) -> PolicyExtensionOnError {
        match self {
            Self::Report => PolicyExtensionOnError::Warn,
            Self::Enforce => PolicyExtensionOnError::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyExtensionOnError {
    Warn,
    Block,
}

impl PolicyExtensionOnError {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "warn" | "report" => Some(Self::Warn),
            "block" | "deny" | "enforce" => Some(Self::Block),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyExtensionAction {
    Allow,
    Warn,
    Block,
}

impl PolicyExtensionAction {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "warn" => Some(Self::Warn),
            "block" | "deny" => Some(Self::Block),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyExtensionConfig {
    name: String,
    command: Vec<String>,
    mode: PolicyExtensionMode,
    on_error: PolicyExtensionOnError,
    timeout: Duration,
}

impl PolicyExtensionConfig {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn command(&self) -> &[String] {
        &self.command
    }

    pub(crate) fn mode(&self) -> PolicyExtensionMode {
        self.mode
    }

    pub(crate) fn on_error(&self) -> PolicyExtensionOnError {
        self.on_error
    }

    pub(crate) fn timeout_ms(&self) -> u128 {
        self.timeout.as_millis()
    }

    pub(crate) fn to_config_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": &self.name,
            "command": &self.command,
            "mode": self.mode.as_str(),
            "on_error": self.on_error.as_str(),
            "timeout_ms": self.timeout.as_millis(),
            "events": [POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE],
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct PolicyExtensionStats {
    enabled: bool,
    configured_count: usize,
    ran_count: u64,
    candidate_count: u64,
    duration_ms: u128,
    allow_count: u64,
    warn_count: u64,
    block_count: u64,
    error_count: u64,
    extensions: Vec<PolicyExtensionRunStats>,
}

impl PolicyExtensionStats {
    fn for_configs(configs: &[PolicyExtensionConfig]) -> Self {
        Self {
            enabled: !configs.is_empty(),
            configured_count: configs.len(),
            ..Self::default()
        }
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "configured_count": self.configured_count,
            "ran_count": self.ran_count,
            "candidate_count": self.candidate_count,
            "duration_ms": self.duration_ms,
            "allow_count": self.allow_count,
            "warn_count": self.warn_count,
            "block_count": self.block_count,
            "error_count": self.error_count,
            "extensions": self.extensions.iter().map(PolicyExtensionRunStats::to_json).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PolicyExtensionRunStats {
    name: String,
    mode: PolicyExtensionMode,
    on_error: PolicyExtensionOnError,
    duration_ms: u128,
    allow_count: u64,
    warn_count: u64,
    block_count: u64,
    error: Option<String>,
}

impl PolicyExtensionRunStats {
    fn from_result(
        config: &PolicyExtensionConfig,
        duration_ms: u128,
        decisions: &[PolicyExtensionDecision],
    ) -> Self {
        let mut stats = Self {
            name: config.name.clone(),
            mode: config.mode,
            on_error: config.on_error,
            duration_ms,
            allow_count: 0,
            warn_count: 0,
            block_count: 0,
            error: None,
        };
        for decision in decisions {
            match decision.action {
                PolicyExtensionAction::Allow => {
                    stats.allow_count = stats.allow_count.saturating_add(1)
                }
                PolicyExtensionAction::Warn => {
                    stats.warn_count = stats.warn_count.saturating_add(1)
                }
                PolicyExtensionAction::Block => {
                    stats.block_count = stats.block_count.saturating_add(1)
                }
            }
        }
        stats
    }

    fn from_error(config: &PolicyExtensionConfig, duration_ms: u128, error: String) -> Self {
        Self {
            name: config.name.clone(),
            mode: config.mode,
            on_error: config.on_error,
            duration_ms,
            allow_count: 0,
            warn_count: 0,
            block_count: 0,
            error: Some(error),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "name": self.name,
            "mode": self.mode.as_str(),
            "on_error": self.on_error.as_str(),
            "duration_ms": self.duration_ms,
            "allow_count": self.allow_count,
            "warn_count": self.warn_count,
            "block_count": self.block_count,
        });
        if let Some(error) = &self.error {
            json["error"] = serde_json::Value::String(error.clone());
        }
        json
    }
}

#[derive(Debug, Serialize)]
struct PolicyExtensionRequest<'a> {
    schema_version: u64,
    event: &'static str,
    packages: &'a [PolicyExtensionPackage],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PolicyExtensionPackage {
    name: String,
    version: String,
    source: String,
    source_kind: &'static str,
    integrity: Option<String>,
    registry_published_at: Option<String>,
    is_direct: bool,
    is_lpm: bool,
    optional: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyExtensionResponse {
    schema_version: u64,
    decisions: Vec<PolicyExtensionRawDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyExtensionRawDecision {
    name: String,
    version: String,
    action: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyExtensionDecision {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) action: PolicyExtensionAction,
    pub(crate) code: Option<String>,
    pub(crate) reason: Option<String>,
}

impl PolicyExtensionDecision {
    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "name": &self.name,
            "version": &self.version,
            "action": self.action.as_str(),
        });
        if let Some(code) = &self.code {
            json["code"] = serde_json::Value::String(code.clone());
        }
        if let Some(reason) = &self.reason {
            json["reason"] = serde_json::Value::String(reason.clone());
        }
        json
    }
}

struct PolicyExtensionRun {
    duration_ms: u128,
    decisions: Vec<PolicyExtensionDecision>,
}

pub(crate) struct PolicyExtensionTestOutcome {
    pub(crate) duration_ms: u128,
    pub(crate) decisions: Vec<PolicyExtensionDecision>,
}

struct LimitedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

pub(crate) fn load_policy_extension_configs(
    global: &GlobalConfig,
) -> Result<Vec<PolicyExtensionConfig>, LpmError> {
    let Some(policy_value) = global.get_value(POLICY_CONFIG_SECTION) else {
        return Ok(Vec::new());
    };
    let policy = policy_value.as_table().ok_or_else(|| {
        LpmError::Registry(format!("`[{POLICY_CONFIG_SECTION}]` must be a TOML table"))
    })?;
    let Some(extensions_value) = policy.get(POLICY_EXTENSIONS_KEY) else {
        return Ok(Vec::new());
    };
    let extensions = extensions_value.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[{POLICY_CONFIG_SECTION}.{POLICY_EXTENSIONS_KEY}]` must be a TOML table"
        ))
    })?;
    let mut configs = Vec::with_capacity(extensions.len());
    for (name, value) in extensions {
        let Some(config) = parse_policy_extension_config(name, value)? else {
            continue;
        };
        configs.push(config);
    }
    configs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(configs)
}

pub(super) fn policy_extensions_disable_tarball_prefetch(
    configs: &[PolicyExtensionConfig],
) -> bool {
    !configs.is_empty()
}

pub(super) fn reject_remote_tarball_url_deps_with_policy_extensions(
    configs: &[PolicyExtensionConfig],
    deps: &HashMap<String, String>,
) -> Result<(), LpmError> {
    if configs.is_empty() {
        return Ok(());
    }

    let mut remote_tarball_deps = BTreeMap::new();
    for (name, raw) in deps {
        if let Ok(lpm_resolver::Specifier::Tarball { url, .. }) =
            lpm_resolver::Specifier::parse(raw)
        {
            remote_tarball_deps.insert(name.as_str(), url);
        }
    }

    if let Some((name, url)) = remote_tarball_deps.into_iter().next() {
        return Err(LpmError::Registry(format!(
            "policy extensions do not support remote tarball URL dependency `{name}` ({url}) because package identity requires downloading the tarball before policy evaluation"
        )));
    }

    Ok(())
}

pub(super) async fn run_policy_extensions(
    configs: &[PolicyExtensionConfig],
    project_dir: &Path,
    packages: &[InstallPackage],
    json_output: bool,
) -> Result<PolicyExtensionStats, LpmError> {
    let mut stats = PolicyExtensionStats::for_configs(configs);
    if configs.is_empty() || packages.is_empty() {
        return Ok(stats);
    }

    let policy_packages = policy_extension_packages(packages);
    if policy_packages.is_empty() {
        return Ok(stats);
    }
    validate_policy_extension_candidate_identities(&policy_packages).map_err(LpmError::Registry)?;
    stats.candidate_count = policy_packages.len() as u64;
    let request = serde_json::to_vec(&PolicyExtensionRequest {
        schema_version: POLICY_EXTENSION_SCHEMA_VERSION,
        event: POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE,
        packages: &policy_packages,
    })
    .map_err(|error| {
        LpmError::Registry(format!(
            "failed to encode policy extension request: {error}"
        ))
    })?;
    let known_packages = known_policy_package_set(&policy_packages);
    let started = Instant::now();
    let mut blocking_decisions = 0u64;

    for config in configs {
        stats.ran_count = stats.ran_count.saturating_add(1);
        let extension_started = Instant::now();
        match run_policy_extension(config, project_dir, &request, &known_packages).await {
            Ok(run) => {
                let run_stats =
                    PolicyExtensionRunStats::from_result(config, run.duration_ms, &run.decisions);
                stats.allow_count = stats.allow_count.saturating_add(run_stats.allow_count);
                stats.warn_count = stats.warn_count.saturating_add(run_stats.warn_count);
                stats.block_count = stats.block_count.saturating_add(run_stats.block_count);
                if !json_output {
                    print_policy_extension_decisions(config, &run.decisions);
                }
                if matches!(config.mode, PolicyExtensionMode::Enforce) {
                    blocking_decisions = blocking_decisions.saturating_add(run_stats.block_count);
                }
                stats.extensions.push(run_stats);
            }
            Err(error) => {
                let duration_ms = extension_started.elapsed().as_millis();
                let safe_error = bounded_sanitized(&error, MAX_POLICY_EXTENSION_REASON_CHARS);
                stats.error_count = stats.error_count.saturating_add(1);
                stats.extensions.push(PolicyExtensionRunStats::from_error(
                    config,
                    duration_ms,
                    safe_error.clone(),
                ));
                stats.duration_ms = started.elapsed().as_millis();
                if matches!(config.on_error, PolicyExtensionOnError::Block) {
                    if !json_output {
                        output::warn(&format!(
                            "policy extension `{}` failed closed: {safe_error}",
                            lpm_common::sanitize_for_terminal(&config.name)
                        ));
                    }
                    return Err(LpmError::Registry(format!(
                        "policy extension `{}` failed closed: {safe_error}",
                        config.name
                    )));
                }
                if !json_output {
                    output::warn(&format!(
                        "policy extension `{}` failed: {safe_error}; continuing because on-error = warn",
                        lpm_common::sanitize_for_terminal(&config.name)
                    ));
                }
            }
        }
    }

    stats.duration_ms = started.elapsed().as_millis();
    if blocking_decisions > 0 {
        return Err(LpmError::Registry(format!(
            "{blocking_decisions} package decision(s) blocked by LPM policy extensions"
        )));
    }
    Ok(stats)
}

pub(crate) async fn run_policy_extension_test(
    config: &PolicyExtensionConfig,
    project_dir: &Path,
    name: &str,
    version: &str,
) -> Result<PolicyExtensionTestOutcome, LpmError> {
    let package = PolicyExtensionPackage {
        name: name.to_string(),
        version: version.to_string(),
        source: "registry+https://registry.npmjs.org".to_string(),
        source_kind: "registry",
        integrity: None,
        registry_published_at: None,
        is_direct: true,
        is_lpm: false,
        optional: false,
    };
    let packages = [package];
    let request = serde_json::to_vec(&PolicyExtensionRequest {
        schema_version: POLICY_EXTENSION_SCHEMA_VERSION,
        event: POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE,
        packages: &packages,
    })
    .map_err(|error| {
        LpmError::Registry(format!(
            "failed to encode policy extension test request: {error}"
        ))
    })?;
    let known_packages = known_policy_package_set(&packages);
    let run = run_policy_extension(config, project_dir, &request, &known_packages)
        .await
        .map_err(|error| {
            LpmError::Registry(format!(
                "policy extension `{}` test failed: {error}",
                config.name
            ))
        })?;
    Ok(PolicyExtensionTestOutcome {
        duration_ms: run.duration_ms,
        decisions: run.decisions,
    })
}

fn parse_policy_extension_config(
    name: &str,
    value: &toml::Value,
) -> Result<Option<PolicyExtensionConfig>, LpmError> {
    let table = value.as_table().ok_or_else(|| {
        LpmError::Registry(format!("`[policy.extensions.{name}]` must be a TOML table"))
    })?;
    validate_policy_extension_config_fields(name, table)?;
    if let Some(enabled) = table.get("enabled") {
        let Some(enabled) = enabled.as_bool() else {
            return Err(LpmError::Registry(format!(
                "`[policy.extensions.{name}].enabled` must be a boolean"
            )));
        };
        if !enabled {
            return Ok(None);
        }
    }
    validate_policy_extension_events(name, table.get("events"))?;
    let command = parse_policy_extension_command(name, table.get("command"))?;
    let mode = parse_policy_extension_mode(name, table.get("mode"))?;
    let on_error = parse_policy_extension_on_error(name, table.get("on-error"), mode)?;
    let timeout = parse_policy_extension_timeout(name, table.get("timeout-ms"))?;
    Ok(Some(PolicyExtensionConfig {
        name: name.to_string(),
        command,
        mode,
        on_error,
        timeout,
    }))
}

fn validate_policy_extension_config_fields(
    name: &str,
    table: &toml::map::Map<String, toml::Value>,
) -> Result<(), LpmError> {
    for key in table.keys() {
        match key.as_str() {
            "command" | "enabled" | "events" | "mode" | "on-error" | "timeout-ms" => {}
            _ => {
                return Err(LpmError::Registry(format!(
                    "unsupported field `[policy.extensions.{name}].{key}`; supported fields: command, enabled, events, mode, on-error, timeout-ms"
                )));
            }
        }
    }
    Ok(())
}

fn parse_policy_extension_command(
    name: &str,
    value: Option<&toml::Value>,
) -> Result<Vec<String>, LpmError> {
    let Some(value) = value else {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].command` is required and must be an array of strings"
        )));
    };
    let args = value.as_array().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[policy.extensions.{name}].command` must be an array of strings"
        ))
    })?;
    if args.is_empty() {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].command` must include a program"
        )));
    }
    if args.len() > MAX_POLICY_EXTENSION_ARGS {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].command` may contain at most {MAX_POLICY_EXTENSION_ARGS} entries"
        )));
    }
    let mut command = Vec::with_capacity(args.len());
    for arg in args {
        let raw = arg.as_str().ok_or_else(|| {
            LpmError::Registry(format!(
                "`[policy.extensions.{name}].command` must contain only strings"
            ))
        })?;
        if raw.is_empty() {
            return Err(LpmError::Registry(format!(
                "`[policy.extensions.{name}].command` must not contain empty strings"
            )));
        }
        if command.is_empty() {
            validate_policy_extension_program_name(name, raw)?;
        }
        command.push(raw.to_string());
    }
    Ok(command)
}

fn validate_policy_extension_program_name(name: &str, raw: &str) -> Result<(), LpmError> {
    let program = Path::new(raw);
    if program.is_absolute() || !raw_contains_path_separator(raw) {
        return Ok(());
    }
    Err(LpmError::Registry(format!(
        "`[policy.extensions.{name}].command[0]` must be an absolute path or a program name on PATH; relative executable paths are not allowed"
    )))
}

pub(crate) fn resolve_policy_extension_program(program: &str) -> Result<PathBuf, String> {
    let path = Path::new(program);
    if path.is_absolute() {
        return validate_policy_extension_program_path(path).map(|_| path.to_path_buf());
    }
    if raw_contains_path_separator(program) {
        return Err(
            "relative executable paths are not allowed; use an absolute path or a bare program name"
                .to_string(),
        );
    }

    let path_var = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    let candidates = policy_extension_program_candidates(program);
    for dir in std::env::split_paths(&path_var) {
        if !dir.is_absolute() {
            continue;
        }
        for candidate in &candidates {
            let path = dir.join(candidate);
            if validate_policy_extension_program_path(&path).is_ok() {
                return Ok(path);
            }
        }
    }
    Err(format!(
        "program `{program}` was not found on PATH entries with absolute directories"
    ))
}

fn validate_policy_extension_program_path(path: &Path) -> Result<(), String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!("{} is not executable", path.display()));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn policy_extension_program_candidates(program: &str) -> Vec<String> {
    let program_path = Path::new(program);
    if program_path.extension().is_some() {
        return vec![program.to_string()];
    }
    let mut candidates = Vec::new();
    candidates.push(program.to_string());
    let path_ext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    candidates.extend(
        path_ext
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(|ext| format!("{program}{ext}")),
    );
    candidates
}

#[cfg(not(windows))]
fn policy_extension_program_candidates(program: &str) -> Vec<String> {
    vec![program.to_string()]
}

fn parse_policy_extension_mode(
    name: &str,
    value: Option<&toml::Value>,
) -> Result<PolicyExtensionMode, LpmError> {
    let Some(value) = value else {
        return Ok(PolicyExtensionMode::Report);
    };
    let raw = value.as_str().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[policy.extensions.{name}].mode` must be a string: report | enforce"
        ))
    })?;
    PolicyExtensionMode::parse(raw).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `[policy.extensions.{name}].mode` value `{raw}`; must be one of: report | enforce"
        ))
    })
}

fn parse_policy_extension_on_error(
    name: &str,
    value: Option<&toml::Value>,
    mode: PolicyExtensionMode,
) -> Result<PolicyExtensionOnError, LpmError> {
    let Some(value) = value else {
        return Ok(mode.default_on_error());
    };
    let raw = value.as_str().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[policy.extensions.{name}].on-error` must be a string: warn | block"
        ))
    })?;
    PolicyExtensionOnError::parse(raw).ok_or_else(|| {
        LpmError::Registry(format!(
            "invalid `[policy.extensions.{name}].on-error` value `{raw}`; must be one of: warn | block"
        ))
    })
}

fn parse_policy_extension_timeout(
    name: &str,
    value: Option<&toml::Value>,
) -> Result<Duration, LpmError> {
    let Some(value) = value else {
        return Ok(Duration::from_millis(DEFAULT_POLICY_EXTENSION_TIMEOUT_MS));
    };
    let Some(timeout_ms) = value
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| {
            value
                .as_str()
                .and_then(crate::release_age_config::parse_strict_u64_string)
        })
    else {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].timeout-ms` must be a positive millisecond integer"
        )));
    };
    if timeout_ms == 0 || timeout_ms > MAX_POLICY_EXTENSION_TIMEOUT_MS {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].timeout-ms` must be between 1 and {MAX_POLICY_EXTENSION_TIMEOUT_MS}"
        )));
    }
    Ok(Duration::from_millis(timeout_ms))
}

fn validate_policy_extension_events(
    name: &str,
    value: Option<&toml::Value>,
) -> Result<(), LpmError> {
    let Some(value) = value else {
        return Ok(());
    };
    let events = value.as_array().ok_or_else(|| {
        LpmError::Registry(format!(
            "`[policy.extensions.{name}].events` must be an array of strings"
        ))
    })?;
    if events.is_empty() {
        return Err(LpmError::Registry(format!(
            "`[policy.extensions.{name}].events` must include `{POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE}`"
        )));
    }
    for event in events {
        let raw = event.as_str().ok_or_else(|| {
            LpmError::Registry(format!(
                "`[policy.extensions.{name}].events` must contain only strings"
            ))
        })?;
        if raw != POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE {
            return Err(LpmError::Registry(format!(
                "unsupported `[policy.extensions.{name}].events` value `{raw}`; supported events: {POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE}"
            )));
        }
    }
    Ok(())
}

fn policy_extension_packages(packages: &[InstallPackage]) -> Vec<PolicyExtensionPackage> {
    let mut out = Vec::with_capacity(packages.len());
    for package in packages {
        out.push(PolicyExtensionPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            source: package.source.clone(),
            source_kind: policy_source_kind(package),
            integrity: package.integrity.clone(),
            registry_published_at: package.registry_published_at.clone(),
            is_direct: package.is_direct,
            is_lpm: package.is_lpm,
            optional: package.optional,
        });
    }
    out
}

fn validate_policy_extension_candidate_identities(
    packages: &[PolicyExtensionPackage],
) -> Result<(), String> {
    let mut seen: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for package in packages {
        let key = (package.name.as_str(), package.version.as_str());
        let Some(previous_source) = seen.insert(key, package.source.as_str()) else {
            continue;
        };
        if previous_source != package.source.as_str() {
            return Err(format!(
                "policy extension candidate set is ambiguous for {}@{}: V1 decisions identify candidates by name and version, but the install graph contains both `{}` and `{}` sources",
                package.name, package.version, previous_source, package.source
            ));
        }
    }
    Ok(())
}

fn policy_source_kind(package: &InstallPackage) -> &'static str {
    match package.source_kind() {
        Ok(lpm_lockfile::Source::Registry { .. }) => "registry",
        Ok(lpm_lockfile::Source::Tarball { .. }) => "tarball",
        Ok(lpm_lockfile::Source::Directory { .. }) => "directory",
        Ok(lpm_lockfile::Source::Link { .. }) => "link",
        Ok(lpm_lockfile::Source::Git { .. }) => "git",
        Err(_) => "unknown",
    }
}

fn known_policy_package_set(packages: &[PolicyExtensionPackage]) -> BTreeSet<(String, String)> {
    packages
        .iter()
        .map(|package| (package.name.clone(), package.version.clone()))
        .collect()
}

async fn run_policy_extension(
    config: &PolicyExtensionConfig,
    project_dir: &Path,
    request: &[u8],
    known_packages: &BTreeSet<(String, String)>,
) -> Result<PolicyExtensionRun, String> {
    let started = Instant::now();
    let program = resolve_policy_extension_program(&config.command[0])?;
    let program_display = program.display().to_string();
    let mut command = tokio::process::Command::new(&program);
    command
        .args(&config.command[1..])
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_policy_extension_environment(&mut command, config);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn `{program_display}`: {error}"))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "policy extension stdin was not piped".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "policy extension stdout was not piped".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "policy extension stderr was not piped".to_string())?;

    let request = request.to_vec();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = stdin;
        if let Err(error) = stdin.write_all(&request).await
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error);
        }
        stdin.shutdown().await
    });
    let stdout_task = tokio::spawn(read_limited(stdout, MAX_POLICY_EXTENSION_STDOUT_BYTES));
    let stderr_task = tokio::spawn(read_limited(stderr, MAX_POLICY_EXTENSION_STDERR_BYTES));
    let stdin_abort = stdin_task.abort_handle();
    let stdout_abort = stdout_task.abort_handle();
    let stderr_abort = stderr_task.abort_handle();
    let timeout = config.timeout;
    let interaction = async move {
        let status = child
            .wait()
            .await
            .map_err(|error| format!("failed to wait for `{program_display}`: {error}"))?;
        let write_result = stdin_task
            .await
            .map_err(|error| format!("stdin writer task panicked: {error}"))?;
        if let Err(error) = write_result {
            return Err(format!("failed to write policy extension request: {error}"));
        }
        let stdout = stdout_task
            .await
            .map_err(|error| format!("stdout reader task panicked: {error}"))?
            .map_err(|error| format!("failed to read policy extension stdout: {error}"))?;
        let stderr = stderr_task
            .await
            .map_err(|error| format!("stderr reader task panicked: {error}"))?
            .map_err(|error| format!("failed to read policy extension stderr: {error}"))?;

        if stdout.truncated {
            return Err(format!(
                "stdout exceeded {MAX_POLICY_EXTENSION_STDOUT_BYTES} bytes"
            ));
        }
        let stderr_preview = stderr_preview(&stderr);
        if !status.success() {
            return Err(format!("exited with status {status}{stderr_preview}"));
        }
        let stdout = std::str::from_utf8(&stdout.bytes)
            .map_err(|error| format!("stdout was not UTF-8 JSON: {error}"))?;
        let response: PolicyExtensionResponse = serde_json::from_str(stdout).map_err(|error| {
            format!("stdout was not a valid policy extension response: {error}")
        })?;
        let decisions = validate_policy_extension_response(response, known_packages)?;
        Ok(PolicyExtensionRun {
            duration_ms: started.elapsed().as_millis(),
            decisions,
        })
    };

    match tokio::time::timeout(timeout, interaction).await {
        Ok(result) => result,
        Err(_) => {
            stdin_abort.abort();
            stdout_abort.abort();
            stderr_abort.abort();
            Err(format!("timed out after {}ms", timeout.as_millis()))
        }
    }
}

fn configure_policy_extension_environment(
    command: &mut tokio::process::Command,
    config: &PolicyExtensionConfig,
) {
    command.env_clear();
    for key in minimal_policy_extension_env_keys() {
        if key.eq_ignore_ascii_case("PATH") {
            if let Some(value) = sanitized_policy_extension_path() {
                command.env(key, value);
            }
        } else if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.env("LPM_POLICY_EXTENSION", "1");
    command.env("LPM_POLICY_EXTENSION_NAME", &config.name);
    command.env(
        "LPM_POLICY_EXTENSION_EVENT",
        POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE,
    );
}

fn sanitized_policy_extension_path() -> Option<std::ffi::OsString> {
    let path_var = std::env::var_os("PATH")?;
    let dirs = std::env::split_paths(&path_var)
        .filter(|dir| dir.is_absolute())
        .collect::<Vec<_>>();
    if dirs.is_empty() {
        return None;
    }
    std::env::join_paths(dirs).ok()
}

#[cfg(windows)]
fn minimal_policy_extension_env_keys() -> &'static [&'static str] {
    &[
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    ]
}

#[cfg(not(windows))]
fn minimal_policy_extension_env_keys() -> &'static [&'static str] {
    &["PATH", "TMPDIR"]
}

async fn read_limited<R>(reader: R, limit: usize) -> std::io::Result<LimitedOutput>
where
    R: AsyncRead + Unpin,
{
    let mut reader = reader.take((limit + 1) as u64);
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024) + 1);
    reader.read_to_end(&mut bytes).await?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok(LimitedOutput { bytes, truncated })
}

fn stderr_preview(stderr: &LimitedOutput) -> String {
    if stderr.bytes.is_empty() {
        return String::new();
    }
    let lossy = String::from_utf8_lossy(&stderr.bytes);
    let mut preview = bounded_sanitized(&lossy, 512);
    if stderr.truncated {
        preview.push_str("...");
    }
    format!(": {preview}")
}

fn validate_policy_extension_response(
    response: PolicyExtensionResponse,
    known_packages: &BTreeSet<(String, String)>,
) -> Result<Vec<PolicyExtensionDecision>, String> {
    if response.schema_version != POLICY_EXTENSION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {}; expected {POLICY_EXTENSION_SCHEMA_VERSION}",
            response.schema_version
        ));
    }
    if response.decisions.len() > known_packages.len() {
        return Err(format!(
            "returned {} decisions for {} package candidate(s)",
            response.decisions.len(),
            known_packages.len()
        ));
    }
    let mut seen = HashSet::with_capacity(response.decisions.len());
    let mut decisions = Vec::with_capacity(response.decisions.len());
    for raw in response.decisions {
        if raw.name.is_empty() || raw.version.is_empty() {
            return Err("decision name and version must be non-empty".to_string());
        }
        let key = (raw.name.clone(), raw.version.clone());
        if !known_packages.contains(&key) {
            return Err(format!(
                "decision references package {}@{} that was not in the request",
                raw.name, raw.version
            ));
        }
        if !seen.insert(key) {
            return Err(format!(
                "returned duplicate decision for {}@{}",
                raw.name, raw.version
            ));
        }
        let action = PolicyExtensionAction::parse(&raw.action).ok_or_else(|| {
            format!(
                "invalid action `{}` for {}@{}; must be allow | warn | block",
                raw.action, raw.name, raw.version
            )
        })?;
        validate_optional_policy_string(
            "code",
            raw.code.as_deref(),
            MAX_POLICY_EXTENSION_CODE_CHARS,
        )?;
        validate_optional_policy_string(
            "reason",
            raw.reason.as_deref(),
            MAX_POLICY_EXTENSION_REASON_CHARS,
        )?;
        decisions.push(PolicyExtensionDecision {
            name: raw.name,
            version: raw.version,
            action,
            code: raw.code,
            reason: raw.reason,
        });
    }
    Ok(decisions)
}

fn validate_optional_policy_string(
    field: &str,
    value: Option<&str>,
    max_chars: usize,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > max_chars {
        return Err(format!(
            "{field} may contain at most {max_chars} characters"
        ));
    }
    Ok(())
}

fn print_policy_extension_decisions(
    config: &PolicyExtensionConfig,
    decisions: &[PolicyExtensionDecision],
) {
    let warned: Vec<_> = decisions
        .iter()
        .filter(|decision| decision.action == PolicyExtensionAction::Warn)
        .collect();
    let blocked: Vec<_> = decisions
        .iter()
        .filter(|decision| decision.action == PolicyExtensionAction::Block)
        .collect();
    if matches!(config.mode, PolicyExtensionMode::Report) {
        if warned.is_empty() && blocked.is_empty() {
            return;
        }
        output::warn(&format!(
            "policy extension `{}` report found {} blocked and {} warned package decision(s); command continues because report mode is active.",
            lpm_common::sanitize_for_terminal(&config.name),
            blocked.len(),
            warned.len()
        ));
        print_policy_decisions(&blocked);
        print_policy_decisions(&warned);
        return;
    }

    if !warned.is_empty() {
        output::warn(&format!(
            "policy extension `{}` warned for {} package decision(s):",
            lpm_common::sanitize_for_terminal(&config.name),
            warned.len()
        ));
        print_policy_decisions(&warned);
    }
    if !blocked.is_empty() {
        output::warn(&format!(
            "policy extension `{}` blocked {} package decision(s):",
            lpm_common::sanitize_for_terminal(&config.name),
            blocked.len()
        ));
        print_policy_decisions(&blocked);
    }
}

fn print_policy_decisions(decisions: &[&PolicyExtensionDecision]) {
    for decision in decisions {
        let name = lpm_common::sanitize_for_terminal(&decision.name);
        let version = lpm_common::sanitize_for_terminal(&decision.version);
        let action = decision.action.as_str();
        let code = decision.code.as_deref().map_or_else(String::new, |code| {
            format!(
                " [{}]",
                bounded_sanitized(code, MAX_POLICY_EXTENSION_CODE_CHARS)
            )
        });
        let reason = decision.reason.as_deref().map_or_else(
            || "no reason provided".to_string(),
            |reason| bounded_sanitized(reason, 240),
        );
        eprintln!("    {name}@{version} - {action}{code}: {reason}");
    }
}

fn bounded_sanitized(value: &str, max_chars: usize) -> String {
    let sanitized = lpm_common::sanitize_for_terminal(value);
    if sanitized.chars().count() <= max_chars {
        return sanitized;
    }
    let mut out: String = sanitized
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect();
    out.push_str("...");
    out
}

fn raw_contains_path_separator(raw: &str) -> bool {
    raw.contains('/') || raw.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_config_fixture() -> PolicyExtensionConfig {
        PolicyExtensionConfig {
            name: "fixture".to_string(),
            command: vec!["policy-fixture".to_string()],
            mode: PolicyExtensionMode::Report,
            on_error: PolicyExtensionOnError::Warn,
            timeout: Duration::from_millis(DEFAULT_POLICY_EXTENSION_TIMEOUT_MS),
        }
    }

    fn global_from_toml(toml: &str) -> GlobalConfig {
        let table = toml::from_str::<toml::Value>(toml)
            .unwrap()
            .as_table()
            .unwrap()
            .clone();
        GlobalConfig::from_table(table)
    }

    fn policy_package_fixture(name: &str, version: &str, source: &str) -> PolicyExtensionPackage {
        PolicyExtensionPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: source.to_string(),
            source_kind: "registry",
            integrity: None,
            registry_published_at: None,
            is_direct: true,
            is_lpm: false,
            optional: false,
        }
    }

    #[cfg(not(windows))]
    fn test_program_name() -> &'static str {
        "policy-fixture"
    }

    #[cfg(windows)]
    fn test_program_name() -> &'static str {
        "policy-fixture.exe"
    }

    fn write_test_executable(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    #[test]
    fn load_policy_extension_configs_reads_enabled_extension() {
        let global = global_from_toml(
            r#"
[policy.extensions.local_feed]
command = ["/usr/local/bin/lpm-policy-feed", "--strict"]
mode = "enforce"
on-error = "warn"
timeout-ms = 750
"#,
        );

        let configs = load_policy_extension_configs(&global).unwrap();

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "local_feed");
        assert_eq!(
            configs[0].command,
            ["/usr/local/bin/lpm-policy-feed", "--strict"]
        );
        assert_eq!(configs[0].mode, PolicyExtensionMode::Enforce);
        assert_eq!(configs[0].on_error, PolicyExtensionOnError::Warn);
        assert_eq!(configs[0].timeout, Duration::from_millis(750));
    }

    #[test]
    fn load_policy_extension_configs_defaults_to_report_and_mode_based_on_error() {
        let global = global_from_toml(
            r#"
[policy.extensions.audit]
command = ["/bin/audit"]
"#,
        );

        let configs = load_policy_extension_configs(&global).unwrap();

        assert_eq!(configs[0].mode, PolicyExtensionMode::Report);
        assert_eq!(configs[0].on_error, PolicyExtensionOnError::Warn);
    }

    #[test]
    fn load_policy_extension_configs_rejects_shell_string_command() {
        let global = global_from_toml(
            r#"
[policy.extensions.audit]
command = "/bin/audit --flag"
"#,
        );

        let err = load_policy_extension_configs(&global).unwrap_err();

        assert!(
            err.to_string()
                .contains("`[policy.extensions.audit].command` must be an array")
        );
    }

    #[test]
    fn load_policy_extension_configs_rejects_unknown_extension_field() {
        let global = global_from_toml(
            r#"
[policy.extensions.audit]
command = ["/bin/audit"]
mdoe = "enforce"
"#,
        );

        let err = load_policy_extension_configs(&global).unwrap_err();

        assert!(
            err.to_string()
                .contains("unsupported field `[policy.extensions.audit].mdoe`"),
            "got: {err}"
        );
    }

    #[test]
    fn load_policy_extension_configs_rejects_relative_executable_path() {
        let global = global_from_toml(
            r#"
[policy.extensions.audit]
command = ["./policy-extension"]
"#,
        );

        let err = load_policy_extension_configs(&global).unwrap_err();

        assert!(
            err.to_string()
                .contains("relative executable paths are not allowed")
        );
    }

    #[test]
    fn reject_remote_tarball_url_deps_with_policy_extensions_blocks_before_materialization() {
        let configs = [policy_config_fixture()];
        let deps = HashMap::from([(
            "tarball-pkg".to_string(),
            "https://example.test/tarball-pkg-1.0.0.tgz".to_string(),
        )]);

        let err =
            reject_remote_tarball_url_deps_with_policy_extensions(&configs, &deps).unwrap_err();

        assert!(
            err.to_string()
                .contains("do not support remote tarball URL dependency `tarball-pkg`")
        );
    }

    #[test]
    fn resolve_policy_extension_program_ignores_relative_and_empty_path_entries() {
        let temp = tempfile::tempdir().unwrap();
        let safe_bin = temp.path().join("safe-bin");
        std::fs::create_dir_all(&safe_bin).unwrap();
        let executable = safe_bin.join(test_program_name());
        write_test_executable(&executable);
        let path_var = std::env::join_paths([
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("relative-bin"),
            safe_bin,
        ])
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([("PATH", path_var)]);

        let resolved = resolve_policy_extension_program(test_program_name()).unwrap();

        assert_eq!(resolved, executable);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_policy_extension_timeout_includes_pipe_readers() {
        use std::os::unix::fs::PermissionsExt;

        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping timeout pipe-reader regression: python3 unavailable");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("holds-stdout-open");
        std::fs::write(
            &executable,
            b"#!/usr/bin/env python3\nimport os, sys, time\npid = os.fork()\nif pid == 0:\n    time.sleep(5)\n    os._exit(0)\nsys.stdout.write('{\"schema_version\":1,\"decisions\":[]}\\n')\nsys.stdout.flush()\nos._exit(0)\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        let config = PolicyExtensionConfig {
            command: vec![executable.display().to_string()],
            timeout: Duration::from_millis(750),
            ..policy_config_fixture()
        };

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_policy_extension(&config, temp.path(), b"{}", &BTreeSet::new()),
        )
        .await
        .expect("policy extension runner must honor timeout");

        let Err(err) = result else {
            panic!("policy extension runner must time out when pipes remain open");
        };
        assert!(err.contains("timed out after 750ms"), "got: {err}");
    }

    #[test]
    fn resolve_policy_extension_program_rejects_path_without_absolute_entries() {
        let path_var =
            std::env::join_paths([PathBuf::new(), PathBuf::from("."), PathBuf::from("bin")])
                .unwrap();
        let _env = crate::test_env::ScopedEnv::set([("PATH", path_var)]);

        let err = resolve_policy_extension_program(test_program_name()).unwrap_err();

        assert!(err.contains("absolute directories"));
    }

    #[test]
    fn validate_policy_extension_candidate_identities_rejects_source_distinct_duplicates() {
        let packages = vec![
            policy_package_fixture("same-name", "1.0.0", "registry+https://registry.npmjs.org"),
            policy_package_fixture(
                "same-name",
                "1.0.0",
                "tarball+https://example.test/same-name-1.0.0.tgz",
            ),
        ];

        let err = validate_policy_extension_candidate_identities(&packages).unwrap_err();

        assert!(err.contains("candidate set is ambiguous for same-name@1.0.0"));
    }

    #[test]
    fn validate_policy_extension_response_rejects_unknown_package() {
        let mut known = BTreeSet::new();
        known.insert(("known".to_string(), "1.0.0".to_string()));
        let response = PolicyExtensionResponse {
            schema_version: POLICY_EXTENSION_SCHEMA_VERSION,
            decisions: vec![PolicyExtensionRawDecision {
                name: "other".to_string(),
                version: "1.0.0".to_string(),
                action: "block".to_string(),
                code: None,
                reason: None,
            }],
        };

        let err = validate_policy_extension_response(response, &known).unwrap_err();

        assert!(err.contains("was not in the request"));
    }

    #[test]
    fn policy_extension_response_rejects_misspelled_decisions_field() {
        let response = serde_json::from_str::<PolicyExtensionResponse>(
            r#"{"schema_version":1,"decision":[{"name":"known","version":"1.0.0","action":"block"}]}"#,
        );

        assert!(
            response.is_err(),
            "policy response parser must reject misspelled decision envelopes"
        );
    }

    #[test]
    fn policy_extension_response_rejects_unknown_top_level_field() {
        let response = serde_json::from_str::<PolicyExtensionResponse>(
            r#"{"schema_version":1,"decisions":[],"extra":true}"#,
        );

        assert!(
            response.is_err(),
            "policy response parser must reject unknown top-level fields"
        );
    }

    #[test]
    fn policy_extension_response_rejects_unknown_decision_field() {
        let response = serde_json::from_str::<PolicyExtensionResponse>(
            r#"{"schema_version":1,"decisions":[{"name":"known","version":"1.0.0","action":"block","extra":true}]}"#,
        );

        assert!(
            response.is_err(),
            "policy response parser must reject unknown decision fields"
        );
    }

    #[test]
    fn validate_policy_extension_response_accepts_block_decision() {
        let mut known = BTreeSet::new();
        known.insert(("known".to_string(), "1.0.0".to_string()));
        let response = PolicyExtensionResponse {
            schema_version: POLICY_EXTENSION_SCHEMA_VERSION,
            decisions: vec![PolicyExtensionRawDecision {
                name: "known".to_string(),
                version: "1.0.0".to_string(),
                action: "block".to_string(),
                code: Some("deny-list".to_string()),
                reason: Some("matched local feed".to_string()),
            }],
        };

        let decisions = validate_policy_extension_response(response, &known).unwrap();

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].action, PolicyExtensionAction::Block);
    }
}
