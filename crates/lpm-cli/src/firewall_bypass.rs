//! Per-package exceptions to LPM Firewall enforcement: the spec grammar
//! (`name`, `name@1.2.3`, `name@<range>`), which kinds of block a rule may
//! cover, and the rules the signed store and the managed policy hold.

use lpm_common::{LpmError, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The most specs one native approval prompt names. Larger `add` calls ask
/// once per group so every prompt lists everything it approves.
pub(crate) const MAX_SPECS_PER_APPROVAL: usize = 5;

/// Which versions of a package a rule names.
#[derive(Clone, Debug)]
enum SpecVersions {
    Any,
    Exact(lpm_semver::Version),
    Range {
        text: String,
        req: lpm_semver::StrictVersionReq,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BypassKind {
    Any,
    Exact,
    Range,
}

impl BypassKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Exact => "exact",
            Self::Range => "range",
        }
    }
}

/// A validated `name`, `name@1.2.3` or `name@<range>`.
#[derive(Clone, Debug)]
pub(crate) struct FirewallBypassSpec {
    name: String,
    versions: SpecVersions,
}

impl FirewallBypassSpec {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("the package spec is empty".to_string());
        }
        if raw.trim() != raw {
            return Err("the package spec has surrounding whitespace".to_string());
        }
        let (name, version_text) = split_spec(raw);
        if name.contains(':') || version_text.is_some_and(|text| text.contains(':')) {
            return Err(
                "protocol specs (npm:, git:, file:, URLs) are not supported; name a registry package"
                    .to_string(),
            );
        }
        if name.ends_with("/*") {
            return Err(
                "scope wildcards are not supported; name each package to allow".to_string(),
            );
        }
        if lpm_common::package_name::is_lpm_package(name) {
            return Err("LPM Firewall never checks @lpm.dev packages".to_string());
        }
        if !valid_npm_name(name) {
            return Err(format!("`{name}` is not a valid npm package name"));
        }
        let versions = match version_text {
            None => SpecVersions::Any,
            Some(text) => parse_versions(text)?,
        };
        Ok(Self {
            name: name.to_string(),
            versions,
        })
    }

    #[inline]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn kind(&self) -> BypassKind {
        match self.versions {
            SpecVersions::Any => BypassKind::Any,
            SpecVersions::Exact(_) => BypassKind::Exact,
            SpecVersions::Range { .. } => BypassKind::Range,
        }
    }

    /// The exact version or range text, or `None` for every version.
    pub(crate) fn version_text(&self) -> Option<String> {
        match &self.versions {
            SpecVersions::Any => None,
            SpecVersions::Exact(version) => Some(version.to_string()),
            SpecVersions::Range { text, .. } => Some(text.clone()),
        }
    }

    pub(crate) fn matches(&self, name: &str, version: &str) -> bool {
        if self.name != name {
            return false;
        }
        match &self.versions {
            SpecVersions::Any => true,
            SpecVersions::Exact(exact) => {
                lpm_semver::Version::parse(version).is_ok_and(|version| version == *exact)
            }
            SpecVersions::Range { req, .. } => {
                lpm_semver::Version::parse(version).is_ok_and(|version| req.matches(&version))
            }
        }
    }

    /// What the rule allows, for prompts and listings: `foo@1.2.3`, every
    /// `foo` version, or `foo` versions matching a range.
    pub(crate) fn describe(&self) -> String {
        match &self.versions {
            SpecVersions::Any => format!("every {} version", self.name),
            SpecVersions::Exact(version) => format!("{}@{version}", self.name),
            SpecVersions::Range { text, .. } => {
                format!("{} versions matching {text}", self.name)
            }
        }
    }
}

impl std::fmt::Display for FirewallBypassSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.versions {
            SpecVersions::Any => f.write_str(&self.name),
            SpecVersions::Exact(version) => write!(f, "{}@{version}", self.name),
            SpecVersions::Range { text, .. } => write!(f, "{}@{text}", self.name),
        }
    }
}

fn split_spec(raw: &str) -> (&str, Option<&str>) {
    let search_from = usize::from(raw.starts_with('@'));
    match raw[search_from..].find('@') {
        Some(at) => {
            let at = at + search_from;
            (&raw[..at], Some(&raw[at + 1..]))
        }
        None => (raw, None),
    }
}

/// The longest range a rule may hold, so the approval prompt names it whole.
const MAX_RANGE_CHARS: usize = 80;

fn parse_versions(text: &str) -> Result<SpecVersions, String> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err("the version after `@` is empty".to_string());
    }
    if matches!(normalized.as_str(), "*" | "x" | "X") {
        return Ok(SpecVersions::Any);
    }
    if normalized.contains('+') {
        return Err(format!(
            "`{normalized}` has build metadata; name the version without it"
        ));
    }
    if let Some(version) = canonical_version(&normalized) {
        return Ok(SpecVersions::Exact(version));
    }
    if let Some(bare) = normalized.strip_prefix(['=', 'v', 'V'])
        && canonical_version(bare).is_some()
    {
        return Err(format!("write the exact version as `{bare}`"));
    }
    if normalized
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() && c != 'x' && c != 'X')
    {
        return Err(format!(
            "`{normalized}` looks like a dist-tag, which moves between versions; name an exact version or a range"
        ));
    }
    if normalized.chars().count() > MAX_RANGE_CHARS {
        return Err(format!(
            "the range is longer than {MAX_RANGE_CHARS} characters; add a shorter range or exact versions"
        ));
    }
    let req = lpm_semver::StrictVersionReq::parse(&normalized)
        .map_err(|_| format!("`{normalized}` is not a valid version or range"))?;
    if req.is_empty() {
        return Err(format!("`{normalized}` matches no version"));
    }
    Ok(SpecVersions::Range {
        text: normalized,
        req,
    })
}

/// `text` as an exact version when it is written the canonical way: three
/// numeric parts and an optional prerelease, as in `1.2.3` or `1.0.0-rc.x`.
fn canonical_version(text: &str) -> Option<lpm_semver::Version> {
    let core = text.split_once('-').map_or(text, |(core, _)| core);
    let mut parts = core.split('.');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    if !(numeric(parts.next()) && numeric(parts.next()) && numeric(parts.next()))
        || parts.next().is_some()
    {
        return None;
    }
    let version = lpm_semver::Version::parse(text).ok()?;
    (version.to_string() == text).then_some(version)
}

/// npm's naming rules, accepting the mixed-case names published before npm
/// required lower case (`JSONStream`).
fn valid_npm_name(name: &str) -> bool {
    fn valid_part(part: &str) -> bool {
        !part.is_empty()
            && !part.starts_with(['.', '_'])
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.' | b'_' | b'~' | b'!' | b'*' | b'\'' | b'(' | b')'
                    )
            })
    }
    if name.len() > 214 {
        return false;
    }
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, package)| valid_part(scope) && valid_part(package)),
        None => valid_part(name),
    }
}

/// What a block is about, which decides the rules that may lift it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockClass {
    /// A category the firewall policy profile tunes: agent control surface,
    /// telemetry, suspicious code, dependency scripts, critical vulnerability.
    Policy,
    /// A version the firewall has no verdict for yet, blocked as too new or by
    /// strict policy.
    Unscanned,
    /// Malware, a public malicious advisory, a malicious verdict, or a policy
    /// group this LPM doesn't know.
    Malware,
    /// A hold LPM reviewers placed; it can't be lifted locally.
    ServerReview,
}

impl BlockClass {
    pub(crate) fn of(verdict: &str, policy_group: Option<&str>) -> Self {
        if policy_group == Some("lpm_administrative_review") {
            return Self::ServerReview;
        }
        if verdict == "malicious" {
            return Self::Malware;
        }
        match policy_group {
            Some(
                "lpm_ai_dependency_script_policy"
                | "lpm_ai_agent_control_surface"
                | "lpm_ai_telemetry"
                | "lpm_ai_suspicious"
                | "static_only_suspicious"
                | "critical_vulnerability",
            ) => Self::Policy,
            Some(_) => Self::Malware,
            None if verdict == "unknown" => Self::Unscanned,
            None => Self::Malware,
        }
    }

    /// How hard a block is to lift: a higher class needs a narrower rule.
    pub(crate) const fn lift_difficulty(self) -> u8 {
        match self {
            Self::Policy => 0,
            Self::Unscanned => 1,
            Self::Malware => 2,
            Self::ServerReview => 3,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Unscanned => "unscanned",
            Self::Malware => "malware",
            Self::ServerReview => "server_review",
        }
    }

    /// Whether a rule of `kind`, approved with or without malware coverage,
    /// may lift a block of this class.
    pub(crate) fn coverable_by(self, kind: BypassKind, covers_malware: bool) -> bool {
        match self {
            Self::Policy => true,
            Self::Unscanned => kind == BypassKind::Exact,
            Self::Malware => kind == BypassKind::Exact && covers_malware,
            Self::ServerReview => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FirewallBypassScope {
    Global,
    Project,
}

impl FirewallBypassScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }
}

/// The verdict a rule's package had when the rule was approved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AddedVerdict {
    pub(crate) verdict: String,
    pub(crate) block_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) policy_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) report_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct FirewallBypassRule {
    pub(crate) id: String,
    pub(crate) spec: String,
    pub(crate) scope: FirewallBypassScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_root: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) covers_malware: bool,
    pub(crate) added_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) added_verdict: Option<AddedVerdict>,
}

impl FirewallBypassRule {
    pub(crate) fn new(
        spec: &FirewallBypassSpec,
        scope: FirewallBypassScope,
        project_root: Option<String>,
        covers_malware: bool,
        added_at: Timestamp,
    ) -> Self {
        let spec_text = spec.to_string();
        Self {
            id: rule_id(scope, project_root.as_deref(), &spec_text, covers_malware),
            spec: spec_text,
            scope,
            project_root,
            covers_malware,
            added_at,
            expires_at: None,
            reason: None,
            added_verdict: None,
        }
    }

    pub(crate) fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

/// Rules with the same scope, project, spec and malware coverage share an id,
/// so adding one twice is a no-op and asks for no second approval.
fn rule_id(
    scope: FirewallBypassScope,
    project_root: Option<&str>,
    spec: &str,
    covers_malware: bool,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(project_root.unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(spec.as_bytes());
    hasher.update([0, u8::from(covers_malware)]);
    let digest = hasher.finalize();
    format!("fwb_{}", hex::encode(&digest[..6]))
}

/// The root a project rule is keyed on: the workspace root for a workspace
/// member, else the nearest directory with a `package.json`.
pub(crate) fn project_policy_root(dir: &Path) -> Result<std::path::PathBuf, LpmError> {
    // Resolved first, so `../typo` can't walk up lexically into the current
    // project.
    let dir = std::fs::canonicalize(dir)
        .map_err(|error| LpmError::NotFound(format!("{}: {error}", dir.display())))?;
    let package_root = dir
        .ancestors()
        .find(|ancestor| ancestor.join("package.json").is_file())
        .ok_or_else(|| {
            LpmError::NotFound(format!(
                "no package.json found in {} or any parent",
                dir.display()
            ))
        })?;
    let root = lpm_workspace::find_workspace_root(package_root)
        .map_err(|error| LpmError::Workspace(error.to_string()))?
        .unwrap_or_else(|| package_root.to_path_buf());
    Ok(std::fs::canonicalize(&root).unwrap_or(root))
}

/// [`project_policy_root`] as the text a project rule stores. A root that
/// isn't valid UTF-8 is refused, so two such roots can never share a key.
pub(crate) fn project_policy_root_text(dir: &Path) -> Result<String, LpmError> {
    let root = project_policy_root(dir)?;
    root.to_str().map(str::to_string).ok_or_else(|| {
        LpmError::Registry(format!(
            "{} isn't valid UTF-8, so a project bypass rule can't name it",
            root.display()
        ))
    })
}

/// The command a person runs to allow `coordinates`, each double-quoted so
/// POSIX shells, PowerShell and cmd read it unchanged. Callers pass only
/// validated specs, which contain no quotes.
pub(crate) fn bypass_add_command<'a>(coordinates: impl IntoIterator<Item = &'a str>) -> String {
    let mut command = String::from("lpm firewall bypass add");
    for coordinate in coordinates {
        command.push_str(" \"");
        command.push_str(coordinate);
        command.push('"');
    }
    command
}

/// Whether `text` reads the same in double quotes in POSIX shells,
/// PowerShell and cmd: no quote, variable, substitution or escape character.
/// A backslash escapes the next character in POSIX double quotes, so it is
/// allowed only in Windows paths, and never last, where it would escape the
/// closing quote.
pub(crate) fn shell_safe_in_double_quotes(text: &str) -> bool {
    !text.is_empty()
        && !text.ends_with('\\')
        && text.chars().all(|character| {
            character.is_alphanumeric()
                || matches!(
                    character,
                    ' ' | '/' | '.' | '_' | '-' | '+' | ',' | '=' | '@' | ':' | '~'
                )
                || (character == '\\' && cfg!(windows))
        })
}

/// A project root as prompts show it: whole, with any control character
/// written as a visible escape so two roots never look alike.
pub(crate) fn visible_root(root: &str) -> std::borrow::Cow<'_, str> {
    if !root.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(root);
    }
    let mut visible = String::with_capacity(root.len() + 8);
    for character in root.chars() {
        if character.is_control() {
            visible.extend(character.escape_unicode());
        } else {
            visible.push(character);
        }
    }
    std::borrow::Cow::Owned(visible)
}

/// Whether a validated spec reads the same in double quotes in every shell:
/// interactive bash and zsh expand `!` even there, and the grammar admits it
/// in old package names.
#[inline]
pub(crate) fn spec_shell_safe(spec: &str) -> bool {
    !spec.contains('!')
}

/// The rule that let a blocked version through, as install output reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AppliedRule {
    pub(crate) spec: String,
    pub(crate) id: Option<String>,
    pub(crate) scope: FirewallBypassScope,
    pub(crate) project_root: Option<String>,
    pub(crate) source: &'static str,
}

impl AppliedRule {
    /// The same fields `lpm firewall bypass list --json` gives a rule.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "spec": self.spec,
            "id": self.id,
            "scope": self.scope.as_str(),
            "project_root": self.project_root,
            "source": self.source,
        })
    }

    /// Where the rule applies, as install output names it.
    pub(crate) fn scope_text(&self) -> String {
        let place = self.project_root.as_deref().unwrap_or("every project");
        if self.source == "managed" {
            format!("{place} from the managed policy")
        } else {
            place.to_string()
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    spec: FirewallBypassSpec,
    covers_malware: bool,
    expires_at: Option<Timestamp>,
    applied: AppliedRule,
    project: bool,
}

impl CompiledRule {
    /// Lower sorts first: an exact project rule is the most specific match.
    fn specificity(&self) -> (u8, u8) {
        let kind = match self.spec.kind() {
            BypassKind::Exact => 0,
            BypassKind::Range => 1,
            BypassKind::Any => 2,
        };
        (kind, u8::from(!self.project))
    }
}

/// The rules one command applies, indexed by package name.
#[derive(Debug, Default)]
pub(crate) struct FirewallBypassSet {
    by_name: std::collections::HashMap<String, Vec<CompiledRule>>,
}

impl FirewallBypassSet {
    fn compile(
        local: &[FirewallBypassRule],
        managed: &[crate::security_approval::ManagedFirewallBypass],
        policy_root: Option<&str>,
        now: Timestamp,
    ) -> Self {
        let mut by_name: std::collections::HashMap<String, Vec<CompiledRule>> =
            std::collections::HashMap::with_capacity(local.len() + managed.len());
        for rule in local {
            if rule.is_expired(now) {
                continue;
            }
            let project = match rule.scope {
                FirewallBypassScope::Global => false,
                FirewallBypassScope::Project => {
                    if policy_root.is_none() || rule.project_root.as_deref() != policy_root {
                        continue;
                    }
                    true
                }
            };
            let Ok(spec) = FirewallBypassSpec::parse(&rule.spec) else {
                continue;
            };
            by_name
                .entry(spec.name().to_string())
                .or_default()
                .push(CompiledRule {
                    covers_malware: rule.covers_malware,
                    expires_at: rule.expires_at,
                    applied: AppliedRule {
                        spec: rule.spec.clone(),
                        id: Some(rule.id.clone()),
                        scope: rule.scope,
                        project_root: rule.project_root.clone(),
                        source: "local",
                    },
                    project,
                    spec,
                });
        }
        for rule in managed {
            let Ok(spec) = FirewallBypassSpec::parse(&rule.spec) else {
                continue;
            };
            by_name
                .entry(spec.name().to_string())
                .or_default()
                .push(CompiledRule {
                    covers_malware: rule.covers_malware,
                    expires_at: None,
                    applied: AppliedRule {
                        spec: rule.spec.clone(),
                        id: None,
                        scope: FirewallBypassScope::Global,
                        project_root: None,
                        source: "managed",
                    },
                    project: false,
                    spec,
                });
        }
        for rules in by_name.values_mut() {
            rules.sort_by_key(CompiledRule::specificity);
        }
        Self { by_name }
    }

    /// The most specific unexpired rule that may lift a `class` block of
    /// `name@version` at `now`.
    pub(crate) fn find(
        &self,
        name: &str,
        version: &str,
        class: BlockClass,
        now: Timestamp,
    ) -> Option<&AppliedRule> {
        self.by_name.get(name)?.iter().find_map(|rule| {
            (rule.expires_at.is_none_or(|expires_at| expires_at > now)
                && class.coverable_by(rule.spec.kind(), rule.covers_malware)
                && rule.spec.matches(name, version))
            .then_some(&rule.applied)
        })
    }
}

/// The compiled rules and, when the local store couldn't be read, why.
#[derive(Debug)]
struct LoadedRules {
    set: FirewallBypassSet,
    local_error: Option<String>,
}

#[derive(Debug)]
struct FirewallBypassRulesInner {
    managed: Vec<crate::security_approval::ManagedFirewallBypass>,
    local_rules_apply: bool,
    local_rules_stored: bool,
    additions_allowed: bool,
    /// The directory whose project rules apply, resolved to its policy root
    /// only when a stored rule needs it.
    policy_dir: Option<std::path::PathBuf>,
    managed_policy_path: Option<String>,
    loaded: std::sync::OnceLock<LoadedRules>,
}

/// The bypass rules a command may apply. The local store is read, and its
/// signature checked against the keychain, only when a block needs it, so a
/// command that blocks nothing never touches it.
#[derive(Clone, Debug)]
pub(crate) struct FirewallBypassRules {
    inner: std::sync::Arc<FirewallBypassRulesInner>,
}

impl FirewallBypassRules {
    /// No rules saved and no managed policy owning the firewall.
    pub(crate) fn none() -> Self {
        Self::from_inner(FirewallBypassRulesInner {
            managed: Vec::new(),
            local_rules_apply: true,
            local_rules_stored: false,
            additions_allowed: true,
            policy_dir: None,
            managed_policy_path: None,
            loaded: std::sync::OnceLock::new(),
        })
    }

    fn from_inner(inner: FirewallBypassRulesInner) -> Self {
        Self {
            inner: std::sync::Arc::new(inner),
        }
    }

    /// The rules for a command whose project rules key on `policy_dir`'s
    /// policy root, or that applies only rules for every project when it is
    /// `None`. `additions_allowed` says whether `lpm firewall bypass add` would
    /// accept a rule here, for block hints.
    pub(crate) fn for_command(
        effective: &crate::security_approval::EffectiveAuthorizedPosture,
        policy_dir: Option<&Path>,
        additions_allowed: bool,
    ) -> Result<Self, LpmError> {
        let local_rules_apply =
            crate::security_approval::local_firewall_bypass_inactive_reason(effective).is_none();
        Ok(Self::from_inner(FirewallBypassRulesInner {
            managed: effective.managed_firewall_bypass.clone(),
            local_rules_apply,
            local_rules_stored: local_rules_apply
                && crate::security_approval::firewall_bypass_file_exists()?,
            additions_allowed: local_rules_apply && additions_allowed,
            policy_dir: policy_dir.map(Path::to_path_buf),
            managed_policy_path: effective
                .managed_policy
                .as_ref()
                .map(|policy| policy.path.clone()),
            loaded: std::sync::OnceLock::new(),
        }))
    }

    /// Rules already in memory, as tests that don't touch the signed store
    /// need them.
    #[cfg(test)]
    pub(crate) fn preloaded(
        local: &[FirewallBypassRule],
        managed: Vec<crate::security_approval::ManagedFirewallBypass>,
        policy_root: Option<&str>,
        local_rules_apply: bool,
    ) -> Self {
        let loaded = std::sync::OnceLock::new();
        let _ = loaded.set(LoadedRules {
            set: FirewallBypassSet::compile(
                if local_rules_apply { local } else { &[] },
                &managed,
                policy_root,
                Timestamp::now(),
            ),
            local_error: None,
        });
        Self::from_inner(FirewallBypassRulesInner {
            managed,
            local_rules_apply,
            local_rules_stored: local_rules_apply && !local.is_empty(),
            additions_allowed: local_rules_apply,
            policy_dir: policy_root.map(std::path::PathBuf::from),
            managed_policy_path: (!local_rules_apply)
                .then(|| "/etc/lpm/security-policy.toml".to_string()),
            loaded,
        })
    }

    /// Rules whose local store can't be read, as a tampered store reads.
    #[cfg(test)]
    pub(crate) fn unreadable(
        error: &str,
        managed: Vec<crate::security_approval::ManagedFirewallBypass>,
    ) -> Self {
        let loaded = std::sync::OnceLock::new();
        let _ = loaded.set(LoadedRules {
            set: FirewallBypassSet::compile(&[], &managed, None, Timestamp::now()),
            local_error: Some(error.to_string()),
        });
        Self::from_inner(FirewallBypassRulesInner {
            managed,
            local_rules_apply: true,
            local_rules_stored: true,
            additions_allowed: true,
            policy_dir: None,
            managed_policy_path: None,
            loaded,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inner.managed.is_empty() && !self.inner.local_rules_stored
    }

    /// Whether rules saved with `lpm firewall bypass add` can lift a block
    /// here; `false` when a managed policy owns the firewall.
    pub(crate) fn local_rules_apply(&self) -> bool {
        self.inner.local_rules_apply
    }

    /// Whether `lpm firewall bypass add` would accept a new rule here.
    pub(crate) fn additions_allowed(&self) -> bool {
        self.inner.additions_allowed
    }

    pub(crate) fn managed_policy_path(&self) -> Option<&str> {
        self.inner.managed_policy_path.as_deref()
    }

    /// Reads and verifies the local rules on first use, off the async
    /// runtime's worker threads. Managed rules apply even when the local
    /// store can't be read; the second value says why it couldn't.
    pub(crate) async fn load(&self) -> (&FirewallBypassSet, Option<&str>) {
        if self.inner.loaded.get().is_none() {
            let inner = std::sync::Arc::clone(&self.inner);
            let _ = tokio::task::spawn_blocking(move || {
                inner.loaded.get_or_init(|| compile_rules(&inner));
            })
            .await;
        }
        let loaded = self.inner.loaded.get_or_init(|| compile_rules(&self.inner));
        (&loaded.set, loaded.local_error.as_deref())
    }
}

fn compile_rules(inner: &FirewallBypassRulesInner) -> LoadedRules {
    let now = Timestamp::now();
    let (local, local_error) = if inner.local_rules_stored {
        match crate::security_approval::load_local_firewall_bypass_rules() {
            Ok(rules) => (rules, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        }
    } else {
        (Vec::new(), None)
    };
    let needs_root = local
        .iter()
        .any(|rule| rule.scope == FirewallBypassScope::Project && !rule.is_expired(now));
    let policy_root = needs_root
        .then_some(inner.policy_dir.as_deref())
        .flatten()
        .filter(|dir| !crate::security_approval::project_dir_is_global_install(dir))
        .and_then(|dir| project_policy_root_text(dir).ok());
    LoadedRules {
        set: FirewallBypassSet::compile(&local, &inner.managed, policy_root.as_deref(), now),
        local_error,
    }
}

/// Whether `force-security-floor = true` keeps the npm firewall at enforce,
/// counting both `~/.lpm/config.toml` and the approved posture, so
/// `lpm firewall bypass add` refuses new rules.
pub(crate) fn forced_floor_refuses_additions(
    global: &crate::commands::config::GlobalConfig,
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
) -> Result<bool, LpmError> {
    if !crate::security_floor::force_security_floor_enabled(global) {
        return Ok(false);
    }
    let floor = crate::security_floor::current_firewall_floor(global)?
        .stricter(effective.posture.firewall_mode());
    Ok(floor == crate::npm_firewall_config::NpmFirewallMode::Enforce)
}

/// A rule as `lpm firewall bypass list --json` and `lpm security status`
/// report it.
pub(crate) fn rule_json(
    rule: &FirewallBypassRule,
    source: &str,
    now: Timestamp,
) -> serde_json::Value {
    let spec = FirewallBypassSpec::parse(&rule.spec).ok();
    serde_json::json!({
        "id": rule.id,
        "spec": rule.spec,
        "name": spec.as_ref().map(FirewallBypassSpec::name),
        "versions": spec.as_ref().and_then(FirewallBypassSpec::version_text),
        "kind": spec.as_ref().map(|spec| spec.kind().as_str()),
        "scope": rule.scope.as_str(),
        "project_root": rule.project_root,
        "covers_malware": rule.covers_malware,
        "source": source,
        "added_at": rule.added_at.to_rfc3339(),
        "expires_at": rule.expires_at.map(Timestamp::to_rfc3339),
        "expired": rule.is_expired(now),
        "reason": rule.reason,
        "added_verdict": rule.added_verdict,
    })
}

/// Serializes local rules as [`rule_json`] reports them.
pub(crate) fn serialize_rules<S: serde::Serializer>(
    rules: &[FirewallBypassRule],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let now = Timestamp::now();
    let mut seq = serializer.serialize_seq(Some(rules.len()))?;
    for rule in rules {
        seq.serialize_element(&rule_json(rule, "local", now))?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(raw: &str) -> FirewallBypassSpec {
        FirewallBypassSpec::parse(raw).unwrap_or_else(|error| panic!("{raw}: {error}"))
    }

    #[test]
    fn spec_names_every_version_exact_version_or_range() {
        assert_eq!(spec("foldrun").kind(), BypassKind::Any);
        assert_eq!(spec("foldrun@32.8.2").kind(), BypassKind::Exact);
        assert_eq!(spec("react@^18.19.0").kind(), BypassKind::Range);
        assert_eq!(spec("react@>=18 <19").kind(), BypassKind::Range);
        assert_eq!(spec("@scope/pkg@1.0.0").name(), "@scope/pkg");
        assert_eq!(spec("@scope/pkg").kind(), BypassKind::Any);
        assert_eq!(spec("foldrun@*").kind(), BypassKind::Any);
    }

    #[test]
    fn spec_keeps_the_case_of_legacy_mixed_case_names() {
        let parsed = spec("JSONStream@1.3.5");

        assert_eq!(parsed.name(), "JSONStream");
        assert!(parsed.matches("JSONStream", "1.3.5"));
        assert!(!parsed.matches("jsonstream", "1.3.5"));
    }

    #[test]
    fn spec_normalizes_range_whitespace_in_its_canonical_text() {
        assert_eq!(spec("react@>=18   <19").to_string(), "react@>=18 <19");
    }

    #[test]
    fn spec_rejects_forms_that_do_not_name_registry_versions() {
        for (raw, needle) in [
            ("", "empty"),
            (" foldrun", "whitespace"),
            ("foldrun@latest", "dist-tag"),
            ("foldrun@npm:other@1.0.0", "protocol"),
            ("foldrun@git+https://example.com/x.git", "protocol"),
            ("@scope/*", "scope wildcards"),
            ("@lpm.dev/acme.widget", "@lpm.dev"),
            (".hidden", "not a valid npm package name"),
            ("foldrun@1.2.3+build.4", "build metadata"),
            ("foldrun@^1.2.3+build.4", "build metadata"),
            ("foldrun@>=1.0.0+a <2", "build metadata"),
            ("foldrun@=1.2.3", "write the exact version as `1.2.3`"),
            ("foldrun@v1.2.3", "write the exact version as `1.2.3`"),
            ("foldrun@vnext", "dist-tag"),
            (
                "foldrun@>=0.0.0-this-range-is-long-enough-to-crowd-out-the-rest-of-the-approval-prompt-text",
                "longer than 80",
            ),
            ("foldrun@>2 <1", "matches no version"),
            ("foldrun@", "empty"),
        ] {
            let error = FirewallBypassSpec::parse(raw).unwrap_err();
            assert!(error.contains(needle), "{raw}: {error}");
        }
    }

    #[test]
    fn prerelease_with_an_x_identifier_is_an_exact_version() {
        let parsed = spec("foldrun@1.0.0-alpha.x");

        assert_eq!(parsed.kind(), BypassKind::Exact);
        assert!(parsed.matches("foldrun", "1.0.0-alpha.x"));
        assert_eq!(spec("foldrun@1.2.x").kind(), BypassKind::Range);
    }

    #[test]
    fn exact_spec_matches_only_its_version() {
        let parsed = spec("foldrun@32.8.2");

        assert!(parsed.matches("foldrun", "32.8.2"));
        assert!(!parsed.matches("foldrun", "32.8.3"));
        assert!(!parsed.matches("foldrun-cli", "32.8.2"));
    }

    #[test]
    fn range_spec_follows_npm_prerelease_rules() {
        let parsed = spec("react@^18.19.0");

        assert!(parsed.matches("react", "18.20.1"));
        assert!(!parsed.matches("react", "19.0.0"));
        assert!(!parsed.matches("react", "18.21.0-rc.1"));
    }

    #[test]
    fn policy_blocks_may_be_lifted_by_any_rule_kind() {
        let class = BlockClass::of("suspicious", Some("lpm_ai_agent_control_surface"));

        assert_eq!(class, BlockClass::Policy);
        for kind in [BypassKind::Any, BypassKind::Range, BypassKind::Exact] {
            assert!(class.coverable_by(kind, false));
        }
    }

    #[test]
    fn malware_blocks_need_an_exact_rule_approved_for_malware() {
        for (verdict, group) in [
            ("malicious", Some("lpm_ai_agent_control_surface")),
            ("suspicious", Some("lpm_ai_confirmed_malware")),
            ("suspicious", Some("trusted_public_malicious_advisories")),
            ("suspicious", Some("lpm_ai_group_from_the_future")),
            ("suspicious", None),
        ] {
            let class = BlockClass::of(verdict, group);
            assert_eq!(class, BlockClass::Malware, "{verdict} {group:?}");
            assert!(!class.coverable_by(BypassKind::Any, true));
            assert!(!class.coverable_by(BypassKind::Range, true));
            assert!(!class.coverable_by(BypassKind::Exact, false));
            assert!(class.coverable_by(BypassKind::Exact, true));
        }
    }

    #[test]
    fn unscanned_blocks_need_an_exact_rule() {
        let class = BlockClass::of("unknown", None);

        assert_eq!(class, BlockClass::Unscanned);
        assert!(!class.coverable_by(BypassKind::Any, true));
        assert!(!class.coverable_by(BypassKind::Range, true));
        assert!(class.coverable_by(BypassKind::Exact, false));
    }

    #[test]
    fn server_review_holds_are_never_lifted_locally() {
        let class = BlockClass::of("clean", Some("lpm_administrative_review"));

        assert_eq!(class, BlockClass::ServerReview);
        assert!(!class.coverable_by(BypassKind::Exact, true));
    }

    #[test]
    fn rule_id_depends_on_scope_project_spec_and_malware_coverage() {
        let parsed = spec("foldrun@32.8.2");
        let now = Timestamp::now();
        let global =
            FirewallBypassRule::new(&parsed, FirewallBypassScope::Global, None, false, now);

        assert_eq!(
            global.id,
            FirewallBypassRule::new(&parsed, FirewallBypassScope::Global, None, false, now).id
        );
        assert_ne!(
            global.id,
            FirewallBypassRule::new(&parsed, FirewallBypassScope::Global, None, true, now).id
        );
        assert_ne!(
            global.id,
            FirewallBypassRule::new(
                &parsed,
                FirewallBypassScope::Project,
                Some("/work/app".into()),
                false,
                now
            )
            .id
        );
    }

    #[test]
    fn project_policy_root_refuses_a_missing_directory_beside_a_project() {
        let temp = tempfile::tempdir().unwrap();
        let app = temp.path().join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("package.json"), r#"{"name":"app"}"#).unwrap();

        let error = project_policy_root(&app.join("../other-ap")).unwrap_err();

        assert_eq!(error.error_code(), "not_found", "{error}");
    }

    #[test]
    fn project_policy_root_is_the_workspace_root_for_a_member() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("package.json"),
            r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let member = temp.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), r#"{"name":"app"}"#).unwrap();

        assert_eq!(
            project_policy_root(&member).unwrap(),
            std::fs::canonicalize(temp.path()).unwrap()
        );
    }

    fn local_rule(raw: &str, scope: FirewallBypassScope, root: Option<&str>) -> FirewallBypassRule {
        FirewallBypassRule::new(
            &spec(raw),
            scope,
            root.map(str::to_string),
            false,
            Timestamp::now(),
        )
    }

    fn compiled(
        local: &[FirewallBypassRule],
        managed: &[crate::security_approval::ManagedFirewallBypass],
        root: Option<&str>,
    ) -> FirewallBypassSet {
        FirewallBypassSet::compile(local, managed, root, Timestamp::now())
    }

    #[test]
    fn bypass_set_reports_the_most_specific_rule_that_matches() {
        let set = compiled(
            &[
                local_rule("foldrun", FirewallBypassScope::Global, None),
                local_rule("foldrun@^32.0.0", FirewallBypassScope::Global, None),
                local_rule("foldrun@32.8.2", FirewallBypassScope::Global, None),
            ],
            &[],
            None,
        );

        let rule = set
            .find("foldrun", "32.8.2", BlockClass::Policy, Timestamp::now())
            .unwrap();

        assert_eq!(rule.spec, "foldrun@32.8.2");
        assert_eq!(
            set.find("foldrun", "32.9.0", BlockClass::Policy, Timestamp::now())
                .unwrap()
                .spec,
            "foldrun@^32.0.0"
        );
        assert_eq!(
            set.find("foldrun", "31.0.0", BlockClass::Policy, Timestamp::now())
                .unwrap()
                .spec,
            "foldrun"
        );
    }

    #[test]
    fn bypass_set_lifts_nothing_its_rules_may_not_cover() {
        let set = compiled(
            &[
                local_rule("foldrun", FirewallBypassScope::Global, None),
                local_rule("foldrun@^32.0.0", FirewallBypassScope::Global, None),
            ],
            &[],
            None,
        );

        assert!(
            set.find("foldrun", "32.8.2", BlockClass::Malware, Timestamp::now())
                .is_none()
        );
        assert!(
            set.find("foldrun", "32.8.2", BlockClass::Unscanned, Timestamp::now())
                .is_none()
        );
        assert!(
            set.find(
                "foldrun",
                "32.8.2",
                BlockClass::ServerReview,
                Timestamp::now()
            )
            .is_none()
        );
        assert!(
            set.find("other", "32.8.2", BlockClass::Policy, Timestamp::now())
                .is_none()
        );
    }

    #[test]
    fn bypass_set_applies_project_rules_only_in_their_project() {
        let rules = [local_rule(
            "foldrun@32.8.2",
            FirewallBypassScope::Project,
            Some("/work/app"),
        )];

        assert!(
            compiled(&rules, &[], Some("/work/app"))
                .find("foldrun", "32.8.2", BlockClass::Policy, Timestamp::now())
                .is_some()
        );
        assert!(
            compiled(&rules, &[], Some("/work/other"))
                .find("foldrun", "32.8.2", BlockClass::Policy, Timestamp::now())
                .is_none()
        );
        assert!(
            compiled(&rules, &[], None)
                .find("foldrun", "32.8.2", BlockClass::Policy, Timestamp::now())
                .is_none()
        );
    }

    #[test]
    fn bypass_set_ignores_expired_rules() {
        let mut rule = local_rule("foldrun@32.8.2", FirewallBypassScope::Global, None);
        rule.expires_at = Some(Timestamp::now() - lpm_common::timestamp::Duration::seconds(1));

        assert!(
            compiled(&[rule], &[], None)
                .find("foldrun", "32.8.2", BlockClass::Policy, Timestamp::now())
                .is_none()
        );
    }

    #[test]
    fn managed_bypass_entries_apply_and_name_their_source() {
        let set = compiled(
            &[],
            &[crate::security_approval::ManagedFirewallBypass {
                spec: "foldrun@32.8.2".into(),
                covers_malware: true,
            }],
            None,
        );

        let rule = set
            .find("foldrun", "32.8.2", BlockClass::Malware, Timestamp::now())
            .unwrap();

        assert_eq!(rule.source, "managed");
        assert_eq!(rule.id, None);
    }

    #[test]
    fn bypass_add_command_double_quotes_each_spec() {
        assert_eq!(
            bypass_add_command(["@scope/pkg@1.0.0", "foldrun@32.8.2"]),
            "lpm firewall bypass add \"@scope/pkg@1.0.0\" \"foldrun@32.8.2\""
        );
    }

    #[test]
    fn bypass_set_checks_expiry_when_a_rule_is_used() {
        let now = Timestamp::now();
        let mut rule = local_rule("foldrun@32.8.2", FirewallBypassScope::Global, None);
        rule.expires_at = Some(now + lpm_common::timestamp::Duration::seconds(5));
        let set = FirewallBypassSet::compile(&[rule], &[], None, now);

        assert!(
            set.find("foldrun", "32.8.2", BlockClass::Policy, now)
                .is_some()
        );
        assert!(
            set.find(
                "foldrun",
                "32.8.2",
                BlockClass::Policy,
                now + lpm_common::timestamp::Duration::seconds(6)
            )
            .is_none()
        );
    }

    #[test]
    fn shell_safe_text_excludes_expansion_and_quote_characters() {
        assert!(shell_safe_in_double_quotes("/Users/a b/work-1.2_x"));
        assert_eq!(
            shell_safe_in_double_quotes("C:\\Users\\dev\\app"),
            cfg!(windows)
        );
        assert!(!shell_safe_in_double_quotes("/work/dir\\"));
        for unsafe_text in ["$HOME", "`id`", "%PATH%", "a\"b", "a!b", "a^b", "", "a\nb"] {
            assert!(!shell_safe_in_double_quotes(unsafe_text), "{unsafe_text:?}");
        }
    }
}
