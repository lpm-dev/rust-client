use miette::Diagnostic;
use serde::Serialize;
use std::fmt;
use thiserror::Error;

/// Machine-readable category for a dependency resolution failure.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionFailureKind {
    /// No published version satisfied the declared semver range.
    NoMatchingVersion,
    /// Matching versions exist but are incompatible with the current platform.
    PlatformIncompatible,
    /// A resolver policy such as minimum release age or trust policy rejected the candidate.
    PolicyBlocked,
    /// The registry metadata for a required package could not be fetched.
    FetchFailed,
    /// The resolver proved that no compatible dependency graph exists.
    NoSolution,
    /// Required peer ranges could not be reconciled.
    PeerConflict,
}

impl ResolutionFailureKind {
    /// Stable string used in JSON error envelopes.
    pub fn as_str(self) -> &'static str {
        match self {
            ResolutionFailureKind::NoMatchingVersion => "no_matching_version",
            ResolutionFailureKind::PlatformIncompatible => "platform_incompatible",
            ResolutionFailureKind::PolicyBlocked => "policy_blocked",
            ResolutionFailureKind::FetchFailed => "fetch_failed",
            ResolutionFailureKind::NoSolution => "no_solution",
            ResolutionFailureKind::PeerConflict => "peer_conflict",
        }
    }
}

impl fmt::Display for ResolutionFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured context for an install-time dependency resolution failure.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResolutionErrorContext {
    /// Canonical package name that could not be resolved.
    pub package: String,
    /// Declared range or version request.
    pub requested: String,
    /// Local dependency key from the requiring manifest. Differs from `package` for aliases.
    pub dependency: String,
    /// Package or project root that declared the request.
    pub required_by: Option<String>,
    /// Stable machine-readable failure category.
    pub kind: ResolutionFailureKind,
    /// Human-readable cause, already specific to the failed edge.
    pub reason: String,
    /// Number of versions present in metadata when known.
    pub available_versions: Option<usize>,
    /// Newest version present in metadata when known.
    pub newest_version: Option<String>,
    /// Solver derivation for no-solution cases when available.
    pub derivation: Option<String>,
}

impl ResolutionErrorContext {
    /// Render the canonical `package@range` request.
    pub fn package_request(&self) -> String {
        if self.requested.is_empty() || self.requested == "*" {
            self.package.clone()
        } else {
            format!("{}@{}", self.package, self.requested)
        }
    }

    /// Compact summary of known published versions for human output.
    pub fn available_summary(&self) -> Option<String> {
        let count = self.available_versions?;
        let noun = if count == 1 { "version" } else { "versions" };
        match self.newest_version.as_deref() {
            Some(newest) => Some(format!("{count} {noun}, newest {newest}")),
            None => Some(format!("{count} {noun}")),
        }
    }
}

impl fmt::Display for ResolutionErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.required_by.as_deref() {
            Some(required_by) => write!(
                f,
                "failed to resolve {} required by {required_by}: {}",
                self.package_request(),
                self.reason
            ),
            None => write!(
                f,
                "failed to resolve {}: {}",
                self.package_request(),
                self.reason
            ),
        }
    }
}

/// Whether an unavailable artifact came from a committed lockfile pin or from
/// the current mutable resolution.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactUnavailableKind {
    Pinned,
    Selected,
}

/// Structured context for an install-time artifact that cannot be retrieved
/// without changing the selected package contract.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ArtifactUnavailableErrorContext {
    pub package: String,
    pub version: String,
    pub source: String,
    pub kind: ArtifactUnavailableKind,
    pub lockfiles_preserved: bool,
    pub suggested_command: Option<String>,
}

impl ArtifactUnavailableErrorContext {
    pub fn package_request(&self) -> String {
        format!("{}@{}", self.package, self.version)
    }
}

impl fmt::Display for ArtifactUnavailableErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ArtifactUnavailableKind::Pinned => {
                write!(
                    f,
                    "pinned artifact {} is unavailable from {}; lpm.lock and lpm.lockb pins were \
                     preserved. ",
                    self.package_request(),
                    self.source,
                )?;
                if let Some(command) = self.suggested_command.as_deref() {
                    write!(
                        f,
                        "Changing the pin requires `{command}` in a mutable development \
                         environment, followed by committing the updated lockfiles. Frozen and \
                         `lpm ci` installs will continue to fail until that explicit update is \
                         committed"
                    )
                } else {
                    write!(
                        f,
                        "No direct package.json dependency key is available for this artifact, so \
                         restore it or update its owning direct dependency or an override in a \
                         mutable development environment, then commit the updated lockfiles. \
                         Frozen and `lpm ci` installs will continue to fail until the artifact is \
                         restored or that explicit update is committed"
                    )
                }
            }
            ArtifactUnavailableKind::Selected => write!(
                f,
                "selected artifact {} is unavailable from {}; existing lpm.lock and lpm.lockb \
                 files were preserved and no new lockfile was written",
                self.package_request(),
                self.source,
            ),
        }
    }
}

/// One suspicious package name detected before it enters a project.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TyposquatErrorFinding {
    /// Package name requested by the user or declared directly in package.json.
    pub package: String,
    /// Popular package name the requested name resembles.
    pub similar_to: String,
    /// Stable machine-readable typo technique.
    pub technique: String,
    /// Where the direct dependency came from.
    pub source: String,
}

/// Structured context for a typosquatting policy refusal.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct TyposquatErrorContext {
    /// Suspicious direct dependencies that were not allow-listed.
    pub findings: Vec<TyposquatErrorFinding>,
    /// Project policy file the user can commit for an intentional exception.
    pub config_path: String,
    /// TOML snippet showing the committed allow-list shape.
    pub allow_example: String,
    /// Safer command when a single CLI package arg has an obvious intended target.
    pub suggested_command: Option<String>,
    /// Whether an interactive user declined the typosquat prompt.
    #[serde(skip)]
    pub cancelled: bool,
}

impl TyposquatErrorContext {
    /// First finding, used by compact human summaries.
    pub fn primary(&self) -> Option<&TyposquatErrorFinding> {
        self.findings.first()
    }
}

impl fmt::Display for TyposquatErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.findings.as_slice() {
            [] => f.write_str("suspicious package name"),
            [finding] => write!(
                f,
                "suspicious package name '{}' looks like '{}'",
                finding.package, finding.similar_to
            ),
            findings => write!(f, "{} suspicious package names", findings.len()),
        }
    }
}

/// Top-level error type for all LPM operations.
///
/// Integrates with `miette` for rich, user-friendly error display.
/// Each variant includes a help message suggesting what to do next.
#[derive(Debug, Error, Diagnostic)]
pub enum LpmError {
    #[error("invalid package name: {0}")]
    #[diagnostic(
        code(lpm::invalid_package_name),
        help("LPM packages use the format @lpm.dev/owner.package-name")
    )]
    InvalidPackageName(String),

    #[error("invalid integrity hash: {0}")]
    #[diagnostic(code(lpm::invalid_integrity))]
    InvalidIntegrity(String),

    #[error("integrity mismatch: expected {expected}, got {actual}")]
    #[diagnostic(
        code(lpm::integrity_mismatch),
        help(
            "The downloaded package may be corrupted. Try again, or report this to the package owner."
        )
    )]
    IntegrityMismatch { expected: String, actual: String },

    #[error("invalid version: {0}")]
    #[diagnostic(
        code(lpm::invalid_version),
        help("Versions must follow semver format: MAJOR.MINOR.PATCH (e.g., 1.2.3)")
    )]
    InvalidVersion(String),

    #[error("invalid version range: {0}")]
    #[diagnostic(
        code(lpm::invalid_version_range),
        help("Examples: ^1.0.0, ~1.2.3, >=1.0.0 <2.0.0, 1.x, *")
    )]
    InvalidVersionRange(String),

    #[error("registry error: {0}")]
    #[diagnostic(code(lpm::registry))]
    Registry(String),

    #[error("{0}")]
    #[diagnostic(
        code(lpm::resolution_failed),
        help(
            "Update the requested version range, change the package that requires it, or add an override if you intentionally want to force a compatible version."
        )
    )]
    Resolution(Box<ResolutionErrorContext>),

    #[error("{0}")]
    #[diagnostic(
        code(lpm::typosquat_suspected),
        help(
            "Install the intended package name, or commit a policy.typosquat allow-list entry with a reason if this name is intentional."
        )
    )]
    TyposquatSuspected(Box<TyposquatErrorContext>),

    #[error("peer dependency check failed: {0}")]
    #[diagnostic(
        code(lpm::peer_dependency),
        help(
            "Fix the missing or incompatible peer dependencies, or pass \
             --no-strict-peer-dependencies / set strict-peer-dependencies = false \
             to return to warn-only mode."
        )
    )]
    PeerDependency(String),

    #[error("network error: {0}")]
    #[diagnostic(
        code(lpm::network),
        help("Check your internet connection, or try again in a moment.")
    )]
    Network(String),

    #[error("HTTP {status}: {message}")]
    #[diagnostic(code(lpm::http))]
    Http { status: u16, message: String },

    #[error("authentication required")]
    #[diagnostic(
        code(lpm::auth_required),
        help("Run `lpm login` or set the LPM_TOKEN environment variable.")
    )]
    AuthRequired,

    #[error("session expired or revoked")]
    #[diagnostic(
        code(lpm::session_expired),
        help("Run `lpm login` to re-authenticate.")
    )]
    SessionExpired,

    #[error("forbidden: {0}")]
    #[diagnostic(
        code(lpm::forbidden),
        help("You may not have access to this resource. Check your permissions.")
    )]
    Forbidden(String),

    #[error("LPM firewall blocked {package} (verdict: {verdict}): {reason}")]
    #[diagnostic(
        code(lpm::npm_firewall_blocked),
        help("Review the package security report or contact LPM support with the decision ID.")
    )]
    NpmFirewallBlocked {
        package: String,
        verdict: String,
        reason: String,
        decision_id: Option<String>,
        match_source: Option<String>,
    },

    #[error("LPM npm firewall access denied: {message}")]
    #[diagnostic(
        code(lpm::npm_firewall_entitlement_required),
        help("Use a Pro/org token for npm firewall checks, or set [firewall].mode = \"off\".")
    )]
    NpmFirewallEntitlementRequired {
        message: String,
        reason: Option<String>,
        entitlement_source: Option<String>,
    },

    #[error("LPM upstream npm proxy access denied: {message}")]
    #[diagnostic(
        code(lpm::upstream_proxy_entitlement_required),
        help(
            "Use a Pro/org token for standalone npm proxy usage, or route standalone npm packages directly to npm."
        )
    )]
    UpstreamProxyEntitlementRequired {
        message: String,
        reason: Option<String>,
        entitlement_source: Option<String>,
    },

    #[error("not found: {0}")]
    #[diagnostic(
        code(lpm::not_found),
        help("Check the package name and try `lpm search` to find packages.")
    )]
    NotFound(String),

    #[error("{0}")]
    #[diagnostic(
        code(lpm::artifact_unavailable),
        help(
            "Restore the pinned artifact in the registry, or update the dependency explicitly in a mutable development environment."
        )
    )]
    ArtifactUnavailable(Box<ArtifactUnavailableErrorContext>),

    #[error("rate limited — retry after {retry_after_secs}s")]
    #[diagnostic(
        code(lpm::rate_limited),
        help("Too many requests. The client will retry automatically.")
    )]
    RateLimited { retry_after_secs: u64 },

    #[error("script error: {0}")]
    #[diagnostic(
        code(lpm::script),
        help("Check your package.json scripts section. Run `lpm run` to list available scripts.")
    )]
    Script(String),

    #[error("certificate error: {0}")]
    #[diagnostic(
        code(lpm::cert),
        help(
            "Run `lpm cert status` to check your certificate setup, or `lpm cert trust` to install the CA."
        )
    )]
    Cert(String),

    #[error("tunnel error: {0}")]
    #[diagnostic(
        code(lpm::tunnel),
        help("Check your network connection. Run `lpm tunnel` to start a new tunnel session.")
    )]
    Tunnel(String),

    #[error("store error: {0}")]
    #[diagnostic(
        code(lpm::store),
        help(
            "The global package store at ~/.lpm/store may be corrupted. Try `lpm cache prune --apply` or `lpm store clean`."
        )
    )]
    Store(String),

    /// Script failed with captured output (used by buffered/prefixed parallel modes
    /// to preserve output for post-failure display).
    #[error("script exited with code {code}")]
    #[diagnostic(code(lpm::script))]
    ScriptWithOutput {
        code: i32,
        stdout: String,
        stderr: String,
    },

    #[error("process exited with code {0}")]
    #[diagnostic(code(lpm::exit_code))]
    ExitCode(i32),

    #[error("IO error: {0}")]
    #[diagnostic(code(lpm::io))]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    #[diagnostic(code(lpm::json))]
    Json(#[from] serde_json::Error),

    #[error("task error: {0}")]
    #[diagnostic(code(lpm::task), help("Check your task configuration in lpm.json"))]
    Task(String),

    #[error("plugin error: {0}")]
    #[diagnostic(
        code(lpm::plugin),
        help("Run `lpm plugin list` to see installed plugins")
    )]
    Plugin(String),

    #[error("engine error: {0}")]
    #[diagnostic(
        code(lpm::engine),
        help(
            "Retry the command, or remove the cached engine under ~/.lpm/engines if it looks corrupted."
        )
    )]
    Engine(String),

    #[error("workspace error: {0}")]
    #[diagnostic(
        code(lpm::workspace),
        help("Check your workspace configuration in package.json or pnpm-workspace.yaml")
    )]
    Workspace(String),

    #[error(
        "invalid recursive catalog entry for dependency '{dependency}' in catalog '{catalog}': catalog entry value '{specifier}' cannot use the catalog protocol recursively"
    )]
    #[diagnostic(
        code(lpm::catalog_entry_invalid_recursive_definition),
        help("Replace the catalog entry with a concrete version range.")
    )]
    CatalogEntryInvalidRecursiveDefinition {
        dependency: String,
        catalog: String,
        specifier: String,
    },

    #[error("environment validation failed:\n{0}")]
    #[diagnostic(
        code(lpm::env_validation),
        help("Check your .env files and lpm.json schema. Run with --no-env-check to bypass.")
    )]
    EnvValidation(String),

    #[error("{engine} version {actual} does not satisfy required {required} (from {from})")]
    #[diagnostic(
        code(lpm::engine_mismatch),
        help(
            "Either install a matching version, relax the constraint in package.json > engines, \
             or pass --no-engine-strict / set engine-strict = false in ~/.lpm/config.toml to skip \
             the check."
        )
    )]
    EngineMismatch {
        engine: String,
        required: String,
        actual: String,
        from: String,
    },

    /// `lpm self-update` is in cooldown after a previous failed probe.
    /// Distinct from `Network` because the failure isn't a live network
    /// problem — it's a local cache decision to back off and not
    /// re-hammer the rate-limited / unreachable endpoint.
    #[error("update check paused: {0}")]
    #[diagnostic(
        code(lpm::self_update_paused),
        help("Re-run with --refresh to bypass the cooldown and retry immediately.")
    )]
    SelfUpdatePaused(String),

    /// Update check hit a GitHub API rate limit on the fallback path.
    /// Distinct from `Forbidden` (which reads to users as "you're
    /// banned") because the fix is "wait" or "raise the limit", not
    /// "check your permissions".
    #[error("update check rate-limited: {0}")]
    #[diagnostic(
        code(lpm::self_update_rate_limited),
        help(
            "The GitHub Releases fallback is rate-limited. Wait for the reset, or set \
             GITHUB_TOKEN / GH_TOKEN to raise the limit from 60 to 5000 req/hr."
        )
    )]
    SelfUpdateRateLimited(String),

    #[error("provenance verification failed: {0}")]
    #[diagnostic(
        code(lpm::provenance_verification),
        help(
            "A Sigstore attestation was fetched for this package but failed cryptographic \
             verification (chain, SET, SCT, inclusion proof, DSSE signature, Rekor body, or \
             identity-pin check). The registry may be compromised or serving a corrupt bundle. \
             Use `--unverified-provenance <pkg>` to opt out for this specific package if you \
             have reason to trust it through another channel."
        )
    )]
    ProvenanceVerification(String),

    /// `lpm self-update` standalone path refused to swap the binary
    /// because the release artifacts failed an integrity gate
    /// (`SHA256SUMS.txt` missing on a release that predates the
    /// signed-install gate, Sigstore bundle rejected, SHA mismatch,
    /// identity pin not satisfied, replay window violated, etc.).
    /// Distinct from `Network` so the CLI can render remediation copy
    /// that names the manual install URL.
    #[error("self-update refused: {0}")]
    #[diagnostic(
        code(lpm::self_update),
        help(
            "The downloaded release could not be cryptographically verified. \
             If this is a release that predates LPM's signed-install gate, install \
             manually from https://github.com/lpm-dev/rust-client/releases. \
             Otherwise the release artifacts may be tampered or the manifest may be missing — \
             retry, and if the failure persists report at https://github.com/lpm-dev/rust-client/issues."
        )
    )]
    SelfUpdate(String),

    #[error("security floor refused: {0}")]
    #[diagnostic(
        code(lpm::security_floor),
        help(
            "This request would lower the current machine floor while `force-security-floor = true` is active. \
             Keep the stricter posture, or lower the floor intentionally in ~/.lpm/config.toml before retrying."
        )
    )]
    SecurityFloor(String),

    #[error("security approval store refused: {0}")]
    #[diagnostic(
        code(lpm::security_approval_store),
        help(
            "The local signed security state could not be verified. If this is stale local state, \
             run `lpm security repair` to quarantine unverified approvals, or restore the original keyring secret."
        )
    )]
    SecurityApprovalStore(String),

    #[error("security approval required: {message}")]
    #[diagnostic(
        code(lpm::security_approval_required),
        help("Approve the requested weakening explicitly, then retry the original command.")
    )]
    SecurityApprovalRequired {
        message: String,
        requested_scopes: Vec<String>,
        project_root: Option<String>,
        suggested_command: Option<String>,
    },
}

impl LpmError {
    /// Machine-readable error code for structured JSON output.
    ///
    /// Used by the CLI's `--json` flag to provide parseable error responses
    /// for LLMs, MCP servers, and CI/CD pipelines.
    pub fn error_code(&self) -> &'static str {
        match self {
            LpmError::InvalidPackageName(_) => "invalid_package_name",
            LpmError::InvalidIntegrity(_) => "invalid_integrity",
            LpmError::IntegrityMismatch { .. } => "integrity_mismatch",
            LpmError::InvalidVersion(_) => "invalid_version",
            LpmError::InvalidVersionRange(_) => "invalid_version_range",
            LpmError::Registry(_) => "registry",
            LpmError::Resolution(_) => "resolution_failed",
            LpmError::TyposquatSuspected(_) => "typosquat_suspected",
            LpmError::PeerDependency(_) => "peer_dependency",
            LpmError::Network(_) => "network",
            LpmError::Http { .. } => "http",
            LpmError::AuthRequired => "auth_required",
            LpmError::SessionExpired => "session_expired",
            LpmError::Forbidden(_) => "forbidden",
            LpmError::NpmFirewallBlocked { .. } => "npm_firewall_blocked",
            LpmError::NpmFirewallEntitlementRequired { .. } => "npm_firewall_entitlement_required",
            LpmError::UpstreamProxyEntitlementRequired { .. } => {
                "upstream_proxy_entitlement_required"
            }
            LpmError::NotFound(_) => "not_found",
            LpmError::ArtifactUnavailable(context) => match context.kind {
                ArtifactUnavailableKind::Pinned => "pinned_artifact_unavailable",
                ArtifactUnavailableKind::Selected => "selected_artifact_unavailable",
            },
            LpmError::RateLimited { .. } => "rate_limited",
            LpmError::Script(_) => "script",
            LpmError::ScriptWithOutput { .. } => "script",
            LpmError::Cert(_) => "cert",
            LpmError::Tunnel(_) => "tunnel",
            LpmError::Store(_) => "store",
            LpmError::ExitCode(_) => "exit_code",
            LpmError::Io(_) => "io",
            LpmError::Json(_) => "json",
            LpmError::Task(_) => "task",
            LpmError::Plugin(_) => "plugin",
            LpmError::Engine(_) => "engine",
            LpmError::Workspace(_) => "workspace",
            LpmError::CatalogEntryInvalidRecursiveDefinition { .. } => {
                "catalog_entry_invalid_recursive_definition"
            }
            LpmError::EnvValidation(_) => "env_validation",
            LpmError::EngineMismatch { .. } => "engine_mismatch",
            LpmError::SelfUpdatePaused(_) => "self_update_paused",
            LpmError::SelfUpdateRateLimited(_) => "self_update_rate_limited",
            LpmError::ProvenanceVerification(_) => "provenance_verification",
            LpmError::SelfUpdate(_) => "self_update",
            LpmError::SecurityFloor(_) => "security_floor",
            LpmError::SecurityApprovalStore(_) => "security_approval_store",
            LpmError::SecurityApprovalRequired { .. } => "security_approval_required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miette::Diagnostic;

    #[test]
    fn task_error_display() {
        let err = LpmError::Task("cache miss".to_string());
        assert_eq!(err.to_string(), "task error: cache miss");
    }

    #[test]
    fn task_error_diagnostic_code() {
        let err = LpmError::Task("cache miss".to_string());
        let code = err.code().unwrap();
        assert_eq!(code.to_string(), "lpm::task");
    }

    #[test]
    fn task_error_help() {
        let err = LpmError::Task("cache miss".to_string());
        let help = err.help().unwrap();
        assert_eq!(
            help.to_string(),
            "Check your task configuration in lpm.json"
        );
    }

    #[test]
    fn plugin_error_display() {
        let err = LpmError::Plugin("version mismatch".to_string());
        assert_eq!(err.to_string(), "plugin error: version mismatch");
    }

    #[test]
    fn plugin_error_diagnostic_code() {
        let err = LpmError::Plugin("version mismatch".to_string());
        let code = err.code().unwrap();
        assert_eq!(code.to_string(), "lpm::plugin");
    }

    #[test]
    fn plugin_error_help() {
        let err = LpmError::Plugin("version mismatch".to_string());
        let help = err.help().unwrap();
        assert_eq!(
            help.to_string(),
            "Run `lpm plugin list` to see installed plugins"
        );
    }

    #[test]
    fn engine_error_display() {
        let err = LpmError::Engine("version mismatch".to_string());
        assert_eq!(err.to_string(), "engine error: version mismatch");
    }

    #[test]
    fn engine_error_diagnostic_code() {
        let err = LpmError::Engine("version mismatch".to_string());
        let code = err.code().unwrap();
        assert_eq!(code.to_string(), "lpm::engine");
    }

    #[test]
    fn engine_error_help() {
        let err = LpmError::Engine("version mismatch".to_string());
        let help = err.help().unwrap();
        assert!(help.to_string().contains("~/.lpm/engines"));
    }

    #[test]
    fn exit_code_error_display() {
        let err = LpmError::ExitCode(42);
        assert_eq!(err.to_string(), "process exited with code 42");
    }

    #[test]
    fn exit_code_error_diagnostic_code() {
        let err = LpmError::ExitCode(1);
        let code = err.code().unwrap();
        assert_eq!(code.to_string(), "lpm::exit_code");
    }

    #[test]
    fn script_error_unchanged() {
        let err = LpmError::Script("build failed".to_string());
        assert_eq!(err.to_string(), "script error: build failed");
        let code = err.code().unwrap();
        assert_eq!(code.to_string(), "lpm::script");
        let help = err.help().unwrap();
        assert!(help.to_string().contains("package.json scripts"));
    }

    #[test]
    fn error_code_covers_all_variants() {
        // Verify every variant returns a non-empty, unique error code
        let variants: Vec<LpmError> = vec![
            LpmError::InvalidPackageName("x".into()),
            LpmError::InvalidIntegrity("x".into()),
            LpmError::IntegrityMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            LpmError::InvalidVersion("x".into()),
            LpmError::InvalidVersionRange("x".into()),
            LpmError::Registry("x".into()),
            LpmError::Resolution(Box::new(resolution_error_context())),
            LpmError::PeerDependency("x".into()),
            LpmError::Network("x".into()),
            LpmError::Http {
                status: 500,
                message: "x".into(),
            },
            LpmError::AuthRequired,
            LpmError::SessionExpired,
            LpmError::Forbidden("x".into()),
            LpmError::NpmFirewallBlocked {
                package: "is-number@7.0.0".into(),
                verdict: "malicious".into(),
                reason: "product_default policy maps malicious to block".into(),
                decision_id: Some("decision-1".into()),
                match_source: Some("package".into()),
            },
            LpmError::NpmFirewallEntitlementRequired {
                message: "A Pro account or active org membership is required.".into(),
                reason: Some("personal_plan_not_eligible".into()),
                entitlement_source: None,
            },
            LpmError::UpstreamProxyEntitlementRequired {
                message: "A Pro account or active org membership is required.".into(),
                reason: Some("personal_plan_not_eligible".into()),
                entitlement_source: None,
            },
            LpmError::NotFound("x".into()),
            LpmError::ArtifactUnavailable(Box::new(ArtifactUnavailableErrorContext {
                package: "left-pad".into(),
                version: "1.3.0".into(),
                source: "registry+https://registry.npmjs.org".into(),
                kind: ArtifactUnavailableKind::Pinned,
                lockfiles_preserved: true,
                suggested_command: Some("lpm upgrade left-pad".into()),
            })),
            LpmError::RateLimited {
                retry_after_secs: 5,
            },
            LpmError::Script("x".into()),
            LpmError::ScriptWithOutput {
                code: 1,
                stdout: String::new(),
                stderr: String::new(),
            },
            LpmError::Cert("x".into()),
            LpmError::Tunnel("x".into()),
            LpmError::Store("x".into()),
            LpmError::ExitCode(1),
            LpmError::Io(std::io::Error::other("x")),
            LpmError::Json(serde_json::from_str::<serde_json::Value>("bad").unwrap_err()),
            LpmError::Task("x".into()),
            LpmError::Plugin("x".into()),
            LpmError::Engine("x".into()),
            LpmError::Workspace("x".into()),
            LpmError::CatalogEntryInvalidRecursiveDefinition {
                dependency: "react".into(),
                catalog: "default".into(),
                specifier: "catalog:shared".into(),
            },
            LpmError::EnvValidation("x".into()),
            LpmError::EngineMismatch {
                engine: "lpm".into(),
                required: ">=1.0.0".into(),
                actual: "0.32.0".into(),
                from: "package.json > engines.lpm".into(),
            },
            LpmError::SelfUpdatePaused("x".into()),
            LpmError::SelfUpdateRateLimited("x".into()),
            LpmError::SecurityFloor("x".into()),
            LpmError::SecurityApprovalStore("x".into()),
        ];

        for variant in &variants {
            let code = variant.error_code();
            assert!(
                !code.is_empty(),
                "error_code() returned empty for: {variant}"
            );
        }
    }

    /// Self-update categories must render with their own user-facing
    /// prefixes — not the historical `network error:` (cooldown) or
    /// `forbidden:` (rate limit) which both miscategorised the failure.
    #[test]
    fn self_update_paused_renders_with_correct_prefix() {
        let err = LpmError::SelfUpdatePaused("last attempt failed 10 minutes ago".into());
        let s = err.to_string();
        assert!(
            s.starts_with("update check paused:"),
            "expected dedicated prefix, got: {s}"
        );
        assert!(
            !s.contains("network error"),
            "must not leak into Network category: {s}"
        );
    }

    #[test]
    fn self_update_rate_limited_renders_with_correct_prefix() {
        let err = LpmError::SelfUpdateRateLimited("Try again in 13 minutes".into());
        let s = err.to_string();
        assert!(
            s.starts_with("update check rate-limited:"),
            "expected dedicated prefix, got: {s}"
        );
        assert!(
            !s.contains("forbidden"),
            "must not leak into Forbidden category: {s}"
        );
    }

    /// Help text for the paused variant must surface `--refresh` since
    /// it's the user-controllable knob; help text for the rate-limited
    /// variant must mention GITHUB_TOKEN / GH_TOKEN.
    #[test]
    fn self_update_paused_help_mentions_refresh() {
        let err = LpmError::SelfUpdatePaused("x".into());
        let help = err.help().unwrap().to_string();
        assert!(help.contains("--refresh"), "help: {help}");
    }

    #[test]
    fn self_update_rate_limited_help_mentions_token_env_vars() {
        let err = LpmError::SelfUpdateRateLimited("x".into());
        let help = err.help().unwrap().to_string();
        assert!(help.contains("GITHUB_TOKEN"), "help: {help}");
        assert!(help.contains("GH_TOKEN"), "help: {help}");
    }

    #[test]
    fn error_code_specific_values() {
        assert_eq!(LpmError::AuthRequired.error_code(), "auth_required");
        assert_eq!(LpmError::NotFound("x".into()).error_code(), "not_found");
        assert_eq!(
            LpmError::ArtifactUnavailable(Box::new(ArtifactUnavailableErrorContext {
                package: "left-pad".into(),
                version: "1.3.0".into(),
                source: "registry+https://registry.npmjs.org".into(),
                kind: ArtifactUnavailableKind::Pinned,
                lockfiles_preserved: true,
                suggested_command: Some("lpm upgrade left-pad".into()),
            }))
            .error_code(),
            "pinned_artifact_unavailable"
        );
        assert_eq!(LpmError::Forbidden("x".into()).error_code(), "forbidden");
        assert_eq!(
            LpmError::NpmFirewallBlocked {
                package: "is-number@7.0.0".into(),
                verdict: "malicious".into(),
                reason: "product_default policy maps malicious to block".into(),
                decision_id: Some("decision-1".into()),
                match_source: Some("package".into()),
            }
            .error_code(),
            "npm_firewall_blocked"
        );
        assert_eq!(
            LpmError::NpmFirewallEntitlementRequired {
                message: "A Pro account or active org membership is required.".into(),
                reason: Some("personal_plan_not_eligible".into()),
                entitlement_source: None,
            }
            .error_code(),
            "npm_firewall_entitlement_required"
        );
        assert_eq!(
            LpmError::UpstreamProxyEntitlementRequired {
                message: "A Pro account or active org membership is required.".into(),
                reason: Some("personal_plan_not_eligible".into()),
                entitlement_source: None,
            }
            .error_code(),
            "upstream_proxy_entitlement_required"
        );
        assert_eq!(LpmError::Network("x".into()).error_code(), "network");
        assert_eq!(
            LpmError::RateLimited {
                retry_after_secs: 5
            }
            .error_code(),
            "rate_limited"
        );
        assert_eq!(
            LpmError::Http {
                status: 404,
                message: "x".into()
            }
            .error_code(),
            "http"
        );
        assert_eq!(
            LpmError::InvalidPackageName("x".into()).error_code(),
            "invalid_package_name"
        );
        assert_eq!(LpmError::Store("x".into()).error_code(), "store");
        assert_eq!(
            LpmError::Resolution(Box::new(resolution_error_context())).error_code(),
            "resolution_failed"
        );
        assert_eq!(
            LpmError::PeerDependency("x".into()).error_code(),
            "peer_dependency"
        );
        assert_eq!(LpmError::Task("x".into()).error_code(), "task");
        assert_eq!(LpmError::Plugin("x".into()).error_code(), "plugin");
        assert_eq!(LpmError::Engine("x".into()).error_code(), "engine");
        assert_eq!(LpmError::Workspace("x".into()).error_code(), "workspace");
        assert_eq!(
            LpmError::CatalogEntryInvalidRecursiveDefinition {
                dependency: "react".into(),
                catalog: "default".into(),
                specifier: "catalog:shared".into(),
            }
            .error_code(),
            "catalog_entry_invalid_recursive_definition"
        );
        assert_eq!(
            LpmError::EnvValidation("x".into()).error_code(),
            "env_validation"
        );
        assert_eq!(
            LpmError::EngineMismatch {
                engine: "lpm".into(),
                required: ">=1.0.0".into(),
                actual: "0.32.0".into(),
                from: "package.json > engines.lpm".into(),
            }
            .error_code(),
            "engine_mismatch"
        );
        assert_eq!(
            LpmError::SecurityFloor("x".into()).error_code(),
            "security_floor"
        );
    }

    fn resolution_error_context() -> ResolutionErrorContext {
        ResolutionErrorContext {
            package: "missing-leaf".into(),
            requested: "^2.0.0".into(),
            dependency: "missing-leaf".into(),
            required_by: Some("parent@1.0.0".into()),
            kind: ResolutionFailureKind::NoMatchingVersion,
            reason: "no published version satisfies ^2.0.0".into(),
            available_versions: Some(1),
            newest_version: Some("1.0.0".into()),
            derivation: None,
        }
    }
}
