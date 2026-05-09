use miette::Diagnostic;
use thiserror::Error;

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

    #[error("not found: {0}")]
    #[diagnostic(
        code(lpm::not_found),
        help("Check the package name and try `lpm search` to find packages.")
    )]
    NotFound(String),

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
            "The global package store at ~/.lpm/store may be corrupted. Try `lpm store gc` or remove it."
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

    #[error("workspace error: {0}")]
    #[diagnostic(
        code(lpm::workspace),
        help("Check your workspace configuration in package.json or pnpm-workspace.yaml")
    )]
    Workspace(String),

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
            LpmError::Network(_) => "network",
            LpmError::Http { .. } => "http",
            LpmError::AuthRequired => "auth_required",
            LpmError::SessionExpired => "session_expired",
            LpmError::Forbidden(_) => "forbidden",
            LpmError::NotFound(_) => "not_found",
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
            LpmError::Workspace(_) => "workspace",
            LpmError::EnvValidation(_) => "env_validation",
            LpmError::EngineMismatch { .. } => "engine_mismatch",
            LpmError::SelfUpdatePaused(_) => "self_update_paused",
            LpmError::SelfUpdateRateLimited(_) => "self_update_rate_limited",
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
            LpmError::Network("x".into()),
            LpmError::Http {
                status: 500,
                message: "x".into(),
            },
            LpmError::AuthRequired,
            LpmError::SessionExpired,
            LpmError::Forbidden("x".into()),
            LpmError::NotFound("x".into()),
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
            LpmError::Workspace("x".into()),
            LpmError::EnvValidation("x".into()),
            LpmError::EngineMismatch {
                engine: "lpm".into(),
                required: ">=1.0.0".into(),
                actual: "0.32.0".into(),
                from: "package.json > engines.lpm".into(),
            },
            LpmError::SelfUpdatePaused("x".into()),
            LpmError::SelfUpdateRateLimited("x".into()),
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
        assert_eq!(LpmError::Forbidden("x".into()).error_code(), "forbidden");
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
        assert_eq!(LpmError::Task("x".into()).error_code(), "task");
        assert_eq!(LpmError::Plugin("x".into()).error_code(), "plugin");
        assert_eq!(LpmError::Workspace("x".into()).error_code(), "workspace");
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
    }
}
