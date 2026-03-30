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
        help("The downloaded package may be corrupted. Try again, or report this to the package owner.")
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
        help("Run `lpm-rs login` or set the LPM_TOKEN environment variable.")
    )]
    AuthRequired,

    #[error("forbidden: {0}")]
    #[diagnostic(
        code(lpm::forbidden),
        help("You may not have access to this resource. Check your permissions.")
    )]
    Forbidden(String),

    #[error("not found: {0}")]
    #[diagnostic(
        code(lpm::not_found),
        help("Check the package name and try `lpm-rs search` to find packages.")
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
        help("Run `lpm cert status` to check your certificate setup, or `lpm cert trust` to install the CA.")
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
        help("The global package store at ~/.lpm/store may be corrupted. Try `lpm-rs store gc` or remove it.")
    )]
    Store(String),

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
    #[diagnostic(
        code(lpm::task),
        help("Check your task configuration in lpm.json")
    )]
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
            LpmError::Forbidden(_) => "forbidden",
            LpmError::NotFound(_) => "not_found",
            LpmError::RateLimited { .. } => "rate_limited",
            LpmError::Script(_) => "script",
            LpmError::Cert(_) => "cert",
            LpmError::Tunnel(_) => "tunnel",
            LpmError::Store(_) => "store",
            LpmError::ExitCode(_) => "exit_code",
            LpmError::Io(_) => "io",
            LpmError::Json(_) => "json",
            LpmError::Task(_) => "task",
            LpmError::Plugin(_) => "plugin",
            LpmError::Workspace(_) => "workspace",
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
        assert_eq!(help.to_string(), "Check your task configuration in lpm.json");
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
        assert_eq!(help.to_string(), "Run `lpm plugin list` to see installed plugins");
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
            LpmError::IntegrityMismatch { expected: "a".into(), actual: "b".into() },
            LpmError::InvalidVersion("x".into()),
            LpmError::InvalidVersionRange("x".into()),
            LpmError::Registry("x".into()),
            LpmError::Network("x".into()),
            LpmError::Http { status: 500, message: "x".into() },
            LpmError::AuthRequired,
            LpmError::Forbidden("x".into()),
            LpmError::NotFound("x".into()),
            LpmError::RateLimited { retry_after_secs: 5 },
            LpmError::Script("x".into()),
            LpmError::Cert("x".into()),
            LpmError::Tunnel("x".into()),
            LpmError::Store("x".into()),
            LpmError::ExitCode(1),
            LpmError::Io(std::io::Error::new(std::io::ErrorKind::Other, "x")),
            LpmError::Json(serde_json::from_str::<serde_json::Value>("bad").unwrap_err()),
            LpmError::Task("x".into()),
            LpmError::Plugin("x".into()),
            LpmError::Workspace("x".into()),
        ];

        for variant in &variants {
            let code = variant.error_code();
            assert!(!code.is_empty(), "error_code() returned empty for: {variant}");
        }
    }

    #[test]
    fn error_code_specific_values() {
        assert_eq!(LpmError::AuthRequired.error_code(), "auth_required");
        assert_eq!(LpmError::NotFound("x".into()).error_code(), "not_found");
        assert_eq!(LpmError::Forbidden("x".into()).error_code(), "forbidden");
        assert_eq!(LpmError::Network("x".into()).error_code(), "network");
        assert_eq!(LpmError::RateLimited { retry_after_secs: 5 }.error_code(), "rate_limited");
        assert_eq!(LpmError::Http { status: 404, message: "x".into() }.error_code(), "http");
        assert_eq!(LpmError::InvalidPackageName("x".into()).error_code(), "invalid_package_name");
        assert_eq!(LpmError::Store("x".into()).error_code(), "store");
        assert_eq!(LpmError::Task("x".into()).error_code(), "task");
        assert_eq!(LpmError::Plugin("x".into()).error_code(), "plugin");
        assert_eq!(LpmError::Workspace("x".into()).error_code(), "workspace");
    }
}
