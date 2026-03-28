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

    #[error("IO error: {0}")]
    #[diagnostic(code(lpm::io))]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    #[diagnostic(code(lpm::json))]
    Json(#[from] serde_json::Error),
}
