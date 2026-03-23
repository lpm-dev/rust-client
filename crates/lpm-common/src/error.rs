use thiserror::Error;

/// Top-level error type for all LPM operations.
#[derive(Debug, Error)]
pub enum LpmError {
    #[error("invalid package name: {0}")]
    InvalidPackageName(String),

    #[error("invalid integrity hash: {0}")]
    InvalidIntegrity(String),

    #[error("integrity mismatch: expected {expected}, got {actual}")]
    IntegrityMismatch { expected: String, actual: String },

    #[error("invalid version: {0}")]
    InvalidVersion(String),

    #[error("invalid version range: {0}")]
    InvalidVersionRange(String),

    #[error("registry error: {0}")]
    Registry(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },

    #[error("authentication required")]
    AuthRequired,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("rate limited — retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
