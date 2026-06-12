/// Errors during dependency resolution.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("registry error: {0}")]
    Registry(String),

    /// Carries auth/entitlement failures across the `LpmError` →
    /// `ProviderError` boundary so the optional-dep skip path can
    /// distinguish "auth needed" (user-visible warn) from
    /// "platform-incompatible" or "registry transient" (silent debug).
    #[error("auth required: {0}")]
    AuthRequired(String),

    #[error("invalid version range: {0}")]
    InvalidRange(String),
}

/// Classify a registry error as auth/entitlement vs everything else, preserving the message.
pub(super) fn classify_registry_error(e: lpm_common::LpmError) -> ProviderError {
    match e {
        lpm_common::LpmError::AuthRequired
        | lpm_common::LpmError::SessionExpired
        | lpm_common::LpmError::Forbidden(_) => ProviderError::AuthRequired(e.to_string()),
        other => ProviderError::Registry(other.to_string()),
    }
}
