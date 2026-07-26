//! Authentication and secure token storage — re-export shim.
//!
//! All token storage, refresh handling, and session metadata moved to
//! the shared `lpm-auth` crate during Step 1 so that
//! `lpm-registry` can depend on the same primitives without a layering
//! violation. This module is now a stable, narrow re-export surface for
//! the rest of `lpm-cli`. Behavior is unchanged.
//!
//! New code should `use lpm_auth::*;` directly. The re-exports here
//! exist so existing `crate::auth::*` call sites keep working without
//! a rename pass.

pub use lpm_auth::{
    AuthStorageBackend, AuthStorageStatus, TokenSource, auth_storage_status,
    check_token_expiry_warnings, clear_all_custom_registries, clear_custom_registry_token,
    clear_github_token, clear_gitlab_token, clear_login_state, clear_npm_token, clear_token,
    clear_token_expiry, get_custom_registry_token, get_github_cli_token, get_github_token,
    get_gitlab_cli_token, get_gitlab_token_for_host, get_token, has_refresh_token,
    has_stored_access_token, is_otp_required, list_registry_auth_statuses,
    set_custom_registry_token_with_backend, set_github_token_with_backend,
    set_gitlab_token_with_backend, set_npm_token_with_backend, set_otp_required,
    set_refresh_token_with_backend, set_session_access_token_expiry, set_token_expiry,
    set_token_with_backend, try_get_npm_token,
};

#[cfg(test)]
pub use lpm_auth::set_refresh_token;
