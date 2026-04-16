//! Authentication and secure token storage — Phase 35 re-export shim.
//!
//! All token storage, refresh handling, and session metadata moved to
//! the shared `lpm-auth` crate during Phase 35 Step 1 so that
//! `lpm-registry` can depend on the same primitives without a layering
//! violation. This module is now a stable, narrow re-export surface for
//! the rest of `lpm-cli`. Behavior is unchanged.
//!
//! New code should `use lpm_auth::*;` directly. The re-exports here
//! exist so existing `crate::auth::*` call sites keep working without
//! a rename pass.

pub use lpm_auth::{
    check_token_expiry_warnings, clear_all_custom_registries, clear_custom_registry_token,
    clear_github_token, clear_gitlab_token, clear_login_state, clear_npm_token, clear_token,
    clear_token_expiry, get_custom_registry_token, get_github_token, get_gitlab_token,
    get_npm_token, get_token, has_refresh_token, is_otp_required, list_stored_registries,
    set_custom_registry_token, set_github_token, set_gitlab_token, set_npm_token, set_otp_required,
    set_refresh_token, set_session_access_token_expiry, set_token, set_token_expiry,
};
