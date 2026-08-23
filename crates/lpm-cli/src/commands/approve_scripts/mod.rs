//! `lpm approve-scripts` — review and approve packages whose install scripts
//! were blocked by the post-existing default-deny security posture.
//!
//! This command pairs with the post-install warning emitted by `lpm install`
//! when packages with lifecycle scripts are not yet covered by an existing
//! strict approval. It reads the install-time blocked set from
//! `<project_dir>/.lpm/build-state.json` and lets the user
//! approve them via:
//!
//! - **Interactive TUI** (`lpm approve-scripts`) — walk the blocked set one
//!   at a time, with `Approve / Skip / View full script / Quit` per package
//! - **Bulk approve** (`--yes`) — approve everything blocked, with a loud
//!   warning banner; the escape hatch for CI / "I trust this manifest"
//! - **Direct approve** (`<pkg>`) — approve a single package by name
//! - **Read-only listing** (`--list`) — print the blocked set, NO mutations
//!
//! All approvals are bound to `{name, version, integrity, script_hash}`
//! per the trust binding contract (see [`lpm_workspace::TrustedDependencies`]).
//!
//! ## Output
//!
//! In `--json` mode the command emits a stable, versioned schema (see
//! [`SCHEMA_VERSION`]). The same schema is used for `--list --json` and
//! `--yes --json` so agents can drive the flow uniformly.

mod display;
mod gate;
mod global;
mod manifest;
mod metadata;
mod project;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use global::{GROUP_AUTO_THRESHOLD, run_global};
#[allow(unused_imports)]
pub use metadata::SCHEMA_VERSION;
#[allow(unused_imports)]
pub use project::{compute_effective_blocked_set, run};

mod prelude {
    #[allow(unused_imports)]
    pub(super) use super::display::{
        _build_state_path_for_tests, blocked_to_json, emit_yes_warning_banner, is_tty,
        print_full_script, print_listing, print_package_card, print_summary,
        print_version_diff_card_for_blocked, truncate_for_display,
    };
    #[allow(unused_imports)]
    pub(super) use super::gate::{
        GateScope, colored_tier_label, enforce_tiered_yes_gate, tier_label_text,
    };
    #[allow(unused_imports)]
    pub(super) use super::global::{
        AggregateLookup, AggregateRowKey, ApprovalProvenanceContext, GROUP_AUTO_THRESHOLD,
        global_blocked_set_incomplete_error, group_remaining_rows_by_origin,
        lookup_aggregate_by_arg, print_global_list, rerun_next_step_json, run_global_bulk_yes,
        run_global_named, union_origins,
    };
    #[cfg(test)]
    #[allow(unused_imports)]
    pub(super) use super::manifest::find_blocked_by_arg;
    #[allow(unused_imports)]
    pub(super) use super::manifest::{
        BlockedLookup, blocked_artifact_selector, ensure_manifest_unchanged,
        extract_trusted_dependencies, lookup_blocked_by_arg, write_back,
    };
    #[cfg(test)]
    pub(super) use super::metadata::snapshot_for_binding_with_mode;
    #[allow(unused_imports)]
    pub(super) use super::metadata::{
        SCHEMA_VERSION, approval_metadata_from_blocked,
        approval_metadata_preserving_existing_provenance, authorize_project_trust_write,
        commit_project_trust_write, fetch_provenance_for_effective_set,
        runtime_verify_policy_with_source, snapshot_for_artifact_binding,
    };
    #[allow(unused_imports)]
    pub(super) use super::project::{InteractiveChoice, compute_effective_blocked_set, run};
    #[allow(unused_imports)]
    pub(super) use crate::build_state::{self, BlockedPackage, BuildState};
    #[allow(unused_imports)]
    pub(super) use crate::{install_ui, output};
    #[allow(unused_imports)]
    pub(super) use lpm_common::LpmError;
    #[allow(unused_imports)]
    pub(super) use lpm_common::color::Painted;
    #[allow(unused_imports)]
    pub(super) use lpm_workspace::{
        ApprovalMetadata, ProvenanceSnapshot, ProvenanceStatus, TrustMatch, TrustedDependencies,
    };
    #[allow(unused_imports)]
    pub(super) use std::collections::HashMap;
    #[allow(unused_imports)]
    pub(super) use std::path::{Path, PathBuf};
}
