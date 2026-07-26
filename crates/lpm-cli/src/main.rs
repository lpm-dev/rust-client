use miette::Result;

mod added_sources_state;
mod auth;
mod auth_storage_notice;
pub mod build_state;
pub mod capability;
mod cli;
mod color_policy;
mod commands;
pub mod constraints;
pub mod doctor_catalog;
pub mod editor_skills;
pub mod engine_check;
pub mod engine_strict_config;
mod global_blocked_set;
mod graph_render;
mod import_rewriter;
pub mod install_state;
pub mod install_ui;
pub mod intelligence;
mod json_contract;
mod linker_config;
mod lpm_config;
mod lpm_skills_config;
mod manifest_tx;
pub mod migration_warnings;
mod npm_firewall_config;
mod npm_public_source;
mod oidc;
mod output;
pub mod overrides_state;
pub mod patch_engine;
pub mod patch_state;
pub mod path_onboarding;
pub mod precedence;
mod prompt;
mod provenance;
mod provenance_bundle;
mod provenance_fetch;
mod quality;
mod registry_signatures;
mod release_age_config;
mod release_age_selection;
mod release_lookup;
mod release_plan;
mod resolver_error;
mod sandbox_config;
mod save_config;
mod save_spec;
mod script_policy_config;
mod security_approval;
pub mod security_check;
mod security_floor;
mod sigstore;
mod sigstore_verify;
mod step_up;
mod swift_manifest;
mod terminal_output;
#[cfg(test)]
mod test_env;
mod tool_pin_validation;
pub mod triage_advisor_session;
mod trust_snapshot;
mod tsc_status;
mod typosquat_guard;
mod update_check;
pub mod upgrade_engine;
pub mod version_diff;
mod workspace_concurrency_config;
mod workspace_filter_config;
pub mod workspace_select;
mod xcode_project;

#[cfg(test)]
pub(crate) use cli::Commands;
pub(crate) use cli::{BundleFormat, BundlePlatform, CheckEngine, Cli};

// dhat heap profiling overrides mimalloc so allocation counts reflect the raw
// Rust alloc surface (not mimalloc's internal pools). Build:
//   cargo build -p lpm-cli --features dhat-heap
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// mimalloc replaces the system allocator on Unix non-profiling builds.
// Typically 5-15% faster on alloc-heavy workloads (resolver BFS, lockfile
// parse, linker path construction) vs the macOS/Linux system malloc.
// Disable for comparison builds: cargo build --release --features no-mimalloc
// Windows uses the system allocator (mimalloc is in cfg(unix) deps).
#[cfg(all(unix, not(feature = "dhat-heap"), not(feature = "no-mimalloc")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    // dhat profiler must be the first live value because it instruments the
    // allocator for the whole process and flushes when dropped.
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();

    cli::run()
}
