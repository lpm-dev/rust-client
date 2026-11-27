// Apple's ld notes that a debug lpm-rs's __eh_frame exceeds the 16 MB its
// compact unwind table can address, which only slows unwinding a panic. Rust
// reports linker output as a warning since 1.97; release builds stay under the
// limit and keep every linker message.
#![cfg_attr(all(target_os = "macos", debug_assertions), allow(linker_messages))]

use miette::Result;

mod added_sources_state;
mod auth;
mod auth_storage_notice;
pub mod build_state;
mod build_version;
pub mod capability;
mod cli;
mod color_policy;
mod commands;
mod dependency_skills;
mod directory_transaction;
pub mod doctor_catalog;
pub mod editor_skills;
mod elevation;
pub mod engine_check;
pub mod engine_strict_config;
mod firewall_bypass;
mod global_blocked_set;
mod graph_render;
mod import_rewriter;
mod install_recovery;
pub mod install_state;
pub mod install_ui;
pub mod intelligence;
mod json_contract;
mod linker_config;
mod live_region;
mod lpm_config;
mod lpm_insights_config;
mod lpm_skills_config;
mod manifest_dependency;
mod manifest_tx;
pub mod migration_warnings;
mod npm_firewall_config;
mod npm_public_source;
mod oidc;
mod open_file_limit;
mod output;
pub mod overrides_state;
pub mod patch_engine;
mod patch_fs;
pub mod patch_state;
pub mod path_onboarding;
pub mod precedence;
mod privilege;
mod project_fs;
mod prompt;
mod provenance;
mod provenance_bundle;
mod provenance_fetch;
mod registry_signatures;
mod relay_trust;
mod release_age_config;
mod release_age_selection;
mod release_channel;
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
mod source_analysis_config;
mod step_up;
mod swift_manifest;
mod terminal_output;
#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_tracing;
mod tool_pin_validation;
pub mod triage_advisor_session;
mod trust_snapshot;
mod tsc_status;
mod tunnel_session_auth;
mod typosquat_guard;
mod update_check;
pub mod upgrade_engine;
pub mod version_diff;
mod workspace_concurrency_config;
mod workspace_discovery_cache;
mod workspace_filter_config;
pub mod workspace_select;
mod xcode_project;

#[cfg(test)]
pub(crate) use cli::Commands;
pub(crate) use cli::{BundleFormat, BundlePlatform, CheckEngine, Cli};

// dhat heap profiling replaces the global allocator so allocation counts
// reflect the raw Rust alloc surface (not an allocator's internal pools). Build:
//   cargo build -p lpm-cli --features dhat-heap
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// mimalloc replaces the system allocator in non-profiling builds for Unix
// targets other than macOS and Linux GNU (comparison builds:
// `--features no-mimalloc`). macOS, Windows, and Linux GNU keep their system
// allocators: on both macOS and Linux glibc (with `M_ARENA_MAX=8`), installs
// peak 40-56% lower in RSS under the system allocator without regressing
// throughput, whereas mimalloc retains freed memory committed in its per-thread
// arenas. Linux musl keeps mimalloc (with `purge_delay=0`) because musl's
// mallocng contends heavily across Tokio/rayon worker threads.
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(target_os = "linux", target_env = "gnu")),
    not(feature = "dhat-heap"),
    not(feature = "no-mimalloc")
))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Bound glibc's per-thread arena proliferation before worker threads start.
/// glibc defaults to `8 * nproc` arenas, which inflates peak RSS across
/// short-lived Tokio and rayon threads; capping at 8 arenas cuts Linux GNU
/// peak RSS by ~55% while avoiding warm-lock arena contention across parallel
/// workspace lanes, and still honors an explicit `MALLOC_ARENA_MAX` set by the
/// caller.
#[cfg(all(target_os = "linux", target_env = "gnu", not(feature = "dhat-heap")))]
fn configure_process_allocator() {
    if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
        // SAFETY: `mallopt` is thread-safe before worker threads spawn and
        // ignores unsupported options safely.
        unsafe {
            libc::mallopt(libc::M_ARENA_MAX, 8);
        }
    }
}

/// Immediately return freed mimalloc pages on musl/other Unix targets unless
/// the caller explicitly overrides `MIMALLOC_PURGE_DELAY`.
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(target_os = "linux", target_env = "gnu")),
    not(feature = "dhat-heap"),
    not(feature = "no-mimalloc")
))]
fn configure_process_allocator() {
    if std::env::var_os("MIMALLOC_PURGE_DELAY").is_none() {
        // `mi_option_purge_delay` in mimalloc v2 (`libmimalloc-sys` 0.1.x).
        const MI_OPTION_PURGE_DELAY: libc::c_int = 15;
        unsafe extern "C" {
            fn mi_option_set_default(option: libc::c_int, value: libc::c_long);
        }
        // SAFETY: `mi_option_set_default` updates mimalloc's default option
        // before any worker threads spawn.
        unsafe {
            mi_option_set_default(MI_OPTION_PURGE_DELAY, 0);
        }
    }
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu", not(feature = "dhat-heap")),
    all(
        unix,
        not(target_os = "macos"),
        not(all(target_os = "linux", target_env = "gnu")),
        not(feature = "dhat-heap"),
        not(feature = "no-mimalloc")
    )
)))]
fn configure_process_allocator() {}

fn main() -> Result<()> {
    configure_process_allocator();

    // dhat profiler must be the first live value because it instruments the
    // allocator for the whole process and flushes when dropped.
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();

    cli::run()
}

#[cfg(all(
    test,
    target_os = "linux",
    target_env = "gnu",
    not(feature = "dhat-heap")
))]
mod linux_gnu_allocator_tests {
    unsafe extern "C" {
        fn malloc_usable_size(ptr: *mut std::ffi::c_void) -> libc::size_t;
    }

    #[test]
    fn linux_gnu_heap_allocations_use_glibc_and_accept_arena_cap() {
        let mut allocation = Box::new([0_u8; 256]);
        // SAFETY: `allocation` was allocated by the global allocator; under
        // glibc `malloc_usable_size` returns at least the requested size.
        let usable = unsafe { malloc_usable_size(allocation.as_mut_ptr().cast()) };
        assert!(
            usable >= 256,
            "linux-gnu allocations must come from glibc malloc"
        );
        // SAFETY: `mallopt(M_ARENA_MAX, 8)` returns 1 on glibc.
        let status = unsafe { libc::mallopt(libc::M_ARENA_MAX, 8) };
        assert_eq!(status, 1);
    }
}

#[cfg(all(test, target_os = "macos", not(feature = "dhat-heap")))]
mod global_allocator_tests {
    unsafe extern "C" {
        fn malloc_zone_from_ptr(ptr: *const std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    #[test]
    fn macos_heap_allocations_come_from_a_malloc_zone_rather_than_mimalloc() {
        let allocation = Box::new([0_u8; 256]);
        // SAFETY: `malloc_zone_from_ptr` only looks the pointer up in the
        // registered malloc zones and returns null when none owns it.
        let zone = unsafe { malloc_zone_from_ptr(allocation.as_ptr().cast()) };
        assert!(
            !zone.is_null(),
            "heap allocations must come from a malloc zone"
        );
    }
}
