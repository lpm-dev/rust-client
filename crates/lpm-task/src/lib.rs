//! Task graph, caching, and workspace-aware execution for LPM.
//!
//! Provides:
//! - `graph` — workspace dependency graph (DAG), topological sort
//! - `hasher` — cache key computation from source files, deps, env, command
//! - `cache` — local task cache (store outputs, restore on hit, stdout replay)
//! - `affected` — git-based change detection for `--affected`
//! - `filter` — Phase 32 shared filter engine for `--filter` (run, install,
//!   uninstall, deploy, MCP tools, CI helpers)
//! - `watch` — file watcher for `lpm dev`

pub mod affected;
pub mod cache;
pub mod filter;
pub mod graph;
pub mod hasher;
pub mod watch;
