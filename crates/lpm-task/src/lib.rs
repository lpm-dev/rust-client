//! Task graph, caching, and workspace-aware execution for LPM.
//!
//! Provides:
//! - `graph` — workspace dependency graph (DAG), topological sort
//! - `hasher` — cache key computation from source files, deps, env, command
//! - `cache` — local task cache (store outputs, restore on hit, stdout replay)
//! - `affected` — git-based change detection for `--affected`

pub mod affected;
pub mod cache;
pub mod graph;
pub mod hasher;
pub mod watch;
