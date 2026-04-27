//! HTTP client for the LPM package registry.
//!
//! Handles all communication between the Rust client and the LPM registry
//! at `lpm.dev`, as well as the upstream npm registry for non-LPM packages.

pub mod client;
pub mod npmrc;
pub mod route;
pub mod timing;
pub mod types;

pub use client::{
    DownloadedTarball, FanOutStats, GateDecision, MAX_COMPRESSED_TARBALL_SIZE, RegistryClient,
    evaluate_cached_url, is_https_url, is_localhost_url,
};
pub use npmrc::{NpmrcConfig, OriginKey, RegistryAuth, RegistryKind, RegistryTarget};
pub use route::{RouteMode, RouteTable, UpstreamRoute};
pub use types::*;
