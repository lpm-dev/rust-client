//! HTTP client for the LPM package registry.
//!
//! Handles all communication between the Rust client and the LPM registry
//! at `lpm.dev`, as well as the upstream npm registry for non-LPM packages.

pub mod client;
pub mod timing;
pub mod types;

pub use client::{
    DownloadedTarball, GateDecision, MAX_COMPRESSED_TARBALL_SIZE, RegistryClient,
    evaluate_cached_url, is_https_url, is_localhost_url,
};
pub use types::*;
