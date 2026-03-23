//! HTTP client for the LPM package registry.
//!
//! This crate handles all communication between the Rust client and the LPM registry
//! at `registry.lpm.dev`, as well as the upstream npm registry for non-LPM packages.
//!
//! # Phase 0 (current)
//! - Basic HTTP client with auth header
//! - Fetch package metadata
//! - Health check
//!
//! # TODOs for Phase 1
//! - [ ] Complete response types for all endpoints (search, skills, quality, etc.)
//! - [ ] Retry logic with exponential backoff (408, 429, 5xx)
//! - [ ] `Retry-After` header parsing for rate limits
//! - [ ] Rate limit awareness (back off proactively)
//! - [ ] Request timeout configuration
//! - [ ] Tarball download with streaming (don't buffer entire tarball in memory)
//! - [ ] Connection pooling / keep-alive tuning
//!
//! # TODOs for Phase 4
//! - [ ] OIDC token exchange (GitHub Actions, GitLab CI)
//! - [ ] 2FA (OTP) header injection for publish
//! - [ ] Token refresh/rotation
//! - [ ] Publish endpoint (PUT with base64 tarball)
//! - [ ] All authenticated POST endpoints
//!
//! # TODOs for Phase 6
//! - [ ] Binary metadata cache (like Bun — cache registry responses in binary format)
//! - [ ] Batched metadata requests (fetch multiple packages in one round-trip)
//! - [ ] Delta updates (only fetch changed metadata since last request)
//! - [ ] `simd-json` for faster response parsing

pub mod client;
pub mod types;

pub use client::RegistryClient;
pub use types::PackageMetadata;
