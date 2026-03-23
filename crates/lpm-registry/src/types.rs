//! Response types for the LPM registry API.
//!
//! These are strongly typed structs matching the JSON responses from the registry.
//! Using concrete types rather than `serde_json::Value` catches schema mismatches
//! at compile time and makes the rest of the codebase safer.
//!
//! # TODOs for Phase 1
//! - [ ] SearchResponse (GET /api/search/packages)
//! - [ ] OwnerSearchResponse (GET /api/search/owners)
//! - [ ] WhoamiResponse (GET /api/registry/-/whoami)
//! - [ ] QualityResponse (GET /api/registry/quality)
//! - [ ] SkillsResponse (GET /api/registry/skills)
//! - [ ] ApiDocsResponse (GET /api/registry/api-docs)
//! - [ ] LlmContextResponse (GET /api/registry/llm-context)
//! - [ ] CheckNameResponse (GET /api/registry/check-name)
//! - [ ] PoolStatsResponse (GET /api/registry/pool/stats)
//! - [ ] MarketplaceEarningsResponse (GET /api/registry/marketplace/earnings)
//! - [ ] HealthResponse (GET /api/registry/health)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full package metadata returned by GET /api/registry/@lpm.dev/owner.pkg
///
/// This is npm-compatible format with LPM extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Full scoped name: `@lpm.dev/owner.package-name`
    pub name: String,

    /// Package description.
    #[serde(default)]
    pub description: Option<String>,

    /// Dist-tags mapping. At minimum contains "latest".
    #[serde(default, rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,

    /// All published versions keyed by version string.
    #[serde(default)]
    pub versions: HashMap<String, VersionMetadata>,

    /// Timestamps for each version + created/modified.
    #[serde(default)]
    pub time: HashMap<String, String>,

    /// Total download count.
    #[serde(default)]
    pub downloads: Option<u64>,

    /// Distribution mode: "pool", "marketplace", or "private".
    #[serde(default, rename = "distributionMode")]
    pub distribution_mode: Option<String>,

    /// Package type: "package", "xcframework", etc.
    #[serde(default, rename = "packageType")]
    pub package_type: Option<String>,

    /// Latest version string (LPM extension).
    #[serde(default, rename = "latestVersion")]
    pub latest_version: Option<String>,
}

/// Metadata for a specific package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    /// Full scoped name.
    pub name: String,

    /// Semver version string.
    pub version: String,

    /// Description.
    #[serde(default)]
    pub description: Option<String>,

    /// Production dependencies.
    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    /// Development dependencies.
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,

    /// Peer dependencies.
    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    /// Optional dependencies.
    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// Distribution info (tarball URL, integrity hash).
    #[serde(default)]
    pub dist: Option<DistInfo>,

    /// README content.
    #[serde(default)]
    pub readme: Option<String>,

    /// LPM source package configuration.
    #[serde(default, rename = "lpmConfig")]
    pub lpm_config: Option<serde_json::Value>,

    /// Ecosystem: "js", "swift", "rust", "python".
    #[serde(default, rename = "_ecosystem")]
    pub ecosystem: Option<String>,
}

/// Distribution info for a specific version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistInfo {
    /// URL to download the tarball.
    #[serde(default)]
    pub tarball: Option<String>,

    /// SRI integrity hash (sha512-...).
    #[serde(default)]
    pub integrity: Option<String>,

    /// SHA1 hash (legacy, for npm compatibility).
    #[serde(default)]
    pub shasum: Option<String>,
}

/// Access info returned alongside package metadata (LPM extension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessInfo {
    /// Distribution model: "pool", "marketplace", "private".
    pub model: String,

    /// Human-readable summary.
    pub summary: String,

    /// Whether user action is required to access this package.
    #[serde(default, rename = "actionRequired")]
    pub action_required: bool,
}

impl PackageMetadata {
    /// Get the latest version string from dist-tags.
    pub fn latest_version_tag(&self) -> Option<&str> {
        self.dist_tags
            .get("latest")
            .map(|s| s.as_str())
            .or(self.latest_version.as_deref())
    }

    /// Get metadata for a specific version.
    pub fn version(&self, version: &str) -> Option<&VersionMetadata> {
        self.versions.get(version)
    }

    /// Get metadata for the latest version.
    pub fn latest(&self) -> Option<&VersionMetadata> {
        self.latest_version_tag()
            .and_then(|v| self.versions.get(v))
    }

    /// List all published version strings.
    pub fn version_list(&self) -> Vec<&str> {
        self.versions.keys().map(|s| s.as_str()).collect()
    }
}

impl VersionMetadata {
    /// Get the tarball URL, if available.
    pub fn tarball_url(&self) -> Option<&str> {
        self.dist.as_ref()?.tarball.as_deref()
    }

    /// Get the SRI integrity hash, if available.
    pub fn integrity(&self) -> Option<&str> {
        self.dist.as_ref()?.integrity.as_deref()
    }
}
