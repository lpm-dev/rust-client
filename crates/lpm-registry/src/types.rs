//! Response types for the LPM registry API.
//!
//! Strongly typed structs matching the JSON responses from every endpoint.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Package Metadata ──────────────────────────────────────────────

/// Full package metadata returned by GET /api/registry/@lpm.dev/owner.pkg
///
/// npm-compatible format with LPM extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default, rename = "dist-tags")]
    pub dist_tags: HashMap<String, String>,

    #[serde(default)]
    pub versions: HashMap<String, VersionMetadata>,

    #[serde(default)]
    pub time: HashMap<String, String>,

    #[serde(default)]
    pub downloads: Option<u64>,

    #[serde(default, rename = "distributionMode")]
    pub distribution_mode: Option<String>,

    #[serde(default, rename = "packageType")]
    pub package_type: Option<String>,

    #[serde(default, rename = "latestVersion")]
    pub latest_version: Option<String>,

    #[serde(default)]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub name: String,
    pub version: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub dependencies: HashMap<String, String>,

    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: HashMap<String, String>,

    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: HashMap<String, String>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// Platform restrictions: ["darwin", "linux", "win32"]
    #[serde(default)]
    pub os: Vec<String>,

    /// CPU restrictions: ["x64", "arm64"]
    #[serde(default)]
    pub cpu: Vec<String>,

    #[serde(default)]
    pub dist: Option<DistInfo>,

    #[serde(default)]
    pub readme: Option<String>,

    #[serde(default, rename = "lpmConfig")]
    pub lpm_config: Option<serde_json::Value>,

    #[serde(default, rename = "_ecosystem")]
    pub ecosystem: Option<String>,

    #[serde(default, rename = "_swiftMeta")]
    pub swift_meta: Option<SwiftMeta>,

    // Security metadata for post-install warnings
    #[serde(default, rename = "_behavioralTags")]
    pub behavioral_tags: Option<BehavioralTags>,

    #[serde(default, rename = "_lifecycleScripts")]
    pub lifecycle_scripts: Option<HashMap<String, String>>,

    #[serde(default, rename = "_securityFindings")]
    pub security_findings: Option<Vec<SecurityFinding>>,

    #[serde(default, rename = "_qualityScore")]
    pub quality_score: Option<u32>,

    #[serde(default, rename = "_vulnerabilities")]
    pub vulnerabilities: Option<Vec<Vulnerability>>,
}

/// Known vulnerability from OSV database (stored server-side on publish).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
}

/// Static behavioral analysis tags — what the package code does.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralTags {
    #[serde(default)]
    pub eval: bool,
    #[serde(default, rename = "childProcess")]
    pub child_process: bool,
    #[serde(default)]
    pub shell: bool,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub filesystem: bool,
    #[serde(default)]
    pub crypto: bool,
    #[serde(default, rename = "dynamicRequire")]
    pub dynamic_require: bool,
    #[serde(default, rename = "nativeBindings")]
    pub native_bindings: bool,
    #[serde(default, rename = "environmentVars")]
    pub environment_vars: bool,
    #[serde(default, rename = "webSocket")]
    pub web_socket: bool,
}

/// AI-detected security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
}

/// Swift package metadata (products, platforms) from SE-0292 manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftMeta {
    #[serde(default)]
    pub products: Vec<SwiftProduct>,

    #[serde(default)]
    pub platforms: Vec<SwiftPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftProduct {
    pub name: String,

    #[serde(default, rename = "type")]
    pub product_type: Option<serde_json::Value>,

    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftPlatform {
    #[serde(default, rename = "platformName")]
    pub platform_name: Option<String>,

    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistInfo {
    #[serde(default)]
    pub tarball: Option<String>,

    #[serde(default)]
    pub integrity: Option<String>,

    #[serde(default)]
    pub shasum: Option<String>,
}

impl PackageMetadata {
    pub fn latest_version_tag(&self) -> Option<&str> {
        self.dist_tags
            .get("latest")
            .map(|s| s.as_str())
            .or(self.latest_version.as_deref())
    }

    pub fn version(&self, version: &str) -> Option<&VersionMetadata> {
        self.versions.get(version)
    }

    pub fn latest(&self) -> Option<&VersionMetadata> {
        self.latest_version_tag().and_then(|v| self.versions.get(v))
    }

    pub fn version_list(&self) -> Vec<&str> {
        self.versions.keys().map(|s| s.as_str()).collect()
    }

    /// Returns true if this is a Swift ecosystem package.
    pub fn is_swift(&self) -> bool {
        self.ecosystem.as_deref() == Some("swift")
    }
}

impl VersionMetadata {
    pub fn tarball_url(&self) -> Option<&str> {
        self.dist.as_ref()?.tarball.as_deref()
    }

    pub fn integrity(&self) -> Option<&str> {
        self.dist.as_ref()?.integrity.as_deref()
    }

    /// Returns the first library product name from Swift metadata.
    pub fn swift_product_name(&self) -> Option<&str> {
        let meta = self.swift_meta.as_ref()?;
        meta.products
            .iter()
            .find(|p| {
                // Skip executables — prefer library products
                p.product_type
                    .as_ref()
                    .and_then(|t| t.as_str())
                    .map(|s| s != "executable")
                    .unwrap_or(true)
            })
            .map(|p| p.name.as_str())
    }

    /// Returns true if this version has any security concerns.
    pub fn has_security_issues(&self) -> bool {
        let has_findings = self
            .security_findings
            .as_ref()
            .map(|f| !f.is_empty())
            .unwrap_or(false);
        let has_dangerous_tags = self
            .behavioral_tags
            .as_ref()
            .map(|t| t.eval || t.child_process || t.shell || t.dynamic_require)
            .unwrap_or(false);
        let has_lifecycle = self
            .lifecycle_scripts
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let has_vulns = self
            .vulnerabilities
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        has_findings || has_dangerous_tags || has_lifecycle || has_vulns
    }

    /// Returns the ecosystem, checking both _ecosystem and lpmConfig.ecosystem.
    pub fn effective_ecosystem(&self) -> &str {
        if let Some(eco) = &self.ecosystem {
            return eco.as_str();
        }
        if let Some(config) = &self.lpm_config
            && let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str())
        {
            return eco;
        }
        "js"
    }
}

// ─── Search ────────────────────────────────────────────────────────

/// GET /api/search/packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub packages: Vec<SearchPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPackage {
    #[serde(default)]
    pub id: Option<String>,

    pub name: String,

    #[serde(default)]
    pub owner: Option<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default, rename = "distributionMode")]
    pub distribution_mode: Option<String>,

    #[serde(default, rename = "downloadCount")]
    pub download_count: Option<u64>,

    #[serde(default, rename = "latestVersion")]
    pub latest_version: Option<String>,

    #[serde(default)]
    pub category: Option<String>,

    #[serde(default, rename = "avatarUrl")]
    pub avatar_url: Option<String>,

    #[serde(default, rename = "isOrg")]
    pub is_org: Option<bool>,

    #[serde(default)]
    pub archived: Option<bool>,
}

/// GET /api/search/owners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerSearchResponse {
    pub owners: Vec<SearchOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOwner {
    #[serde(default)]
    pub id: Option<String>,

    pub username: String,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default, rename = "avatarUrl")]
    pub avatar_url: Option<String>,

    #[serde(default, rename = "type")]
    pub owner_type: Option<String>,
}

/// GET /api/registry/check-name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckNameResponse {
    pub name: String,
    pub available: bool,

    #[serde(default, rename = "ownerExists")]
    pub owner_exists: Option<bool>,

    #[serde(default, rename = "ownerType")]
    pub owner_type: Option<String>,
}

// ─── Auth ──────────────────────────────────────────────────────────

/// GET /api/registry/-/whoami
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    #[serde(default)]
    pub username: Option<String>,

    #[serde(default, rename = "profile_username")]
    pub profile_username: Option<String>,

    #[serde(default)]
    pub email: Option<String>,

    #[serde(default, rename = "mfa_enabled")]
    pub mfa_enabled: Option<bool>,

    #[serde(default)]
    pub organizations: Vec<WhoamiOrg>,

    #[serde(default, rename = "available_scopes")]
    pub available_scopes: Vec<String>,

    #[serde(default, rename = "plan_tier")]
    pub plan_tier: Option<String>,

    #[serde(default, rename = "has_pool_access")]
    pub has_pool_access: Option<bool>,

    #[serde(default)]
    pub usage: Option<WhoamiUsage>,

    #[serde(default)]
    pub limits: Option<WhoamiLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiUsage {
    #[serde(default, rename = "storage_bytes")]
    pub storage_bytes: u64,

    #[serde(default, rename = "private_packages")]
    pub private_packages: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiLimits {
    #[serde(default, rename = "storageBytes")]
    pub storage_bytes: Option<u64>,

    #[serde(default, rename = "privatePackages")]
    pub private_packages: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiOrg {
    pub slug: String,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub role: Option<String>,

    #[serde(default, rename = "require_2fa")]
    pub require_2fa: Option<bool>,
}

/// GET /api/registry/cli/check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCheckResponse {
    pub valid: bool,

    #[serde(default)]
    pub scopes: Vec<String>,

    #[serde(default)]
    pub user: Option<String>,

    #[serde(default)]
    pub error: Option<String>,
}

// ─── Intelligence ──────────────────────────────────────────────────

/// GET /api/registry/quality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityResponse {
    pub name: String,

    #[serde(default)]
    pub score: Option<u32>,

    #[serde(default, rename = "maxScore")]
    pub max_score: Option<u32>,

    #[serde(default)]
    pub tier: Option<String>,

    #[serde(default)]
    pub ecosystem: Option<String>,

    #[serde(default)]
    pub checks: Vec<QualityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCheck {
    pub id: String,

    #[serde(default)]
    pub category: Option<String>,

    #[serde(default)]
    pub label: Option<String>,

    #[serde(default)]
    pub passed: Option<bool>,

    #[serde(default)]
    pub points: Option<u32>,

    #[serde(default, rename = "maxPoints")]
    pub max_points: Option<u32>,

    #[serde(default)]
    pub detail: Option<String>,
}

/// GET /api/registry/skills
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillsResponse {
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub available: Option<bool>,

    #[serde(default, rename = "skillsCount")]
    pub skills_count: Option<u32>,

    #[serde(default, rename = "skillsStatus")]
    pub skills_status: Option<String>,

    #[serde(default)]
    pub skills: Vec<Skill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub globs: Vec<String>,

    #[serde(default)]
    pub content: Option<String>,

    #[serde(default, rename = "rawContent")]
    pub raw_content: Option<String>,

    #[serde(default, rename = "sizeBytes")]
    pub size_bytes: Option<u64>,
}

/// GET /api/registry/api-docs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiDocsResponse {
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub available: Option<bool>,

    #[serde(default, rename = "docsStatus")]
    pub docs_status: Option<String>,

    #[serde(default, rename = "apiDocs")]
    pub api_docs: Option<serde_json::Value>,
}

/// GET /api/registry/llm-context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmContextResponse {
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub available: Option<bool>,

    #[serde(default, rename = "llmContextStatus")]
    pub llm_context_status: Option<String>,

    #[serde(default, rename = "llmContext")]
    pub llm_context: Option<serde_json::Value>,
}

// ─── Revenue ───────────────────────────────────────────────────────

/// GET /api/registry/pool/stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStatsResponse {
    #[serde(default, rename = "billingPeriod")]
    pub billing_period: Option<String>,

    #[serde(default, rename = "totalWeightedDownloads")]
    pub total_weighted_downloads: Option<u64>,

    #[serde(default, rename = "estimatedEarningsCents")]
    pub estimated_earnings_cents: Option<u64>,

    #[serde(default)]
    pub packages: Vec<PoolPackageStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolPackageStat {
    pub name: String,

    #[serde(default)]
    pub owner: Option<String>,

    #[serde(default, rename = "packageName")]
    pub package_name: Option<String>,

    #[serde(default, rename = "installCount")]
    pub install_count: Option<u64>,

    #[serde(default, rename = "weightedDownloads")]
    pub weighted_downloads: Option<u64>,

    #[serde(default, rename = "sharePercentage")]
    pub share_percentage: Option<f64>,

    #[serde(default, rename = "estimatedEarningsCents")]
    pub estimated_earnings_cents: Option<u64>,
}

/// GET /api/registry/marketplace/earnings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceEarningsResponse {
    #[serde(default, rename = "totalSales")]
    pub total_sales: Option<u64>,

    #[serde(default, rename = "grossRevenueCents")]
    pub gross_revenue_cents: Option<u64>,

    #[serde(default, rename = "platformFeesCents")]
    pub platform_fees_cents: Option<u64>,

    #[serde(default, rename = "netRevenueCents")]
    pub net_revenue_cents: Option<u64>,
}
