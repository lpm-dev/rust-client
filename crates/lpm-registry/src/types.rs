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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
///
/// 22 tags in three groups matching the client-side `lpm-security` analyzer
/// and the server-side `behavioral-tags.js`:
///
/// - Source (10): eval, childProcess, shell, network, filesystem, crypto,
///   dynamicRequire, nativeBindings, environmentVars, webSocket
/// - Supply chain (7): obfuscated, highEntropyStrings, minified, telemetry,
///   urlStrings, trivial, protestware
/// - Manifest (5): gitDependency, httpDependency, wildcardDependency,
///   copyleftLicense, noLicense
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralTags {
    // ── Source code tags (10) ──────────────────���─────────────────
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

    // ── Supply chain tags (7) ────────────────────────────────��──
    #[serde(default)]
    pub obfuscated: bool,
    #[serde(default, rename = "highEntropyStrings")]
    pub high_entropy_strings: bool,
    #[serde(default)]
    pub minified: bool,
    #[serde(default)]
    pub telemetry: bool,
    #[serde(default, rename = "urlStrings")]
    pub url_strings: bool,
    #[serde(default)]
    pub trivial: bool,
    #[serde(default)]
    pub protestware: bool,

    // ── Manifest tags (5) ───────────────────────────────────────
    #[serde(default, rename = "gitDependency")]
    pub git_dependency: bool,
    #[serde(default, rename = "httpDependency")]
    pub http_dependency: bool,
    #[serde(default, rename = "wildcardDependency")]
    pub wildcard_dependency: bool,
    #[serde(default, rename = "copyleftLicense")]
    pub copyleft_license: bool,
    #[serde(default, rename = "noLicense")]
    pub no_license: bool,
}

impl BehavioralTags {
    /// The canonical, camelCase tag name of every field that is
    /// currently `true`, sorted lexicographically.
    ///
    /// **Phase 46 P1** — the ordered input for
    /// `lpm_security::triage::hash_behavioral_tag_set`. Names use the
    /// same spelling as the registry's wire protocol so the hash is
    /// portable across any tooling that speaks the registry schema
    /// (registry, CLI, dashboard).
    ///
    /// Returning `Vec<&'static str>` (not `Vec<String>`) keeps the
    /// caller's allocation cost at the small-Vec-of-pointers level;
    /// the static strings mirror the `#[serde(rename)]` attributes
    /// above and the server-side `behavioral-tags.js` definition.
    pub fn active_tag_names(&self) -> Vec<&'static str> {
        let mut active: Vec<&'static str> = Vec::new();
        // Source tags (10)
        if self.eval {
            active.push("eval");
        }
        if self.child_process {
            active.push("childProcess");
        }
        if self.shell {
            active.push("shell");
        }
        if self.network {
            active.push("network");
        }
        if self.filesystem {
            active.push("filesystem");
        }
        if self.crypto {
            active.push("crypto");
        }
        if self.dynamic_require {
            active.push("dynamicRequire");
        }
        if self.native_bindings {
            active.push("nativeBindings");
        }
        if self.environment_vars {
            active.push("environmentVars");
        }
        if self.web_socket {
            active.push("webSocket");
        }
        // Supply chain tags (7)
        if self.obfuscated {
            active.push("obfuscated");
        }
        if self.high_entropy_strings {
            active.push("highEntropyStrings");
        }
        if self.minified {
            active.push("minified");
        }
        if self.telemetry {
            active.push("telemetry");
        }
        if self.url_strings {
            active.push("urlStrings");
        }
        if self.trivial {
            active.push("trivial");
        }
        if self.protestware {
            active.push("protestware");
        }
        // Manifest tags (5)
        if self.git_dependency {
            active.push("gitDependency");
        }
        if self.http_dependency {
            active.push("httpDependency");
        }
        if self.wildcard_dependency {
            active.push("wildcardDependency");
        }
        if self.copyleft_license {
            active.push("copyleftLicense");
        }
        if self.no_license {
            active.push("noLicense");
        }
        // Sort so downstream hashing is order-stable regardless of
        // struct-field declaration order or future additions.
        active.sort();
        active
    }
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DistInfo {
    #[serde(default)]
    pub tarball: Option<String>,

    #[serde(default)]
    pub integrity: Option<String>,

    #[serde(default)]
    pub shasum: Option<String>,

    /// **Phase 46 P4.** Per-key detached package signatures (npm's
    /// package-signing surface). Empty/missing when the registry does
    /// not sign packages — which is the current state for the LPM
    /// registry and many niche npm-compatible hosts. Parsed loosely
    /// here; Chunk 2 wires the CLI-side fetcher, Chunk 3 wires the
    /// drift check. Registry servers that do not publish this field
    /// continue to round-trip through serde-default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<RegistrySignature>>,

    /// **Phase 46 P4.** Sigstore attestation pointer. Present on
    /// npm packages published via GitHub Actions with Trusted
    /// Publishing. `None` indicates "no attestation" — which is the
    /// exact axios-case signal when compared against a prior-approved
    /// version that had one (§7.2 "provenance dropped" branch).
    ///
    /// The LPM registry does not expose this field today; the
    /// coordinated server-side PR (§11 P4) adds it as a parallel
    /// track.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<AttestationRef>,
}

/// **Phase 46 P4.** Per-key detached signature over the tarball
/// integrity hash, as served by npm's package-metadata
/// `dist.signatures` array.
///
/// Fields are `Option<String>` for maximum serde tolerance: a partial
/// signature payload (e.g., a registry that emits `keyid` without
/// `sig` during a rollout) does not fail deserialization. Consumers
/// should check both fields are `Some` before trusting the entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySignature {
    /// npm's published public-key fingerprint, typically
    /// `"SHA256:<base64>"`.
    #[serde(default)]
    pub keyid: Option<String>,
    /// Detached ECDSA signature (base64) over the signing input.
    #[serde(default)]
    pub sig: Option<String>,
}

/// **Phase 46 P4.** Pointer to a Sigstore attestation bundle for this
/// version, plus the pre-parsed provenance summary that npm inlines
/// in the metadata response.
///
/// Chunk 1 models the wire shape loosely: `provenance` is kept as
/// `serde_json::Value` because its schema (SLSA predicateType +
/// subject array) is consumed only by the fetcher in Chunk 2, which
/// can type-parse on demand. The `url` pointer is the actionable
/// field for drift detection — the fetcher GETs it to retrieve the
/// full attestation bundle and extract the cert SAN.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationRef {
    /// Registry-relative URL to the full attestation bundle
    /// (e.g., `https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.0`).
    #[serde(default)]
    pub url: Option<String>,
    /// Inline pre-parsed provenance summary. npm includes a JSON
    /// object with `predicateType` and (optionally) the raw SLSA
    /// statement. Kept untyped in Chunk 1; Chunk 2 types the subset
    /// the fetcher consumes.
    #[serde(default)]
    pub provenance: Option<serde_json::Value>,
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
            .map(|t| {
                t.eval
                    || t.child_process
                    || t.shell
                    || t.dynamic_require
                    || t.obfuscated
                    || t.protestware
                    || t.high_entropy_strings
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── DistInfo round-trip with + without Phase 46 P4 fields ─────

    /// Legacy `DistInfo` response shape (registries that don't publish
    /// provenance, incl. LPM today) must round-trip unchanged when the
    /// new `signatures` / `attestations` fields are absent — both on
    /// deserialization (via `serde(default)`) and on re-serialization
    /// (via `skip_serializing_if = "Option::is_none"`).
    #[test]
    fn dist_info_legacy_shape_roundtrips_without_provenance_fields() {
        let legacy = r#"{
            "tarball": "https://example.com/pkg-1.0.0.tgz",
            "integrity": "sha512-abc",
            "shasum": "deadbeef"
        }"#;
        let parsed: DistInfo = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            parsed.tarball.as_deref(),
            Some("https://example.com/pkg-1.0.0.tgz")
        );
        assert_eq!(parsed.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(parsed.shasum.as_deref(), Some("deadbeef"));
        assert!(parsed.signatures.is_none());
        assert!(parsed.attestations.is_none());

        // Re-serialize and assert the new fields do NOT leak in as
        // `null` keys. Pre-P4 readers wouldn't trip on extra nullable
        // fields but the wire is cleaner without them.
        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("signatures"),
            "legacy DistInfo must not emit a `signatures` key when None; got {reserialized}"
        );
        assert!(
            !reserialized.contains("attestations"),
            "legacy DistInfo must not emit an `attestations` key when None; got {reserialized}"
        );
    }

    /// npm wire shape: `dist.signatures` is an array of
    /// `{keyid, sig}` pairs; `dist.attestations` is an object with
    /// `url` and an inline `provenance` summary. Parse both fields
    /// round-trip through serde without type surgery.
    #[test]
    fn dist_info_npm_shape_roundtrips_with_provenance_fields() {
        let npm_wire = r#"{
            "tarball": "https://registry.npmjs.org/axios/-/axios-1.14.0.tgz",
            "integrity": "sha512-xxx",
            "shasum": "cafef00d",
            "signatures": [
                {"keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", "sig": "MEUCIAbc..."}
            ],
            "attestations": {
                "url": "https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.0",
                "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
            }
        }"#;
        let parsed: DistInfo = serde_json::from_str(npm_wire).unwrap();

        let sigs = parsed.signatures.as_ref().expect("signatures parsed");
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].keyid.as_deref().unwrap().starts_with("SHA256:"));
        assert!(sigs[0].sig.as_deref().unwrap().starts_with("MEUCIAbc"));

        let att = parsed.attestations.as_ref().expect("attestations parsed");
        assert!(
            att.url
                .as_deref()
                .unwrap()
                .contains("/attestations/axios@1.14.0")
        );
        let provenance = att.provenance.as_ref().expect("provenance parsed");
        assert_eq!(
            provenance.get("predicateType").and_then(|v| v.as_str()),
            Some("https://slsa.dev/provenance/v1"),
            "inline provenance summary preserved as untyped JSON for Chunk 2 to type-parse on demand",
        );

        // Full round-trip through serde.
        let reserialized = serde_json::to_string(&parsed).unwrap();
        let reparsed: DistInfo = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(reparsed.signatures.as_ref().unwrap().len(), 1);
        assert!(reparsed.attestations.is_some());
    }

    /// A registry that ships an empty signatures array (between
    /// publishing a package and uploading its signature) must still
    /// round-trip — `Some(vec![])` is a distinct signal from `None`.
    #[test]
    fn dist_info_empty_signatures_array_preserves_distinction_from_absent() {
        let json = r#"{
            "tarball": "https://example.com/pkg-1.0.0.tgz",
            "signatures": []
        }"#;
        let parsed: DistInfo = serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed.signatures.as_ref().map(|s| s.len()),
            Some(0),
            "empty array must deserialize as Some(vec![]), distinct from missing key"
        );
    }

    /// Partial signature payload — keyid without sig, or vice versa —
    /// must not fail deserialization. A registry could emit a stub
    /// during a rollout; consumers (Chunk 2 fetcher) check both
    /// fields are `Some` before trusting an entry.
    #[test]
    fn registry_signature_tolerates_partial_payload() {
        let keyid_only = r#"{"keyid": "SHA256:abc"}"#;
        let parsed: RegistrySignature = serde_json::from_str(keyid_only).unwrap();
        assert_eq!(parsed.keyid.as_deref(), Some("SHA256:abc"));
        assert!(parsed.sig.is_none());

        let sig_only = r#"{"sig": "MEUCIAbc"}"#;
        let parsed: RegistrySignature = serde_json::from_str(sig_only).unwrap();
        assert!(parsed.keyid.is_none());
        assert_eq!(parsed.sig.as_deref(), Some("MEUCIAbc"));
    }

    /// `AttestationRef.provenance` is kept untyped in Chunk 1 so an
    /// unexpected schema extension (a new npm field, a custom
    /// predicate type) doesn't trip deserialization. Chunk 2 will
    /// type-parse the subset the CLI fetcher actually consumes.
    #[test]
    fn attestation_ref_provenance_accepts_unknown_fields() {
        let json = r#"{
            "url": "https://registry.example.com/att",
            "provenance": {
                "predicateType": "https://custom.example/predicate/v2",
                "someFutureField": { "nested": true }
            }
        }"#;
        let parsed: AttestationRef = serde_json::from_str(json).unwrap();
        assert!(parsed.url.is_some());
        let prov = parsed.provenance.as_ref().unwrap();
        assert_eq!(
            prov.get("someFutureField")
                .and_then(|v| v.get("nested"))
                .and_then(|v| v.as_bool()),
            Some(true),
            "unknown fields must round-trip through the untyped serde_json::Value",
        );
    }
}
