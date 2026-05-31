//! Response types for the LPM registry API.
//!
//! Strongly typed structs matching the JSON responses from every endpoint.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

const NPM_MISSING_SIGNATURE_TIME_CUTOFF: &str = "2015-01-01T00:00:00.000Z";

/// Per-peer metadata as declared in a package's
/// `peerDependenciesMeta` map. The npm spec is open-ended; today
/// the resolver consumes only the `optional` flag (R5). Unknown
/// keys round-trip via `serde`'s default `deny_unknown_fields = false`
/// so a future flag added by the npm spec doesn't break parsing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerDependencyMeta {
    /// True when the peer is marked optional. Missing optional peers
    /// produce no `unmet peer` warning in [`check_unmet_peers`];
    /// optional peers that ARE present but at the wrong version still
    /// warn (the user opted into having a peer — just at an
    /// incompatible version).
    #[serde(default)]
    pub optional: bool,
}

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

    /// `peerDependenciesMeta` flags from package.json. The npm spec
    /// defines a per-peer metadata bag; only the `optional: true` flag
    /// is read today. Empty when the manifest declares no metadata.
    /// Consumers gate the unmet-peer warning on
    /// `peer_dependencies_meta[name].optional`.
    #[serde(default, rename = "peerDependenciesMeta")]
    pub peer_dependencies_meta: HashMap<String, PeerDependencyMeta>,

    /// Names this version vendors inside its published tarball's
    /// `node_modules/` dir. npm's spec accepts both `bundleDependencies`
    /// and `bundledDependencies` spellings; both deserialize into this
    /// field. Consumers skip enqueuing these names as separate installs —
    /// they're already provided by the parent's tarball.
    #[serde(
        default,
        rename = "bundleDependencies",
        alias = "bundledDependencies",
        deserialize_with = "deserialize_bundle_dependencies"
    )]
    pub bundle_dependencies: Vec<String>,

    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: HashMap<String, String>,

    /// Platform restrictions: ["darwin", "linux", "win32"]
    #[serde(default)]
    pub os: Vec<String>,

    /// CPU restrictions: ["x64", "arm64"]
    #[serde(default)]
    pub cpu: Vec<String>,

    /// Linux libc flavor restrictions: ["glibc"], ["musl"], or
    /// exclusion form like ["!glibc"]. Documented at
    /// <https://docs.npmjs.com/cli/v9/configuring-npm/package-json#libc>.
    /// Native modules (sharp, esbuild, `@next/swc-*`) ship distinct
    /// binaries per libc; the resolver's platform filter consumes this
    /// field alongside `os`/`cpu`.
    #[serde(default)]
    pub libc: Vec<String>,

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
    /// Ordered input for `lpm_security::triage::hash_behavioral_tag_set`.
    /// Names use the same spelling as the registry wire protocol so the
    /// hash is portable across any tooling that speaks the registry schema.
    ///
    /// Returns `Vec<&'static str>` (not `Vec<String>`) to keep allocation
    /// cost at the small-Vec-of-pointers level. Static strings mirror the
    /// `#[serde(rename)]` attributes above and the server-side
    /// `behavioral-tags.js` definition.
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

    /// Per-key detached package signatures (npm's package-signing surface).
    /// Empty/missing when the registry does not sign packages. Registry
    /// servers that do not publish this field continue to round-trip
    /// through serde-default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<RegistrySignature>>,

    /// Sigstore attestation pointer. Present on npm packages published
    /// via GitHub Actions with Trusted Publishing. `None` indicates
    /// "no attestation" — a distinct signal when compared against a
    /// prior-approved version that had one ("provenance dropped" branch).
    ///
    /// The LPM registry does not expose this field today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<AttestationRef>,
}

/// Per-key detached signature over the tarball integrity hash, as
/// served by npm's package-metadata `dist.signatures` array.
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySigningKey {
    #[serde(default)]
    pub expires: Option<String>,
    pub keyid: String,
    pub keytype: String,
    pub scheme: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrySignatureVerification {
    NoSignatures,
    Verified { count: usize },
}

/// Pointer to a Sigstore attestation bundle for this version, plus
/// the pre-parsed provenance summary that npm inlines in the metadata
/// response.
///
/// `provenance` is kept as `serde_json::Value` because its schema
/// (SLSA predicateType + subject array) is consumed only by the
/// attestation fetcher, which can type-parse on demand. The `url`
/// pointer is the actionable field for drift detection — the fetcher
/// GETs it to retrieve the full attestation bundle and extract the
/// cert SAN.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationRef {
    /// Registry-relative URL to the full attestation bundle
    /// (e.g., `https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.0`).
    #[serde(default)]
    pub url: Option<String>,
    /// Inline pre-parsed provenance summary. npm includes a JSON
    /// object with `predicateType` and (optionally) the raw SLSA
    /// statement. Kept untyped here; the attestation fetcher types
    /// the subset it consumes on demand.
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

    /// Resolve a user-supplied version spec to a concrete version present
    /// in `versions`.
    ///
    /// Three-tier resolution:
    /// 1. **Dist-tag** — if `spec` matches a key in `dist_tags`
    ///    (e.g., `latest`, `next`, `beta`, `canary`), return the tagged
    ///    version.
    /// 2. **Exact match** — if `versions` contains `spec` verbatim,
    ///    return it.
    /// 3. **Semver range** — parse `spec` as a `VersionReq` and return
    ///    the highest version in `versions` that satisfies it.
    ///
    /// Error variants used by all call sites (behavior-preserving across
    /// install, update, and global paths):
    ///
    /// - parse failure → `LpmError::Script("could not parse version token '{spec}': {e}")`
    /// - empty parseable set → `LpmError::Script("registry returned no parseable versions for '{name}'")`
    /// - no satisfying version → `LpmError::Script("no version of '{name}' satisfies '{spec}'. Available: {top-5-desc}")`
    pub fn resolve_version_spec(&self, spec: &str) -> Result<String, lpm_common::LpmError> {
        // Tier 1: dist-tag fast path.
        if let Some(v) = self.dist_tags.get(spec) {
            return Ok(v.clone());
        }
        // Tier 2: exact-version match.
        if self.versions.contains_key(spec) {
            return Ok(spec.to_string());
        }
        // Tier 3: parse + max_satisfying.
        let req = lpm_semver::VersionReq::parse(spec).map_err(|e| {
            lpm_common::LpmError::Script(format!("could not parse version token '{spec}': {e}"))
        })?;
        let mut versions: Vec<lpm_semver::Version> = self
            .versions
            .keys()
            .filter_map(|s| lpm_semver::Version::parse(s).ok())
            .collect();
        if versions.is_empty() {
            return Err(lpm_common::LpmError::Script(format!(
                "registry returned no parseable versions for '{}'",
                self.name
            )));
        }
        let refs: Vec<&lpm_semver::Version> = versions.iter().collect();
        match lpm_semver::max_satisfying(&refs, &req) {
            Some(v) => Ok(v.to_string()),
            None => {
                versions.sort();
                Err(lpm_common::LpmError::Script(format!(
                    "no version of '{}' satisfies '{}'. Available: {}",
                    self.name,
                    spec,
                    versions
                        .iter()
                        .rev()
                        .take(5)
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )))
            }
        }
    }
}

impl VersionMetadata {
    pub fn tarball_url(&self) -> Option<&str> {
        self.dist.as_ref()?.tarball.as_deref()
    }

    pub fn integrity(&self) -> Option<&str> {
        self.dist.as_ref()?.integrity.as_deref()
    }

    pub fn integrity_or_shasum(&self) -> Option<Cow<'_, str>> {
        let dist = self.dist.as_ref()?;
        if let Some(integrity) = dist.integrity.as_deref() {
            return Some(Cow::Borrowed(integrity));
        }
        dist.shasum
            .as_deref()
            .and_then(shasum_to_sha1_sri)
            .map(Cow::Owned)
    }

    /// Returns the first library product name from Swift metadata.
    pub fn swift_product_name(&self) -> Option<&str> {
        let meta = self.swift_meta.as_ref()?;
        meta.products
            .iter()
            .find(|p| {
                // Skip executables — prefer library products
                p.product_type.as_ref().and_then(|t| t.as_str()) != Some("executable")
            })
            .map(|p| p.name.as_str())
    }

    /// Returns true if this version has any security concerns.
    pub fn has_security_issues(&self) -> bool {
        let has_findings = self
            .security_findings
            .as_ref()
            .is_some_and(|f| !f.is_empty());
        let has_dangerous_tags = self.behavioral_tags.as_ref().is_some_and(|t| {
            t.eval
                || t.child_process
                || t.shell
                || t.dynamic_require
                || t.obfuscated
                || t.protestware
                || t.high_entropy_strings
        });
        let has_lifecycle = self
            .lifecycle_scripts
            .as_ref()
            .is_some_and(|s| !s.is_empty());
        let has_vulns = self.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty());
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

fn shasum_to_sha1_sri(shasum: &str) -> Option<String> {
    use base64::Engine;

    if shasum.len() != 40 {
        return None;
    }
    let bytes = hex::decode(shasum).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("sha1-{b64}"))
}

pub fn verify_registry_signatures(
    name: &str,
    version: &str,
    integrity: &str,
    signatures: &[RegistrySignature],
    keys: &[RegistrySigningKey],
    published_at: Option<&str>,
) -> Result<RegistrySignatureVerification, lpm_common::LpmError> {
    if signatures.is_empty() {
        return Ok(RegistrySignatureVerification::NoSignatures);
    }

    let message = format!("{name}@{version}:{integrity}");
    let mut verified = 0usize;
    for signature in signatures {
        let keyid = signature.keyid.as_deref().ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "{name}@{version} has a registry signature without keyid"
            ))
        })?;
        let sig = signature.sig.as_deref().ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "{name}@{version} has a registry signature without sig"
            ))
        })?;
        let key = keys.iter().find(|key| key.keyid == keyid).ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "{name}@{version} has a registry signature with keyid {keyid} but no matching public key"
            ))
        })?;
        verify_registry_signature_key_supported(name, version, key)?;
        verify_registry_signature_key_not_expired(name, version, key, published_at)?;
        verify_registry_signature_bytes(name, version, key, sig, message.as_bytes())?;
        verified += 1;
    }

    Ok(RegistrySignatureVerification::Verified { count: verified })
}

fn verify_registry_signature_key_supported(
    name: &str,
    version: &str,
    key: &RegistrySigningKey,
) -> Result<(), lpm_common::LpmError> {
    if key.keytype == "ecdsa-sha2-nistp256" && key.scheme == "ecdsa-sha2-nistp256" {
        Ok(())
    } else {
        Err(lpm_common::LpmError::Registry(format!(
            "{name}@{version} registry signature key {} uses unsupported keytype/scheme {}/{}",
            key.keyid, key.keytype, key.scheme
        )))
    }
}

fn verify_registry_signature_key_not_expired(
    name: &str,
    version: &str,
    key: &RegistrySigningKey,
    published_at: Option<&str>,
) -> Result<(), lpm_common::LpmError> {
    let Some(expires) = key.expires.as_deref() else {
        return Ok(());
    };
    let published_at = published_at.unwrap_or(NPM_MISSING_SIGNATURE_TIME_CUTOFF);
    let expires_time = parse_registry_signature_time(expires).ok_or_else(|| {
        lpm_common::LpmError::Registry(format!(
            "{name}@{version} registry signature key {} has invalid expires timestamp {expires}",
            key.keyid
        ))
    })?;
    let published_time = parse_registry_signature_time(published_at).ok_or_else(|| {
        lpm_common::LpmError::Registry(format!(
            "{name}@{version} has invalid publish timestamp {published_at}"
        ))
    })?;
    if published_time < expires_time {
        Ok(())
    } else {
        Err(lpm_common::LpmError::Registry(format!(
            "{name}@{version} registry signature key {} expired at {expires} before publish time {published_at}",
            key.keyid
        )))
    }
}

fn parse_registry_signature_time(input: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(input, &time::format_description::well_known::Rfc3339).ok()
}

fn verify_registry_signature_bytes(
    name: &str,
    version: &str,
    key: &RegistrySigningKey,
    sig: &str,
    message: &[u8],
) -> Result<(), lpm_common::LpmError> {
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let key_b64 = if key.key.bytes().any(|byte| byte.is_ascii_whitespace()) {
        Cow::Owned(
            key.key
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .map(char::from)
                .collect::<String>(),
        )
    } else {
        Cow::Borrowed(key.key.as_str())
    };
    let key_der = base64::engine::general_purpose::STANDARD
        .decode(key_b64.as_bytes())
        .map_err(|e| {
            lpm_common::LpmError::Registry(format!(
                "{name}@{version} registry signature key {} is not valid base64: {e}",
                key.keyid
            ))
        })?;
    let verifying_key = VerifyingKey::from_public_key_der(&key_der).map_err(|e| {
        lpm_common::LpmError::Registry(format!(
            "{name}@{version} registry signature key {} is not a valid P-256 public key: {e}",
            key.keyid
        ))
    })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig)
        .map_err(|e| {
            lpm_common::LpmError::Registry(format!(
                "{name}@{version} registry signature for key {} is not valid base64: {e}",
                key.keyid
            ))
        })?;
    let signature = Signature::from_der(&sig_bytes).map_err(|e| {
        lpm_common::LpmError::Registry(format!(
            "{name}@{version} registry signature for key {} is not DER ECDSA: {e}",
            key.keyid
        ))
    })?;
    verifying_key.verify(message, &signature).map_err(|_| {
        lpm_common::LpmError::Registry(format!(
            "{name}@{version} has an invalid registry signature for keyid {}",
            key.keyid
        ))
    })
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

    #[serde(default, alias = "_ecosystem", skip_serializing)]
    pub ecosystem: Option<String>,

    #[serde(
        default,
        rename = "_qualityScore",
        alias = "qualityScore",
        alias = "quality_score",
        skip_serializing
    )]
    pub quality_score: Option<u32>,

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

/// Deserializer for `bundleDependencies` / `bundledDependencies`.
///
/// The npm spec accepts two shapes:
///   - `["foo", "bar"]` — list of canonical names (the canonical form).
///   - `true` — historical alias meaning "bundle every entry in
///     `dependencies`" (rare in practice).
///
/// We deserialize the list shape directly. `true` / `false` collapse
/// to an empty list with a debug log — pre-R4 behavior was "ignore
/// bundling entirely," so this preserves the no-regression contract
/// for the rare `bundleDependencies: true` packages while keeping the
/// common list form first-class.
fn deserialize_bundle_dependencies<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct BundleVisitor;

    impl<'de> Visitor<'de> for BundleVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list of dependency names, a boolean, or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
            if value {
                tracing::debug!(
                    "bundleDependencies: true — collapsing to empty list \
                     (whole-deps bundling is rare and not yet implemented; \
                     pre-R4 behavior preserved)"
                );
            }
            Ok(Vec::new())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(BundleVisitor)
}

// ─── Minimal types for install-time blocked-set capture ─────────────────────

/// Package metadata deserialized from the registry cache using only the fields
/// required for install-time blocked-set capture: `time` (for `published_at`)
/// and `versions[v]._behavioralTags` (for the static tier fingerprint).
///
/// Using this instead of [`PackageMetadata`] on cache hits eliminates ~90% of
/// the rmp_serde string allocations that arise from deserializing all version
/// fields (deps, devDeps, readme, etc.) for packages that are already cached.
#[derive(serde::Deserialize, Default)]
pub struct BlockedSetPackageMeta {
    #[serde(default)]
    pub time: HashMap<String, String>,
    #[serde(default)]
    pub versions: HashMap<String, BlockedSetVersionMeta>,
}

/// Per-version slice of [`BlockedSetPackageMeta`] — only the behavioral-tags
/// field. All other `VersionMetadata` fields are skipped during deserialization.
#[derive(serde::Deserialize, Default)]
pub struct BlockedSetVersionMeta {
    #[serde(default, rename = "_behavioralTags")]
    pub behavioral_tags: Option<BehavioralTags>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DistInfo round-trip with + without provenance fields ──────

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
        // `null` keys — the wire is cleaner without them.
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

    #[test]
    fn version_integrity_uses_sha1_sri_from_dist_shasum_when_integrity_missing() {
        let meta = VersionMetadata {
            name: "legacy".to_string(),
            version: "1.0.0".to_string(),
            dist: Some(DistInfo {
                tarball: Some("https://example.com/legacy-1.0.0.tgz".to_string()),
                integrity: None,
                shasum: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
                signatures: None,
                attestations: None,
            }),
            ..VersionMetadata::default()
        };

        assert_eq!(
            meta.integrity_or_shasum().as_deref(),
            Some("sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=")
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
            "inline provenance summary preserved as untyped JSON for the attestation fetcher to type-parse on demand",
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
    /// during a rollout; consumers check both fields are `Some` before
    /// trusting an entry.
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

    #[test]
    fn registry_signature_verifier_accepts_valid_npm_ecdsa_signature() {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pem = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();
        let public_key_body = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let message = "signed-pkg@1.0.0:sha512-test";
        let sig: Signature = signing_key.sign(message.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes());

        let result = verify_registry_signatures(
            "signed-pkg",
            "1.0.0",
            "sha512-test",
            &[RegistrySignature {
                keyid: Some("SHA256:test".to_string()),
                sig: Some(sig),
            }],
            &[RegistrySigningKey {
                expires: None,
                keyid: "SHA256:test".to_string(),
                keytype: "ecdsa-sha2-nistp256".to_string(),
                scheme: "ecdsa-sha2-nistp256".to_string(),
                key: public_key_body,
            }],
            Some("2026-05-29T00:00:00.000Z"),
        )
        .unwrap();

        assert_eq!(result, RegistrySignatureVerification::Verified { count: 1 });
    }

    #[test]
    fn registry_signature_verifier_rejects_tampered_message() {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let signing_key = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pem = verifying_key.to_public_key_pem(LineEnding::LF).unwrap();
        let public_key_body = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let sig: Signature = signing_key.sign(b"signed-pkg@1.0.0:sha512-good");
        let sig = base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes());

        let err = verify_registry_signatures(
            "signed-pkg",
            "1.0.0",
            "sha512-tampered",
            &[RegistrySignature {
                keyid: Some("SHA256:test".to_string()),
                sig: Some(sig),
            }],
            &[RegistrySigningKey {
                expires: None,
                keyid: "SHA256:test".to_string(),
                keytype: "ecdsa-sha2-nistp256".to_string(),
                scheme: "ecdsa-sha2-nistp256".to_string(),
                key: public_key_body,
            }],
            Some("2026-05-29T00:00:00.000Z"),
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid registry signature"));
    }

    #[test]
    fn registry_signature_expiry_uses_cutoff_when_publish_time_missing() {
        let key = RegistrySigningKey {
            expires: Some("2025-01-29T00:00:00.000Z".to_string()),
            keyid: "SHA256:test".to_string(),
            keytype: "ecdsa-sha2-nistp256".to_string(),
            scheme: "ecdsa-sha2-nistp256".to_string(),
            key: String::new(),
        };

        verify_registry_signature_key_not_expired("signed-pkg", "1.0.0", &key, None).unwrap();
    }

    /// `AttestationRef.provenance` is kept untyped so an unexpected
    /// schema extension (a new npm field, a custom predicate type)
    /// doesn't trip deserialization. The attestation fetcher
    /// type-parses the subset it actually consumes.
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

    // ── PackageMetadata::resolve_version_spec ──────────────────────

    fn metadata_for_resolver_tests() -> PackageMetadata {
        let json = r#"{
            "name": "fixture",
            "dist-tags": {
                "latest": "1.2.3",
                "beta": "2.0.0-beta.1",
                "canary": "3.0.0-canary.5"
            },
            "versions": {
                "1.0.0": { "name": "fixture", "version": "1.0.0" },
                "1.1.0": { "name": "fixture", "version": "1.1.0" },
                "1.2.3": { "name": "fixture", "version": "1.2.3" },
                "2.0.0-beta.1": { "name": "fixture", "version": "2.0.0-beta.1" },
                "3.0.0-canary.5": { "name": "fixture", "version": "3.0.0-canary.5" }
            }
        }"#;
        serde_json::from_str(json).expect("fixture metadata parses")
    }

    #[test]
    fn resolve_version_spec_dist_tag_beta() {
        let m = metadata_for_resolver_tests();
        assert_eq!(m.resolve_version_spec("beta").unwrap(), "2.0.0-beta.1");
    }

    #[test]
    fn resolve_version_spec_dist_tag_canary() {
        let m = metadata_for_resolver_tests();
        assert_eq!(m.resolve_version_spec("canary").unwrap(), "3.0.0-canary.5");
    }

    #[test]
    fn resolve_version_spec_dist_tag_latest() {
        let m = metadata_for_resolver_tests();
        assert_eq!(m.resolve_version_spec("latest").unwrap(), "1.2.3");
    }

    #[test]
    fn resolve_version_spec_exact_version() {
        let m = metadata_for_resolver_tests();
        assert_eq!(m.resolve_version_spec("1.2.3").unwrap(), "1.2.3");
        assert_eq!(m.resolve_version_spec("1.0.0").unwrap(), "1.0.0");
    }

    #[test]
    fn resolve_version_spec_caret_range_picks_max_satisfying() {
        let m = metadata_for_resolver_tests();
        // ^1 → >=1.0.0 <2.0.0; max satisfying is 1.2.3
        assert_eq!(m.resolve_version_spec("^1").unwrap(), "1.2.3");
    }

    #[test]
    fn resolve_version_spec_tilde_range() {
        let m = metadata_for_resolver_tests();
        // ~1.0 → >=1.0.0 <1.1.0; only 1.0.0 satisfies
        assert_eq!(m.resolve_version_spec("~1.0").unwrap(), "1.0.0");
    }

    #[test]
    fn resolve_version_spec_no_satisfying_version_errors_with_script_variant() {
        let m = metadata_for_resolver_tests();
        let err = m.resolve_version_spec("99.99.99").unwrap_err();
        // Error variant is Script (not NotFound) — all install paths use this
        // helper so behavior is consistent across install/update/global.
        match &err {
            lpm_common::LpmError::Script(msg) => {
                assert!(msg.contains("no version of 'fixture' satisfies '99.99.99'"));
                assert!(msg.contains("Available:"));
            }
            other => panic!("expected LpmError::Script, got {other:?}"),
        }
    }

    #[test]
    fn resolve_version_spec_unparseable_spec_errors_with_script_variant() {
        let m = metadata_for_resolver_tests();
        let err = m
            .resolve_version_spec("not-a-version-or-range")
            .unwrap_err();
        match &err {
            lpm_common::LpmError::Script(msg) => {
                assert!(msg.contains("could not parse version token 'not-a-version-or-range'"));
            }
            other => panic!("expected LpmError::Script, got {other:?}"),
        }
    }

    #[test]
    fn resolve_version_spec_empty_versions_errors_with_script_variant() {
        let json = r#"{
            "name": "empty",
            "dist-tags": {},
            "versions": {}
        }"#;
        let m: PackageMetadata = serde_json::from_str(json).unwrap();
        let err = m.resolve_version_spec("^1").unwrap_err();
        match &err {
            lpm_common::LpmError::Script(msg) => {
                assert!(msg.contains("no parseable versions for 'empty'"));
            }
            other => panic!("expected LpmError::Script, got {other:?}"),
        }
    }
}
