use futures::StreamExt;
use lpm_common::LpmError;
use lpm_registry::{
    RegistryClient, RegistrySignature, RegistrySignatureVerification, RegistrySigningKey,
    RouteTable, UpstreamRoute,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const VERIFY_CONCURRENCY: usize = 16;

#[derive(Debug, Default)]
pub(crate) struct RegistrySignatureTimings {
    total_wall_ns: AtomicU64,
    hydration_ns: AtomicU64,
    hydration_count: AtomicU64,
    key_fetch_ns: AtomicU64,
    key_fetch_count: AtomicU64,
    crypto_ns: AtomicU64,
    crypto_count: AtomicU64,
    crypto_max_ns: AtomicU64,
}

impl RegistrySignatureTimings {
    fn record_total_wall(&self, elapsed: std::time::Duration) {
        self.total_wall_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    }

    fn record_hydration(&self, elapsed: std::time::Duration) {
        self.hydration_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        self.hydration_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_key_fetch(&self, elapsed: std::time::Duration) {
        self.key_fetch_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        self.key_fetch_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_crypto(&self, elapsed: std::time::Duration) {
        let ns = elapsed.as_nanos() as u64;
        self.crypto_ns.fetch_add(ns, Ordering::Relaxed);
        self.crypto_count.fetch_add(1, Ordering::Relaxed);
        let mut current = self.crypto_max_ns.load(Ordering::Relaxed);
        while ns > current {
            match self.crypto_max_ns.compare_exchange_weak(
                current,
                ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_wall_ms": self.total_wall_ns.load(Ordering::Relaxed) / 1_000_000,
            "hydration": {
                "sum_ms": self.hydration_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.hydration_count.load(Ordering::Relaxed),
            },
            "key_fetch": {
                "sum_ms": self.key_fetch_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.key_fetch_count.load(Ordering::Relaxed),
            },
            "crypto_verify": {
                "sum_ms": self.crypto_ns.load(Ordering::Relaxed) / 1_000_000,
                "max_ms": self.crypto_max_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.crypto_count.load(Ordering::Relaxed),
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct RegistrySignatureInput {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub resolved_url: Option<String>,
    pub integrity: Option<String>,
    pub signatures: Vec<RegistrySignature>,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrySignatureStatus {
    Verified,
    NotVerified,
    Skipped,
}

impl RegistrySignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::NotVerified => "not_verified",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone)]
pub enum RegistrySignatureReason {
    MissingIntegrity,
    MissingSignatures,
    MetadataUnavailable(String),
    VerificationFailed(String),
    NonRegistrySource,
    LpmRegistryPackage,
    InvalidSource(String),
}

impl RegistrySignatureReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingIntegrity => "missing_integrity",
            Self::MissingSignatures => "missing_signatures",
            Self::MetadataUnavailable(_) => "metadata_unavailable",
            Self::VerificationFailed(_) => "verification_failed",
            Self::NonRegistrySource => "non_registry_source",
            Self::LpmRegistryPackage => "lpm_registry_package",
            Self::InvalidSource(_) => "invalid_source",
        }
    }

    pub fn human(&self) -> String {
        match self {
            Self::MissingIntegrity => "missing dist.integrity".to_string(),
            Self::MissingSignatures => "missing dist.signatures".to_string(),
            Self::MetadataUnavailable(err) => format!("metadata unavailable: {err}"),
            Self::VerificationFailed(err) => format!("verification failed: {err}"),
            Self::NonRegistrySource => "not a registry package".to_string(),
            Self::LpmRegistryPackage => "LPM registry package".to_string(),
            Self::InvalidSource(err) => format!("invalid source: {err}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegistrySignaturePackageResult {
    pub name: String,
    pub version: String,
    pub status: RegistrySignatureStatus,
    pub reason: Option<RegistrySignatureReason>,
    pub signatures_verified: usize,
}

impl RegistrySignaturePackageResult {
    pub fn package_id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Clone)]
pub struct RegistrySignatureReport {
    pub packages: Vec<RegistrySignaturePackageResult>,
}

impl RegistrySignatureReport {
    pub fn scanned(&self) -> usize {
        self.packages.len()
    }

    pub fn verified(&self) -> usize {
        self.packages
            .iter()
            .filter(|package| package.status == RegistrySignatureStatus::Verified)
            .count()
    }

    pub fn not_verified(&self) -> usize {
        self.packages
            .iter()
            .filter(|package| package.status == RegistrySignatureStatus::NotVerified)
            .count()
    }

    pub fn skipped(&self) -> usize {
        self.packages
            .iter()
            .filter(|package| package.status == RegistrySignatureStatus::Skipped)
            .count()
    }

    pub fn has_failures(&self) -> bool {
        self.not_verified() > 0
    }

    pub fn not_verified_packages(&self) -> impl Iterator<Item = &RegistrySignaturePackageResult> {
        self.packages
            .iter()
            .filter(|package| package.status == RegistrySignatureStatus::NotVerified)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "success": !self.has_failures(),
            "scanned": self.scanned(),
            "verified": self.verified(),
            "not_verified": self.not_verified(),
            "skipped": self.skipped(),
            "packages": self.packages.iter().map(package_result_to_json).collect::<Vec<_>>(),
        })
    }
}

pub async fn verify_packages(
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    inputs: Vec<RegistrySignatureInput>,
    allow_metadata_hydration: bool,
) -> RegistrySignatureReport {
    verify_packages_with_timings(client, route_table, inputs, allow_metadata_hydration, None).await
}

pub(crate) async fn verify_packages_with_timings(
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    inputs: Vec<RegistrySignatureInput>,
    allow_metadata_hydration: bool,
    timings: Option<Arc<RegistrySignatureTimings>>,
) -> RegistrySignatureReport {
    let total_start = std::time::Instant::now();
    let packages = futures::stream::iter(inputs.into_iter().map(|input| {
        let client = Arc::clone(&client);
        let route_table = route_table.clone();
        let timings = timings.clone();
        async move {
            verify_one_package(
                client,
                route_table,
                input,
                allow_metadata_hydration,
                timings.as_deref(),
            )
            .await
        }
    }))
    .buffered(VERIFY_CONCURRENCY)
    .collect()
    .await;

    if let Some(timings) = &timings {
        timings.record_total_wall(total_start.elapsed());
    }

    RegistrySignatureReport { packages }
}

fn package_result_to_json(package: &RegistrySignaturePackageResult) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": package.name,
        "version": package.version,
        "status": package.status.as_str(),
        "signatures_verified": package.signatures_verified,
    });
    if let Some(reason) = &package.reason {
        value["reason"] = serde_json::Value::String(reason.code().to_string());
        value["reason_detail"] = serde_json::Value::String(reason.human());
    }
    value
}

async fn verify_one_package(
    client: Arc<RegistryClient>,
    route_table: RouteTable,
    mut input: RegistrySignatureInput,
    allow_metadata_hydration: bool,
    timings: Option<&RegistrySignatureTimings>,
) -> RegistrySignaturePackageResult {
    if input.name.starts_with("@lpm.dev/") && is_lpm_registry_source(&client, &input) {
        return skipped(input, RegistrySignatureReason::LpmRegistryPackage);
    }

    let route = match route_for_input(&client, &route_table, &input) {
        Ok(Some(route)) => route,
        Ok(None) => return skipped(input, RegistrySignatureReason::NonRegistrySource),
        Err(reason) => return not_verified(input, reason),
    };

    if allow_metadata_hydration
        && (input.signatures.is_empty()
            || input.integrity.is_none()
            || input.published_at.is_none())
        && let Err(reason) = hydrate_from_metadata(&client, &route, &mut input, timings).await
    {
        return not_verified(input, reason);
    }

    if input.signatures.is_empty() {
        return not_verified(input, RegistrySignatureReason::MissingSignatures);
    }

    let Some(integrity) = input
        .integrity
        .as_deref()
        .map(str::trim)
        .filter(|integrity| !integrity.is_empty())
    else {
        return not_verified(input, RegistrySignatureReason::MissingIntegrity);
    };

    let key_fetch_start = std::time::Instant::now();
    let keys = match registry_signing_keys_for_route(&client, &route, &input.signatures).await {
        Ok(keys) => keys,
        Err(error) => {
            return not_verified(
                input,
                RegistrySignatureReason::VerificationFailed(error.to_string()),
            );
        }
    };
    if let Some(timings) = timings {
        timings.record_key_fetch(key_fetch_start.elapsed());
    }

    let crypto_start = std::time::Instant::now();
    let verification = lpm_registry::verify_registry_signatures(
        &input.name,
        &input.version,
        integrity,
        &input.signatures,
        &keys,
        input.published_at.as_deref(),
    );
    if let Some(timings) = timings {
        timings.record_crypto(crypto_start.elapsed());
    }
    match verification {
        Ok(RegistrySignatureVerification::Verified { count }) => RegistrySignaturePackageResult {
            name: input.name,
            version: input.version,
            status: RegistrySignatureStatus::Verified,
            reason: None,
            signatures_verified: count,
        },
        Ok(RegistrySignatureVerification::NoSignatures) => {
            not_verified(input, RegistrySignatureReason::MissingSignatures)
        }
        Err(error) => not_verified(
            input,
            RegistrySignatureReason::VerificationFailed(error.to_string()),
        ),
    }
}

async fn hydrate_from_metadata(
    client: &RegistryClient,
    route: &UpstreamRoute,
    input: &mut RegistrySignatureInput,
    timings: Option<&RegistrySignatureTimings>,
) -> Result<(), RegistrySignatureReason> {
    let hydration_start = std::time::Instant::now();
    let metadata = lpm_registry::timing::with_metadata_purpose(
        lpm_registry::timing::MetadataPurpose::SignatureHydration,
        client.get_npm_metadata_routed(&input.name, route.clone()),
    )
    .await
    .map_err(|error| RegistrySignatureReason::MetadataUnavailable(error.to_string()))?;
    if let Some(timings) = timings {
        timings.record_hydration(hydration_start.elapsed());
    }

    let version = metadata.version(&input.version).ok_or_else(|| {
        RegistrySignatureReason::MetadataUnavailable(format!(
            "{}@{} not found in registry metadata",
            input.name, input.version
        ))
    })?;

    if let Some(dist) = version.dist.as_ref() {
        if input.integrity.is_none() {
            input.integrity = dist.integrity.clone();
        }
        if input.signatures.is_empty() {
            input.signatures = dist.signatures.clone().unwrap_or_default();
        }
    }

    if input.published_at.is_none() {
        input.published_at = metadata.time.get(&input.version).cloned();
    }

    Ok(())
}

fn route_for_input(
    client: &RegistryClient,
    route_table: &RouteTable,
    input: &RegistrySignatureInput,
) -> Result<Option<UpstreamRoute>, RegistrySignatureReason> {
    if let Some(source) = input.source.as_deref() {
        return match lpm_lockfile::Source::parse(source) {
            Ok(lpm_lockfile::Source::Registry { url }) => {
                authorized_registry_route(client, route_table, input, &url).map(Some)
            }
            Ok(_) => Ok(None),
            Err(error) => Err(RegistrySignatureReason::InvalidSource(error.to_string())),
        };
    }
    let Some(resolved_url) = input.resolved_url.as_deref() else {
        return Ok(Some(route_table.route_for_package(&input.name)));
    };
    route_for_foreign_resolved_url(client, route_table, input, resolved_url)
}

fn is_lpm_registry_source(client: &RegistryClient, input: &RegistrySignatureInput) -> bool {
    if let Some(source) = input.source.as_deref()
        && let Ok(lpm_lockfile::Source::Registry { url }) = lpm_lockfile::Source::parse(source)
    {
        return normalized_registry_endpoint(&url)
            == normalized_registry_endpoint(client.base_url());
    }
    input
        .resolved_url
        .as_deref()
        .is_some_and(|url| url_is_below_registry(url, client.base_url()))
}

fn normalized_registry_endpoint(raw: &str) -> Option<String> {
    let mut parsed = reqwest::Url::parse(raw).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let path = parsed.path().trim_end_matches('/').to_string();
    parsed.set_path(&path);
    Some(parsed.to_string().trim_end_matches('/').to_string())
}

fn authorized_registry_route(
    client: &RegistryClient,
    route_table: &RouteTable,
    input: &RegistrySignatureInput,
    recorded_url: &str,
) -> Result<UpstreamRoute, RegistrySignatureReason> {
    let recorded = normalized_registry_endpoint(recorded_url).ok_or_else(|| {
        RegistrySignatureReason::InvalidSource("registry source has an invalid URL".into())
    })?;
    if Some(recorded.clone()) == normalized_registry_endpoint(client.base_url()) {
        return Ok(UpstreamRoute::LpmWorker);
    }
    if Some(recorded.clone()) == normalized_registry_endpoint(client.npm_registry_url()) {
        return Ok(UpstreamRoute::NpmDirect);
    }
    if let Some(configured) = route_table.custom_route_for_package_url(&input.name, &recorded) {
        return Ok(configured);
    }
    Err(RegistrySignatureReason::InvalidSource(
        "lockfile registry source is not an authorized registry route".into(),
    ))
}

fn route_for_foreign_resolved_url(
    client: &RegistryClient,
    route_table: &RouteTable,
    input: &RegistrySignatureInput,
    resolved_url: &str,
) -> Result<Option<UpstreamRoute>, RegistrySignatureReason> {
    let parsed = reqwest::Url::parse(resolved_url).map_err(|_| {
        RegistrySignatureReason::InvalidSource(
            "foreign lockfile has an invalid resolved URL".into(),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Ok(None);
    }
    if url_is_below_registry(resolved_url, client.npm_registry_url()) {
        return Ok(Some(UpstreamRoute::NpmDirect));
    }
    if let Some(configured) = route_table.custom_route_for_package_url(&input.name, resolved_url) {
        return Ok(Some(configured));
    }
    if url_is_below_registry(resolved_url, client.base_url()) {
        return Ok(Some(UpstreamRoute::LpmWorker));
    }
    Ok(None)
}

fn url_is_below_registry(candidate: &str, registry: &str) -> bool {
    let Ok(candidate) = reqwest::Url::parse(candidate) else {
        return false;
    };
    let Ok(registry) = reqwest::Url::parse(registry) else {
        return false;
    };
    if candidate.scheme() != registry.scheme()
        || candidate.host_str().map(str::to_ascii_lowercase)
            != registry.host_str().map(str::to_ascii_lowercase)
        || candidate.port_or_known_default() != registry.port_or_known_default()
    {
        return false;
    }
    let base = registry.path().trim_end_matches('/');
    if base.is_empty() {
        return true;
    }
    candidate.path() == base
        || candidate
            .path()
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(crate) async fn registry_signing_keys_for_route(
    client: &RegistryClient,
    route: &UpstreamRoute,
    signatures: &[RegistrySignature],
) -> Result<Vec<RegistrySigningKey>, LpmError> {
    match route {
        UpstreamRoute::Custom { target, auth } => {
            match client
                .get_registry_signing_keys(target.base_url.as_ref(), auth.as_deref())
                .await
            {
                Ok(mut keys) => {
                    if !registry_signatures_have_matching_key(signatures, &keys) {
                        keys.extend(
                            client
                                .get_registry_signing_keys(client.npm_registry_url(), None)
                                .await?,
                        );
                    }
                    Ok(keys)
                }
                Err(custom_error) => {
                    let npm_keys = match client
                        .get_registry_signing_keys(client.npm_registry_url(), None)
                        .await
                    {
                        Ok(keys) => keys,
                        Err(npm_error) => {
                            return Err(LpmError::Registry(format!(
                                "custom registry signing keys unavailable ({custom_error}); \
                                 npm signing-key fallback failed ({npm_error})"
                            )));
                        }
                    };
                    if registry_signatures_have_matching_key(signatures, &npm_keys) {
                        tracing::debug!(
                            target: "lpm_cli::registry_signatures",
                            custom_registry = %target.base_url,
                            error = %custom_error,
                            "custom registry signing keys unavailable; using npm public keys for npm registry signatures"
                        );
                        Ok(npm_keys)
                    } else {
                        Err(custom_error)
                    }
                }
            }
        }
        UpstreamRoute::LpmWorker | UpstreamRoute::NpmDirect => {
            client
                .get_registry_signing_keys(client.npm_registry_url(), None)
                .await
        }
    }
}

pub(crate) fn registry_signatures_have_matching_key(
    signatures: &[RegistrySignature],
    keys: &[RegistrySigningKey],
) -> bool {
    signatures
        .iter()
        .filter_map(|signature| signature.keyid.as_deref())
        .any(|keyid| keys.iter().any(|key| key.keyid == keyid))
}

fn not_verified(
    input: RegistrySignatureInput,
    reason: RegistrySignatureReason,
) -> RegistrySignaturePackageResult {
    RegistrySignaturePackageResult {
        name: input.name,
        version: input.version,
        status: RegistrySignatureStatus::NotVerified,
        reason: Some(reason),
        signatures_verified: 0,
    }
}

fn skipped(
    input: RegistrySignatureInput,
    reason: RegistrySignatureReason,
) -> RegistrySignaturePackageResult {
    RegistrySignaturePackageResult {
        name: input.name,
        version: input.version,
        status: RegistrySignatureStatus::Skipped,
        reason: Some(reason),
        signatures_verified: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn foreign_input(resolved_url: &str) -> RegistrySignatureInput {
        RegistrySignatureInput {
            name: "foreign-package".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            resolved_url: Some(resolved_url.to_string()),
            integrity: Some("sha512-test".to_string()),
            signatures: Vec::new(),
            published_at: None,
        }
    }

    #[test]
    fn unconfigured_foreign_resolved_origin_cannot_create_a_registry_route() {
        let client = RegistryClient::new();
        let routes = RouteTable::from_mode_only(lpm_registry::RouteMode::Direct);
        let input = foreign_input("http://127.0.0.1:4873/foreign-package/-/foreign-package.tgz");

        let route = route_for_input(&client, &routes, &input).unwrap();

        assert!(route.is_none());
    }

    #[test]
    fn configured_path_registry_preserves_its_authorized_base_path() {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            "registry=https://registry.example.test/npm/virtual/\n",
            "test",
            &|_| None,
        );
        let routes = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let client = RegistryClient::new();
        let input = foreign_input(
            "https://registry.example.test/npm/virtual/foreign-package/-/foreign-package.tgz",
        );

        let route = route_for_input(&client, &routes, &input).unwrap().unwrap();

        match route {
            UpstreamRoute::Custom { target, .. } => {
                assert_eq!(
                    target.base_url.as_ref(),
                    "https://registry.example.test/npm/virtual"
                )
            }
            other => panic!("expected configured custom route, got {other:?}"),
        }
    }

    #[test]
    fn configured_default_registry_authorizes_a_foreign_lpm_scope() {
        let npmrc =
            lpm_registry::NpmrcConfig::parse("registry=http://127.0.0.1:4873/\n", "test", &|_| {
                None
            });
        let routes = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let client = RegistryClient::new();
        let mut input = foreign_input(
            "http://127.0.0.1:4873/@lpm.dev/dependency-confusion/-/dependency-confusion-1.0.0.tgz",
        );
        input.name = "@lpm.dev/dependency-confusion".to_string();

        let route = route_for_input(&client, &routes, &input).unwrap().unwrap();

        assert!(matches!(route, UpstreamRoute::Custom { .. }));
    }

    #[test]
    fn sibling_path_on_the_same_origin_is_not_an_authorized_registry_route() {
        let npmrc = lpm_registry::NpmrcConfig::parse(
            "registry=https://registry.example.test/npm/virtual/\n",
            "test",
            &|_| None,
        );
        let routes = RouteTable::new(lpm_registry::RouteMode::Direct, npmrc).unwrap();
        let client = RegistryClient::new();
        let input = foreign_input(
            "https://registry.example.test/npm/other/foreign-package/-/foreign-package.tgz",
        );

        let route = route_for_input(&client, &routes, &input).unwrap();

        assert!(route.is_none());
    }

    #[tokio::test]
    async fn foreign_lpm_scoped_package_is_not_skipped_by_name_alone() {
        let result = verify_one_package(
            Arc::new(RegistryClient::new()),
            RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            RegistrySignatureInput {
                name: "@lpm.dev/dependency-confusion".to_string(),
                version: "1.0.0".to_string(),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                resolved_url: None,
                integrity: Some("sha512-test".to_string()),
                signatures: Vec::new(),
                published_at: None,
            },
            false,
            None,
        )
        .await;

        assert_eq!(result.status, RegistrySignatureStatus::NotVerified);
        assert!(matches!(
            result.reason,
            Some(RegistrySignatureReason::MissingSignatures)
        ));
    }

    #[tokio::test]
    async fn lpm_scoped_package_from_configured_lpm_registry_is_skipped() {
        let result = verify_one_package(
            Arc::new(RegistryClient::new()),
            RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            RegistrySignatureInput {
                name: "@lpm.dev/owner.package".to_string(),
                version: "1.0.0".to_string(),
                source: Some("registry+https://lpm.dev".to_string()),
                resolved_url: None,
                integrity: None,
                signatures: Vec::new(),
                published_at: None,
            },
            false,
            None,
        )
        .await;

        assert_eq!(result.status, RegistrySignatureStatus::Skipped);
        assert!(matches!(
            result.reason,
            Some(RegistrySignatureReason::LpmRegistryPackage)
        ));
    }
}
