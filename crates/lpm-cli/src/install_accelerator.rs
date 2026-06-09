use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use lpm_common::LpmError;
use lpm_registry::{
    InstallAcceleratorCapability, InstallAcceleratorPlanOptions, InstallAcceleratorPlanRequest,
    InstallAcceleratorStoreBundleIndex, InstallAcceleratorStoreBundlePackage,
    InstallAcceleratorStoreBundleRequest, PackageMetadata, RegistryClient, RouteTable,
};
use lpm_store::PackageStore;

#[derive(Debug, Clone)]
pub(crate) struct AcceleratedInstall {
    capability: InstallAcceleratorCapability,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AcceleratedPlanStats {
    pub requested: bool,
    pub plan_used: bool,
    pub skipped_reason: Option<&'static str>,
    pub plan_ms: u128,
    pub metadata_count: usize,
    pub seeded_metadata_count: usize,
    pub store_candidate_count: usize,
    pub store_candidate_hits: usize,
    pub store_candidate_misses: usize,
    pub store_candidate_unknown: usize,
    pub unsupported_spec_count: u32,
    pub truncated: bool,
    pub speculation_frames_sent: usize,
    pub store_bundle_used: bool,
    pub store_bundle_ms: u128,
    pub store_bundle_bytes: usize,
    pub store_bundle_requested_count: usize,
    pub store_bundle_bundled_count: usize,
    pub store_bundle_hydrated_count: usize,
    pub store_bundle_skipped_count: usize,
    pub store_bundle_truncated: bool,
}

pub(crate) struct AcceleratedPlanResult {
    pub packages: HashMap<String, PackageMetadata>,
    pub stats: AcceleratedPlanStats,
}

pub(crate) async fn prepare_project_install(
    client: &RegistryClient,
    project_dir: &Path,
    offline: bool,
    accelerated: bool,
) -> Result<Option<AcceleratedInstall>, LpmError> {
    if !accelerated {
        return Ok(None);
    }

    if offline {
        return Err(LpmError::Script(
            "`--accelerated` cannot be combined with `--offline`; accelerated installs require the LPM control plane."
                .into(),
        ));
    }

    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;
    if route_table.has_custom_registries() {
        return Err(LpmError::Script(
            "`--accelerated` does not support custom `.npmrc` registries yet. Run without `--accelerated` to keep custom registry resolution and credentials local."
                .into(),
        ));
    }

    if !client.has_auth_bearer() {
        return Err(LpmError::AuthRequired);
    }

    let capability = match client.install_accelerator_capability().await {
        Ok(capability) => capability,
        Err(LpmError::NotFound(_)) => {
            return Err(LpmError::Script(
                "`--accelerated` is not available on this registry deployment yet. Run without `--accelerated` to use the local installer."
                    .into(),
            ));
        }
        Err(error) => return Err(error),
    };

    if !capability.enabled {
        return Err(LpmError::Script(
            "`--accelerated` is not enabled for this account or registry deployment. Run without `--accelerated` to use the local installer."
                .into(),
        ));
    }

    if capability.protocol_version != 1 {
        return Err(LpmError::Script(format!(
            "`--accelerated` protocol v{} is not supported by this client build. Run without `--accelerated` to use the local installer.",
            capability.protocol_version
        )));
    }

    if !capability.features.graph_plan {
        return Err(execution_not_wired_error(&capability));
    }

    Ok(Some(AcceleratedInstall { capability }))
}

fn execution_not_wired_error(capability: &InstallAcceleratorCapability) -> LpmError {
    let source = capability
        .entitlement_source
        .as_deref()
        .unwrap_or("unknown entitlement");
    LpmError::Script(format!(
        "`--accelerated` capability is reachable (protocol v{}, {source}), but graph/store-diff execution is not wired in this client build yet. Run without `--accelerated` to use the local installer.",
        capability.protocol_version
    ))
}

impl AcceleratedInstall {
    pub(crate) fn requested_stats(&self) -> AcceleratedPlanStats {
        AcceleratedPlanStats {
            requested: true,
            ..AcceleratedPlanStats::default()
        }
    }

    pub(crate) async fn fetch_plan(
        &self,
        client: &RegistryClient,
        dependencies: &HashMap<String, String>,
        include_optional: bool,
        store: &PackageStore,
        store_v2: Option<&lpm_store::v2::Store>,
    ) -> Result<AcceleratedPlanResult, LpmError> {
        let started = Instant::now();
        let request = InstallAcceleratorPlanRequest {
            dependencies: dependencies.clone(),
            options: InstallAcceleratorPlanOptions {
                include_optional: false,
                include_peers: true,
                max_packages: self.capability.limits.max_packages,
                max_depth: Some(8),
            },
        };
        let _ = include_optional;

        let plan = client.install_accelerator_plan(&request).await?;
        if plan.protocol_version != 1 || plan.mode != "metadata-prefetch" {
            return Err(LpmError::Script(
                "`--accelerated` returned an unsupported plan. Run without `--accelerated` to use the local installer."
                    .into(),
            ));
        }

        let mut stats = AcceleratedPlanStats {
            requested: true,
            plan_used: true,
            plan_ms: started.elapsed().as_millis(),
            metadata_count: plan.packages.len(),
            store_candidate_count: plan.store.candidates.len(),
            unsupported_spec_count: plan.graph.unsupported_spec_count,
            truncated: plan.graph.truncated,
            ..AcceleratedPlanStats::default()
        };

        for candidate in &plan.store.candidates {
            match candidate_cached(candidate, store, store_v2) {
                Some(true) => stats.store_candidate_hits += 1,
                Some(false) => stats.store_candidate_misses += 1,
                None => stats.store_candidate_unknown += 1,
            }
        }

        Ok(AcceleratedPlanResult {
            packages: plan.packages,
            stats,
        })
    }

    pub(crate) async fn hydrate_store_bundle(
        &self,
        client: &RegistryClient,
        packages: Vec<InstallAcceleratorStoreBundlePackage>,
        store_v2: &lpm_store::v2::Store,
    ) -> Result<AcceleratedStoreBundleStats, LpmError> {
        let mut stats = AcceleratedStoreBundleStats {
            requested_count: packages.len(),
            ..AcceleratedStoreBundleStats::default()
        };

        if packages.is_empty() {
            return Ok(stats);
        }

        if !self.capability.features.store_diff {
            stats.skipped_count = packages.len();
            return Ok(stats);
        }

        let started = Instant::now();
        let request = InstallAcceleratorStoreBundleRequest {
            protocol_version: 1,
            packages,
        };
        let bundle = client.install_accelerator_store_bundle(&request).await?;
        stats.bundle_bytes = bundle.len();

        let store_for_apply = store_v2.clone();
        let applied = tokio::task::spawn_blocking(move || {
            apply_store_bundle_bytes(&store_for_apply, &bundle)
        })
        .await
        .map_err(|e| LpmError::Registry(format!("store bundle apply task failed: {e}")))??;
        stats.bundle_ms = started.elapsed().as_millis();
        stats.used = applied.hydrated_count > 0;
        stats.bundled_count = applied.index.bundled_count as usize;
        stats.hydrated_count = applied.hydrated_count;
        stats.skipped_count = applied.index.skipped_count as usize;
        stats.truncated = applied.index.truncated;
        Ok(stats)
    }
}

impl AcceleratedPlanStats {
    pub(crate) fn merge_store_bundle(&mut self, bundle: AcceleratedStoreBundleStats) {
        self.store_bundle_used = bundle.used;
        self.store_bundle_ms = bundle.bundle_ms;
        self.store_bundle_bytes = bundle.bundle_bytes;
        self.store_bundle_requested_count = bundle.requested_count;
        self.store_bundle_bundled_count = bundle.bundled_count;
        self.store_bundle_hydrated_count = bundle.hydrated_count;
        self.store_bundle_skipped_count = bundle.skipped_count;
        self.store_bundle_truncated = bundle.truncated;
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "requested": self.requested,
            "plan_used": self.plan_used,
            "skipped_reason": self.skipped_reason,
            "plan_ms": self.plan_ms,
            "metadata_count": self.metadata_count,
            "seeded_metadata_count": self.seeded_metadata_count,
            "store_candidate_count": self.store_candidate_count,
            "store_candidate_hits": self.store_candidate_hits,
            "store_candidate_misses": self.store_candidate_misses,
            "store_candidate_unknown": self.store_candidate_unknown,
            "unsupported_spec_count": self.unsupported_spec_count,
            "truncated": self.truncated,
            "speculation_frames_sent": self.speculation_frames_sent,
            "store_bundle_used": self.store_bundle_used,
            "store_bundle_ms": self.store_bundle_ms,
            "store_bundle_bytes": self.store_bundle_bytes,
            "store_bundle_requested_count": self.store_bundle_requested_count,
            "store_bundle_bundled_count": self.store_bundle_bundled_count,
            "store_bundle_hydrated_count": self.store_bundle_hydrated_count,
            "store_bundle_skipped_count": self.store_bundle_skipped_count,
            "store_bundle_truncated": self.store_bundle_truncated,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AcceleratedStoreBundleStats {
    pub used: bool,
    pub bundle_ms: u128,
    pub bundle_bytes: usize,
    pub requested_count: usize,
    pub bundled_count: usize,
    pub hydrated_count: usize,
    pub skipped_count: usize,
    pub truncated: bool,
}

#[derive(Debug)]
struct StoreBundleApplyResult {
    index: InstallAcceleratorStoreBundleIndex,
    hydrated_count: usize,
}

fn apply_store_bundle_bytes(
    store_v2: &lpm_store::v2::Store,
    bundle: &[u8],
) -> Result<StoreBundleApplyResult, LpmError> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bundle));
    let mut entries = archive
        .entries()
        .map_err(|e| LpmError::Registry(format!("invalid accelerator store bundle: {e}")))?;

    let Some(first) = entries.next() else {
        return Err(LpmError::Registry(
            "accelerator store bundle was empty".into(),
        ));
    };
    let mut first =
        first.map_err(|e| LpmError::Registry(format!("invalid store bundle entry: {e}")))?;
    let first_path = bundle_entry_path(&first)?;
    if first_path != "index.json" {
        return Err(LpmError::Registry(
            "accelerator store bundle missing leading index.json".into(),
        ));
    }

    let mut index_bytes = Vec::with_capacity(first.header().size().unwrap_or(0) as usize);
    first
        .read_to_end(&mut index_bytes)
        .map_err(|e| LpmError::Registry(format!("failed to read store bundle index: {e}")))?;
    let index: InstallAcceleratorStoreBundleIndex = serde_json::from_slice(&index_bytes)
        .map_err(|e| LpmError::Registry(format!("failed to parse store bundle index: {e}")))?;
    validate_store_bundle_index(&index)?;

    let mut by_path = HashMap::with_capacity(index.objects.len());
    for object in &index.objects {
        validate_store_bundle_object_path(&object.path)?;
        if by_path.insert(object.path.clone(), object).is_some() {
            return Err(LpmError::Registry(format!(
                "duplicate object path in store bundle index: {}",
                object.path
            )));
        }
    }

    let mut seen = HashSet::with_capacity(index.objects.len());
    let mut objects_to_extract = Vec::with_capacity(index.objects.len());
    for entry in entries {
        let mut entry =
            entry.map_err(|e| LpmError::Registry(format!("invalid store bundle entry: {e}")))?;
        let path = bundle_entry_path(&entry)?;
        let Some(object) = by_path.get(path.as_str()) else {
            return Err(LpmError::Registry(format!(
                "unexpected object in accelerator store bundle: {path}"
            )));
        };
        if !seen.insert(path.clone()) {
            return Err(LpmError::Registry(format!(
                "duplicate object entry in accelerator store bundle: {path}"
            )));
        }

        let declared_size = entry.header().size().map_err(|e| {
            LpmError::Registry(format!("failed to read store bundle entry size: {e}"))
        })?;
        if object.bytes > 0 && object.bytes != declared_size {
            return Err(LpmError::Registry(format!(
                "store bundle object {} size mismatch: index={} actual={declared_size}",
                object.path, object.bytes
            )));
        }

        let mut bytes = Vec::with_capacity(declared_size as usize);
        entry.read_to_end(&mut bytes).map_err(|e| {
            LpmError::Registry(format!(
                "failed to read store bundle object {}: {e}",
                object.path
            ))
        })?;
        objects_to_extract.push(((*object).clone(), bytes));
    }

    if objects_to_extract.len() != index.objects.len() {
        return Err(LpmError::Registry(format!(
            "store bundle object count mismatch: index={} actual={}",
            index.objects.len(),
            objects_to_extract.len()
        )));
    }

    use rayon::prelude::*;
    objects_to_extract
        .par_iter()
        .try_for_each(|(object, bytes)| {
            store_v2
                .extract_object_from_bytes(bytes, Some(&object.integrity))
                .map(|_| ())
        })?;

    Ok(StoreBundleApplyResult {
        index,
        hydrated_count: objects_to_extract.len(),
    })
}

fn validate_store_bundle_index(index: &InstallAcceleratorStoreBundleIndex) -> Result<(), LpmError> {
    if index.protocol_version != 1 || index.mode != "lockfile-v2-store-bundle" {
        return Err(LpmError::Registry(
            "accelerator returned an unsupported store bundle".into(),
        ));
    }
    Ok(())
}

fn validate_store_bundle_object_path(path: &str) -> Result<(), LpmError> {
    let valid = path.starts_with("objects/")
        && !path.contains("..")
        && !path.contains('\\')
        && path.len() > "objects/".len();
    if valid {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "invalid object path in accelerator store bundle: {path}"
        )))
    }
}

fn bundle_entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, LpmError> {
    let path = entry
        .path()
        .map_err(|e| LpmError::Registry(format!("invalid store bundle entry path: {e}")))?;
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| LpmError::Registry("non-UTF8 path in store bundle".into()))
}

fn candidate_cached(
    candidate: &lpm_registry::InstallAcceleratorStoreCandidate,
    store: &PackageStore,
    store_v2: Option<&lpm_store::v2::Store>,
) -> Option<bool> {
    match store_v2 {
        Some(v2) => candidate.integrity.as_deref().map(|sri| v2.has_object(sri)),
        None => Some(store.has_package(&candidate.name, &candidate.version)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"accelerator-gate","version":"0.0.0"}"#,
        )
        .expect("write package.json");
        dir
    }

    #[tokio::test]
    async fn accelerated_install_gate_ignores_disabled_flag() {
        let dir = temp_project();
        let client = RegistryClient::new();

        let result = prepare_project_install(&client, dir.path(), true, false)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn accelerated_install_rejects_offline_before_auth() {
        let dir = temp_project();
        let client = RegistryClient::new();

        let error = prepare_project_install(&client, dir.path(), true, true)
            .await
            .unwrap_err();

        match error {
            LpmError::Script(message) => {
                assert!(message.contains("`--accelerated`"));
                assert!(message.contains("`--offline`"));
            }
            other => panic!("expected Script error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accelerated_install_rejects_custom_npmrc_registries() {
        let dir = temp_project();
        std::fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.internal.example/\n",
        )
        .expect("write .npmrc");
        let client = RegistryClient::new();

        let error = prepare_project_install(&client, dir.path(), false, true)
            .await
            .unwrap_err();

        match error {
            LpmError::Script(message) => {
                assert!(message.contains("custom `.npmrc` registries"));
            }
            other => panic!("expected Script error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accelerated_install_requires_auth_before_capability_lookup() {
        let dir = temp_project();
        let client = RegistryClient::new();

        let error = prepare_project_install(&client, dir.path(), false, true)
            .await
            .unwrap_err();

        assert!(matches!(error, LpmError::AuthRequired));
    }

    #[test]
    fn store_bundle_hydration_extracts_verified_v2_objects() {
        let store_root = tempfile::tempdir().expect("store root");
        let store = lpm_store::v2::Store::at(store_root.path());
        let tarball = create_package_tarball("bundled", "1.0.0");
        let sri = lpm_store::compute_sri_hash(&tarball);
        let bundle = create_store_bundle(
            serde_json::json!({
                "protocolVersion": 1,
                "mode": "lockfile-v2-store-bundle",
                "requestedCount": 1,
                "bundledCount": 1,
                "skippedCount": 0,
                "truncated": false,
                "objects": [{
                    "name": "bundled",
                    "version": "1.0.0",
                    "source": "registry+https://registry.npmjs.org",
                    "integrity": sri,
                    "tarballUrl": "https://registry.npmjs.org/bundled/-/bundled-1.0.0.tgz",
                    "path": "objects/0.tgz",
                    "bytes": tarball.len()
                }],
                "skipped": []
            }),
            &[("objects/0.tgz", &tarball)],
        );

        let result = apply_store_bundle_bytes(&store, &bundle).expect("bundle applies");

        assert_eq!(result.hydrated_count, 1);
        assert!(store.has_object(&sri));
    }

    #[test]
    fn store_bundle_hydration_rejects_integrity_mismatches() {
        let store_root = tempfile::tempdir().expect("store root");
        let store = lpm_store::v2::Store::at(store_root.path());
        let tarball = create_package_tarball("tampered", "1.0.0");
        let actual_sri = lpm_store::compute_sri_hash(&tarball);
        let wrong_sri = lpm_store::compute_sri_hash(b"different bytes");
        let bundle = create_store_bundle(
            serde_json::json!({
                "protocolVersion": 1,
                "mode": "lockfile-v2-store-bundle",
                "requestedCount": 1,
                "bundledCount": 1,
                "skippedCount": 0,
                "truncated": false,
                "objects": [{
                    "name": "tampered",
                    "version": "1.0.0",
                    "source": "registry+https://registry.npmjs.org",
                    "integrity": wrong_sri,
                    "tarballUrl": "https://registry.npmjs.org/tampered/-/tampered-1.0.0.tgz",
                    "path": "objects/0.tgz",
                    "bytes": tarball.len()
                }],
                "skipped": []
            }),
            &[("objects/0.tgz", &tarball)],
        );

        let error = apply_store_bundle_bytes(&store, &bundle).expect_err("bundle must fail");

        assert!(matches!(error, LpmError::IntegrityMismatch { .. }));
        assert!(!store.has_object(&actual_sri));
        assert!(!store.has_object(&wrong_sri));
    }

    fn create_package_tarball(name: &str, version: &str) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            append_tar_entry(&mut builder, "package/package.json", manifest.as_bytes());
            append_tar_entry(&mut builder, "package/index.js", b"module.exports = 1\n");
            builder.finish().expect("finish package tar");
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).expect("gzip package tar");
        encoder.finish().expect("finish gzip")
    }

    fn create_store_bundle(index: serde_json::Value, entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let index_bytes = serde_json::to_vec(&index).expect("encode index");
            append_tar_entry(&mut builder, "index.json", &index_bytes);
            for (path, bytes) in entries {
                append_tar_entry(&mut builder, path, bytes);
            }
            builder.finish().expect("finish store bundle");
        }
        tar_data
    }

    fn append_tar_entry<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        path: &str,
        bytes: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, std::io::Cursor::new(bytes))
            .expect("append tar entry");
    }
}
