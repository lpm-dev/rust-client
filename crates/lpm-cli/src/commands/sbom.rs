use crate::commands::manifest_metadata::graph::{
    PackageIndexes, PackageScope as ComponentScope, package_scopes_by_lockfile_index,
    selected_roots,
};
use crate::commands::manifest_metadata::{
    ManifestMetadata, extract_manifest_metadata, license_expression_from_list,
    package_artifact_key, read_installed_manifest_metadata, read_json_file,
};
use crate::commands::registry_reads::prepare_locked_read_context;
use crate::install_ui;
use crate::provenance_fetch;
use clap::ValueEnum;
use futures::stream::{self, StreamExt as _};
use lpm_common::provenance::{ProvenanceSnapshot, ProvenanceStatus};
use lpm_common::{LpmError, LpmRoot};
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_registry::RegistryClient;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::io::BufWriter;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

const CYCLONEDX_SPEC_VERSION: &str = "1.7";
const SPDX_SPEC_VERSION: &str = "SPDX-2.3";
const SBOM_SCHEMA_VERSION: u32 = 1;
const REGISTRY_ENRICHMENT_CONCURRENCY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SbomFormat {
    Cyclonedx,
    Spdx,
}

#[derive(Debug, Clone)]
struct PatchMetadata {
    path: String,
    original_integrity: String,
    patch_sha256: String,
}

#[derive(Debug, Clone)]
struct ProvenanceMetadata {
    status: &'static str,
    snapshot: Option<ProvenanceSnapshot>,
    reason: Option<String>,
}

#[derive(Debug, Clone)]
struct SbomComponent {
    package: LockedPackage,
    bom_ref: String,
    spdx_id: String,
    purl: String,
    scope: ComponentScope,
    metadata: ManifestMetadata,
    patch: Option<PatchMetadata>,
    provenance: Option<ProvenanceMetadata>,
}

#[derive(Debug)]
struct SbomDocument {
    root_name: String,
    root_version: String,
    root_metadata: ManifestMetadata,
    root_dependency_refs: Vec<String>,
    components: Vec<SbomComponent>,
    dependencies: BTreeMap<String, Vec<String>>,
    generated_at: String,
}

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    format: SbomFormat,
    output: Option<&Path>,
    registry: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    install_ui::phase_line(crate::install_ui::terminal_line!(
        "Generating {} SBOM from lpm.lock",
        install_ui::yellow(sbom_format_title(format)),
    ));

    let selected = Lockfile::read_for_project(project_dir).map_err(|e| {
        LpmError::NotFound(format!(
            "no usable lpm.lock found. Run `lpm install` before generating an SBOM: {e}"
        ))
    })?;
    let mut selected_dir = selected.path.parent().unwrap_or(project_dir).to_path_buf();
    if selected.importer != "." {
        selected_dir.push(&selected.importer);
    }
    let root_json = read_json_file(&selected_dir.join("package.json"))?;
    let document = build_document(
        client,
        &selected_dir,
        root_json,
        selected.lockfile,
        registry,
    )
    .await?;
    print_sbom_summary(project_dir, &document, format, output);
    emit_sbom(project_dir, &document, format, output)?;

    install_ui::done_untrusted(metadata_inclusion_line(&document));
    let verb = if output.is_some() { "wrote" } else { "printed" };
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · {} SBOM in {}",
        verb,
        install_ui::green(&install_ui::format_duration(start.elapsed())),
    ));
    Ok(())
}

fn sbom_format_title(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::Cyclonedx => "CycloneDX",
        SbomFormat::Spdx => "SPDX",
    }
}

fn sbom_format_id(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::Cyclonedx => "cyclonedx",
        SbomFormat::Spdx => "spdx",
    }
}

fn print_sbom_summary(
    project_dir: &Path,
    document: &SbomDocument,
    format: SbomFormat,
    output: Option<&Path>,
) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{:<8}", "packages")),
        document.components.len(),
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&format!("{:<8}", "format")),
        sbom_format_id(format),
    ));
    if let Some(path) = output {
        let display_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            project_dir.join(path)
        };
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<8}", "output")),
            install_ui::dim(&display_path.display().to_string()),
        ));
    }
    install_ui::detail("");
}

fn metadata_inclusion_line(document: &SbomDocument) -> &'static str {
    let has_patch = document
        .components
        .iter()
        .any(|component| component.patch.is_some());
    let has_provenance = document
        .components
        .iter()
        .any(|component| component.provenance.is_some());

    match (has_patch, has_provenance) {
        (true, true) => "Included patch and provenance metadata",
        (true, false) => "Included patch metadata",
        (false, true) => "Included provenance metadata",
        (false, false) => "Included lockfile metadata",
    }
}

async fn build_document(
    client: &RegistryClient,
    project_dir: &Path,
    root_json: Value,
    mut lockfile: Lockfile,
    registry: bool,
) -> Result<SbomDocument, LpmError> {
    let root_name = root_json
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| {
            project_dir
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "project".to_string());
    let root_version = root_json
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .unwrap_or("0.0.0")
        .to_string();
    let root_metadata = extract_manifest_metadata(&root_json);
    let patch_metadata = read_patch_metadata(&lockfile);
    let generated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let local_metadata = read_installed_manifest_metadata(project_dir, &lockfile, &root_json)?;
    lockfile
        .packages
        .retain(|package| !local_metadata.is_platform_skipped(package));
    let registry_metadata = if registry {
        fetch_registry_metadata(client, project_dir, &lockfile.packages).await?
    } else {
        BTreeMap::new()
    };
    let provenance_metadata = collect_provenance_metadata(
        &registry_metadata,
        &lockfile.packages,
        &lockfile.provenance,
        registry,
    )
    .await?;
    let component_scopes = package_scopes_by_lockfile_index(&root_json, &lockfile);
    let root_dependency_refs = selected_roots(
        &root_json,
        &lockfile,
        &PackageIndexes::new(&lockfile.packages),
    )
    .into_iter()
    .map(|(_, index, _)| bom_ref_for_package(&lockfile.packages[index]))
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();

    let dependencies = dependency_graph(&lockfile);
    let mut components = Vec::with_capacity(lockfile.packages.len());
    for (index, package) in lockfile.packages.into_iter().enumerate() {
        let key = package_artifact_key(&package);
        let bom_ref = bom_ref_for_package(&package);
        let mut metadata = ManifestMetadata::default();
        if let Some(local) = local_metadata.get(&package) {
            metadata.merge_missing(local.clone());
        }
        if let Some(registry) = registry_metadata.get(&key) {
            metadata.merge_missing(registry.manifest.clone());
        }

        let selector = format!("{}@{}", package.name, package.version);
        let patch = patch_metadata.get(&selector).cloned();

        components.push(SbomComponent {
            spdx_id: spdx_id_for_package(&package),
            purl: purl_for_package(&package.name, &package.version),
            provenance: provenance_metadata.get(&key).cloned(),
            package,
            bom_ref,
            scope: component_scopes[index].unwrap_or(ComponentScope::Required),
            metadata,
            patch,
        });
    }
    components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));

    Ok(SbomDocument {
        root_name,
        root_version,
        root_metadata,
        root_dependency_refs,
        components,
        dependencies,
        generated_at,
    })
}

#[derive(Debug, Clone)]
struct RegistryComponentMetadata {
    manifest: ManifestMetadata,
    attestation_ref: Option<lpm_registry::AttestationRef>,
    registry_url: String,
}

fn locked_registry_source(package: &LockedPackage) -> Option<String> {
    match package.source_kind()? {
        Ok(lpm_lockfile::Source::Registry { url }) => Some(url),
        Ok(
            lpm_lockfile::Source::Tarball { .. }
            | lpm_lockfile::Source::Directory { .. }
            | lpm_lockfile::Source::Link { .. }
            | lpm_lockfile::Source::Git { .. },
        )
        | Err(_) => None,
    }
}

async fn fetch_registry_metadata(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[LockedPackage],
) -> Result<BTreeMap<String, RegistryComponentMetadata>, LpmError> {
    let registry_packages = packages
        .iter()
        .filter(|package| locked_registry_source(package).is_some())
        .collect::<Vec<_>>();
    let destinations: BTreeSet<_> = registry_packages
        .iter()
        .filter_map(|package| {
            let url = if package.name.starts_with("@lpm.dev/") {
                client.base_url().to_string()
            } else {
                locked_registry_source(package)?
            };
            Some((url, package.name.clone()))
        })
        .collect();
    let origins: Vec<_> = destinations
        .iter()
        .filter_map(|(url, _)| lpm_registry::npmrc::OriginKey::from_request_url(url))
        .collect();
    let context = prepare_locked_read_context(client, project_dir, &origins)?;
    let mut required_versions_by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for package in &registry_packages {
        if package.name.starts_with("@lpm.dev/") {
            required_versions_by_name
                .entry(&package.name)
                .or_default()
                .push(&package.version);
        }
    }
    let fetched_results = stream::iter(destinations.into_iter().map(|(url, name)| {
        let client = &context.client;
        let route_table = &context.route_table;
        let required_versions = required_versions_by_name
            .get(name.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        async move {
            let result = if name.starts_with("@lpm.dev/") {
                match lpm_common::PackageName::parse(&name) {
                    Ok(package) => {
                        client
                            .get_package_manifest_metadata(&package, required_versions)
                            .await
                    }
                    Err(error) => Err(error),
                }
            } else {
                let destination = format!("{}/{name}", url.trim_end_matches('/'));
                client
                    .get_manifest_metadata_from(&url, &name, route_table.auth_for_url(&destination))
                    .await
            };
            (url, name, result)
        }
    }))
    .buffer_unordered(REGISTRY_ENRICHMENT_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut fetched = BTreeMap::new();
    for (url, name, result) in fetched_results {
        let metadata = result.map_err(|error| {
            LpmError::Registry(format!(
                "failed to fetch registry metadata for {name}: {error}"
            ))
        })?;
        fetched.insert((url, name), metadata);
    }
    let mut by_key = BTreeMap::new();
    for package in registry_packages {
        let key = package_artifact_key(package);
        if by_key.contains_key(&key) {
            continue;
        }
        let url = if package.name.starts_with("@lpm.dev/") {
            client.base_url().to_string()
        } else {
            locked_registry_source(package).unwrap_or_default()
        };
        let versions = fetched
            .get(&(url.clone(), package.name.clone()))
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "registry metadata was not fetched for {}",
                    package.name
                ))
            })?;
        let version = versions.get(&package.version).ok_or_else(|| {
            LpmError::Registry(format!(
                "registry metadata for {} does not include locked version {}",
                package.name, package.version
            ))
        })?;
        let value = serde_json::to_value(version)
            .map_err(|e| LpmError::Registry(format!("failed to serialize metadata: {e}")))?;
        by_key.insert(
            key,
            RegistryComponentMetadata {
                manifest: extract_manifest_metadata(&value),
                attestation_ref: version
                    .dist
                    .as_ref()
                    .and_then(|dist| dist.attestations.clone()),
                registry_url: url,
            },
        );
    }
    Ok(by_key)
}

async fn collect_provenance_metadata(
    registry_metadata: &BTreeMap<String, RegistryComponentMetadata>,
    packages: &[LockedPackage],
    locked_provenance: &BTreeMap<String, lpm_lockfile::LockedProvenance>,
    registry: bool,
) -> Result<BTreeMap<String, ProvenanceMetadata>, LpmError> {
    let mut out = BTreeMap::new();

    if registry {
        let root = match LpmRoot::from_env() {
            Ok(root) => root,
            Err(_) => return Ok(out),
        };
        let cache_root = root.cache_metadata_attestations();
        let http = crate::provenance_bundle::ProvenanceHttpClient::build().map_err(|error| {
            LpmError::Network(format!("failed to build provenance HTTP client: {error}"))
        })?;
        let mut requests = BTreeMap::new();
        for package in packages {
            if locked_registry_source(package).is_none() {
                continue;
            }
            let key = package_artifact_key(package);
            let Some(metadata) = registry_metadata.get(&key) else {
                continue;
            };
            requests.entry(key).or_insert((package, metadata));
        }
        let results = stream::iter(requests.into_iter().map(|(key, (package, metadata))| {
            let http = &http;
            let cache_root = &cache_root;
            async move {
                let status = provenance_fetch::map_fetch_result_to_status(
                    &package.name,
                    &package.version,
                    provenance_fetch::fetch_provenance_snapshot(
                        http,
                        cache_root,
                        provenance_fetch::ProvenanceFetchRequest::new(
                            &metadata.registry_url,
                            &package.name,
                            &package.version,
                            package.integrity.as_deref(),
                            metadata.attestation_ref.as_ref(),
                        ),
                        None,
                    )
                    .await,
                );
                (key, provenance_from_status(status))
            }
        }))
        .buffer_unordered(REGISTRY_ENRICHMENT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        for (key, provenance) in results {
            out.insert(key, provenance);
        }
        return Ok(out);
    }

    let mut cache_candidates = Vec::with_capacity(packages.len());
    let mut seen = BTreeSet::new();
    for package in packages {
        if !seen.insert(package_artifact_key(package)) {
            continue;
        }
        let Some(registry_source) = locked_registry_source(package) else {
            continue;
        };
        if let Some(evidence) = locked_provenance.get(&package.package_key().lockfile_id()) {
            crate::provenance_bundle::validate_locked_provenance(
                &package.name,
                &package.version,
                package.integrity.as_deref(),
                evidence,
            )?;
            out.insert(
                package_artifact_key(package),
                ProvenanceMetadata {
                    status: "verified",
                    snapshot: Some(evidence.snapshot.clone()),
                    reason: None,
                },
            );
            continue;
        }
        cache_candidates.push((package, registry_source));
    }
    if cache_candidates.is_empty() {
        return Ok(out);
    }
    let root = match LpmRoot::from_env() {
        Ok(root) => root,
        Err(_) => return Ok(out),
    };
    let cache_root = root.cache_metadata_attestations();
    for (package, registry_source) in cache_candidates {
        if let Some(snapshot) = provenance_fetch::read_cached_provenance_snapshot(
            &cache_root,
            &registry_source,
            &package.name,
            &package.version,
            package.integrity.as_deref(),
        )? {
            out.insert(
                package_artifact_key(package),
                ProvenanceMetadata {
                    status: "cached",
                    snapshot: Some(snapshot),
                    reason: None,
                },
            );
        }
    }
    Ok(out)
}

fn provenance_from_status(status: ProvenanceStatus) -> ProvenanceMetadata {
    match status {
        ProvenanceStatus::Verified(snapshot) => ProvenanceMetadata {
            status: "verified",
            snapshot: Some(snapshot),
            reason: None,
        },
        ProvenanceStatus::Unverified(snapshot) => ProvenanceMetadata {
            status: "unverified",
            snapshot: Some(snapshot),
            reason: None,
        },
        ProvenanceStatus::Disabled(snapshot) => ProvenanceMetadata {
            status: "disabled",
            snapshot: Some(snapshot),
            reason: None,
        },
        ProvenanceStatus::Absent => ProvenanceMetadata {
            status: "absent",
            snapshot: None,
            reason: None,
        },
        ProvenanceStatus::TransportDegraded => ProvenanceMetadata {
            status: "unknown",
            snapshot: None,
            reason: Some("transport_degraded".to_string()),
        },
        ProvenanceStatus::VerificationRejected { reason } => ProvenanceMetadata {
            status: "rejected",
            snapshot: None,
            reason: Some(reason),
        },
    }
}

fn read_patch_metadata(lockfile: &Lockfile) -> BTreeMap<String, PatchMetadata> {
    let mut out = BTreeMap::new();
    for (selector, patch) in &lockfile.patches {
        out.insert(
            selector.clone(),
            PatchMetadata {
                path: patch.path.clone(),
                original_integrity: patch.original_integrity.clone(),
                patch_sha256: patch.sha256.clone(),
            },
        );
    }
    out
}

struct CyclonedxDocument<'a>(&'a SbomDocument);

impl Serialize for CyclonedxDocument<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let document = self.0;
        let root_ref = "lpm:root";
        let metadata = json!({
            "timestamp": document.generated_at,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "lpm-rs",
                    "version": crate::build_version::version(),
                }]
            },
            "component": cyclonedx_root_component(document, root_ref),
            "properties": [
                property("lpm:sbom:schemaVersion", SBOM_SCHEMA_VERSION.to_string()),
                property("lpm:sbom:source", "lpm.lock"),
            ],
        });

        let mut map = serializer.serialize_map(Some(8))?;
        map.serialize_entry("$schema", "http://cyclonedx.org/schema/bom-1.7.schema.json")?;
        map.serialize_entry("bomFormat", "CycloneDX")?;
        map.serialize_entry("specVersion", CYCLONEDX_SPEC_VERSION)?;
        map.serialize_entry("serialNumber", &document_serial("cyclonedx", document))?;
        map.serialize_entry("version", &1)?;
        map.serialize_entry("metadata", &metadata)?;
        map.serialize_entry("components", &CyclonedxComponents(&document.components))?;
        map.serialize_entry("dependencies", &CyclonedxDependencies(document))?;
        map.end()
    }
}

struct CyclonedxComponents<'a>(&'a [SbomComponent]);

impl Serialize for CyclonedxComponents<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for component in self.0 {
            sequence.serialize_element(&cyclonedx_component(component))?;
        }
        sequence.end()
    }
}

struct CyclonedxDependencies<'a>(&'a SbomDocument);

impl Serialize for CyclonedxDependencies<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let document = self.0;
        let mut sequence = serializer.serialize_seq(Some(document.dependencies.len() + 1))?;
        sequence.serialize_element(&json!({
            "ref": "lpm:root",
            "dependsOn": document.root_dependency_refs,
        }))?;
        for (reference, depends_on) in &document.dependencies {
            sequence.serialize_element(&json!({
                "ref": reference,
                "dependsOn": depends_on,
            }))?;
        }
        sequence.end()
    }
}

fn cyclonedx_root_component(document: &SbomDocument, bom_ref: &str) -> Value {
    let mut component = json!({
        "type": "application",
        "bom-ref": bom_ref,
        "name": document.root_name,
        "version": document.root_version,
        "purl": purl_for_package(&document.root_name, &document.root_version),
    });
    merge_cyclonedx_metadata(&mut component, &document.root_metadata);
    component
}

fn cyclonedx_component(component: &SbomComponent) -> Value {
    let mut value = json!({
        "type": "library",
        "bom-ref": component.bom_ref,
        "name": component.package.name,
        "version": component.package.version,
        "purl": component.purl,
        "scope": component.scope.as_str(),
    });
    merge_cyclonedx_metadata(&mut value, &component.metadata);

    let mut properties = Vec::new();
    if let Some(source) = &component.package.source {
        properties.push(property("lpm:source", source));
    }
    if let Some(integrity) = &component.package.integrity {
        properties.push(property("lpm:integrity", integrity));
    }
    if let Some(tarball) = &component.package.tarball {
        add_external_reference(&mut value, "distribution", tarball);
    }
    if let Some(patch) = &component.patch {
        add_cyclonedx_patch_pedigree(&mut value, patch);
        properties.push(property("lpm:patch:path", &patch.path));
        properties.push(property(
            "lpm:patch:originalIntegrity",
            &patch.original_integrity,
        ));
        properties.push(property("lpm:patch:sha256", &patch.patch_sha256));
        properties.push(property("lpm:patched", "true"));
    }
    if let Some(provenance) = &component.provenance {
        properties.push(property("lpm:provenance:status", provenance.status));
        if let Some(reason) = &provenance.reason {
            properties.push(property("lpm:provenance:reason", reason));
        }
        if let Some(snapshot) = &provenance.snapshot {
            if let Some(publisher) = &snapshot.publisher {
                properties.push(property("lpm:provenance:publisher", publisher));
            }
            if let Some(workflow_path) = &snapshot.workflow_path {
                properties.push(property("lpm:provenance:workflowPath", workflow_path));
            }
            if let Some(workflow_ref) = &snapshot.workflow_ref {
                properties.push(property("lpm:provenance:workflowRef", workflow_ref));
            }
            if let Some(cert) = &snapshot.attestation_cert_sha256 {
                properties.push(property("lpm:provenance:attestationCertSha256", cert));
            }
        }
    }
    if !properties.is_empty()
        && let Some(object) = value.as_object_mut()
    {
        object.insert("properties".to_string(), Value::Array(properties));
    }
    value
}

fn add_cyclonedx_patch_pedigree(value: &mut Value, patch: &PatchMetadata) {
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "pedigree".to_string(),
            json!({
                "patches": [{
                    "type": "unofficial",
                    "diff": {
                        "url": &patch.path,
                    },
                }],
            }),
        );
    }
}

fn merge_cyclonedx_metadata(value: &mut Value, metadata: &ManifestMetadata) {
    {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        if let Some(description) = &metadata.description {
            object.insert(
                "description".to_string(),
                Value::String(description.clone()),
            );
        }
        if !metadata.licenses.is_empty() {
            object.insert(
                "licenses".to_string(),
                Value::Array(
                    metadata
                        .licenses
                        .iter()
                        .map(|license| json!({ "license": { "name": license } }))
                        .collect(),
                ),
            );
        }
        if let Some(author) = &metadata.author {
            object.insert("author".to_string(), Value::String(author.clone()));
        }
    }
    if let Some(homepage) = &metadata.homepage {
        add_external_reference(value, "website", homepage);
    }
    if let Some(repository) = &metadata.repository {
        add_external_reference(value, "vcs", repository);
    }
}

fn add_external_reference(value: &mut Value, kind: &str, url: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let entry = json!({
        "type": kind,
        "url": url,
    });
    match object.get_mut("externalReferences") {
        Some(Value::Array(existing)) => existing.push(entry),
        _ => {
            object.insert("externalReferences".to_string(), Value::Array(vec![entry]));
        }
    }
}

struct SpdxDocument<'a>(&'a SbomDocument);

impl Serialize for SpdxDocument<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let document = self.0;
        let components_by_ref = document
            .components
            .iter()
            .map(|component| (component.bom_ref.as_str(), component))
            .collect::<HashMap<_, _>>();
        let creation_info = json!({
            "created": document.generated_at,
            "creators": [format!("Tool: lpm-rs-{}", crate::build_version::version())],
        });

        let mut map = serializer.serialize_map(Some(8))?;
        map.serialize_entry("spdxVersion", SPDX_SPEC_VERSION)?;
        map.serialize_entry("dataLicense", "CC0-1.0")?;
        map.serialize_entry("SPDXID", "SPDXRef-DOCUMENT")?;
        map.serialize_entry("name", &document.root_name)?;
        map.serialize_entry("documentNamespace", &document_namespace(document))?;
        map.serialize_entry("creationInfo", &creation_info)?;
        map.serialize_entry("packages", &SpdxPackages(document))?;
        map.serialize_entry(
            "relationships",
            &SpdxRelationships {
                document,
                components_by_ref: &components_by_ref,
            },
        )?;
        map.end()
    }
}

struct SpdxPackages<'a>(&'a SbomDocument);

impl Serialize for SpdxPackages<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let document = self.0;
        let mut sequence = serializer.serialize_seq(Some(document.components.len() + 1))?;
        sequence.serialize_element(&spdx_root_package(document, "SPDXRef-RootPackage"))?;
        for component in &document.components {
            sequence.serialize_element(&spdx_package(component))?;
        }
        sequence.end()
    }
}

struct SpdxRelationships<'a> {
    document: &'a SbomDocument,
    components_by_ref: &'a HashMap<&'a str, &'a SbomComponent>,
}

impl Serialize for SpdxRelationships<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let root_spdx_id = "SPDXRef-RootPackage";
        let mut sequence = serializer.serialize_seq(None)?;
        sequence.serialize_element(&json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_spdx_id,
        }))?;
        for dependency in &self.document.root_dependency_refs {
            if let Some(component) = self.components_by_ref.get(dependency.as_str()) {
                sequence.serialize_element(&json!({
                    "spdxElementId": root_spdx_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": component.spdx_id,
                }))?;
            }
        }
        for (reference, depends_on) in &self.document.dependencies {
            let Some(component) = self.components_by_ref.get(reference.as_str()) else {
                continue;
            };
            for dependency in depends_on {
                if let Some(target) = self.components_by_ref.get(dependency.as_str()) {
                    sequence.serialize_element(&json!({
                        "spdxElementId": component.spdx_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target.spdx_id,
                    }))?;
                }
            }
        }
        sequence.end()
    }
}

fn spdx_root_package(document: &SbomDocument, spdx_id: &str) -> Value {
    let mut package = json!({
        "name": document.root_name,
        "SPDXID": spdx_id,
        "versionInfo": document.root_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": license_declared(&document.root_metadata),
        "licenseDeclared": license_declared(&document.root_metadata),
        "copyrightText": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl_for_package(&document.root_name, &document.root_version),
        }],
    });
    add_spdx_license_comments(&mut package, &document.root_metadata);
    package
}

fn spdx_package(component: &SbomComponent) -> Value {
    let mut package = json!({
        "name": component.package.name,
        "SPDXID": component.spdx_id,
        "versionInfo": component.package.version,
        "downloadLocation": component.package.tarball.as_deref().unwrap_or("NOASSERTION"),
        "filesAnalyzed": false,
        "licenseConcluded": license_declared(&component.metadata),
        "licenseDeclared": license_declared(&component.metadata),
        "copyrightText": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": component.purl,
        }],
    });
    if let Some(description) = &component.metadata.description
        && let Some(object) = package.as_object_mut()
    {
        object.insert(
            "description".to_string(),
            Value::String(description.clone()),
        );
    }
    add_spdx_license_comments(&mut package, &component.metadata);
    let attribution = spdx_attribution(component);
    if !attribution.is_empty()
        && let Some(object) = package.as_object_mut()
    {
        object.insert(
            "attributionTexts".to_string(),
            Value::Array(attribution.into_iter().map(Value::String).collect()),
        );
    }
    package
}

fn spdx_attribution(component: &SbomComponent) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(source) = &component.package.source {
        out.push(format!("lpm:source={source}"));
    }
    if let Some(integrity) = &component.package.integrity {
        out.push(format!("lpm:integrity={integrity}"));
    }
    if let Some(patch) = &component.patch {
        out.push(format!("lpm:patch:path={}", patch.path));
        out.push(format!(
            "lpm:patch:originalIntegrity={}",
            patch.original_integrity
        ));
        out.push(format!("lpm:patch:sha256={}", patch.patch_sha256));
    }
    if let Some(provenance) = &component.provenance {
        out.push(format!("lpm:provenance:status={}", provenance.status));
        if let Some(snapshot) = &provenance.snapshot {
            if let Some(publisher) = &snapshot.publisher {
                out.push(format!("lpm:provenance:publisher={publisher}"));
            }
            if let Some(workflow_path) = &snapshot.workflow_path {
                out.push(format!("lpm:provenance:workflowPath={workflow_path}"));
            }
        }
    }
    out
}

fn dependency_graph(lockfile: &Lockfile) -> BTreeMap<String, Vec<String>> {
    let refs: Vec<_> = lockfile.packages.iter().map(bom_ref_for_package).collect();
    crate::commands::manifest_metadata::graph::package_adjacency(
        &lockfile.packages,
        &PackageIndexes::new(&lockfile.packages),
    )
    .into_iter()
    .enumerate()
    .map(|(index, targets)| {
        let edges = targets
            .into_iter()
            .map(|target| refs[target].clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        (refs[index].clone(), edges)
    })
    .collect()
}

fn purl_for_package(name: &str, version: &str) -> String {
    lpm_common::npm_package_purl(name, version)
}

fn bom_ref_for_package(package: &LockedPackage) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package.name.as_bytes());
    hasher.update([0]);
    hasher.update(package.version.as_bytes());
    hasher.update([0]);
    hasher.update(package.source.as_deref().unwrap_or("").as_bytes());
    if let Some(instance_id) = package.instance_id {
        hasher.update([0]);
        hasher.update(instance_id.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!(
        "lpm:component:{}@{}:{}",
        sanitize_ref_fragment(&package.name),
        sanitize_ref_fragment(&package.version),
        &digest[..16]
    )
}

fn spdx_id_for_package(package: &LockedPackage) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package.name.as_bytes());
    hasher.update([0]);
    hasher.update(package.version.as_bytes());
    hasher.update([0]);
    hasher.update(package.source.as_deref().unwrap_or("").as_bytes());
    if let Some(instance_id) = package.instance_id {
        hasher.update([0]);
        hasher.update(instance_id.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!(
        "SPDXRef-Package-{}-{}-{}",
        sanitize_ref_fragment(&package.name),
        sanitize_ref_fragment(&package.version),
        &digest[..12]
    )
}

fn sanitize_ref_fragment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

fn license_declared(metadata: &ManifestMetadata) -> String {
    let expression = license_expression_from_list(&metadata.licenses);
    if expression == "NONE"
        || expression == "NOASSERTION"
        || spdx::Expression::parse(&expression).is_ok_and(|parsed| {
            parsed
                .requirements()
                .all(|requirement| requirement.req.license.id().is_some())
        })
    {
        expression
    } else {
        "NOASSERTION".to_string()
    }
}

fn add_spdx_license_comments(value: &mut Value, metadata: &ManifestMetadata) {
    if !metadata.licenses.is_empty() && license_declared(metadata) == "NOASSERTION" {
        value["licenseComments"] = Value::String(format!(
            "Package manifest declarations: {}",
            metadata.licenses.join("; ")
        ));
    }
}

fn property(name: &str, value: impl ToString) -> Value {
    json!({
        "name": name,
        "value": value.to_string(),
    })
}

fn document_serial(kind: &str, document: &SbomDocument) -> String {
    format!("urn:uuid:{}", pseudo_uuid(kind, document))
}

fn document_namespace(document: &SbomDocument) -> String {
    format!(
        "https://lpm.dev/sbom/{}/{}",
        sanitize_ref_fragment(&document.root_name),
        pseudo_uuid("spdx", document)
    )
}

fn pseudo_uuid(kind: &str, document: &SbomDocument) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(document.root_name.as_bytes());
    hasher.update([0]);
    hasher.update(document.root_version.as_bytes());
    for component in &document.components {
        hasher.update([0]);
        hasher.update(component.bom_ref.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn emit_sbom(
    project_dir: &Path,
    document: &SbomDocument,
    format: SbomFormat,
    output: Option<&Path>,
) -> Result<(), LpmError> {
    if let Some(path) = output {
        let output_path = normalized_output_path(project_dir, path)?;
        let (directory, file_name) = open_output_parent(&output_path)?;
        let file = open_output_file_nofollow(&directory, &file_name)?;
        write_sbom_json(BufWriter::new(file), document, format)?;
    } else {
        let stdout = std::io::stdout();
        write_sbom_json(BufWriter::new(stdout.lock()), document, format)?;
    }
    Ok(())
}

fn write_sbom_json(
    mut writer: impl std::io::Write,
    document: &SbomDocument,
    format: SbomFormat,
) -> Result<(), LpmError> {
    let result = match format {
        SbomFormat::Cyclonedx => {
            serde_json::to_writer_pretty(&mut writer, &CyclonedxDocument(document))
        }
        SbomFormat::Spdx => serde_json::to_writer_pretty(&mut writer, &SpdxDocument(document)),
    };
    result.map_err(|error| LpmError::Registry(format!("failed to serialize SBOM: {error}")))?;
    std::io::Write::write_all(&mut writer, b"\n").map_err(LpmError::Io)?;
    std::io::Write::flush(&mut writer).map_err(LpmError::Io)
}

fn normalized_output_path(project_dir: &Path, output: &Path) -> Result<PathBuf, LpmError> {
    let path = if output.is_absolute() {
        output.to_path_buf()
    } else {
        project_dir.join(output)
    };
    if !path.is_absolute() {
        return Err(LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SBOM output path is not absolute: {}", path.display()),
        )));
    }

    let mut normalized = PathBuf::with_capacity(path.as_os_str().len());
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(LpmError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "SBOM output escapes the filesystem root: {}",
                            path.display()
                        ),
                    )));
                }
            }
        }
    }
    Ok(normalized)
}

fn open_output_parent(path: &Path) -> Result<(cap_std::fs::Dir, OsString), LpmError> {
    use cap_fs_ext::DirExt as _;

    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SBOM output has no file name: {}", path.display()),
            ))
        })?
        .to_os_string();
    let parent_path = path.parent().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SBOM output has no parent: {}", path.display()),
        ))
    })?;
    let root = parent_path
        .ancestors()
        .last()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .ok_or_else(|| {
            LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SBOM output has no filesystem root: {}", path.display()),
            ))
        })?;
    let mut directory = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
        .map_err(LpmError::Io)?;
    let relative_parent = parent_path.strip_prefix(root).map_err(|error| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid SBOM output parent {}: {error}",
                parent_path.display()
            ),
        ))
    })?;
    for component in relative_parent.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe SBOM output parent: {}", parent_path.display()),
            )));
        };
        directory = match directory.open_dir_nofollow(name) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match directory.create_dir(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(LpmError::Io(error)),
                }
                directory.open_dir_nofollow(name).map_err(LpmError::Io)?
            }
            Err(error) => return Err(LpmError::Io(error)),
        };
        let metadata = directory.dir_metadata().map_err(LpmError::Io)?;
        if !metadata.is_dir() || capability_metadata_is_link_or_reparse(&metadata) {
            return Err(LpmError::Io(std::io::Error::other(format!(
                "refusing linked SBOM output parent at {}",
                parent_path.display()
            ))));
        }
    }
    Ok((directory, file_name))
}

fn open_output_file_nofollow(
    directory: &cap_std::fs::Dir,
    file_name: &std::ffi::OsStr,
) -> Result<cap_std::fs::File, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = directory
        .open_with(file_name, &options)
        .map_err(LpmError::Io)?;
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_file() || capability_metadata_is_link_or_reparse(&metadata) {
        return Err(LpmError::Io(std::io::Error::other(
            "refusing SBOM output that is not a regular file",
        )));
    }
    file.set_len(0).map_err(LpmError::Io)?;
    Ok(file)
}

#[cfg(not(windows))]
fn capability_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.is_symlink()
}

#[cfg(windows)]
fn capability_metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_encodes_scoped_npm_names() {
        assert_eq!(
            purl_for_package("@scope/pkg", "1.2.3"),
            "pkg:npm/%40scope/pkg@1.2.3"
        );
    }

    #[test]
    fn manifest_metadata_extracts_common_package_json_shapes() {
        let value = json!({
            "description": "demo",
            "license": { "type": "MIT" },
            "licenses": ["Apache-2.0"],
            "homepage": "https://example.test",
            "repository": { "url": "git+https://example.test/repo.git" },
            "author": { "name": "Alice" }
        });

        let metadata = extract_manifest_metadata(&value);
        assert_eq!(metadata.description.as_deref(), Some("demo"));
        assert_eq!(
            metadata.licenses,
            vec!["Apache-2.0".to_string(), "MIT".to_string()]
        );
        assert_eq!(metadata.homepage.as_deref(), Some("https://example.test"));
        assert_eq!(
            metadata.repository.as_deref(),
            Some("git+https://example.test/repo.git")
        );
        assert_eq!(metadata.author.as_deref(), Some("Alice"));
    }
}
