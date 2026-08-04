use crate::commands::manifest_metadata::{
    ManifestMetadata, extract_manifest_metadata, package_metadata_key, read_json_file,
    read_local_metadata,
};
use crate::commands::registry_reads::{
    RoutedPackageRef, RoutedReadContext, fetch_routed_package_metadata, prepare_routed_read_context,
};
use crate::install_ui;
use crate::provenance_fetch;
use clap::ValueEnum;
use lpm_common::provenance::{ProvenanceSnapshot, ProvenanceStatus};
use lpm_common::{LpmError, LpmRoot};
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_registry::{RegistryClient, UpstreamRoute};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

const CYCLONEDX_SPEC_VERSION: &str = "1.7";
const SPDX_SPEC_VERSION: &str = "SPDX-2.3";
const SBOM_SCHEMA_VERSION: u32 = 1;

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
    scope: &'static str,
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

    let lockfile = Lockfile::read_for_project(project_dir)
        .map_err(|e| {
            LpmError::NotFound(format!(
                "no usable lpm.lock found. Run `lpm install` before generating an SBOM: {e}"
            ))
        })?
        .lockfile;
    let package_json_path = project_dir.join("package.json");
    let root_json = read_json_file(&package_json_path)?;
    let document = build_document(client, project_dir, root_json, lockfile, registry).await?;
    print_sbom_summary(project_dir, &document, format, output);
    let value = match format {
        SbomFormat::Cyclonedx => render_cyclonedx(&document),
        SbomFormat::Spdx => render_spdx(&document),
    };
    emit_sbom(&value, output)?;

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
    lockfile: Lockfile,
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
    let direct_scopes = root_dependency_scopes(&root_json);
    let generated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let local_metadata = read_local_metadata(project_dir, &lockfile.packages)?;
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

    let mut source_index: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for package in &lockfile.packages {
        let bom_ref = bom_ref_for_package(package);
        source_index
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(bom_ref);
    }
    for refs in source_index.values_mut() {
        refs.sort();
    }

    let mut components = Vec::with_capacity(lockfile.packages.len());
    let mut component_refs = BTreeSet::new();
    for package in lockfile.packages {
        let key = package_metadata_key(&package);
        let bom_ref = bom_ref_for_package(&package);
        component_refs.insert(bom_ref.clone());
        let mut metadata = ManifestMetadata::default();
        if let Some(local) = local_metadata.get(&key) {
            metadata.merge_missing(local.clone());
        }
        if let Some(registry) = registry_metadata.get(&key) {
            metadata.merge_missing(registry.manifest.clone());
        }

        let selector = format!("{}@{}", package.name, package.version);
        let patch = patch_metadata.get(&selector).cloned();
        let scope = direct_scopes
            .get(&package.name)
            .copied()
            .unwrap_or("required");

        components.push(SbomComponent {
            spdx_id: spdx_id_for_package(&package),
            purl: purl_for_package(&package.name, &package.version),
            provenance: provenance_metadata.get(&key).cloned(),
            package,
            bom_ref,
            scope,
            metadata,
            patch,
        });
    }
    components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));

    let root_dependency_refs = root_dependency_refs(&root_json, &source_index);
    let dependencies = dependency_graph(&components, &source_index, &component_refs);

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

fn attestation_registry_url(
    context: &RoutedReadContext,
    package_name: &str,
    routed_package: &RoutedPackageRef,
) -> String {
    match routed_package {
        RoutedPackageRef::Lpm(_) => context.client.base_url().to_string(),
        RoutedPackageRef::Registry(_) => {
            match context.route_table.route_for_package(package_name) {
                UpstreamRoute::Custom { target, .. } => target.base_url.as_ref().to_string(),
                UpstreamRoute::LpmWorker | UpstreamRoute::NpmDirect => {
                    context.client.npm_registry_url().to_string()
                }
            }
        }
    }
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
    let names = registry_packages
        .iter()
        .map(|package| package.name.clone())
        .collect::<Vec<_>>();
    let context = prepare_routed_read_context(client, project_dir, &names, true)?;
    let mut by_key = BTreeMap::new();

    let mut fetched = BTreeMap::new();
    for package in registry_packages {
        if !fetched.contains_key(&package.name) {
            let fetched_metadata = fetch_routed_package_metadata(&context, &package.name)
                .await
                .ok();
            fetched.insert(package.name.clone(), fetched_metadata);
        }
        let Some((routed_package, metadata)) = fetched
            .get(&package.name)
            .and_then(|metadata| metadata.as_ref())
        else {
            continue;
        };
        let Some(version) = metadata.versions.get(&package.version) else {
            continue;
        };
        let value = serde_json::to_value(version)
            .map_err(|e| LpmError::Registry(format!("failed to serialize metadata: {e}")))?;
        by_key.insert(
            package_metadata_key(package),
            RegistryComponentMetadata {
                manifest: extract_manifest_metadata(&value),
                attestation_ref: version
                    .dist
                    .as_ref()
                    .and_then(|dist| dist.attestations.clone()),
                registry_url: attestation_registry_url(&context, &package.name, routed_package),
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
        for package in packages {
            if locked_registry_source(package).is_none() {
                continue;
            }
            let key = package_metadata_key(package);
            let Some(metadata) = registry_metadata.get(&key) else {
                continue;
            };
            let status = provenance_fetch::map_fetch_result_to_status(
                &package.name,
                &package.version,
                provenance_fetch::fetch_provenance_snapshot(
                    &http,
                    &cache_root,
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
            out.insert(key, provenance_from_status(status));
        }
        return Ok(out);
    }

    let mut cache_candidates = Vec::with_capacity(packages.len());
    for package in packages {
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
                package_metadata_key(package),
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
                package_metadata_key(package),
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

fn render_cyclonedx(document: &SbomDocument) -> Value {
    let root_ref = "lpm:root";
    let mut dependencies = Vec::with_capacity(document.dependencies.len() + 1);
    dependencies.push(json!({
        "ref": root_ref,
        "dependsOn": document.root_dependency_refs,
    }));
    for (reference, depends_on) in &document.dependencies {
        dependencies.push(json!({
            "ref": reference,
            "dependsOn": depends_on,
        }));
    }

    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": document_serial("cyclonedx", document),
        "version": 1,
        "metadata": {
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
        },
        "components": document.components.iter().map(cyclonedx_component).collect::<Vec<_>>(),
        "dependencies": dependencies,
    })
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
        "scope": component.scope,
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

fn render_spdx(document: &SbomDocument) -> Value {
    let root_spdx_id = "SPDXRef-RootPackage";
    let mut packages = Vec::with_capacity(document.components.len() + 1);
    packages.push(spdx_root_package(document, root_spdx_id));
    for component in &document.components {
        packages.push(spdx_package(component));
    }

    let mut relationships = Vec::new();
    relationships.push(json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_spdx_id,
    }));
    for dependency in &document.root_dependency_refs {
        if let Some(component) = document
            .components
            .iter()
            .find(|component| &component.bom_ref == dependency)
        {
            relationships.push(json!({
                "spdxElementId": root_spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": component.spdx_id,
            }));
        }
    }
    for (reference, depends_on) in &document.dependencies {
        let Some(component) = document
            .components
            .iter()
            .find(|component| &component.bom_ref == reference)
        else {
            continue;
        };
        for dependency in depends_on {
            if let Some(target) = document
                .components
                .iter()
                .find(|component| &component.bom_ref == dependency)
            {
                relationships.push(json!({
                    "spdxElementId": component.spdx_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target.spdx_id,
                }));
            }
        }
    }

    json!({
        "spdxVersion": SPDX_SPEC_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document.root_name,
        "documentNamespace": document_namespace(document),
        "creationInfo": {
            "created": document.generated_at,
            "creators": [format!("Tool: lpm-rs-{}", crate::build_version::version())],
        },
        "packages": packages,
        "relationships": relationships,
    })
}

fn spdx_root_package(document: &SbomDocument, spdx_id: &str) -> Value {
    json!({
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
    })
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

fn dependency_graph(
    components: &[SbomComponent],
    source_index: &BTreeMap<(String, String), Vec<String>>,
    component_refs: &BTreeSet<String>,
) -> BTreeMap<String, Vec<String>> {
    let mut graph = BTreeMap::new();
    for component in components {
        let mut refs = BTreeSet::new();
        let alias_targets = component
            .package
            .alias_dependencies
            .iter()
            .map(|[local, target]| (local.as_str(), target.as_str()))
            .collect::<BTreeMap<_, _>>();
        for dep in component
            .package
            .dependencies
            .iter()
            .chain(component.package.peers.iter())
        {
            let Some((local_name, version)) = split_dependency_pin(dep) else {
                continue;
            };
            let target_name = alias_targets
                .get(local_name.as_str())
                .copied()
                .unwrap_or(local_name.as_str());
            if let Some(target_refs) = source_index.get(&(target_name.to_string(), version))
                && let Some(target_ref) = target_refs.first()
                && component_refs.contains(target_ref)
            {
                refs.insert(target_ref.clone());
            }
        }
        graph.insert(component.bom_ref.clone(), refs.into_iter().collect());
    }
    graph
}

fn root_dependency_refs(
    root_json: &Value,
    source_index: &BTreeMap<(String, String), Vec<String>>,
) -> Vec<String> {
    let scopes = root_dependency_scopes(root_json);
    let mut out = BTreeSet::new();
    for name in scopes.keys() {
        for ((package_name, _version), refs) in source_index {
            if package_name == name
                && let Some(reference) = refs.first()
            {
                out.insert(reference.clone());
            }
        }
    }
    out.into_iter().collect()
}

fn root_dependency_scopes(root_json: &Value) -> BTreeMap<String, &'static str> {
    let mut scopes = BTreeMap::new();
    collect_dependency_scope(root_json, "dependencies", "required", &mut scopes, false);
    collect_dependency_scope(
        root_json,
        "peerDependencies",
        "required",
        &mut scopes,
        false,
    );
    collect_dependency_scope(
        root_json,
        "optionalDependencies",
        "optional",
        &mut scopes,
        true,
    );
    collect_dependency_scope(root_json, "devDependencies", "excluded", &mut scopes, true);
    scopes
}

fn collect_dependency_scope(
    root_json: &Value,
    section: &str,
    scope: &'static str,
    scopes: &mut BTreeMap<String, &'static str>,
    only_if_absent: bool,
) {
    let Some(deps) = root_json.get(section).and_then(Value::as_object) else {
        return;
    };
    for name in deps.keys() {
        if only_if_absent {
            scopes.entry(name.clone()).or_insert(scope);
        } else {
            scopes.insert(name.clone(), scope);
        }
    }
}

fn split_dependency_pin(input: &str) -> Option<(String, String)> {
    let split_at = input.rfind('@')?;
    if split_at == 0 {
        return None;
    }
    let name = &input[..split_at];
    let version = &input[split_at + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
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
    if metadata.licenses.is_empty() {
        "NOASSERTION".to_string()
    } else {
        metadata.licenses.join(" AND ")
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

fn emit_sbom(value: &Value, output: Option<&Path>) -> Result<(), LpmError> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| LpmError::Registry(format!("failed to serialize SBOM: {e}")))?;
    if let Some(path) = output {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
        }
        std::fs::write(path, format!("{body}\n")).map_err(LpmError::Io)?;
    } else {
        println!("{body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_registry::{RouteMode, RouteTable};

    #[test]
    fn split_dependency_pin_handles_scoped_names() {
        assert_eq!(
            split_dependency_pin("@scope/pkg@1.2.3"),
            Some(("@scope/pkg".to_string(), "1.2.3".to_string()))
        );
        assert_eq!(
            split_dependency_pin("left-pad@1.3.0"),
            Some(("left-pad".to_string(), "1.3.0".to_string()))
        );
        assert_eq!(split_dependency_pin("@1.0.0"), None);
    }

    #[test]
    fn purl_encodes_scoped_npm_names() {
        assert_eq!(
            purl_for_package("@scope/pkg", "1.2.3"),
            "pkg:npm/%40scope/pkg@1.2.3"
        );
    }

    #[test]
    fn proxy_routed_npm_metadata_keeps_the_npm_attestation_origin() {
        let context = RoutedReadContext {
            client: RegistryClient::new()
                .with_base_url("https://lpm.example.test")
                .with_npm_registry_url("https://npm.example.test"),
            route_table: RouteTable::from_mode_only(RouteMode::Proxy),
        };
        let routed = RoutedPackageRef::Registry("axios".to_string());

        assert_eq!(
            attestation_registry_url(&context, "axios", &routed),
            "https://npm.example.test"
        );
    }

    #[test]
    fn lpm_metadata_uses_the_lpm_attestation_origin() {
        let context = RoutedReadContext {
            client: RegistryClient::new()
                .with_base_url("https://lpm.example.test")
                .with_npm_registry_url("https://npm.example.test"),
            route_table: RouteTable::from_mode_only(RouteMode::Proxy),
        };
        let routed = RoutedPackageRef::Lpm(
            lpm_common::PackageName::parse("@lpm.dev/acme.package")
                .expect("valid LPM package name"),
        );

        assert_eq!(
            attestation_registry_url(&context, "@lpm.dev/acme.package", &routed),
            "https://lpm.example.test"
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
