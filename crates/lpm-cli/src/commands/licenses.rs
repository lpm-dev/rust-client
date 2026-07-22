use crate::commands::install::select_locked_package_for_requested_spec;
use crate::commands::manifest_metadata::{
    ManifestMetadata, extract_manifest_metadata, package_metadata_key, read_json_file,
    read_local_metadata,
};
use crate::install_ui;
use clap::ValueEnum;
use lpm_common::LpmError;
use lpm_lockfile::{LockedPackage, Lockfile};
use lpm_resolver::specifier::Specifier;
use lpm_security::behavioral::manifest::license_expression_is_copyleft;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, ValueEnum)]
pub enum LicenseFailOn {
    Copyleft,
    Missing,
}

impl LicenseFailOn {
    fn as_str(self) -> &'static str {
        match self {
            LicenseFailOn::Copyleft => "copyleft",
            LicenseFailOn::Missing => "missing",
        }
    }
}

#[derive(Debug)]
struct LicenseInventory {
    root: RootLicense,
    packages: Vec<PackageLicense>,
    denied_policy: Vec<String>,
    fail_on_policy: BTreeSet<LicenseFailOn>,
}

#[derive(Debug)]
struct RootLicense {
    name: String,
    version: String,
    licenses: Vec<String>,
    license_expression: String,
    missing: bool,
    copyleft: bool,
}

#[derive(Debug)]
struct PackageLicense {
    name: String,
    version: String,
    source: Option<String>,
    scope: &'static str,
    licenses: Vec<String>,
    license_expression: String,
    missing: bool,
    copyleft: bool,
    denied_licenses: Vec<String>,
}

#[derive(Debug)]
struct PolicySummary {
    failed: bool,
    copyleft_count: usize,
    missing_count: usize,
    denied_count: usize,
}

pub fn run(
    project_dir: &Path,
    fail_on: &[LicenseFailOn],
    deny: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return Err(LpmError::NotFound(
            "no lpm.lock found. Run `lpm install` before listing licenses.".into(),
        ));
    }

    let package_json_path = project_dir.join("package.json");
    let root_json = read_json_file(&package_json_path)?;
    let lockfile = Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?;
    let inventory = build_inventory(project_dir, root_json, &lockfile, fail_on, deny)?;
    let summary = policy_summary(&inventory);

    if json_output {
        emit_json(&inventory, &summary)?;
    } else {
        emit_human(&inventory, &summary);
    }

    if summary.failed {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

fn build_inventory(
    project_dir: &Path,
    root_json: Value,
    lockfile: &Lockfile,
    fail_on: &[LicenseFailOn],
    deny: &[String],
) -> Result<LicenseInventory, LpmError> {
    let root_metadata = extract_manifest_metadata(&root_json);
    let root = RootLicense {
        name: root_project_name(&root_json, project_dir),
        version: root_json
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .unwrap_or("0.0.0")
            .to_string(),
        licenses: root_metadata.licenses.clone(),
        license_expression: license_expression(&root_metadata),
        missing: license_is_missing(&root_metadata.licenses),
        copyleft: licenses_are_copyleft(&root_metadata.licenses),
    };

    let local_metadata = read_local_metadata(project_dir, &lockfile.packages)?;
    let scopes = package_scopes_by_lockfile_index(&root_json, lockfile);
    let denied_policy = normalize_policy_values(deny);
    let denied_lookup: BTreeSet<String> = denied_policy
        .iter()
        .map(|value| normalize_license(value))
        .collect();
    let fail_on_policy = fail_on.iter().copied().collect::<BTreeSet<_>>();

    let mut packages = Vec::with_capacity(lockfile.packages.len());
    for (index, package) in lockfile.packages.iter().enumerate() {
        packages.push(package_license(
            package,
            local_metadata.get(&package_metadata_key(package)),
            scopes
                .get(index)
                .copied()
                .flatten()
                .unwrap_or({
                    if package.optional {
                        LicenseScope::Optional
                    } else {
                        LicenseScope::Excluded
                    }
                })
                .as_str(),
            &denied_lookup,
        ));
    }
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
            .then(left.source.cmp(&right.source))
    });

    Ok(LicenseInventory {
        root,
        packages,
        denied_policy,
        fail_on_policy,
    })
}

fn root_project_name(root_json: &Value, project_dir: &Path) -> String {
    if let Some(name) = root_json
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
    {
        return name.to_string();
    }

    project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map_or_else(|| "project".to_string(), str::to_string)
}

fn package_license(
    package: &LockedPackage,
    metadata: Option<&ManifestMetadata>,
    scope: &'static str,
    denied_lookup: &BTreeSet<String>,
) -> PackageLicense {
    let licenses = metadata
        .map(|metadata| metadata.licenses.clone())
        .unwrap_or_default();
    let denied_licenses = licenses
        .iter()
        .filter(|license| denied_lookup.contains(&normalize_license(license)))
        .cloned()
        .collect::<Vec<_>>();
    PackageLicense {
        name: package.name.clone(),
        version: package.version.clone(),
        source: package.source.clone(),
        scope,
        license_expression: license_expression_from_list(&licenses),
        missing: license_is_missing(&licenses),
        copyleft: licenses_are_copyleft(&licenses),
        licenses,
        denied_licenses,
    }
}

fn policy_summary(inventory: &LicenseInventory) -> PolicySummary {
    let copyleft_count = inventory
        .packages
        .iter()
        .filter(|package| package.copyleft)
        .count();
    let missing_count = inventory
        .packages
        .iter()
        .filter(|package| package.missing)
        .count();
    let denied_count = inventory
        .packages
        .iter()
        .filter(|package| !package.denied_licenses.is_empty())
        .count();
    let failed = denied_count > 0
        || (copyleft_count > 0 && inventory.fail_on_policy.contains(&LicenseFailOn::Copyleft))
        || (missing_count > 0 && inventory.fail_on_policy.contains(&LicenseFailOn::Missing));

    PolicySummary {
        failed,
        copyleft_count,
        missing_count,
        denied_count,
    }
}

fn emit_json(inventory: &LicenseInventory, summary: &PolicySummary) -> Result<(), LpmError> {
    let packages = inventory
        .packages
        .iter()
        .map(package_to_json)
        .collect::<Vec<_>>();
    let json = json!({
        "success": !summary.failed,
        "root": root_to_json(&inventory.root),
        "packages": packages,
        "count": inventory.packages.len(),
        "summary": {
            "copyleft": summary.copyleft_count,
            "missing": summary.missing_count,
            "denied": summary.denied_count,
        },
        "policy": {
            "fail_on": inventory
                .fail_on_policy
                .iter()
                .map(|policy| policy.as_str())
                .collect::<Vec<_>>(),
            "deny": inventory.denied_policy,
            "failed": summary.failed,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json)
            .map_err(|e| LpmError::Registry(format!("failed to serialize licenses JSON: {e}")))?
    );
    Ok(())
}

fn emit_human(inventory: &LicenseInventory, summary: &PolicySummary) {
    println!(
        "{:<42} {:<12} {:<10} License",
        "Package", "Version", "Scope"
    );
    println!("{:-<42} {:-<12} {:-<10} {:-<1}", "", "", "", "");
    for package in &inventory.packages {
        println!(
            "{:<42} {:<12} {:<10} {}",
            truncate_cell(&package.name, 42),
            truncate_cell(&package.version, 12),
            package.scope,
            package.license_expression
        );
    }

    if summary.failed {
        install_ui::warn_untrusted(&format!(
            "license policy failed: {} copyleft, {} missing, {} denied",
            summary.copyleft_count, summary.missing_count, summary.denied_count
        ));
    } else {
        install_ui::done_untrusted(&format!(
            "Listed {} package license(s)",
            inventory.packages.len()
        ));
    }
}

fn root_to_json(root: &RootLicense) -> Value {
    json!({
        "name": root.name,
        "version": root.version,
        "licenses": root.licenses,
        "license_expression": root.license_expression,
        "missing": root.missing,
        "copyleft": root.copyleft,
    })
}

fn package_to_json(package: &PackageLicense) -> Value {
    json!({
        "name": package.name,
        "version": package.version,
        "source": package.source,
        "scope": package.scope,
        "licenses": package.licenses,
        "license_expression": package.license_expression,
        "missing": package.missing,
        "copyleft": package.copyleft,
        "denied": !package.denied_licenses.is_empty(),
        "denied_licenses": package.denied_licenses,
    })
}

fn normalize_policy_values(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    normalized.sort_by_key(|value| normalize_license(value));
    normalized.dedup_by(|left, right| normalize_license(left) == normalize_license(right));
    normalized
}

fn license_expression(metadata: &ManifestMetadata) -> String {
    license_expression_from_list(&metadata.licenses)
}

fn license_expression_from_list(licenses: &[String]) -> String {
    if licenses.is_empty() {
        "NOASSERTION".to_string()
    } else {
        licenses.join(" AND ")
    }
}

fn licenses_are_copyleft(licenses: &[String]) -> bool {
    licenses
        .iter()
        .any(|license| license_expression_is_copyleft(license))
}

fn license_is_missing(licenses: &[String]) -> bool {
    licenses.is_empty()
        || licenses
            .iter()
            .all(|license| is_no_license_marker(license.as_str()))
}

fn is_no_license_marker(license: &str) -> bool {
    let normalized = normalize_license(license);
    normalized == "noassertion"
        || normalized == "unlicensed"
        || normalized == "none"
        || normalized == "proprietary"
        || normalized.starts_with("see license in")
}

fn normalize_license(license: &str) -> String {
    license.trim().to_ascii_lowercase()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum LicenseScope {
    Excluded,
    Optional,
    Required,
}

impl LicenseScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Excluded => "excluded",
        }
    }

    fn child_scope(self, child: &LockedPackage) -> Self {
        match self {
            Self::Excluded => Self::Excluded,
            Self::Optional => Self::Optional,
            Self::Required if child.optional => Self::Optional,
            Self::Required => Self::Required,
        }
    }
}

fn package_scopes_by_lockfile_index(
    root_json: &Value,
    lockfile: &Lockfile,
) -> Vec<Option<LicenseScope>> {
    let version_index = package_version_index(&lockfile.packages);
    let adjacency = package_adjacency(&lockfile.packages, &version_index);
    let root_seeds = root_dependency_seeds(root_json);
    let mut scopes = vec![None; lockfile.packages.len()];
    let mut queue = VecDeque::new();

    for (local_name, (spec, scope)) in root_seeds {
        let target_name = root_dependency_target_name(&local_name, &spec, lockfile);
        let Some(package) = select_locked_package_for_requested_spec(lockfile, &target_name, &spec)
        else {
            continue;
        };
        let Some(package_index) = lockfile
            .packages
            .iter()
            .position(|candidate| std::ptr::eq(candidate, package))
        else {
            continue;
        };
        if set_package_scope(&mut scopes, package_index, scope) {
            queue.push_back((package_index, scope));
        }
    }

    while let Some((package_index, scope)) = queue.pop_front() {
        for &child_index in &adjacency[package_index] {
            let child_scope = scope.child_scope(&lockfile.packages[child_index]);
            if set_package_scope(&mut scopes, child_index, child_scope) {
                queue.push_back((child_index, child_scope));
            }
        }
    }

    scopes
}

fn set_package_scope(
    scopes: &mut [Option<LicenseScope>],
    package_index: usize,
    scope: LicenseScope,
) -> bool {
    let slot = &mut scopes[package_index];
    if slot.is_none_or(|existing| scope > existing) {
        *slot = Some(scope);
        return true;
    }
    false
}

fn package_version_index(packages: &[LockedPackage]) -> BTreeMap<(String, String), Vec<usize>> {
    let mut index: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (package_index, package) in packages.iter().enumerate() {
        index
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(package_index);
    }
    index
}

fn package_adjacency(
    packages: &[LockedPackage],
    version_index: &BTreeMap<(String, String), Vec<usize>>,
) -> Vec<Vec<usize>> {
    let mut adjacency = Vec::with_capacity(packages.len());
    for package in packages {
        let alias_targets = package
            .alias_dependencies
            .iter()
            .map(|[local, target]| (local.as_str(), target.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut children = BTreeSet::new();
        for dep in package.dependencies.iter().chain(package.peers.iter()) {
            let Some((local_name, version)) = split_dependency_pin(dep) else {
                continue;
            };
            let target_name = alias_targets
                .get(local_name.as_str())
                .copied()
                .unwrap_or(local_name.as_str());
            if let Some(indices) = version_index.get(&(target_name.to_string(), version)) {
                children.extend(indices.iter().copied());
            }
        }
        adjacency.push(children.into_iter().collect());
    }
    adjacency
}

fn root_dependency_seeds(root_json: &Value) -> BTreeMap<String, (String, LicenseScope)> {
    let mut seeds = BTreeMap::new();
    collect_root_dependency_seeds(
        root_json,
        "dependencies",
        LicenseScope::Required,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "peerDependencies",
        LicenseScope::Required,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "optionalDependencies",
        LicenseScope::Optional,
        &mut seeds,
    );
    collect_root_dependency_seeds(
        root_json,
        "devDependencies",
        LicenseScope::Excluded,
        &mut seeds,
    );
    seeds
}

fn collect_root_dependency_seeds(
    root_json: &Value,
    section: &str,
    scope: LicenseScope,
    seeds: &mut BTreeMap<String, (String, LicenseScope)>,
) {
    let Some(deps) = root_json.get(section).and_then(Value::as_object) else {
        return;
    };
    for (name, spec) in deps {
        let spec = spec.as_str().unwrap_or_default().to_string();
        let entry = seeds.entry(name.clone()).or_insert((spec.clone(), scope));
        if scope > entry.1 {
            *entry = (spec, scope);
        }
    }
}

fn root_dependency_target_name(local_name: &str, spec: &str, lockfile: &Lockfile) -> String {
    if let Some(target) = lockfile.root_aliases.get(local_name) {
        return target.clone();
    }
    if spec.trim_start().starts_with("npm:")
        && let Ok(Specifier::NpmAlias { target, .. }) = Specifier::parse(spec)
    {
        return target;
    }
    local_name.to_string()
}

fn split_dependency_pin(input: &str) -> Option<(String, String)> {
    let at = input.rfind('@')?;
    if at == 0 || at + 1 >= input.len() {
        return None;
    }
    let name = input[..at].to_string();
    let version = input[at + 1..].to_string();
    Some((name, version))
}

fn truncate_cell(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(width.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_is_missing_treats_unlicensed_markers_as_missing() {
        assert!(license_is_missing(&["UNLICENSED".to_string()]));
        assert!(license_is_missing(&["SEE LICENSE IN LICENSE".to_string()]));
        assert!(!license_is_missing(&["MIT".to_string()]));
    }

    #[test]
    fn policy_summary_fails_on_denied_license_without_fail_on_flag() {
        let inventory = LicenseInventory {
            root: RootLicense {
                name: "app".to_string(),
                version: "1.0.0".to_string(),
                licenses: vec!["MIT".to_string()],
                license_expression: "MIT".to_string(),
                missing: false,
                copyleft: false,
            },
            packages: vec![PackageLicense {
                name: "dep".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                scope: "required",
                licenses: vec!["GPL-3.0".to_string()],
                license_expression: "GPL-3.0".to_string(),
                missing: false,
                copyleft: true,
                denied_licenses: vec!["GPL-3.0".to_string()],
            }],
            denied_policy: vec!["GPL-3.0".to_string()],
            fail_on_policy: BTreeSet::new(),
        };

        let summary = policy_summary(&inventory);

        assert!(summary.failed);
        assert_eq!(summary.denied_count, 1);
    }
}
