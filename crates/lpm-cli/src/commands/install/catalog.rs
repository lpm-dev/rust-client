use super::*;

pub(super) struct CatalogSavePolicy {
    pub(super) mode: lpm_workspace::CatalogMode,
    pub(super) catalogs: HashMap<String, HashMap<String, String>>,
    pub(super) forced_catalog: Option<String>,
}

impl CatalogSavePolicy {
    #[cfg(test)]
    pub(super) fn manual() -> Self {
        Self {
            mode: lpm_workspace::CatalogMode::Manual,
            catalogs: HashMap::new(),
            forced_catalog: None,
        }
    }

    pub(super) fn from_package(
        pkg: &lpm_workspace::PackageJson,
        forced_catalog: Option<&str>,
    ) -> Self {
        let mode = pkg
            .lpm
            .as_ref()
            .and_then(|lpm| lpm.catalog_mode)
            .unwrap_or(lpm_workspace::CatalogMode::Manual);
        let forced_catalog = forced_catalog.map(normalize_catalog_name);
        Self {
            mode,
            catalogs: pkg.catalogs.clone(),
            forced_catalog,
        }
    }

    pub(super) fn can_rewrite_manifest(&self) -> bool {
        self.forced_catalog.is_some() || !matches!(self.mode, lpm_workspace::CatalogMode::Manual)
    }

    pub(super) fn optional_catalog_entry(
        &self,
        catalog_name: &str,
        package: &str,
    ) -> Option<&String> {
        let catalog = self.catalogs.get(catalog_name)?;
        catalog.get(package)
    }

    pub(super) fn catalog_entry(
        &self,
        catalog_name: &str,
        package: &str,
    ) -> Result<&String, LpmError> {
        let catalog = self.catalogs.get(catalog_name).ok_or_else(|| {
            LpmError::Registry(format!(
                "{} rejected {package}: catalog `{catalog_name}` does not exist",
                forced_catalog_flag(catalog_name)
            ))
        })?;
        catalog.get(package).ok_or_else(|| {
            LpmError::Registry(format!(
                "{} rejected {package}: no catalog entry exists in catalog `{catalog_name}` for this package",
                forced_catalog_flag(catalog_name)
            ))
        })
    }
}

pub(super) fn normalize_catalog_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "default" {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn catalog_save_policy_for_project(
    project_dir: &Path,
    forced_catalog: Option<&str>,
) -> Result<CatalogSavePolicy, LpmError> {
    if let Some(workspace) = crate::workspace_discovery_cache::discover_workspace(project_dir)
        .map_err(|e| LpmError::Registry(format!("failed to discover workspace catalogs: {e}")))?
    {
        return Ok(CatalogSavePolicy::from_package(
            &workspace.root_package,
            forced_catalog,
        ));
    }

    let pkg_json_path = project_dir.join("package.json");
    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    Ok(CatalogSavePolicy::from_package(&pkg, forced_catalog))
}

pub(super) fn cleanup_unused_catalogs_after_install(project_dir: &Path) -> Result<bool, LpmError> {
    let workspace = crate::workspace_discovery_cache::discover_workspace(project_dir)
        .map_err(|e| LpmError::Registry(format!("failed to discover workspace catalogs: {e}")))?;

    let (root_dir, cleanup_enabled, member_dirs) = if let Some(workspace) = workspace {
        let cleanup_enabled = cleanup_unused_catalogs_enabled(&workspace.root_package);
        let member_dirs = workspace
            .members
            .iter()
            .map(|member| member.path.clone())
            .collect();
        (workspace.root.clone(), cleanup_enabled, member_dirs)
    } else {
        let pkg_json_path = project_dir.join("package.json");
        let pkg = lpm_workspace::read_package_json(&pkg_json_path)
            .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
        (
            project_dir.to_path_buf(),
            cleanup_unused_catalogs_enabled(&pkg),
            Vec::new(),
        )
    };

    if !cleanup_enabled {
        return Ok(false);
    }

    let mut references = lpm_workspace::CatalogReferences::new();
    let root_pkg_path = root_dir.join("package.json");
    let root_pkg = lpm_workspace::read_package_json(&root_pkg_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    lpm_workspace::collect_catalog_references(&root_pkg, &mut references);

    for member_dir in member_dirs {
        let member_pkg_path = member_dir.join("package.json");
        let member_pkg = lpm_workspace::read_package_json(&member_pkg_path).map_err(|e| {
            LpmError::Registry(format!(
                "failed to read workspace member package.json {}: {e}",
                member_pkg_path.display()
            ))
        })?;
        lpm_workspace::collect_catalog_references(&member_pkg, &mut references);
    }

    let package_json_changed =
        lpm_workspace::prune_unused_package_json_catalogs(&root_pkg_path, &references).map_err(
            |e| {
                LpmError::Registry(format!(
                    "failed to cleanup unused package.json catalog entries: {e}"
                ))
            },
        )?;
    let pnpm_workspace_changed = lpm_workspace::prune_unused_pnpm_workspace_catalogs(
        &root_dir.join("pnpm-workspace.yaml"),
        &references,
    )
    .map_err(|e| {
        LpmError::Registry(format!(
            "failed to cleanup unused pnpm-workspace.yaml catalog entries: {e}"
        ))
    })?;

    Ok(package_json_changed || pnpm_workspace_changed)
}

pub(super) fn cleanup_unused_catalogs_enabled(pkg: &lpm_workspace::PackageJson) -> bool {
    pkg.lpm
        .as_ref()
        .and_then(|lpm| lpm.cleanup_unused_catalogs)
        .unwrap_or(false)
}
