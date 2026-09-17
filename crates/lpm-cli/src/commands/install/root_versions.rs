use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};

use crate::manifest_dependency::ManifestDependencySpec;
use lpm_common::LpmError;
use lpm_semver::{Version, VersionReq};

pub(crate) struct RootVersionPin {
    pub(crate) canonical_name: String,
    pub(crate) version: String,
    pub(crate) catalog_specifier: Option<String>,
}

tokio::task_local! {
    static UPGRADE_ROOTS: (PathBuf, HashMap<String, RootVersionPin>);
}

pub(crate) async fn scope<F: Future>(
    project_dir: &Path,
    versions: HashMap<String, RootVersionPin>,
    future: F,
) -> F::Output {
    UPGRADE_ROOTS
        .scope((project_dir.to_path_buf(), versions), future)
        .await
}

pub(super) fn active(project_dir: &Path) -> bool {
    UPGRADE_ROOTS
        .try_with(|(project, _)| project == project_dir)
        .unwrap_or(false)
}

pub(super) fn constrain(
    project_dir: &Path,
    dependencies: &HashMap<String, String>,
) -> Result<HashMap<String, String>, LpmError> {
    let mut dependencies = dependencies.clone();
    UPGRADE_ROOTS
        .try_with(|(project, versions)| -> Result<(), LpmError> {
            if project != project_dir {
                return Ok(());
            }
            for (name, pin) in versions {
                let canonical = &pin.canonical_name;
                let version = &pin.version;
                let Some(value) = dependencies.get_mut(name) else {
                    continue;
                };
                let (spec, range) = ManifestDependencySpec::from_manifest_value(name, value)?;
                let lookup_name = match &spec {
                    ManifestDependencySpec::Plain => name,
                    ManifestDependencySpec::NpmAlias { target } => target,
                };
                if lookup_name != canonical {
                    continue;
                }
                // A stale lock entry must not override a newer manifest requirement.
                if let Ok(requirement) = VersionReq::parse(&range)
                    && Version::parse(version).is_ok_and(|version| !requirement.matches(&version))
                {
                    continue;
                }
                if VersionReq::parse(&range).is_err()
                    && let Some(previous) = &pin.catalog_specifier
                {
                    let (_, previous_range) =
                        ManifestDependencySpec::from_manifest_value(name, previous)?;
                    if previous_range.trim() != range.trim() {
                        continue;
                    }
                }
                *value = spec.render_new_value(version);
            }
            Ok(())
        })
        .unwrap_or(Ok(()))?;
    Ok(dependencies)
}
