use super::super::global_util::pick_version;
use crate::save_spec::{
    SaveConfig, SaveFlags, decide_saved_dependency_spec, parse_user_save_intent,
};
use lpm_common::LpmError;
use lpm_global::PackageSource;
use lpm_registry::RegistryClient;
use lpm_semver::Version;

#[derive(Debug, Clone)]
pub(super) struct ResolvedSpec {
    pub(super) name: String,
    pub(super) version: Version,
    pub(super) integrity: String,
    pub(super) source: PackageSource,
    pub(super) saved_spec: String,
}

pub(super) async fn pre_resolve(
    registry: &RegistryClient,
    spec: &str,
) -> Result<ResolvedSpec, LpmError> {
    let (name, intent) = parse_user_save_intent(spec)?;
    // Dispatch by name shape: `@lpm.dev/owner.tool` goes through the
    // first-party registry path (PackageName parser); everything else
    // (`eslint`, `@types/node`, `@scope/foo`) is fetched via the npm
    // upstream proxy. This matches what the project install pipeline
    // does — global install just lifts the same dispatch.
    let metadata = if lpm_common::package_name::is_lpm_package(&name) {
        let pkg_name = lpm_common::PackageName::parse(&name)
            .map_err(|e| LpmError::Script(format!("invalid LPM package name '{name}': {e}")))?;
        registry.get_package_metadata(&pkg_name).await?
    } else {
        registry.get_npm_package_metadata(&name).await?
    };

    // Pick a concrete version that satisfies `intent`.
    let version_str = pick_version(&metadata, &intent, "global install")?;
    let version = Version::parse(&version_str).map_err(|e| {
        LpmError::Script(format!(
            "registry returned unparseable version '{version_str}' for '{name}': {e}"
        ))
    })?;
    let version_meta = metadata.versions.get(&version_str).ok_or_else(|| {
        LpmError::Script(format!(
            "version '{version_str}' missing from metadata for '{name}'"
        ))
    })?;
    let integrity = version_meta
        .dist
        .as_ref()
        .and_then(|d| d.integrity.clone())
        .ok_or_else(|| {
            LpmError::Script(format!(
                "version '{version_str}' of '{name}' has no integrity hash in registry metadata"
            ))
        })?;

    // Source is implied by name scope. `@lpm.dev/...` packages live on
    // the LPM registry; everything else is proxied through upstream npm.
    let source = if lpm_common::package_name::is_lpm_package(&name) {
        PackageSource::LpmDev
    } else {
        PackageSource::UpstreamNpm
    };

    // Global installs honor the same save-spec precedence as project installs.
    let decision = decide_saved_dependency_spec(
        &intent,
        &version,
        SaveFlags::default(),
        SaveConfig::default(),
    );

    Ok(ResolvedSpec {
        name,
        version,
        integrity,
        source,
        saved_spec: decision.spec_to_write,
    })
}
