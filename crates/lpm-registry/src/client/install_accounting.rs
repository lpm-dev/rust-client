use super::*;

/// Header used to distinguish LPM-managed tarball fetches from unmanaged clients.
pub const MANAGED_INSTALL_ACCOUNTING_HEADER: &str = "x-lpm-install-accounting";
/// Protocol version sent in [`MANAGED_INSTALL_ACCOUNTING_HEADER`].
pub const MANAGED_INSTALL_ACCOUNTING_VERSION: &str = "explicit-v1";
/// Maximum roots accepted by one managed Pool install report.
pub const MAX_MANAGED_POOL_INSTALL_ROOTS: usize = 200;

/// Typed proof that an install will submit explicit Pool attribution after linking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagedInstallAccounting;

/// A resolved top-level LPM accounting root reported after a successful install.
///
/// Pool eligibility is intentionally absent: the Registry derives distribution
/// and publisher access authoritatively before crediting the root or traversing
/// its saved Pool dependency tree.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct ManagedInstallRoot {
    /// Canonical LPM package name.
    pub name: String,
    /// Exact resolved package version.
    pub version: String,
}

impl ManagedInstallRoot {
    /// Construct a resolved LPM accounting root.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

impl RegistryClient {
    /// Report the Pool roots of a completed managed install.
    ///
    /// The Registry authenticates the subscriber and derives dependency depths
    /// from its saved package-version dependency trees.
    pub async fn report_managed_pool_install(
        &self,
        roots: &[ManagedInstallRoot],
        _accounting: ManagedInstallAccounting,
    ) -> Result<(), LpmError> {
        if roots.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/registry/pool/install-report", self.base_url);
        let mut deterministic_roots = roots.to_vec();
        deterministic_roots.sort_unstable();
        deterministic_roots.dedup();
        for chunk in deterministic_roots.chunks(MAX_MANAGED_POOL_INSTALL_ROOTS) {
            let body = serde_json::json!({ "roots": chunk });
            self.execute_with_recovery(AuthPosture::AuthRequired, || {
                self.post_json_raw(&url, &body)
            })
            .await?;
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct InstallAccessResponse {
    packages: Vec<InstallAccessDecision>,
}

#[derive(serde::Deserialize)]
struct InstallAccessDecision {
    name: String,
    version: String,
    allowed: bool,
    reason: Option<String>,
    deprecated: Option<String>,
}

impl RegistryClient {
    /// Check current installation rights for every exact registry dependency.
    /// Local artifacts and metadata never stand in for this online check.
    pub async fn check_install_access(
        &self,
        packages: &[ManagedInstallRoot],
    ) -> Result<Vec<String>, LpmError> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = packages.to_vec();
        packages.sort_unstable();
        packages.dedup();
        let url = format!("{}/api/registry/install-check", self.base_url);
        let mut warnings = Vec::new();
        for chunk in packages.chunks(200) {
            let body = serde_json::json!({ "packages": chunk });
            let response: InstallAccessResponse = self
                .execute_with_recovery(AuthPosture::AuthRequired, || async {
                    let response = self.post_json_raw(&url, &body).await?;
                    parse_capped_api_json(response, "registry install access check").await
                })
                .await?;
            let mut decisions = std::collections::BTreeMap::new();
            for decision in response.packages {
                if decisions
                    .insert((decision.name.clone(), decision.version.clone()), decision)
                    .is_some()
                {
                    return Err(LpmError::Registry(
                        "Duplicate registry install access decision".into(),
                    ));
                }
            }
            if decisions.len() != chunk.len() {
                return Err(LpmError::Registry(
                    "Incomplete registry install access response".into(),
                ));
            }
            for package in chunk {
                let decision = decisions
                    .remove(&(package.name.clone(), package.version.clone()))
                    .ok_or_else(|| {
                        LpmError::Registry(format!(
                            "Registry did not verify {}@{}",
                            package.name, package.version
                        ))
                    })?;
                if !decision.allowed {
                    return Err(LpmError::PackageInstallDenied {
                        package: package.name.clone(),
                        version: package.version.clone(),
                        reason: decision.reason.unwrap_or_else(|| {
                            "Package access denied or version unavailable".into()
                        }),
                    });
                }
                if let Some(message) = decision
                    .deprecated
                    .filter(|message| !message.trim().is_empty())
                {
                    warnings.push(format!(
                        "{}@{} is deprecated: {}",
                        package.name, package.version, message
                    ));
                }
            }
        }
        Ok(warnings)
    }
}
