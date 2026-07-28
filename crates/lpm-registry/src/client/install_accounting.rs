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
