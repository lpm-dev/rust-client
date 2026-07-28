use super::*;

/// Header used to distinguish LPM-managed tarball fetches from unmanaged clients.
pub const MANAGED_INSTALL_ACCOUNTING_HEADER: &str = "x-lpm-install-accounting";
/// Protocol version sent in [`MANAGED_INSTALL_ACCOUNTING_HEADER`].
pub const MANAGED_INSTALL_ACCOUNTING_VERSION: &str = "explicit-v1";

/// Typed proof that an install will submit explicit Pool attribution after linking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ManagedInstallAccounting;

/// A resolved top-level Pool accounting root reported after a successful install.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct PoolInstallRoot {
    /// Canonical LPM package name.
    pub name: String,
    /// Exact resolved package version.
    pub version: String,
}

impl PoolInstallRoot {
    /// Construct a resolved Pool accounting root.
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
        roots: &[PoolInstallRoot],
        _accounting: ManagedInstallAccounting,
    ) -> Result<(), LpmError> {
        if roots.is_empty() {
            return Ok(());
        }

        let url = format!("{}/api/registry/pool/install-report", self.base_url);
        let body = serde_json::json!({ "roots": roots });
        self.execute_with_recovery(AuthPosture::AuthRequired, || {
            self.post_json_raw(&url, &body)
        })
        .await?;
        Ok(())
    }
}
