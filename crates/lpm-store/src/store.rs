use std::path::{Path, PathBuf};

use lpm_common::{LpmError, LpmRoot};

use crate::{STORE_VERSION, is_complete_package_dir};

/// The global content-addressable package store.
#[derive(Clone)]
pub struct PackageStore {
    /// Root directory of the store (e.g., ~/.lpm/store).
    root: PathBuf,
    /// `~/.lpm/store/v1/` — precomputed to avoid one PathBuf
    /// allocation per `package_dir` call on hot install paths.
    v1_root: PathBuf,
}

impl PackageStore {
    /// Create a store at the default location (`~/.lpm/store`).
    ///
    /// Thin convenience wrapper around [`PackageStore::from_root`] that
    /// resolves the LPM home through [`LpmRoot::from_env`]. Prefer
    /// [`PackageStore::from_root`] when the caller already has an
    /// `LpmRoot` in scope — the store then shares the same home-resolution
    /// decision as every other path in the command.
    pub fn default_location() -> Result<Self, LpmError> {
        Ok(Self::from_root(&LpmRoot::from_env()?))
    }

    /// Create a store rooted at the given [`LpmRoot`]'s `store/` directory.
    pub fn from_root(root: &LpmRoot) -> Self {
        let store_root = root.store_root();
        let v1_root = store_root.join(STORE_VERSION);
        PackageStore {
            root: store_root,
            v1_root,
        }
    }

    /// Create a store at a specific path (for testing).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let v1_root = root.join(STORE_VERSION);
        PackageStore { root, v1_root }
    }

    /// Derive an [`lpm_common::LpmRoot`] from this store's root.
    /// `PackageStore::root` is `<lpm_root>/store/`, so the LpmRoot is
    /// the parent. Used by callers that need to consult the v2
    /// virtual store (constructed via [`crate::v2::Store::from_lpm_root`])
    /// without threading an additional `LpmRoot` parameter through
    /// every API.
    pub fn lpm_root(&self) -> Result<lpm_common::LpmRoot, LpmError> {
        let parent = self.root.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "package store root {:?} has no parent — cannot derive LpmRoot",
                self.root
            ))
        })?;
        Ok(lpm_common::LpmRoot::from_dir(parent))
    }

    /// Get the store directory for a package version.
    /// e.g., `~/.lpm/store/v1/react@19.2.4/`
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        use std::borrow::Cow;
        // Avoid heap alloc for the common case of unscoped packages.
        let safe_name: Cow<'_, str> = if name.contains(['/', '\\']) {
            Cow::Owned(name.replace(['/', '\\'], "+"))
        } else {
            Cow::Borrowed(name)
        };
        self.v1_root.join(format!("{safe_name}@{version}"))
    }

    /// Get the store root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Check if a package version is already in the store.
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        let dir = self.package_dir(name, version);
        is_complete_package_dir(&dir)
    }

    /// Check whether the coordinate-keyed v1 entry carries the exact
    /// integrity selected by the current resolution.
    pub fn has_package_with_integrity(
        &self,
        name: &str,
        version: &str,
        expected_integrity: &str,
    ) -> bool {
        let dir = self.package_dir(name, version);
        is_complete_package_dir(&dir)
            && crate::read_stored_integrity(&dir).as_deref() == Some(expected_integrity)
    }
}
