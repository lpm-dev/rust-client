//! The dependency skills of the user's global packages: `lpm skills link
//! --global` saves selectors to a policy of their own, and installing,
//! updating or removing a global package keeps the links in the home
//! folder's agent folders in sync. Each global package is installed in a
//! folder of its own, and each counts as one importer.

use super::Settings;
use super::policy::{ParsedPolicy, SkillsPolicy};
use super::state::{FileStamp, Site};
use crate::commands::install::FetchedPackageSkills;
use cap_fs_ext::DirExt as _;
use lpm_common::{LpmError, LpmRoot};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

/// The global policy's file in the LPM root's `global` folder.
pub(super) const POLICY_FILE: &str = "skills.json";

/// Where the global packages' links live, and what decides them.
#[derive(Debug, Clone)]
pub(crate) struct GlobalSkills {
    site: Site,
    lpm_root: LpmRoot,
    tx_lock: PathBuf,
    policy_path: PathBuf,
    manifest: GlobalManifestRead,
}

/// The active global packages as one read of the global manifest found
/// them, and that read's size, modification time and digest, all taken
/// from one open file.
#[derive(Debug, Clone, Default)]
pub(crate) struct GlobalManifestRead {
    packages: Vec<GlobalPackage>,
    installs: Vec<PathBuf>,
    contents: Option<ManifestContents>,
}

#[derive(Debug, Clone)]
struct ManifestContents {
    size: u64,
    modified_nanos: u64,
    checked_nanos: u64,
    digest: String,
}

/// An active global package and the folder it is installed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) root: PathBuf,
}

impl GlobalSkills {
    /// The global packages of the LPM root, with their links in the home
    /// folder. Fails when the global manifest can't be read, rather than
    /// taking it for one that lists no packages.
    pub(crate) fn locate() -> Result<Self, LpmError> {
        let (root, site) = root_and_site()?;
        Self::at(&root, site)
    }

    /// [`Self::locate`], or `None` without a global policy or links LPM
    /// made, judged with two `stat` calls before the global manifest is
    /// read.
    pub(crate) fn locate_with_work() -> Result<Option<Self>, LpmError> {
        let (root, site) = root_and_site()?;
        let has_work = std::fs::symlink_metadata(root.global_root().join(POLICY_FILE)).is_ok()
            || super::state::state_exists(&site);
        if !has_work {
            return Ok(None);
        }
        Self::at(&root, site).map(Some)
    }

    fn at(root: &LpmRoot, site: Site) -> Result<Self, LpmError> {
        let manifest = read_manifest(root)?;
        Ok(Self {
            site,
            lpm_root: root.clone(),
            policy_path: root.global_root().join(POLICY_FILE),
            tx_lock: root.global_tx_lock(),
            manifest,
        })
    }

    #[inline]
    pub(crate) fn site(&self) -> &Site {
        &self.site
    }

    #[inline]
    pub(crate) fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// The LPM root whose `global` folder holds the policy, which is only
    /// ever opened without following a link in its place.
    #[inline]
    pub(crate) fn lpm_root(&self) -> &LpmRoot {
        &self.lpm_root
    }

    /// The global manifest as [`Self::locate`] read it.
    #[inline]
    pub(crate) fn manifest(&self) -> &GlobalManifestRead {
        &self.manifest
    }

    /// The folder each installed global package lives in, as
    /// [`Self::locate`] read them.
    #[inline]
    pub(crate) fn installs(&self) -> &[PathBuf] {
        self.manifest.installs()
    }

    /// The global manifest as it stands now, for planning under the link
    /// lock from the package list the plan's fingerprint records.
    pub(crate) fn reread_manifest(&self) -> Result<GlobalManifestRead, LpmError> {
        read_manifest(&self.lpm_root)
    }

    /// The LPM.dev global packages whose reviewed skills `policy` may link
    /// under `settings` and whose installed version's skills aren't in
    /// their folder yet: none with LPM.dev package skills off or offline,
    /// none under a policy that links nothing (no allowing entry, or a deny
    /// entry LPM can't read), never one a deny entry names whole or at its
    /// installed version, nor one whose version the registry recently said
    /// it offers no reviewed skills for, and when every allowing entry names
    /// its packages only those.
    pub(crate) fn lpm_dev_sets_to_fetch(
        &self,
        policy: Option<&SkillsPolicy>,
        settings: Settings,
    ) -> Vec<&GlobalPackage> {
        let Some(policy) = policy else {
            return Vec::new();
        };
        if !settings.lpm_dev_packages || settings.offline || !policy.is_active() {
            return Vec::new();
        }
        let named = super::plan::named_packages(policy);
        let denied: Vec<&str> = policy
            .deny
            .iter()
            .filter_map(|entry| match &entry.selector {
                lpm_security::query::Selector::Id(id) => Some(id.as_str()),
                _ => None,
            })
            .collect();
        let denies = |package: &GlobalPackage| {
            denied.iter().any(|id| {
                *id == package.name
                    || id
                        .strip_prefix(package.name.as_str())
                        .and_then(|rest| rest.strip_prefix('@'))
                        == Some(package.version.as_str())
            })
        };
        self.lpm_dev_packages_without_sets(settings)
            .into_iter()
            .filter(|package| {
                !denies(package)
                    && named
                        .as_ref()
                        .is_none_or(|names| names.contains(&package.name))
            })
            .collect()
    }

    /// The LPM.dev global packages whose installed version's reviewed
    /// skills aren't in their folder and could be fetched, whatever the
    /// policy says: what the picker offers besides the skills it can see.
    /// None with LPM.dev package skills off or offline, and never one whose
    /// version the registry recently said it offers no reviewed skills for.
    pub(crate) fn lpm_dev_packages_without_sets(&self, settings: Settings) -> Vec<&GlobalPackage> {
        if !settings.lpm_dev_packages || settings.offline {
            return Vec::new();
        }
        self.manifest
            .packages
            .iter()
            .filter(|package| {
                super::plan::is_lpm_dev(&package.name)
                    && !crate::commands::skills::package::version_is_materialized(
                        &package.root,
                        &package.name,
                        &package.version,
                    )
                    && !crate::commands::skills::reviews::refusal_is_current(
                        package
                            .name
                            .strip_prefix("@lpm.dev/")
                            .unwrap_or(&package.name),
                        &package.version,
                    )
            })
            .collect()
    }

    /// Runs `body` holding [`Self::tx_lock`], as global installs hold it,
    /// once LPM's global folder is known not to be a link, so the lock never
    /// lands in a folder a link points at.
    pub(crate) fn with_tx_lock<T>(
        &self,
        body: impl FnOnce() -> Result<T, LpmError>,
    ) -> Result<T, LpmError> {
        lpm_common::open_or_create_global_directory(&self.lpm_root)?;
        lpm_common::with_exclusive_lock(&self.tx_lock, body)
    }

    /// Writes each fetched set into the folder of its package when the
    /// global manifest, read again, still lists that package at the same
    /// version in the same folder, reached through real folders only: a
    /// package removed or replaced since gets nothing. Returns a warning for
    /// each set not written. Holds [`Self::tx_lock`], which keeps the
    /// manifest and the folders from changing meanwhile, only when there is
    /// a set to write.
    pub(crate) fn write_fetched_sets(
        &self,
        fetched: Vec<(GlobalPackage, FetchedPackageSkills)>,
    ) -> Result<Vec<String>, LpmError> {
        if fetched.is_empty() {
            return Ok(Vec::new());
        }
        self.with_tx_lock(|| self.write_fetched_sets_locked(fetched))
    }

    /// [`Self::write_fetched_sets`] for a caller holding [`Self::tx_lock`].
    pub(crate) fn write_fetched_sets_locked(
        &self,
        fetched: Vec<(GlobalPackage, FetchedPackageSkills)>,
    ) -> Result<Vec<String>, LpmError> {
        if fetched.is_empty() {
            return Ok(Vec::new());
        }
        let current = self.reread_manifest()?;
        let installed: std::collections::HashMap<&str, &GlobalPackage> = current
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package))
            .collect();
        let installs = lpm_common::open_global_directory(&self.lpm_root)?
            .map(|global| global.open_dir_nofollow("installs"))
            .transpose();
        let mut warnings = Vec::new();
        for (package, skills) in fetched {
            if installed.get(package.name.as_str()) != Some(&&package) {
                continue;
            }
            let plain = match &installs {
                Ok(Some(installs)) => package
                    .root
                    .file_name()
                    .is_some_and(|leaf| installs.open_dir_nofollow(leaf).is_ok()),
                _ => false,
            };
            if let Err(error) = skills.record_refusal() {
                tracing::debug!("could not record a skill review refusal: {error}");
            }
            if !plain {
                warnings.push(format!(
                    "package skills for {}@{} were not written: its install folder {} is not a plain directory",
                    package.name,
                    package.version,
                    package.root.display()
                ));
                continue;
            }
            if let Err(warning) = skills.write(&package.root) {
                warnings.push(warning);
            }
        }
        Ok(warnings)
    }

    /// Whether anything could need reconciling: a policy, or links LPM
    /// made. Two `stat` calls, for the hooks after global installs.
    pub(crate) fn may_have_work(&self) -> bool {
        std::fs::symlink_metadata(&self.policy_path).is_ok()
            || super::state::state_exists(&self.site)
    }

    /// The global policy document: the policy object itself, empty when
    /// the file doesn't exist.
    pub(crate) fn policy_document(&self) -> Result<serde_json::Value, LpmError> {
        let text = match lpm_common::open_global_directory(&self.lpm_root)? {
            Some(directory) => read_policy_text(&directory, &self.policy_path)?,
            None => None,
        };
        let Some(text) = text else {
            return Ok(serde_json::Value::Object(serde_json::Map::new()));
        };
        serde_json::from_str(lpm_common::strip_utf8_bom_str(&text)).map_err(|error| {
            LpmError::Registry(format!("invalid {}: {error}", self.policy_path.display()))
        })
    }

    /// The global policy as a reconcile reads it: a document LPM can't read
    /// links nothing, and says why.
    pub(crate) fn read_policy(&self) -> ParsedPolicy {
        match self.policy_document() {
            Ok(document) => super::policy::read_global_policy(&document),
            Err(error) => ParsedPolicy::unreadable(format!(
                "{error}, so no global dependency skills are linked until it is fixed"
            )),
        }
    }
}

impl GlobalManifestRead {
    /// The folder each installed global package lives in, in name order.
    #[inline]
    pub(crate) fn installs(&self) -> &[PathBuf] {
        &self.installs
    }

    /// The manifest's identity, for the link record: `recorded` while it
    /// names the same bytes, size and modification time, so an unchanged
    /// manifest leaves the record as it is. `None` without a manifest.
    pub(crate) fn stamp(&self, recorded: Option<&FileStamp>) -> Option<FileStamp> {
        let contents = self.contents.as_ref()?;
        if let Some(recorded) = recorded
            && recorded.size == contents.size
            && recorded.modified_nanos == contents.modified_nanos
            && recorded.digest == contents.digest
        {
            return Some(recorded.clone());
        }
        Some(FileStamp {
            size: contents.size,
            modified_nanos: contents.modified_nanos,
            checked_nanos: contents.checked_nanos,
            digest: contents.digest.clone(),
        })
    }
}

/// The global policy file's text, read through `directory`, LPM's global
/// folder, without following a link in the file's place: `None` when it
/// doesn't exist. `shown` names it in errors.
pub(super) fn read_policy_text(
    directory: &cap_std::fs::Dir,
    shown: &Path,
) -> Result<Option<String>, LpmError> {
    let Some((bytes, _)) = read_file_in(
        directory,
        POLICY_FILE,
        shown,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?
    else {
        return Ok(None);
    };
    String::from_utf8(bytes).map(Some).map_err(|error| {
        read_error(
            shown,
            std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        )
    })
}

/// The regular file `name` in `directory`, opened without following a link
/// in its place and read up to `limit` bytes, with the metadata of the file
/// read: `None` when nothing is there. A link, even one to nowhere, is an
/// error. `shown` names it in errors.
fn read_file_in(
    directory: &cap_std::fs::Dir,
    name: &str,
    shown: &Path,
    limit: u64,
) -> Result<Option<(Vec<u8>, cap_std::fs::Metadata)>, LpmError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
    use std::io::Read as _;

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(read_error(shown, error)),
    };
    let metadata = file.metadata().map_err(|error| read_error(shown, error))?;
    if !metadata.is_file() {
        return Err(read_error(
            shown,
            std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len().min(limit)).unwrap_or(0));
    file.into_std()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| read_error(shown, error))?;
    if bytes.len() as u64 > limit {
        return Err(read_error(
            shown,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("exceeds the {limit}-byte limit"),
            ),
        ));
    }
    Ok(Some((bytes, metadata)))
}

fn read_error(shown: &Path, error: std::io::Error) -> LpmError {
    LpmError::Io(std::io::Error::new(
        error.kind(),
        format!("failed to read {}: {error}", shown.display()),
    ))
}

/// Where the global packages' links live, without reading the global
/// manifest.
pub(crate) fn global_site() -> Result<Site, LpmError> {
    root_and_site().map(|(_, site)| site)
}

fn root_and_site() -> Result<(LpmRoot, Site), LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Registry("could not determine the home folder for global skills".into())
    })?;
    let root = LpmRoot::from_env()?;
    let site = Site::global(&home, root.root());
    Ok((root, site))
}

/// Reads `root`'s global manifest once, through its global folder opened
/// without following links: the active global packages, in name order, and
/// the identity of the bytes they came from. No manifest lists no packages;
/// one LPM can't read, a link in its place included, is an error. A
/// developer checkout linked onto PATH isn't installed, so its folder isn't
/// read, and a package recorded with a folder that isn't an install folder
/// is ignored.
fn read_manifest(root: &LpmRoot) -> Result<GlobalManifestRead, LpmError> {
    let Some(global) = lpm_common::open_global_directory(root)? else {
        return Ok(GlobalManifestRead::default());
    };
    let Some((bytes, metadata)) = read_file_in(
        &global,
        lpm_global::MANIFEST_FILENAME,
        &root.global_manifest(),
        lpm_common::STATE_FILE_SIZE_CAP_BYTES,
    )?
    else {
        return Ok(GlobalManifestRead::default());
    };
    let checked_nanos = super::nanos_since_epoch(std::time::SystemTime::now()).unwrap_or(0);
    let manifest = lpm_global::parse_manifest(&bytes)?;
    let global_root = root.global_root();
    let packages: Vec<GlobalPackage> = manifest
        .packages
        .iter()
        .filter(|(_, entry)| entry.source != lpm_global::PackageSource::LocalLink)
        .filter_map(|(name, entry)| {
            let root =
                lpm_global::validated_install_root_relative(&global_root, &entry.root).ok()?;
            Some(GlobalPackage {
                name: name.clone(),
                version: entry.resolved.clone(),
                root,
            })
        })
        .collect();
    let installs = packages
        .iter()
        .map(|package| package.root.clone())
        .collect();
    Ok(GlobalManifestRead {
        packages,
        installs,
        contents: Some(ManifestContents {
            size: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std)
                .and_then(super::nanos_since_epoch)
                .unwrap_or(0),
            checked_nanos,
            digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_PACKAGES: &str = r#"schema_version = 1

[packages.zeta]
saved_spec = "^1.0.0"
resolved = "1.0.0"
integrity = "sha512-zeta"
source = "upstream-npm"
installed_at = "2026-01-01T00:00:00Z"
root = "installs/zeta@1.0.0"
commands = []

[packages.alpha]
saved_spec = "^2.0.0"
resolved = "2.0.0"
integrity = "sha512-alpha"
source = "upstream-npm"
installed_at = "2026-01-01T00:00:00Z"
root = "installs/alpha@2.0.0"
commands = []
"#;

    fn manifest_in(dir: &Path, text: &str) -> LpmRoot {
        let root = LpmRoot::from_dir(dir);
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(root.global_manifest(), text).unwrap();
        root
    }

    #[test]
    fn a_missing_global_manifest_lists_no_packages_and_has_no_stamp() {
        let dir = tempfile::tempdir().unwrap();

        let read = read_manifest(&LpmRoot::from_dir(dir.path())).unwrap();

        assert!(read.installs().is_empty());
        assert_eq!(read.stamp(None), None);
    }

    #[test]
    fn a_global_manifest_newer_than_lpm_reads_as_an_error_not_as_no_packages() {
        let dir = tempfile::tempdir().unwrap();
        let root = manifest_in(dir.path(), "schema_version = 999\n");

        let error = read_manifest(&root).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("newer than this binary supports"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_manifest_or_global_folder_that_is_a_link_reads_as_an_error_not_as_no_packages() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::os::unix::fs::symlink(
            elsewhere.path().join("missing.toml"),
            root.global_manifest(),
        )
        .unwrap();
        assert!(read_manifest(&root).is_err(), "a link to nowhere");

        std::fs::remove_dir_all(root.global_root()).unwrap();
        std::fs::write(elsewhere.path().join("manifest.toml"), TWO_PACKAGES).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.global_root()).unwrap();
        assert!(read_manifest(&root).is_err(), "a linked global folder");
    }

    #[test]
    fn a_global_manifest_lpm_cannot_parse_reads_as_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = manifest_in(dir.path(), "schema_version = [\n");

        assert!(read_manifest(&root).is_err());
    }

    #[test]
    fn one_manifest_read_lists_packages_in_name_order_and_stamps_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root = manifest_in(dir.path(), TWO_PACKAGES);

        let read = read_manifest(&root).unwrap();

        assert_eq!(
            read.installs(),
            [
                root.global_root().join("installs/alpha@2.0.0"),
                root.global_root().join("installs/zeta@1.0.0"),
            ]
        );
        let stamp = read.stamp(None).unwrap();
        assert_eq!(stamp.size, TWO_PACKAGES.len() as u64);
        assert_eq!(
            stamp.digest,
            format!("sha256:{}", hex::encode(Sha256::digest(TWO_PACKAGES)))
        );
    }

    #[test]
    fn rereading_the_global_manifest_sees_a_package_installed_since_it_was_located() {
        let dir = tempfile::tempdir().unwrap();
        let root = manifest_in(
            dir.path(),
            &TWO_PACKAGES.replace("[packages.alpha]", "[packages.alpha-old]"),
        );
        let located = read_manifest(&root).unwrap();
        manifest_in(dir.path(), TWO_PACKAGES);
        let global = GlobalSkills {
            site: Site::project(dir.path()),
            lpm_root: root,
            tx_lock: dir.path().join(".tx.lock"),
            policy_path: dir.path().join(POLICY_FILE),
            manifest: located,
        };

        let reread = global.reread_manifest().unwrap();

        assert_ne!(
            reread.stamp(None).unwrap().digest,
            global.manifest().stamp(None).unwrap().digest
        );
        assert_eq!(
            reread.stamp(None).unwrap().digest,
            format!("sha256:{}", hex::encode(Sha256::digest(TWO_PACKAGES)))
        );
    }

    #[test]
    fn the_picker_is_offered_lpm_dev_packages_whose_reviewed_skills_are_missing_and_never_offline()
    {
        let dir = tempfile::tempdir().unwrap();
        let text = TWO_PACKAGES
            .replace("[packages.zeta]", "[packages.\"@lpm.dev/acme.cli\"]")
            .replace("installs/zeta@1.0.0", "installs/@lpm.dev+acme.cli@1.0.0");
        let root = manifest_in(dir.path(), &text);
        let global = GlobalSkills::at(&root, Site::project(dir.path())).unwrap();
        let mut settings = super::super::tests::settings();
        settings.lpm_dev_packages = true;

        let offered: Vec<&str> = global
            .lpm_dev_packages_without_sets(settings)
            .into_iter()
            .map(|package| package.name.as_str())
            .collect();

        assert_eq!(offered, ["@lpm.dev/acme.cli"]);
        settings.offline = true;
        assert!(global.lpm_dev_packages_without_sets(settings).is_empty());
    }

    #[test]
    fn an_unchanged_global_manifest_keeps_the_recorded_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let root = manifest_in(dir.path(), TWO_PACKAGES);
        let read = read_manifest(&root).unwrap();
        let mut recorded = read.stamp(None).unwrap();
        recorded.checked_nanos = 1;

        assert_eq!(read.stamp(Some(&recorded)), Some(recorded.clone()));
        recorded.digest = "sha256:other".into();
        assert_ne!(read.stamp(Some(&recorded)), Some(recorded));
    }

    #[test]
    fn linked_checkouts_and_folders_outside_installs_are_not_global_installs() {
        let dir = tempfile::tempdir().unwrap();
        let text = TWO_PACKAGES
            .replace(
                "root = \"installs/zeta@1.0.0\"",
                "root = \"installs/../../escape@1.0.0\"",
            )
            .replace("source = \"upstream-npm\"\ninstalled_at = \"2026-01-01T00:00:00Z\"\nroot = \"installs/alpha@2.0.0\"", "source = \"local-link\"\ninstalled_at = \"2026-01-01T00:00:00Z\"\nroot = \"links/alpha\"");
        let root = manifest_in(dir.path(), &text);

        let read = read_manifest(&root).unwrap();

        assert!(read.installs().is_empty(), "{:?}", read.installs());
    }
}
