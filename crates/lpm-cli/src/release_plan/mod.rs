use lpm_common::LpmError;
use lpm_semver::{Version, VersionBump, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

const RELEASE_JOURNAL_SCHEMA_VERSION: u32 = 1;
const RELEASE_STATE_DIRECTORY: &str = "release-apply";
const RELEASE_JOURNAL_FILE: &str = "journal.json";
const RELEASE_COMMIT_FILE: &str = "commit.json";
const MAX_RELEASE_COMMIT_BYTES: u64 = 8 * 1024;
const RELEASE_TRANSACTION_ID_BYTES: usize = 16;
const RELEASE_TRANSACTION_ID_HEX_BYTES: usize = RELEASE_TRANSACTION_ID_BYTES * 2;
const MAX_RELEASE_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RELEASE_JOURNAL_ENTRIES: usize = 128;
const MAX_RELEASE_ORIGINAL_BYTES: usize = 48 * 1024 * 1024;
const MAX_RELEASE_UPDATED_BYTES: usize = 48 * 1024 * 1024;
const MAX_RELEASE_PATH_BYTES: usize = 64 * 1024;
const MAX_RELEASE_ENCODED_PATH_BYTES: usize = MAX_RELEASE_PATH_BYTES.div_ceil(3) * 4;
const MAX_RELEASE_ENCODED_MANIFEST_BYTES: usize =
    (lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize).div_ceil(3) * 4;
const MAX_RELEASE_GIT_OID_BYTES: usize = 128;
const MAX_RELEASE_GIT_TAG_BYTES: usize = 4096;

const DEPENDENCY_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReleasePlan {
    pub(crate) packages: Vec<PackageRelease>,
    pub(crate) dependency_updates: Vec<DependencyUpdate>,
    pub(crate) files: Vec<FileUpdate>,
    #[serde(skip)]
    source_manifests: BTreeMap<PathBuf, SourceManifest>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageRelease {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) manifest_path: PathBuf,
    pub(crate) old_version: String,
    pub(crate) new_version: String,
    pub(crate) bump: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DependencyUpdate {
    pub(crate) dependent: String,
    pub(crate) dependency: String,
    pub(crate) section: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) old_spec: String,
    pub(crate) new_spec: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FileUpdate {
    pub(crate) path: PathBuf,
    pub(crate) changes: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedManifest {
    pub(crate) path: PathBuf,
    original_bytes: Arc<[u8]>,
    updated_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionGitTransaction {
    pub(crate) old_head: String,
    pub(crate) tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReleaseTransactionOperationKind {
    ReleaseApply,
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseTransactionOperation {
    kind: ReleaseTransactionOperationKind,
    #[serde(deserialize_with = "deserialize_release_digest")]
    fingerprint: String,
}

impl ReleaseTransactionOperation {
    pub(crate) fn new(kind: ReleaseTransactionOperationKind, identity: &[u8]) -> Self {
        Self {
            kind,
            fingerprint: sha256_hex(identity),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReleaseOperationRecoveryOutcome {
    Continue,
    Completed { tag: Option<String> },
}

#[derive(Debug, Clone)]
struct SourceManifest {
    original_bytes: Arc<[u8]>,
    json: serde_json::Value,
}

struct CappedManifestWriter {
    bytes: Vec<u8>,
    limit: usize,
    limit_exceeded: bool,
}

impl CappedManifestWriter {
    fn new(initial_capacity: usize, limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(initial_capacity.min(limit)),
            limit,
            limit_exceeded: false,
        }
    }
}

impl std::io::Write for CappedManifestWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "serialized package.json exceeds the manifest limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct WorkspaceManifest {
    name: String,
    version: Version,
    path: PathBuf,
    manifest_path: PathBuf,
    original_bytes: Arc<[u8]>,
    json: serde_json::Value,
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseApplyJournal {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_release_transaction_id")]
    transaction_id: String,
    operation: ReleaseTransactionOperation,
    state: ReleaseApplyJournalState,
    #[serde(deserialize_with = "deserialize_release_path_encoding")]
    path_encoding: String,
    #[serde(deserialize_with = "deserialize_release_journal_entries")]
    entries: Vec<ReleaseApplyJournalEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version_git: Option<VersionGitJournal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseApplyJournalState {
    Applying,
    Complete,
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseApplyJournalEntry {
    #[serde(deserialize_with = "deserialize_release_encoded_path")]
    path: String,
    #[serde(deserialize_with = "deserialize_release_digest")]
    original_sha256: String,
    #[serde(deserialize_with = "deserialize_release_manifest_backup")]
    original_base64: String,
    #[serde(deserialize_with = "deserialize_release_digest")]
    updated_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryApplyJournal<'a> {
    schema_version: u32,
    #[serde(
        borrow,
        deserialize_with = "deserialize_borrowed_release_transaction_id"
    )]
    transaction_id: &'a str,
    operation: ReleaseTransactionOperation,
    state: ReleaseApplyJournalState,
    #[serde(
        borrow,
        deserialize_with = "deserialize_borrowed_release_path_encoding"
    )]
    path_encoding: &'a str,
    #[serde(borrow, deserialize_with = "deserialize_recovery_journal_entries")]
    entries: Vec<RecoveryApplyJournalEntry<'a>>,
    #[serde(default)]
    version_git: Option<VersionGitJournal>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryApplyJournalEntry<'a> {
    #[serde(borrow, deserialize_with = "deserialize_borrowed_release_encoded_path")]
    path: &'a str,
    #[serde(borrow, deserialize_with = "deserialize_borrowed_release_digest")]
    original_sha256: &'a str,
    #[serde(
        borrow,
        deserialize_with = "deserialize_borrowed_release_manifest_backup"
    )]
    original_base64: &'a str,
    #[serde(borrow, deserialize_with = "deserialize_borrowed_release_digest")]
    updated_sha256: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionGitJournal {
    #[serde(deserialize_with = "deserialize_release_git_oid")]
    old_head: String,
    #[serde(deserialize_with = "deserialize_release_git_tag")]
    tag: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseApplyCommit {
    schema_version: u32,
    journal_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation: Option<ReleaseTransactionOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[cfg(test)]
fn deserialize_release_journal_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<ReleaseApplyJournalEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;

    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = Vec<ReleaseApplyJournalEntry>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_RELEASE_JOURNAL_ENTRIES} release journal entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_RELEASE_JOURNAL_ENTRIES)
            {
                return Err(serde::de::Error::invalid_length(
                    MAX_RELEASE_JOURNAL_ENTRIES + 1,
                    &self,
                ));
            }
            let mut entries = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(MAX_RELEASE_JOURNAL_ENTRIES),
            );
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == MAX_RELEASE_JOURNAL_ENTRIES {
                    return Err(serde::de::Error::invalid_length(entries.len() + 1, &self));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(EntriesVisitor)
}

fn deserialize_recovery_journal_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<RecoveryApplyJournalEntry<'de>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;

    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = Vec<RecoveryApplyJournalEntry<'de>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_RELEASE_JOURNAL_ENTRIES} borrowed release journal entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_RELEASE_JOURNAL_ENTRIES)
            {
                return Err(serde::de::Error::invalid_length(
                    MAX_RELEASE_JOURNAL_ENTRIES + 1,
                    &self,
                ));
            }
            let mut entries = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(MAX_RELEASE_JOURNAL_ENTRIES),
            );
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == MAX_RELEASE_JOURNAL_ENTRIES {
                    return Err(serde::de::Error::invalid_length(entries.len() + 1, &self));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(EntriesVisitor)
}

#[cfg(test)]
fn deserialize_release_path_encoding<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, 32>(deserializer, "release journal path encoding")
}

#[cfg(test)]
fn deserialize_release_transaction_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, RELEASE_TRANSACTION_ID_HEX_BYTES>(
        deserializer,
        "release transaction ID",
    )
}

#[cfg(test)]
fn deserialize_release_encoded_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RELEASE_ENCODED_PATH_BYTES>(
        deserializer,
        "encoded release manifest path",
    )
}

fn deserialize_release_digest<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, 64>(deserializer, "release manifest SHA-256 digest")
}

#[cfg(test)]
fn deserialize_release_manifest_backup<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RELEASE_ENCODED_MANIFEST_BYTES>(
        deserializer,
        "encoded release manifest backup",
    )
}

fn deserialize_release_git_oid<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RELEASE_GIT_OID_BYTES>(deserializer, "Git object ID")
}

fn deserialize_release_git_tag<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RELEASE_GIT_TAG_BYTES>(deserializer, "Git tag")
}

fn deserialize_borrowed_release_transaction_id<'de, D>(
    deserializer: D,
) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_borrowed_str::<D, RELEASE_TRANSACTION_ID_HEX_BYTES>(
        deserializer,
        "release transaction ID",
    )
}

fn deserialize_borrowed_release_path_encoding<'de, D>(deserializer: D) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_borrowed_str::<D, 32>(deserializer, "release journal path encoding")
}

fn deserialize_borrowed_release_encoded_path<'de, D>(deserializer: D) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_borrowed_str::<D, MAX_RELEASE_ENCODED_PATH_BYTES>(
        deserializer,
        "encoded release manifest path",
    )
}

fn deserialize_borrowed_release_digest<'de, D>(deserializer: D) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_borrowed_str::<D, 64>(deserializer, "release manifest SHA-256 digest")
}

fn deserialize_borrowed_release_manifest_backup<'de, D>(
    deserializer: D,
) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_borrowed_str::<D, MAX_RELEASE_ENCODED_MANIFEST_BYTES>(
        deserializer,
        "encoded release manifest backup",
    )
}

fn deserialize_bounded_borrowed_str<'de, D, const MAX: usize>(
    deserializer: D,
    description: &'static str,
) -> Result<&'de str, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BorrowedStringVisitor<const MAX: usize> {
        description: &'static str,
    }

    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BorrowedStringVisitor<MAX> {
        type Value = &'de str;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{} no longer than {MAX} bytes", self.description)
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX {
                return Err(E::invalid_length(value.len(), &self));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_str(BorrowedStringVisitor::<MAX> { description })
}

fn deserialize_bounded_string<'de, D, const MAX: usize>(
    deserializer: D,
    description: &'static str,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedStringVisitor<const MAX: usize> {
        description: &'static str,
    }

    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedStringVisitor<MAX> {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{} no longer than {MAX} bytes", self.description)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX {
                return Err(E::invalid_length(value.len(), &self));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX {
                return Err(E::invalid_length(value.len(), &self));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor::<MAX> { description })
}

struct RecoveryEntry {
    target: ManifestTarget,
    original: Vec<u8>,
    updated_sha256: String,
    restore: bool,
}

struct ManifestTarget {
    parent: cap_std::fs::Dir,
    file_name: OsString,
    display: PathBuf,
}

struct ReleaseStateDirectory {
    dir: cap_std::fs::Dir,
    display: PathBuf,
}

struct ResolvedPlannedManifest<'a> {
    relative: PathBuf,
    encoded_path: String,
    target: ManifestTarget,
    manifest: &'a PlannedManifest,
}

impl ReleasePlan {
    pub(crate) fn to_json(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "dry_run": dry_run,
            "packages": self.packages,
            "dependency_updates": self.dependency_updates,
            "files": self.files,
        })
    }

    pub(crate) fn planned_manifests(&self) -> Result<Vec<PlannedManifest>, LpmError> {
        let mut manifests: BTreeMap<PathBuf, SourceManifest> = BTreeMap::new();

        for package in &self.packages {
            let entry = self.manifest_draft(&mut manifests, &package.manifest_path)?;
            replace_top_level_string(
                &mut entry.json,
                "version",
                &package.old_version,
                &package.new_version,
            )?;
        }

        for update in &self.dependency_updates {
            let entry = self.manifest_draft(&mut manifests, &update.manifest_path)?;
            replace_dependency_string(
                &mut entry.json,
                &update.section,
                &update.dependency,
                &update.old_spec,
                &update.new_spec,
            )?;
        }

        let mut planned = Vec::with_capacity(manifests.len());
        let mut total_updated_bytes = 0usize;
        for (path, manifest) in manifests {
            let remaining_updated_bytes = MAX_RELEASE_UPDATED_BYTES - total_updated_bytes;
            let updated_bytes = serialize_updated_manifest(
                &path,
                &manifest.json,
                manifest.original_bytes.len(),
                remaining_updated_bytes,
            )?;
            total_updated_bytes =
                checked_total_updated_bytes(total_updated_bytes, updated_bytes.len())?;
            planned.push(PlannedManifest {
                path,
                original_bytes: manifest.original_bytes,
                updated_bytes,
            });
        }
        Ok(planned)
    }

    fn manifest_draft<'a>(
        &'a self,
        manifests: &'a mut BTreeMap<PathBuf, SourceManifest>,
        path: &Path,
    ) -> Result<&'a mut SourceManifest, LpmError> {
        match manifests.entry(path.to_path_buf()) {
            std::collections::btree_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let source = self.source_manifests.get(path).ok_or_else(|| {
                    LpmError::Script(format!(
                        "release plan is missing the original bytes for {}",
                        path.display()
                    ))
                })?;
                Ok(entry.insert(source.clone()))
            }
        }
    }
}

fn serialize_updated_manifest(
    path: &Path,
    manifest: &serde_json::Value,
    estimated_size: usize,
    aggregate_remaining: usize,
) -> Result<Vec<u8>, LpmError> {
    let manifest_limit = lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize;
    let output_limit = manifest_limit.min(aggregate_remaining);
    if output_limit == 0 {
        return Err(updated_manifest_size_error());
    }
    let mut writer = CappedManifestWriter::new(estimated_size, output_limit - 1);
    if let Err(error) = serde_json::to_writer_pretty(&mut writer, manifest) {
        if writer.limit_exceeded {
            if output_limit < manifest_limit {
                return Err(updated_manifest_size_error());
            }
            return Err(manifest_size_error(path, "serialized package.json"));
        }
        return Err(error.into());
    }
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

fn checked_total_updated_bytes(current: usize, next: usize) -> Result<usize, LpmError> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| LpmError::Script("release updated manifest size overflow".into()))?;
    if total > MAX_RELEASE_UPDATED_BYTES {
        return Err(updated_manifest_size_error());
    }
    Ok(total)
}

fn updated_manifest_size_error() -> LpmError {
    LpmError::Script(format!(
        "release updated manifests exceed the {} MiB in-memory transaction limit",
        MAX_RELEASE_UPDATED_BYTES / (1024 * 1024)
    ))
}

fn manifest_size_error(path: &Path, description: &str) -> LpmError {
    LpmError::Script(format!(
        "{description} for {} exceeds the {}-byte package manifest limit",
        path.display(),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES
    ))
}

mod planning;
mod transaction;
mod version_git;

use planning::*;
use transaction::*;
use version_git::*;

pub(crate) use planning::{
    ensure_unique_selection, load_change_bumps, plan_single_package, plan_workspace,
    sorted_selected_indices, validate_workspace_internal_ranges,
};
pub(crate) use transaction::{
    ensure_no_pending_release_transaction, ensure_no_pending_release_transaction_from_open_root,
    has_release_transaction_from_open_root, recover_pending_operation_transaction,
    recover_pending_release_transaction_from_open_root, write_planned_manifests,
    write_planned_manifests_then_git,
};
pub(crate) use version_git::create_version_commit_and_tag;

pub(crate) fn write_publish_manifest_relative_durable(
    parent: &cap_std::fs::Dir,
    file_name: &OsStr,
    bytes: &[u8],
) -> std::io::Result<()> {
    transaction::write_relative_file_durable(parent, file_name, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_workspace::{PackageJson, Workspace, WorkspaceMember};
    use tempfile::TempDir;

    fn write_manifest(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("package.json"), body).unwrap();
    }

    fn workspace_with_app_dep(app_dep: &str) -> (TempDir, Workspace) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let core = root.join("packages/core");
        let app = root.join("packages/app");
        write_manifest(&core, r#"{"name":"core","version":"1.2.3"}"#);
        write_manifest(
            &app,
            &format!(r#"{{"name":"app","version":"2.0.0","dependencies":{{"core":"{app_dep}"}}}}"#),
        );
        let workspace = Workspace {
            root,
            root_package: PackageJson::default(),
            members: vec![
                WorkspaceMember {
                    path: core.clone(),
                    package: lpm_workspace::read_package_json(&core.join("package.json")).unwrap(),
                },
                WorkspaceMember {
                    path: app.clone(),
                    package: lpm_workspace::read_package_json(&app.join("package.json")).unwrap(),
                },
            ],
        };
        (tmp, workspace)
    }

    fn major_release_manifests(workspace: &Workspace) -> Vec<PlannedManifest> {
        plan_workspace(workspace, &[0], &HashMap::new(), Some(&VersionBump::Major))
            .unwrap()
            .planned_manifests()
            .unwrap()
    }

    fn seed_release_journal(root: &Path, manifests: &[PlannedManifest]) -> PathBuf {
        let canonical_root = canonical_workspace_root(root).unwrap();
        let mut resolved = resolve_planned_manifests(&canonical_root, manifests).unwrap();
        let journal = build_release_journal(&mut resolved).unwrap();
        let bytes = serialize_release_journal(&journal).unwrap();
        persist_release_journal(&canonical_root, &bytes).unwrap();
        canonical_root
    }

    fn planned_manifest_paths(manifests: &[PlannedManifest]) -> Vec<PathBuf> {
        manifests
            .iter()
            .map(|manifest| manifest.path.clone())
            .collect()
    }

    fn root_manifest_allowlist(root: &Path) -> Vec<PathBuf> {
        let manifest = root.join("package.json");
        if !manifest.exists() {
            std::fs::write(&manifest, b"{}").unwrap();
        }
        vec![manifest]
    }

    fn test_operation() -> ReleaseTransactionOperation {
        ReleaseTransactionOperation::new(
            ReleaseTransactionOperationKind::ReleaseApply,
            b"release-plan-unit-test",
        )
    }

    fn run_git(directory: &Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new("git")
            .args(args)
            .current_dir(directory)
            .output()
            .unwrap()
    }

    fn initialize_git_repository(directory: &Path) -> String {
        assert!(run_git(directory, &["init", "--quiet"]).status.success());
        assert!(
            run_git(directory, &["add", "package.json"])
                .status
                .success()
        );
        assert!(
            run_git(
                directory,
                &[
                    "-c",
                    "user.name=LPM Test",
                    "-c",
                    "user.email=lpm-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "initial",
                ],
            )
            .status
            .success()
        );
        let output = run_git(directory, &["rev-parse", "HEAD"]);
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn plan_workspace_updates_dependent_range_when_new_version_is_outside_existing_range() {
        let (_tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Major)).unwrap();

        assert_eq!(plan.dependency_updates.len(), 1);
        assert_eq!(plan.dependency_updates[0].old_spec, "^1.2.3");
        assert_eq!(plan.dependency_updates[0].new_spec, "^2.0.0");
    }

    #[test]
    fn plan_workspace_leaves_dependent_range_when_new_version_is_satisfied() {
        let (_tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Patch)).unwrap();

        assert!(plan.dependency_updates.is_empty());
    }

    #[test]
    fn plan_workspace_leaves_workspace_caret_range_when_new_version_is_satisfied() {
        let (_tmp, workspace) = workspace_with_app_dep("workspace:^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Patch)).unwrap();

        assert!(plan.dependency_updates.is_empty());
    }

    #[test]
    fn plan_workspace_rejects_unselected_dependent_with_unrewritable_range() {
        let (_tmp, workspace) = workspace_with_app_dep(">=1 <2");
        let err = plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Major))
            .unwrap_err();

        assert!(err.to_string().contains("will not accept 2.0.0"));
    }

    #[test]
    fn plan_workspace_rejects_selected_dependent_with_unrewritable_stale_range() {
        let (_tmp, workspace) = workspace_with_app_dep(">=1 <2");
        let err = plan_workspace(
            &workspace,
            &[0, 1],
            &HashMap::new(),
            Some(&VersionBump::Major),
        )
        .unwrap_err();

        assert!(err.to_string().contains("will not accept 2.0.0"));
    }

    #[test]
    fn planned_manifests_reject_pretty_json_that_exceeds_the_manifest_limit() {
        let tmp = TempDir::new().unwrap();
        let mut manifest = String::with_capacity(5_100_000);
        manifest.push_str(r#"{"name":"demo","version":"1.0.0","data":["#);
        for index in 0..2_500_000 {
            if index != 0 {
                manifest.push(',');
            }
            manifest.push('0');
        }
        manifest.push_str("]}");
        assert!(manifest.len() as u64 <= lpm_common::CONFIG_FILE_SIZE_CAP_BYTES);
        std::fs::write(tmp.path().join("package.json"), manifest).unwrap();
        let plan = plan_single_package(tmp.path(), &VersionBump::Patch).unwrap();

        let error = plan.planned_manifests().unwrap_err();

        assert!(error.to_string().contains("serialized package.json"));
    }

    #[test]
    fn capped_manifest_writer_never_retains_bytes_above_its_limit() {
        let value = serde_json::json!({ "padding": "x".repeat(1024) });
        let mut writer = CappedManifestWriter::new(0, 32);

        let error = serde_json::to_writer_pretty(&mut writer, &value).unwrap_err();

        assert!(error.is_io());
        assert!(writer.limit_exceeded);
        assert!(writer.bytes.len() <= writer.limit);
    }

    #[test]
    fn planned_manifests_reject_aggregate_updated_bytes_above_transaction_budget() {
        let tmp = TempDir::new().unwrap();
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let mut packages = Vec::with_capacity(4);
        let mut source_manifests = BTreeMap::new();
        for index in 0..4 {
            let path = tmp.path().join(format!("package-{index}/package.json"));
            packages.push(PackageRelease {
                name: format!("package-{index}"),
                path: path.parent().unwrap().to_path_buf(),
                manifest_path: path.clone(),
                old_version: "1.0.0".into(),
                new_version: "1.0.1".into(),
                bump: "patch".into(),
            });
            source_manifests.insert(
                path,
                SourceManifest {
                    original_bytes: Arc::clone(&original),
                    json: serde_json::json!({
                        "name": format!("package-{index}"),
                        "version": "1.0.0",
                        "padding": "x".repeat(13 * 1024 * 1024),
                    }),
                },
            );
        }
        let plan = ReleasePlan {
            packages,
            dependency_updates: Vec::new(),
            files: Vec::new(),
            source_manifests,
        };

        let error = match plan.planned_manifests() {
            Ok(_) => panic!("aggregate updated manifest bytes were accepted"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("updated manifests exceed"));
    }

    #[test]
    fn write_planned_manifests_rejects_aggregate_updated_bytes_before_mutating_files() {
        let tmp = TempDir::new().unwrap();
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let mut paths = Vec::with_capacity(4);
        let mut manifests = Vec::with_capacity(4);
        for index in 0..4 {
            let path = tmp.path().join(format!("package-{index}/package.json"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, original.as_ref()).unwrap();
            paths.push(path.clone());
            manifests.push(PlannedManifest {
                path,
                original_bytes: Arc::clone(&original),
                updated_bytes: vec![b' '; 13 * 1024 * 1024],
            });
        }

        let error = write_planned_manifests(tmp.path(), &manifests, test_operation()).unwrap_err();

        assert!(error.to_string().contains("updated manifests exceed"));
        assert!(
            paths
                .iter()
                .all(|path| std::fs::read(path).unwrap() == original.as_ref())
        );
        assert!(existing_release_journal_path(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn write_planned_manifests_rejects_oversized_updated_bytes_before_creating_a_journal() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original: Arc<[u8]> = Vec::from(br#"{"name":"demo","version":"1.0.0"}"#).into();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifest = PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: Arc::clone(&original),
            updated_bytes: vec![b' '; lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize + 1],
        };

        let error = write_planned_manifests(tmp.path(), &[manifest], test_operation()).unwrap_err();

        assert!(error.to_string().contains("updated package.json"));
        assert_eq!(std::fs::read(manifest_path).unwrap(), original.as_ref());
        assert!(existing_release_journal_path(tmp.path()).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn release_transaction_entry_limit_fits_a_common_descriptor_budget() {
        const CHILD_ENV: &str = "LPM_TEST_RELEASE_DESCRIPTOR_BUDGET_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("release_plan::tests::release_transaction_entry_limit_fits_a_common_descriptor_budget")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "descriptor-budget child failed\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let descriptor_limit = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        assert_eq!(
            // SAFETY: the child owns this process-wide limit and passes a valid rlimit pointer.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &descriptor_limit) },
            0
        );
        let tmp = TempDir::new().unwrap();
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        let mut manifests = Vec::with_capacity(MAX_RELEASE_JOURNAL_ENTRIES);
        for index in 0..MAX_RELEASE_JOURNAL_ENTRIES {
            let manifest_path = tmp.path().join(index.to_string()).join("package.json");
            std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
            std::fs::write(&manifest_path, original.as_ref()).unwrap();
            manifests.push(PlannedManifest {
                path: manifest_path,
                original_bytes: Arc::clone(&original),
                updated_bytes: updated.clone(),
            });
        }

        write_planned_manifests(tmp.path(), &manifests, test_operation()).unwrap();

        assert!(
            manifests
                .iter()
                .all(|manifest| std::fs::read(&manifest.path).unwrap() == updated)
        );
    }

    #[test]
    fn write_planned_manifests_rejects_external_edits_made_after_planning() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let plan =
            plan_workspace(&workspace, &[0], &HashMap::new(), Some(&VersionBump::Major)).unwrap();
        let planned = plan.planned_manifests().unwrap();
        let core_manifest = tmp.path().join("packages/core/package.json");
        let edited = r#"{"name":"core","version":"1.2.3","description":"external edit"}"#;
        std::fs::write(&core_manifest, edited).unwrap();

        let error = write_planned_manifests(tmp.path(), &planned, test_operation()).unwrap_err();

        assert!(error.to_string().contains("changed since it was read"));
        assert_eq!(std::fs::read_to_string(core_manifest).unwrap(), edited);
    }

    #[cfg(unix)]
    #[test]
    fn release_manifest_open_rejects_a_fifo_promptly() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::sync::mpsc;

        let root = TempDir::new().unwrap();
        let manifest_path = root.path().join("package.json");
        let encoded_path = std::ffi::CString::new(manifest_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded_path.as_ptr(), 0o600) }, 0);
        let canonical_root = canonical_workspace_root(root.path()).unwrap();
        let root_dir = open_root_directory_nofollow(&canonical_root).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);

        let worker = std::thread::spawn(move || {
            let result =
                open_manifest_target(&root_dir, &canonical_root, Path::new("package.json"))
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            sender.send(result).unwrap();
        });
        let timely = receiver.recv_timeout(std::time::Duration::from_millis(250));
        let completed_without_blocking = timely.is_ok();
        let result = match timely {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&manifest_path)
                    .unwrap();
                drop(writer);
                receiver.recv().unwrap()
            }
            Err(error) => panic!("release manifest worker disconnected: {error}"),
        };
        worker.join().unwrap();

        assert!(
            completed_without_blocking,
            "opening a release manifest FIFO blocked recovery"
        );
        assert!(result.is_err(), "a release manifest FIFO must be rejected");
    }

    #[test]
    fn write_planned_manifests_restores_earlier_files_when_a_later_write_fails() {
        let tmp = TempDir::new().unwrap();
        let first_path = tmp.path().join("a/package.json");
        let second_path = tmp.path().join("z/package.json");
        std::fs::create_dir_all(first_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(second_path.parent().unwrap()).unwrap();
        let first_original: Arc<[u8]> = Vec::from(br#"{"name":"a","version":"1.0.0"}"#).into();
        let second_original: Arc<[u8]> = Vec::from(br#"{"name":"z","version":"1.0.0"}"#).into();
        std::fs::write(&first_path, &first_original).unwrap();
        std::fs::write(&second_path, &second_original).unwrap();
        let manifests = vec![
            PlannedManifest {
                path: first_path.clone(),
                original_bytes: Arc::clone(&first_original),
                updated_bytes: Vec::from(br#"{"name":"a","version":"2.0.0"}"#),
            },
            PlannedManifest {
                path: second_path,
                original_bytes: second_original,
                updated_bytes: Vec::from(br#"{"name":"z","version":"2.0.0"}"#),
            },
        ];
        let mut write_count = 0;

        let result = write_planned_manifests_with(tmp.path(), &manifests, |target, bytes| {
            write_count += 1;
            if write_count == 2 {
                return Err(std::io::Error::other("injected second write failure"));
            }
            write_manifest_target_durable(target, bytes)
        });

        assert!(result.is_err());
        assert_eq!(std::fs::read(first_path).unwrap(), first_original.as_ref());
    }

    #[test]
    fn write_planned_manifests_restores_from_memory_when_the_journal_disappears() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let originals = manifests
            .iter()
            .map(|manifest| (manifest.path.clone(), Arc::clone(&manifest.original_bytes)))
            .collect::<Vec<_>>();
        let mut write_count = 0;

        let result = write_planned_manifests_with(tmp.path(), &manifests, |target, bytes| {
            write_count += 1;
            if write_count == 2 {
                return Err(std::io::Error::other("injected second write failure"));
            }
            write_manifest_target_durable(target, bytes)?;
            let root = canonical_workspace_root(tmp.path()).unwrap();
            remove_release_journal(&root).unwrap();
            Ok(())
        });

        assert!(result.is_err());
        for (path, original) in originals {
            assert_eq!(std::fs::read(path).unwrap(), original.as_ref());
        }
    }

    #[test]
    fn release_journal_size_accounting_matches_serialized_bytes() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path,
            original_bytes: original,
            updated_bytes: br#"{"name":"demo","version":"1.0.1"}"#.to_vec(),
        }];
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let mut resolved = resolve_planned_manifests(&root, &manifests).unwrap();
        let journal = build_release_journal(&mut resolved).unwrap();
        let encoded_original_len =
            base64::encoded_len(manifests[0].original_bytes.len(), true).unwrap();
        let expected = release_journal_size_after_entry(
            empty_release_journal_serialized_len(),
            0,
            journal.entries[0].path.len(),
            encoded_original_len,
        )
        .unwrap();

        assert_eq!(serialize_release_journal(&journal).unwrap().len(), expected);
    }

    #[test]
    fn recovery_journal_keeps_encoded_manifest_backups_borrowed() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path,
            original_bytes: original,
            updated_bytes: br#"{"name":"demo","version":"1.0.1"}"#.to_vec(),
        }];
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let mut resolved = resolve_planned_manifests(&root, &manifests).unwrap();
        let journal = build_release_journal(&mut resolved).unwrap();
        let bytes = serialize_release_journal(&journal).unwrap();

        let parsed: RecoveryApplyJournal<'_> = serde_json::from_slice(&bytes).unwrap();
        let backup = parsed.entries[0].original_base64.as_bytes();
        let bytes_start = bytes.as_ptr() as usize;
        let bytes_end = bytes_start + bytes.len();
        let backup_start = backup.as_ptr() as usize;

        assert!(backup_start >= bytes_start);
        assert!(backup_start + backup.len() <= bytes_end);
    }

    #[test]
    fn streamed_release_journal_matches_the_structured_recovery_contract() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path,
            original_bytes: original,
            updated_bytes: br#"{"name":"demo","version":"1.0.1"}"#.to_vec(),
        }];
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let mut resolved = resolve_planned_manifests(&root, &manifests).unwrap();
        let operation = test_operation();
        let git = VersionGitTransaction {
            old_head: "0123456789abcdef".into(),
            tag: "v1.0.1".into(),
        };

        let (streamed_bytes, commit) =
            serialize_planned_release_journal(&resolved, operation.clone(), Some(git.clone()))
                .unwrap();
        let streamed: ReleaseApplyJournal = serde_json::from_slice(&streamed_bytes).unwrap();
        let mut structured =
            build_release_journal_with_version_git(&mut resolved, operation, Some(git)).unwrap();
        structured.transaction_id = streamed.transaction_id.clone();

        assert_eq!(
            streamed_bytes,
            serialize_release_journal(&structured).unwrap()
        );
        assert_eq!(
            commit,
            release_commit_for_journal(&streamed, &streamed_bytes)
        );
    }

    #[test]
    fn write_planned_manifests_accepts_a_durable_complete_marker_after_a_late_error() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: original,
            updated_bytes: updated.clone(),
        }];
        FAIL_NEXT_COMMIT_PERSIST.with(|fail| fail.set(true));

        let result = write_planned_manifests(tmp.path(), &manifests, test_operation());

        assert!(
            result.is_ok(),
            "durable complete marker was reported as failure: {result:?}"
        );
        assert_eq!(std::fs::read(manifest_path).unwrap(), updated);
    }

    #[test]
    fn write_planned_manifests_reports_committed_cleanup_failure_for_safe_retry() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: original,
            updated_bytes: updated.clone(),
        }];
        let operation = test_operation();
        FAIL_NEXT_JOURNAL_REMOVE.with(|fail| fail.set(true));

        let error = write_planned_manifests(tmp.path(), &manifests, operation.clone()).unwrap_err();

        assert!(error.to_string().contains("committed"), "{error}");
        assert_eq!(std::fs::read(manifest_path).unwrap(), updated);
        assert!(matches!(
            recover_pending_operation_transaction(
                tmp.path(),
                &planned_manifest_paths(&manifests),
                &operation,
            )
            .unwrap(),
            ReleaseOperationRecoveryOutcome::Completed { .. }
        ));
    }

    #[test]
    fn committed_transaction_restores_its_receipt_when_commit_marker_cleanup_fails() {
        assert_committed_cleanup_failure_preserves_receipt(&FAIL_NEXT_COMMIT_REMOVE);
    }

    #[test]
    fn committed_transaction_restores_its_receipt_when_cleanup_sync_fails() {
        assert_committed_cleanup_failure_preserves_receipt(&FAIL_NEXT_CLEANUP_SYNC);
    }

    fn assert_committed_cleanup_failure_preserves_receipt(
        failure: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
    ) {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: original,
            updated_bytes: updated.clone(),
        }];
        let operation = test_operation();
        failure.with(|fail| fail.set(true));

        let error = write_planned_manifests(tmp.path(), &manifests, operation.clone()).unwrap_err();

        assert!(error.to_string().contains("committed"), "{error}");
        assert_eq!(std::fs::read(manifest_path).unwrap(), updated);
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let state = open_release_state_directory(&root, false)
            .unwrap()
            .expect("release state must retain a completion receipt");
        let journal_bytes = read_existing_release_journal_bytes_in(&state)
            .unwrap()
            .expect("release journal must be restored");
        assert!(release_commit_is_durable_in(&state, &journal_bytes).unwrap());
        assert!(matches!(
            recover_pending_operation_transaction(
                tmp.path(),
                &planned_manifest_paths(&manifests),
                &operation,
            )
            .unwrap(),
            ReleaseOperationRecoveryOutcome::Completed { .. }
        ));
    }

    #[test]
    fn stale_commit_marker_does_not_commit_a_later_identical_partial_transaction() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let originals = manifests
            .iter()
            .map(|manifest| (manifest.path.clone(), Arc::clone(&manifest.original_bytes)))
            .collect::<Vec<_>>();
        let root = seed_release_journal(tmp.path(), &manifests);
        let journal_path = existing_release_journal_path(&root).unwrap().unwrap();
        let journal_bytes = std::fs::read(&journal_path).unwrap();
        persist_release_commit(&root, &journal_bytes).unwrap();
        std::fs::remove_file(journal_path).unwrap();

        let mut writes = 0usize;
        let result = write_planned_manifests_with(tmp.path(), &manifests, |target, bytes| {
            writes += 1;
            if writes == 2 {
                return Err(std::io::Error::other("injected second manifest failure"));
            }
            write_manifest_target_durable(target, bytes)
        });

        assert!(result.is_err());
        for (path, original) in originals {
            assert_eq!(std::fs::read(path).unwrap(), original.as_ref());
        }
    }

    #[test]
    fn commit_marker_without_journal_recovers_the_completed_operation() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: original,
            updated_bytes: updated.clone(),
        }];
        let operation = test_operation();
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let mut resolved = resolve_planned_manifests(&root, &manifests).unwrap();
        let journal =
            build_release_journal_with_version_git(&mut resolved, operation.clone(), None).unwrap();
        let journal_bytes = serialize_release_journal(&journal).unwrap();
        persist_release_journal(&root, &journal_bytes).unwrap();
        persist_release_commit(&root, &journal_bytes).unwrap();
        std::fs::write(&manifest_path, updated).unwrap();
        let state = open_release_state_directory(&root, false).unwrap().unwrap();
        state.dir.remove_file(RELEASE_JOURNAL_FILE).unwrap();
        sync_cap_directory(&state.dir).unwrap();

        let outcome = recover_pending_operation_transaction(
            &root,
            &planned_manifest_paths(&manifests),
            &operation,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            ReleaseOperationRecoveryOutcome::Completed { .. }
        ));
        assert_eq!(
            std::fs::read(manifest_path).unwrap(),
            manifests[0].updated_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_planned_manifests_does_not_follow_a_swapped_parent_directory() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let package_dir = tmp.path().join("packages/core");
        let moved_dir = tmp.path().join("packages/core-original");
        let manifest_path = package_dir.join("package.json");
        let outside_manifest = outside.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"core","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"core","version":"2.0.0"}"#.to_vec();
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        std::fs::write(&outside_manifest, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path,
            original_bytes: Arc::clone(&original),
            updated_bytes: updated.clone(),
        }];

        let result = write_planned_manifests_with(tmp.path(), &manifests, |target, bytes| {
            std::fs::rename(&package_dir, &moved_dir)?;
            std::os::unix::fs::symlink(outside.path(), &package_dir)?;
            write_manifest_target_durable(target, bytes)
        });

        assert!(
            result.is_ok(),
            "descriptor-relative apply failed: {result:?}"
        );
        assert_eq!(std::fs::read(outside_manifest).unwrap(), original.as_ref());
        assert_eq!(
            std::fs::read(moved_dir.join("package.json")).unwrap(),
            updated
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_release_journal_does_not_follow_a_replaced_state_directory() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let state_dir = root.join(".lpm/release-apply");
        let moved_state_dir = root.join(".lpm/release-apply-original");
        let outside_path = outside.path().to_path_buf();
        let state_dir_for_hook = state_dir;
        let moved_state_dir_for_hook = moved_state_dir.clone();
        AFTER_RELEASE_STATE_RESOLUTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&state_dir_for_hook, &moved_state_dir_for_hook).unwrap();
                std::os::unix::fs::symlink(&outside_path, &state_dir_for_hook).unwrap();
            }));
        });

        persist_release_journal(&root, br#"{"schema_version":1}"#).unwrap();

        assert!(
            moved_state_dir.join(RELEASE_JOURNAL_FILE).is_file(),
            "journal was not written through the trusted directory handle"
        );
        assert!(
            !outside.path().join(RELEASE_JOURNAL_FILE).exists(),
            "journal escaped through the replacement state-directory symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn committed_transaction_keeps_using_its_open_state_directory_after_replacement() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: original,
            updated_bytes: updated.clone(),
        }];
        let transaction = apply_planned_manifests_with(
            tmp.path(),
            &manifests,
            test_operation(),
            None,
            write_manifest_target_durable,
        )
        .unwrap();
        let state_dir = tmp.path().join(".lpm/release-apply");
        let moved_state_dir = tmp.path().join(".lpm/release-apply-original");
        std::fs::rename(&state_dir, &moved_state_dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), &state_dir).unwrap();

        transaction.commit().unwrap();

        assert_eq!(std::fs::read(manifest_path).unwrap(), updated);
        assert!(!moved_state_dir.join(RELEASE_JOURNAL_FILE).exists());
        assert!(!moved_state_dir.join(RELEASE_COMMIT_FILE).exists());
        assert!(!outside.path().join(RELEASE_JOURNAL_FILE).exists());
        assert!(!outside.path().join(RELEASE_COMMIT_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_keeps_using_its_open_state_directory_after_replacement() {
        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: Arc::clone(&original),
            updated_bytes: updated.clone(),
        }];
        let root = seed_release_journal(tmp.path(), &manifests);
        std::fs::write(&manifest_path, updated).unwrap();
        let root_dir = open_root_directory_nofollow(&root).unwrap();
        let state = open_release_state_directory_from_open_root(&root, &root_dir, false)
            .unwrap()
            .expect("seeded release state");
        let state_dir = tmp.path().join(".lpm/release-apply");
        let moved_state_dir = tmp.path().join(".lpm/release-apply-original");
        std::fs::rename(&state_dir, &moved_state_dir).unwrap();
        std::os::unix::fs::symlink(outside.path(), &state_dir).unwrap();

        let outcome = recover_pending_release_transaction_in(
            &root,
            &root_dir,
            &state,
            &planned_manifest_paths(&manifests),
        )
        .unwrap();

        assert!(matches!(outcome, RecoveryOutcome::RolledBack));
        assert_eq!(std::fs::read(manifest_path).unwrap(), original.as_ref());
        assert!(!moved_state_dir.join(RELEASE_JOURNAL_FILE).exists());
        assert!(!outside.path().join(RELEASE_JOURNAL_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn publish_recovery_keeps_using_the_selected_root_after_path_replacement() {
        let base = TempDir::new().unwrap();
        let selected = base.path().join("selected");
        let displaced = base.path().join("displaced");
        std::fs::create_dir(&selected).unwrap();
        let manifest_path = selected.join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: Arc::clone(&original),
            updated_bytes: updated.clone(),
        }];
        let root = seed_release_journal(&selected, &manifests);
        std::fs::write(&manifest_path, updated).unwrap();
        let root_dir = open_root_directory_nofollow(&root).unwrap();
        std::fs::rename(&selected, &displaced).unwrap();
        std::fs::create_dir(&selected).unwrap();
        let replacement = br#"{"name":"replacement","version":"9.9.9"}"#;
        std::fs::write(selected.join("package.json"), replacement).unwrap();

        assert!(
            recover_pending_release_transaction_from_open_root(
                &root,
                &root_dir,
                &planned_manifest_paths(&manifests),
            )
            .unwrap()
        );

        assert_eq!(
            std::fs::read(displaced.join("package.json")).unwrap(),
            original.as_ref()
        );
        assert_eq!(
            std::fs::read(selected.join("package.json")).unwrap(),
            replacement
        );
        assert!(!displaced.join(".lpm/release-apply/journal.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn version_git_recovery_does_not_mutate_a_same_path_replacement_repository() {
        let base = TempDir::new().unwrap();
        let selected = base.path().join("selected");
        let displaced = base.path().join("displaced");
        std::fs::create_dir(&selected).unwrap();
        let manifest_path = selected.join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        let replacement = br#"{"name":"replacement","version":"9.9.9"}"#;
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let old_head = initialize_git_repository(&selected);
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: Arc::clone(&original),
            updated_bytes: updated.clone(),
        }];
        let root = canonical_workspace_root(&selected).unwrap();
        let resolved = resolve_planned_manifests(&root, &manifests).unwrap();
        let (journal, _) = serialize_planned_release_journal(
            &resolved,
            test_operation(),
            Some(VersionGitTransaction {
                old_head,
                tag: "v1.0.1".into(),
            }),
        )
        .unwrap();
        persist_release_journal(&root, &journal).unwrap();
        std::fs::write(&manifest_path, &updated).unwrap();
        let root_dir = open_root_directory_nofollow(&root).unwrap();
        std::fs::rename(&selected, &displaced).unwrap();
        let clone = std::process::Command::new("git")
            .args(["clone", "--quiet"])
            .arg(&displaced)
            .arg(&selected)
            .output()
            .unwrap();
        assert!(clone.status.success());
        std::fs::write(selected.join("package.json"), &updated).unwrap();
        assert!(
            run_git(&selected, &["add", "package.json"])
                .status
                .success()
        );
        assert!(
            run_git(
                &selected,
                &[
                    "-c",
                    "user.name=LPM Test",
                    "-c",
                    "user.email=lpm-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "replacement version",
                ],
            )
            .status
            .success()
        );
        let replacement_head = run_git(&selected, &["rev-parse", "HEAD"]);
        assert!(replacement_head.status.success());
        let replacement_head = String::from_utf8(replacement_head.stdout)
            .unwrap()
            .trim()
            .to_string();
        std::fs::write(selected.join("package.json"), replacement).unwrap();

        let outcome = recover_pending_release_transaction_from_open_root(
            &root,
            &root_dir,
            &[root.join("package.json")],
        )
        .unwrap();

        assert!(outcome);
        assert_eq!(
            std::fs::read(displaced.join("package.json")).unwrap(),
            original.as_ref()
        );
        assert_eq!(
            std::fs::read(selected.join("package.json")).unwrap(),
            replacement
        );
        let current_replacement_head = run_git(&selected, &["rev-parse", "HEAD"]);
        assert!(current_replacement_head.status.success());
        assert_eq!(
            String::from_utf8(current_replacement_head.stdout)
                .unwrap()
                .trim(),
            replacement_head
        );
    }

    #[cfg(unix)]
    #[test]
    fn generic_recovery_does_not_mix_state_and_manifest_root_generations() {
        let base = TempDir::new().unwrap();
        let selected = base.path().join("selected");
        let displaced = base.path().join("displaced");
        std::fs::create_dir(&selected).unwrap();
        let manifest_path = selected.join("package.json");
        let original = Arc::<[u8]>::from(br#"{"name":"demo","version":"1.0.0"}"#.as_slice());
        let updated = br#"{"name":"demo","version":"1.0.1"}"#.to_vec();
        std::fs::write(&manifest_path, original.as_ref()).unwrap();
        let manifests = vec![PlannedManifest {
            path: manifest_path.clone(),
            original_bytes: Arc::clone(&original),
            updated_bytes: updated.clone(),
        }];
        let root = seed_release_journal(&selected, &manifests);
        std::fs::write(&manifest_path, &updated).unwrap();
        let outcome = recover_pending_release_transaction_inner_with_hook(
            &root,
            &[selected.join("package.json")],
            || {
                std::fs::rename(&selected, &displaced).unwrap();
                std::fs::create_dir(&selected).unwrap();
                std::fs::write(selected.join("package.json"), &updated).unwrap();
            },
        )
        .unwrap();

        assert!(matches!(outcome, RecoveryOutcome::RolledBack));
        assert_eq!(
            std::fs::read(selected.join("package.json")).unwrap(),
            updated
        );
        assert_eq!(
            std::fs::read(displaced.join("package.json")).unwrap(),
            manifests[0].original_bytes.as_ref()
        );
        assert!(!displaced.join(".lpm/release-apply/journal.json").exists());
    }

    #[test]
    fn recover_pending_release_transaction_restores_a_partial_apply() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let originals = manifests
            .iter()
            .map(|manifest| (manifest.path.clone(), Arc::clone(&manifest.original_bytes)))
            .collect::<Vec<_>>();
        let root = seed_release_journal(tmp.path(), &manifests);
        write_manifest_durable(&manifests[0].path, &manifests[0].updated_bytes).unwrap();

        assert!(
            recover_pending_release_transaction(&root, &planned_manifest_paths(&manifests))
                .unwrap()
        );

        for (path, original) in originals {
            assert_eq!(std::fs::read(path).unwrap(), original.as_ref());
        }
        assert!(existing_release_journal_path(&root).unwrap().is_none());
    }

    #[test]
    fn recover_pending_release_transaction_validates_every_file_before_restoring_any() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let root = seed_release_journal(tmp.path(), &manifests);
        write_manifest_durable(&manifests[0].path, &manifests[0].updated_bytes).unwrap();
        write_manifest_durable(&manifests[1].path, b"external edit").unwrap();

        let error = recover_pending_release_transaction(&root, &planned_manifest_paths(&manifests))
            .unwrap_err();

        assert!(error.to_string().contains("changed outside"));
        assert_eq!(
            std::fs::read(&manifests[0].path).unwrap(),
            manifests[0].updated_bytes
        );
        assert_eq!(std::fs::read(&manifests[1].path).unwrap(), b"external edit");
        assert!(existing_release_journal_path(&root).unwrap().is_some());
    }

    #[test]
    fn recover_pending_release_transaction_resumes_an_interrupted_rollback() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let root = seed_release_journal(tmp.path(), &manifests);
        for manifest in &manifests {
            write_manifest_durable(&manifest.path, &manifest.updated_bytes).unwrap();
        }
        write_manifest_durable(&manifests[0].path, manifests[0].original_bytes.as_ref()).unwrap();

        assert!(
            recover_pending_release_transaction(&root, &planned_manifest_paths(&manifests))
                .unwrap()
        );

        for manifest in manifests {
            assert_eq!(
                std::fs::read(manifest.path).unwrap(),
                manifest.original_bytes.as_ref()
            );
        }
    }

    #[test]
    fn recover_pending_release_transaction_keeps_completed_manifest_updates() {
        let (tmp, workspace) = workspace_with_app_dep("^1.2.3");
        let manifests = major_release_manifests(&workspace);
        let root = seed_release_journal(tmp.path(), &manifests);
        for manifest in &manifests {
            write_manifest_durable(&manifest.path, &manifest.updated_bytes).unwrap();
        }
        let journal_path = existing_release_journal_path(&root).unwrap().unwrap();
        let bytes = std::fs::read(&journal_path).unwrap();
        persist_release_commit(&root, &bytes).unwrap();

        assert!(ensure_no_pending_release_transaction(&root).is_ok());
        assert!(
            recover_pending_release_transaction(&root, &planned_manifest_paths(&manifests))
                .unwrap()
        );
        for manifest in manifests {
            assert_eq!(
                std::fs::read(manifest.path).unwrap(),
                manifest.updated_bytes
            );
        }
        assert!(existing_release_journal_path(&root).unwrap().is_none());
    }

    #[test]
    fn recover_pending_release_transaction_rejects_parent_traversal_without_writing_outside() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let sentinel = outside.path().join("sentinel");
        std::fs::write(&sentinel, b"outside").unwrap();
        let original = b"outside";
        let journal = ReleaseApplyJournal {
            schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0".repeat(RELEASE_TRANSACTION_ID_HEX_BYTES),
            operation: test_operation(),
            state: ReleaseApplyJournalState::Applying,
            path_encoding: release_path_encoding().to_string(),
            entries: vec![ReleaseApplyJournalEntry {
                path: encode_relative_path(Path::new("../sentinel")).unwrap(),
                original_sha256: sha256_hex(original),
                original_base64: STANDARD.encode(original),
                updated_sha256: sha256_hex(b"updated"),
            }],
            version_git: None,
        };
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, &serialize_release_journal(&journal).unwrap()).unwrap();

        let error =
            recover_pending_release_transaction(&root, &root_manifest_allowlist(tmp.path()))
                .unwrap_err();

        assert!(error.to_string().contains("unsafe relative path"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"outside");
        assert!(existing_release_journal_path(&root).unwrap().is_some());
    }

    #[test]
    fn recover_pending_release_transaction_rejects_non_manifest_targets() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let tmp = TempDir::new().unwrap();
        let victim = tmp.path().join("victim.txt");
        std::fs::write(&victim, b"current").unwrap();
        let journal = ReleaseApplyJournal {
            schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0".repeat(RELEASE_TRANSACTION_ID_HEX_BYTES),
            operation: test_operation(),
            state: ReleaseApplyJournalState::Applying,
            path_encoding: release_path_encoding().to_string(),
            entries: vec![ReleaseApplyJournalEntry {
                path: encode_relative_path(Path::new("victim.txt")).unwrap(),
                original_sha256: sha256_hex(b"attacker replacement"),
                original_base64: STANDARD.encode(b"attacker replacement"),
                updated_sha256: sha256_hex(b"current"),
            }],
            version_git: None,
        };
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, &serialize_release_journal(&journal).unwrap()).unwrap();

        let error =
            recover_pending_release_transaction(&root, &root_manifest_allowlist(tmp.path()))
                .unwrap_err();

        assert!(error.to_string().contains("release manifest"));
        assert_eq!(std::fs::read(victim).unwrap(), b"current");
        assert!(existing_release_journal_path(&root).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn recover_pending_release_transaction_rejects_a_parent_symlink_escape() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let tmp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_manifest = outside.path().join("package.json");
        let original = br#"{"name":"outside","version":"1.0.0"}"#;
        std::fs::write(&outside_manifest, original).unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("linked")).unwrap();
        let journal = ReleaseApplyJournal {
            schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
            transaction_id: "0".repeat(RELEASE_TRANSACTION_ID_HEX_BYTES),
            operation: test_operation(),
            state: ReleaseApplyJournalState::Applying,
            path_encoding: release_path_encoding().to_string(),
            entries: vec![ReleaseApplyJournalEntry {
                path: encode_relative_path(Path::new("linked/package.json")).unwrap(),
                original_sha256: sha256_hex(original),
                original_base64: STANDARD.encode(original),
                updated_sha256: sha256_hex(b"updated"),
            }],
            version_git: None,
        };
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, &serialize_release_journal(&journal).unwrap()).unwrap();

        let error =
            recover_pending_release_transaction(&root, &[tmp.path().join("linked/package.json")])
                .unwrap_err();

        assert!(error.to_string().contains("escapes the workspace"));
        assert_eq!(std::fs::read(outside_manifest).unwrap(), original);
        assert!(existing_release_journal_path(&root).unwrap().is_some());
    }

    #[test]
    fn recover_pending_release_transaction_preserves_unknown_schema_journal() {
        let tmp = TempDir::new().unwrap();
        let journal = ReleaseApplyJournal {
            schema_version: RELEASE_JOURNAL_SCHEMA_VERSION + 1,
            transaction_id: "0".repeat(RELEASE_TRANSACTION_ID_HEX_BYTES),
            operation: test_operation(),
            state: ReleaseApplyJournalState::Applying,
            path_encoding: release_path_encoding().to_string(),
            entries: Vec::new(),
            version_git: None,
        };
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, &serialize_release_journal(&journal).unwrap()).unwrap();

        let error =
            recover_pending_release_transaction(&root, &root_manifest_allowlist(tmp.path()))
                .unwrap_err();

        assert!(error.to_string().contains("schema"));
        assert!(existing_release_journal_path(&root).unwrap().is_some());
    }

    #[test]
    fn read_release_journal_rejects_an_oversized_encoded_path_during_deserialization() {
        let tmp = TempDir::new().unwrap();
        let root = canonical_workspace_root(tmp.path()).unwrap();
        let oversized_path = "A".repeat(MAX_RELEASE_PATH_BYTES.div_ceil(3) * 4 + 1);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": RELEASE_JOURNAL_SCHEMA_VERSION,
            "transaction_id": "0".repeat(RELEASE_TRANSACTION_ID_HEX_BYTES),
            "operation": test_operation(),
            "state": "applying",
            "path_encoding": release_path_encoding(),
            "entries": [{
                "path": oversized_path,
                "original_sha256": "0".repeat(64),
                "original_base64": "",
                "updated_sha256": "0".repeat(64),
            }]
        }))
        .unwrap();
        persist_release_journal(&root, &bytes).unwrap();
        let journal_path = existing_release_journal_path(&root).unwrap().unwrap();

        let result = read_release_journal(&journal_path);

        assert!(result.is_err(), "oversized path was fully deserialized");
    }

    #[cfg(unix)]
    #[test]
    fn persist_release_journal_rejects_a_group_writable_lpm_parent() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let lpm_dir = tmp.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        std::fs::set_permissions(&lpm_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        let root = canonical_workspace_root(tmp.path()).unwrap();

        let result = persist_release_journal(&root, br#"{"schema_version":1}"#);

        assert!(
            result.is_err(),
            "unsafe .lpm parent permissions were accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn persist_release_journal_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, br#"{"schema_version":1}"#).unwrap();
        let journal = existing_release_journal_path(&root).unwrap().unwrap();

        assert_eq!(
            std::fs::metadata(journal).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let state_dir = release_state_dir(&root, false).unwrap().unwrap();
        assert_eq!(
            std::fs::metadata(state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn persist_release_journal_uses_owner_only_windows_acls() {
        let tmp = TempDir::new().unwrap();
        let root = canonical_workspace_root(tmp.path()).unwrap();
        persist_release_journal(&root, br#"{"schema_version":1}"#).unwrap();
        let journal = existing_release_journal_path(&root).unwrap().unwrap();
        let state_dir = release_state_dir(&root, false).unwrap().unwrap();

        for (path, directory) in [
            (root.join(".lpm"), true),
            (state_dir, true),
            (journal, false),
        ] {
            let sddl = windows_dacl_sddl(&path, directory);
            assert!(sddl.starts_with("D:P"), "DACL is not protected: {sddl}");
            assert!(
                !sddl.contains(";;;WD)"),
                "DACL grants Everyone access: {sddl}"
            );
            assert!(sddl.contains(";;;OW)"), "DACL omits owner access: {sddl}");
            assert!(sddl.contains(";;;SY)"), "DACL omits SYSTEM access: {sddl}");
        }
    }

    #[cfg(windows)]
    fn windows_dacl_sddl(path: &Path, directory: bool) -> String {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL,
        };

        struct LocalAllocation(*mut std::ffi::c_void);

        impl Drop for LocalAllocation {
            fn drop(&mut self) {
                unsafe {
                    // SAFETY: the wrapped pointer was allocated by a Win32 security conversion
                    // function and is released exactly once here.
                    let _ = LocalFree(self.0);
                }
            }
        }

        let mut options = std::fs::OpenOptions::new();
        options
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            );
        let file = options.open(path).unwrap();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            // SAFETY: the output pointer is initialized, the file handle stays open, and the
            // returned allocation is transferred to `LocalAllocation` after success.
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let descriptor_guard = LocalAllocation(descriptor.cast());
        let mut text = null_mut();
        let mut text_len = 0;
        let converted = unsafe {
            // SAFETY: `descriptor_guard` owns a valid security descriptor and both output values
            // are initialized for the conversion call.
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor_guard.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut text_len,
            )
        };
        assert_ne!(converted, 0);
        let text_guard = LocalAllocation(text.cast());
        String::from_utf16_lossy(unsafe {
            // SAFETY: the conversion returned `text_len` initialized UTF-16 code units which
            // remain live through `text_guard`.
            std::slice::from_raw_parts(text_guard.0.cast::<u16>(), text_len as usize)
        })
    }
}
