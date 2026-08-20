mod fs;

use super::*;
pub(super) use fs::*;

pub(crate) fn write_planned_manifests(
    workspace_root: &Path,
    manifests: &[PlannedManifest],
    operation: ReleaseTransactionOperation,
) -> Result<(), LpmError> {
    if manifests.is_empty() {
        return Ok(());
    }
    let transaction = apply_planned_manifests_with(
        workspace_root,
        manifests,
        operation,
        None,
        write_manifest_target_durable,
    )?;
    transaction.commit()
}

pub(crate) fn write_planned_manifests_then_git<T>(
    workspace_root: &Path,
    manifests: &[PlannedManifest],
    transaction_operation: ReleaseTransactionOperation,
    git: VersionGitTransaction,
    operation: impl FnOnce() -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    if manifests.is_empty() {
        return Err(LpmError::Script(
            "version transaction contained no manifest changes".into(),
        ));
    }
    let transaction = apply_planned_manifests_with(
        workspace_root,
        manifests,
        transaction_operation,
        Some(git),
        write_manifest_target_durable,
    )?;
    match operation() {
        Ok(value) => {
            transaction.commit()?;
            Ok(value)
        }
        Err(error) => transaction.rollback(error),
    }
}

pub(super) struct AppliedReleaseTransaction {
    canonical_root: PathBuf,
    root: cap_std::fs::Dir,
    state: ReleaseStateDirectory,
    allowed_manifests: Vec<PathBuf>,
    journal_bytes: Vec<u8>,
    commit: ReleaseApplyCommit,
}

impl AppliedReleaseTransaction {
    pub(super) fn commit(self) -> Result<(), LpmError> {
        if let Err(error) = persist_release_commit_in(&self.state, &self.commit)
            && !release_commit_is_durable_in(&self.state, &self.journal_bytes)?
        {
            return Err(LpmError::Script(format!(
                "release manifests were written but the durable commit marker failed: {error}; the transaction journal was preserved for recovery"
            )));
        }
        abort_after_release_commit_for_test();
        if let Err(error) =
            remove_committed_release_journal_in(&self.state, &self.journal_bytes, &self.commit)
        {
            return Err(LpmError::Script(format!(
                "release transaction committed, but its recovery journal could not be cleaned up: {error}; retry the same operation to confirm completion"
            )));
        }
        Ok(())
    }

    fn rollback<T>(self, primary: LpmError) -> Result<T, LpmError> {
        rollback_after_apply_error(
            &self.canonical_root,
            &self.root,
            &self.state,
            &self.allowed_manifests,
            &self.journal_bytes,
            primary,
        )
    }
}

pub(super) fn apply_planned_manifests_with(
    workspace_root: &Path,
    manifests: &[PlannedManifest],
    operation: ReleaseTransactionOperation,
    version_git: Option<VersionGitTransaction>,
    mut write_manifest: impl FnMut(&ManifestTarget, &[u8]) -> std::io::Result<()>,
) -> Result<AppliedReleaseTransaction, LpmError> {
    let canonical_root = canonical_workspace_root(workspace_root)?;
    let root = open_root_directory_nofollow(&canonical_root)?;
    let state = open_release_state_directory_from_open_root(&canonical_root, &root, true)?
        .ok_or_else(|| {
            LpmError::Script("could not create the release transaction directory".into())
        })?;
    ensure_no_pending_release_transaction_in(&state)?;
    let resolved = resolve_planned_manifests_from_open_root(&canonical_root, &root, manifests)?;
    let (journal_bytes, commit) =
        serialize_planned_release_journal(&resolved, operation, version_git)?;
    persist_release_journal_in(&state, &journal_bytes)?;
    let allowed_manifests = resolved
        .iter()
        .map(|manifest| manifest.target.display.clone())
        .collect::<Vec<_>>();

    for (index, resolved_manifest) in resolved.into_iter().enumerate() {
        let manifest = resolved_manifest.manifest;
        let current = match read_manifest_target(&resolved_manifest.target) {
            Ok(current) => current,
            Err(error) => {
                return rollback_after_apply_error(
                    &canonical_root,
                    &root,
                    &state,
                    &allowed_manifests,
                    &journal_bytes,
                    error,
                );
            }
        };
        if current.as_slice() != manifest.original_bytes.as_ref() {
            return rollback_after_apply_error(
                &canonical_root,
                &root,
                &state,
                &allowed_manifests,
                &journal_bytes,
                LpmError::Script(format!(
                    "{} changed after the release journal was created",
                    resolved_manifest.target.display.display()
                )),
            );
        }
        if let Err(error) = write_manifest(&resolved_manifest.target, &manifest.updated_bytes) {
            return rollback_after_apply_error(
                &canonical_root,
                &root,
                &state,
                &allowed_manifests,
                &journal_bytes,
                LpmError::Io(error),
            );
        }
        abort_after_manifest_write_for_test(index + 1);
    }

    Ok(AppliedReleaseTransaction {
        canonical_root,
        root,
        state,
        allowed_manifests,
        journal_bytes,
        commit,
    })
}

#[cfg(test)]
pub(super) fn write_planned_manifests_with(
    workspace_root: &Path,
    manifests: &[PlannedManifest],
    write_manifest: impl FnMut(&ManifestTarget, &[u8]) -> std::io::Result<()>,
) -> Result<(), LpmError> {
    if manifests.is_empty() {
        return Ok(());
    }
    apply_planned_manifests_with(
        workspace_root,
        manifests,
        test_transaction_operation(),
        None,
        write_manifest,
    )?
    .commit()
}

pub(crate) fn ensure_no_pending_release_transaction(workspace_root: &Path) -> Result<(), LpmError> {
    let canonical_root = canonical_workspace_root(workspace_root)?;
    let Some(state) = open_release_state_directory(&canonical_root, false)? else {
        return Ok(());
    };
    ensure_no_pending_release_transaction_in(&state)
}

pub(crate) fn ensure_no_pending_release_transaction_from_open_root(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
) -> Result<(), LpmError> {
    let Some(state) = open_release_state_directory_from_open_root(canonical_root, root, false)?
    else {
        return Ok(());
    };
    ensure_no_pending_release_transaction_in(&state)
}

pub(super) fn ensure_no_pending_release_transaction_in(
    state: &ReleaseStateDirectory,
) -> Result<(), LpmError> {
    let Some(journal_bytes) = read_existing_release_journal_bytes_in(state)? else {
        return Ok(());
    };
    let journal = parse_recovery_release_journal(state, &journal_bytes)?;
    validate_recovery_release_journal_header(&journal)?;
    if journal.state == ReleaseApplyJournalState::Complete
        || release_commit_is_durable_in(state, &journal_bytes)?
    {
        return Ok(());
    }
    Err(LpmError::Script(format!(
        "an interrupted release manifest transaction is pending at {}. Re-run a mutating release apply, release publish, or version command to recover it before planning or dry-run publishing.",
        state.display.join(RELEASE_JOURNAL_FILE).display()
    )))
}

pub(crate) fn has_release_transaction_from_open_root(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
) -> Result<bool, LpmError> {
    let Some(state) = open_release_state_directory_from_open_root(canonical_root, root, false)?
    else {
        return Ok(false);
    };
    Ok(release_journal_exists_in(&state)? || release_commit_exists_in(&state)?)
}

#[cfg(test)]
pub(crate) fn recover_pending_release_transaction(
    workspace_root: &Path,
    allowed_manifests: &[PathBuf],
) -> Result<bool, LpmError> {
    Ok(!matches!(
        recover_pending_release_transaction_inner(workspace_root, allowed_manifests)?,
        RecoveryOutcome::None
    ))
}

pub(crate) fn recover_pending_release_transaction_from_open_root(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
    allowed_manifests: &[PathBuf],
) -> Result<bool, LpmError> {
    let Some(state) = open_release_state_directory_from_open_root(canonical_root, root, false)?
    else {
        return Ok(false);
    };
    Ok(!matches!(
        recover_pending_release_transaction_in_open_root(
            canonical_root,
            root,
            &state,
            allowed_manifests,
        )?,
        RecoveryOutcome::None
    ))
}

pub(crate) fn recover_pending_operation_transaction(
    workspace_root: &Path,
    allowed_manifests: &[PathBuf],
    expected_operation: &ReleaseTransactionOperation,
) -> Result<ReleaseOperationRecoveryOutcome, LpmError> {
    match recover_pending_release_transaction_inner(workspace_root, allowed_manifests)? {
        RecoveryOutcome::Completed { operation, tag } if operation == *expected_operation => {
            Ok(ReleaseOperationRecoveryOutcome::Completed { tag })
        }
        RecoveryOutcome::None | RecoveryOutcome::RolledBack | RecoveryOutcome::Completed { .. } => {
            Ok(ReleaseOperationRecoveryOutcome::Continue)
        }
    }
}

pub(super) enum RecoveryOutcome {
    None,
    RolledBack,
    Completed {
        operation: ReleaseTransactionOperation,
        tag: Option<String>,
    },
}

pub(super) fn recover_pending_release_transaction_inner(
    workspace_root: &Path,
    allowed_manifests: &[PathBuf],
) -> Result<RecoveryOutcome, LpmError> {
    recover_pending_release_transaction_inner_with_hook(workspace_root, allowed_manifests, || {})
}

pub(super) fn recover_pending_release_transaction_inner_with_hook(
    workspace_root: &Path,
    allowed_manifests: &[PathBuf],
    after_root_open: impl FnOnce(),
) -> Result<RecoveryOutcome, LpmError> {
    let canonical_root = canonical_workspace_root(workspace_root)?;
    let root = open_root_directory_nofollow(&canonical_root)?;
    after_root_open();
    let Some(state) = open_release_state_directory_from_open_root(&canonical_root, &root, false)?
    else {
        return Ok(RecoveryOutcome::None);
    };
    recover_pending_release_transaction_in(&canonical_root, &root, &state, allowed_manifests)
}

pub(super) fn recover_pending_release_transaction_in(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
    state: &ReleaseStateDirectory,
    allowed_manifests: &[PathBuf],
) -> Result<RecoveryOutcome, LpmError> {
    recover_pending_release_transaction_in_open_root(canonical_root, root, state, allowed_manifests)
}

fn recover_pending_release_transaction_in_open_root(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
    state: &ReleaseStateDirectory,
    allowed_manifests: &[PathBuf],
) -> Result<RecoveryOutcome, LpmError> {
    let Some(journal_bytes) = read_existing_release_journal_bytes_in(state)? else {
        return recover_commit_marker_without_journal_in(state);
    };
    let journal = parse_recovery_release_journal(state, &journal_bytes)?;
    validate_recovery_release_journal_header(&journal)?;
    let commit = release_commit_for_parts(
        journal.operation.clone(),
        journal.version_git.as_ref().map(|git| git.tag.clone()),
        &journal_bytes,
    );
    if journal.state == ReleaseApplyJournalState::Complete
        || release_commit_is_durable_in(state, &journal_bytes)?
    {
        let outcome = RecoveryOutcome::Completed {
            operation: journal.operation,
            tag: journal.version_git.map(|git| git.tag),
        };
        remove_committed_release_journal_in(state, &journal_bytes, &commit)?;
        return Ok(outcome);
    }
    let operation = journal.operation;
    let version_git = journal.version_git;
    let entries = validate_recovery_entries_from_open_root(
        canonical_root,
        root,
        journal.entries,
        allowed_manifests,
    )?;

    if let Some(git) = version_git
        && recover_version_git_transaction(canonical_root, &git, &entries)?
            == VersionGitRecoveryState::Completed
    {
        if let Err(error) = persist_release_commit_in(state, &commit)
            && !release_commit_is_durable_in(state, &journal_bytes)?
        {
            return Err(LpmError::Script(format!(
                "the Git version transaction completed but its durable release marker failed: {error}; the journal was preserved for recovery"
            )));
        }
        remove_committed_release_journal_in(state, &journal_bytes, &commit)?;
        return Ok(RecoveryOutcome::Completed {
            operation,
            tag: Some(git.tag),
        });
    }

    for entry in entries.iter().filter(|entry| entry.restore) {
        write_manifest_target_durable(&entry.target, &entry.original).map_err(|error| {
            LpmError::Script(format!(
                "interrupted release rollback could not restore {}: {error}; the journal was preserved for retry",
                entry.target.display.display()
            ))
        })?;
    }

    if let Err(error) = remove_release_journal_in(state) {
        let _ = persist_release_journal_in(state, &journal_bytes);
        return Err(error);
    }
    Ok(RecoveryOutcome::RolledBack)
}

pub(super) fn recover_commit_marker_without_journal_in(
    state: &ReleaseStateDirectory,
) -> Result<RecoveryOutcome, LpmError> {
    let Some((commit_bytes, mut commit)) = read_release_commit_in(state)? else {
        return Ok(RecoveryOutcome::None);
    };
    let operation = commit.operation.take().ok_or_else(|| {
        LpmError::Script(format!(
            "release completion marker at {} predates self-contained recovery and its journal is missing; preserve the marker and use the LPM version that created it",
            state.display.join(RELEASE_COMMIT_FILE).display()
        ))
    })?;
    remove_release_commit_receipt_in(state, &commit_bytes)?;
    Ok(RecoveryOutcome::Completed {
        operation,
        tag: commit.tag,
    })
}

pub(super) fn rollback_after_apply_error<T>(
    canonical_root: &Path,
    root: &cap_std::fs::Dir,
    state: &ReleaseStateDirectory,
    allowed_manifests: &[PathBuf],
    trusted_journal_bytes: &[u8],
    primary: LpmError,
) -> Result<T, LpmError> {
    match recover_pending_release_transaction_in(canonical_root, root, state, allowed_manifests) {
        Ok(RecoveryOutcome::RolledBack | RecoveryOutcome::Completed { .. }) => Err(primary),
        Ok(RecoveryOutcome::None) | Err(_) => {
            if let Err(error) = persist_release_journal_in(state, trusted_journal_bytes) {
                return Err(LpmError::Script(format!(
                    "{primary}; rollback journal could not be restored: {error}"
                )));
            }
            match recover_pending_release_transaction_in(
                canonical_root,
                root,
                state,
                allowed_manifests,
            ) {
                Ok(RecoveryOutcome::RolledBack | RecoveryOutcome::Completed { .. }) => Err(primary),
                Ok(RecoveryOutcome::None) => Err(LpmError::Script(format!(
                    "{primary}; rollback journal disappeared before recovery"
                ))),
                Err(rollback) => Err(LpmError::Script(format!(
                    "{primary}; rollback incomplete: {rollback}"
                ))),
            }
        }
    }
}

#[cfg(test)]
pub(super) fn read_release_journal(
    path: &Path,
) -> Result<(Vec<u8>, ReleaseApplyJournal), LpmError> {
    let bytes = lpm_common::read_file_capped(path, MAX_RELEASE_JOURNAL_BYTES)?;
    let journal = serde_json::from_slice(&bytes).map_err(|error| {
        LpmError::Script(format!(
            "cannot recover interrupted release transaction from {}: {error}",
            path.display()
        ))
    })?;
    Ok((bytes, journal))
}

pub(super) fn read_existing_release_journal_bytes_in(
    state: &ReleaseStateDirectory,
) -> Result<Option<Vec<u8>>, LpmError> {
    let Some(bytes) =
        read_private_state_file_capped(state, RELEASE_JOURNAL_FILE, MAX_RELEASE_JOURNAL_BYTES)?
    else {
        return Ok(None);
    };
    Ok(Some(bytes))
}

fn parse_recovery_release_journal<'a>(
    state: &ReleaseStateDirectory,
    bytes: &'a [u8],
) -> Result<RecoveryApplyJournal<'a>, LpmError> {
    serde_json::from_slice(bytes).map_err(|error| {
        LpmError::Script(format!(
            "cannot recover interrupted release transaction from {}: {error}",
            state.display.join(RELEASE_JOURNAL_FILE).display()
        ))
    })
}

fn validate_recovery_release_journal_header(
    journal: &RecoveryApplyJournal<'_>,
) -> Result<(), LpmError> {
    validate_release_journal_header_fields(
        journal.schema_version,
        journal.transaction_id,
        journal.path_encoding,
    )
}

fn validate_release_journal_header_fields(
    schema_version: u32,
    transaction_id: &str,
    path_encoding: &str,
) -> Result<(), LpmError> {
    if schema_version != RELEASE_JOURNAL_SCHEMA_VERSION {
        return Err(LpmError::Script(format!(
            "release journal schema {} is unsupported; preserve the journal and use a compatible LPM version",
            schema_version
        )));
    }
    if transaction_id.len() != RELEASE_TRANSACTION_ID_HEX_BYTES
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LpmError::Script(
            "release journal contains an invalid transaction ID".into(),
        ));
    }
    if path_encoding != release_path_encoding() {
        return Err(LpmError::Script(format!(
            "release journal path encoding `{}` is not valid on this platform",
            path_encoding
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn resolve_planned_manifests<'a>(
    canonical_root: &Path,
    manifests: &'a [PlannedManifest],
) -> Result<Vec<ResolvedPlannedManifest<'a>>, LpmError> {
    let root_dir = open_root_directory_nofollow(canonical_root)?;
    resolve_planned_manifests_from_open_root(canonical_root, &root_dir, manifests)
}

pub(super) fn resolve_planned_manifests_from_open_root<'a>(
    canonical_root: &Path,
    root_dir: &cap_std::fs::Dir,
    manifests: &'a [PlannedManifest],
) -> Result<Vec<ResolvedPlannedManifest<'a>>, LpmError> {
    if manifests.len() > MAX_RELEASE_JOURNAL_ENTRIES {
        return Err(LpmError::Script(format!(
            "release plan changes {} manifests, exceeding the transaction limit of {MAX_RELEASE_JOURNAL_ENTRIES}",
            manifests.len()
        )));
    }

    let mut resolved = Vec::with_capacity(manifests.len());
    let mut serialized_bytes = empty_release_journal_serialized_len();
    let mut total_original_bytes = 0usize;
    let mut total_updated_bytes = 0usize;
    for manifest in manifests {
        validate_manifest_size(
            &manifest.path,
            manifest.original_bytes.as_ref(),
            "original package.json",
        )?;
        validate_manifest_size(
            &manifest.path,
            &manifest.updated_bytes,
            "updated package.json",
        )?;
        total_updated_bytes =
            checked_total_updated_bytes(total_updated_bytes, manifest.updated_bytes.len())?;
        let relative = planned_manifest_relative_path(canonical_root, &manifest.path)?;
        let encoded_path = encode_relative_path(&relative)?;
        total_original_bytes = total_original_bytes
            .checked_add(manifest.original_bytes.len())
            .ok_or_else(|| LpmError::Script("release journal size overflow".into()))?;
        if total_original_bytes > MAX_RELEASE_ORIGINAL_BYTES {
            return Err(LpmError::Script(format!(
                "release manifest originals exceed the {} MiB durable transaction limit",
                MAX_RELEASE_ORIGINAL_BYTES / (1024 * 1024)
            )));
        }
        let encoded_original_len = base64::encoded_len(manifest.original_bytes.len(), true)
            .ok_or_else(|| LpmError::Script("release journal size overflow".into()))?;
        serialized_bytes = release_journal_size_after_entry(
            serialized_bytes,
            resolved.len(),
            encoded_path.len(),
            encoded_original_len,
        )?;
        if serialized_bytes > MAX_RELEASE_JOURNAL_BYTES as usize {
            return Err(LpmError::Script(format!(
                "release journal exceeds the {} MiB transaction limit",
                MAX_RELEASE_JOURNAL_BYTES / (1024 * 1024)
            )));
        }
        let target = open_manifest_target(root_dir, canonical_root, &relative)?;
        let current = read_manifest_target(&target)?;
        if current.as_slice() != manifest.original_bytes.as_ref() {
            return Err(LpmError::Script(format!(
                "{} changed since it was read; retry the release command",
                manifest.path.display()
            )));
        }
        resolved.push(ResolvedPlannedManifest {
            relative,
            encoded_path,
            target,
            manifest,
        });
    }
    resolved.sort_by(|left, right| left.relative.cmp(&right.relative));
    if let Some(duplicate) = resolved
        .windows(2)
        .find(|pair| pair[0].relative == pair[1].relative)
    {
        return Err(LpmError::Script(format!(
            "release plan contains duplicate manifest path {}",
            duplicate[1].target.display.display()
        )));
    }
    Ok(resolved)
}

pub(super) fn validate_manifest_size(
    path: &Path,
    bytes: &[u8],
    description: &str,
) -> Result<(), LpmError> {
    if bytes.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(manifest_size_error(path, description));
    }
    Ok(())
}

struct StreamingReleaseJournalEntries<'a, 'manifest> {
    manifests: &'a [ResolvedPlannedManifest<'manifest>],
}

impl Serialize for StreamingReleaseJournalEntries<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use serde::ser::SerializeSeq as _;

        #[derive(Serialize)]
        struct Entry<'a> {
            path: &'a str,
            original_sha256: String,
            original_base64: String,
            updated_sha256: String,
        }

        let mut entries = serializer.serialize_seq(Some(self.manifests.len()))?;
        for resolved in self.manifests {
            let manifest = resolved.manifest;
            entries.serialize_element(&Entry {
                path: &resolved.encoded_path,
                original_sha256: sha256_hex(manifest.original_bytes.as_ref()),
                original_base64: STANDARD.encode(manifest.original_bytes.as_ref()),
                updated_sha256: sha256_hex(&manifest.updated_bytes),
            })?;
        }
        entries.end()
    }
}

#[derive(Serialize)]
struct StreamingReleaseApplyJournal<'a, 'manifest> {
    schema_version: u32,
    transaction_id: &'a str,
    operation: &'a ReleaseTransactionOperation,
    state: ReleaseApplyJournalState,
    path_encoding: &'static str,
    entries: StreamingReleaseJournalEntries<'a, 'manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_git: Option<&'a VersionGitJournal>,
}

pub(super) fn serialize_planned_release_journal(
    manifests: &[ResolvedPlannedManifest<'_>],
    operation: ReleaseTransactionOperation,
    version_git: Option<VersionGitTransaction>,
) -> Result<(Vec<u8>, ReleaseApplyCommit), LpmError> {
    let transaction_id = new_release_transaction_id();
    let version_git = version_git.map(|git| VersionGitJournal {
        old_head: git.old_head,
        tag: git.tag,
    });
    let journal = StreamingReleaseApplyJournal {
        schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
        transaction_id: &transaction_id,
        operation: &operation,
        state: ReleaseApplyJournalState::Applying,
        path_encoding: release_path_encoding(),
        entries: StreamingReleaseJournalEntries { manifests },
        version_git: version_git.as_ref(),
    };
    let journal_bytes = serialize_release_journal_value(&journal)?;
    let commit = release_commit_for_parts(
        operation,
        version_git.as_ref().map(|git| git.tag.clone()),
        &journal_bytes,
    );
    Ok((journal_bytes, commit))
}

#[cfg(test)]
pub(super) fn build_release_journal(
    manifests: &mut [ResolvedPlannedManifest<'_>],
) -> Result<ReleaseApplyJournal, LpmError> {
    build_release_journal_with_version_git(manifests, test_transaction_operation(), None)
}

#[cfg(test)]
pub(super) fn build_release_journal_with_version_git(
    manifests: &mut [ResolvedPlannedManifest<'_>],
    operation: ReleaseTransactionOperation,
    version_git: Option<VersionGitTransaction>,
) -> Result<ReleaseApplyJournal, LpmError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let mut total_original_bytes = 0usize;
    let mut serialized_bytes = empty_release_journal_serialized_len();
    let mut entries = Vec::with_capacity(manifests.len());
    for resolved in manifests {
        let manifest = resolved.manifest;
        total_original_bytes = total_original_bytes
            .checked_add(manifest.original_bytes.len())
            .ok_or_else(|| LpmError::Script("release journal size overflow".into()))?;
        if total_original_bytes > MAX_RELEASE_ORIGINAL_BYTES {
            return Err(LpmError::Script(format!(
                "release manifest originals exceed the {} MiB durable transaction limit",
                MAX_RELEASE_ORIGINAL_BYTES / (1024 * 1024)
            )));
        }
        let encoded_path = std::mem::take(&mut resolved.encoded_path);
        let encoded_original_len = base64::encoded_len(manifest.original_bytes.len(), true)
            .ok_or_else(|| LpmError::Script("release journal size overflow".into()))?;
        serialized_bytes = release_journal_size_after_entry(
            serialized_bytes,
            entries.len(),
            encoded_path.len(),
            encoded_original_len,
        )?;
        if serialized_bytes > MAX_RELEASE_JOURNAL_BYTES as usize {
            return Err(LpmError::Script(format!(
                "release journal exceeds the {} MiB transaction limit",
                MAX_RELEASE_JOURNAL_BYTES / (1024 * 1024)
            )));
        }
        entries.push(ReleaseApplyJournalEntry {
            path: encoded_path,
            original_sha256: sha256_hex(manifest.original_bytes.as_ref()),
            original_base64: STANDARD.encode(manifest.original_bytes.as_ref()),
            updated_sha256: sha256_hex(&manifest.updated_bytes),
        });
    }

    Ok(ReleaseApplyJournal {
        schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
        transaction_id: new_release_transaction_id(),
        operation,
        state: ReleaseApplyJournalState::Applying,
        path_encoding: release_path_encoding().to_string(),
        entries,
        version_git: version_git.map(|git| VersionGitJournal {
            old_head: git.old_head,
            tag: git.tag,
        }),
    })
}

pub(super) fn empty_release_journal_serialized_len() -> usize {
    br#"{"schema_version":1,"transaction_id":"00000000000000000000000000000000","operation":{"kind":"release_apply","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"},"state":"applying","path_encoding":"","entries":[]}"#.len()
        + release_path_encoding().len()
}

pub(super) fn new_release_transaction_id() -> String {
    use rand::RngCore as _;

    let mut bytes = [0u8; RELEASE_TRANSACTION_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
pub(super) fn test_transaction_operation() -> ReleaseTransactionOperation {
    ReleaseTransactionOperation::new(
        ReleaseTransactionOperationKind::ReleaseApply,
        b"release-plan-unit-test",
    )
}

pub(super) fn release_journal_size_after_entry(
    current: usize,
    entry_count: usize,
    encoded_path_len: usize,
    encoded_original_len: usize,
) -> Result<usize, LpmError> {
    let fixed_entry_bytes =
        br#"{"path":"","original_sha256":"","original_base64":"","updated_sha256":""}"#.len() + 128;
    current
        .checked_add(usize::from(entry_count != 0))
        .and_then(|size| size.checked_add(fixed_entry_bytes))
        .and_then(|size| size.checked_add(encoded_path_len))
        .and_then(|size| size.checked_add(encoded_original_len))
        .ok_or_else(|| LpmError::Script("release journal size overflow".into()))
}

#[cfg(test)]
pub(super) fn serialize_release_journal(
    journal: &ReleaseApplyJournal,
) -> Result<Vec<u8>, LpmError> {
    serialize_release_journal_value(journal)
}

fn serialize_release_journal_value(journal: &impl Serialize) -> Result<Vec<u8>, LpmError> {
    let bytes = serde_json::to_vec(journal)?;
    if bytes.len() as u64 > MAX_RELEASE_JOURNAL_BYTES {
        return Err(LpmError::Script(format!(
            "release journal exceeds the {} MiB transaction limit",
            MAX_RELEASE_JOURNAL_BYTES / (1024 * 1024)
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn persist_release_journal(canonical_root: &Path, bytes: &[u8]) -> Result<(), LpmError> {
    let state = open_release_state_directory(canonical_root, true)?.ok_or_else(|| {
        LpmError::Script("could not create the release transaction directory".into())
    })?;
    #[cfg(test)]
    AFTER_RELEASE_STATE_RESOLUTION.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    persist_release_journal_in(&state, bytes)
}

pub(super) fn persist_release_journal_in(
    state: &ReleaseStateDirectory,
    bytes: &[u8],
) -> Result<(), LpmError> {
    write_private_state_file_atomic(state, RELEASE_JOURNAL_FILE, bytes)
}

#[cfg(test)]
std::thread_local! {
    pub(super) static AFTER_RELEASE_STATE_RESOLUTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    pub(super) static FAIL_NEXT_COMMIT_PERSIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FAIL_NEXT_JOURNAL_REMOVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FAIL_NEXT_COMMIT_REMOVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FAIL_NEXT_CLEANUP_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn persist_release_commit(
    canonical_root: &Path,
    journal_bytes: &[u8],
) -> Result<(), LpmError> {
    let state = open_release_state_directory(canonical_root, true)?.ok_or_else(|| {
        LpmError::Script("could not open the release transaction directory".into())
    })?;
    let journal: ReleaseApplyJournal = serde_json::from_slice(journal_bytes)?;
    let commit = release_commit_for_journal(&journal, journal_bytes);
    persist_release_commit_in(&state, &commit)
}

pub(super) fn persist_release_commit_in(
    state: &ReleaseStateDirectory,
    commit: &ReleaseApplyCommit,
) -> Result<(), LpmError> {
    let bytes = serde_json::to_vec(commit)?;
    write_private_state_file_atomic(state, RELEASE_COMMIT_FILE, &bytes)?;
    #[cfg(test)]
    if FAIL_NEXT_COMMIT_PERSIST.with(|fail| fail.replace(false)) {
        return Err(LpmError::Io(std::io::Error::other(
            "injected post-replacement commit persistence failure",
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn release_commit_for_journal(
    journal: &ReleaseApplyJournal,
    journal_bytes: &[u8],
) -> ReleaseApplyCommit {
    release_commit_for_parts(
        journal.operation.clone(),
        journal.version_git.as_ref().map(|git| git.tag.clone()),
        journal_bytes,
    )
}

fn release_commit_for_parts(
    operation: ReleaseTransactionOperation,
    tag: Option<String>,
    journal_bytes: &[u8],
) -> ReleaseApplyCommit {
    ReleaseApplyCommit {
        schema_version: RELEASE_JOURNAL_SCHEMA_VERSION,
        journal_sha256: sha256_hex(journal_bytes),
        operation: Some(operation),
        tag,
    }
}

pub(super) fn release_commit_is_durable_in(
    state: &ReleaseStateDirectory,
    journal_bytes: &[u8],
) -> Result<bool, LpmError> {
    let Some((_bytes, commit)) = read_release_commit_in(state)? else {
        return Ok(false);
    };
    Ok(commit.journal_sha256 == sha256_hex(journal_bytes))
}

pub(super) fn read_release_commit_in(
    state: &ReleaseStateDirectory,
) -> Result<Option<(Vec<u8>, ReleaseApplyCommit)>, LpmError> {
    let Some(bytes) =
        read_private_state_file_capped(state, RELEASE_COMMIT_FILE, MAX_RELEASE_COMMIT_BYTES)?
    else {
        return Ok(None);
    };
    let commit: ReleaseApplyCommit = serde_json::from_slice(&bytes).map_err(|error| {
        LpmError::Script(format!(
            "cannot validate release commit marker at {}: {error}",
            state.display.join(RELEASE_COMMIT_FILE).display()
        ))
    })?;
    if commit.schema_version != RELEASE_JOURNAL_SCHEMA_VERSION
        || !valid_sha256_hex(&commit.journal_sha256)
        || commit
            .operation
            .as_ref()
            .is_some_and(|operation| !valid_sha256_hex(&operation.fingerprint))
    {
        return Err(LpmError::Script(format!(
            "release commit marker is invalid: {}",
            state.display.join(RELEASE_COMMIT_FILE).display()
        )));
    }
    Ok(Some((bytes, commit)))
}

pub(super) fn release_commit_exists_in(state: &ReleaseStateDirectory) -> Result<bool, LpmError> {
    Ok(open_private_state_file(state, RELEASE_COMMIT_FILE)?.is_some())
}

#[cfg(test)]
pub(super) fn existing_release_journal_path(
    canonical_root: &Path,
) -> Result<Option<PathBuf>, LpmError> {
    let Some(state) = open_release_state_directory(canonical_root, false)? else {
        return Ok(None);
    };
    Ok(release_journal_exists_in(&state)?.then(|| state.display.join(RELEASE_JOURNAL_FILE)))
}

pub(super) fn release_journal_exists_in(state: &ReleaseStateDirectory) -> Result<bool, LpmError> {
    Ok(open_private_state_file(state, RELEASE_JOURNAL_FILE)?.is_some())
}

#[cfg(test)]
pub(super) fn remove_release_journal(canonical_root: &Path) -> Result<(), LpmError> {
    let Some(state) = open_release_state_directory(canonical_root, false)? else {
        return Ok(());
    };
    remove_release_journal_in(&state)
}

pub(super) fn remove_release_journal_in(state: &ReleaseStateDirectory) -> Result<(), LpmError> {
    if !release_journal_exists_in(state)? {
        return Ok(());
    }
    #[cfg(test)]
    if FAIL_NEXT_JOURNAL_REMOVE.with(|fail| fail.replace(false)) {
        return Err(LpmError::Io(std::io::Error::other(
            "injected release journal cleanup failure",
        )));
    }
    state
        .dir
        .remove_file(RELEASE_JOURNAL_FILE)
        .map_err(LpmError::Io)?;
    #[cfg(test)]
    if FAIL_NEXT_COMMIT_REMOVE.with(|fail| fail.replace(false)) {
        return Err(LpmError::Io(std::io::Error::other(
            "injected release commit-marker cleanup failure",
        )));
    }
    match state.dir.remove_file(RELEASE_COMMIT_FILE) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(LpmError::Io(error)),
    }
    #[cfg(test)]
    if FAIL_NEXT_CLEANUP_SYNC.with(|fail| fail.replace(false)) {
        return Err(LpmError::Io(std::io::Error::other(
            "injected release state-directory sync failure",
        )));
    }
    sync_cap_directory(&state.dir).map_err(LpmError::Io)
}

pub(super) fn remove_committed_release_journal_in(
    state: &ReleaseStateDirectory,
    journal_bytes: &[u8],
    commit: &ReleaseApplyCommit,
) -> Result<(), LpmError> {
    let Err(cleanup_error) = remove_release_journal_in(state) else {
        return Ok(());
    };
    let restore_result = persist_release_journal_in(state, journal_bytes)
        .and_then(|()| persist_release_commit_in(state, commit))
        .and_then(|()| {
            release_commit_is_durable_in(state, journal_bytes)?
                .then_some(())
                .ok_or_else(|| {
                    LpmError::Script("restored release completion marker is not durable".into())
                })
        });
    match restore_result {
        Ok(()) => Err(cleanup_error),
        Err(restore_error) => Err(LpmError::Script(format!(
            "{cleanup_error}; release completion receipt could not be restored: {restore_error}"
        ))),
    }
}

pub(super) fn remove_release_commit_receipt_in(
    state: &ReleaseStateDirectory,
    commit_bytes: &[u8],
) -> Result<(), LpmError> {
    match state.dir.remove_file(RELEASE_COMMIT_FILE) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    }
    if let Err(error) = sync_cap_directory(&state.dir) {
        write_private_state_file_atomic(state, RELEASE_COMMIT_FILE, commit_bytes).map_err(
            |restore_error| {
                LpmError::Script(format!(
                    "release completion marker cleanup failed: {error}; the marker could not be restored: {restore_error}"
                ))
            },
        )?;
        return Err(LpmError::Io(error));
    }
    Ok(())
}

fn validate_recovery_entries_from_open_root(
    canonical_root: &Path,
    root_dir: &cap_std::fs::Dir,
    journal_entries: Vec<RecoveryApplyJournalEntry<'_>>,
    allowed_manifests: &[PathBuf],
) -> Result<Vec<RecoveryEntry>, LpmError> {
    if journal_entries.is_empty() || journal_entries.len() > MAX_RELEASE_JOURNAL_ENTRIES {
        return Err(LpmError::Script(format!(
            "release journal entry count {} is outside the supported range 1..={MAX_RELEASE_JOURNAL_ENTRIES}",
            journal_entries.len()
        )));
    }

    use base64::{Engine, engine::general_purpose::STANDARD};

    let max_encoded_manifest = (lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize).div_ceil(3) * 4;
    let allowed_manifests = allowed_release_manifest_paths(canonical_root, allowed_manifests)?;
    let mut total_original_bytes = 0usize;
    let mut previous_path: Option<PathBuf> = None;
    let mut entries = Vec::with_capacity(journal_entries.len());
    for entry in journal_entries {
        if !valid_sha256_hex(entry.original_sha256) || !valid_sha256_hex(entry.updated_sha256) {
            return Err(LpmError::Script(
                "release journal contains an invalid SHA-256 digest".into(),
            ));
        }
        if entry.original_base64.len() > max_encoded_manifest {
            return Err(LpmError::Script(
                "release journal contains an oversized manifest backup".into(),
            ));
        }
        let original = STANDARD.decode(entry.original_base64).map_err(|error| {
            LpmError::Script(format!(
                "release journal contains invalid manifest backup encoding: {error}"
            ))
        })?;
        if original.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES
            || sha256_hex(&original) != entry.original_sha256
        {
            return Err(LpmError::Script(
                "release journal manifest backup failed integrity validation".into(),
            ));
        }
        total_original_bytes = total_original_bytes
            .checked_add(original.len())
            .ok_or_else(|| LpmError::Script("release journal size overflow".into()))?;
        if total_original_bytes > MAX_RELEASE_ORIGINAL_BYTES {
            return Err(LpmError::Script(
                "release journal manifest backups exceed the aggregate limit".into(),
            ));
        }

        let relative = decode_relative_path(entry.path)?;
        if !allowed_manifests.contains(&relative) {
            return Err(LpmError::Script(format!(
                "release journal target is not a release manifest: {}",
                relative.display()
            )));
        }
        if previous_path
            .as_ref()
            .is_some_and(|previous| previous >= &relative)
        {
            return Err(LpmError::Script(
                "release journal paths must be unique and sorted".into(),
            ));
        }
        previous_path = Some(relative.clone());
        let target = recovery_manifest_target(root_dir, canonical_root, &relative)?;
        let current = read_manifest_target(&target)?;
        let restore = if current == original {
            false
        } else if sha256_hex(&current) == entry.updated_sha256 {
            true
        } else {
            return Err(LpmError::Script(format!(
                "{} changed outside the interrupted release transaction; no files were restored and the journal was preserved",
                target.display.display()
            )));
        };
        entries.push(RecoveryEntry {
            target,
            original,
            updated_sha256: entry.updated_sha256.to_owned(),
            restore,
        });
    }
    Ok(entries)
}

pub(super) fn allowed_release_manifest_paths(
    canonical_root: &Path,
    allowed_manifests: &[PathBuf],
) -> Result<BTreeSet<PathBuf>, LpmError> {
    let mut allowed = BTreeSet::new();
    for manifest in allowed_manifests {
        if manifest.file_name().and_then(|name| name.to_str()) != Some("package.json") {
            return Err(LpmError::Script(format!(
                "release manifest allow-list contains a non-package manifest: {}",
                manifest.display()
            )));
        }
        allowed.insert(planned_manifest_relative_path(canonical_root, manifest)?);
    }
    Ok(allowed)
}
