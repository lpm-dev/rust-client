//! The sandbox helper beside lpm on Windows, `lpm-sandbox-helper.exe`,
//! which a standalone self-update brings to the release it installs.

use super::download::StagedAsset;
use super::{
    ASSET_MAX_BYTES, VerifiedReleaseManifest, copy_executable_atomic, ensure_staged_file_unchanged,
    fetch_asset_to_staged_file, github_release_download_url,
    remove_binaries_moved_aside_by_earlier_updates, safe_remote_label, verify_release_asset_digest,
};
#[cfg(windows)]
use super::{
    InstallMethod, detect_install_method_from_path_with_roots, detect_platform,
    fetch_verified_release_manifest, release_http_client, update_site,
    validate_standalone_install_location, windows_trust,
};
use crate::install_ui;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/// The file the sandbox looks for beside lpm on Windows, after any
/// `LPM_SANDBOX_HELPER`.
#[cfg(any(windows, test))]
pub(super) const SANDBOX_HELPER_FILE_NAME: &str = "lpm-sandbox-helper.exe";

/// A release's sandbox helper, checked against its signed manifest and
/// staged beside the helper at `path`.
#[cfg(any(windows, test))]
#[derive(Debug)]
pub(super) struct StagedHelper {
    asset: StagedAsset,
    path: PathBuf,
}

/// Fetches the sandbox helper `asset_name` of release `version`, checks it
/// against the release's verified manifest, and stages it beside
/// `helper_path`, the helper it is to replace, which needn't exist yet.
/// A release whose manifest lists no helper, from before one shipped,
/// stages none, and the helper there stays.
#[cfg(any(windows, test))]
pub(super) async fn stage_sandbox_helper(
    client: &reqwest::Client,
    release: &VerifiedReleaseManifest,
    version: &str,
    asset_name: &str,
    helper_path: &Path,
    human_output: bool,
) -> Result<Option<StagedHelper>, LpmError> {
    if !release.entries.contains_key(asset_name) {
        if human_output {
            install_ui::warn_untrusted(&format!(
                "release v{version} ships no `{asset_name}`; the sandbox helper beside lpm \
                 stays as it is"
            ));
        }
        return Ok(None);
    }
    let asset_url = github_release_download_url(version, asset_name);
    let asset = fetch_asset_to_staged_file(client, &asset_url, ASSET_MAX_BYTES, helper_path)
        .await?
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "release v{version} advertises `{asset_name}` in SHA256SUMS.txt but the asset is missing at {} — release-pipeline bug",
                safe_remote_label(&asset_url)
            ))
        })?;
    verify_release_asset_digest(release, asset.sha256.clone(), asset_name)?;
    if human_output {
        install_ui::done_untrusted(&format!(
            "Verified {asset_name} ({}) against the same signed checksums",
            lpm_common::format_bytes(asset.byte_len as u64)
        ));
    }
    Ok(Some(StagedHelper {
        asset,
        path: helper_path.to_path_buf(),
    }))
}

/// The sandbox helper beside lpm, swapped for a release's. The one it
/// replaced is kept aside until lpm's own binary is in place.
#[cfg(any(windows, test))]
#[derive(Debug)]
pub(super) struct HelperSwap {
    pub(super) path: PathBuf,
    moved_aside: Option<PathBuf>,
    /// `<helper>.previous`, refreshed from the helper replaced.
    backup: Option<PathBuf>,
    /// Why `<helper>.previous` couldn't be refreshed.
    backup_error: Option<String>,
}

/// Puts the staged helper where the sandbox looks for it, beside lpm. A
/// helper already there, which may be running a lifecycle script, is
/// copied to `<helper>.previous`, as lpm itself is, and moved aside under
/// a name earlier updates' leftovers are swept by. Anything there but a
/// file, which the sweep wouldn't remove, is refused.
#[cfg(any(windows, test))]
pub(super) fn install_staged_helper(staged: StagedHelper) -> Result<HelperSwap, LpmError> {
    let StagedHelper { asset, path } = staged;
    ensure_staged_file_unchanged(&asset.temporary, &asset.sha256)?;
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return Err(LpmError::SelfUpdate(format!(
            "the sandbox helper path {} has no directory or file name",
            plain_display(&path)
        )));
    };
    if asset.temporary.path().parent() != Some(parent) {
        return Err(LpmError::SelfUpdate(
            "the staged sandbox helper is not beside the one it replaces".to_string(),
        ));
    }
    let file_name = file_name.to_string_lossy();

    let mut backup = None;
    let mut backup_error = None;
    let moved_aside = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(LpmError::SelfUpdate(format!(
                "{} isn't a file, so self-update won't put the sandbox helper there; move it \
                 away and run `lpm self-update` again",
                plain_display(&path)
            )));
        }
        Ok(_) => {
            let previous = parent.join(format!("{file_name}.previous"));
            match copy_executable_atomic(&path, &previous) {
                Ok(()) => backup = Some(previous),
                Err(error) => backup_error = Some(error.to_string()),
            }
            remove_binaries_moved_aside_by_earlier_updates(parent, &file_name);
            let aside = parent.join(format!("{file_name}.old.{}", std::process::id()));
            std::fs::rename(&path, &aside).map_err(|error| {
                LpmError::SelfUpdate(format!(
                    "failed to move the sandbox helper {} aside: {error}",
                    plain_display(&path)
                ))
            })?;
            Some(aside)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(LpmError::SelfUpdate(format!(
                "could not inspect the sandbox helper {}: {error}",
                plain_display(&path)
            )));
        }
    };
    let temporary = asset.temporary.into_temp_path();
    if let Err(error) = std::fs::rename(&temporary, &path) {
        if let Some(aside) = &moved_aside {
            let _ = std::fs::rename(aside, &path);
        }
        return Err(LpmError::SelfUpdate(format!(
            "failed to install the sandbox helper at {}: {error}",
            plain_display(&path)
        )));
    }
    Ok(HelperSwap {
        path,
        moved_aside,
        backup,
        backup_error,
    })
}

#[cfg(any(windows, test))]
impl HelperSwap {
    /// Keeps the new helper. The one moved aside is removed now, or, while
    /// it still runs a script, by a later update.
    pub(super) fn finish(self) -> SandboxHelperReport {
        let status = if let Some(aside) = &self.moved_aside {
            let _ = std::fs::remove_file(aside);
            SandboxHelperStatus::Updated
        } else {
            SandboxHelperStatus::Installed
        };
        SandboxHelperReport {
            backup: self.backup,
            backup_error: self.backup_error,
            ..SandboxHelperReport::new(status, self.path)
        }
    }

    /// Puts back the helper that was there, as lpm's own binary wasn't
    /// replaced. The new one may already be running a script, and a running
    /// executable can be renamed but not removed or replaced, so it is
    /// moved aside, under a name a later update sweeps, before the earlier
    /// one comes back.
    pub(super) fn undo(self) -> std::io::Result<()> {
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let new_aside = self.path.with_file_name(format!(
            "{file_name}.old.{}{:09}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        std::fs::rename(&self.path, &new_aside)?;
        if let Some(aside) = &self.moved_aside
            && let Err(error) = std::fs::rename(aside, &self.path)
        {
            let _ = std::fs::rename(&new_aside, &self.path);
            return Err(error);
        }
        let _ = std::fs::remove_file(&new_aside);
        Ok(())
    }

    /// What the update journal says of the helper: where its copy of the
    /// one replaced is, if there is one.
    pub(super) fn journal_entry(&self) -> Option<serde_json::Value> {
        let backup = self.backup.as_ref()?;
        Some(serde_json::json!({
            "path": self.path.display().to_string(),
            "backup_path": backup.display().to_string(),
        }))
    }
}

/// What a self-update did to the sandbox helper beside lpm.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SandboxHelperStatus {
    /// It was replaced with the release's.
    Updated,
    /// The release's was put there, where there was none.
    Installed,
    /// The release ships none, so the one there stays.
    NotInRelease,
    /// It couldn't be brought to the release's, for the reason given.
    Failed(String),
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(super) struct SandboxHelperReport {
    status: SandboxHelperStatus,
    path: PathBuf,
    backup: Option<PathBuf>,
    backup_error: Option<String>,
    /// The helper `LPM_SANDBOX_HELPER` names instead, which the sandbox
    /// uses and self-update leaves as it is.
    pub(super) named_elsewhere: Option<PathBuf>,
}

#[cfg(any(windows, test))]
impl SandboxHelperReport {
    pub(super) fn new(status: SandboxHelperStatus, path: PathBuf) -> Self {
        Self {
            status,
            path,
            backup: None,
            backup_error: None,
            named_elsewhere: None,
        }
    }

    /// The `sandbox_helper` object of `--json`.
    pub(super) fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "status": match &self.status {
                SandboxHelperStatus::Updated => "updated",
                SandboxHelperStatus::Installed => "installed",
                SandboxHelperStatus::NotInRelease => "not_in_release",
                SandboxHelperStatus::Failed(_) => "failed",
            },
            "path": plain_display(&self.path),
            "backup_path": self.backup.as_deref().map(plain_display),
        });
        if let SandboxHelperStatus::Failed(error) = &self.status {
            json["error"] = error.clone().into();
        }
        if let Some(error) = &self.backup_error {
            json["backup_error"] = error.clone().into();
        }
        if let Some(named) = &self.named_elsewhere {
            json["lpm_sandbox_helper"] = plain_display(named).into();
        }
        json
    }

    /// Says what happened, for a person reading the update's output. A
    /// release with no helper was named when its assets were fetched.
    #[cfg(windows)]
    pub(super) fn print(&self) {
        let path = plain_display(&self.path);
        match &self.status {
            SandboxHelperStatus::Updated => {
                install_ui::done_untrusted(&format!("Updated the sandbox helper at {path}"));
            }
            SandboxHelperStatus::Installed => {
                install_ui::done_untrusted(&format!("Installed the sandbox helper at {path}"));
            }
            SandboxHelperStatus::NotInRelease => {}
            SandboxHelperStatus::Failed(error) => install_ui::warn_untrusted(&format!(
                "couldn't bring the sandbox helper at {path} to this release's: {error}; run \
                 `lpm self-update` again to retry"
            )),
        }
        if let Some(error) = &self.backup_error {
            install_ui::warn_untrusted(&format!(
                "couldn't keep a copy of the earlier sandbox helper as {path}.previous: {error}"
            ));
        }
        if let Some(named) = &self.named_elsewhere {
            install_ui::warn_untrusted(&format!(
                "LPM_SANDBOX_HELPER names {}, which self-update doesn't replace; save this \
                 release's sandbox helper there, or unset LPM_SANDBOX_HELPER to use the one \
                 beside lpm",
                plain_display(named)
            ));
        }
    }
}

/// `path` as a person would type it: without the `\\?\` prefix that only
/// lifts Windows' length limit, `\\?\UNC\server` as `\\server`.
#[cfg(any(windows, test))]
pub(super) fn plain_display(path: &Path) -> String {
    let text = path.display().to_string();
    if let Some(share) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{share}")
    } else if let Some(local) = text
        .strip_prefix(r"\\?\")
        .filter(|local| local.as_bytes().get(1) == Some(&b':'))
    {
        local.to_owned()
    } else {
        text
    }
}

/// The helper `LPM_SANDBOX_HELPER` names when it isn't the one beside lpm:
/// the sandbox uses that one, which self-update leaves as it is.
#[cfg(windows)]
pub(super) fn sandbox_helper_named_elsewhere(current_executable: &Path) -> Option<PathBuf> {
    let named =
        PathBuf::from(std::env::var_os("LPM_SANDBOX_HELPER").filter(|value| !value.is_empty())?);
    let beside = current_executable.with_file_name(SANDBOX_HELPER_FILE_NAME);
    (!same_file::is_same_file(&named, &beside).unwrap_or(false)).then_some(named)
}

/// The release the sandbox helper at `helper` says it comes from, if it
/// says: one from before helpers did exits with an argument error.
#[cfg(windows)]
fn sandbox_helper_release(helper: &Path) -> Option<String> {
    let output = lpm_common::process_output::output_capped(
        std::process::Command::new(helper).arg(lpm_sandbox::helper_protocol::RELEASE_FLAG),
        Duration::from_secs(10),
        256,
    )
    .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|release| release.trim().to_owned())
}

/// Puts release `version`'s sandbox helper beside lpm when the one there is
/// another release's, or there is none, for a standalone install already on
/// `version`. The update to this release may have run under an earlier lpm,
/// which left the helper as it was. A package manager's install brings its
/// own helper. Says what it did, if anything; a failure leaves lpm as it is.
#[cfg(windows)]
pub(super) async fn refresh_stale_sandbox_helper(
    version: &str,
    current_executable: &Path,
    account_home: &Path,
    human_output: bool,
) -> Option<SandboxHelperReport> {
    let path = current_executable.with_file_name(SANDBOX_HELPER_FILE_NAME);
    if sandbox_helper_release(&path).as_deref() == Some(version) {
        return None;
    }
    let standalone = update_site(account_home, current_executable)
        .and_then(|site| {
            detect_install_method_from_path_with_roots(
                Some(current_executable),
                &site.install_roots,
            )
        })
        .is_ok_and(|method| method == InstallMethod::Standalone);
    if !standalone {
        return None;
    }
    let refreshed = async {
        let _installation_lock = windows_trust::try_acquire_installation_lock(current_executable)
            .map_err(LpmError::Io)?
            .ok_or_else(|| {
                LpmError::SelfUpdate(
                    "another self-update is changing this LPM installation".to_string(),
                )
            })?;
        validate_standalone_install_location(current_executable)?;
        let (platform, ext) = detect_platform()?;
        let client = release_http_client()?;
        let release = fetch_verified_release_manifest(&client, version, human_output).await?;
        let Some(staged) = stage_sandbox_helper(
            &client,
            &release,
            version,
            &format!("lpm-sandbox-helper-{platform}{ext}"),
            &path,
            human_output,
        )
        .await?
        else {
            return Ok(SandboxHelperReport::new(
                SandboxHelperStatus::NotInRelease,
                path.clone(),
            ));
        };
        validate_standalone_install_location(current_executable)?;
        Ok::<_, LpmError>(install_staged_helper(staged)?.finish())
    }
    .await;
    let mut report = refreshed.unwrap_or_else(|error| {
        SandboxHelperReport::new(SandboxHelperStatus::Failed(error.to_string()), path)
    });
    report.named_elsewhere = sandbox_helper_named_elsewhere(current_executable);
    if human_output {
        report.print();
    }
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::super::tests::run_standalone_against_server;
    use super::super::{
        create_staged_binary, finish_staged_binary, install_staged_binary_noting,
        release_http_client, sha256_hex,
    };
    use super::*;

    /// `contents`, staged to replace the sandbox helper at `path`.
    fn staged_helper_at(path: &Path, contents: &[u8]) -> StagedHelper {
        use std::io::Write as _;

        let mut temporary = create_staged_binary(path).unwrap();
        temporary.write_all(contents).unwrap();
        StagedHelper {
            asset: StagedAsset {
                temporary: finish_staged_binary(temporary).unwrap(),
                byte_len: contents.len(),
                sha256: sha256_hex(contents),
            },
            path: path.to_path_buf(),
        }
    }

    fn file_names_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// `lpm self-update` replaced lpm but left the sandbox helper of the
    /// release it came from.
    #[test]
    fn a_staged_sandbox_helper_replaces_the_one_beside_lpm_and_can_be_put_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        std::fs::write(&path, b"earlier helper").unwrap();

        let swap = install_staged_helper(staged_helper_at(&path, b"later helper")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"later helper");
        assert_eq!(
            std::fs::read(directory.path().join("lpm-sandbox-helper.exe.previous")).unwrap(),
            b"earlier helper"
        );
        // lpm's own binary couldn't be replaced.
        swap.undo().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier helper");

        let report = install_staged_helper(staged_helper_at(&path, b"later helper"))
            .unwrap()
            .finish();
        assert_eq!(report.status, SandboxHelperStatus::Updated);
        assert_eq!(
            report.backup.as_deref(),
            Some(
                directory
                    .path()
                    .join("lpm-sandbox-helper.exe.previous")
                    .as_path()
            )
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"later helper");
        assert_eq!(
            file_names_in(directory.path()),
            ["lpm-sandbox-helper.exe", "lpm-sandbox-helper.exe.previous"]
        );
    }

    /// A directory, or a link, where the helper goes would be moved aside
    /// and never swept, as the sweep removes files only; the update is
    /// refused before anything changes.
    #[test]
    fn a_sandbox_helper_path_that_isnt_a_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        std::fs::create_dir(&path).unwrap();

        let refused = install_staged_helper(staged_helper_at(&path, b"helper")).unwrap_err();
        assert!(refused.to_string().contains("isn't a file"), "{refused}");
        assert!(path.is_dir());
        assert_eq!(file_names_in(directory.path()), ["lpm-sandbox-helper.exe"]);
    }

    /// The update says when the copy of the earlier helper couldn't be
    /// refreshed, rather than leave an older one there without a word.
    #[test]
    fn a_sandbox_helper_copy_that_cant_be_refreshed_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        std::fs::write(&path, b"earlier helper").unwrap();
        let previous = directory.path().join("lpm-sandbox-helper.exe.previous");
        std::fs::create_dir(&previous).unwrap();

        let report = install_staged_helper(staged_helper_at(&path, b"later helper"))
            .unwrap()
            .finish();
        assert_eq!(report.status, SandboxHelperStatus::Updated);
        assert_eq!(report.backup, None);
        assert!(report.backup_error.is_some());
        assert!(report.to_json()["backup_error"].is_string());
        assert_eq!(std::fs::read(&path).unwrap(), b"later helper");
    }

    /// A rollback to `lpm.exe.previous` by hand can find the helper's copy
    /// in the update journal.
    #[test]
    fn the_update_journal_names_the_sandbox_helpers_copy() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("lpm-test-bin");
        std::fs::write(&current, b"old").unwrap();
        let helper = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        std::fs::write(&helper, b"earlier helper").unwrap();

        let swap = install_staged_helper(staged_helper_at(&helper, b"later helper")).unwrap();
        let mut temporary = create_staged_binary(&current).unwrap();
        std::io::Write::write_all(&mut temporary, b"new").unwrap();
        install_staged_binary_noting(
            &current,
            finish_staged_binary(temporary).unwrap(),
            &sha256_hex(b"new"),
            swap.journal_entry().as_ref(),
        )
        .unwrap();
        swap.finish();

        let journal: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("lpm-test-bin.update-journal.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            journal["sandbox_helper"]["backup_path"],
            directory
                .path()
                .join("lpm-sandbox-helper.exe.previous")
                .display()
                .to_string()
        );
        assert_eq!(
            journal["sandbox_helper"]["path"],
            helper.display().to_string()
        );
    }

    /// `--json` says what became of the helper, and names one
    /// `LPM_SANDBOX_HELPER` points at instead, by paths a person would
    /// type.
    #[test]
    fn the_sandbox_helper_report_says_what_happened() {
        let report = SandboxHelperReport {
            backup: Some(PathBuf::from(r"\\?\C:\lpm\lpm-sandbox-helper.exe.previous")),
            named_elsewhere: Some(PathBuf::from(r"\\?\UNC\nas\tools\helper.exe")),
            ..SandboxHelperReport::new(
                SandboxHelperStatus::Updated,
                PathBuf::from(r"\\?\C:\lpm\lpm-sandbox-helper.exe"),
            )
        };
        assert_eq!(
            report.to_json(),
            serde_json::json!({
                "status": "updated",
                "path": r"C:\lpm\lpm-sandbox-helper.exe",
                "backup_path": r"C:\lpm\lpm-sandbox-helper.exe.previous",
                "lpm_sandbox_helper": r"\\nas\tools\helper.exe",
            })
        );
        let failed = SandboxHelperReport::new(
            SandboxHelperStatus::Failed("offline".to_string()),
            PathBuf::from(r"C:\lpm\lpm-sandbox-helper.exe"),
        );
        assert_eq!(failed.to_json()["status"], "failed");
        assert_eq!(failed.to_json()["error"], "offline");
        assert_eq!(
            SandboxHelperReport::new(SandboxHelperStatus::NotInRelease, PathBuf::from("x"))
                .to_json()["status"],
            "not_in_release"
        );
        assert_eq!(
            plain_display(Path::new(r"\\?\Volume{0}\lpm.exe")),
            r"\\?\Volume{0}\lpm.exe"
        );
    }

    #[test]
    fn a_staged_sandbox_helper_is_installed_where_there_was_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);

        let swap = install_staged_helper(staged_helper_at(&path, b"helper")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"helper");
        swap.undo().unwrap();
        assert!(file_names_in(directory.path()).is_empty());

        let report = install_staged_helper(staged_helper_at(&path, b"helper"))
            .unwrap()
            .finish();
        assert_eq!(report.status, SandboxHelperStatus::Installed);
        assert_eq!(file_names_in(directory.path()), ["lpm-sandbox-helper.exe"]);
    }

    /// A helper running a lifecycle script, in another lpm, is moved aside
    /// rather than overwritten, and swept once it has exited.
    #[cfg(windows)]
    #[test]
    fn a_running_sandbox_helper_is_moved_aside_and_swept_later() {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        let system = std::env::var_os("SystemRoot").unwrap();
        std::fs::copy(Path::new(&system).join(r"System32\PING.EXE"), &path).unwrap();
        let mut running = std::process::Command::new(&path)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();

        // While it runs, the helper moved aside can't be removed yet.
        let installed =
            install_staged_helper(staged_helper_at(&path, b"later helper")).map(HelperSwap::finish);
        let names = file_names_in(directory.path());
        running.kill().unwrap();
        running.wait().unwrap();
        installed.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"later helper");
        let moved_aside = format!("lpm-sandbox-helper.exe.old.{}", std::process::id());
        assert!(names.contains(&moved_aside), "{names:?}");

        remove_binaries_moved_aside_by_earlier_updates(directory.path(), SANDBOX_HELPER_FILE_NAME);
        assert_eq!(
            file_names_in(directory.path()),
            ["lpm-sandbox-helper.exe", "lpm-sandbox-helper.exe.previous"]
        );
    }

    /// lpm's own binary couldn't be replaced after the new helper had
    /// started a script: the earlier helper still comes back, and the new
    /// one, which can't be removed while it runs, is swept later.
    #[cfg(windows)]
    #[test]
    fn the_earlier_sandbox_helper_comes_back_while_the_new_one_runs() {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);
        std::fs::write(&path, b"earlier helper").unwrap();
        let system = std::env::var_os("SystemRoot").unwrap();
        let ping = std::fs::read(Path::new(&system).join(r"System32\PING.EXE")).unwrap();

        let swap = install_staged_helper(staged_helper_at(&path, &ping)).unwrap();
        let mut running = std::process::Command::new(&path)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let undone = swap.undo();
        let restored = std::fs::read(&path);
        running.kill().unwrap();
        running.wait().unwrap();
        undone.unwrap();
        assert_eq!(restored.unwrap(), b"earlier helper");

        remove_binaries_moved_aside_by_earlier_updates(directory.path(), SANDBOX_HELPER_FILE_NAME);
        assert_eq!(
            file_names_in(directory.path()),
            ["lpm-sandbox-helper.exe", "lpm-sandbox-helper.exe.previous"]
        );
    }

    fn release_listing(entries: &[(&str, &[u8])]) -> VerifiedReleaseManifest {
        VerifiedReleaseManifest {
            publisher: None,
            workflow_path: None,
            workflow_ref: None,
            integrated_time: chrono::Utc::now(),
            log_index: 0,
            log_id: String::new(),
            leaf_cert_sha256: String::new(),
            manifest_sha256: String::new(),
            source_commit: String::new(),
            entries: entries
                .iter()
                .map(|(name, contents)| ((*name).to_string(), sha256_hex(contents)))
                .collect(),
        }
    }

    #[tokio::test]
    async fn the_sandbox_helper_is_fetched_only_as_the_signed_manifest_lists_it() {
        const ASSET: &str = "lpm-sandbox-helper-win32-arm64.exe";
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!(
                "/download/v0.42.0/{ASSET}"
            )))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_bytes(b"release helper".to_vec()),
            )
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SANDBOX_HELPER_FILE_NAME);

        run_standalone_against_server(&server, "0.42.0", || async {
            let client = release_http_client().unwrap();
            let listed = release_listing(&[(ASSET, b"release helper")]);
            let staged = stage_sandbox_helper(&client, &listed, "0.42.0", ASSET, &path, false)
                .await
                .unwrap()
                .expect("a listed helper is staged");
            assert_eq!(staged.path, path);
            assert_eq!(
                std::fs::read(staged.asset.temporary.path()).unwrap(),
                b"release helper"
            );
            drop(staged);

            let other = release_listing(&[(ASSET, b"another helper")]);
            let refused = stage_sandbox_helper(&client, &other, "0.42.0", ASSET, &path, false)
                .await
                .expect_err("a helper the manifest doesn't list by its digest is refused");
            assert!(
                refused.to_string().contains("SHA-256 mismatch"),
                "{refused}"
            );

            let earlier = release_listing(&[("lpm-win32-arm64.exe", b"lpm")]);
            assert!(
                stage_sandbox_helper(&client, &earlier, "0.42.0", ASSET, &path, false)
                    .await
                    .unwrap()
                    .is_none()
            );
        })
        .await;
        // Nothing staged is left beside the helper.
        assert!(file_names_in(directory.path()).is_empty());
    }
}
