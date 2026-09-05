use crate::install_ui;
use crate::release_channel::ReleaseChannel;
use crate::release_lookup::{
    FetchOutcome, LookupError, fetch_github_release_published_at, github_release_download_url,
    is_newer_semver, operating_system_home_dir, probe_release, read_cache_at, write_cache_at,
};
use crate::sigstore_verify::{
    IdentityExpectations, VerifiedProvenance, VerifyError, VerifyOptions,
    extract_subject_digest_from_statement, verify_sigstore_bundle,
};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(any(target_os = "macos", test))]
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod cargo_metadata;
mod download;
mod probe;
#[cfg(windows)]
mod windows_trust;

use self::download::{
    StagedAsset, ensure_staged_file_unchanged, fetch_asset_to_staged_file, fetch_bounded,
    safe_remote_label,
};
#[cfg(test)]
use self::download::{create_staged_binary, finish_staged_binary};
use self::probe::{BoundUpdateCommand, VersionProbe};

/// User-facing self-update reuses the banner cache file but with a much
/// shorter success TTL: a second `lpm self-update` within 10 minutes
/// short-circuits to the cached version. Long enough to defang
/// pathological CI loops, short enough that an interactive user
/// re-running shortly after a release still sees the new version on
/// the next cache miss.
const LOOKUP_TTL: Duration = Duration::from_secs(10 * 60);

/// If the previous probe failed (transport, 403, malformed response),
/// back off for an hour before letting the foreground command hit
/// GitHub again. Without this, a script looping on `lpm self-update`
/// re-hammers the API on every iteration even though we just persisted
/// `last_failure_check`. `--refresh` bypasses this gate.
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Update LPM to the latest version.
///
/// Detects the installation method from the executable path and runs
/// the appropriate upgrade command. Supports npm, Homebrew, cargo,
/// and standalone (curl) installations.
///
/// Version discovery probes the installed or requested channel's npm
/// dist-tag first and falls back to the matching GitHub release.
pub async fn run(
    json_output: bool,
    refresh: bool,
    requested_channel: Option<ReleaseChannel>,
) -> Result<(), LpmError> {
    let started = Instant::now();
    let account_home = canonical_account_home()?;
    let current_executable = canonical_current_executable()?;
    let _operation_lock = try_acquire_self_update_lock(&account_home)?.ok_or_else(|| {
        LpmError::SelfUpdate(
            "another self-update operation is already running; wait for it to finish and retry"
                .to_string(),
        )
    })?;
    let current = crate::build_version::version();
    let channel = ReleaseChannel::from_installed_version(current);
    let target_channel = requested_channel.unwrap_or(channel);
    let channel_changed = channel != target_channel;

    let cache_path = Some(account_home.join(".lpm").join("update-check.json"));
    let mut cache = cache_path
        .as_deref()
        .and_then(read_cache_at)
        .unwrap_or_default();

    if !json_output {
        install_ui::phase("Checking for updates");
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Three-way decision before touching the network:
    //   (a) recent success → use cached version (cache hit).
    //   (b) recent failure → refuse without probing. Stale cached
    //       version (if any) is intentionally NOT used here: the user
    //       asked to upgrade right now and we should not silently
    //       install whatever we last saw an hour or a day ago.
    //   (c) otherwise → probe.
    // `--refresh` bypasses both (a) and (b).
    let cache_hit = !refresh
        && !cache.latest_for(target_channel).is_empty()
        && target_channel.accepts_version(cache.latest_for(target_channel))
        && cache.last_check_for(target_channel) > 0
        && now.saturating_sub(cache.last_check_for(target_channel)) < LOOKUP_TTL.as_secs();

    let in_failure_backoff = !refresh
        && !cache_hit
        && cache.last_failure_check_for(target_channel) > 0
        && now.saturating_sub(cache.last_failure_check_for(target_channel))
            < FAILURE_BACKOFF.as_secs();

    if in_failure_backoff {
        let elapsed = now.saturating_sub(cache.last_failure_check_for(target_channel));
        let remaining = FAILURE_BACKOFF.as_secs().saturating_sub(elapsed);
        // SelfUpdatePaused — not Network. The failure isn't a live
        // transport problem; it's a local cache decision to back off.
        // The variant's help text surfaces `--refresh` so we don't have
        // to repeat that hint inside the message body.
        return Err(LpmError::SelfUpdatePaused(format!(
            "last attempt failed {} ago, retrying automatically in {}",
            humanize_seconds(elapsed),
            humanize_seconds(remaining),
        )));
    }

    let latest = if cache_hit {
        cache.latest_for(target_channel).to_owned()
    } else {
        match probe_release(target_channel, &mut cache).await {
            Ok(FetchOutcome::Fresh { version }) | Ok(FetchOutcome::NotModified { version }) => {
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                version
            }
            Err(e) => {
                // Persist the failure so this command AND the banner
                // staleness gate both back off on the next invocation.
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                return Err(lookup_error_to_lpm(e));
            }
        }
    };

    if !json_output {
        eprintln!("    {}   {}", install_ui::dim("current"), current.dimmed());
        eprintln!(
            "    {}    {}",
            install_ui::dim("latest"),
            install_ui::status_ok(&latest)
        );
        eprintln!(
            "    {}   {}",
            install_ui::dim("release channel"),
            target_channel.as_str().cyan()
        );
    }

    if !should_install_update(current, &latest, channel, target_channel) {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "current": current,
                "latest": latest,
                "up_to_date": true,
                "cache_hit": cache_hit,
                "channel": channel.as_str(),
                "target_channel": target_channel.as_str(),
                "channel_changed": channel_changed,
                "duration_ms": started.elapsed().as_millis() as u64,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        } else if latest == current {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Done · already on {} version {}",
                install_ui::status_ok("latest"),
                install_ui::yellow(current)
            ));
        } else {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Done · current version {} is newer than {} release {}",
                install_ui::yellow(current),
                install_ui::status_ok("latest"),
                install_ui::dim(&latest)
            ));
        }
        return Ok(());
    }

    let working_dir = std::env::current_dir().map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve the working directory before self-update: {error}"
        ))
    })?;
    let project_root = active_project_root(&working_dir, &account_home)?;
    let environment_exclusion_root =
        environment_exclusion_root(&working_dir, &project_root, &account_home)?;
    if project_root
        .as_deref()
        .is_some_and(|root| current_executable.starts_with(root))
    {
        return Err(LpmError::SelfUpdate(
            "self-update must be run from a global LPM installation, not a project-local executable"
                .to_string(),
        ));
    }
    let install_roots = InstallRoots::from_environment(
        environment_exclusion_root.as_deref(),
        &account_home,
        &current_executable,
    );
    #[cfg(windows)]
    let _installation_lock =
        windows_trust::try_acquire_installation_lock(&current_executable)?.ok_or_else(|| {
            LpmError::SelfUpdate(
                "another self-update is already mutating this LPM installation; wait for it to finish and retry"
                    .to_string(),
            )
        })?;
    let method =
        detect_install_method_from_path_with_roots(Some(&current_executable), &install_roots)?;
    method.ensure_channel_supported(target_channel)?;
    let cargo_install_root = if method == InstallMethod::Cargo {
        Some(cargo_install_root(&current_executable)?)
    } else {
        None
    };
    let cargo_source_commit = if method == InstallMethod::Cargo {
        let client = release_http_client()?;
        Some(
            fetch_verified_release_manifest(&client, &latest, !json_output)
                .await?
                .source_commit,
        )
    } else {
        None
    };
    let external_update_command = method.external_update_command_with_root(
        &latest,
        cargo_source_commit.as_deref(),
        cargo_install_root.as_deref(),
    )?;
    let sanitized_path = sanitized_path_for_method(&method, environment_exclusion_root.as_deref())?;
    let bound_update_command = external_update_command
        .as_ref()
        .map(|command| {
            let sanitized_path = sanitized_path.as_deref().ok_or_else(|| {
                LpmError::SelfUpdate("package-manager update has no sanitized PATH".to_string())
            })?;
            BoundUpdateCommand::bind(
                command.program,
                &command.args,
                sanitized_path,
                project_root.as_deref(),
                environment_exclusion_root.as_deref(),
                &account_home,
                &current_executable,
            )
        })
        .transpose()?;
    let version_probe = if method == InstallMethod::Standalone {
        None
    } else {
        Some(VersionProbe::bind_and_preflight(
            method == InstallMethod::Cargo,
            current,
            &current_executable,
            &working_dir,
            sanitized_path.as_deref().ok_or_else(|| {
                LpmError::SelfUpdate("package-manager probe has no sanitized PATH".to_string())
            })?,
            project_root.as_deref(),
            &account_home,
        )?)
    };
    if let (Some(command), Some(probe)) = (&bound_update_command, &version_probe) {
        command.ensure_owns_launcher(probe, &method)?;
    }

    // Package-manager JSON is plan-only, but a successful plan is still
    // bound to the launcher and verified owning manager before emission.
    if json_output && !matches!(method, InstallMethod::Standalone) {
        let command = external_update_command.as_ref().ok_or_else(|| {
            LpmError::SelfUpdate("package-manager plan has no update command".to_string())
        })?;
        let bound_command = bound_update_command.as_ref().ok_or_else(|| {
            LpmError::SelfUpdate("package-manager plan has no bound update command".to_string())
        })?;
        let json = serde_json::json!({
            "success": true,
            "current": current,
            "latest": latest,
            "up_to_date": false,
            "install_method": method.name(),
            "update_command": bound_command.render_verified_plan()?,
            "update_shell": command.shell(),
            "update_program": bound_command.verified_program_utf8()?,
            "update_args": bound_command.args_utf8()?,
            "applied": false,
            "launcher_verified": true,
            "manager_target_verified": true,
            "cache_hit": cache_hit,
            "channel": channel.as_str(),
            "target_channel": target_channel.as_str(),
            "channel_changed": channel_changed,
            "duration_ms": started.elapsed().as_millis() as u64,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if !json_output {
        eprintln!(
            "    {}   {}",
            install_ui::dim("install method"),
            method.name().cyan()
        );
        if let Some(command) = bound_update_command.as_ref() {
            install_ui::phase(if cfg!(windows) {
                "PowerShell update command"
            } else {
                "POSIX shell update command"
            });
            if let Ok(update_command) = command.render_verified_plan() {
                eprintln!("    {}", install_ui::yellow(&update_command));
            } else {
                eprintln!(
                    "    {}",
                    install_ui::dim(
                        "exact command contains a non-UTF-8 path and cannot be rendered safely"
                    )
                );
            }
        } else {
            install_ui::phase("Built-in signed updater");
            eprintln!(
                "    {}",
                install_ui::dim("Sigstore verification and atomic replacement are enforced")
            );
        }
    }

    let mut standalone_audit: Option<AttestationAudit> = None;
    match method {
        InstallMethod::Npm
        | InstallMethod::Pnpm
        | InstallMethod::Bun
        | InstallMethod::Yarn
        | InstallMethod::Volta
        | InstallMethod::Homebrew
        | InstallMethod::Cargo => {
            let command = bound_update_command.as_ref().ok_or_else(|| {
                LpmError::SelfUpdate(format!(
                    "{} update has no package-manager command",
                    method.name()
                ))
            })?;
            command.run()?;
            version_probe
                .as_ref()
                .ok_or_else(|| {
                    LpmError::SelfUpdate("package-manager update has no version probe".to_string())
                })?
                .verify_requested(&latest)?;
        }
        InstallMethod::Standalone => {
            standalone_audit = Some(
                run_standalone_update(&latest, &current_executable, &account_home, !json_output)
                    .await?,
            );
        }
    }

    // Post-upgrade cache stamp policy:
    // - Standalone: we downloaded the exact tag → safe to stamp.
    // - Cargo and npm-registry managers install a pinned source/version.
    // Every package-manager path is stamped only after the bound public
    // launcher reports this exact version.
    if let Some(p) = cache_path.as_deref() {
        match method {
            InstallMethod::Standalone
            | InstallMethod::Cargo
            | InstallMethod::Npm
            | InstallMethod::Pnpm
            | InstallMethod::Bun
            | InstallMethod::Yarn
            | InstallMethod::Volta
            | InstallMethod::Homebrew => {
                cache.record_success_for(target_channel, latest.clone(), now);
                let _ = write_cache_at(p, &cache);
            }
        }
    }

    if json_output {
        let audit = standalone_audit.as_ref().ok_or_else(|| {
            LpmError::SelfUpdate(
                "standalone self-update completed without an attestation audit".to_string(),
            )
        })?;
        let json = serde_json::json!({
            "success": true,
            "current": current,
            "latest": latest,
            "up_to_date": false,
            "install_method": method.name(),
            "cache_hit": cache_hit,
            "channel": channel.as_str(),
            "target_channel": target_channel.as_str(),
            "channel_changed": channel_changed,
            "applied": true,
            "verified": true,
            "attestation": audit_json(audit),
            "duration_ms": started.elapsed().as_millis() as u64,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · LPM updated to {}",
            install_ui::yellow(&latest)
        ));
    }

    Ok(())
}

fn sanitized_path_for_method(
    method: &InstallMethod,
    environment_exclusion_root: Option<&Path>,
) -> Result<Option<OsString>, LpmError> {
    if method == &InstallMethod::Standalone {
        Ok(None)
    } else {
        probe::sanitized_current_path(environment_exclusion_root).map(Some)
    }
}

fn should_install_update(
    current: &str,
    latest: &str,
    channel: ReleaseChannel,
    target_channel: ReleaseChannel,
) -> bool {
    latest != current && (channel != target_channel || is_newer_semver(latest, current))
}

/// Map a `LookupError` into `LpmError` so the existing CLI error
/// surfaces (slim UI / `--json`) render it without losing the typed
/// rate-limit info.
///
/// Mapping is purpose-specific so error categories match user intent:
/// - Transport / HTTP / malformed → `Network`. Live network problem.
/// - GitHub-API rate limit → `SelfUpdateRateLimited`. Not a permission
///   issue (the historical `Forbidden` mapping read like the user was
///   blocked); it's a quota issue with a clear remediation surfaced in
///   the variant's help text (`GITHUB_TOKEN` / `GH_TOKEN`).
///
/// `LookupError`'s own `Display` is the canonical body — it owns the
/// reset-hint formatting and intentionally omits the `GITHUB_TOKEN`
/// guidance (which lives in the wrapping variant's diagnostic help). The
/// wrapper here just adds the user-facing context prefix.
fn lookup_error_to_lpm(e: LookupError) -> LpmError {
    match &e {
        LookupError::Transport(_) | LookupError::HttpStatus { .. } => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
        LookupError::RateLimited { .. } => LpmError::SelfUpdateRateLimited(e.to_string()),
        LookupError::MalformedResponse(_) | LookupError::NotFound(_) => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
    }
}

/// Installation method detection.
#[derive(Debug, PartialEq, Eq)]
enum InstallMethod {
    Npm,
    Pnpm,
    Bun,
    Yarn,
    Volta,
    Homebrew,
    Cargo,
    Standalone,
}

#[derive(Default)]
struct InstallRoots {
    cargo: Vec<PathBuf>,
    npm: Vec<PathBuf>,
    pnpm: Vec<PathBuf>,
    bun: Vec<PathBuf>,
    yarn: Vec<PathBuf>,
    volta: Vec<PathBuf>,
    bun_config_errors: Vec<String>,
    yarn_config_errors: Vec<String>,
}

impl InstallRoots {
    fn from_environment(
        excluded_root: Option<&Path>,
        account_home: &Path,
        current_executable: &Path,
    ) -> Self {
        let mut roots = Self {
            cargo: paths_from_environment(
                &["CARGO_HOME", "CARGO_INSTALL_ROOT"],
                excluded_root,
                current_executable,
            ),
            npm: paths_from_environment(
                &[
                    "NPM_CONFIG_PREFIX",
                    "npm_config_prefix",
                    "NPM_CONFIG_GLOBAL_DIR",
                    "npm_config_global_dir",
                    "NPM_CONFIG_GLOBAL_BIN_DIR",
                    "npm_config_global_bin_dir",
                ],
                excluded_root,
                current_executable,
            ),
            pnpm: paths_from_environment(&["PNPM_HOME"], excluded_root, current_executable),
            bun: paths_from_environment(
                &[
                    "BUN_INSTALL",
                    "BUN_INSTALL_GLOBAL_DIR",
                    "BUN_INSTALL_GLOBAL_BIN_DIR",
                ],
                excluded_root,
                current_executable,
            ),
            yarn: paths_from_environment(
                &["YARN_GLOBAL_FOLDER"],
                excluded_root,
                current_executable,
            ),
            volta: paths_from_environment(&["VOLTA_HOME"], excluded_root, current_executable),
            bun_config_errors: Vec::new(),
            yarn_config_errors: Vec::new(),
        };
        let xdg_config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| trusted_config_path(path, excluded_root, account_home));
        roots.load_user_config(Some(account_home), xdg_config.as_deref(), excluded_root);
        roots
    }

    fn load_user_config(
        &mut self,
        home: Option<&Path>,
        xdg_config: Option<&Path>,
        excluded_root: Option<&Path>,
    ) {
        let Some(home) = home else {
            return;
        };
        let mut bun_configs = vec![home.join(".bunfig.toml")];
        if let Some(xdg_config) = xdg_config {
            bun_configs.push(xdg_config.join(".bunfig.toml"));
            bun_configs.push(xdg_config.join("bun").join("bunfig.toml"));
        }
        for config in bun_configs {
            match read_bun_global_roots(&config, home, excluded_root) {
                Ok(roots) => self.bun.extend(roots),
                Err(error) => self.bun_config_errors.push(error.to_string()),
            }
        }
        match read_yarn_global_roots(&home.join(".yarnrc"), home, excluded_root) {
            Ok(roots) => self.yarn.extend(roots),
            Err(error) => self.yarn_config_errors.push(error.to_string()),
        }
        deduplicate_paths(&mut self.bun);
        deduplicate_paths(&mut self.yarn);
    }
}

const MANAGER_CONFIG_LIMIT: u64 = 64 * 1024;

fn trusted_config_path(path: &Path, excluded_root: Option<&Path>, account_home: &Path) -> bool {
    path.is_absolute()
        && path_resolves_within(path, account_home).unwrap_or(false)
        && excluded_root.is_none_or(|root| !path_resolves_within(path, root).unwrap_or(true))
}

#[derive(serde::Deserialize)]
struct BunConfigFile {
    install: Option<BunInstallConfig>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BunInstallConfig {
    global_dir: Option<String>,
    global_bin_dir: Option<String>,
}

fn read_bun_global_roots(
    config: &Path,
    home: &Path,
    excluded_root: Option<&Path>,
) -> Result<Vec<PathBuf>, LpmError> {
    let Some(content) = read_manager_config(config, home, excluded_root, "Bun")? else {
        return Ok(Vec::new());
    };
    let parsed = toml::from_str::<BunConfigFile>(&content).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not parse Bun configuration {}: {error}",
            config.display()
        ))
    })?;
    let Some(install) = parsed.install else {
        return Ok(Vec::new());
    };
    Ok([install.global_dir, install.global_bin_dir]
        .into_iter()
        .flatten()
        .filter_map(|value| configured_absolute_path(&value, home, excluded_root))
        .collect())
}

fn read_yarn_global_roots(
    config: &Path,
    home: &Path,
    excluded_root: Option<&Path>,
) -> Result<Vec<PathBuf>, LpmError> {
    let Some(content) = read_manager_config(config, home, excluded_root, "Yarn")? else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("--global-folder") {
            continue;
        }
        let fields = shlex::split(trimmed).ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "could not parse Yarn global-folder setting in {}",
                config.display()
            ))
        })?;
        let value = match fields.as_slice() {
            [flag, value] if flag == "--global-folder" => Some(value.as_str()),
            [setting] => setting.strip_prefix("--global-folder="),
            _ => None,
        }
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "invalid Yarn global-folder setting in {}",
                config.display()
            ))
        })?;
        if let Some(root) = configured_absolute_path(value, home, excluded_root) {
            roots.push(root);
        }
    }
    Ok(roots)
}

fn read_manager_config(
    config: &Path,
    home: &Path,
    excluded_root: Option<&Path>,
    manager: &str,
) -> Result<Option<String>, LpmError> {
    let metadata = match std::fs::symlink_metadata(config) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::SelfUpdate(format!(
                "could not inspect {manager} configuration {}: {error}",
                config.display()
            )));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !trusted_config_path(config, excluded_root, home)
        || !manager_config_path_is_private(config, home)
    {
        return Err(LpmError::SelfUpdate(format!(
            "{manager} configuration is not a real private file in the account home: {}",
            config.display()
        )));
    }
    let file = open_unfollowed_file(config).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not open {manager} configuration {} safely: {error}",
            config.display()
        ))
    })?;
    let opened_identity = same_file::Handle::from_file(file.try_clone().map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not bind opened {manager} configuration {}: {error}",
            config.display()
        ))
    })?)
    .map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not bind opened {manager} configuration {}: {error}",
            config.display()
        ))
    })?;
    if !path_matches_opened_identity(config, &opened_identity) {
        return Err(LpmError::SelfUpdate(format!(
            "{manager} configuration changed while it was being opened: {}",
            config.display()
        )));
    }
    let (content, opened_metadata) =
        lpm_common::read_text_file_capped_from_open_file(file, config, MANAGER_CONFIG_LIMIT)
            .map_err(|error| {
                LpmError::SelfUpdate(format!(
                    "could not read bounded {manager} configuration {}: {error}",
                    config.display()
                ))
            })?;
    if !opened_manager_config_is_private(&opened_metadata)
        || !manager_config_path_is_private(config, home)
        || !path_matches_opened_identity(config, &opened_identity)
    {
        return Err(LpmError::SelfUpdate(format!(
            "{manager} configuration is not a real private file in the account home: {}",
            config.display()
        )));
    }
    Ok(Some(content))
}

fn path_matches_opened_identity(path: &Path, opened: &same_file::Handle) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    same_file::Handle::from_path(path).is_ok_and(|current| &current == opened)
}

#[cfg(unix)]
fn open_unfollowed_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_unfollowed_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_unfollowed_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn manager_config_path_is_private(path: &Path, home: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        if metadata.file_type().is_symlink()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            return false;
        }
        if ancestor == home {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn manager_config_path_is_private(path: &Path, home: &Path) -> bool {
    windows_trust::path_is_private_to_account(path, home)
}

#[cfg(not(any(unix, windows)))]
fn manager_config_path_is_private(path: &Path, home: &Path) -> bool {
    path.starts_with(home)
}

#[cfg(unix)]
fn opened_manager_config_is_private(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    metadata.is_file()
        && metadata.uid() == effective_uid
        && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn opened_manager_config_is_private(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

fn configured_absolute_path(
    value: &str,
    home: &Path,
    excluded_root: Option<&Path>,
) -> Option<PathBuf> {
    let path = if value == "~" {
        home.to_path_buf()
    } else if let Some(relative) = value.strip_prefix("~/") {
        home.join(relative)
    } else {
        PathBuf::from(value)
    };
    (path.is_absolute()
        && path.parent().and_then(Path::parent).is_some()
        && resolve_for_containment(&path).is_ok()
        && excluded_root.is_none_or(|root| !path_resolves_within(&path, root).unwrap_or(true)))
    .then_some(path)
}

fn deduplicate_paths(paths: &mut Vec<PathBuf>) {
    paths.sort_unstable();
    paths.dedup();
}

fn paths_from_environment(
    names: &[&str],
    excluded_root: Option<&Path>,
    current_executable: &Path,
) -> Vec<PathBuf> {
    let Ok(current_executable) = resolve_for_containment(current_executable) else {
        return Vec::new();
    };
    let resolved_excluded_root = match excluded_root.map(resolve_for_containment).transpose() {
        Ok(root) => root,
        Err(()) => return Vec::new(),
    };
    names
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .filter(|path| path.parent().and_then(Path::parent).is_some())
        .filter(|path| {
            resolve_for_containment(path).is_ok_and(|path| {
                resolved_excluded_root
                    .as_ref()
                    .is_none_or(|root| !path.starts_with(root))
                    && current_executable.starts_with(path)
            })
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct ExternalUpdateCommand {
    program: &'static str,
    args: Vec<OsString>,
}

impl ExternalUpdateCommand {
    fn new(program: &'static str, args: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            program,
            args: args.into_iter().collect(),
        }
    }

    fn shell(&self) -> &'static str {
        if cfg!(windows) { "powershell" } else { "posix" }
    }

    #[cfg(test)]
    fn render(&self) -> Result<String, LpmError> {
        render_update_invocation(OsStr::new(self.program), &self.args)
    }
}

fn utf8_update_args(args: &[OsString]) -> Result<Vec<&str>, LpmError> {
    args.iter()
        .map(|argument| {
            argument.to_str().ok_or_else(|| {
                LpmError::SelfUpdate(
                    "cannot emit a runnable self-update plan containing a non-UTF-8 argument"
                        .to_string(),
                )
            })
        })
        .collect()
}

fn render_update_invocation(program: &OsStr, args: &[OsString]) -> Result<String, LpmError> {
    let program_utf8 = program.to_str().ok_or_else(|| {
        LpmError::SelfUpdate(
            "cannot emit a runnable self-update plan containing a non-UTF-8 program path"
                .to_string(),
        )
    })?;
    let args_utf8 = utf8_update_args(args)?;
    #[cfg(windows)]
    {
        Ok(render_powershell_invocation(program_utf8, &args_utf8))
    }
    #[cfg(not(windows))]
    {
        let args_len = args.iter().map(|arg| arg.len() + 3).sum::<usize>();
        let mut rendered = String::with_capacity(program_utf8.len() + args_len + 2);
        render_shell_argument(program, &mut rendered);
        for argument in args_utf8 {
            rendered.push(' ');
            render_shell_argument(OsStr::new(argument), &mut rendered);
        }
        Ok(rendered)
    }
}

#[cfg(any(windows, test))]
fn render_powershell_literal(value: &str, rendered: &mut String) {
    rendered.push('\'');
    rendered.push_str(&value.replace('\'', "''"));
    rendered.push('\'');
}

#[cfg(any(windows, test))]
fn render_powershell_invocation(program: &str, args: &[&str]) -> String {
    let args_len = args.iter().map(|arg| arg.len() + 3).sum::<usize>();
    let mut rendered = String::with_capacity(program.len() + args_len + 4);
    rendered.push_str("& ");
    render_powershell_literal(program, &mut rendered);
    for argument in args {
        rendered.push(' ');
        render_powershell_literal(argument, &mut rendered);
    }
    rendered
}

impl InstallMethod {
    fn name(&self) -> &'static str {
        match self {
            InstallMethod::Npm => "npm",
            InstallMethod::Pnpm => "pnpm",
            InstallMethod::Bun => "bun",
            InstallMethod::Yarn => "yarn",
            InstallMethod::Volta => "volta",
            InstallMethod::Homebrew => "homebrew",
            InstallMethod::Cargo => "cargo",
            InstallMethod::Standalone => "standalone",
        }
    }

    #[cfg(test)]
    fn command(
        &self,
        version: &str,
        cargo_source_commit: Option<&str>,
    ) -> Result<String, LpmError> {
        match self.external_update_command_with_root(version, cargo_source_commit, None)? {
            Some(command) => command.render(),
            None => Err(LpmError::SelfUpdate(
                "standalone self-update uses the built-in signed updater and has no equivalent shell command"
                    .to_string(),
            )),
        }
    }

    fn external_update_command_with_root(
        &self,
        version: &str,
        cargo_source_commit: Option<&str>,
        cargo_install_root: Option<&Path>,
    ) -> Result<Option<ExternalUpdateCommand>, LpmError> {
        let package = || format!("@lpm-registry/cli@{version}");
        Ok(Some(match self {
            InstallMethod::Npm => {
                ExternalUpdateCommand::new("npm", ["install".into(), "-g".into(), package().into()])
            }
            InstallMethod::Pnpm => ExternalUpdateCommand::new(
                "pnpm",
                ["add".into(), "--global".into(), package().into()],
            ),
            InstallMethod::Bun => ExternalUpdateCommand::new(
                "bun",
                ["add".into(), "--global".into(), package().into()],
            ),
            InstallMethod::Yarn => ExternalUpdateCommand::new(
                "yarn",
                ["global".into(), "add".into(), package().into()],
            ),
            InstallMethod::Volta => {
                ExternalUpdateCommand::new("volta", ["install".into(), package().into()])
            }
            InstallMethod::Homebrew => {
                ExternalUpdateCommand::new("brew", ["upgrade".into(), "lpm".into()])
            }
            InstallMethod::Cargo => {
                let source_commit = cargo_source_commit.ok_or_else(|| {
                    LpmError::SelfUpdate(
                        "Cargo update has no verified release source commit".to_string(),
                    )
                })?;
                ExternalUpdateCommand::new(
                    "cargo",
                    cargo_install_args(source_commit, cargo_install_root),
                )
            }
            InstallMethod::Standalone => return Ok(None),
        }))
    }

    fn ensure_channel_supported(&self, channel: ReleaseChannel) -> Result<(), LpmError> {
        if channel != ReleaseChannel::Nightly
            || self.is_registry_package_manager()
            || self == &InstallMethod::Standalone
        {
            return Ok(());
        }

        Err(LpmError::SelfUpdate(format!(
            "the nightly channel is not available through {} installs; use the npm or standalone installer",
            self.name()
        )))
    }

    fn is_registry_package_manager(&self) -> bool {
        matches!(
            self,
            InstallMethod::Npm
                | InstallMethod::Pnpm
                | InstallMethod::Bun
                | InstallMethod::Yarn
                | InstallMethod::Volta
        )
    }
}

#[cfg(unix)]
fn render_shell_argument(argument: &OsStr, rendered: &mut String) {
    use std::os::unix::ffi::OsStrExt;

    let bytes = argument.as_bytes();
    if !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(byte))
    {
        rendered.push_str(&String::from_utf8_lossy(bytes));
        return;
    }
    if std::str::from_utf8(bytes).is_err() {
        rendered.push_str("$'");
        for byte in bytes {
            if byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(byte) {
                rendered.push(char::from(*byte));
            } else if *byte == b'\'' {
                rendered.push_str("\\'");
            } else if *byte == b'\\' {
                rendered.push_str("\\\\");
            } else {
                use std::fmt::Write as _;
                let _ = write!(rendered, "\\x{byte:02x}");
            }
        }
        rendered.push('\'');
        return;
    }
    rendered.push('\'');
    for byte in bytes {
        if *byte == b'\'' {
            rendered.push_str("'\"'\"'");
        } else {
            rendered.push(char::from(*byte));
        }
    }
    rendered.push('\'');
}

#[cfg(not(any(unix, windows)))]
fn render_shell_argument(argument: &OsStr, rendered: &mut String) {
    rendered.push_str(&argument.to_string_lossy());
}

fn canonical_current_executable() -> Result<PathBuf, LpmError> {
    let executable = std::env::current_exe().map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve the running executable for self-update: {error}"
        ))
    })?;
    std::fs::canonicalize(&executable).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve the running executable for self-update: {error}"
        ))
    })
}

pub(crate) fn canonical_account_home() -> Result<PathBuf, LpmError> {
    let home = operating_system_home_dir().ok_or_else(|| {
        LpmError::SelfUpdate("could not resolve the operating-system account home".to_string())
    })?;
    std::fs::canonicalize(&home).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve the operating-system account home {}: {error}",
            home.display()
        ))
    })
}

#[cfg(test)]
pub(crate) fn acquire_self_update_lock(
    account_home: &Path,
) -> Result<lpm_common::SingleFileExclusiveLockHandle, LpmError> {
    let lock_file = open_self_update_operation_lock(account_home)?;
    lpm_common::acquire_single_file_exclusive_lock_from_file(lock_file)
}

pub(crate) fn try_acquire_self_update_lock(
    account_home: &Path,
) -> Result<Option<lpm_common::SingleFileExclusiveLockHandle>, LpmError> {
    let lock_file = open_self_update_operation_lock(account_home)?;
    lpm_common::try_acquire_single_file_exclusive_lock_from_file(lock_file)
}

fn open_self_update_operation_lock(account_home: &Path) -> Result<std::fs::File, LpmError> {
    let lpm_dir = account_home.join(".lpm");
    ensure_self_update_directory(&lpm_dir)?;
    let resolved_lpm_dir = std::fs::canonicalize(&lpm_dir)?;
    if resolved_lpm_dir.parent() != Some(account_home) {
        return Err(LpmError::SelfUpdate(format!(
            "LPM state directory escapes the account home: {}",
            lpm_dir.display()
        )));
    }

    let state_dir = resolved_lpm_dir.join("self-update");
    ensure_self_update_directory(&state_dir)?;
    let resolved_state = std::fs::canonicalize(&state_dir)?;
    if resolved_state.parent() != Some(resolved_lpm_dir.as_path()) {
        return Err(LpmError::SelfUpdate(format!(
            "self-update state path escapes the LPM state directory: {}",
            state_dir.display()
        )));
    }
    let lock_path = resolved_state.join("operation.lock");
    let lock_file = open_self_update_lock_file(&lock_path)?;
    #[cfg(windows)]
    {
        let opened_identity = same_file::Handle::from_file(lock_file.try_clone()?)?;
        if !windows_trust::path_is_private_to_account(&lock_path, account_home)
            || !path_matches_opened_identity(&lock_path, &opened_identity)
        {
            return Err(LpmError::SelfUpdate(
                "self-update operation lock is not a private account file".to_string(),
            ));
        }
    }
    Ok(lock_file)
}

fn ensure_self_update_directory(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(LpmError::SelfUpdate(format!(
                "self-update state path is not a real directory: {}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                if let Err(error) = builder.mode(0o700).create(path)
                    && error.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(error.into());
                }
            }
            #[cfg(not(unix))]
            if let Err(error) = std::fs::create_dir(path)
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(error.into());
            }
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LpmError::SelfUpdate(format!(
                    "self-update state path is not a real directory: {}",
                    path.display()
                )));
            }
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_self_update_lock_file(path: &Path) -> Result<std::fs::File, LpmError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(windows)]
fn open_self_update_lock_file(path: &Path) -> Result<std::fs::File, LpmError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    Ok(std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_self_update_lock_file(path: &Path) -> Result<std::fs::File, LpmError> {
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?)
}

fn active_project_root(
    working_dir: &Path,
    account_home: &Path,
) -> Result<Option<PathBuf>, LpmError> {
    let root = lpm_workspace::find_workspace_root(working_dir)
        .ok()
        .flatten()
        .or_else(|| lpm_workspace::find_project_root(working_dir));
    let root = if let Some(root) = root {
        Some(std::fs::canonicalize(&root).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not resolve active project root {}: {error}",
                root.display()
            ))
        })?)
    } else {
        None
    };
    Ok(project_root_distinct_from_home(root, Some(account_home)))
}

fn project_root_distinct_from_home(root: Option<PathBuf>, home: Option<&Path>) -> Option<PathBuf> {
    root.filter(|root| home != Some(root.as_path()))
}

fn environment_exclusion_root(
    working_dir: &Path,
    project_root: &Option<PathBuf>,
    account_home: &Path,
) -> Result<Option<PathBuf>, LpmError> {
    if project_root.is_some() {
        return Ok(project_root.clone());
    }
    let working_dir = std::fs::canonicalize(working_dir).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve active working directory {}: {error}",
            working_dir.display()
        ))
    })?;
    Ok(fallback_containment_root(working_dir, Some(account_home)))
}

fn fallback_containment_root(working_dir: PathBuf, home: Option<&Path>) -> Option<PathBuf> {
    (home != Some(working_dir.as_path())).then_some(working_dir)
}

#[cfg(test)]
fn detect_install_method() -> Result<InstallMethod, LpmError> {
    let exe = std::env::current_exe().ok();
    // Resolve symlinks so `/usr/local/bin/lpm → ~/.volta/bin/lpm` (or
    // any version-manager shim) classifies as the underlying channel,
    // not Standalone. `canonicalize` can fail on Windows for some
    // symlink targets — fall back to the raw path so detection still
    // works on the common case where the exe IS the canonical binary.
    let resolved = exe
        .as_ref()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .or(exe);
    detect_install_method_from_path_with_roots(resolved.as_deref(), &InstallRoots::default())
}

/// Pure helper for [`detect_install_method`]. Split out so the
/// per-shim classification can be unit-tested with synthetic paths
/// without depending on whatever package manager happens to own the
/// running binary.
#[cfg(test)]
fn detect_install_method_from_path(exe: Option<&Path>) -> InstallMethod {
    detect_install_method_from_path_with_roots(exe, &InstallRoots::default()).unwrap()
}

fn detect_install_method_from_path_with_roots(
    exe: Option<&Path>,
    roots: &InstallRoots,
) -> Result<InstallMethod, LpmError> {
    let Some(path) = exe else {
        return Ok(InstallMethod::Standalone);
    };
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let has = |name: &str| {
        components
            .iter()
            .any(|component| component.eq_ignore_ascii_case(name))
    };
    if has_component_sequence(&components, &["Cellar", "lpm"]) {
        return Ok(InstallMethod::Homebrew);
    }
    match cargo_install_ownership(path) {
        CargoInstallOwnership::Owned => return Ok(InstallMethod::Cargo),
        CargoInstallOwnership::Invalid(error) => {
            return Err(LpmError::SelfUpdate(format!(
                "invalid Cargo install metadata for {}: {error}",
                path.display()
            )));
        }
        CargoInstallOwnership::NotOwned => {
            return Err(LpmError::SelfUpdate(format!(
                "Cargo install metadata exists but does not claim the active LPM executable {}; refusing destructive standalone replacement",
                path.display()
            )));
        }
        CargoInstallOwnership::Absent => {
            if has_component_sequence(&components, &[".cargo", "bin"])
                || path_is_under_any_root(path, &roots.cargo)
            {
                return Err(LpmError::SelfUpdate(format!(
                    "cannot verify ownership of Cargo-shaped LPM executable {}; refusing destructive standalone replacement",
                    path.display()
                )));
            }
        }
    }
    let has_manager_roots = [
        &roots.volta,
        &roots.pnpm,
        &roots.bun,
        &roots.yarn,
        &roots.npm,
    ]
    .into_iter()
    .any(|roots| !roots.is_empty());
    let resolved_path = has_manager_roots
        .then(|| resolve_for_containment(path))
        .and_then(Result::ok);
    let is_under_any_root = |roots: &[PathBuf]| {
        resolved_path
            .as_deref()
            .is_some_and(|path| path_is_under_any_resolved_root(path, roots))
    };
    if is_under_any_root(&roots.volta)
        || has_component_sequence(&components, &[".volta", "tools", "image", "packages"])
        || has_component_sequence(&components, &["volta", "tools", "image", "packages"])
    {
        return Ok(InstallMethod::Volta);
    }
    if is_under_any_root(&roots.pnpm)
        || (has(".pnpm") && has("node_modules"))
        || has_component_sequence(&components, &["pnpm", "global"])
    {
        return Ok(InstallMethod::Pnpm);
    }
    if is_under_any_root(&roots.bun)
        || has_component_sequence(&components, &[".bun", "install", "global"])
    {
        return Ok(InstallMethod::Bun);
    }
    if is_under_any_root(&roots.yarn)
        || has_component_sequence(&components, &[".config", "yarn", "global"])
        || has_component_sequence(&components, &[".yarn", "global"])
    {
        return Ok(InstallMethod::Yarn);
    }
    if is_under_any_root(&roots.npm) || is_npm_managed(&components) {
        return Ok(InstallMethod::Npm);
    }
    if has(".pnpm-store") || has_component_sequence(&components, &["pnpm", "store"]) {
        return Err(LpmError::SelfUpdate(format!(
            "active LPM executable {} is inside a pnpm store, not a global install target; refusing destructive standalone replacement",
            path.display()
        )));
    }
    if has("node_modules") {
        let config_errors = roots
            .bun_config_errors
            .iter()
            .chain(&roots.yarn_config_errors)
            .cloned()
            .collect::<Vec<_>>();
        if !config_errors.is_empty() {
            return Err(LpmError::SelfUpdate(format!(
                "cannot determine which package manager owns the active LPM executable {} because manager configuration is invalid: {}",
                path.display(),
                config_errors.join("; ")
            )));
        }
        return Err(LpmError::SelfUpdate(format!(
            "cannot determine which package manager owns the active LPM executable {}; configure the global package-manager prefix or reinstall LPM globally",
            path.display()
        )));
    }
    Ok(InstallMethod::Standalone)
}

fn has_component_sequence(components: &[&str], expected: &[&str]) -> bool {
    components.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
    })
}

fn path_is_under_any_resolved_root(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| resolve_for_containment(root).is_ok_and(|root| path.starts_with(root)))
}

fn path_is_under_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    if roots.is_empty() {
        return false;
    }
    resolve_for_containment(path).is_ok_and(|path| path_is_under_any_resolved_root(&path, roots))
}

fn path_resolves_within(candidate: &Path, root: &Path) -> Result<bool, ()> {
    Ok(resolve_for_containment(candidate)?.starts_with(resolve_for_containment(root)?))
}

fn resolve_for_containment(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(());
    }
    let mut unresolved = Vec::<OsString>::new();
    let mut ancestor = path;
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(ancestor) {
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        unresolved.push(ancestor.file_name().ok_or(())?.to_owned());
        ancestor = ancestor.parent().ok_or(())?;
    }
}

enum CargoInstallOwnership {
    Owned,
    NotOwned,
    Absent,
    Invalid(String),
}

enum CargoMetadataOwnership {
    Owned,
    NotOwned,
    Absent,
    Invalid(String),
}

fn cargo_install_ownership(executable: &Path) -> CargoInstallOwnership {
    let Some(bin_dir) = executable.parent() else {
        return CargoInstallOwnership::Absent;
    };
    let is_bin_dir = bin_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"));
    if !is_bin_dir {
        return CargoInstallOwnership::Absent;
    }

    let Some(root) = bin_dir.parent() else {
        return CargoInstallOwnership::Absent;
    };
    match cargo_metadata_ownership(root, executable) {
        CargoMetadataOwnership::Owned => CargoInstallOwnership::Owned,
        CargoMetadataOwnership::NotOwned => CargoInstallOwnership::NotOwned,
        CargoMetadataOwnership::Absent => CargoInstallOwnership::Absent,
        CargoMetadataOwnership::Invalid(error) => CargoInstallOwnership::Invalid(error),
    }
}

const CARGO_INSTALL_METADATA_LIMIT: u64 = 4 * 1024 * 1024;

fn cargo_metadata_ownership(root: &Path, executable: &Path) -> CargoMetadataOwnership {
    let Some(binary_name) = executable.file_stem().and_then(OsStr::to_str) else {
        return CargoMetadataOwnership::NotOwned;
    };
    let modern_path = root.join(".crates2.json");
    match read_cargo_metadata(&modern_path) {
        Ok(Some(content)) => {
            let owned = match cargo_metadata::modern_claims_binary(&content, binary_name) {
                Ok(owned) => owned,
                Err(error) => return CargoMetadataOwnership::Invalid(error),
            };
            return if owned {
                CargoMetadataOwnership::Owned
            } else {
                CargoMetadataOwnership::NotOwned
            };
        }
        Ok(None) => {}
        Err(error) => return CargoMetadataOwnership::Invalid(error),
    }

    let legacy_path = root.join(".crates.toml");
    match read_cargo_metadata(&legacy_path) {
        Ok(Some(content)) => {
            let owned = match cargo_metadata::legacy_claims_binary(&content, binary_name) {
                Ok(owned) => owned,
                Err(error) => return CargoMetadataOwnership::Invalid(error),
            };
            if owned {
                CargoMetadataOwnership::Owned
            } else {
                CargoMetadataOwnership::NotOwned
            }
        }
        Ok(None) => CargoMetadataOwnership::Absent,
        Err(error) => CargoMetadataOwnership::Invalid(error),
    }
}

fn read_cargo_metadata(path: &Path) -> Result<Option<String>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !cargo_metadata_path_is_trusted(path)
    {
        return Err(format!(
            "Cargo install metadata is not a real trusted file: {}",
            path.display()
        ));
    }
    let file = open_unfollowed_file(path)
        .map_err(|error| format!("could not open {} safely: {error}", path.display()))?;
    let opened_identity = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|error| format!("could not bind {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("could not bind {}: {error}", path.display()))?;
    if !path_matches_opened_identity(path, &opened_identity) {
        return Err(format!(
            "Cargo install metadata changed while it was being opened: {}",
            path.display()
        ));
    }
    let (content, opened_metadata) =
        lpm_common::read_text_file_capped_from_open_file(file, path, CARGO_INSTALL_METADATA_LIMIT)
            .map_err(|error| error.to_string())?;
    if !opened_cargo_metadata_is_trusted(&opened_metadata)
        || !cargo_metadata_path_is_trusted(path)
        || !path_matches_opened_identity(path, &opened_identity)
    {
        return Err(format!(
            "Cargo install metadata is not a stable trusted file: {}",
            path.display()
        ));
    }
    Ok(Some(content))
}

#[cfg(unix)]
fn cargo_metadata_path_is_trusted(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    path.ancestors().all(|ancestor| {
        std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
            let owner = metadata.uid();
            !metadata.file_type().is_symlink()
                && (owner == 0 || owner == effective_uid)
                && metadata.permissions().mode() & 0o022 == 0
        })
    })
}

#[cfg(windows)]
fn cargo_metadata_path_is_trusted(path: &Path) -> bool {
    canonical_account_home().is_ok_and(|home| {
        windows_trust::path_is_trusted_install_location(path, &home)
            || windows_trust::path_has_trusted_dacl_to_root(path)
    })
}

#[cfg(not(any(unix, windows)))]
fn cargo_metadata_path_is_trusted(path: &Path) -> bool {
    path.ancestors().all(|ancestor| {
        std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| !metadata.file_type().is_symlink())
    })
}

#[cfg(unix)]
fn opened_cargo_metadata_is_trusted(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let owner = metadata.uid();
    metadata.is_file()
        && (owner == 0 || owner == effective_uid)
        && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn opened_cargo_metadata_is_trusted(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

/// Path-component (not substring) match against npm-ecosystem install
/// roots. The previous substring-based check matched any path with
/// `"npm"` anywhere in it (e.g. `/Users/npmtest/...` false-positived as
/// npm-installed) and missed Volta / fnm / asdf / pnpm-global entirely.
fn is_npm_managed(components: &[&str]) -> bool {
    let has = |name: &str| {
        components
            .iter()
            .any(|component| component.eq_ignore_ascii_case(name))
    };

    if has_component_sequence(components, &["lib", "node_modules"])
        || has_component_sequence(components, &["npm", "node_modules"])
    {
        return true;
    }

    // Version manager and alternative install roots. Component-level
    // exact match avoids the substring trap.
    const SHIMS: &[&str] = &[
        ".npm",  // npm cache root (`~/.npm`)
        ".nvm",  // nvm install root (`~/.nvm`)
        ".fnm",  // fnm install root (`~/.fnm`)
        ".asdf", // asdf install root (`~/.asdf`)
        ".n",    // `n` install root with custom `N_PREFIX=~/.n`
        "nvm",   // nvm shared-install variants
        "fnm",   // fnm shared-install variants
        "asdf",  // asdf shared-install variants
    ];
    if SHIMS.iter().any(|s| has(s)) {
        return true;
    }

    // The `n` version manager's default install layout has BOTH `n`
    // and `versions` as path components — e.g.
    // `/usr/local/n/versions/node/20.0.0/bin/lpm` (system) or
    // `~/n/versions/node/20.0.0/bin/lpm` (default `N_PREFIX=$HOME`).
    // Bare `n` alone would be too aggressive (matches any folder
    // literally named `n`); requiring `versions` as well anchors the
    // match to n's actual directory shape.
    if has("n") && has("versions") {
        return true;
    }

    false
}

fn cargo_install_root(executable: &Path) -> Result<PathBuf, LpmError> {
    cargo_install_root_from_executable(executable).ok_or_else(|| {
        LpmError::SelfUpdate(format!(
            "Cargo-managed executable is not under an install-root bin directory: {}",
            executable.display()
        ))
    })
}

fn cargo_install_root_from_executable(executable: &Path) -> Option<PathBuf> {
    let bin_dir = executable.parent()?;
    let is_bin_dir = bin_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"));
    is_bin_dir
        .then(|| bin_dir.parent().map(Path::to_path_buf))
        .flatten()
}

fn cargo_install_args(source_commit: &str, install_root: Option<&Path>) -> Vec<OsString> {
    let mut args = vec![
        "install".into(),
        "--git".into(),
        "https://github.com/lpm-dev/rust-client".into(),
        "--rev".into(),
        source_commit.into(),
    ];
    if let Some(root) = install_root {
        args.push("--root".into());
        args.push(root.as_os_str().to_owned());
    }
    args.extend(["lpm-cli".into(), "--force".into(), "--locked".into()]);
    args
}

/// `SHA256SUMS.txt` size cap (4 KiB). The real manifest is ~600 B
/// today (six lines of `<sha>  <name>`); 4 KiB leaves comfortable
/// headroom for future binaries without giving a hostile server an
/// unbounded body.
const MANIFEST_MAX_BYTES: usize = 4 * 1024;

/// `SHA256SUMS.txt.sigstore` size cap (1 MiB). Real bundles are
/// ~12 KiB but the protocol allows for embedded inclusion proofs that
/// can grow; mirror the `SIGSTORE_RESPONSE_CAP_BYTES` used elsewhere.
const BUNDLE_MAX_BYTES: usize = 1024 * 1024;

/// Per-asset download cap (256 MiB). Today's largest published binary
/// is ~30 MiB; the cap is set well above realistic growth so the
/// guard only trips on a hostile server streaming junk.
const ASSET_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Replay-window: bundle `integratedTime` must lie within
/// `[published_at - PRE_WINDOW, published_at + POST_WINDOW]`. The
/// 1-hour pre-window absorbs the GitHub Actions run minting the
/// attestation before the Release object is finalized; the 24-hour
/// post-window allows for late asset publication / re-uploads.
const REPLAY_PRE_WINDOW: chrono::Duration = chrono::Duration::hours(1);
const REPLAY_POST_WINDOW: chrono::Duration = chrono::Duration::hours(24);

/// Captured trail of attestation metadata, surfaced into the
/// `--json` self-update output so audit pipelines can pin which
/// release identity actually authorised the binary swap.
#[derive(Debug, Clone)]
struct AttestationAudit {
    publisher: Option<String>,
    workflow_path: Option<String>,
    workflow_ref: Option<String>,
    integrated_time: chrono::DateTime<chrono::Utc>,
    log_index: i64,
    log_id: String,
    leaf_cert_sha256: String,
    manifest_sha256: String,
    asset_sha256: String,
    asset_name: String,
    source_commit: String,
}

/// Map a `VerifyError` into the user-facing `LpmError::SelfUpdate`
/// shape. The verifier error's `Display` already names the failing
/// primitive (DSSE / chain / SET / SCT / Rekor body / inclusion proof
/// / identity) so the wrapping prefix names the surface for the user.
fn map_verify_error(e: VerifyError) -> LpmError {
    LpmError::SelfUpdate(format!(
        "Sigstore verification of release manifest failed: {e}"
    ))
}

/// Parse a single line of a `sha256sum`-style manifest.
///
/// Lines must match `^([0-9a-f]{64})  (.+)$` — two ASCII spaces
/// separate the hex digest from the file name (the GNU coreutils
/// default; `shasum -a 256` produces the same shape). Anything else
/// returns `None` so callers can choose to reject the manifest
/// entirely rather than silently drop the malformed entry.
fn parse_manifest_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_end_matches('\r');
    let (sha_part, name_part) = line.split_once("  ")?;
    if sha_part.len() != 64 || !sha_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let sha = sha_part.to_ascii_lowercase();
    let name = name_part.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((sha, name))
}

/// Look up the expected SHA-256 for a given filename in a parsed
/// `SHA256SUMS.txt` body. Skips blank lines and rejects lines that
/// fail [`parse_manifest_line`] — a malformed manifest is an integrity
/// failure, not a silent miss.
fn parse_release_manifest(manifest: &str) -> Result<HashMap<String, String>, LpmError> {
    let mut entries = HashMap::with_capacity(manifest.lines().count());
    for (idx, raw_line) in manifest.lines().enumerate() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let (sha, name) = parse_manifest_line(raw_line).ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "SHA256SUMS.txt line {} is malformed (expected `<64-hex-sha>  <filename>`); \
                 refusing to install from a manifest we cannot fully parse",
                idx + 1
            ))
        })?;
        if entries.insert(name.clone(), sha).is_some() {
            return Err(LpmError::SelfUpdate(format!(
                "SHA256SUMS.txt enumerates `{name}` more than once — refusing an ambiguous release manifest"
            )));
        }
    }
    Ok(entries)
}

#[cfg(test)]
fn lookup_platform_sha(manifest: &str, basename: &str) -> Result<String, LpmError> {
    parse_release_manifest(manifest)?
        .remove(basename)
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "SHA256SUMS.txt does not enumerate `{basename}` for this platform — release pipeline may be missing artifacts"
            ))
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_release_provenance(
    version: &str,
    snapshot: &lpm_workspace::ProvenanceSnapshot,
    statement: &serde_json::Value,
) -> Result<String, LpmError> {
    const REPOSITORY: &str = "https://github.com/lpm-dev/rust-client";
    const PUBLISHER: &str = "github:lpm-dev/rust-client";
    const WORKFLOW_PATH: &str = ".github/workflows/release.yml";

    let channel = ReleaseChannel::from_installed_version(version);
    let expected_ref = match channel {
        ReleaseChannel::Stable => format!("refs/tags/v{version}"),
        ReleaseChannel::Nightly => "refs/heads/main".to_string(),
    };
    let invalid = |detail: String| {
        LpmError::SelfUpdate(format!(
            "release v{version} has invalid signed provenance: {detail}"
        ))
    };

    if !snapshot.present
        || snapshot.publisher.as_deref() != Some(PUBLISHER)
        || snapshot.workflow_path.as_deref() != Some(WORKFLOW_PATH)
        || snapshot.workflow_ref.as_deref() != Some(expected_ref.as_str())
    {
        return Err(invalid(format!(
            "certificate identity must be `{PUBLISHER}` workflow `{WORKFLOW_PATH}` at `{expected_ref}`"
        )));
    }

    let required_str = |pointer: &str, field: &str| {
        statement
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid(format!("missing string `{field}`")))
    };
    if required_str("/_type", "_type")? != "https://in-toto.io/Statement/v1" {
        return Err(invalid("unexpected in-toto statement type".to_string()));
    }
    if required_str("/predicateType", "predicateType")? != "https://slsa.dev/provenance/v1" {
        return Err(invalid("unexpected SLSA predicate type".to_string()));
    }

    let workflow = "/predicate/buildDefinition/externalParameters/workflow";
    if required_str(&format!("{workflow}/repository"), "workflow.repository")? != REPOSITORY
        || required_str(&format!("{workflow}/path"), "workflow.path")? != WORKFLOW_PATH
        || required_str(&format!("{workflow}/ref"), "workflow.ref")? != expected_ref
    {
        return Err(invalid(format!(
            "workflow identity must be `{REPOSITORY}/{WORKFLOW_PATH}@{expected_ref}`"
        )));
    }

    let expected_uri = format!("git+{REPOSITORY}@{expected_ref}");
    let dependencies = statement
        .pointer("/predicate/buildDefinition/resolvedDependencies")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("missing `resolvedDependencies` array".to_string()))?;
    let mut source_commit = None;
    for dependency in dependencies {
        if dependency.get("uri").and_then(serde_json::Value::as_str) != Some(&expected_uri) {
            continue;
        }
        let commit = dependency
            .pointer("/digest/gitCommit")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("source dependency has no `digest.gitCommit`".to_string()))?;
        if source_commit.replace(commit).is_some() {
            return Err(invalid(format!(
                "source dependency `{expected_uri}` appears more than once"
            )));
        }
    }
    let source_commit = source_commit
        .ok_or_else(|| invalid(format!("missing source dependency `{expected_uri}`")))?;
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "source commit must be a 40-character lowercase hexadecimal Git object ID".to_string(),
        ));
    }

    if channel == ReleaseChannel::Nightly {
        let version_commit = version
            .rsplit_once('.')
            .map(|(_, suffix)| suffix.strip_prefix('g').unwrap_or(suffix))
            .ok_or_else(|| invalid("nightly version has no commit suffix".to_string()))?;
        if version_commit.len() != 7 || !source_commit.starts_with(version_commit) {
            return Err(invalid(format!(
                "nightly commit suffix `{version_commit}` does not match signed source commit `{source_commit}`"
            )));
        }
    }

    Ok(source_commit.to_string())
}

#[derive(Debug)]
struct VerifiedReleaseManifest {
    publisher: Option<String>,
    workflow_path: Option<String>,
    workflow_ref: Option<String>,
    integrated_time: chrono::DateTime<chrono::Utc>,
    log_index: i64,
    log_id: String,
    leaf_cert_sha256: String,
    manifest_sha256: String,
    source_commit: String,
    entries: HashMap<String, String>,
}

fn verify_release_manifest(
    version: &str,
    manifest_bytes: &[u8],
    bundle_bytes: &[u8],
    published_at: chrono::DateTime<chrono::Utc>,
) -> Result<VerifiedReleaseManifest, LpmError> {
    let expectations = IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".to_string()),
        expected_workflow_path: Some(".github/workflows/release.yml".to_string()),
    };
    let options = VerifyOptions::strict();

    let VerifiedProvenance {
        snapshot,
        statement,
        integrated_time,
        leaf_cert_sha256,
        log_id,
        log_index,
    } = verify_sigstore_bundle(bundle_bytes, &expectations, options).map_err(map_verify_error)?;

    let source_commit = validate_release_provenance(version, &snapshot, &statement)?;

    let integrated_time_utc: chrono::DateTime<chrono::Utc> = integrated_time.into();
    let earliest = published_at - REPLAY_PRE_WINDOW;
    let latest = published_at + REPLAY_POST_WINDOW;
    if integrated_time_utc < earliest || integrated_time_utc > latest {
        return Err(LpmError::SelfUpdate(format!(
            "Sigstore bundle integratedTime ({integrated_time_utc}) is outside the replay window \
             [{earliest}, {latest}] for release v{version} (published_at = {published_at}). \
             The bundle may be a replayed attestation from a different release."
        )));
    }

    let (subject_name, subject_sha256) =
        extract_subject_digest_from_statement(&statement, "sha256", true)
            .map_err(map_verify_error)?;
    if subject_name != "SHA256SUMS.txt" {
        return Err(LpmError::SelfUpdate(format!(
            "Sigstore bundle attests unexpected subject `{subject_name}` instead of `SHA256SUMS.txt`"
        )));
    }
    let manifest_sha256 = sha256_hex(manifest_bytes);
    if subject_sha256 != manifest_sha256 {
        return Err(LpmError::SelfUpdate(format!(
            "Sigstore bundle subject digest does not match SHA256SUMS.txt: bundle attests \
             sha256={subject_sha256} (subject `{subject_name}`), downloaded manifest \
             sha256={manifest_sha256}. The manifest may be tampered."
        )));
    }

    let manifest_text = std::str::from_utf8(manifest_bytes).map_err(|e| {
        LpmError::SelfUpdate(format!(
            "SHA256SUMS.txt is not valid UTF-8 — refusing to parse: {e}"
        ))
    })?;
    let entries = parse_release_manifest(manifest_text)?;

    Ok(VerifiedReleaseManifest {
        publisher: snapshot.publisher,
        workflow_path: snapshot.workflow_path,
        workflow_ref: snapshot.workflow_ref,
        integrated_time: integrated_time_utc,
        log_index,
        log_id,
        leaf_cert_sha256,
        manifest_sha256,
        source_commit,
        entries,
    })
}

fn verify_release_asset_digest(
    release: &VerifiedReleaseManifest,
    actual_asset_sha: String,
    asset_basename: &str,
) -> Result<AttestationAudit, LpmError> {
    let expected_asset_sha = release.entries.get(asset_basename).ok_or_else(|| {
        LpmError::SelfUpdate(format!(
            "SHA256SUMS.txt does not enumerate `{asset_basename}` for this platform — release pipeline may be missing artifacts"
        ))
    })?;
    if &actual_asset_sha != expected_asset_sha {
        return Err(LpmError::SelfUpdate(format!(
            "downloaded `{asset_basename}` SHA-256 mismatch: signed manifest declares \
             {expected_asset_sha}, actual download is {actual_asset_sha}. \
             Refusing to replace the running binary."
        )));
    }

    Ok(AttestationAudit {
        publisher: release.publisher.clone(),
        workflow_path: release.workflow_path.clone(),
        workflow_ref: release.workflow_ref.clone(),
        integrated_time: release.integrated_time,
        log_index: release.log_index,
        log_id: release.log_id.clone(),
        leaf_cert_sha256: release.leaf_cert_sha256.clone(),
        manifest_sha256: release.manifest_sha256.clone(),
        asset_sha256: actual_asset_sha,
        asset_name: asset_basename.to_string(),
        source_commit: release.source_commit.clone(),
    })
}

/// Download and replace the binary in-place for standalone installations.
///
/// Every fetched byte is anchored to the Sigstore-signed `SHA256SUMS.txt`
/// manifest: the bundle's identity must match `lpm-dev/rust-client`'s
/// release workflow, its `integratedTime` must lie inside a sane window
/// around the GitHub Release `published_at`, the manifest's own hash
/// must match the bundle's in-toto subject digest, and the downloaded
/// binary's hash must match the manifest line for this platform. Any
/// failure short-circuits before `install_staged_binary` is reached.
///
/// Returns the captured attestation audit so the caller can surface it
/// into `--json` output (or wherever else a structured audit trail
/// belongs). The audit is also logged via `tracing::info!`.
async fn run_standalone_update(
    version: &str,
    current_executable: &Path,
    account_home: &Path,
    human_output: bool,
) -> Result<AttestationAudit, LpmError> {
    validate_standalone_install_location(current_executable)?;
    #[cfg(not(target_os = "macos"))]
    let _ = account_home;
    #[cfg(target_os = "macos")]
    let macos_layout = prepare_macos_standalone_layout(current_executable, account_home)?;
    #[cfg(target_os = "macos")]
    let staging_anchor = macos_layout.app_parent.join(".lpm-release-asset.zip");
    #[cfg(not(target_os = "macos"))]
    let staging_anchor = current_executable.to_path_buf();

    let assets = verify_and_stage_for_standalone(version, &staging_anchor, human_output).await?;

    #[cfg(target_os = "macos")]
    {
        ensure_staged_file_unchanged(
            &assets.staged_binary.temporary,
            &assets.staged_binary.sha256,
        )?;
        let staged_bundle = stage_macos_bundle(
            assets.staged_binary.temporary.path(),
            &macos_layout.app_parent,
        )?;
        VersionProbe::verify_staged_path(&staged_bundle.executable, version)?;
        install_staged_macos_bundle(&macos_layout, staged_bundle, version)?;
    }

    #[cfg(not(target_os = "macos"))]
    {
        VersionProbe::verify_staged(
            &assets.staged_binary.temporary,
            &assets.staged_binary.sha256,
            version,
        )?;
        ensure_staged_file_unchanged(
            &assets.staged_binary.temporary,
            &assets.staged_binary.sha256,
        )?;
        let StagedAsset {
            temporary, sha256, ..
        } = assets.staged_binary;
        install_staged_binary(current_executable, temporary, &sha256)?;
    }

    tracing::info!(
        target: "lpm_cli::self_update",
        publisher = assets.audit.publisher.as_deref().unwrap_or("<absent>"),
        workflow_path = assets.audit.workflow_path.as_deref().unwrap_or("<absent>"),
        workflow_ref = assets.audit.workflow_ref.as_deref().unwrap_or("<absent>"),
        integrated_time = %assets.audit.integrated_time,
        log_index = assets.audit.log_index,
        log_id = %assets.audit.log_id,
        leaf_cert_sha256 = %assets.audit.leaf_cert_sha256,
        manifest_sha256 = %assets.audit.manifest_sha256,
        asset_sha256 = %assets.audit.asset_sha256,
        asset_name = %assets.audit.asset_name,
        source_commit = %assets.audit.source_commit,
        "standalone self-update verified and applied"
    );
    Ok(assets.audit)
}

/// Render an `AttestationAudit` as the JSON shape callers see under
/// `--json` mode. Stable wire shape — adding new fields is fine, but
/// renaming or removing keys is a contract break.
fn audit_json(audit: &AttestationAudit) -> serde_json::Value {
    serde_json::json!({
        "publisher": audit.publisher,
        "workflow_path": audit.workflow_path,
        "workflow_ref": audit.workflow_ref,
        "integrated_time": audit.integrated_time.to_rfc3339(),
        "log_index": audit.log_index,
        "log_id": audit.log_id,
        "leaf_cert_sha256": audit.leaf_cert_sha256,
        "manifest_sha256": audit.manifest_sha256,
        "asset_sha256": audit.asset_sha256,
        "asset_name": audit.asset_name,
        "source_commit": audit.source_commit,
    })
}

#[derive(Debug)]
struct StandaloneAssets {
    staged_binary: StagedAsset,
    audit: AttestationAudit,
}

#[cfg(any(target_os = "macos", test))]
const MACOS_APP_NAME: &str = "LPM CLI.app";
#[cfg(any(target_os = "macos", test))]
const MACOS_INTERNAL_EXECUTABLE: &str = "Contents/MacOS/lpm-rs";
#[cfg(any(target_os = "macos", test))]
const MACOS_BUNDLE_MAX_ENTRIES: usize = 64;
#[cfg(any(target_os = "macos", test))]
const MACOS_BUNDLE_MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(any(target_os = "macos", test))]
const MACOS_BUNDLE_MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MACOS_EXPECTED_TEAM_ID: &str = "823S8YKMRW";
#[cfg(target_os = "macos")]
const MACOS_EXPECTED_BUNDLE_ID: &str = "dev.lpm.cli";
#[cfg(target_os = "macos")]
const MACOS_EXPECTED_ACCESS_GROUP: &str = "823S8YKMRW.dev.lpm.vault.shared";
#[cfg(target_os = "macos")]
const MACOS_EXPECTED_PROFILE_ACCESS_GROUP: &str = "823S8YKMRW.*";
#[cfg(any(target_os = "macos", test))]
const MACOS_REQUIRED_BUNDLE_FILES: [&str; 6] = [
    "LPM CLI.app/Contents/Info.plist",
    "LPM CLI.app/Contents/CodeResources",
    "LPM CLI.app/Contents/embedded.provisionprofile",
    "LPM CLI.app/Contents/MacOS/lpm-rs",
    "LPM CLI.app/Contents/Resources/LPMCLI.icns",
    "LPM CLI.app/Contents/_CodeSignature/CodeResources",
];
#[cfg(any(target_os = "macos", test))]
const MACOS_ALLOWED_BUNDLE_DIRECTORIES: [&str; 5] = [
    "LPM CLI.app",
    "LPM CLI.app/Contents",
    "LPM CLI.app/Contents/MacOS",
    "LPM CLI.app/Contents/Resources",
    "LPM CLI.app/Contents/_CodeSignature",
];

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MacOSStandaloneLayout {
    app_parent: PathBuf,
    app_bundle: PathBuf,
    lpm_link: PathBuf,
    lpx_link: PathBuf,
}

#[cfg(any(target_os = "macos", test))]
fn macos_standalone_layout_for(
    current_executable: &Path,
    account_home: &Path,
) -> Result<MacOSStandaloneLayout, LpmError> {
    if !current_executable.is_absolute() || !account_home.is_absolute() {
        return Err(LpmError::SelfUpdate(
            "macOS standalone installation paths must be absolute".to_string(),
        ));
    }
    let install_root = account_home.join(".lpm");
    let app_parent = install_root.join("libexec");
    let app_bundle = app_parent.join(MACOS_APP_NAME);
    let lpm_link = install_root.join("bin/lpm");
    let lpx_link = install_root.join("bin/lpx");
    let internal_executable = app_bundle.join(MACOS_INTERNAL_EXECUTABLE);
    if current_executable != internal_executable {
        return Err(LpmError::SelfUpdate(format!(
            "macOS standalone updates require execution from {}; reinstall with https://github.com/lpm-dev/rust-client/blob/main/install.sh",
            internal_executable.display()
        )));
    }
    Ok(MacOSStandaloneLayout {
        app_parent,
        app_bundle,
        lpm_link,
        lpx_link,
    })
}

#[cfg(target_os = "macos")]
fn prepare_macos_standalone_layout(
    current_executable: &Path,
    account_home: &Path,
) -> Result<MacOSStandaloneLayout, LpmError> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    let layout = macos_standalone_layout_for(current_executable, account_home)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&layout.app_parent) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LpmError::SelfUpdate(format!(
                "macOS bundle parent is not a real directory: {}",
                layout.app_parent.display()
            )));
        }
    } else {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(false).mode(0o755);
        builder.create(&layout.app_parent).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not create macOS bundle parent {}: {error}",
                layout.app_parent.display()
            ))
        })?;
    }
    let metadata = std::fs::symlink_metadata(&layout.app_parent).map_err(LpmError::Io)?;
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(LpmError::SelfUpdate(format!(
            "macOS bundle parent is not private to the current account: {}",
            layout.app_parent.display()
        )));
    }
    Ok(layout)
}

#[cfg(any(target_os = "macos", test))]
fn validate_macos_bundle_zip(archive_path: &Path) -> Result<(), LpmError> {
    let archive_file = std::fs::File::open(archive_path).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not open staged macOS app archive {}: {error}",
            archive_path.display()
        ))
    })?;
    let mut archive = zip::ZipArchive::new(archive_file).map_err(|error| {
        LpmError::SelfUpdate(format!("could not parse staged macOS app archive: {error}"))
    })?;
    if archive.is_empty() || archive.len() > MACOS_BUNDLE_MAX_ENTRIES {
        return Err(LpmError::SelfUpdate(format!(
            "macOS app archive entry count {} is outside the allowed range 1..={MACOS_BUNDLE_MAX_ENTRIES}",
            archive.len()
        )));
    }

    let required = MACOS_REQUIRED_BUNDLE_FILES
        .into_iter()
        .collect::<HashSet<_>>();
    let allowed_directories = MACOS_ALLOWED_BUNDLE_DIRECTORIES
        .into_iter()
        .collect::<HashSet<_>>();
    let mut seen = HashSet::with_capacity(archive.len());
    let mut seen_required = HashSet::with_capacity(required.len());
    let mut total_bytes = 0_u64;

    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not inspect macOS app archive entry {index}: {error}"
            ))
        })?;
        let enclosed = entry.enclosed_name().ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "macOS app archive contains an unsafe path: {}",
                entry.name()
            ))
        })?;
        let relative = enclosed.to_str().ok_or_else(|| {
            LpmError::SelfUpdate("macOS app archive contains a non-UTF-8 path".to_string())
        })?;
        if !seen.insert(relative.to_string()) {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive contains a duplicate entry: {relative}"
            )));
        }
        if !enclosed.starts_with(MACOS_APP_NAME) || enclosed.components().count() > 8 {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive contains an unsafe path: {relative}"
            )));
        }
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & 0o170000;
            if file_type == 0o120000
                || (file_type != 0 && file_type != 0o040000 && file_type != 0o100000)
            {
                return Err(LpmError::SelfUpdate(format!(
                    "macOS app archive contains a link or special file: {relative}"
                )));
            }
        }

        let declared = entry.size();
        if declared > MACOS_BUNDLE_MAX_ENTRY_BYTES {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive entry {relative} exceeds {MACOS_BUNDLE_MAX_ENTRY_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(declared);
        if total_bytes > MACOS_BUNDLE_MAX_EXTRACTED_BYTES {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive exceeds {MACOS_BUNDLE_MAX_EXTRACTED_BYTES} extracted bytes"
            )));
        }

        if entry.is_dir() {
            if !allowed_directories.contains(relative.trim_end_matches('/')) {
                return Err(LpmError::SelfUpdate(format!(
                    "macOS app archive contains an unexpected entry: {relative}"
                )));
            }
        } else if required.contains(relative) {
            seen_required.insert(relative.to_string());
        } else if !enclosed
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("._"))
        {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive contains an unexpected entry: {relative}"
            )));
        }
    }

    for required_file in required {
        if !seen_required.contains(required_file) {
            return Err(LpmError::SelfUpdate(format!(
                "macOS app archive is missing required entry: {required_file}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct StagedMacOSBundle {
    staging_root: tempfile::TempDir,
    app_bundle: PathBuf,
    executable: PathBuf,
}

#[cfg(target_os = "macos")]
fn stage_macos_bundle(
    archive_path: &Path,
    app_parent: &Path,
) -> Result<StagedMacOSBundle, LpmError> {
    validate_macos_bundle_zip(archive_path)?;
    let staging_root = tempfile::Builder::new()
        .prefix(".lpm-bundle-update-")
        .tempdir_in(app_parent)
        .map_err(LpmError::Io)?;
    let status = std::process::Command::new("/usr/bin/ditto")
        .args([OsStr::new("-x"), OsStr::new("-k")])
        .arg(archive_path)
        .arg(staging_root.path())
        .status()
        .map_err(|error| {
            LpmError::SelfUpdate(format!("could not start ditto for app extraction: {error}"))
        })?;
    if !status.success() {
        return Err(LpmError::SelfUpdate(format!(
            "ditto failed to extract the macOS app archive with status {status}"
        )));
    }
    let app_bundle = staging_root.path().join(MACOS_APP_NAME);
    validate_macos_app_bundle(&app_bundle)?;
    let executable = app_bundle.join(MACOS_INTERNAL_EXECUTABLE);
    Ok(StagedMacOSBundle {
        staging_root,
        app_bundle,
        executable,
    })
}

#[cfg(target_os = "macos")]
fn validate_macos_app_inventory(app_bundle: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt as _;

    let app_metadata = std::fs::symlink_metadata(app_bundle).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not inspect staged macOS app bundle {}: {error}",
            app_bundle.display()
        ))
    })?;
    if app_metadata.file_type().is_symlink() || !app_metadata.is_dir() {
        return Err(LpmError::SelfUpdate(
            "staged macOS app bundle is not a real directory".to_string(),
        ));
    }

    let expected_directories = [
        PathBuf::from("Contents"),
        PathBuf::from("Contents/MacOS"),
        PathBuf::from("Contents/Resources"),
        PathBuf::from("Contents/_CodeSignature"),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let expected_files = [
        PathBuf::from("Contents/Info.plist"),
        PathBuf::from("Contents/CodeResources"),
        PathBuf::from("Contents/embedded.provisionprofile"),
        PathBuf::from("Contents/MacOS/lpm-rs"),
        PathBuf::from("Contents/Resources/LPMCLI.icns"),
        PathBuf::from("Contents/_CodeSignature/CodeResources"),
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let mut seen_files = HashSet::with_capacity(expected_files.len());
    let mut stack = vec![app_bundle.to_path_buf()];
    let mut total_bytes = 0_u64;
    let mut entry_count = 0_usize;

    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).map_err(LpmError::Io)? {
            let entry = entry.map_err(LpmError::Io)?;
            entry_count += 1;
            if entry_count > MACOS_BUNDLE_MAX_ENTRIES {
                return Err(LpmError::SelfUpdate(
                    "staged macOS app bundle contains too many entries".to_string(),
                ));
            }
            let path = entry.path();
            let relative = path.strip_prefix(app_bundle).map_err(|_| {
                LpmError::SelfUpdate(
                    "staged macOS app bundle escaped its extraction root".to_string(),
                )
            })?;
            let metadata = std::fs::symlink_metadata(&path).map_err(LpmError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(LpmError::SelfUpdate(format!(
                    "staged macOS app bundle contains a symbolic link: {}",
                    relative.display()
                )));
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(LpmError::SelfUpdate(format!(
                    "staged macOS app bundle contains a shared-writable entry: {}",
                    relative.display()
                )));
            }
            if metadata.is_dir() {
                if !expected_directories.contains(relative) {
                    return Err(LpmError::SelfUpdate(format!(
                        "staged macOS app bundle contains an unexpected directory: {}",
                        relative.display()
                    )));
                }
                stack.push(path);
            } else if metadata.is_file() {
                if !expected_files.contains(relative) {
                    return Err(LpmError::SelfUpdate(format!(
                        "staged macOS app bundle contains an unexpected file: {}",
                        relative.display()
                    )));
                }
                total_bytes = total_bytes.saturating_add(metadata.len());
                if total_bytes > MACOS_BUNDLE_MAX_EXTRACTED_BYTES {
                    return Err(LpmError::SelfUpdate(
                        "staged macOS app bundle exceeds its extracted-size limit".to_string(),
                    ));
                }
                seen_files.insert(relative.to_path_buf());
            } else {
                return Err(LpmError::SelfUpdate(format!(
                    "staged macOS app bundle contains an unsupported file type: {}",
                    relative.display()
                )));
            }
        }
    }

    if seen_files != expected_files {
        return Err(LpmError::SelfUpdate(
            "staged macOS app bundle is missing a required signed file".to_string(),
        ));
    }
    let executable = app_bundle.join(MACOS_INTERNAL_EXECUTABLE);
    let mode = std::fs::metadata(&executable)
        .map_err(LpmError::Io)?
        .permissions()
        .mode();
    if mode & 0o111 == 0 {
        return Err(LpmError::SelfUpdate(
            "staged macOS app bundle executable does not have an executable mode".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_macos_validation_tool(
    program: &str,
    arguments: &[&OsStr],
    description: &str,
) -> Result<std::process::Output, LpmError> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| LpmError::SelfUpdate(format!("could not start {description}: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LpmError::SelfUpdate(format!(
            "{description} failed with status {}{}",
            output.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        )));
    }
    Ok(output)
}

#[cfg(target_os = "macos")]
fn plist_buddy_value(plist: &Path, key: &str) -> Result<String, LpmError> {
    let command = format!("Print :{key}");
    let output = run_macos_validation_tool(
        "/usr/libexec/PlistBuddy",
        &[OsStr::new("-c"), command.as_ref(), plist.as_os_str()],
        "provisioning-profile metadata validation",
    )?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| {
            LpmError::SelfUpdate(format!(
                "provisioning-profile metadata is not valid UTF-8: {error}"
            ))
        })
}

#[cfg(target_os = "macos")]
fn plist_array_contains(value: &str, expected: &str) -> bool {
    value.lines().any(|line| line.trim() == expected)
}

#[cfg(target_os = "macos")]
fn provisioning_profile_application_identifier(plist: &Path) -> Result<String, LpmError> {
    plist_buddy_value(plist, "Entitlements:com.apple.application-identifier")
        .or_else(|_| plist_buddy_value(plist, "Entitlements:application-identifier"))
}

#[cfg(target_os = "macos")]
fn provisioning_profile_authorizes_access_group(groups: &str) -> bool {
    plist_array_contains(groups, MACOS_EXPECTED_ACCESS_GROUP)
        || plist_array_contains(groups, MACOS_EXPECTED_PROFILE_ACCESS_GROUP)
}

#[cfg(target_os = "macos")]
fn macos_entitlement_inspection_arguments(app_bundle: &Path) -> [&OsStr; 4] {
    [
        OsStr::new("-d"),
        OsStr::new("--entitlements"),
        OsStr::new(":-"),
        app_bundle.as_os_str(),
    ]
}

#[cfg(target_os = "macos")]
fn validate_macos_app_bundle(app_bundle: &Path) -> Result<(), LpmError> {
    use std::io::Write as _;

    validate_macos_app_inventory(app_bundle)?;
    run_macos_validation_tool(
        "/usr/bin/codesign",
        &[
            OsStr::new("--verify"),
            OsStr::new("--strict"),
            OsStr::new("--verbose=4"),
            app_bundle.as_os_str(),
        ],
        "macOS app code-signature validation",
    )?;

    let details = run_macos_validation_tool(
        "/usr/bin/codesign",
        &[OsStr::new("-dvv"), app_bundle.as_os_str()],
        "macOS app signing-identity inspection",
    )?;
    let details = format!(
        "{}{}",
        String::from_utf8_lossy(&details.stdout),
        String::from_utf8_lossy(&details.stderr)
    );
    let detail_value = |name: &str| {
        details
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(str::trim)
    };
    if detail_value("TeamIdentifier") != Some(MACOS_EXPECTED_TEAM_ID)
        || detail_value("Identifier") != Some(MACOS_EXPECTED_BUNDLE_ID)
    {
        return Err(LpmError::SelfUpdate(
            "macOS app has an unexpected Team ID or bundle identifier".to_string(),
        ));
    }

    let entitlement_arguments = macos_entitlement_inspection_arguments(app_bundle);
    let signed_entitlements = run_macos_validation_tool(
        "/usr/bin/codesign",
        &entitlement_arguments,
        "macOS app entitlement inspection",
    )?;
    let mut entitlement_plist = tempfile::NamedTempFile::new().map_err(LpmError::Io)?;
    entitlement_plist
        .write_all(&signed_entitlements.stdout)
        .map_err(LpmError::Io)?;
    entitlement_plist.flush().map_err(LpmError::Io)?;
    let signed_groups = plist_buddy_value(entitlement_plist.path(), "keychain-access-groups")?;
    if !plist_array_contains(&signed_groups, MACOS_EXPECTED_ACCESS_GROUP) {
        return Err(LpmError::SelfUpdate(
            "macOS app does not have the LPM Vault shared Keychain access group".to_string(),
        ));
    }

    let profile = app_bundle.join("Contents/embedded.provisionprofile");
    let decoded_profile = run_macos_validation_tool(
        "/usr/bin/security",
        &[
            OsStr::new("cms"),
            OsStr::new("-D"),
            OsStr::new("-i"),
            profile.as_os_str(),
        ],
        "macOS provisioning-profile decoding",
    )?;
    let mut profile_plist = tempfile::NamedTempFile::new().map_err(LpmError::Io)?;
    profile_plist
        .write_all(&decoded_profile.stdout)
        .map_err(LpmError::Io)?;
    profile_plist.flush().map_err(LpmError::Io)?;
    let profile_team = plist_buddy_value(profile_plist.path(), "TeamIdentifier:0")?;
    let profile_application = provisioning_profile_application_identifier(profile_plist.path())?;
    let profile_groups =
        plist_buddy_value(profile_plist.path(), "Entitlements:keychain-access-groups")?;
    if profile_team != MACOS_EXPECTED_TEAM_ID
        || profile_application != format!("{MACOS_EXPECTED_TEAM_ID}.{MACOS_EXPECTED_BUNDLE_ID}")
        || !provisioning_profile_authorizes_access_group(&profile_groups)
    {
        return Err(LpmError::SelfUpdate(
            "macOS provisioning profile does not authorize the shared Keychain contract"
                .to_string(),
        ));
    }

    run_macos_validation_tool(
        "/usr/bin/stapler",
        &[OsStr::new("validate"), app_bundle.as_os_str()],
        "macOS notarization-ticket validation",
    )?;
    run_macos_validation_tool(
        "/usr/sbin/spctl",
        &[
            OsStr::new("--assess"),
            OsStr::new("--type"),
            OsStr::new("execute"),
            OsStr::new("--verbose=4"),
            app_bundle.as_os_str(),
        ],
        "macOS Gatekeeper validation",
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_staged_macos_bundle(
    layout: &MacOSStandaloneLayout,
    staged: StagedMacOSBundle,
    version: &str,
) -> Result<(), LpmError> {
    let staging_root = staged.staging_root.path();
    if staged.app_bundle.parent() != Some(staging_root) {
        return Err(LpmError::SelfUpdate(
            "staged macOS app bundle is not inside its bound staging directory".to_string(),
        ));
    }
    let previous_app = staging_root.join("previous-LPM CLI.app");
    let previous_lpm = staging_root.join("previous-lpm");
    let previous_lpx = staging_root.join("previous-lpx");
    let failed_app = staging_root.join("failed-LPM CLI.app");

    let app_metadata = std::fs::symlink_metadata(&layout.app_bundle);
    let had_app = match app_metadata {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
        Ok(_) => {
            return Err(LpmError::SelfUpdate(format!(
                "existing macOS app path is not a real directory: {}",
                layout.app_bundle.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(LpmError::Io(error)),
    };
    for command_path in [&layout.lpm_link, &layout.lpx_link] {
        if std::fs::symlink_metadata(command_path).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(LpmError::SelfUpdate(format!(
                "refusing to replace command directory {}",
                command_path.display()
            )));
        }
    }

    let had_lpm = std::fs::symlink_metadata(&layout.lpm_link).is_ok();
    let had_lpx = std::fs::symlink_metadata(&layout.lpx_link).is_ok();
    let mut moved_app = false;
    let mut moved_lpm = false;
    let mut moved_lpx = false;
    let mut installed_app = false;
    let mut installed_lpm = false;
    let mut installed_lpx = false;

    let install_result = (|| -> Result<(), LpmError> {
        if had_app {
            std::fs::rename(&layout.app_bundle, &previous_app).map_err(LpmError::Io)?;
            moved_app = true;
        }
        if had_lpm {
            std::fs::rename(&layout.lpm_link, &previous_lpm).map_err(LpmError::Io)?;
            moved_lpm = true;
        }
        if had_lpx {
            std::fs::rename(&layout.lpx_link, &previous_lpx).map_err(LpmError::Io)?;
            moved_lpx = true;
        }

        std::fs::rename(&staged.app_bundle, &layout.app_bundle).map_err(LpmError::Io)?;
        installed_app = true;
        let link_target = Path::new("../libexec/LPM CLI.app/Contents/MacOS/lpm-rs");
        lpm_common::replace_symlink_atomic(&layout.lpm_link, link_target).map_err(LpmError::Io)?;
        installed_lpm = true;
        lpm_common::replace_symlink_atomic(&layout.lpx_link, link_target).map_err(LpmError::Io)?;
        installed_lpx = true;
        validate_macos_app_bundle(&layout.app_bundle)?;
        let final_executable = layout.app_bundle.join(MACOS_INTERNAL_EXECUTABLE);
        VersionProbe::verify_staged_path(&final_executable, version)?;
        let expected_executable = std::fs::canonicalize(&final_executable).map_err(LpmError::Io)?;
        for link in [&layout.lpm_link, &layout.lpx_link] {
            if std::fs::canonicalize(link).map_err(LpmError::Io)? != expected_executable {
                return Err(LpmError::SelfUpdate(format!(
                    "installed command does not resolve to the staged macOS app: {}",
                    link.display()
                )));
            }
        }
        Ok(())
    })();

    if let Err(install_error) = install_result {
        let mut rollback_errors = Vec::new();
        for (installed, link) in [
            (installed_lpm, &layout.lpm_link),
            (installed_lpx, &layout.lpx_link),
        ] {
            if !installed {
                continue;
            }
            match std::fs::remove_file(link) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => rollback_errors.push(format!("remove {}: {error}", link.display())),
            }
        }
        if installed_app
            && std::fs::symlink_metadata(&layout.app_bundle).is_ok()
            && let Err(error) = std::fs::rename(&layout.app_bundle, &failed_app)
        {
            rollback_errors.push(format!(
                "move failed app {} aside: {error}",
                layout.app_bundle.display()
            ));
        }
        for (moved, previous, destination) in [
            (moved_app, &previous_app, &layout.app_bundle),
            (moved_lpm, &previous_lpm, &layout.lpm_link),
            (moved_lpx, &previous_lpx, &layout.lpx_link),
        ] {
            if !moved {
                continue;
            }
            match std::fs::symlink_metadata(destination) {
                Ok(_) => {
                    rollback_errors.push(format!(
                        "refuse to restore over occupied destination {}",
                        destination.display()
                    ));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    rollback_errors.push(format!(
                        "inspect restore destination {}: {error}",
                        destination.display()
                    ));
                    continue;
                }
            }
            if let Err(error) = std::fs::rename(previous, destination) {
                rollback_errors.push(format!("restore {}: {error}", destination.display()));
            }
        }
        if rollback_errors.is_empty() {
            return Err(install_error);
        }
        let retained_staging_root = staged.staging_root.keep();
        return Err(LpmError::SelfUpdate(format!(
            "{install_error}; rollback also failed: {}; recovery data was retained at {}",
            rollback_errors.join("; "),
            retained_staging_root.display()
        )));
    }
    Ok(())
}

fn release_http_client() -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))
}

async fn fetch_verified_release_manifest(
    client: &reqwest::Client,
    version: &str,
    human_output: bool,
) -> Result<VerifiedReleaseManifest, LpmError> {
    let manifest_url = github_release_download_url(version, "SHA256SUMS.txt");
    let bundle_url = github_release_download_url(version, "SHA256SUMS.txt.sigstore");

    if human_output {
        install_ui::phase_untrusted(&format!("Fetching signed checksums for v{version}"));
    }

    let manifest = async {
        fetch_bounded(client, &manifest_url, MANIFEST_MAX_BYTES)
            .await?
            .ok_or_else(|| {
                LpmError::SelfUpdate(format!(
                    "release v{version} does not ship SHA256SUMS.txt — this release predates LPM's \
                     signed-install gate. Install manually from \
                     https://github.com/lpm-dev/rust-client/releases/v{version}"
                ))
            })
    };
    let bundle = async {
        fetch_bounded(client, &bundle_url, BUNDLE_MAX_BYTES)
            .await?
            .ok_or_else(|| {
                LpmError::SelfUpdate(format!(
                    "release v{version} ships SHA256SUMS.txt but not SHA256SUMS.txt.sigstore — \
                     cannot cryptographically verify the manifest. Install manually."
                ))
            })
    };
    let release_metadata = async {
        fetch_github_release_published_at(version)
            .await
            .map_err(|e| match e {
                LookupError::NotFound(_) => LpmError::SelfUpdate(format!(
                    "GitHub has no release at tag v{version} — cannot anchor the Sigstore replay window. \
                     Install manually."
                )),
                LookupError::MalformedResponse(msg) => LpmError::SelfUpdate(format!(
                    "release v{version} did not expose valid release metadata: {msg}. \
                     Cannot bind the Sigstore attestation to the requested release."
                )),
                other => LpmError::Network(format!(
                    "could not fetch release metadata for v{version}: {other}"
                )),
            })
    };

    let (manifest_bytes, bundle_bytes, published_at) =
        tokio::try_join!(manifest, bundle, release_metadata)?;
    if human_output {
        install_ui::phase("Verifying Sigstore attestation");
    }
    verify_release_manifest(version, &manifest_bytes, &bundle_bytes, published_at)
}

async fn verify_and_stage_for_standalone(
    version: &str,
    staging_anchor: &std::path::Path,
    human_output: bool,
) -> Result<StandaloneAssets, LpmError> {
    let (platform, ext) = detect_platform()?;
    let binary_name = standalone_asset_name_for(std::env::consts::OS, platform, ext);
    let asset_url = github_release_download_url(version, &binary_name);

    let client = release_http_client()?;
    let release = fetch_verified_release_manifest(&client, version, human_output).await?;
    if !release.entries.contains_key(&binary_name) {
        return Err(LpmError::SelfUpdate(format!(
            "SHA256SUMS.txt does not enumerate `{binary_name}` for this platform — release pipeline may be missing artifacts"
        )));
    }

    let staged = fetch_asset_to_staged_file(&client, &asset_url, ASSET_MAX_BYTES, staging_anchor)
        .await?
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "release v{version} advertises `{binary_name}` in SHA256SUMS.txt but the asset is missing at {} — release-pipeline bug",
                safe_remote_label(&asset_url)
            ))
        })?;

    let audit = verify_release_asset_digest(&release, staged.sha256.clone(), &binary_name)?;

    if human_output {
        install_ui::done_untrusted(&format!(
            "Verified Sigstore attestation for {} ({}, integratedTime {})",
            binary_name,
            format_bytes(staged.byte_len),
            audit.integrated_time
        ));
    }

    Ok(StandaloneAssets {
        staged_binary: staged,
        audit,
    })
}

#[cfg(test)]
async fn verify_and_fetch_for_standalone(version: &str) -> Result<StandaloneAssets, LpmError> {
    let destination = std::env::temp_dir().join("lpm-self-update-test-bin");
    verify_and_stage_for_standalone(version, &destination, false).await
}

/// Atomically swap the running binary at `current_exe` for a verified,
/// same-directory staged file.
///
/// **Windows EBUSY:** the OS holds an exclusive handle on the running
/// `current_exe()`, so a direct `rename(new, current_exe)` fails.
/// The standard dance is `rename(current_exe, current_exe.old)`
/// (legal even with a live handle), then `rename(new, current_exe)`,
/// then best-effort delete the `.old` (OS releases the handle when
/// this process exits, so the delete will succeed on the next run).
#[cfg(any(not(target_os = "macos"), test))]
fn install_staged_binary(
    current_exe: &std::path::Path,
    temporary: tempfile::NamedTempFile,
    expected_sha256: &str,
) -> Result<(), LpmError> {
    validate_standalone_install_location(current_exe)?;
    ensure_staged_file_unchanged(&temporary, expected_sha256)?;
    let file_name = current_exe.file_name().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no file name",
        ))
    })?;
    let parent = current_exe.parent().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no parent directory",
        ))
    })?;
    if temporary.path().parent() != Some(parent) {
        return Err(LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staged self-update binary is not next to current_exe",
        )));
    }

    // Save a backup copy of the running binary next to itself before
    // we install the new one, so a user who discovers the new binary is
    // broken can rename `<lpm>.previous` back over `<lpm>` and recover
    // without going to GitHub. The journal file is a parallel marker
    // recording when the backup was made + the version string the user
    // updated FROM, so a future `lpm self-rollback` command (tracked
    // separately) can drive the rename automatically.
    //
    // Best-effort: if the copy fails (read-only filesystem, perms), log
    // and continue with the install. The user opted into the update
    // and would get a confusing "can't update" error otherwise.
    let backup_name = format!("{}.previous", file_name.to_string_lossy());
    let backup_path = parent.join(backup_name);
    if let Err(e) = copy_executable_atomic(current_exe, &backup_path) {
        tracing::warn!(
            target: "lpm_cli::self_update",
            current_exe = %current_exe.display(),
            backup_path = %backup_path.display(),
            error = %e,
            "could not back up the running binary before self-update — rollback via `<binary>.previous` rename will not be available"
        );
    } else {
        let journal_path = parent.join(format!(
            "{}.update-journal.json",
            file_name.to_string_lossy()
        ));
        let journal = serde_json::json!({
            "version": 1,
            "backup_path": backup_path.display().to_string(),
            "current_exe": current_exe.display().to_string(),
            "updated_at_unix_secs": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            "previous_binary_version": crate::build_version::version(),
        });
        let journal_bytes = serde_json::to_vec_pretty(&journal).unwrap_or_default();
        if let Err(e) = lpm_common::write_file_atomic(&journal_path, journal_bytes) {
            tracing::warn!(
                target: "lpm_cli::self_update",
                journal_path = %journal_path.display(),
                error = %e,
                "wrote backup but failed to record update-journal sidecar — rollback via rename still possible"
            );
        }
    }

    let tmp_path = temporary.into_temp_path();

    #[cfg(windows)]
    {
        let old_name = format!("{}.old.{}", file_name.to_string_lossy(), std::process::id());
        let old_path = parent.join(&old_name);
        if let Err(e) = std::fs::rename(current_exe, &old_path) {
            return Err(LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to move running binary aside: {e}"),
            )));
        }
        if let Err(e) = std::fs::rename(&tmp_path, current_exe) {
            // Try to restore the original binary so we don't leave the
            // install in a broken state.
            let _ = std::fs::rename(&old_path, current_exe);
            return Err(LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to install new binary: {e}"),
            )));
        }
        // Best-effort cleanup. The OS will release the handle on the
        // `.old` file when this process exits; the next run of the new
        // binary can sweep it.
        let _ = std::fs::remove_file(&old_path);
        Ok(())
    }

    #[cfg(unix)]
    {
        std::fs::rename(&tmp_path, current_exe).map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to replace binary: {e}"),
            ))
        })
    }
}

#[cfg(unix)]
fn validate_standalone_install_location(current_executable: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let parent = current_executable.parent().ok_or_else(|| {
        LpmError::SelfUpdate("standalone install path has no parent directory".to_string())
    })?;
    let parent = std::fs::canonicalize(parent).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not resolve the standalone install directory: {error}"
        ))
    })?;
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not inspect the standalone install directory {}: {error}",
                ancestor.display()
            ))
        })?;
        let owner = metadata.uid();
        let mode = metadata.permissions().mode();
        let protected_shared_directory = owner == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || (owner != 0 && owner != effective_uid)
            || (mode & 0o022 != 0 && !protected_shared_directory)
        {
            return Err(LpmError::SelfUpdate(format!(
                "refusing standalone self-update through shared-writable install directory {}",
                ancestor.display()
            )));
        }
    }
    let metadata = std::fs::metadata(current_executable).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "could not inspect the running standalone executable: {error}"
        ))
    })?;
    let owner = metadata.uid();
    if (owner != 0 && owner != effective_uid) || metadata.permissions().mode() & 0o022 != 0 {
        return Err(LpmError::SelfUpdate(
            "refusing standalone self-update of a shared-writable executable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_standalone_install_location(current_executable: &Path) -> Result<(), LpmError> {
    let account_home = canonical_account_home()?;
    if !windows_trust::path_is_trusted_install_location(current_executable, &account_home) {
        return Err(LpmError::SelfUpdate(
            "refusing standalone self-update through an untrusted Windows install location"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_standalone_install_location(_current_executable: &Path) -> Result<(), LpmError> {
    Ok(())
}

#[cfg(test)]
fn swap_current_binary(current_exe: &std::path::Path, new_bytes: &[u8]) -> Result<(), LpmError> {
    use std::io::Write as _;

    let mut temporary = create_staged_binary(current_exe)?;
    temporary
        .as_file_mut()
        .write_all(new_bytes)
        .map_err(LpmError::Io)?;
    let temporary = finish_staged_binary(temporary)?;
    install_staged_binary(current_exe, temporary, &sha256_hex(new_bytes))
}

#[cfg(any(not(target_os = "macos"), test))]
fn copy_executable_atomic(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    lpm_common::write_file_atomic_with(
        destination,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o755),
        |output| {
            let mut input = std::fs::File::open(source)?;
            std::io::copy(&mut input, output)?;
            Ok(())
        },
    )
}

/// Detect the current platform for GitHub Release binary names.
fn detect_platform() -> Result<(&'static str, &'static str), LpmError> {
    detect_platform_for(
        std::env::consts::OS,
        std::env::consts::ARCH,
        resolve_linux_libc(EXECUTABLE_LINUX_LIBC, lpm_common::platform::detect_libc()),
    )
}

fn standalone_asset_name_for(os: &str, platform: &str, extension: &str) -> String {
    if os == "macos" {
        format!("lpm-{platform}.zip")
    } else {
        format!("lpm-{platform}{extension}")
    }
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = Some("musl");

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = Some("gnu");

#[cfg(not(any(
    all(target_os = "linux", target_env = "musl"),
    all(target_os = "linux", target_env = "gnu")
)))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = None;

const fn resolve_linux_libc<'a>(
    executable_libc: Option<&'a str>,
    detected_host_libc: Option<&'a str>,
) -> Option<&'a str> {
    match executable_libc {
        Some(libc) => Some(libc),
        None => detected_host_libc,
    }
}

fn detect_platform_for(
    os: &str,
    arch: &str,
    libc: Option<&str>,
) -> Result<(&'static str, &'static str), LpmError> {
    match (os, arch) {
        ("macos", "aarch64") => Ok(("darwin-arm64", "")),
        ("macos", "x86_64") => Ok(("darwin-x64", "")),
        ("linux", "x86_64") if libc == Some("musl") => Ok(("linux-x64-musl", "")),
        ("linux", "x86_64") => Ok(("linux-x64", "")),
        ("linux", "aarch64") if libc == Some("musl") => Err(LpmError::Script(
            "unsupported platform: linux-aarch64-musl. Official musl releases currently support x86_64; build from source on ARM64"
                .to_string(),
        )),
        ("linux", "aarch64") => Ok(("linux-arm64", "")),
        ("windows", "x86_64") => Ok(("win32-x64", ".exe")),
        _ => Err(LpmError::Script(format!(
            "unsupported platform: {os}-{arch}. Download manually from https://github.com/lpm-dev/rust-client/releases"
        ))),
    }
}

/// Render a duration in seconds as a coarse human string. Picks the
/// largest unit that gives at least one whole quantity. Pluralises.
fn humanize_seconds(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else if secs >= 60 {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else {
        format!("{secs} second{}", if secs == 1 { "" } else { "s" })
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_lookup::{self, UpdateCache};
    use tempfile::tempdir;

    fn cargo_metadata_test_root() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
    }

    #[test]
    fn install_method_name_not_empty() {
        let method = detect_install_method().unwrap();
        assert!(!method.name().is_empty());
    }

    #[test]
    fn standalone_update_does_not_require_or_scan_path() {
        let _environment = crate::test_env::ScopedEnv::update([("PATH", None)]);

        assert_eq!(
            sanitized_path_for_method(&InstallMethod::Standalone, None).unwrap(),
            None
        );
    }

    #[test]
    fn detect_platform_selects_musl_asset_on_linux_x64_musl() {
        assert_eq!(
            detect_platform_for("linux", "x86_64", Some("musl")).unwrap(),
            ("linux-x64-musl", "")
        );
    }

    #[test]
    fn detect_platform_preserves_gnu_asset_on_linux_x64_glibc() {
        assert_eq!(
            detect_platform_for("linux", "x86_64", Some("glibc")).unwrap(),
            ("linux-x64", "")
        );
    }

    #[test]
    fn detect_platform_rejects_linux_arm64_musl_without_release_asset() {
        assert!(detect_platform_for("linux", "aarch64", Some("musl")).is_err());
    }

    #[test]
    fn standalone_release_asset_uses_a_bundle_zip_only_on_macos() {
        assert_eq!(
            standalone_asset_name_for("macos", "darwin-arm64", ""),
            "lpm-darwin-arm64.zip"
        );
        assert_eq!(
            standalone_asset_name_for("linux", "linux-x64", ""),
            "lpm-linux-x64"
        );
        assert_eq!(
            standalone_asset_name_for("windows", "win32-x64", ".exe"),
            "lpm-win32-x64.exe"
        );
    }

    #[test]
    fn macos_bundle_zip_contract_rejects_traversal_and_unknown_payloads() {
        use std::io::Write as _;

        fn archive_with(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
            let mut archive = tempfile::NamedTempFile::new().unwrap();
            {
                let mut writer = zip::ZipWriter::new(archive.as_file_mut());
                let options = zip::write::SimpleFileOptions::default();
                for (name, body) in entries {
                    writer.start_file(*name, options).unwrap();
                    writer.write_all(body).unwrap();
                }
                writer.finish().unwrap();
            }
            archive
        }

        let traversal = archive_with(&[("LPM CLI.app/../../escape", b"no")]);
        let error = validate_macos_bundle_zip(traversal.path())
            .expect_err("parent traversal must fail closed");
        assert!(error.to_string().contains("unsafe path"));

        let unknown = archive_with(&[("LPM CLI.app/Contents/extra", b"no")]);
        let error = validate_macos_bundle_zip(unknown.path())
            .expect_err("unknown bundle payloads must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
    }

    #[test]
    fn macos_bundle_zip_contract_accepts_the_signed_bundle_inventory() {
        use std::io::Write as _;

        let mut archive = tempfile::NamedTempFile::new().unwrap();
        {
            let mut writer = zip::ZipWriter::new(archive.as_file_mut());
            let options = zip::write::SimpleFileOptions::default();
            for (name, body) in [
                ("LPM CLI.app/Contents/Info.plist", b"plist".as_slice()),
                (
                    "LPM CLI.app/Contents/CodeResources",
                    b"notarization-ticket".as_slice(),
                ),
                (
                    "LPM CLI.app/Contents/embedded.provisionprofile",
                    b"profile".as_slice(),
                ),
                (
                    "LPM CLI.app/Contents/Resources/LPMCLI.icns",
                    b"icon".as_slice(),
                ),
                ("LPM CLI.app/Contents/MacOS/lpm-rs", b"binary".as_slice()),
                (
                    "LPM CLI.app/Contents/_CodeSignature/CodeResources",
                    b"signature".as_slice(),
                ),
                (
                    "LPM CLI.app/Contents/MacOS/._lpm-rs",
                    b"apple-double".as_slice(),
                ),
            ] {
                writer.start_file(name, options).unwrap();
                writer.write_all(body).unwrap();
            }
            writer.finish().unwrap();
        }

        validate_macos_bundle_zip(archive.path()).unwrap();
    }

    #[test]
    fn macos_standalone_layout_accepts_only_bundle_execution_path() {
        let home = Path::new("/Users/alice");
        let root = home.join(".lpm");
        let expected_app = root.join("libexec/LPM CLI.app");
        let current = expected_app.join("Contents/MacOS/lpm-rs");
        let layout = macos_standalone_layout_for(&current, home).unwrap();
        assert_eq!(layout.app_bundle, expected_app);
        assert_eq!(layout.lpm_link, root.join("bin/lpm"));
        assert_eq!(layout.lpx_link, root.join("bin/lpx"));

        assert!(macos_standalone_layout_for(&root.join("bin/lpm"), home).is_err());
        assert!(macos_standalone_layout_for(Path::new("/usr/local/bin/lpm"), home).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_entitlement_inspection_writes_the_plist_to_stdout() {
        let app_bundle = Path::new("/Applications/LPM CLI.app");

        assert_eq!(
            macos_entitlement_inspection_arguments(app_bundle),
            [
                OsStr::new("-d"),
                OsStr::new("--entitlements"),
                OsStr::new(":-"),
                app_bundle.as_os_str(),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provisioning_profile_accepts_the_exact_shared_keychain_group() {
        assert!(provisioning_profile_authorizes_access_group(
            "Array {\n    823S8YKMRW.dev.lpm.vault.shared\n}"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provisioning_profile_accepts_the_team_scoped_keychain_wildcard() {
        assert!(provisioning_profile_authorizes_access_group(
            "Array {\n    823S8YKMRW.*\n}"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provisioning_profile_rejects_another_team_keychain_wildcard() {
        assert!(!provisioning_profile_authorizes_access_group(
            "Array {\n    WRONGTEAM.*\n}"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provisioning_profile_rejects_a_shared_group_prefix_match() {
        assert!(!provisioning_profile_authorizes_access_group(
            "Array {\n    823S8YKMRW.dev.lpm.vault.shared.attacker\n}"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bundle_install_restores_the_app_when_command_backup_fails() {
        let root = tempfile::tempdir().unwrap();
        let install_root = root.path().join(".lpm");
        let app_parent = install_root.join("libexec");
        let app_bundle = app_parent.join(MACOS_APP_NAME);
        let command_parent = install_root.join("bin");
        let lpm_link = command_parent.join("lpm");
        let lpx_link = command_parent.join("lpx");
        std::fs::create_dir_all(&app_bundle).unwrap();
        std::fs::create_dir_all(&command_parent).unwrap();
        std::fs::write(app_bundle.join("existing-marker"), b"existing app").unwrap();
        std::fs::write(&lpm_link, b"existing command").unwrap();

        let staging_root = tempfile::Builder::new()
            .prefix(".lpm-bundle-update-")
            .tempdir_in(&app_parent)
            .unwrap();
        let staged_app = staging_root.path().join(MACOS_APP_NAME);
        let staged_executable = staged_app.join(MACOS_INTERNAL_EXECUTABLE);
        std::fs::create_dir_all(&staged_app).unwrap();
        std::fs::create_dir(staging_root.path().join("previous-lpm")).unwrap();

        let layout = MacOSStandaloneLayout {
            app_parent,
            app_bundle: app_bundle.clone(),
            lpm_link: lpm_link.clone(),
            lpx_link,
        };
        let staged = StagedMacOSBundle {
            staging_root,
            app_bundle: staged_app,
            executable: staged_executable,
        };

        let error = install_staged_macos_bundle(&layout, staged, "0.75.0")
            .expect_err("command backup collision must fail");

        assert!(matches!(error, LpmError::Io(_)));
        assert_eq!(
            std::fs::read(app_bundle.join("existing-marker")).unwrap(),
            b"existing app"
        );
        assert_eq!(std::fs::read(lpm_link).unwrap(), b"existing command");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bundle_install_retains_recovery_data_when_rollback_fails() {
        let root = tempfile::tempdir().unwrap();
        let install_root = root.path().join(".lpm");
        let app_parent = install_root.join("libexec");
        let app_bundle = app_parent.join(MACOS_APP_NAME);
        let command_parent = install_root.join("bin");
        let lpm_link = command_parent.join("lpm");
        let lpx_link = command_parent.join("lpx");
        std::fs::create_dir_all(&app_bundle).unwrap();
        std::fs::create_dir_all(&command_parent).unwrap();
        std::fs::write(app_bundle.join("existing-marker"), b"existing app").unwrap();
        std::fs::write(&lpm_link, b"existing lpm").unwrap();
        std::fs::write(&lpx_link, b"existing lpx").unwrap();

        let staging_root = tempfile::Builder::new()
            .prefix(".lpm-bundle-update-")
            .tempdir_in(&app_parent)
            .unwrap();
        let staging_path = staging_root.path().to_path_buf();
        let staged_app = staging_path.join(MACOS_APP_NAME);
        let staged_executable = staged_app.join(MACOS_INTERNAL_EXECUTABLE);
        std::fs::create_dir_all(&staged_app).unwrap();
        std::fs::write(staged_app.join("unexpected-marker"), b"invalid staged app").unwrap();
        let failed_app = staging_path.join("failed-LPM CLI.app");
        std::fs::create_dir(&failed_app).unwrap();
        std::fs::write(failed_app.join("collision"), b"occupied").unwrap();

        let layout = MacOSStandaloneLayout {
            app_parent,
            app_bundle: app_bundle.clone(),
            lpm_link,
            lpx_link,
        };
        let staged = StagedMacOSBundle {
            staging_root,
            app_bundle: staged_app,
            executable: staged_executable,
        };

        let error = install_staged_macos_bundle(&layout, staged, "0.75.0")
            .expect_err("occupied rollback destination must retain recovery data");

        let message = error.to_string();
        assert!(message.contains("rollback also failed"), "{message}");
        assert!(
            message.contains(&staging_path.display().to_string()),
            "{message}"
        );
        assert!(staging_path.is_dir());
        assert_eq!(
            std::fs::read(staging_path.join("previous-LPM CLI.app/existing-marker")).unwrap(),
            b"existing app"
        );
        assert_eq!(
            std::fs::read(app_bundle.join("unexpected-marker")).unwrap(),
            b"invalid staged app"
        );
    }

    #[test]
    fn executable_abi_wins_when_host_has_both_glibc_and_musl_loaders() {
        assert_eq!(resolve_linux_libc(Some("gnu"), Some("musl")), Some("gnu"));
    }

    #[test]
    fn parse_manifest_line_accepts_canonical_two_space_form() {
        let line =
            "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  lpm-linux-x64";
        let (sha, name) = parse_manifest_line(line).expect("must parse");
        assert_eq!(sha.len(), 64);
        assert_eq!(name, "lpm-linux-x64");
    }

    #[test]
    fn parse_manifest_line_lowercases_hex_digest() {
        let line = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890  X";
        let (sha, _) = parse_manifest_line(line).expect("must parse");
        assert_eq!(
            sha,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn parse_manifest_line_rejects_short_digest() {
        let line = "abc  lpm-linux-x64";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_non_hex_digest() {
        let line = "zzz123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  lpm";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_single_space_separator() {
        let line = "0000000000000000000000000000000000000000000000000000000000000000 lpm";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_empty_filename() {
        let line = "0000000000000000000000000000000000000000000000000000000000000000  ";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_strips_trailing_carriage_return() {
        let line =
            "1111111111111111111111111111111111111111111111111111111111111111  lpm-darwin-arm64\r";
        let (sha, name) = parse_manifest_line(line).expect("must parse");
        assert_eq!(
            sha,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(name, "lpm-darwin-arm64");
    }

    #[test]
    fn lookup_platform_sha_returns_correct_entry() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  lpm-darwin-x64\n\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  lpm-linux-x64\n\
";
        let got = lookup_platform_sha(manifest, "lpm-linux-x64").expect("must find");
        assert_eq!(
            got,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn lookup_platform_sha_returns_err_on_missing_platform() {
        let manifest =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64\n";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64").expect_err("must fail");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("lpm-linux-x64")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn lookup_platform_sha_skips_blank_lines() {
        let manifest =
            "\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-linux-x64\n\n";
        let got = lookup_platform_sha(manifest, "lpm-linux-x64").expect("must find");
        assert!(got.starts_with("aaaa"));
    }

    #[test]
    fn lookup_platform_sha_rejects_malformed_line() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64
not-a-valid-line
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  lpm-linux-x64
";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64").expect_err("must reject");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("malformed")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn lookup_platform_sha_rejects_malformed_line_after_target() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-linux-x64
not-a-valid-line
";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64")
            .expect_err("the complete manifest must be valid");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("malformed")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn lookup_platform_sha_rejects_duplicate_target() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-linux-x64
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  lpm-linux-x64
";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64")
            .expect_err("a platform must have exactly one digest");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("more than once")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        let got = sha256_hex(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn release_provenance_fixture(
        workflow_ref: &str,
        source_commit: &str,
    ) -> (lpm_workspace::ProvenanceSnapshot, serde_json::Value) {
        let snapshot = lpm_workspace::ProvenanceSnapshot {
            present: true,
            publisher: Some("github:lpm-dev/rust-client".to_string()),
            workflow_path: Some(".github/workflows/release.yml".to_string()),
            workflow_ref: Some(workflow_ref.to_string()),
            attestation_cert_sha256: Some("sha256-fixture".to_string()),
        };
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "SHA256SUMS.txt",
                "digest": { "sha256": "a".repeat(64) },
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "ref": workflow_ref,
                            "repository": "https://github.com/lpm-dev/rust-client",
                            "path": ".github/workflows/release.yml",
                        },
                    },
                    "resolvedDependencies": [{
                        "uri": format!("git+https://github.com/lpm-dev/rust-client@{workflow_ref}"),
                        "digest": { "gitCommit": source_commit },
                    }],
                },
            },
        });
        (snapshot, statement)
    }

    #[test]
    fn release_provenance_rejects_stable_workflow_ref_for_another_version() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let (snapshot, statement) = release_provenance_fixture("refs/tags/v0.74.1", source_commit);
        let err = validate_release_provenance("0.75.0", &snapshot, &statement)
            .expect_err("a stable release must be signed from its requested tag");
        assert!(err.to_string().contains("refs/tags/v0.75.0"));
    }

    #[test]
    fn release_provenance_rejects_nightly_version_from_another_commit() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let (snapshot, statement) = release_provenance_fixture("refs/heads/main", source_commit);
        let err =
            validate_release_provenance("0.75.0-nightly.20260817.1.fffffff", &snapshot, &statement)
                .expect_err("a nightly version must name its signed source commit");
        assert!(err.to_string().contains("fffffff"));
    }

    #[test]
    fn release_provenance_accepts_exact_stable_tag_and_source_commit() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let (snapshot, statement) = release_provenance_fixture("refs/tags/v0.74.1", source_commit);
        let verified = validate_release_provenance("0.74.1", &snapshot, &statement).unwrap();
        assert_eq!(verified, source_commit);
    }

    #[test]
    fn release_provenance_accepts_nightly_commit_suffix() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let (snapshot, statement) = release_provenance_fixture("refs/heads/main", source_commit);
        let verified =
            validate_release_provenance("0.75.0-nightly.20260817.1.1e98fb8", &snapshot, &statement)
                .unwrap();
        assert_eq!(verified, source_commit);
    }

    /// Wire-shape pin for the audit JSON surface — `--json self-update`
    /// emits these keys for the Standalone channel and downstream
    /// consumers (audit pipelines, CI provenance check) parse them by
    /// name. Renaming or removing a key is a contract break; adding a
    /// key is non-breaking.
    #[test]
    fn audit_json_emits_stable_wire_shape() {
        let audit = AttestationAudit {
            publisher: Some("github:lpm-dev/rust-client".to_string()),
            workflow_path: Some(".github/workflows/release.yml".to_string()),
            workflow_ref: Some("refs/tags/v1.2.3".to_string()),
            integrated_time: chrono::DateTime::parse_from_rfc3339("2026-05-19T12:34:56Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            log_index: 9876543210,
            log_id: "c0d23d6ad406973f9559f3ba2d1ca01f8.. (truncated)".to_string(),
            leaf_cert_sha256: "feedface".to_string(),
            manifest_sha256: "deadbeef".to_string(),
            asset_sha256: "cafebabe".to_string(),
            asset_name: "lpm-linux-x64".to_string(),
            source_commit: "1e98fb8efbcc00f620678fc8091b512ed503768f".to_string(),
        };
        let json = audit_json(&audit);
        let obj = json.as_object().expect("audit_json returns an object");
        for key in [
            "publisher",
            "workflow_path",
            "workflow_ref",
            "integrated_time",
            "log_index",
            "log_id",
            "leaf_cert_sha256",
            "manifest_sha256",
            "asset_sha256",
            "asset_name",
            "source_commit",
        ] {
            assert!(
                obj.contains_key(key),
                "audit_json wire shape dropped key `{key}`: {json}"
            );
        }
        assert_eq!(
            obj["integrated_time"], "2026-05-19T12:34:56+00:00",
            "integrated_time must be RFC 3339 with explicit zone offset"
        );
        assert_eq!(obj["log_index"], 9876543210_i64);
    }

    // ── verify_and_fetch_for_standalone (wiremock-backed) ────────

    const DOWNLOAD_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE";
    const RELEASE_BY_TAG_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE";

    fn acquire_standalone_env(
        download_template: &str,
        release_by_tag_template: &str,
    ) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([
            (DOWNLOAD_OVERRIDE_KEY, download_template.into()),
            (RELEASE_BY_TAG_OVERRIDE_KEY, release_by_tag_template.into()),
        ])
    }

    #[test]
    fn standalone_published_release_overrides_share_process_env_lock() {
        let release_env = crate::test_env::ScopedEnv::set([(
            RELEASE_BY_TAG_OVERRIDE_KEY,
            "http://127.0.0.1:41001/releases/tags/v{tag}".into(),
        )]);
        let (contention_tx, contention_rx) = std::sync::mpsc::channel();
        let (standalone_values_tx, standalone_values_rx) = std::sync::mpsc::channel();
        let standalone_thread = std::thread::spawn(move || {
            crate::test_env::signal_next_env_lock_contention(contention_tx);
            let _env = acquire_standalone_env(
                "http://127.0.0.1:41002/download/v{tag}/{file}",
                "http://127.0.0.1:41002/releases/tags/v{tag}",
            );
            standalone_values_tx
                .send((
                    std::env::var(DOWNLOAD_OVERRIDE_KEY).unwrap(),
                    std::env::var(RELEASE_BY_TAG_OVERRIDE_KEY).unwrap(),
                ))
                .unwrap();
        });

        contention_rx.recv().unwrap();
        assert!(
            matches!(
                standalone_values_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "standalone override scope acquired while the shared environment lock was held"
        );
        drop(release_env);
        let (download_override, release_by_tag_override) = standalone_values_rx.recv().unwrap();
        standalone_thread.join().unwrap();
        assert_eq!(
            download_override,
            "http://127.0.0.1:41002/download/v{tag}/{file}"
        );
        assert_eq!(
            release_by_tag_override,
            "http://127.0.0.1:41002/releases/tags/v{tag}"
        );
    }

    /// Drive `verify_and_fetch_for_standalone` against a wiremock-served
    /// release fixture. Caller mounts the asset / manifest / bundle /
    /// release-tag responses on the supplied [`wiremock::MockServer`],
    /// then awaits the future — this helper just wires the env vars up.
    async fn run_standalone_against_server<F>(
        server: &wiremock::MockServer,
        version: &str,
        fut: impl FnOnce() -> F,
    ) where
        F: std::future::Future<Output = ()>,
    {
        let download_template = format!("{}/download/v{{tag}}/{{file}}", server.uri());
        let release_by_tag_template = format!("{}/releases/tags/v{{tag}}", server.uri());
        let _guard = acquire_standalone_env(&download_template, &release_by_tag_template);
        let _ = version; // version is captured by the caller's future
        fut().await;
    }

    fn mount_release_tag_with_published_at(server_uri_path: &str) -> serde_json::Value {
        serde_json::json!({
            "tag_name": format!("v{server_uri_path}"),
            "published_at": "2099-01-01T00:00:00Z",
        })
    }

    async fn mount_release_metadata(server: &wiremock::MockServer) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(mount_release_tag_with_published_at("0.42.0")),
            )
            .mount(server)
            .await;
    }

    async fn mount_placeholder_bundle(server: &wiremock::MockServer) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"{}".to_vec()))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_is_404() {
        let server = wiremock::MockServer::start().await;
        mount_release_metadata(&server).await;
        mount_placeholder_bundle(&server).await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(
                wiremock::ResponseTemplate::new(404)
                    .set_delay(std::time::Duration::from_millis(100)),
            )
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing manifest must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("predates LPM's signed-install gate"),
                        "msg: {msg}"
                    );
                    assert!(msg.contains("0.42.0"), "version must appear: {msg}");
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    #[tokio::test]
    async fn standalone_update_refuses_when_bundle_is_404() {
        let server = wiremock::MockServer::start().await;
        mount_release_metadata(&server).await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(
                b"0000000000000000000000000000000000000000000000000000000000000000  lpm-darwin-arm64\n"
                    .to_vec(),
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing bundle must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("SHA256SUMS.txt.sigstore"),
                        "msg names the missing bundle file: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Hostile server that serves the manifest but the bundle is
    /// signed by axios/axios's release workflow (real npm fixture).
    /// The verifier must reject on identity-pin BEFORE the manifest
    /// or asset content is honoured — proves the SAN URI prefix check
    /// is load-bearing for the C2 path.
    #[tokio::test]
    async fn standalone_update_refuses_when_bundle_identity_does_not_match_lpm_dev_rust_client() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");
        let (platform, ext) = detect_platform().expect("platform must be supported");
        let asset_name = standalone_asset_name_for(std::env::consts::OS, platform, ext);
        let asset_path = format!("/download/v0.42.0/{asset_name}");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(mount_release_tag_with_published_at("0.42.0")),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(&asset_path))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .expect(0)
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("foreign-repo bundle must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    let lower = msg.to_ascii_lowercase();
                    assert!(
                        lower.contains("identity")
                            || lower.contains("san")
                            || lower.contains("workflow")
                            || lower.contains("issuer"),
                        "rejection must name the identity-pin field: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Server returns a `releases/tags/v{tag}` JSON with no
    /// `published_at` field — replay-window anchor cannot be
    /// computed and the update must refuse rather than fall through.
    #[tokio::test]
    async fn standalone_update_refuses_when_published_at_is_missing() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.42.0",
                })),
            )
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing published_at must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("published_at"),
                        "msg names the missing field: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// `releases/tags/v{tag}` returns 404 (release doesn't exist on
    /// GitHub even though the manifest + bundle came from somewhere) —
    /// surface as `SelfUpdate` with the manual-install hint, not as a
    /// generic network error.
    #[tokio::test]
    async fn standalone_update_refuses_when_release_tag_endpoint_is_404() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing release tag must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("no release at tag v0.42.0")
                            || msg.contains("Install manually"),
                        "msg points the user at manual install: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Oversized manifest body must trigger the size cap rather than
    /// being silently accepted. Cap is `MANIFEST_MAX_BYTES = 4 KiB`.
    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_exceeds_size_cap() {
        let server = wiremock::MockServer::start().await;
        mount_release_metadata(&server).await;
        mount_placeholder_bundle(&server).await;
        // 8 KiB of zeros — well over the 4 KiB cap.
        let huge = vec![b'0'; 8 * 1024];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(huge))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("oversized manifest must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(msg.contains("cap of"), "msg names the cap: {msg}");
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Hostile endpoint that omits Content-Length and streams more
    /// bytes than the cap allows. The mid-stream guard in
    /// [`fetch_bounded`] must trip before the whole body buffers.
    /// This is the defense-in-depth pair for the Content-Length pre-check.
    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_streams_past_cap_without_content_length() {
        let server = wiremock::MockServer::start().await;
        mount_release_metadata(&server).await;
        mount_placeholder_bundle(&server).await;
        let huge = vec![b'0'; 8 * 1024];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(huge)
                    // Wiremock auto-fills Content-Length; force chunked
                    // by setting Transfer-Encoding so the pre-check is
                    // bypassed and the mid-stream guard is what fires.
                    .insert_header("Transfer-Encoding", "chunked"),
            )
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("oversized chunked manifest must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("mid-stream") || msg.contains("cap of"),
                        "msg names the cap: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    #[test]
    fn install_staged_binary_rejects_cross_directory_rename() {
        use std::io::Write as _;

        let destination_dir = tempdir().unwrap();
        let staging_dir = tempdir().unwrap();
        let current = destination_dir.path().join("lpm");
        let other_destination = staging_dir.path().join("lpm");
        std::fs::write(&current, b"old").unwrap();
        let mut temporary = create_staged_binary(&other_destination).unwrap();
        temporary.as_file_mut().write_all(b"new").unwrap();
        let temporary = finish_staged_binary(temporary).unwrap();

        let err = install_staged_binary(&current, temporary, &sha256_hex(b"new"))
            .expect_err("the atomic swap requires one filesystem directory");

        assert!(err.to_string().contains("not next to current_exe"));
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
    }

    #[test]
    fn install_staged_binary_rejects_a_replaced_staging_path() {
        use std::io::Write as _;

        let directory = tempdir().unwrap();
        let current = directory.path().join("lpm");
        std::fs::write(&current, b"old").unwrap();
        let mut temporary = create_staged_binary(&current).unwrap();
        temporary.as_file_mut().write_all(b"verified").unwrap();
        let temporary = finish_staged_binary(temporary).unwrap();
        let staged_path = temporary.path().to_path_buf();
        let displaced = directory.path().join("displaced-staged-binary");
        std::fs::rename(&staged_path, &displaced).unwrap();
        std::fs::write(&staged_path, b"replacement").unwrap();

        let error = install_staged_binary(&current, temporary, &sha256_hex(b"verified"))
            .expect_err("the installed path must still name the opened staged file");

        assert!(
            error
                .to_string()
                .contains("staged self-update binary changed")
        );
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn install_staged_binary_rejects_a_shared_writable_install_directory() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let current = directory.path().join("lpm");
        std::fs::write(&current, b"old").unwrap();
        let mut temporary = create_staged_binary(&current).unwrap();
        temporary.as_file_mut().write_all(b"new").unwrap();
        let temporary = finish_staged_binary(temporary).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let error = install_staged_binary(&current, temporary, &sha256_hex(b"new"))
            .expect_err("shared-writable install directories must fail closed");

        assert!(error.to_string().contains("shared-writable"));
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
    }

    /// The staging file lands next to `current_exe` and preserves an
    /// extension such as `.exe`, so the rename stays atomic. Recovery
    /// sidecars remain after a successful swap by design.
    #[test]
    fn swap_current_binary_replaces_file_atomically() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm-test-bin");
        std::fs::write(&current, b"old-binary").unwrap();
        let new_bytes = b"new-binary-content";
        swap_current_binary(&current, new_bytes).expect("swap must succeed");
        let read = std::fs::read(&current).unwrap();
        assert_eq!(read, new_bytes);
        let allowed_sidecars = ["lpm-test-bin.previous", "lpm-test-bin.update-journal.json"];
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| {
                let n = e.unwrap().file_name().to_string_lossy().into_owned();
                if n == "lpm-test-bin" || allowed_sidecars.contains(&n.as_str()) {
                    None
                } else {
                    Some(n)
                }
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "swap left behind unexpected staging files: {leftovers:?}"
        );
    }

    /// Extension preservation: `with_extension("tmp")` would have
    /// turned `lpm.exe` into `lpm.tmp` — when the destination was
    /// `lpm.exe`, the rename target on Windows would have moved a
    /// non-executable file into place. The current staging name is
    /// `<file_name>.new.<pid>`, which keeps the `.exe` suffix on
    /// `current_exe` intact.
    #[test]
    fn swap_current_binary_keeps_destination_extension_intact() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm.exe");
        std::fs::write(&current, b"old").unwrap();
        swap_current_binary(&current, b"new").expect("swap must succeed");
        assert!(current.exists(), "destination .exe still present");
        assert_eq!(std::fs::read(&current).unwrap(), b"new");
    }

    /// On Unix the swapped binary must end up at 0o755.
    #[cfg(unix)]
    #[test]
    fn swap_current_binary_sets_executable_perms_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm-perms");
        std::fs::write(&current, b"old").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o644)).unwrap();
        swap_current_binary(&current, b"new").expect("swap must succeed");
        let mode = std::fs::metadata(&current).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0o755, got 0o{mode:o}");
    }

    /// Per-channel detection table. Synthetic paths drive the pure
    /// helper so the test holds regardless of what package manager
    /// owns the running test binary.
    ///
    /// The substring-based predecessor false-positived on any path
    /// containing the literal `"npm"` (e.g. `/Users/npmtest/...`) and
    /// missed Volta / fnm / asdf / pnpm-global outright.
    #[test]
    fn detect_install_method_from_path_classifies_each_channel() {
        use std::path::Path;
        let cases: &[(&str, InstallMethod)] = &[
            // Homebrew
            (
                "/opt/homebrew/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            (
                "/usr/local/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            (
                "/home/linuxbrew/.linuxbrew/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            // Direct npm install
            (
                "/usr/local/lib/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Npm,
            ),
            (
                "/Users/x/.npm/_npx/abc/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Npm,
            ),
            // npm version managers
            (
                "/Users/x/.nvm/versions/node/v20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            (
                "/Users/x/.volta/tools/image/packages/@lpm-registry/cli/bin/lpm",
                InstallMethod::Volta,
            ),
            ("/Users/x/.fnm/aliases/default/bin/lpm", InstallMethod::Npm),
            (
                "/Users/x/.asdf/installs/nodejs/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            // `n` version manager — three real-world layouts. Pre-fix,
            // these fell through to Standalone, so self-update would
            // overwrite n's binary tree with a GitHub Releases
            // download instead of going through `npm install -g`.
            ("/Users/x/.n/bin/lpm", InstallMethod::Npm),
            (
                "/Users/x/n/versions/node/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            (
                "/usr/local/n/versions/node/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            // pnpm global (requires BOTH `pnpm` and `global` segments)
            (
                "/Users/x/.local/share/pnpm/global/5/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Pnpm,
            ),
            (
                "/Users/x/.bun/install/global/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Bun,
            ),
            (
                "/Users/x/.config/yarn/global/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Yarn,
            ),
            // Standalone — no shim, no node_modules
            ("/Users/x/.lpm/bin/lpm", InstallMethod::Standalone),
            ("/usr/local/bin/lpm", InstallMethod::Standalone),
        ];
        for (raw, expected) in cases {
            let p = Path::new(raw);
            let got = detect_install_method_from_path(Some(p));
            assert_eq!(
                got, *expected,
                "path {raw}: expected {expected:?}, got {got:?}"
            );
        }
    }

    /// Substring-trap regression: a literal `"npm"` anywhere in the
    /// path used to false-positive as an npm install. With component
    /// matching, only exact path components count.
    #[test]
    fn detect_install_method_substring_npm_does_not_false_positive() {
        use std::path::Path;
        // `npmtest` contains "npm" as a substring but is not an npm
        // path component. Must classify as Standalone.
        let p = Path::new("/Users/npmtest/.lpm/bin/lpm");
        assert_eq!(
            detect_install_method_from_path(Some(p)),
            InstallMethod::Standalone,
        );
    }

    #[test]
    fn unrelated_homebrew_directory_is_not_treated_as_a_formula_install() {
        for executable in [
            Path::new("/Users/x/projects/homebrew/bin/lpm"),
            Path::new("/Users/x/projects/Cellar/other/bin/lpm"),
        ] {
            assert_eq!(
                detect_install_method_from_path(Some(executable)),
                InstallMethod::Standalone,
                "path {}",
                executable.display()
            );
        }
    }

    /// Bare `n` component without `versions` must NOT classify as
    /// Npm. The `n` version manager's directory layout always has
    /// both segments, so a stray folder named `n` (project source,
    /// initial of a username, etc.) doesn't get misclassified.
    #[test]
    fn detect_install_method_bare_n_without_versions_is_standalone() {
        use std::path::Path;
        // No `versions` segment — could be a project folder named `n`,
        // not the n version manager.
        let p = Path::new("/Users/x/projects/n/bin/lpm");
        assert_eq!(
            detect_install_method_from_path(Some(p)),
            InstallMethod::Standalone,
            "bare `n` segment without `versions` must not classify as Npm"
        );
    }

    /// pnpm content-addressable store has a `pnpm` component but NOT
    /// `global`. Must NOT classify as Npm — it's not an install root,
    /// and routing the upgrade through `npm install -g` would corrupt
    /// the store.
    #[test]
    fn detect_install_method_refuses_a_pnpm_store_entry() {
        use std::path::Path;
        let p = Path::new("/Users/x/.pnpm-store/v3/files/aa/bb/lpm-bin");
        let error = detect_install_method_from_path_with_roots(Some(p), &InstallRoots::default())
            .expect_err("a pnpm store entry must not be overwritten as standalone");

        assert!(error.to_string().contains("pnpm store"));
    }

    #[test]
    fn custom_node_modules_layout_is_not_assumed_to_be_npm_owned() {
        let executable = Path::new("/opt/custom-global/node_modules/@lpm-registry/cli/lpm-rs");
        let error =
            detect_install_method_from_path_with_roots(Some(executable), &InstallRoots::default())
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot determine which package manager")
        );
    }

    #[test]
    fn malformed_project_metadata_does_not_block_project_containment_discovery() {
        let project = tempdir().unwrap();
        let account = tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{").unwrap();

        assert_eq!(
            active_project_root(project.path(), account.path()).unwrap(),
            Some(std::fs::canonicalize(project.path()).unwrap())
        );
    }

    #[test]
    fn unrecognized_working_directory_is_not_treated_as_a_project() {
        let directory = tempdir().unwrap();
        let account = tempdir().unwrap();

        assert_eq!(
            active_project_root(directory.path(), account.path()).unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn self_update_lock_rejects_a_symlinked_parent_without_writing_through_it() {
        use std::os::unix::fs::symlink;

        let account = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let account_path = std::fs::canonicalize(account.path()).unwrap();
        symlink(outside.path(), account_path.join(".lpm")).unwrap();

        assert!(acquire_self_update_lock(&account_path).is_err());
        assert!(!outside.path().join("self-update").exists());
    }

    #[test]
    fn concurrent_self_update_refuses_to_wait_for_the_active_operation() {
        let account = tempdir().unwrap();
        let account_path = std::fs::canonicalize(account.path()).unwrap();
        let _held = acquire_self_update_lock(&account_path).unwrap();

        assert!(
            try_acquire_self_update_lock(&account_path)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[ignore = "manual release-mode self-update lock contention latency probe"]
    fn self_update_lock_contention_probe_reports_fail_fast_latency() {
        const ATTEMPTS: usize = 10_000;

        let account = tempdir().unwrap();
        let account_path = std::fs::canonicalize(account.path()).unwrap();
        let _held = acquire_self_update_lock(&account_path).unwrap();
        let started = Instant::now();
        for _ in 0..ATTEMPTS {
            assert!(
                try_acquire_self_update_lock(&account_path)
                    .unwrap()
                    .is_none()
            );
        }
        let elapsed = started.elapsed();

        eprintln!(
            "self_update_lock_contention attempts={ATTEMPTS} elapsed_us={} per_attempt_ns={}",
            elapsed.as_micros(),
            elapsed.as_nanos() / ATTEMPTS as u128
        );
    }

    #[cfg(windows)]
    #[test]
    fn self_update_lock_rejects_an_everyone_writable_lock_file() {
        let account = tempdir().unwrap();
        let account_path = std::fs::canonicalize(account.path()).unwrap();
        drop(acquire_self_update_lock(&account_path).unwrap());
        let lock_path = account_path
            .join(".lpm")
            .join("self-update")
            .join("operation.lock");
        let status = std::process::Command::new("icacls")
            .arg(&lock_path)
            .args(["/grant", "*S-1-1-0:F"])
            .status()
            .unwrap();
        assert!(status.success());

        let Err(error) = try_acquire_self_update_lock(&account_path) else {
            panic!("an Everyone-writable operation lock must fail closed");
        };

        assert!(error.to_string().contains("not a private account file"));
    }

    #[test]
    fn home_directory_without_project_metadata_is_not_treated_as_a_project() {
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\example"
        } else {
            "/home/example"
        });

        assert_eq!(fallback_containment_root(home.clone(), Some(&home)), None);
    }

    #[test]
    fn home_directory_project_metadata_does_not_capture_global_runtime_installs() {
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\example"
        } else {
            "/home/example"
        });

        assert_eq!(
            project_root_distinct_from_home(Some(home.clone()), Some(&home)),
            None
        );
    }

    /// `None` (no exe path resolvable) falls through to Standalone.
    /// Keeps the function total and the upgrade flow predictable.
    #[test]
    fn detect_install_method_none_falls_back_to_standalone() {
        assert_eq!(
            detect_install_method_from_path(None),
            InstallMethod::Standalone
        );
    }

    #[test]
    fn configured_manager_roots_classify_nondefault_install_layouts() {
        let base = tempdir().unwrap();
        let cases = [
            ("pnpm-root", InstallMethod::Pnpm),
            ("bun-root", InstallMethod::Bun),
            ("yarn-root", InstallMethod::Yarn),
            ("volta-root", InstallMethod::Volta),
        ];
        for (directory, expected) in cases {
            let root = base.path().join(directory);
            let executable = root
                .join("custom")
                .join("packages")
                .join("lpm")
                .join(if cfg!(windows) { "lpm.exe" } else { "lpm" });
            std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
            std::fs::write(&executable, b"").unwrap();
            let roots = match expected {
                InstallMethod::Pnpm => InstallRoots {
                    pnpm: vec![root],
                    ..InstallRoots::default()
                },
                InstallMethod::Bun => InstallRoots {
                    bun: vec![root],
                    ..InstallRoots::default()
                },
                InstallMethod::Yarn => InstallRoots {
                    yarn: vec![root],
                    ..InstallRoots::default()
                },
                InstallMethod::Volta => InstallRoots {
                    volta: vec![root],
                    ..InstallRoots::default()
                },
                _ => unreachable!(),
            };

            assert_eq!(
                detect_install_method_from_path_with_roots(Some(&executable), &roots).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn bun_user_config_global_directories_classify_custom_install_layouts() {
        let home = tempdir().unwrap();
        let global_dir = home.path().join("custom bun global");
        let global_bin = home.path().join("custom bun bin");
        std::fs::write(
            home.path().join(".bunfig.toml"),
            format!(
                "[install]\nglobalDir = {:?}\nglobalBinDir = {:?}\n",
                global_dir.to_string_lossy(),
                global_bin.to_string_lossy()
            ),
        )
        .unwrap();
        let executable = global_dir.join("packages").join("lpm");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"").unwrap();
        let mut roots = InstallRoots::default();

        roots.load_user_config(Some(home.path()), None, None);

        assert_eq!(
            detect_install_method_from_path_with_roots(Some(&executable), &roots).unwrap(),
            InstallMethod::Bun
        );
        assert!(roots.bun.contains(&global_bin));
    }

    #[test]
    fn yarn_classic_user_config_classifies_a_custom_global_folder() {
        let home = tempdir().unwrap();
        let global = home.path().join("custom yarn global");
        std::fs::write(
            home.path().join(".yarnrc"),
            format!("--global-folder {:?}\n", global.to_string_lossy()),
        )
        .unwrap();
        let executable = global.join("node_modules").join("lpm").join("lpm");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"").unwrap();
        let mut roots = InstallRoots::default();

        roots.load_user_config(Some(home.path()), None, None);

        assert_eq!(
            detect_install_method_from_path_with_roots(Some(&executable), &roots).unwrap(),
            InstallMethod::Yarn
        );
    }

    #[cfg(unix)]
    #[test]
    fn bun_config_symlink_outside_the_account_home_is_rejected() {
        use std::os::unix::fs::symlink;

        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let configured_root = home.path().join("bun-global");
        let outside_config = outside.path().join("bunfig.toml");
        std::fs::write(
            &outside_config,
            format!(
                "[install]\nglobalDir = {:?}\n",
                configured_root.to_string_lossy()
            ),
        )
        .unwrap();
        symlink(&outside_config, home.path().join(".bunfig.toml")).unwrap();

        let error = read_bun_global_roots(&home.path().join(".bunfig.toml"), home.path(), None)
            .expect_err("a manager config symlink must not be followed");

        assert!(error.to_string().contains("real private file"));
    }

    #[cfg(unix)]
    #[test]
    fn yarn_config_symlink_outside_the_account_home_is_rejected() {
        use std::os::unix::fs::symlink;

        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let configured_root = home.path().join("yarn-global");
        let outside_config = outside.path().join("yarnrc");
        std::fs::write(
            &outside_config,
            format!("--global-folder {:?}\n", configured_root.to_string_lossy()),
        )
        .unwrap();
        symlink(&outside_config, home.path().join(".yarnrc")).unwrap();

        let error = read_yarn_global_roots(&home.path().join(".yarnrc"), home.path(), None)
            .expect_err("a manager config symlink must not be followed");

        assert!(error.to_string().contains("real private file"));
    }

    #[test]
    fn bun_user_config_accepts_an_external_root_that_owns_the_running_executable() {
        let home = tempdir().unwrap();
        let external = tempdir().unwrap();
        let executable = external.path().join("install").join("global").join("lpm");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"").unwrap();
        std::fs::write(
            home.path().join(".bunfig.toml"),
            format!(
                "[install]\nglobalDir = {:?}\n",
                external.path().to_string_lossy()
            ),
        )
        .unwrap();

        let roots =
            read_bun_global_roots(&home.path().join(".bunfig.toml"), home.path(), None).unwrap();

        assert_eq!(roots, vec![external.path().to_path_buf()]);
    }

    #[test]
    fn yarn_user_config_accepts_an_external_global_root() {
        let home = tempdir().unwrap();
        let external = tempdir().unwrap();
        std::fs::write(
            home.path().join(".yarnrc"),
            format!("--global-folder {:?}\n", external.path().to_string_lossy()),
        )
        .unwrap();

        let roots =
            read_yarn_global_roots(&home.path().join(".yarnrc"), home.path(), None).unwrap();

        assert_eq!(roots, vec![external.path().to_path_buf()]);
    }

    #[test]
    fn oversized_bun_config_does_not_block_an_unrelated_npm_install() {
        let home = tempdir().unwrap();
        std::fs::write(
            home.path().join(".bunfig.toml"),
            vec![b' '; MANAGER_CONFIG_LIMIT as usize + 1],
        )
        .unwrap();
        let executable = home
            .path()
            .join("lib")
            .join("node_modules")
            .join("@lpm-registry")
            .join("cli")
            .join("lpm-rs");
        let mut roots = InstallRoots::default();

        roots.load_user_config(Some(home.path()), None, None);

        assert_eq!(
            detect_install_method_from_path_with_roots(Some(&executable), &roots).unwrap(),
            InstallMethod::Npm
        );
    }

    #[test]
    #[ignore = "manual release-mode install-root containment latency probe"]
    fn install_root_containment_probe_reports_repeated_resolution_cost() {
        let attempts = std::env::var("LPM_INSTALL_ROOT_BENCH_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1_000);
        let mode = std::env::var("LPM_INSTALL_ROOT_BENCH_MODE")
            .unwrap_or_else(|_| "resolved-once".to_string());
        let base = tempdir().unwrap();
        let managed_root = base.path().join("managed");
        let target = managed_root.join("bin").join("lpm");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let mut groups = Vec::with_capacity(6);
        for index in 0..5 {
            let root = base.path().join(format!("unrelated-{index}"));
            std::fs::create_dir(&root).unwrap();
            groups.push(vec![root]);
        }
        groups.push(vec![managed_root]);

        let started = Instant::now();
        for _ in 0..attempts {
            let found = match mode.as_str() {
                "fixture" => true,
                "repeated" => groups
                    .iter()
                    .any(|roots| path_is_under_any_root(&target, roots)),
                "resolved-once" => {
                    let resolved = resolve_for_containment(&target).unwrap();
                    groups
                        .iter()
                        .any(|roots| path_is_under_any_resolved_root(&resolved, roots))
                }
                other => panic!("unknown LPM_INSTALL_ROOT_BENCH_MODE `{other}`"),
            };
            assert!(found);
        }

        eprintln!(
            "install_root_containment mode={mode} attempts={attempts} elapsed_us={}",
            started.elapsed().as_micros()
        );
    }

    #[test]
    fn unrelated_volta_and_yarn_directory_names_do_not_claim_ownership() {
        for path in [
            Path::new("/srv/projects/volta/bin/lpm"),
            Path::new("/srv/projects/yarn/global/bin/lpm"),
        ] {
            assert_eq!(
                detect_install_method_from_path(Some(path)),
                InstallMethod::Standalone,
                "unrelated path {}",
                path.display()
            );
        }
    }

    #[test]
    fn detect_install_method_custom_cargo_root_uses_install_metadata() {
        let root = cargo_metadata_test_root();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&binary, b"").unwrap();
        let metadata = serde_json::json!({
            "installs": {
                "lpm-cli 0.74.1 (registry+https://github.com/rust-lang/crates.io-index)": {
                    "bins": [binary.file_stem().unwrap().to_string_lossy()]
                }
            }
        });
        std::fs::write(
            root.path().join(".crates2.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();

        assert_eq!(
            detect_install_method_from_path(Some(&binary)).name(),
            "cargo"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_metadata_symlink_cannot_claim_the_active_executable() {
        use std::os::unix::fs::symlink;

        let working_dir = std::env::current_dir().unwrap();
        let root = tempfile::tempdir_in(&working_dir).unwrap();
        let external = tempfile::tempdir_in(&working_dir).unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join("lpm-rs");
        std::fs::write(&binary, b"").unwrap();
        let external_metadata = external.path().join("cargo-metadata.json");
        std::fs::write(
            &external_metadata,
            br#"{"installs":{"lpm-cli 0.74.1":{"bins":["lpm-rs"]}}}"#,
        )
        .unwrap();
        symlink(&external_metadata, root.path().join(".crates2.json")).unwrap();

        let error =
            detect_install_method_from_path_with_roots(Some(&binary), &InstallRoots::default())
                .expect_err("symlinked Cargo ownership metadata must fail closed");

        assert!(error.to_string().contains("invalid Cargo install metadata"));
    }

    #[cfg(unix)]
    #[test]
    fn shared_writable_cargo_metadata_cannot_claim_the_active_executable() {
        use std::os::unix::fs::PermissionsExt;

        let working_dir = std::env::current_dir().unwrap();
        let root = tempfile::tempdir_in(&working_dir).unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join("lpm-rs");
        std::fs::write(&binary, b"").unwrap();
        let metadata = root.path().join(".crates2.json");
        std::fs::write(
            &metadata,
            br#"{"installs":{"lpm-cli 0.74.1":{"bins":["lpm-rs"]}}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o666)).unwrap();

        let error =
            detect_install_method_from_path_with_roots(Some(&binary), &InstallRoots::default())
                .expect_err("shared-writable Cargo ownership metadata must fail closed");

        assert!(error.to_string().contains("invalid Cargo install metadata"));
    }

    #[test]
    fn cargo_bin_directory_without_matching_metadata_does_not_claim_ownership() {
        let root = tempdir().unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&binary, b"").unwrap();

        assert_eq!(
            detect_install_method_from_path(Some(&binary)),
            InstallMethod::Standalone
        );
    }

    #[test]
    fn empty_cargo_metadata_refuses_destructive_standalone_fallback() {
        let root = cargo_metadata_test_root();
        std::fs::write(root.path().join(".crates2.json"), br#"{"installs":{}}"#).unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&binary, b"").unwrap();

        let error =
            detect_install_method_from_path_with_roots(Some(&binary), &InstallRoots::default())
                .expect_err("a Cargo root that does not own LPM must fail closed");

        assert!(error.to_string().contains("does not claim"));
    }

    #[test]
    fn conventional_cargo_path_without_metadata_refuses_standalone_fallback() {
        let path = Path::new("/Users/x/.cargo/bin/lpm");

        let error =
            detect_install_method_from_path_with_roots(Some(path), &InstallRoots::default())
                .expect_err("a conventional Cargo path without metadata must fail closed");

        assert!(error.to_string().contains("Cargo-shaped"));
    }

    #[test]
    fn malformed_cargo_metadata_fails_closed_for_a_cargo_shaped_path() {
        let root = cargo_metadata_test_root();
        std::fs::write(root.path().join(".crates2.json"), b"{").unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&binary, b"").unwrap();

        let error =
            detect_install_method_from_path_with_roots(Some(&binary), &InstallRoots::default())
                .unwrap_err();

        assert!(error.to_string().contains("invalid Cargo install metadata"));
    }

    #[test]
    fn oversized_cargo_metadata_fails_closed_for_a_cargo_shaped_path() {
        let root = cargo_metadata_test_root();
        let metadata = vec![b' '; CARGO_INSTALL_METADATA_LIMIT as usize + 1];
        std::fs::write(root.path().join(".crates2.json"), metadata).unwrap();
        let bin_dir = root.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = bin_dir.join(if cfg!(windows) {
            "lpm-rs.exe"
        } else {
            "lpm-rs"
        });
        std::fs::write(&binary, b"").unwrap();

        let error =
            detect_install_method_from_path_with_roots(Some(&binary), &InstallRoots::default())
                .unwrap_err();

        assert!(error.to_string().contains("invalid Cargo install metadata"));
    }

    #[test]
    fn install_method_command_npm_pins_exact_version() {
        let cmd = InstallMethod::Npm.command("0.25.0", None).unwrap();
        assert!(cmd.contains("@lpm-registry/cli@0.25.0"), "cmd: {cmd}");
        assert!(!cmd.contains("@latest"), "must not use @latest: {cmd}");
    }

    #[test]
    fn explicit_stable_to_nightly_switch_installs_target() {
        assert!(should_install_update(
            "0.71.0",
            "0.72.0-nightly.20260728.42.d82ceea",
            ReleaseChannel::Stable,
            ReleaseChannel::Nightly,
        ));
    }

    #[test]
    fn installed_nightly_advances_to_next_nightly() {
        assert!(should_install_update(
            "0.72.0-nightly.20260728.41.aaaaaaa",
            "0.72.0-nightly.20260728.42.d82ceea",
            ReleaseChannel::Nightly,
            ReleaseChannel::Nightly,
        ));
    }

    #[test]
    fn explicit_nightly_to_older_stable_switch_allows_semver_downgrade() {
        assert!(should_install_update(
            "0.72.0-nightly.20260728.42.d82ceea",
            "0.71.0",
            ReleaseChannel::Nightly,
            ReleaseChannel::Stable,
        ));
    }

    #[test]
    fn same_channel_does_not_install_equal_or_older_version() {
        assert!(!should_install_update(
            "0.71.0",
            "0.71.0",
            ReleaseChannel::Stable,
            ReleaseChannel::Stable,
        ));
        assert!(!should_install_update(
            "0.71.0",
            "0.70.0",
            ReleaseChannel::Stable,
            ReleaseChannel::Stable,
        ));
    }

    #[test]
    fn nightly_channel_is_limited_to_registry_managers_and_standalone_installs() {
        for method in [
            InstallMethod::Npm,
            InstallMethod::Pnpm,
            InstallMethod::Bun,
            InstallMethod::Yarn,
            InstallMethod::Volta,
        ] {
            assert!(
                method
                    .ensure_channel_supported(ReleaseChannel::Nightly)
                    .is_ok(),
                "method {method:?}"
            );
        }
        assert!(
            InstallMethod::Standalone
                .ensure_channel_supported(ReleaseChannel::Nightly)
                .is_ok()
        );
        for method in [InstallMethod::Homebrew, InstallMethod::Cargo] {
            let error = method
                .ensure_channel_supported(ReleaseChannel::Nightly)
                .unwrap_err();
            assert!(
                error.to_string().contains("nightly channel"),
                "method {method:?}: {error}"
            );
        }
    }

    #[test]
    fn self_update_channel_argument_parses() {
        use clap::Parser;

        for (argument, expected) in [
            ("stable", ReleaseChannel::Stable),
            ("nightly", ReleaseChannel::Nightly),
        ] {
            let cli =
                crate::Cli::try_parse_from(["lpm", "self-update", "--channel", argument]).unwrap();
            let Some(crate::Commands::SelfUpdate(args)) = cli.command else {
                panic!("expected self-update command")
            };
            assert_eq!(args.channel, Some(expected));
        }
    }

    #[test]
    fn install_method_command_cargo_uses_verified_revision() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let cmd = InstallMethod::Cargo
            .command("0.25.0", Some(source_commit))
            .unwrap();
        assert!(
            cmd.contains(&format!("--rev {source_commit}")),
            "cmd: {cmd}"
        );
        assert!(!cmd.contains("--tag"), "cmd: {cmd}");
        assert!(cmd.contains("--force"), "cmd: {cmd}");
    }

    #[test]
    fn cargo_install_arguments_use_verified_source_commit_instead_of_tag() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let args = cargo_install_args(source_commit, None);
        assert!(
            args.windows(2).any(|pair| pair == ["--rev", source_commit]),
            "Cargo arguments do not bind the verified commit: {args:?}"
        );
        assert!(!args.iter().any(|arg| arg == "--tag"));
    }

    #[test]
    fn cargo_install_arguments_preserve_the_detected_install_root() {
        let source_commit = "1e98fb8efbcc00f620678fc8091b512ed503768f";
        let root = Path::new("/opt/custom-cargo");
        let args = cargo_install_args(source_commit, Some(root));

        assert!(
            args.windows(2)
                .any(|pair| pair == ["--root", "/opt/custom-cargo"]),
            "Cargo arguments must update the root that owns the running binary: {args:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_install_root_uses_the_already_resolved_executable() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("lpm-rs");
        std::fs::write(&executable, b"").unwrap();
        let shim_dir = tempdir().unwrap();
        let shim = shim_dir.path().join("lpm");
        symlink(&executable, &shim).unwrap();
        let resolved = std::fs::canonicalize(shim).unwrap();

        assert_eq!(
            cargo_install_root(&resolved).unwrap(),
            std::fs::canonicalize(root.path()).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_update_plan_shell_quotes_a_root_with_spaces_and_metacharacters() {
        let command = InstallMethod::Cargo
            .external_update_command_with_root(
                "0.75.0",
                Some("1e98fb8efbcc00f620678fc8091b512ed503768f"),
                Some(Path::new("/opt/Cargo Root;echo owned")),
            )
            .unwrap()
            .unwrap()
            .render()
            .unwrap();

        assert!(command.contains("--root '/opt/Cargo Root;echo owned'"));
    }

    #[test]
    fn powershell_update_plan_quotes_unicode_spaces_and_metacharacters() {
        let command = render_powershell_invocation(
            "cargo",
            &["install", "C:\\Cargo Root Ω;Write-Output owned's"],
        );

        assert_eq!(
            command,
            "& 'cargo' 'install' 'C:\\Cargo Root Ω;Write-Output owned''s'"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_update_preserves_a_non_utf8_install_root_as_an_os_argument() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let root = PathBuf::from(OsString::from_vec(b"/opt/cargo-\xff".to_vec()));
        let args = cargo_install_args("1e98fb8efbcc00f620678fc8091b512ed503768f", Some(&root));
        let root_index = args.iter().position(|arg| arg == "--root").unwrap() + 1;
        assert_eq!(args[root_index].as_bytes(), root.as_os_str().as_bytes());

        let error = ExternalUpdateCommand::new("cargo", args)
            .render()
            .unwrap_err();
        assert!(error.to_string().contains("non-UTF-8 argument"));
    }

    #[test]
    fn install_method_command_homebrew_unchanged() {
        assert_eq!(
            InstallMethod::Homebrew.command("0.25.0", None).unwrap(),
            "brew upgrade lpm"
        );
    }

    #[test]
    fn standalone_update_does_not_expose_an_unverified_equivalent_command() {
        let error = InstallMethod::Standalone
            .command("0.25.0", None)
            .expect_err("the verified built-in updater has no shell-command equivalent");

        assert!(error.to_string().contains("built-in signed updater"));
    }

    #[test]
    fn detect_platform_returns_valid_tuple() {
        let result = detect_platform();
        assert!(
            result.is_ok(),
            "detect_platform should succeed on this host"
        );
        let (platform, _ext) = result.unwrap();
        assert!(!platform.is_empty());
        assert!(
            [
                "darwin-arm64",
                "darwin-x64",
                "linux-x64",
                "linux-arm64",
                "win32-x64",
            ]
            .contains(&platform),
            "unexpected platform: {platform}"
        );
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(2_621_440), "2.5 MB");
    }

    /// Rate-limit lands on `SelfUpdateRateLimited`, not `Forbidden`.
    /// `Forbidden` is the user-permission category and reads to users
    /// as "you're banned" — wrong category for a quota-reset wait.
    #[test]
    fn lookup_error_rate_limit_maps_to_self_update_rate_limited() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        assert!(
            matches!(err, LpmError::SelfUpdateRateLimited(_)),
            "got {err:?}"
        );
        // And — explicitly NOT Forbidden, the historical wrong category.
        assert!(
            !matches!(err, LpmError::Forbidden(_)),
            "must not regress to Forbidden: {err:?}"
        );
    }

    /// Rendered body must not duplicate the GITHUB_TOKEN hint — that
    /// guidance now lives in the variant's diagnostic help text. Doubling
    /// it would print the same instruction twice.
    #[test]
    fn lookup_error_rate_limit_body_is_not_doubled_with_help_text() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        let LpmError::SelfUpdateRateLimited(body) = err else {
            panic!("expected SelfUpdateRateLimited variant");
        };
        assert!(
            !body.contains("GITHUB_TOKEN"),
            "body must not duplicate help text: {body}"
        );
        assert!(
            !body.contains("GH_TOKEN"),
            "body must not duplicate help text: {body}"
        );
    }

    #[test]
    fn lookup_error_transport_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::Transport("dns failed".into()));
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    #[test]
    fn lookup_error_http_status_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::HttpStatus {
            status: 503,
            body_excerpt: "down".into(),
        });
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    /// Once an exact version has been verified, every installation
    /// channel records the same cache contract.
    #[test]
    fn post_upgrade_cache_policy_pinning_channels_stamp() {
        for method in [
            InstallMethod::Standalone,
            InstallMethod::Cargo,
            InstallMethod::Npm,
            InstallMethod::Pnpm,
            InstallMethod::Bun,
            InstallMethod::Yarn,
            InstallMethod::Volta,
            InstallMethod::Homebrew,
        ] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("update-check.json");
            let cache = UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                ..Default::default()
            };
            write_cache_at(&path, &cache).unwrap();
            // Mirror the post-upgrade branch logic against the path.
            let mut after = read_cache_at(&path).unwrap();
            after.latest = "0.25.0".into();
            after.last_check = 1_700_000_000;
            after.last_failure_check = 0;
            write_cache_at(&path, &after).unwrap();
            let loaded = read_cache_at(&path).unwrap();
            assert_eq!(loaded.latest, "0.25.0", "method {method:?}");
        }
    }

    /// `--refresh` is supposed to bypass the in-process cache hit
    /// short-circuit. Lock the cache-hit predicate that gates it.
    #[test]
    fn refresh_flag_bypasses_cache_hit_predicate() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 60,
            ..Default::default()
        };
        let refresh = false;
        let predicate = |refresh: bool| -> bool {
            !refresh
                && !cache.latest.is_empty()
                && cache.last_check > 0
                && now.saturating_sub(cache.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(
            predicate(refresh),
            "fresh cache must hit when refresh=false"
        );
        assert!(!predicate(true), "refresh=true must bypass the cache hit");
    }

    /// Recent failure must short-circuit BEFORE the network call so a
    /// script looping on `lpm self-update` after a 403 doesn't re-hit
    /// the rate-limited API on every iteration.
    #[test]
    fn recent_failure_triggers_backoff_without_refresh() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 60,
            ..Default::default()
        };
        let predicate = |refresh: bool, cache_hit: bool| -> bool {
            !refresh
                && !cache_hit
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(
            predicate(false, false),
            "default invocation must respect backoff"
        );
        assert!(!predicate(true, false), "--refresh must bypass the backoff");
        assert!(
            !predicate(false, true),
            "fresh success cache pre-empts backoff"
        );
    }

    #[test]
    fn failure_backoff_lapses_past_ttl() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 4000, // > 1h
            ..Default::default()
        };
        let predicate = |refresh: bool| -> bool {
            !refresh
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(!predicate(false));
    }

    #[test]
    fn humanize_seconds_picks_largest_unit() {
        assert_eq!(humanize_seconds(0), "0 seconds");
        assert_eq!(humanize_seconds(1), "1 second");
        assert_eq!(humanize_seconds(45), "45 seconds");
        assert_eq!(humanize_seconds(60), "1 minute");
        assert_eq!(humanize_seconds(150), "2 minutes");
        assert_eq!(humanize_seconds(3600), "1 hour");
        assert_eq!(humanize_seconds(7200), "2 hours");
    }

    #[test]
    fn cache_hit_only_within_lookup_ttl() {
        let now = 1_700_000_500u64;
        let stale_cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 700, // > 10m TTL
            ..Default::default()
        };
        let predicate = |c: &UpdateCache| -> bool {
            !c.latest.is_empty()
                && c.last_check > 0
                && now.saturating_sub(c.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(!predicate(&stale_cache));
    }

    #[test]
    fn release_lookup_module_is_reachable() {
        // Smoke check: the shared module's public surface is wired
        // in. If the module is renamed or visibility changes, this
        // catches it before the CLI dispatch path breaks.
        let _ = release_lookup::default_cache_path();
    }
}
