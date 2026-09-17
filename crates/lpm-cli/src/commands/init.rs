use crate::cli::InitPackageTargetCli;
use crate::install_ui;
use crate::manifest_tx::ManifestTransaction;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_PACKAGE_NAME: &str = "package";
const DEFAULT_VERSION: &str = "1.0.0";
const DEFAULT_OWNER: &str = "username";
const AGENTS_START_MARKER: &str = "<!-- lpm:init:start -->";
const AGENTS_END_MARKER: &str = "<!-- lpm:init:end -->";
const AGENTS_SNIPPET: &str = "\
<!-- lpm:init:start -->
## Package Manager

This project uses lpm.

- Install dependencies with `lpm install`.
- Add source packages with `lpm add <package>`.
- Run scripts with `lpm run <script>`.
- Use `--json` when you need machine-readable output from lpm commands.
- CLI docs: https://cli.lpm.dev/
<!-- lpm:init:end -->
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitPackageTarget {
    Lpm,
    Npm,
}

impl InitPackageTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lpm => "lpm",
            Self::Npm => "npm",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileWriteStatus {
    Created,
    Updated,
    Unchanged,
    Skipped,
}

impl FileWriteStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
            Self::Skipped => "skipped",
        }
    }

    const fn human_verb(self) -> &'static str {
        match self {
            Self::Created => "Wrote",
            Self::Updated => "Updated",
            Self::Unchanged => "Kept",
            Self::Skipped => "Skipped",
        }
    }
}

pub(crate) struct InitOptions<'a> {
    pub(crate) yes: bool,
    pub(crate) target: Option<InitPackageTargetCli>,
    pub(crate) name: Option<&'a str>,
    pub(crate) owner: Option<&'a str>,
    pub(crate) write_agents: bool,
    pub(crate) json_output: bool,
}

struct InitAnswers {
    target: InitPackageTarget,
    name: String,
    version: String,
    description: String,
}

/// Initialize a new package.json.
pub(crate) async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    options: InitOptions<'_>,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    require_missing_manifest(&pkg_json_path)?;
    if !options.yes && (options.json_output || !std::io::stdin().is_terminal()) {
        return Err(LpmError::Registry(
            "lpm init requires --yes when prompts are unavailable or --json is used".into(),
        ));
    }

    let target = resolve_init_target(&options)?;
    let resolved_owner =
        if target == InitPackageTarget::Lpm && lpm_target_needs_owner_default(&options) {
            Some(resolve_owner_default(client).await)
        } else {
            None
        };
    let answers = collect_init_answers(&options, target, resolved_owner.as_deref())?;
    let package_manager = format!("lpm@{}", crate::build_version::version());

    let mut pkg = serde_json::json!({
        "name": answers.name,
        "version": answers.version,
        "main": "dist/index.js",
        "types": "dist/index.d.ts",
        "type": "module",
        "license": "MIT",
        "files": ["dist"],
        "packageManager": package_manager,
    });

    if !answers.description.is_empty() {
        pkg["description"] = serde_json::json!(answers.description);
    }

    let content =
        serde_json::to_string_pretty(&pkg).map_err(|e| LpmError::Registry(e.to_string()))?;

    let (agents_status, agents_update) = if options.write_agents {
        prepare_agents_snippet(project_dir)?
    } else {
        (FileWriteStatus::Skipped, None)
    };
    let mut transaction = ManifestTransaction::snapshot_install_state(&[], &[], &[])?;
    create_manifest(&pkg_json_path, &format!("{content}\n"), &mut transaction)?;
    if let Some(update) = agents_update {
        apply_agents_update(project_dir, update, &mut transaction)?;
    }
    let lpm_json_status = if answers.target == InitPackageTarget::Npm {
        ensure_npm_publish_config(project_dir, Some(&mut transaction))?
    } else {
        FileWriteStatus::Skipped
    };
    transaction.commit();

    let gitattributes_ready = match lpm_lockfile::ensure_gitattributes(project_dir) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("failed to ensure .gitattributes: {e}");
            false
        }
    };

    if options.json_output {
        let json = serde_json::json!({
            "success": true,
            "target": answers.target.as_str(),
            "name": answers.name,
            "version": answers.version,
            "path": pkg_json_path.display().to_string(),
            "package_manager": package_manager,
            "agents_path": agents_path_for_json(project_dir, agents_status),
            "agents_status": agents_status.as_str(),
            "lpm_json_path": lpm_json_path_for_json(project_dir, lpm_json_status),
            "lpm_json_status": lpm_json_status.as_str(),
            "gitattributes_ready": gitattributes_ready,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json).map_err(|e| LpmError::Registry(e.to_string()))?
        );
    } else {
        install_ui::done("Wrote package.json");
        if lpm_json_status != FileWriteStatus::Skipped {
            install_ui::done_untrusted(&format!("{} lpm.json", lpm_json_status.human_verb()));
        }
        if agents_status != FileWriteStatus::Skipped {
            install_ui::done_untrusted(&format!("{} AGENTS.md", agents_status.human_verb()));
        }
        if gitattributes_ready {
            install_ui::done("Added lpm.lockb binary to .gitattributes");
        } else {
            install_ui::warn("Could not update .gitattributes");
        }
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · initialized {}",
            install_ui::cyan(pkg["name"].as_str().unwrap_or(DEFAULT_PACKAGE_NAME))
        ));
    }

    Ok(())
}

fn collect_init_answers(
    options: &InitOptions<'_>,
    target: InitPackageTarget,
    resolved_owner: Option<&str>,
) -> Result<InitAnswers, LpmError> {
    if target == InitPackageTarget::Npm && options.owner.is_some() {
        return Err(LpmError::Registry(
            "`--owner` only applies to lpm.dev packages; remove it or use `--lpm`".into(),
        ));
    }

    let (name, owner) = match target {
        InitPackageTarget::Lpm => {
            let (owner, package_name) =
                resolve_lpm_name_inputs(options, resolved_owner.unwrap_or(DEFAULT_OWNER))?;
            let package = PackageName::parse(&format!("{owner}.{package_name}"))?;
            (package.scoped(), Some(package.owner))
        }
        InitPackageTarget::Npm => {
            let name = resolve_npm_name_input(options)?;
            validate_npm_init_name(&name)?;
            (name, None)
        }
    };

    let version = if options.yes {
        DEFAULT_VERSION.to_string()
    } else {
        prompt_string(
            "Version",
            Some(DEFAULT_VERSION),
            Some(DEFAULT_VERSION),
            true,
        )?
    };

    super::publish::validate_publish_version(&version).map_err(|error| {
        LpmError::Registry(format!("invalid package version '{version}': {error}"))
    })?;

    let description = if options.yes {
        String::new()
    } else {
        prompt_string(
            "Description",
            None,
            Some("A brief description of your package"),
            false,
        )?
    };

    if let Some(owner) = owner {
        validate_lpm_owner(&owner)?;
    }

    Ok(InitAnswers {
        target,
        name,
        version,
        description,
    })
}

fn resolve_init_target(options: &InitOptions<'_>) -> Result<InitPackageTarget, LpmError> {
    match options.target {
        Some(InitPackageTargetCli::Lpm) => return Ok(InitPackageTarget::Lpm),
        Some(InitPackageTargetCli::Npm) => return Ok(InitPackageTarget::Npm),
        None => {}
    }

    if options.yes {
        return Ok(InitPackageTarget::Lpm);
    }
    let choice: &str = cliclack::select("Package target?")
        .item("lpm", "lpm.dev package", "@lpm.dev/<owner>.<name>")
        .item("npm", "npm-compatible package", "publish target: npm")
        .initial_value("lpm")
        .interact()
        .map_err(|e| LpmError::Registry(e.to_string()))?;

    match choice {
        "lpm" => Ok(InitPackageTarget::Lpm),
        "npm" => Ok(InitPackageTarget::Npm),
        _ => Err(LpmError::Registry("invalid init package target".into())),
    }
}

fn resolve_lpm_name_inputs(
    options: &InitOptions<'_>,
    resolved_owner: &str,
) -> Result<(String, String), LpmError> {
    if let Some(name) = options.name.map(str::trim) {
        let unscoped = name.strip_prefix("@lpm.dev/").unwrap_or(name);
        if unscoped.contains(['@', '?']) {
            return Err(LpmError::InvalidPackageName(
                "init requires a package name without a version or query suffix".into(),
            ));
        }
        if name.starts_with('@') || name.contains('.') {
            let parsed = PackageName::parse(name)?;
            if let Some(owner) = options.owner.map(str::trim)
                && owner != parsed.owner
            {
                return Err(LpmError::InvalidPackageName(format!(
                    "`--owner {owner}` does not match package name `{name}`"
                )));
            }
            validate_lpm_owner(&parsed.owner)?;
            return Ok((parsed.owner, parsed.name));
        }
    }

    let owner = match (options.yes, options.owner) {
        (_, Some(owner)) => owner.trim().to_string(),
        (true, None) => resolved_owner.to_string(),
        (false, None) => prompt_string(
            "Owner (your username or org)",
            Some(resolved_owner),
            Some("username"),
            true,
        )?,
    };
    validate_lpm_owner(&owner)?;

    let package_name = match (options.yes, options.name) {
        (_, Some(name)) => name.trim().to_string(),
        (true, None) => DEFAULT_PACKAGE_NAME.to_string(),
        (false, None) => prompt_string(
            "Package name",
            Some(DEFAULT_PACKAGE_NAME),
            Some(DEFAULT_PACKAGE_NAME),
            true,
        )?,
    };
    if package_name.contains(['@', '?']) {
        return Err(LpmError::InvalidPackageName(
            "init requires a package name without a version or query suffix".into(),
        ));
    }

    Ok((owner, package_name))
}

fn lpm_target_needs_owner_default(options: &InitOptions<'_>) -> bool {
    if options.owner.is_some() {
        return false;
    }

    match options.name.map(str::trim) {
        Some(name) if name.starts_with("@lpm.dev/") => false,
        Some(name) if name.contains('.') => false,
        _ => true,
    }
}

fn resolve_npm_name_input(options: &InitOptions<'_>) -> Result<String, LpmError> {
    match (options.yes, options.name) {
        (_, Some(name)) => Ok(name.trim().to_string()),
        (true, None) => Ok(DEFAULT_PACKAGE_NAME.to_string()),
        (false, None) => prompt_string(
            "Package name",
            Some(DEFAULT_PACKAGE_NAME),
            Some(DEFAULT_PACKAGE_NAME),
            true,
        ),
    }
}

fn prompt_string(
    label: &str,
    default: Option<&str>,
    placeholder: Option<&str>,
    required: bool,
) -> Result<String, LpmError> {
    let mut prompt = cliclack::input(crate::prompt::untrusted(label));
    if let Some(default) = default {
        prompt = prompt.default_input(&crate::prompt::untrusted(default));
    }
    if let Some(placeholder) = placeholder {
        prompt = prompt.placeholder(&crate::prompt::untrusted(placeholder));
    }
    if !required {
        prompt = prompt.required(false);
    }
    prompt
        .interact()
        .map_err(|e| LpmError::Registry(e.to_string()))
}

fn validate_lpm_owner(owner: &str) -> Result<(), LpmError> {
    if owner.is_empty() {
        return Err(LpmError::InvalidPackageName(
            "lpm.dev owner cannot be empty".into(),
        ));
    }
    if !owner
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(LpmError::InvalidPackageName(format!(
            "lpm.dev owner '{owner}' must use lowercase a-z, 0-9, or -"
        )));
    }
    Ok(())
}

fn validate_npm_init_name(name: &str) -> Result<(), LpmError> {
    super::publish_npm::validate_npm_name(name)
}

fn ensure_npm_publish_config(
    project_dir: &Path,
    mut transaction: Option<&mut ManifestTransaction>,
) -> Result<FileWriteStatus, LpmError> {
    lpm_common::update_lpm_json(project_dir, |obj, file_state| {
        let publish = obj
            .entry("publish".to_string())
            .or_insert_with(|| serde_json::json!({}));
        let publish_obj = publish
            .as_object_mut()
            .ok_or_else(|| "lpm.json publish field must be an object".to_string())?;

        let registries = publish_obj
            .entry("registries".to_string())
            .or_insert_with(|| serde_json::json!([]));
        let Some(registries_array) = registries.as_array_mut() else {
            return Err("lpm.json publish.registries must be an array".into());
        };

        let changed = registries_array.is_empty();
        if registries_array.is_empty() {
            registries_array.push(serde_json::json!("npm"));
        } else if registries_array.len() != 1
            || registries_array.first().and_then(|v| v.as_str()) != Some("npm")
        {
            return Err(
                "lpm init --npm requires lpm.json publish.registries to be empty or [\"npm\"]"
                    .into(),
            );
        }

        let status = match file_state {
            lpm_common::LpmJsonFileState::Missing => FileWriteStatus::Created,
            lpm_common::LpmJsonFileState::Existing if changed => FileWriteStatus::Updated,
            lpm_common::LpmJsonFileState::Existing => FileWriteStatus::Unchanged,
        };
        if changed && let Some(transaction) = transaction.as_mut() {
            let path = project_dir.join("lpm.json");
            let original = match file_state {
                lpm_common::LpmJsonFileState::Missing => None,
                lpm_common::LpmJsonFileState::Existing => Some(
                    lpm_common::read_text_file_capped_nofollow(
                        &path,
                        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                    )
                    .map_err(|error| error.to_string())?
                    .into_bytes(),
                ),
            };
            let expected = format!(
                "{}\n",
                serde_json::to_string_pretty(obj).map_err(|error| error.to_string())?
            );
            transaction
                .snapshot_optional_path_with_bytes(&path, original)
                .map_err(|error| error.to_string())?;
            // The config writer can fail its directory sync after the replacement succeeds.
            transaction
                .restore_only_if_unchanged(&path, expected.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        Ok(
            if changed || matches!(file_state, lpm_common::LpmJsonFileState::Missing) {
                lpm_common::LpmJsonMutation::Changed(status)
            } else {
                lpm_common::LpmJsonMutation::Unchanged(status)
            },
        )
    })
    .map(lpm_common::LpmJsonMutation::into_inner)
    .map_err(|error| LpmError::Registry(error.to_string()))
}

#[cfg(all(test, unix))]
mod lpm_json_mutation_tests {
    use super::*;

    #[test]
    fn npm_publish_config_does_not_follow_lpm_json_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "{}\n").unwrap();
        symlink(outside.path(), dir.path().join("lpm.json")).unwrap();

        let error = ensure_npm_publish_config(dir.path(), None)
            .expect_err("mutating a symlinked lpm.json must be rejected");

        assert!(error.to_string().contains("symbolic link"));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "{}\n");
    }

    #[test]
    fn npm_publish_config_reports_unchanged_when_npm_is_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.json");
        std::fs::write(&path, "{\"publish\":{\"registries\":[\"npm\"]}}\n").unwrap();

        let first = ensure_npm_publish_config(dir.path(), None).unwrap();
        let after_first = std::fs::read_to_string(&path).unwrap();
        let second = ensure_npm_publish_config(dir.path(), None).unwrap();

        assert_eq!(first, FileWriteStatus::Unchanged);
        assert_eq!(second, FileWriteStatus::Unchanged);
        assert_eq!(std::fs::read_to_string(path).unwrap(), after_first);
    }
}

fn require_missing_manifest(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(LpmError::Registry("package.json already exists".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_manifest(
    path: &Path,
    content: &str,
    transaction: &mut ManifestTransaction,
) -> Result<(), LpmError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".lpm-init-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut temporary = builder.tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))?;
    temporary.write_all(content.as_bytes())?;
    temporary.as_file().sync_all()?;
    // Commit without replacement: another process can create a manifest while we prompt.
    temporary
        .persist_noclobber(path)
        .map_err(|error| LpmError::Io(error.error))?;
    transaction.snapshot_optional_path_with_bytes(path, None)?;
    transaction.restore_only_if_unchanged(path, content.as_bytes())?;
    Ok(())
}

struct AgentsUpdate {
    original: Option<String>,
    updated: String,
}

fn read_agents(path: &Path) -> Result<Option<String>, LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() => {
            return Err(LpmError::Registry(
                "AGENTS.md must be a regular file, not a link or special file".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    lpm_common::read_text_file_capped_nofollow(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map(Some)
        .map_err(|error| LpmError::Registry(error.to_string()))
}

fn prepare_agents_snippet(
    project_dir: &Path,
) -> Result<(FileWriteStatus, Option<AgentsUpdate>), LpmError> {
    let original = read_agents(&project_dir.join("AGENTS.md"))?;
    let Some(current) = original.as_deref() else {
        return Ok((
            FileWriteStatus::Created,
            Some(AgentsUpdate {
                original: None,
                updated: AGENTS_SNIPPET.to_string(),
            }),
        ));
    };
    if current.contains(AGENTS_SNIPPET.trim_end()) {
        return Ok((FileWriteStatus::Unchanged, None));
    }
    let updated = replace_or_append_agents_snippet(current)?;
    if updated == current {
        return Ok((FileWriteStatus::Unchanged, None));
    }
    if updated.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Registry(
            "updated AGENTS.md exceeds the configuration file size limit".into(),
        ));
    }
    Ok((
        FileWriteStatus::Updated,
        Some(AgentsUpdate { original, updated }),
    ))
}

fn apply_agents_update(
    project_dir: &Path,
    update: AgentsUpdate,
    transaction: &mut ManifestTransaction,
) -> Result<(), LpmError> {
    let path = project_dir.join("AGENTS.md");
    if read_agents(&path)? != update.original {
        return Err(LpmError::Registry(
            "AGENTS.md changed during initialization; retry the command".into(),
        ));
    }
    transaction
        .snapshot_optional_path_with_bytes(&path, update.original.map(String::into_bytes))?;
    transaction.restore_only_if_unchanged(&path, update.updated.as_bytes())?;
    lpm_common::write_file_atomic(&path, update.updated)?;
    Ok(())
}

fn replace_or_append_agents_snippet(current: &str) -> Result<String, LpmError> {
    let Some(start) = current.find(AGENTS_START_MARKER) else {
        if has_unmanaged_lpm_agents_guidance(current) {
            return Ok(current.to_string());
        }
        let mut updated = String::with_capacity(current.len() + AGENTS_SNIPPET.len() + 2);
        updated.push_str(current.trim_end());
        if !updated.is_empty() {
            updated.push_str("\n\n");
        }
        updated.push_str(AGENTS_SNIPPET);
        return Ok(updated);
    };

    let end = current[start..]
        .find(AGENTS_END_MARKER)
        .map(|end| start + end + AGENTS_END_MARKER.len())
        .ok_or_else(|| {
            LpmError::Registry(
                "AGENTS.md has an lpm init start marker without a matching end marker".into(),
            )
        })?;

    let mut updated = String::with_capacity(current.len() + AGENTS_SNIPPET.len());
    updated.push_str(&current[..start]);
    updated.push_str(AGENTS_SNIPPET.trim_end());
    updated.push_str(&current[end..]);
    Ok(updated)
}

fn has_unmanaged_lpm_agents_guidance(current: &str) -> bool {
    current.contains("This project uses lpm.")
        && current.contains("lpm install")
        && current.contains("lpm add")
}

fn agents_path_for_json(project_dir: &Path, status: FileWriteStatus) -> Option<String> {
    (status != FileWriteStatus::Skipped).then(|| display_path(project_dir.join("AGENTS.md")))
}

fn lpm_json_path_for_json(project_dir: &Path, status: FileWriteStatus) -> Option<String> {
    (status != FileWriteStatus::Skipped).then(|| display_path(project_dir.join("lpm.json")))
}

fn display_path(path: PathBuf) -> String {
    path.display().to_string()
}

/// Look up the logged-in user's lpm.dev profile name to pre-fill the owner
/// default. Falls back to the literal `"username"` on any failure (offline,
/// no token, expired session, profile not set on the account) — init must
/// not block on the network or fail for users who haven't logged in yet.
async fn resolve_owner_default(client: &RegistryClient) -> String {
    const TIMEOUT: Duration = Duration::from_secs(3);

    match tokio::time::timeout(TIMEOUT, client.whoami()).await {
        Ok(Ok(user)) => user
            .profile_username
            .unwrap_or_else(|| DEFAULT_OWNER.to_string()),
        _ => DEFAULT_OWNER.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_npm_init_name_rejects_reserved_lpm_scope() {
        let err = validate_npm_init_name("@lpm.dev/owner.pkg").unwrap_err();
        assert!(
            err.to_string().contains("@lpm.dev"),
            "error should name the reserved lpm.dev scope: {err}"
        );
    }

    #[test]
    fn validate_npm_init_name_rejects_malformed_scoped_name() {
        let err = validate_npm_init_name("@scope").unwrap_err();
        assert!(
            err.to_string().contains("one slash"),
            "error should explain scoped npm syntax: {err}"
        );
    }

    #[test]
    fn replace_or_append_agents_snippet_replaces_existing_managed_block() {
        let current = format!(
            "# Rules\n\n{AGENTS_START_MARKER}\nold\n{AGENTS_END_MARKER}\n\n## After\nkeep\n"
        );
        let updated = replace_or_append_agents_snippet(&current).unwrap();

        assert!(updated.contains("This project uses lpm."));
        assert!(updated.contains("## After\nkeep"));
        assert!(updated.contains("Use `--json` when you need machine-readable output"));
        assert!(!updated.contains("Keep `lpm.lock`"));
        assert!(!updated.contains("\nold\n"));
    }

    #[test]
    fn replace_or_append_agents_snippet_upgrades_partial_lpm_guidance() {
        let current = "# Rules\n\nThis project uses lpm.\n";
        let updated = replace_or_append_agents_snippet(current).unwrap();

        assert!(updated.contains(AGENTS_START_MARKER));
        assert!(updated.contains("Install dependencies with `lpm install`."));
        assert!(updated.contains("Add source packages with `lpm add <package>`."));
        assert!(updated.contains("Use `--json` when you need machine-readable output"));
    }
}
