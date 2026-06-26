use crate::cli::InitPackageTargetCli;
use crate::install_ui;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use std::io::IsTerminal;
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
- Keep `lpm.lock` and `lpm.lockb` in sync by using lpm commands.
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
    if pkg_json_path.exists() {
        return Err(LpmError::Registry("package.json already exists".into()));
    }

    let target = resolve_init_target(&options)?;
    let resolved_owner =
        if target == InitPackageTarget::Lpm && lpm_target_needs_owner_default(&options) {
            Some(resolve_owner_default(client).await)
        } else {
            None
        };
    let answers = collect_init_answers(&options, target, resolved_owner.as_deref())?;
    let package_manager = format!("lpm@{}", env!("CARGO_PKG_VERSION"));

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

    let lpm_json_status = if answers.target == InitPackageTarget::Npm {
        ensure_npm_publish_config(project_dir)?
    } else {
        FileWriteStatus::Skipped
    };

    std::fs::write(&pkg_json_path, format!("{content}\n"))?;

    let agents_status = if options.write_agents {
        ensure_agents_snippet(project_dir)?
    } else {
        FileWriteStatus::Skipped
    };

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
            install_ui::done(&format!("{} lpm.json", lpm_json_status.human_verb()));
        }
        if agents_status != FileWriteStatus::Skipped {
            install_ui::done(&format!("{} AGENTS.md", agents_status.human_verb()));
        }
        if gitattributes_ready {
            install_ui::done("Added lpm.lockb binary to .gitattributes");
        } else {
            install_ui::warn("Could not update .gitattributes");
        }
        install_ui::done(&format!(
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
    if matches!(options.target, Some(InitPackageTargetCli::Npm)) && options.owner.is_some() {
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
    if !std::io::stdin().is_terminal() || options.json_output {
        return Err(LpmError::Registry(
            "lpm init needs --lpm, --npm, or -y when prompts are unavailable".into(),
        ));
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
        if name.starts_with("@lpm.dev/") {
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

        if options.owner.is_none() && name.contains('.') {
            let parsed = PackageName::parse(name)?;
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
    let mut prompt = cliclack::input(label);
    if let Some(default) = default {
        prompt = prompt.default_input(default);
    }
    if let Some(placeholder) = placeholder {
        prompt = prompt.placeholder(placeholder);
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
    if name.is_empty() {
        return Err(LpmError::InvalidPackageName(
            "npm package name cannot be empty".into(),
        ));
    }
    if name.len() > 214 {
        return Err(LpmError::InvalidPackageName(format!(
            "npm package name too long ({} chars, max 214)",
            name.len()
        )));
    }
    if name.starts_with("@lpm.dev/") {
        return Err(LpmError::InvalidPackageName(
            "npm package names cannot use the reserved @lpm.dev/ scope".into(),
        ));
    }
    if name == "node_modules" || name == "favicon.ico" {
        return Err(LpmError::InvalidPackageName(format!(
            "npm package name '{name}' is reserved"
        )));
    }

    if let Some(rest) = name.strip_prefix('@') {
        let Some((scope, package)) = rest.split_once('/') else {
            return Err(LpmError::InvalidPackageName(format!(
                "scoped npm package '{name}' must be in @scope/name format"
            )));
        };
        validate_npm_name_part(scope, "scope", name)?;
        validate_npm_name_part(package, "package", name)?;
        return Ok(());
    }

    if name.contains('/') {
        return Err(LpmError::InvalidPackageName(format!(
            "unscoped npm package name cannot contain '/': {name}"
        )));
    }
    validate_npm_name_part(name, "package", name)
}

fn validate_npm_name_part(part: &str, label: &str, full_name: &str) -> Result<(), LpmError> {
    if part.is_empty() {
        return Err(LpmError::InvalidPackageName(format!(
            "npm {label} cannot be empty in '{full_name}'"
        )));
    }
    if part.starts_with('.') || part.starts_with('_') {
        return Err(LpmError::InvalidPackageName(format!(
            "npm {label} cannot start with '.' or '_' in '{full_name}'"
        )));
    }
    if part != part.to_ascii_lowercase() {
        return Err(LpmError::InvalidPackageName(format!(
            "npm package name must be lowercase: '{full_name}'"
        )));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err(LpmError::InvalidPackageName(format!(
            "npm {label} contains invalid characters in '{full_name}'"
        )));
    }
    Ok(())
}

fn ensure_npm_publish_config(project_dir: &Path) -> Result<FileWriteStatus, LpmError> {
    let path = project_dir.join("lpm.json");
    let mut value = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str::<serde_json::Value>(&content)
            .map_err(|e| LpmError::Registry(format!("failed to parse lpm.json: {e}")))?
    } else {
        serde_json::json!({})
    };

    let obj = value
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("lpm.json must be a JSON object".into()))?;

    let publish = obj
        .entry("publish".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let publish_obj = publish
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("lpm.json publish field must be an object".into()))?;

    let registries = publish_obj
        .entry("registries".to_string())
        .or_insert_with(|| serde_json::json!([]));
    let Some(registries_array) = registries.as_array_mut() else {
        return Err(LpmError::Registry(
            "lpm.json publish.registries must be an array".into(),
        ));
    };

    if registries_array.is_empty() {
        registries_array.push(serde_json::json!("npm"));
    } else if registries_array.len() != 1
        || registries_array.first().and_then(|v| v.as_str()) != Some("npm")
    {
        return Err(LpmError::Registry(
            "lpm init --npm requires lpm.json publish.registries to be empty or [\"npm\"]".into(),
        ));
    }

    let rendered =
        serde_json::to_string_pretty(&value).map_err(|e| LpmError::Registry(e.to_string()))?;
    let rendered = format!("{rendered}\n");
    if path.exists() {
        let current = std::fs::read_to_string(&path)?;
        if current == rendered {
            return Ok(FileWriteStatus::Unchanged);
        }
        std::fs::write(path, rendered)?;
        Ok(FileWriteStatus::Updated)
    } else {
        std::fs::write(path, rendered)?;
        Ok(FileWriteStatus::Created)
    }
}

fn ensure_agents_snippet(project_dir: &Path) -> Result<FileWriteStatus, LpmError> {
    let path = project_dir.join("AGENTS.md");
    if !path.exists() {
        std::fs::write(path, AGENTS_SNIPPET)?;
        return Ok(FileWriteStatus::Created);
    }

    let current = std::fs::read_to_string(&path)?;
    if current.contains(AGENTS_SNIPPET.trim_end()) {
        return Ok(FileWriteStatus::Unchanged);
    }
    let updated = replace_or_append_agents_snippet(&current)?;
    if updated == current {
        return Ok(FileWriteStatus::Unchanged);
    }
    std::fs::write(path, updated)?;
    Ok(FileWriteStatus::Updated)
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
    updated.push_str(current[..start].trim_end());
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(AGENTS_SNIPPET.trim_end());
    updated.push('\n');
    let tail = current[end..].trim_start();
    if !tail.is_empty() {
        updated.push('\n');
        updated.push_str(tail);
    }
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
            err.to_string().contains("@scope/name"),
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
        assert!(!updated.contains("\nold\n"));
    }

    #[test]
    fn replace_or_append_agents_snippet_upgrades_partial_lpm_guidance() {
        let current = "# Rules\n\nThis project uses lpm.\n";
        let updated = replace_or_append_agents_snippet(current).unwrap();

        assert!(updated.contains(AGENTS_START_MARKER));
        assert!(updated.contains("Install dependencies with `lpm install`."));
        assert!(updated.contains("Add source packages with `lpm add <package>`."));
    }
}
