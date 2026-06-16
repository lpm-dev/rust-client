use crate::provenance_fetch::{DriftIgnorePolicy, VerifyPolicy};
use crate::save_spec::UserSaveIntent;
use crate::script_policy_config::ScriptPolicy;
use lpm_common::{LpmError, LpmRoot};
use lpm_registry::RegistryClient;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(super) enum SyntheticProjectJsonFormat {
    Compact,
    Pretty,
}

pub(super) struct InnerGlobalInstallOptions<'a> {
    pub(super) install_root: &'a Path,
    pub(super) package_name: &'a str,
    pub(super) package_version: &'a str,
    pub(super) synthetic_project_scope: &'a str,
    pub(super) trust_root: Option<&'a LpmRoot>,
    pub(super) json_format: SyntheticProjectJsonFormat,
    pub(super) suppress_nested_output: bool,
    pub(super) allow_new: bool,
    pub(super) strict_peer_dependencies_override: Option<bool>,
    pub(super) auto_build: bool,
    pub(super) script_policy_override: Option<ScriptPolicy>,
    pub(super) min_release_age_override: Option<u64>,
    pub(super) drift_ignore_policy: DriftIgnorePolicy,
    pub(super) verify_policy: VerifyPolicy,
}

pub(super) async fn run_inner_global_install(
    registry: &RegistryClient,
    options: InnerGlobalInstallOptions<'_>,
) -> Result<(), LpmError> {
    let install_root_ext = lpm_common::as_extended_path(options.install_root);
    std::fs::create_dir_all(&install_root_ext)?;
    let pkg_json_value = synthesize_pkg_json(
        options.synthetic_project_scope,
        options.trust_root,
        options.package_name,
        options.package_version,
    )?;
    let pkg_json_body = match options.json_format {
        SyntheticProjectJsonFormat::Compact => serde_json::to_string(&pkg_json_value),
        SyntheticProjectJsonFormat::Pretty => serde_json::to_string_pretty(&pkg_json_value),
    }
    .map_err(|e| LpmError::Script(format!("serializing synthetic package.json: {e}")))?;
    std::fs::write(install_root_ext.join("package.json"), pkg_json_body)?;

    let _stdout_gag =
        crate::output::suppress_stdout(options.suppress_nested_output).map_err(LpmError::Script)?;

    crate::commands::install::run_with_options(
        registry,
        options.install_root,
        options.suppress_nested_output,
        false,
        crate::commands::install::FrozenLockfileMode::Never,
        false,
        options.allow_new,
        false,
        options.strict_peer_dependencies_override,
        None,
        true,
        true,
        true,
        options.auto_build,
        None,
        None,
        None,
        options.script_policy_override,
        None,
        options.min_release_age_override,
        options.drift_ignore_policy,
        options.verify_policy,
        crate::commands::install::InstallOmitPolicy::default(),
        false,
        false,
        false,
        false,
        &[],
    )
    .await
}

#[cfg(test)]
pub(super) fn pick_version(
    metadata: &lpm_registry::PackageMetadata,
    intent: &UserSaveIntent,
    command_label: &str,
) -> Result<String, LpmError> {
    pick_version_with_policy(
        metadata,
        intent,
        command_label,
        &lpm_resolver::ResolverPolicy::default(),
    )
}

pub(super) fn pick_version_with_policy(
    metadata: &lpm_registry::PackageMetadata,
    intent: &UserSaveIntent,
    command_label: &str,
    policy: &lpm_resolver::ResolverPolicy,
) -> Result<String, LpmError> {
    if let UserSaveIntent::Exact(version) = intent
        && !metadata.versions.contains_key(version)
    {
        return Err(LpmError::Script(format!(
            "registry no longer serves version '{version}' for '{}' - the version may have been yanked or deleted upstream",
            metadata.name
        )));
    }

    if let UserSaveIntent::Bare = intent {
        return crate::release_age_selection::latest_allowed_version_or_policy_error(
            metadata, policy,
        );
    }

    let token = match intent {
        UserSaveIntent::Exact(s) => s.clone(),
        UserSaveIntent::Range(s) => s.clone(),
        UserSaveIntent::DistTag(t) => t.clone(),
        UserSaveIntent::Wildcard => "*".to_string(),
        UserSaveIntent::Bare => unreachable!(),
        UserSaveIntent::Workspace(_) => {
            return Err(LpmError::Script(format!(
                "{command_label} does not support workspace: protocol"
            )));
        }
    };

    crate::release_age_selection::resolve_version_spec_with_policy(metadata, &token, policy)
}

pub(super) fn discover_bin_commands(
    install_root: &Path,
    package_name: &str,
) -> Result<Vec<String>, LpmError> {
    let pkg_json_path = lpm_common::as_extended_path(
        &install_root
            .join("node_modules")
            .join(package_name)
            .join("package.json"),
    );
    let bytes = std::fs::read(&pkg_json_path).map_err(|e| {
        LpmError::Script(format!(
            "could not read installed package.json at {}: {e}",
            pkg_json_path.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        LpmError::Script(format!(
            "installed package.json is not valid JSON at {}: {e}",
            pkg_json_path.display()
        ))
    })?;

    let Some(bin_field) = value.get("bin") else {
        return Ok(Vec::new());
    };
    let mut commands = Vec::new();
    match bin_field {
        serde_json::Value::String(_) => {
            commands.push(short_name(package_name).to_string());
        }
        serde_json::Value::Object(map) => {
            commands.extend(map.keys().cloned());
        }
        _ => {}
    }
    Ok(commands)
}

pub(super) fn discover_materialized_bin_commands(
    install_root: &Path,
    package_name: &str,
) -> Result<Vec<String>, LpmError> {
    let declared = discover_bin_commands(install_root, package_name)?;
    let bin_dir = install_root.join("node_modules").join(".bin");
    let mut commands = Vec::with_capacity(declared.len());
    for command in declared {
        if let Err(reason) = lpm_linker::validate_bin_name(&command, package_name) {
            tracing::warn!("global install: skipping invalid bin \"{command}\": {reason}");
            continue;
        }
        let bin_path = bin_dir.join(&command);
        if !is_materialized_bin_command(&bin_path)? {
            tracing::warn!(
                "global install: skipping bin \"{command}\" because {} was not materialized",
                bin_path.display()
            );
            continue;
        }
        commands.push(command);
    }
    Ok(commands)
}

pub(super) fn mk_tx_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos}-{}", std::process::id())
}

pub(super) fn short_name(package_name: &str) -> &str {
    if let Some(rest) = package_name.strip_prefix('@')
        && let Some(slash) = rest.find('/')
    {
        return &rest[slash + 1..];
    }
    package_name
}

fn sanitize_inner_name(name: &str) -> String {
    name.replace(['@', '/', '.'], "-")
}

fn synthesize_pkg_json(
    synthetic_project_scope: &str,
    trust_root: Option<&LpmRoot>,
    pkg_name: &str,
    pkg_version: &str,
) -> Result<serde_json::Value, LpmError> {
    let mut obj = serde_json::Map::new();
    obj.insert("private".into(), serde_json::Value::Bool(true));
    obj.insert(
        "name".into(),
        serde_json::Value::String(format!(
            "{}/{}",
            synthetic_project_scope,
            sanitize_inner_name(pkg_name)
        )),
    );
    let mut deps = serde_json::Map::new();
    deps.insert(
        pkg_name.to_string(),
        serde_json::Value::String(pkg_version.to_string()),
    );
    obj.insert("dependencies".into(), serde_json::Value::Object(deps));

    if let Some(root) = trust_root {
        let trust = lpm_global::trusted_deps::read_for(root)?;
        if !trust.trusted.is_empty() {
            let mut rich = serde_json::Map::new();
            for (key, binding) in &trust.trusted {
                rich.insert(
                    key.clone(),
                    serde_json::to_value(binding).unwrap_or(serde_json::Value::Null),
                );
            }
            let mut lpm_block = serde_json::Map::new();
            lpm_block.insert(
                "trustedDependencies".into(),
                serde_json::Value::Object(rich),
            );
            obj.insert("lpm".into(), serde_json::Value::Object(lpm_block));
        }
    }

    Ok(serde_json::Value::Object(obj))
}

fn is_materialized_bin_command(bin_path: &Path) -> Result<bool, LpmError> {
    let meta = match std::fs::symlink_metadata(bin_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(LpmError::Io(e)),
    };
    if meta.is_symlink() && !bin_path.exists() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let target_meta = std::fs::metadata(bin_path).map_err(LpmError::Io)?;
        Ok(target_meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn package_metadata(
        name: &str,
        dist_tags: HashMap<String, String>,
        versions: HashMap<String, lpm_registry::VersionMetadata>,
    ) -> lpm_registry::PackageMetadata {
        lpm_registry::PackageMetadata {
            name: name.into(),
            description: None,
            dist_tags,
            versions,
            time: Default::default(),
            modified: None,
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: None,
            ecosystem: None,
        }
    }

    fn tmp_pkg_json(root: &Path, package_name: &str, bin: serde_json::Value) {
        let pkg_dir = root.join("node_modules").join(package_name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let body = serde_json::json!({
            "name": package_name,
            "version": "1.0.0",
            "bin": bin,
        });
        std::fs::write(
            pkg_dir.join("package.json"),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn pick_version_returns_exact_verbatim() {
        let mut versions = HashMap::new();
        versions.insert(
            "1.0.0".to_string(),
            lpm_registry::VersionMetadata::default(),
        );
        let metadata = package_metadata("x", HashMap::new(), versions);

        let version = pick_version(
            &metadata,
            &UserSaveIntent::Exact("1.0.0".into()),
            "global install",
        )
        .unwrap();

        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn pick_version_dist_tag_resolves() {
        let mut dist_tags = HashMap::new();
        dist_tags.insert("latest".to_string(), "9.24.0".to_string());
        let metadata = package_metadata("x", dist_tags, HashMap::new());

        let version = pick_version(
            &metadata,
            &UserSaveIntent::DistTag("latest".into()),
            "global install",
        )
        .unwrap();

        assert_eq!(version, "9.24.0");
    }

    #[test]
    fn pick_version_range_picks_max_satisfying() {
        let mut versions = HashMap::new();
        for v in ["9.10.0", "9.24.0", "10.0.0"] {
            versions.insert(v.to_string(), lpm_registry::VersionMetadata::default());
        }
        let metadata = package_metadata("x", HashMap::new(), versions);

        let version = pick_version(
            &metadata,
            &UserSaveIntent::Range("^9".into()),
            "global install",
        )
        .unwrap();

        assert_eq!(version, "9.24.0");
    }

    #[test]
    fn pick_version_bare_reports_release_age_block_when_all_versions_are_too_new() {
        let mut versions = HashMap::new();
        versions.insert(
            "1.0.0".to_string(),
            lpm_registry::VersionMetadata::default(),
        );
        let mut metadata = package_metadata("x", HashMap::new(), versions);
        metadata
            .time
            .insert("1.0.0".to_string(), "2999-01-01T00:00:00.000Z".to_string());
        let policy = lpm_resolver::ResolverPolicy::new(259_200, lpm_resolver::TrustPolicyMode::Off);

        let err =
            pick_version_with_policy(&metadata, &UserSaveIntent::Bare, "global install", &policy)
                .unwrap_err();
        let message = err.to_string();

        assert!(
            message.contains("published too recently for minimumReleaseAge")
                && message.contains("minimumReleaseAge=259200s"),
            "bare global selection must surface release-age policy errors; got {message}"
        );
    }

    #[test]
    fn pick_version_workspace_intent_mentions_calling_command() {
        let metadata = package_metadata("x", HashMap::new(), HashMap::new());

        let err = pick_version(
            &metadata,
            &UserSaveIntent::Workspace("workspace:*".into()),
            "global update",
        )
        .unwrap_err();

        assert!(format!("{err}").contains("global update does not support workspace: protocol"));
    }

    #[test]
    fn discover_bin_string_form_uses_short_name() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(tmp.path(), "eslint", serde_json::json!("./bin/eslint.js"));

        let cmds = discover_bin_commands(tmp.path(), "eslint").unwrap();

        assert_eq!(cmds, vec!["eslint"]);
    }

    #[test]
    fn discover_bin_string_form_strips_scope() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(
            tmp.path(),
            "@lpm.dev/owner.tool",
            serde_json::json!("./bin/run.js"),
        );

        let cmds = discover_bin_commands(tmp.path(), "@lpm.dev/owner.tool").unwrap();

        assert_eq!(cmds, vec!["owner.tool"]);
    }

    #[test]
    fn discover_bin_object_form_returns_keys() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(
            tmp.path(),
            "typescript",
            serde_json::json!({"tsc": "./bin/tsc", "tsserver": "./bin/tsserver"}),
        );

        let mut cmds = discover_bin_commands(tmp.path(), "typescript").unwrap();
        cmds.sort();

        assert_eq!(cmds, vec!["tsc", "tsserver"]);
    }

    #[test]
    fn discover_materialized_bin_commands_uses_actual_bin_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        tmp_pkg_json(
            tmp.path(),
            "tool",
            serde_json::json!({
                "good": "./bin/good.js",
                "../escape": "./bin/escape.js",
                "missing": "./bin/missing.js",
            }),
        );
        let bin_dir = tmp.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let good = bin_dir.join("good");
        std::fs::write(&good, b"#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let commands = discover_materialized_bin_commands(tmp.path(), "tool").unwrap();

        assert_eq!(commands, vec!["good"]);
    }

    #[test]
    fn discover_bin_returns_empty_when_no_bin_field() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules").join("just-a-lib");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"just-a-lib","version":"1.0.0"}"#,
        )
        .unwrap();

        let cmds = discover_bin_commands(tmp.path(), "just-a-lib").unwrap();

        assert!(cmds.is_empty());
    }

    #[test]
    fn discover_bin_errors_when_package_json_missing() {
        let tmp = tempfile::tempdir().unwrap();

        let err = discover_bin_commands(tmp.path(), "ghost").unwrap_err();

        assert!(format!("{err}").contains("could not read installed package.json"));
    }

    #[test]
    fn short_name_strips_scope() {
        assert_eq!(short_name("@lpm.dev/owner.tool"), "owner.tool");
        assert_eq!(short_name("@scope/name"), "name");
        assert_eq!(short_name("eslint"), "eslint");
    }

    #[test]
    fn mk_tx_id_includes_pid_and_is_unique_within_process() {
        let a = mk_tx_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = mk_tx_id();
        assert_ne!(a, b);
        let pid = std::process::id().to_string();
        assert!(a.ends_with(&pid));
    }

    #[test]
    fn sanitize_inner_name_strips_at_slash_dot() {
        assert_eq!(
            sanitize_inner_name("@lpm.dev/owner.tool"),
            "-lpm-dev-owner-tool"
        );
        assert_eq!(sanitize_inner_name("eslint"), "eslint");
    }

    #[test]
    fn synthesize_pkg_json_omits_lpm_block_when_global_trust_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let value = synthesize_pkg_json("@lpm-global", Some(&root), "eslint", "9.24.0").unwrap();

        assert!(value.get("lpm").is_none());
        assert_eq!(
            value.get("name").and_then(|v| v.as_str()),
            Some("@lpm-global/eslint")
        );
        assert_eq!(
            value
                .get("dependencies")
                .and_then(|d| d.get("eslint"))
                .and_then(|v| v.as_str()),
            Some("9.24.0")
        );
    }

    #[test]
    fn synthesize_pkg_json_embeds_global_trust_under_lpm_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut trust = lpm_global::GlobalTrustedDependencies::default();
        trust.insert_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-x".into()),
            Some("sha256-y".into()),
        );
        lpm_global::trusted_deps::write_for(&root, &trust).unwrap();

        let value = synthesize_pkg_json("@lpm-global", Some(&root), "eslint", "9.24.0").unwrap();
        let lpm_block = value.get("lpm").expect("lpm block must be present");
        let trusted = lpm_block
            .get("trustedDependencies")
            .expect("trustedDependencies must be present");
        let entry = trusted
            .get("esbuild@0.25.1")
            .expect("entry keyed name@version");

        assert_eq!(
            entry.get("integrity").and_then(|v| v.as_str()),
            Some("sha512-x")
        );
        assert_eq!(
            entry.get("scriptHash").and_then(|v| v.as_str()),
            Some("sha256-y")
        );
    }

    #[test]
    fn synthesize_pkg_json_preserves_scoped_dependency_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let value = synthesize_pkg_json("@lpm-global", Some(&root), "@lpm.dev/owner.tool", "1.0.0")
            .unwrap();

        assert_eq!(
            value.get("name").and_then(|v| v.as_str()),
            Some("@lpm-global/-lpm-dev-owner-tool")
        );
        assert_eq!(
            value
                .get("dependencies")
                .and_then(|d| d.get("@lpm.dev/owner.tool"))
                .and_then(|v| v.as_str()),
            Some("1.0.0")
        );
    }

    #[test]
    fn synthesize_pkg_json_update_scope_omits_trusted_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut trust = lpm_global::GlobalTrustedDependencies::default();
        trust.insert_strict("esbuild", "0.25.1", None, None);
        lpm_global::trusted_deps::write_for(&root, &trust).unwrap();

        let value = synthesize_pkg_json("@lpm-global-upgrade", None, "eslint", "9.24.0").unwrap();

        assert_eq!(
            value.get("name").and_then(|v| v.as_str()),
            Some("@lpm-global-upgrade/eslint")
        );
        assert!(value.get("lpm").is_none());
    }

    #[test]
    fn synthesize_pkg_json_compact_and_pretty_formats_round_trip() {
        let value = synthesize_pkg_json("@lpm-global-upgrade", None, "eslint", "9.24.0").unwrap();

        let compact = serde_json::to_string(&value).unwrap();
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&compact).unwrap(),
            value
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&pretty).unwrap(),
            value
        );
    }
}
