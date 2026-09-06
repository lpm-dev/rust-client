use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use lpm_common::{LpmError, TyposquatErrorContext, TyposquatErrorFinding};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};

const ENV_TYPOSQUAT_GUARD: &str = "LPM_TYPOSQUAT_GUARD";
const SINGLE_FINDING_DEFAULT_CHOICE: &str = "cancel";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TyposquatSource<'a> {
    CliArg,
    Manifest { path: &'a Path },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GuardedPackageSpecs {
    pub specs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuardFinding {
    package: String,
    similar_to: String,
    technique: String,
    source: String,
}

#[derive(Debug, Default)]
struct TyposquatPolicy {
    allow: Vec<AllowEntry>,
}

#[derive(Debug)]
struct AllowEntry {
    package: String,
    similar_to: Option<String>,
}

pub(crate) fn guard_explicit_package_specs(
    project_dir: &Path,
    packages: &[String],
    install_roots: &[PathBuf],
    yes: bool,
    json_output: bool,
) -> Result<GuardedPackageSpecs, LpmError> {
    let package_names = parse_package_names(packages)?;
    if typosquat_guard_disabled(project_dir, json_output)? {
        return Ok(GuardedPackageSpecs {
            specs: packages.to_vec(),
        });
    }
    let policy = TyposquatPolicy::load(project_dir)?;
    let locked_direct_by_root: Vec<BTreeSet<String>> = install_roots
        .iter()
        .map(|root| locked_direct_names(root))
        .collect();
    let mut findings = Vec::new();

    for name in &package_names {
        if locked_in_every_root(name, &locked_direct_by_root) {
            continue;
        }
        if let Some(finding) = analyze_name(name, TyposquatSource::CliArg) {
            if policy.allows(&finding.package, Some(&finding.similar_to)) {
                continue;
            }
            findings.push(finding);
        }
    }

    resolve_findings(
        project_dir,
        packages,
        &package_names,
        findings,
        yes,
        json_output,
        ExplicitPromptMode::AllowRewrite,
    )
}

pub(crate) fn guard_manifest_direct_dependencies(
    project_dir: &Path,
    manifest_path: &Path,
    pkg: &lpm_workspace::PackageJson,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut direct_names = BTreeSet::new();
    for dependencies in [
        &pkg.dependencies,
        &pkg.dev_dependencies,
        &pkg.optional_dependencies,
        &pkg.peer_dependencies,
    ] {
        for (local_name, spec) in dependencies {
            validate_package_name(local_name)?;
            direct_names.insert(registry_name_for_typosquat_analysis(local_name, spec));
        }
    }

    if typosquat_guard_disabled(project_dir, json_output)? {
        return Ok(());
    }

    let mut findings = Vec::new();
    let policy = TyposquatPolicy::load(project_dir)?;
    let locked_direct = locked_direct_names(project_dir);
    for name in &direct_names {
        if locked_direct.contains(name.as_ref()) {
            continue;
        }
        if let Some(finding) = analyze_name(
            name,
            TyposquatSource::Manifest {
                path: manifest_path,
            },
        ) {
            if policy.allows(&finding.package, Some(&finding.similar_to)) {
                continue;
            }
            findings.push(finding);
        }
    }

    if findings.is_empty() {
        return Ok(());
    }

    if can_prompt(json_output, false) {
        prompt_allow_manifest_findings(project_dir, &findings)?;
        return Ok(());
    }

    Err(error_context(project_dir, findings, None, false))
}

fn registry_name_for_typosquat_analysis<'a>(local_name: &'a str, spec: &str) -> Cow<'a, str> {
    lpm_resolver::ranges::parse_npm_alias(spec).map_or_else(
        || Cow::Borrowed(local_name),
        |alias| Cow::Owned(alias.target),
    )
}

pub(crate) fn validate_package_name(name: &str) -> Result<(), LpmError> {
    if name.is_empty() {
        return Err(LpmError::InvalidPackageName(
            "package name cannot be empty".to_string(),
        ));
    }
    if name.starts_with('-') {
        return Err(LpmError::InvalidPackageName(format!(
            "'{name}' looks like a command-line flag; package names cannot start with '-'"
        )));
    }
    Ok(())
}

fn parse_package_names(packages: &[String]) -> Result<Vec<String>, LpmError> {
    let mut names = Vec::with_capacity(packages.len());
    for spec in packages {
        let (name, _) = crate::save_spec::parse_user_save_intent(spec)?;
        validate_package_name(&name)?;
        names.push(name);
    }
    Ok(names)
}

fn resolve_findings(
    project_dir: &Path,
    specs: &[String],
    package_names: &[String],
    findings: Vec<GuardFinding>,
    yes: bool,
    json_output: bool,
    prompt_mode: ExplicitPromptMode,
) -> Result<GuardedPackageSpecs, LpmError> {
    if findings.is_empty() {
        return Ok(GuardedPackageSpecs {
            specs: specs.to_vec(),
        });
    }

    let suggested_command = suggested_command(specs, package_names, &findings);
    if can_prompt(json_output, yes) {
        return prompt_explicit_findings(project_dir, specs, package_names, &findings, prompt_mode);
    }

    Err(error_context(
        project_dir,
        findings,
        suggested_command,
        false,
    ))
}

#[derive(Clone, Copy)]
enum ExplicitPromptMode {
    AllowRewrite,
}

fn can_prompt(json_output: bool, yes: bool) -> bool {
    !json_output
        && !yes
        && !crate::install_state::ci_env_is_truthy()
        && std::io::stdin().is_terminal()
}

fn typosquat_guard_disabled(project_dir: &Path, json_output: bool) -> Result<bool, LpmError> {
    let global = crate::commands::config::GlobalConfig::load();
    if let Some(selection) = global.get_typosquat_guard_mode() {
        crate::security_approval::ensure_runtime_typosquat_guard_config_authorized(
            project_dir,
            json_output,
            selection,
        )?;
        return Ok(selection.disables_guard());
    }
    if typosquat_guard_disabled_from_env_value(std::env::var(ENV_TYPOSQUAT_GUARD).ok().as_deref())
        && typosquat_guard_env_disable_allowed(&global)?
    {
        return Ok(true);
    }
    if global
        .get_value(crate::commands::config::TYPOSQUAT_GUARD_KEY)
        .is_some()
    {
        return Ok(false);
    }
    Ok(
        crate::security_approval::load_effective_authorized_posture()?
            .posture
            .typosquat_guard()
            .disables_guard(),
    )
}

fn typosquat_guard_env_disable_allowed(
    global: &crate::commands::config::GlobalConfig,
) -> Result<bool, LpmError> {
    if crate::security_floor::force_security_floor_enabled(global) {
        return Ok(false);
    }

    let effective = crate::security_approval::load_effective_authorized_posture()?;
    if matches!(
        effective.sources.typosquat_guard,
        crate::security_approval::PostureSourceKind::ManagedPolicy
    ) && crate::commands::config::TyposquatGuardSelection::Off
        .loosens(effective.posture.typosquat_guard())
    {
        return Ok(false);
    }

    Ok(true)
}

fn typosquat_guard_disabled_from_env_value(value: Option<&str>) -> bool {
    value.is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "disabled"
        )
    })
}

fn analyze_name(name: &str, source: TyposquatSource<'_>) -> Option<GuardFinding> {
    let finding = lpm_security::typosquatting::analyze_typosquatting(name)?;
    Some(GuardFinding {
        package: name.to_string(),
        similar_to: finding.similar.to_string(),
        technique: finding.technique.as_str().to_string(),
        source: match source {
            TyposquatSource::CliArg => "cli".to_string(),
            TyposquatSource::Manifest { path } => path.display().to_string(),
        },
    })
}

fn prompt_explicit_findings(
    project_dir: &Path,
    specs: &[String],
    package_names: &[String],
    findings: &[GuardFinding],
    _prompt_mode: ExplicitPromptMode,
) -> Result<GuardedPackageSpecs, LpmError> {
    if findings.len() == 1 {
        let finding = &findings[0];
        let package_idx = package_names
            .iter()
            .position(|name| name == &finding.package)
            .ok_or_else(|| LpmError::Registry("internal typosquat prompt mismatch".to_string()))?;
        let rewritten =
            rewrite_spec_name(&specs[package_idx], &finding.package, &finding.similar_to);
        let allow_label =
            crate::prompt::untrusted(format!("Allow {} in project policy", finding.package));
        let choice: &str = cliclack::select(crate::prompt::untrusted(format!(
            "{} looks like {}",
            finding.package, finding.similar_to
        )))
        .item(
            "install_suggestion",
            crate::prompt::untrusted(format!("Install {rewritten} instead")),
            "",
        )
        .item("allow", allow_label, "Writes policy.typosquat to lpm.toml")
        .item("cancel", "Cancel", "")
        .initial_value(SINGLE_FINDING_DEFAULT_CHOICE)
        .interact()
        .map_err(crate::prompt::prompt_err)?;

        return match choice {
            "install_suggestion" => {
                let mut updated = specs.to_vec();
                updated[package_idx] = rewritten;
                Ok(GuardedPackageSpecs { specs: updated })
            }
            "allow" => {
                let reason = prompt_allow_reason(&finding.package, &finding.similar_to)?;
                append_allow_entry(project_dir, &finding.package, &finding.similar_to, &reason)?;
                Ok(GuardedPackageSpecs {
                    specs: specs.to_vec(),
                })
            }
            "cancel" => Err(error_context(
                project_dir,
                findings.to_vec(),
                suggested_command(specs, package_names, findings),
                true,
            )),
            _ => Err(LpmError::Registry(
                "unknown typosquat prompt choice".to_string(),
            )),
        };
    }

    let choice: &str = cliclack::select(format!("{} suspicious package names", findings.len()))
        .item(
            "allow",
            "Allow all in project policy",
            "Writes policy.typosquat to lpm.toml",
        )
        .item("cancel", "Cancel", "")
        .initial_value("cancel")
        .interact()
        .map_err(crate::prompt::prompt_err)?;

    match choice {
        "allow" => {
            for finding in findings {
                let reason = prompt_allow_reason(&finding.package, &finding.similar_to)?;
                append_allow_entry(project_dir, &finding.package, &finding.similar_to, &reason)?;
            }
            Ok(GuardedPackageSpecs {
                specs: specs.to_vec(),
            })
        }
        "cancel" => Err(error_context(project_dir, findings.to_vec(), None, true)),
        _ => Err(LpmError::Registry(
            "unknown typosquat prompt choice".to_string(),
        )),
    }
}

fn prompt_allow_manifest_findings(
    project_dir: &Path,
    findings: &[GuardFinding],
) -> Result<(), LpmError> {
    let choice: &str = cliclack::select(format!(
        "{} suspicious direct dependencies in package.json",
        findings.len()
    ))
    .item(
        "allow",
        "Allow in project policy",
        "Writes policy.typosquat to lpm.toml",
    )
    .item(
        "cancel",
        "Cancel",
        "Edit package.json or retry with the intended package",
    )
    .initial_value("cancel")
    .interact()
    .map_err(crate::prompt::prompt_err)?;

    match choice {
        "allow" => {
            for finding in findings {
                let reason = prompt_allow_reason(&finding.package, &finding.similar_to)?;
                append_allow_entry(project_dir, &finding.package, &finding.similar_to, &reason)?;
            }
            Ok(())
        }
        "cancel" => Err(error_context(project_dir, findings.to_vec(), None, true)),
        _ => Err(LpmError::Registry(
            "unknown typosquat prompt choice".to_string(),
        )),
    }
}

fn prompt_allow_reason(package: &str, similar_to: &str) -> Result<String, LpmError> {
    let reason: String = cliclack::input(crate::prompt::untrusted(format!(
        "Reason for allowing {package} instead of {similar_to}"
    )))
    .placeholder("Intentional internal package")
    .interact()
    .map_err(crate::prompt::prompt_err)?;
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(LpmError::Registry(
            "typosquat allow-list entries require a reason".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn rewrite_spec_name(spec: &str, old_name: &str, new_name: &str) -> String {
    if spec == old_name {
        return new_name.to_string();
    }
    spec.strip_prefix(old_name).map_or_else(
        || new_name.to_string(),
        |suffix| format!("{new_name}{suffix}"),
    )
}

fn suggested_command(
    specs: &[String],
    package_names: &[String],
    findings: &[GuardFinding],
) -> Option<String> {
    if findings.len() != 1 || specs.len() != 1 || package_names.len() != 1 {
        return None;
    }
    Some(format!(
        "lpm install {}",
        rewrite_spec_name(&specs[0], &package_names[0], &findings[0].similar_to)
    ))
}

fn error_context(
    project_dir: &Path,
    findings: Vec<GuardFinding>,
    suggested_command: Option<String>,
    cancelled: bool,
) -> LpmError {
    let allow_example = findings
        .first()
        .map_or_else(default_allow_example, allow_example_for_finding);

    LpmError::TyposquatSuspected(Box::new(TyposquatErrorContext {
        findings: findings
            .into_iter()
            .map(|finding| TyposquatErrorFinding {
                package: finding.package,
                similar_to: finding.similar_to,
                technique: finding.technique,
                source: finding.source,
            })
            .collect(),
        config_path: project_dir.join("lpm.toml").display().to_string(),
        allow_example,
        suggested_command,
        cancelled,
    }))
}

fn allow_example_for_finding(finding: &GuardFinding) -> String {
    allow_example(&finding.package, &finding.similar_to)
}

fn default_allow_example() -> String {
    allow_example("axois", "axios")
}

fn allow_example(package: &str, similar_to: &str) -> String {
    format!(
        "[[policy.typosquat.allow]]\npackage = {}\nsimilar-to = {}\nreason = \"Intentional package\"",
        Value::from(package),
        Value::from(similar_to)
    )
}

fn locked_in_every_root(name: &str, roots: &[BTreeSet<String>]) -> bool {
    !roots.is_empty() && roots.iter().all(|locked| locked.contains(name))
}

pub(crate) fn locked_direct_names(project_dir: &Path) -> BTreeSet<String> {
    let Ok(lockfile) =
        crate::commands::install::workspace_lockfile::read_project_metadata_shared(project_dir)
    else {
        return BTreeSet::new();
    };
    let Some(importer) = lockfile.importers.get(".") else {
        return BTreeSet::new();
    };

    let mut names = BTreeSet::new();
    for dependencies in [
        &importer.dependencies,
        &importer.dev_dependencies,
        &importer.optional_dependencies,
        &importer.peer_dependencies,
    ] {
        names.extend(dependencies.iter().map(|(local_name, spec)| {
            registry_name_for_typosquat_analysis(local_name, spec).into_owned()
        }));
    }
    names
}

impl TyposquatPolicy {
    fn load(project_dir: &Path) -> Result<Self, LpmError> {
        let path = project_dir.join("lpm.toml");
        let raw = match lpm_common::read_text_file_capped(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(raw) => raw,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(Self::default()),
            Err(error) => return Err(LpmError::Registry(error.to_string())),
        };
        let parsed: toml::Value = toml::from_str(&raw)
            .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;
        let mut policy = Self::default();

        let Some(typosquat) = parsed
            .get("policy")
            .and_then(|value| value.get("typosquat"))
        else {
            return Ok(policy);
        };
        let Some(allow) = typosquat.get("allow") else {
            return Ok(policy);
        };
        let Some(entries) = allow.as_array() else {
            return Err(LpmError::Registry(format!(
                "{}: `policy.typosquat.allow` must be an array of tables",
                path.display()
            )));
        };

        for entry in entries {
            let package = entry
                .get("package")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    LpmError::Registry(format!(
                        "{}: each `policy.typosquat.allow` entry needs `package`",
                        path.display()
                    ))
                })?;
            let reason = entry
                .get("reason")
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .trim();
            if reason.is_empty() {
                return Err(LpmError::Registry(format!(
                    "{}: `policy.typosquat.allow` entry for `{package}` needs a non-empty `reason`",
                    path.display()
                )));
            }
            let similar_to = entry
                .get("similar-to")
                .or_else(|| entry.get("similar_to"))
                .and_then(toml::Value::as_str)
                .map(str::to_string);
            policy.allow.push(AllowEntry {
                package: package.to_string(),
                similar_to,
            });
        }

        Ok(policy)
    }

    fn allows(&self, package: &str, similar_to: Option<&str>) -> bool {
        self.allow.iter().any(|entry| {
            entry.package == package
                && match (&entry.similar_to, similar_to) {
                    (Some(configured), Some(actual)) => configured == actual,
                    (Some(_), None) => false,
                    (None, _) => true,
                }
        })
    }
}

fn append_allow_entry(
    project_dir: &Path,
    package: &str,
    similar_to: &str,
    reason: &str,
) -> Result<(), LpmError> {
    let path = project_dir.join("lpm.toml");
    let raw = match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    {
        Ok(raw) => raw,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => String::new(),
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let mut doc = raw
        .parse::<DocumentMut>()
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;

    ensure_allow_array(&mut doc)?;
    let allow = doc["policy"]["typosquat"]["allow"]
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `policy.typosquat.allow` must be an array of tables",
                path.display()
            ))
        })?;

    if allow.iter().any(|table| {
        table
            .get("package")
            .and_then(Item::as_str)
            .is_some_and(|value| value == package)
            && table
                .get("similar-to")
                .or_else(|| table.get("similar_to"))
                .and_then(Item::as_str)
                .is_some_and(|value| value == similar_to)
    }) {
        return Ok(());
    }

    let mut table = Table::new();
    table["package"] = Item::Value(Value::from(package));
    table["similar-to"] = Item::Value(Value::from(similar_to));
    table["reason"] = Item::Value(Value::from(reason));
    allow.push(table);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, doc.to_string()).map_err(LpmError::Io)
}

fn ensure_allow_array(doc: &mut DocumentMut) -> Result<(), LpmError> {
    ensure_table(doc, "policy")?;
    {
        let policy = doc["policy"].as_table_mut().ok_or_else(|| {
            LpmError::Registry("lpm.toml: `policy` must be a TOML table".to_string())
        })?;
        if policy.get("typosquat").is_none() {
            policy.insert("typosquat", Item::Table(Table::new()));
        }
    }
    {
        let typosquat = doc["policy"]["typosquat"].as_table_mut().ok_or_else(|| {
            LpmError::Registry("lpm.toml: `policy.typosquat` must be a TOML table".to_string())
        })?;
        if typosquat.get("allow").is_none() {
            typosquat.insert("allow", Item::ArrayOfTables(ArrayOfTables::new()));
        }
    }
    Ok(())
}

fn ensure_table(doc: &mut DocumentMut, key: &str) -> Result<(), LpmError> {
    if doc.get(key).is_none() {
        doc[key] = Item::Table(Table::new());
        return Ok(());
    }
    if doc[key].is_table() {
        Ok(())
    } else {
        Err(LpmError::Registry(format!(
            "lpm.toml: `{key}` must be a TOML table"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::fs;

    fn absent_managed_policy_path(dir: &tempfile::TempDir) -> OsString {
        dir.path()
            .join("absent-managed-security-policy.toml")
            .as_os_str()
            .to_owned()
    }

    fn scoped_lpm_home_with_config(raw: &str) -> (tempfile::TempDir, crate::test_env::ScopedEnv) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), raw).unwrap();
        let env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(dir.path().as_os_str().to_owned())),
            (
                "LPM_SECURITY_POLICY_PATH",
                Some(absent_managed_policy_path(&dir)),
            ),
            (ENV_TYPOSQUAT_GUARD, None),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                Some(OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
            ),
        ]);
        (dir, env)
    }

    fn scoped_enabled_lpm_home() -> (tempfile::TempDir, crate::test_env::ScopedEnv) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), "typosquat-guard = \"on\"\n").unwrap();
        let env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(dir.path().as_os_str().to_owned())),
            (
                "LPM_SECURITY_POLICY_PATH",
                Some(absent_managed_policy_path(&dir)),
            ),
            (ENV_TYPOSQUAT_GUARD, None),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                Some(OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
            ),
        ]);
        (dir, env)
    }

    fn scoped_lpm_home_with_env(
        env_value: &str,
    ) -> (tempfile::TempDir, crate::test_env::ScopedEnv) {
        let dir = tempfile::tempdir().unwrap();
        let env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(dir.path().as_os_str().to_owned())),
            (
                "LPM_SECURITY_POLICY_PATH",
                Some(absent_managed_policy_path(&dir)),
            ),
            (
                ENV_TYPOSQUAT_GUARD,
                Some(std::ffi::OsString::from(env_value)),
            ),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                Some(OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
            ),
        ]);
        (dir, env)
    }

    fn approve_typosquat_guard(selection: crate::commands::config::TyposquatGuardSelection) {
        let posture = crate::security_approval::AuthorizedPosture {
            typosquat_guard: selection.as_str().to_string(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();
    }

    #[test]
    fn validate_package_name_rejects_flag_shaped_names() {
        let err = validate_package_name("--legacy-peer-deps").unwrap_err();
        assert!(err.to_string().contains("command-line flag"));
    }

    #[test]
    fn typosquat_guard_env_values_disable_only_when_explicitly_off() {
        assert!(typosquat_guard_disabled_from_env_value(Some("0")));
        assert!(typosquat_guard_disabled_from_env_value(Some("false")));
        assert!(typosquat_guard_disabled_from_env_value(Some("off")));
        assert!(typosquat_guard_disabled_from_env_value(Some("disabled")));
        assert!(!typosquat_guard_disabled_from_env_value(None));
        assert!(!typosquat_guard_disabled_from_env_value(Some("")));
        assert!(!typosquat_guard_disabled_from_env_value(Some("1")));
        assert!(!typosquat_guard_disabled_from_env_value(Some("true")));
    }

    #[test]
    fn typosquat_guard_global_config_off_disables_analysis() {
        let (_dir, _env) = scoped_lpm_home_with_config("typosquat-guard = \"off\"\n");
        approve_typosquat_guard(crate::commands::config::TyposquatGuardSelection::Off);
        let project = tempfile::tempdir().unwrap();

        assert!(typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_env_disable_applies_when_config_override_is_absent() {
        let (_dir, _env) = scoped_lpm_home_with_env("0");
        let project = tempfile::tempdir().unwrap();

        assert!(typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_global_config_default_disables_analysis() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config.toml"),
            "typosquat-guard = \"default\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", dir.path().as_os_str().to_owned()),
            ("LPM_SECURITY_POLICY_PATH", absent_managed_policy_path(&dir)),
            (ENV_TYPOSQUAT_GUARD, OsString::from("0")),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                OsString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
        ]);
        let project = tempfile::tempdir().unwrap();

        assert!(typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_force_floor_blocks_env_disable_when_config_override_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config.toml"),
            "force-security-floor = true\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", dir.path().as_os_str().to_owned()),
            ("LPM_SECURITY_POLICY_PATH", absent_managed_policy_path(&dir)),
            (ENV_TYPOSQUAT_GUARD, OsString::from("off")),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                OsString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
        ]);
        approve_typosquat_guard(crate::commands::config::TyposquatGuardSelection::On);
        let project = tempfile::tempdir().unwrap();

        assert!(!typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_managed_policy_blocks_env_disable_when_config_override_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("managed-security-policy.toml"),
            "typosquat-guard = \"on\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(dir.path().as_os_str().to_owned())),
            (
                "LPM_SECURITY_POLICY_PATH",
                Some(
                    dir.path()
                        .join("managed-security-policy.toml")
                        .as_os_str()
                        .to_owned(),
                ),
            ),
            (ENV_TYPOSQUAT_GUARD, Some(OsString::from("off"))),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                Some(OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )),
            ),
        ]);
        let project = tempfile::tempdir().unwrap();

        assert!(!typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_global_config_on_overrides_env_disable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), "typosquat-guard = \"on\"\n").unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("LPM_HOME", dir.path().as_os_str().to_owned()),
            ("LPM_SECURITY_POLICY_PATH", absent_managed_policy_path(&dir)),
            (ENV_TYPOSQUAT_GUARD, OsString::from("off")),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                OsString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ),
        ]);
        let project = tempfile::tempdir().unwrap();

        assert!(!typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn typosquat_guard_invalid_global_config_value_stays_enabled() {
        let (_dir, _env) = scoped_lpm_home_with_config("typosquat-guard = \"yolo\"\n");
        let project = tempfile::tempdir().unwrap();

        assert!(!typosquat_guard_disabled(project.path(), true).unwrap());
    }

    #[test]
    fn explicit_typosquat_prompt_defaults_to_cancel() {
        assert_eq!(SINGLE_FINDING_DEFAULT_CHOICE, "cancel");
    }

    #[test]
    fn policy_requires_reason_for_allow_entries() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[[policy.typosquat.allow]]\npackage = \"axois\"\nsimilar-to = \"axios\"\n",
        )
        .unwrap();

        let err = TyposquatPolicy::load(dir.path()).unwrap_err();
        assert!(err.to_string().contains("reason"));
    }

    #[test]
    fn policy_accepts_kebab_or_snake_similar_to_keys() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.toml"),
            "[[policy.typosquat.allow]]\npackage = \"axois\"\nsimilar_to = \"axios\"\nreason = \"fixture\"\n",
        )
        .unwrap();

        let policy = TyposquatPolicy::load(dir.path()).unwrap();
        assert!(policy.allows("axois", Some("axios")));
    }

    #[test]
    fn locked_direct_names_read_importer_snapshot_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: [("axois".to_string(), "^1.0.0".to_string())].into(),
                ..Default::default()
            },
        );
        lockfile
            .write_to_file(&dir.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        assert!(locked_direct_names(dir.path()).contains("axois"));
    }

    #[test]
    fn append_allow_entry_preserves_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.toml"), "save-prefix = \"~\"\n").unwrap();

        append_allow_entry(dir.path(), "axois", "axios", "fixture").unwrap();
        let raw = fs::read_to_string(dir.path().join("lpm.toml")).unwrap();

        assert!(raw.contains("save-prefix = \"~\""));
        assert!(raw.contains("[[policy.typosquat.allow]]"));
        assert!(raw.contains("package = \"axois\""));
    }

    #[test]
    fn guard_explicit_specs_returns_rewritten_suggestion_in_json_mode_error() {
        let (_home, _env) = scoped_enabled_lpm_home();
        let dir = tempfile::tempdir().unwrap();
        let specs = vec!["axois@^1".to_string()];
        let err = guard_explicit_package_specs(
            dir.path(),
            &specs,
            &[dir.path().to_path_buf()],
            false,
            true,
        )
        .unwrap_err();

        let LpmError::TyposquatSuspected(context) = err else {
            panic!("expected typosquat error");
        };
        assert_eq!(
            context.suggested_command.as_deref(),
            Some("lpm install axios@^1")
        );
    }

    #[test]
    fn typosquat_error_allow_example_uses_actual_finding() {
        let dir = tempfile::tempdir().unwrap();
        let err = error_context(
            dir.path(),
            vec![GuardFinding {
                package: "expres".to_string(),
                similar_to: "express".to_string(),
                technique: "edit_distance".to_string(),
                source: "cli".to_string(),
            }],
            None,
            false,
        );

        let LpmError::TyposquatSuspected(context) = err else {
            panic!("expected typosquat error");
        };
        assert!(context.allow_example.contains("package = \"expres\""));
        assert!(context.allow_example.contains("similar-to = \"express\""));
        assert!(!context.allow_example.contains("axois"));
    }

    #[test]
    fn explicit_guard_rejects_when_package_is_new_for_one_target_root() {
        let (_home, _env) = scoped_enabled_lpm_home();
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: [("axois".to_string(), "^1.0.0".to_string())].into(),
                ..Default::default()
            },
        );
        lockfile
            .write_to_file(&root_a.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        let specs = vec!["axois".to_string()];

        let err = guard_explicit_package_specs(
            root_a.path(),
            &specs,
            &[root_a.path().to_path_buf(), root_b.path().to_path_buf()],
            false,
            true,
        )
        .unwrap_err();

        assert!(matches!(err, LpmError::TyposquatSuspected(_)));
    }

    #[test]
    fn explicit_guard_skips_when_package_is_locked_for_every_target_root() {
        let (_home, _env) = scoped_enabled_lpm_home();
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        for root in [root_a.path(), root_b.path()] {
            let mut lockfile = lpm_lockfile::Lockfile::new();
            lockfile.importers.insert(
                ".".to_string(),
                lpm_lockfile::ImporterSnapshot {
                    dependencies: [("axois".to_string(), "^1.0.0".to_string())].into(),
                    ..Default::default()
                },
            );
            lockfile
                .write_to_file(&root.join(lpm_lockfile::LOCKFILE_NAME))
                .unwrap();
        }
        let specs = vec!["axois".to_string()];

        let guarded = guard_explicit_package_specs(
            root_a.path(),
            &specs,
            &[root_a.path().to_path_buf(), root_b.path().to_path_buf()],
            false,
            true,
        )
        .unwrap();

        assert_eq!(guarded.specs, specs);
    }

    #[test]
    fn explicit_guard_env_disable_skips_suspicious_name_analysis() {
        let (_home, _env) = scoped_lpm_home_with_env("0");
        let dir = tempfile::tempdir().unwrap();
        let specs = vec!["axois".to_string()];

        let guarded = guard_explicit_package_specs(
            dir.path(),
            &specs,
            &[dir.path().to_path_buf()],
            false,
            true,
        )
        .unwrap();

        assert_eq!(guarded.specs, specs);
    }

    #[test]
    fn explicit_guard_env_disable_preserves_package_name_validation() {
        let (_home, _env) = scoped_lpm_home_with_env("0");
        let dir = tempfile::tempdir().unwrap();
        let specs = vec!["--legacy-peer-deps".to_string()];

        let err = guard_explicit_package_specs(
            dir.path(),
            &specs,
            &[dir.path().to_path_buf()],
            false,
            true,
        )
        .unwrap_err();

        assert!(matches!(err, LpmError::InvalidPackageName(_)));
    }

    #[test]
    fn explicit_guard_config_disable_preserves_package_name_validation() {
        let (_home, _env) = scoped_lpm_home_with_config("typosquat-guard = \"off\"\n");
        let dir = tempfile::tempdir().unwrap();
        let specs = vec!["--legacy-peer-deps".to_string()];

        let err = guard_explicit_package_specs(
            dir.path(),
            &specs,
            &[dir.path().to_path_buf()],
            false,
            true,
        )
        .unwrap_err();

        assert!(matches!(err, LpmError::InvalidPackageName(_)));
    }

    #[test]
    fn manifest_guard_skips_direct_dependency_already_in_lockfile() {
        let (_home, _env) = scoped_enabled_lpm_home();
        let dir = tempfile::tempdir().unwrap();
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.importers.insert(
            ".".to_string(),
            lpm_lockfile::ImporterSnapshot {
                dependencies: [("axois".to_string(), "^1.0.0".to_string())].into(),
                ..Default::default()
            },
        );
        lockfile
            .write_to_file(&dir.path().join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();
        let pkg = lpm_workspace::PackageJson {
            dependencies: HashMap::from([("axois".to_string(), "^1.0.0".to_string())]),
            ..Default::default()
        };

        guard_manifest_direct_dependencies(
            dir.path(),
            &dir.path().join("package.json"),
            &pkg,
            true,
        )
        .unwrap();
    }

    #[test]
    fn manifest_guard_env_disable_skips_suspicious_name_analysis() {
        let (_home, _env) = scoped_lpm_home_with_env("0");
        let dir = tempfile::tempdir().unwrap();
        let pkg = lpm_workspace::PackageJson {
            dependencies: HashMap::from([("axois".to_string(), "^1.0.0".to_string())]),
            ..Default::default()
        };

        guard_manifest_direct_dependencies(
            dir.path(),
            &dir.path().join("package.json"),
            &pkg,
            true,
        )
        .unwrap();
    }

    #[test]
    fn manifest_guard_env_disable_skips_typosquat_policy_loading() {
        let (_home, _env) = scoped_lpm_home_with_env("0");
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lpm.toml"), "[policy.typosquat.allow]\n").unwrap();
        let pkg = lpm_workspace::PackageJson {
            dependencies: HashMap::from([("axois".to_string(), "^1.0.0".to_string())]),
            ..Default::default()
        };

        guard_manifest_direct_dependencies(
            dir.path(),
            &dir.path().join("package.json"),
            &pkg,
            true,
        )
        .unwrap();
    }
}
