use crate::commands::{npm_auth, npm_stage, publish, publish_npm};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::lpm_json::{self, NpmPublishConfig};
use std::path::Path;

pub(crate) struct StagePublishOptions<'a> {
    pub(crate) tag: Option<&'a str>,
    pub(crate) access: Option<&'a str>,
    pub(crate) dry_run: bool,
    pub(crate) provenance: bool,
    pub(crate) min_score: Option<u32>,
    pub(crate) allow_secrets: bool,
    pub(crate) yes: bool,
    pub(crate) npm_registry: Option<&'a str>,
    pub(crate) json_output: bool,
}

pub(crate) async fn publish_current_project(
    project_dir: &Path,
    options: StagePublishOptions<'_>,
) -> Result<(), LpmError> {
    let started_at = std::time::Instant::now();
    let prepared = publish::prepare_publish_project(project_dir)?;
    let npm_config = prepared
        .publish_config
        .as_ref()
        .and_then(|config| config.npm.as_ref());
    let npm_name = npm_config
        .and_then(|config| config.name.clone())
        .map_or_else(|| publish_npm::resolve_npm_name(&prepared.name, None), Ok)?;
    let registry = npm_stage::resolve_npm_stage_registry(npm_config, options.npm_registry)?;
    let access = resolve_stage_access(options.access, &npm_name, npm_config)?;
    let (tag, tag_explicit) = resolve_stage_tag(options.tag, npm_config);

    publish::run_publish_secret_scan(project_dir, options.json_output, options.allow_secrets)?;
    let quality = publish::run_publish_quality_gate(publish::PublishQualityGateInput {
        pkg_json: &prepared.pkg_json,
        readme: prepared.readme.as_deref(),
        project_dir,
        tarball_files: &prepared.tarball_files,
        detected_ecosystem: &prepared.detected_ecosystem,
        swift_manifest: prepared.swift_manifest.as_ref(),
        min_score: options.min_score,
        json_output: options.json_output,
    })?;

    if options.dry_run {
        let json = serde_json::json!({
            "success": true,
            "dry_run": true,
            "target": "npm",
            "registry": registry,
            "name": npm_name,
            "version": prepared.version,
            "tag": tag,
            "access": access,
            "files": prepared.tarball_files.len(),
            "tarball_size": prepared.tarball_size,
            "quality": quality,
        });
        if options.json_output {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::done(&format!(
                "Dry run · would stage {}",
                install_ui::yellow(&format!("{}@{}", npm_name, prepared.version))
            ));
        }
        return Ok(());
    }

    if !options.json_output && !options.yes {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            let confirm =
                cliclack::confirm(format!("Stage {}@{} to npm?", npm_name, prepared.version))
                    .initial_value(true)
                    .interact()
                    .map_err(|e| LpmError::Registry(e.to_string()))?;
            if !confirm {
                install_ui::skipped("Stage cancelled");
                return Ok(());
            }
        }
    }

    let auth = npm_auth::resolve_publish_auth(&npm_name, &registry).await?;
    if auth.source() == npm_auth::NpmAuthSource::Oidc && !options.json_output {
        install_ui::phase("Using npm Trusted Publishing (OIDC)");
    }
    let metadata = npm_stage::fetch_package_metadata(auth.token(), &npm_name, &registry).await?;
    enforce_stage_version_policy(&metadata, &npm_name, &prepared.version, tag_explicit)?;
    let version_data = publish::build_publish_version_data(
        &prepared.pkg_json,
        &prepared.name,
        &prepared.version,
        prepared.readme.as_deref(),
        &prepared.tarball_data,
    );
    let provenance_context = publish::resolve_provenance_context(options.provenance).await?;
    let artifact = publish::prepare_npm_target_artifact(publish::NpmTargetArtifactInput {
        package_json_name: &prepared.name,
        npm_name: &npm_name,
        version: &prepared.version,
        base_version_data: &version_data,
        base_tarball_data: &prepared.tarball_data,
        provenance_context: provenance_context.as_ref(),
        target_label: "npm",
        json_output: options.json_output,
    })
    .await?;

    let upload_spinner = if options.json_output {
        None
    } else {
        Some(install_ui::spin(&format!(
            "Staging {} to npm",
            install_ui::yellow(&format!("{}@{}", npm_name, prepared.version))
        )))
    };

    let result = npm_stage::stage_publish(
        auth.token(),
        &npm_name,
        &prepared.version,
        &artifact.version_data,
        &artifact.tarball_data,
        &access,
        &tag,
        &registry,
    )
    .await?;
    if let Some(spinner) = upload_spinner {
        spinner.settle();
    }

    if options.json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry,
            "auth": auth.source().as_str(),
            "stageId": result.stage_id,
            "duration_ms": result.duration.as_millis() as u64,
            "data": result.data,
        }));
    } else {
        let elapsed = install_ui::green(&install_ui::format_duration(started_at.elapsed()));
        install_ui::done(&format!(
            "Done · staged {} with id {} in {elapsed}",
            install_ui::yellow(&format!("{}@{}", npm_name, prepared.version)),
            install_ui::cyan(&result.stage_id),
        ));
    }

    Ok(())
}

pub(crate) async fn list(
    cwd: &Path,
    package: Option<&str>,
    npm_registry: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let npm_config = read_npm_config(cwd);
    let registry = npm_stage::resolve_npm_stage_registry(npm_config.as_ref(), npm_registry)?;
    let package_filter = npm_stage::parse_stage_list_filter(package)?;
    let token = npm_token()?;
    let result =
        npm_stage::list_staged_packages(&token, &registry, package_filter.as_deref()).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry,
            "total": result.total,
            "data": result.items,
        }));
    } else if result.items.is_empty() {
        install_ui::done("No staged packages found");
    } else {
        for item in result.items {
            print_stage_item(&item);
        }
    }

    Ok(())
}

pub(crate) async fn view(
    cwd: &Path,
    stage_id: &str,
    npm_registry: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let npm_config = read_npm_config(cwd);
    let registry = npm_stage::resolve_npm_stage_registry(npm_config.as_ref(), npm_registry)?;
    let token = npm_token()?;
    let data = npm_stage::view_staged_package(&token, &registry, stage_id).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry,
            "stageId": stage_id,
            "data": data,
        }));
    } else {
        print_stage_item(&data);
    }

    Ok(())
}

pub(crate) async fn approve(
    cwd: &Path,
    stage_id: &str,
    otp: Option<&str>,
    npm_registry: Option<&str>,
    json_output: bool,
    yes: bool,
) -> Result<(), LpmError> {
    mutate_stage(cwd, stage_id, otp, npm_registry, json_output, yes, true).await
}

pub(crate) async fn reject(
    cwd: &Path,
    stage_id: &str,
    otp: Option<&str>,
    npm_registry: Option<&str>,
    json_output: bool,
    yes: bool,
) -> Result<(), LpmError> {
    mutate_stage(cwd, stage_id, otp, npm_registry, json_output, yes, false).await
}

pub(crate) async fn download(
    cwd: &Path,
    stage_id: &str,
    npm_registry: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let npm_config = read_npm_config(cwd);
    let registry = npm_stage::resolve_npm_stage_registry(npm_config.as_ref(), npm_registry)?;
    let token = npm_token()?;
    let result = npm_stage::download_staged_package(&token, &registry, stage_id, cwd).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry,
            "stageId": stage_id,
            "path": result.path,
            "bytes": result.bytes,
            "data": result.manifest,
        }));
    } else {
        install_ui::done(&format!(
            "Downloaded staged package to {}",
            install_ui::cyan(&result.path.display().to_string())
        ));
    }

    Ok(())
}

async fn mutate_stage(
    cwd: &Path,
    stage_id: &str,
    otp: Option<&str>,
    npm_registry: Option<&str>,
    json_output: bool,
    yes: bool,
    approve: bool,
) -> Result<(), LpmError> {
    let npm_config = read_npm_config(cwd);
    let registry = npm_stage::resolve_npm_stage_registry(npm_config.as_ref(), npm_registry)?;
    let token = npm_token()?;
    let data = if approve {
        npm_stage::approve_staged_package(&token, &registry, stage_id, otp, json_output, yes)
            .await?
    } else {
        npm_stage::reject_staged_package(&token, &registry, stage_id, otp, json_output, yes).await?
    };
    let action = if approve { "approved" } else { "rejected" };

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry,
            "stageId": stage_id,
            "action": action,
            "data": data,
        }));
    } else {
        install_ui::done(&format!(
            "Staged package {} {action}",
            install_ui::cyan(stage_id)
        ));
    }

    Ok(())
}

fn npm_token() -> Result<String, LpmError> {
    npm_auth::resolve_token_auth().map(|auth| auth.token().to_string())
}

fn read_npm_config(cwd: &Path) -> Option<NpmPublishConfig> {
    lpm_json::read_lpm_json(cwd)
        .ok()
        .flatten()
        .and_then(|config| config.publish)
        .and_then(|publish| publish.npm)
}

fn resolve_stage_access(
    cli_access: Option<&str>,
    npm_name: &str,
    npm_config: Option<&NpmPublishConfig>,
) -> Result<String, LpmError> {
    let access = cli_access.map_or_else(
        || publish_npm::resolve_npm_access(npm_name, npm_config),
        str::to_string,
    );
    match access.as_str() {
        "public" | "restricted" => Ok(access),
        other => Err(LpmError::Registry(format!(
            "invalid npm access {other:?}: expected public or restricted"
        ))),
    }
}

fn resolve_stage_tag(
    cli_tag: Option<&str>,
    npm_config: Option<&NpmPublishConfig>,
) -> (String, bool) {
    if let Some(tag) = cli_tag {
        return (tag.to_string(), true);
    }
    if let Some(tag) = npm_config.and_then(|config| config.tag.as_deref()) {
        return (tag.to_string(), true);
    }
    ("latest".to_string(), false)
}

fn enforce_stage_version_policy(
    metadata: &serde_json::Value,
    npm_name: &str,
    version: &str,
    tag_explicit: bool,
) -> Result<(), LpmError> {
    let versions = metadata
        .get("versions")
        .and_then(|value| value.as_object())
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "npm metadata for {npm_name} is missing published versions"
            ))
        })?;

    if versions.contains_key(version) {
        return Err(LpmError::Registry(format!(
            "version {version} already exists on npm for {npm_name}"
        )));
    }

    let current = lpm_semver::Version::parse(version)?;
    if current.is_prerelease() && !tag_explicit {
        return Err(LpmError::Registry(
            "You must specify a tag using --tag when staging a prerelease version.".into(),
        ));
    }

    if tag_explicit {
        return Ok(());
    }

    let highest = versions
        .iter()
        .filter(|(_, data)| {
            !data
                .get("deprecated")
                .is_some_and(|value| value.is_string())
        })
        .filter_map(|(published_version, _)| lpm_semver::Version::parse(published_version).ok())
        .filter(|published_version| !published_version.is_prerelease())
        .max();

    if let Some(highest) = highest
        && highest >= current
    {
        return Err(LpmError::Registry(format!(
            "Cannot implicitly apply the \"latest\" tag because previously published version {highest} is higher than the new version {version}. You must specify a tag using --tag."
        )));
    }

    Ok(())
}

fn print_stage_item(item: &serde_json::Value) {
    let id = item
        .get("id")
        .or_else(|| item.get("stageId"))
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let package = item
        .get("packageName")
        .or_else(|| item.get("name"))
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let version = item
        .get("version")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let tag = item
        .get("tag")
        .and_then(|value| value.as_str())
        .unwrap_or("latest");

    println!(
        "{} {} {}",
        install_ui::cyan(id),
        install_ui::yellow(&format!("{package}@{version}")),
        install_ui::yellow(tag)
    );
}

fn print_json(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_stage_tag_treats_config_tag_as_explicit() {
        let config = NpmPublishConfig {
            tag: Some("next".to_string()),
            ..NpmPublishConfig::default()
        };
        assert_eq!(
            resolve_stage_tag(None, Some(&config)),
            ("next".to_string(), true)
        );
    }

    #[test]
    fn enforce_stage_version_policy_blocks_duplicate_published_version() {
        let metadata = serde_json::json!({ "versions": { "1.0.0": {} } });
        let err = enforce_stage_version_policy(&metadata, "pkg", "1.0.0", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn enforce_stage_version_policy_requires_explicit_tag_for_prerelease() {
        let metadata = serde_json::json!({ "versions": { "1.0.0": {} } });
        let err = enforce_stage_version_policy(&metadata, "pkg", "1.1.0-beta.1", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--tag"));
    }

    #[test]
    fn enforce_stage_version_policy_blocks_implicit_latest_for_lower_version() {
        let metadata = serde_json::json!({ "versions": { "2.0.0": {} } });
        let err = enforce_stage_version_policy(&metadata, "pkg", "1.9.0", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("latest"));
    }

    #[test]
    fn enforce_stage_version_policy_allows_lower_version_with_explicit_tag() {
        let metadata = serde_json::json!({ "versions": { "2.0.0": {} } });
        assert!(enforce_stage_version_policy(&metadata, "pkg", "1.9.0", true).is_ok());
    }
}
