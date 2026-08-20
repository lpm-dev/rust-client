use crate::commands::{npm_auth, npm_stage, publish, publish_common, publish_npm};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::lpm_json::{self, NpmPublishConfig};
use std::path::Path;

pub(crate) struct StagePublishOptions<'a> {
    pub(crate) tag: Option<&'a str>,
    pub(crate) access: Option<&'a str>,
    pub(crate) dry_run: bool,
    pub(crate) provenance: bool,
    pub(crate) no_provenance: bool,
    pub(crate) provenance_file: Option<&'a Path>,
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
    let prepared = publish::prepare_publish_project(project_dir, !options.allow_secrets)?;
    let npm_config = prepared
        .publish_config
        .as_ref()
        .and_then(|config| config.npm.as_ref());
    let npm_name = npm_config
        .and_then(|config| config.name.clone())
        .map_or_else(|| publish_npm::resolve_npm_name(&prepared.name, None), Ok)?;
    let rewritten_tarball = publish_common::rewrite_tarball_name_for_publish(
        &prepared.tarball_data,
        &prepared.name,
        &npm_name,
        !options.allow_secrets,
    )?;
    if let Some(rewritten) = &rewritten_tarball {
        publish::validate_publish_tarball_size(rewritten.len())?;
    }
    let final_tarball_hashes = rewritten_tarball
        .as_ref()
        .map_or(&prepared.tarball_hashes, |tarball| &tarball.hashes);
    let final_secret_scan = rewritten_tarball
        .as_ref()
        .map_or(prepared.secret_scan.as_ref(), |tarball| {
            tarball.secret_scan.as_ref()
        });
    let registry =
        npm_stage::resolve_npm_stage_registry_with_source(npm_config, options.npm_registry)?;
    let access = resolve_stage_access(options.access, &npm_name, npm_config)?;
    let (tag, tag_explicit) = resolve_stage_tag(options.tag, npm_config);
    let provenance_request = publish::resolve_provenance_request_from_project_source(
        project_dir,
        &prepared.source_dir,
        &prepared.pkg_json,
        options.provenance,
        options.no_provenance,
        options.provenance_file,
    )?;
    if !matches!(provenance_request, publish::ProvenanceRequest::Disabled) && access != "public" {
        return Err(LpmError::Registry(format!(
            "npm provenance requires public access for {npm_name}. \
             Pass --access public or set publish.npm.access to \"public\"."
        )));
    }
    let version_data = publish::build_publish_version_data(
        &prepared.pkg_json,
        &prepared.name,
        &prepared.version,
        prepared.readme.as_deref(),
        &prepared.tarball_hashes,
    );
    let file_artifact = if matches!(provenance_request, publish::ProvenanceRequest::File(_)) {
        let provenance_context =
            publish::materialize_provenance_request(provenance_request.clone()).await?;
        Some(
            publish::prepare_npm_target_artifact(publish::NpmTargetArtifactInput {
                npm_name: &npm_name,
                version: &prepared.version,
                base_version_data: &version_data,
                final_tarball_hashes: std::sync::Arc::clone(final_tarball_hashes),
                provenance_context: provenance_context.as_ref(),
                target_label: "npm",
                json_output: options.json_output,
            })
            .await?,
        )
    } else {
        None
    };

    publish::run_publish_secret_scan(
        final_secret_scan.into_iter(),
        options.json_output,
        options.allow_secrets,
    )?;
    let quality = publish::run_publish_quality_gate(publish::PublishQualityGateInput {
        pkg_json: &prepared.pkg_json,
        readme: prepared.readme.as_deref(),
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
            "registry": registry.url(),
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
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Dry run · would stage {}",
                install_ui::yellow(&format!("{}@{}", npm_name, prepared.version))
            ));
        }
        return Ok(());
    }

    if !options.json_output && !options.yes {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            let confirm = cliclack::confirm(crate::prompt::untrusted(format!(
                "Stage {}@{} to npm?",
                npm_name, prepared.version
            )))
            .initial_value(true)
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;
            if !confirm {
                install_ui::skipped("Stage cancelled");
                return Ok(());
            }
        }
    }

    let auth = npm_auth::resolve_publish_auth_with_policy(
        &npm_name,
        registry.url(),
        auth_policy(&registry),
    )
    .await?;
    if auth.source() == npm_auth::NpmAuthSource::Oidc && !options.json_output {
        install_ui::phase("Using npm Trusted Publishing (OIDC)");
    }
    let metadata =
        npm_stage::fetch_package_metadata(auth.token(), &npm_name, registry.url()).await?;
    publish_npm::enforce_npm_version_policy(&metadata, &npm_name, &prepared.version, tag_explicit)?;
    let artifact = if let Some(artifact) = file_artifact {
        drop(provenance_request);
        artifact
    } else {
        let provenance_context =
            publish::materialize_provenance_request(provenance_request).await?;
        publish::prepare_npm_target_artifact(publish::NpmTargetArtifactInput {
            npm_name: &npm_name,
            version: &prepared.version,
            base_version_data: &version_data,
            final_tarball_hashes: std::sync::Arc::clone(final_tarball_hashes),
            provenance_context: provenance_context.as_ref(),
            target_label: "npm",
            json_output: options.json_output,
        })
        .await?
    };
    let final_tarball_data = rewritten_tarball.as_ref().map_or_else(
        || Ok(std::sync::Arc::clone(&prepared.tarball_data)),
        |tarball| tarball.read_data().map(std::sync::Arc::new),
    )?;

    let upload_spinner = if options.json_output {
        None
    } else {
        Some(install_ui::spin_line(crate::install_ui::terminal_line!(
            "Staging {} to npm",
            install_ui::yellow(&format!("{}@{}", npm_name, prepared.version))
        )))
    };

    let result = npm_stage::stage_publish(
        auth.token(),
        &npm_name,
        &prepared.version,
        &artifact.version_data,
        &final_tarball_data,
        &artifact.tarball_hashes,
        artifact.provenance_attachment.as_ref(),
        &access,
        &tag,
        registry.url(),
    )
    .await?;
    if let Some(spinner) = upload_spinner {
        spinner.settle();
    }

    if options.json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry.url(),
            "auth": auth.source().as_str(),
            "stageId": result.stage_id,
            "duration_ms": result.duration.as_millis() as u64,
            "data": result.data,
        }));
    } else {
        let elapsed = install_ui::green(&install_ui::format_duration(started_at.elapsed()));
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · staged {} with id {} in {}",
            install_ui::yellow(&format!("{}@{}", npm_name, prepared.version)),
            install_ui::cyan(&result.stage_id),
            elapsed,
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
    let registry =
        npm_stage::resolve_npm_stage_registry_with_source(npm_config.as_ref(), npm_registry)?;
    let package_filter = npm_stage::parse_stage_list_filter(package)?;
    let token = npm_token(&registry)?;
    let result =
        npm_stage::list_staged_packages(&token, registry.url(), package_filter.as_deref()).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry.url(),
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
    let registry =
        npm_stage::resolve_npm_stage_registry_with_source(npm_config.as_ref(), npm_registry)?;
    let token = npm_token(&registry)?;
    let data = npm_stage::view_staged_package(&token, registry.url(), stage_id).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry.url(),
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
    let registry =
        npm_stage::resolve_npm_stage_registry_with_source(npm_config.as_ref(), npm_registry)?;
    let token = npm_token(&registry)?;
    let result = npm_stage::download_staged_package(&token, registry.url(), stage_id, cwd).await?;

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry.url(),
            "stageId": stage_id,
            "path": result.path,
            "bytes": result.bytes,
            "data": result.manifest,
        }));
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
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
    let registry =
        npm_stage::resolve_npm_stage_registry_with_source(npm_config.as_ref(), npm_registry)?;
    let token = npm_token(&registry)?;
    let data = if approve {
        npm_stage::approve_staged_package(&token, registry.url(), stage_id, otp, json_output, yes)
            .await?
    } else {
        npm_stage::reject_staged_package(&token, registry.url(), stage_id, otp, json_output, yes)
            .await?
    };
    let action = if approve { "approved" } else { "rejected" };

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "target": "npm",
            "registry": registry.url(),
            "stageId": stage_id,
            "action": action,
            "data": data,
        }));
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Staged package {} {}",
            install_ui::cyan(stage_id),
            action,
        ));
    }

    Ok(())
}

fn npm_token(registry: &npm_stage::NpmStageRegistry) -> Result<String, LpmError> {
    npm_auth::resolve_token_auth_for_registry(registry.url(), auth_policy(registry))
        .map(|auth| auth.token().to_string())
}

fn auth_policy(registry: &npm_stage::NpmStageRegistry) -> npm_auth::NpmRegistryAuthPolicy {
    if registry.source() == npm_stage::NpmStageRegistrySource::Config
        && !npm_auth::registry_is_default_npm(registry.url())
    {
        npm_auth::NpmRegistryAuthPolicy::RequireRegistryScopedToken
    } else {
        npm_auth::NpmRegistryAuthPolicy::AllowAmbientNpmToken
    }
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
        let err = publish_npm::enforce_npm_version_policy(&metadata, "pkg", "1.0.0", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn enforce_stage_version_policy_requires_explicit_tag_for_prerelease() {
        let metadata = serde_json::json!({ "versions": { "1.0.0": {} } });
        let err = publish_npm::enforce_npm_version_policy(&metadata, "pkg", "1.1.0-beta.1", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--tag"));
    }

    #[test]
    fn enforce_stage_version_policy_blocks_implicit_latest_for_lower_version() {
        let metadata = serde_json::json!({ "versions": { "2.0.0": {} } });
        let err = publish_npm::enforce_npm_version_policy(&metadata, "pkg", "1.9.0", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("latest"));
    }

    #[test]
    fn enforce_stage_version_policy_allows_lower_version_with_explicit_tag() {
        let metadata = serde_json::json!({ "versions": { "2.0.0": {} } });
        assert!(publish_npm::enforce_npm_version_policy(&metadata, "pkg", "1.9.0", true).is_ok());
    }
}
