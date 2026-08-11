use super::npm_artifact::{load_provenance_file, prepare_npm_target_artifact};
use super::output::{
    DryRunSummary, format_lpm_publication_notice, format_multi_publish_partial_summary,
    format_multi_publish_success_summary, format_publish_retry_detail,
    format_single_publish_success_summary, format_upload_message, lpm_visibility,
    print_dry_run_summary, print_upload_details, publish_check_json, publish_detail,
    publish_result_json, visibility_from_access,
};
use super::prepare::{
    prepare_publish_project_from_manifest, read_publish_manifest, validate_publish_tarball_size,
};
use super::provenance::{
    ProvenanceRequest, materialize_provenance_request, resolve_provenance_request,
};
use super::quality_gate::run_publish_quality_gate;
use super::secret_scan::run_publish_secret_scan;
use super::skills::{ManifestWriteMode, compute_published_skills_digest, ensure_lpm_in_files};
use super::target::resolve_targets;
use super::types::{
    LpmPublicationStatus, NpmTargetArtifact, NpmTargetArtifactInput, PublicationWaitResult,
    PublishProject, PublishQualityGateInput, PublishResult, PublishTarget, ResolvedProvenance,
};
use super::upload_lpm::publish_to_lpm;
use super::version_data::{build_publish_version_data, integrity_to_sha512_hex};
use super::wait::{DEFAULT_PUBLICATION_WAIT_TIMEOUT, wait_for_lpm_publication_with_oidc};
use crate::commands::skills::author;
use crate::commands::{npm_auth, publish_common, publish_npm};
use crate::{auth, install_ui, oidc, provenance, sigstore};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::collections::HashMap;
use std::path::Path;

struct NpmFilePreflightInput<'a> {
    provenance_request: &'a ProvenanceRequest,
    targets: &'a [PublishTarget],
    target_names: &'a HashMap<String, String>,
    package_json_name: &'a str,
    version: &'a str,
    version_data: &'a serde_json::Value,
    tarball_data: &'a std::sync::Arc<Vec<u8>>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
    json_output: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    dry_run: bool,
    check_only: bool,
    wait_for_publication: bool,
    wait_timeout_seconds: Option<u64>,
    yes: bool,
    json_output: bool,
    min_score: Option<u32>,
    allow_secrets: bool,
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    provenance_flag: bool,
    no_provenance: bool,
    provenance_file: Option<&Path>,
) -> Result<(), LpmError> {
    let publish_started = std::time::Instant::now();

    let mut publish_manifest = read_publish_manifest(project_dir)?;

    // Resolve target registries
    let targets = resolve_targets(
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
        publish_manifest.publish_config.as_ref(),
    )?;

    // Cap registry fan-out so one publish command cannot spray tokens too broadly.
    const MAX_REGISTRIES: usize = 5;
    if targets.len() > MAX_REGISTRIES {
        return Err(LpmError::Registry(format!(
            "too many target registries ({}, max {MAX_REGISTRIES})",
            targets.len()
        )));
    }

    let targets_lpm = targets.contains(&PublishTarget::Lpm);
    if wait_for_publication && !targets_lpm {
        return Err(LpmError::Registry(
            "--wait requires publishing to the LPM registry".into(),
        ));
    }
    let publication_wait_timeout = wait_for_publication.then(|| {
        wait_timeout_seconds.map_or(
            DEFAULT_PUBLICATION_WAIT_TIMEOUT,
            std::time::Duration::from_secs,
        )
    });
    if targets_lpm {
        let lpm_name = publish_manifest
            .publish_config
            .as_ref()
            .and_then(|config| config.lpm.as_ref())
            .and_then(|config| config.name.as_deref())
            .unwrap_or(&publish_manifest.name);
        if !lpm_name.starts_with("@lpm.dev/") {
            return Err(LpmError::Registry(format!(
                "LPM registry requires @lpm.dev/ prefix (got \"{lpm_name}\"). \
						 Set publish.lpm.name in lpm.json."
            )));
        }
    }

    // Publisher-authored skills must be validated and included in a restrictive
    // package.json `files` list before the publish tarball is created.
    let skills_dir = project_dir.join(".lpm").join("skills");
    let has_skills = if targets_lpm {
        let validation = author::validate_directory(&skills_dir)?;

        if !validation.security_issues.is_empty() {
            for located in &validation.security_issues {
                let issue = &located.issue;
                install_ui::warn_untrusted(&format!(
                    "Skill security: {}: {} — {} at line {} ({})",
                    lpm_common::sanitize_terminal_inline(&located.path),
                    lpm_common::sanitize_terminal_inline(&issue.matched_text),
                    lpm_common::sanitize_terminal_inline(&issue.category),
                    issue.line_number,
                    lpm_common::sanitize_terminal_inline(&issue.pattern)
                ));
            }
            return Err(LpmError::Registry(
                "skills contain blocked security patterns".into(),
            ));
        }

        if !validation.errors.is_empty() {
            for error in &validation.errors {
                install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(error));
            }
            return Err(LpmError::Registry(
                "skills validation failed — fix errors above".into(),
            ));
        }

        let has_authored_skills = !validation.valid_files.is_empty();
        if has_authored_skills {
            if !json_output {
                install_ui::done_untrusted(&format!(
                    "{} skill(s) validated",
                    validation.valid_files.len()
                ));
            }
            let write_mode = if dry_run || check_only {
                ManifestWriteMode::ReadOnly
            } else {
                ManifestWriteMode::Persist
            };
            ensure_lpm_in_files(&mut publish_manifest, write_mode)?;
        }
        has_authored_skills
    } else {
        false
    };

    let PublishProject {
        pkg_json,
        name,
        version,
        publish_config,
        readme,
        tarball_data,
        tarball_files,
        secret_scan,
        tarball_size,
        detected_ecosystem,
        swift_manifest,
    } = prepare_publish_project_from_manifest(project_dir, publish_manifest, !allow_secrets)?;
    let publish_config = publish_config.as_ref();

    let targets_gitlab = targets.iter().any(|t| matches!(t, PublishTarget::GitLab));

    // GitLab Packages requires projectId in lpm.json
    if targets_gitlab {
        let gl_config = publish_config.and_then(|p| p.gitlab.as_ref());
        if gl_config.and_then(|c| c.project_id.as_deref()).is_none() {
            return Err(LpmError::Registry(
                "GitLab Packages requires publish.gitlab.projectId in lpm.json".into(),
            ));
        }
    }

    // Resolve the package name used by each target.
    // Each registry can have its own name override in lpm.json.
    // package.json `name` is the fallback when no config override exists.
    let lpm_config = publish_config.and_then(|p| p.lpm.as_ref());
    let npm_config = publish_config.and_then(|p| p.npm.as_ref());
    let github_config = publish_config.and_then(|p| p.github.as_ref());
    let gitlab_config = publish_config.and_then(|p| p.gitlab.as_ref());

    let mut target_names: HashMap<String, String> = HashMap::new();
    for target in &targets {
        let resolved = match target {
            PublishTarget::Lpm => {
                // LPM: config override → package.json name. Must be @lpm.dev/.
                let lpm_name = lpm_config
                    .and_then(|c| c.name.clone())
                    .unwrap_or_else(|| name.to_string());
                if !lpm_name.starts_with("@lpm.dev/") {
                    return Err(LpmError::Registry(format!(
                        "LPM registry requires @lpm.dev/ prefix (got \"{lpm_name}\"). \
						 Set publish.lpm.name in lpm.json."
                    )));
                }
                lpm_name
            }
            PublishTarget::Npm => {
                // npm: config override → package.json name. Reject @lpm.dev/.
                npm_config
                    .and_then(|c| c.name.clone())
                    .map_or_else(|| publish_npm::resolve_npm_name(&name, None), Ok)?
            }
            PublishTarget::GitHub => {
                // GitHub: config override → npm config → package.json. Must be scoped.
                let gh_name = github_config
                    .and_then(|c| c.name.clone())
                    .or_else(|| npm_config.and_then(|c| c.name.clone()))
                    .map_or_else(|| publish_npm::resolve_npm_name(&name, None), Ok)?;
                if !gh_name.starts_with('@') {
                    return Err(LpmError::Registry(
                        "GitHub Packages requires scoped package names (@owner/package). \
						 Set publish.github.name in lpm.json."
                            .into(),
                    ));
                }
                gh_name
            }
            PublishTarget::GitLab => {
                // GitLab: config override → npm config → package.json.
                gitlab_config
                    .and_then(|c| c.name.clone())
                    .or_else(|| npm_config.and_then(|c| c.name.clone()))
                    .map_or_else(|| publish_npm::resolve_npm_name(&name, None), Ok)?
            }
            PublishTarget::Custom(_) => {
                // Custom: npm config → package.json.
                npm_config
                    .and_then(|c| c.name.clone())
                    .map_or_else(|| publish_npm::resolve_npm_name(&name, None), Ok)?
            }
        };
        target_names.insert(target.key(), resolved);
    }

    let provenance_request = resolve_provenance_request(
        project_dir,
        &pkg_json,
        provenance_flag,
        no_provenance,
        provenance_file,
    )?;
    if matches!(provenance_request, ProvenanceRequest::File(_)) && targets_lpm {
        return Err(LpmError::Registry(
            "--provenance-file is only supported for npm-compatible publish targets".into(),
        ));
    }
    if !matches!(provenance_request, ProvenanceRequest::Disabled) {
        for target in &targets {
            if !is_npm_compatible_target(target) {
                continue;
            }
            let npm_name_str = target_names.get(&target.key()).ok_or_else(|| {
                LpmError::Registry(format!("no name resolved for {}", target.display_name()))
            })?;
            let npm_access = match target {
                PublishTarget::GitHub => github_config
                    .and_then(|c| c.access.clone())
                    .unwrap_or_else(|| publish_npm::resolve_npm_access(npm_name_str, npm_config)),
                PublishTarget::GitLab => gitlab_config
                    .and_then(|c| c.access.clone())
                    .unwrap_or_else(|| publish_npm::resolve_npm_access(npm_name_str, npm_config)),
                _ => publish_npm::resolve_npm_access(npm_name_str, npm_config),
            };
            if npm_access != "public" {
                return Err(LpmError::Registry(format!(
                    "npm provenance requires public access for {npm_name_str}. \
                     Set publish.npm.access to \"public\" or omit restricted access."
                )));
            }
        }
    }

    let rewritten_tarballs = prepare_rewritten_target_tarballs(
        &targets,
        &target_names,
        &name,
        &tarball_data,
        !allow_secrets,
    )?;
    let version_data =
        build_publish_version_data(&pkg_json, &name, &version, readme.as_deref(), &tarball_data);
    let mut precomputed_npm_artifacts =
        precompute_file_provenance_artifacts(NpmFilePreflightInput {
            provenance_request: &provenance_request,
            targets: &targets,
            target_names: &target_names,
            package_json_name: &name,
            version: &version,
            version_data: &version_data,
            tarball_data: &tarball_data,
            rewritten_tarballs: &rewritten_tarballs,
            json_output,
        })
        .await?;

    let mut final_secret_scans = Vec::with_capacity(targets.len());
    if !allow_secrets {
        for target in &targets {
            let target_name = target_names.get(&target.key()).ok_or_else(|| {
                LpmError::Registry(format!("no name resolved for {}", target.display_name()))
            })?;
            final_secret_scans.push(target_secret_scan(
                target_name,
                &name,
                secret_scan.as_ref(),
                &rewritten_tarballs,
            )?);
        }
    }
    run_publish_secret_scan(final_secret_scans, json_output, allow_secrets)?;

    // Quality checks are required only for the LPM target.
    let quality_result = if targets_lpm {
        Some(run_publish_quality_gate(PublishQualityGateInput {
            pkg_json: &pkg_json,
            readme: readme.as_deref(),
            project_dir,
            tarball_files: &tarball_files,
            detected_ecosystem: &detected_ecosystem,
            swift_manifest: swift_manifest.as_ref(),
            min_score,
            json_output,
        })?)
    } else {
        None
    };

    // OIDC auto-exchange is limited to LPM publishes, real publish, and dry-run.
    //
    // Gated on `targets_lpm && !check_only`:
    //
    // - **`targets_lpm`** — `--npm` / `--github` / `--gitlab`-only publishes
    //   never touch the LPM target client, so leaking the package name to the
    //   LPM exchange endpoint would be a privacy violation with no upside.
    // - **`!check_only`** — `--check` is a local-validation surface; running
    //   a real CI OIDC exchange there mints a session token the user never
    //   asked for and contradicts the documented contract. `--dry-run` IS
    //   honored — it forms part of the LPM-side preflight (alongside the
    //   skills-staleness lookup below) so OIDC trust misconfiguration
    //   surfaces before a real publish. The dry-run authorization and version
    //   check runs below; upload-only checks still run only on a real publish.
    //
    // This runs before the skill-staleness check so the first LPM network
    // call uses the exchanged client too.
    //
    // The origin requires `package` for `scope=publish`, and the package name
    // only becomes known after `package.json` is parsed — that's why this
    // can't live in main.rs.
    //
    let mut oidc_token_for_wait = None;
    let oidc_swapped_client;
    let client: &RegistryClient =
        if targets_lpm && !check_only && oidc::registry_exchange_jwt_available() {
            let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
                LpmError::Registry("no resolved LPM.dev package name for OIDC exchange".into())
            })?;
            let oidc_token = oidc::exchange_publish_oidc_token(
                client.base_url(),
                resolved_lpm_name,
                publication_wait_timeout,
            )
            .await
            .map_err(|error| {
                LpmError::Registry(format!(
                    "Trusted Publisher exchange failed for {resolved_lpm_name}: {error}"
                ))
            })?;
            if let Some(timeout) = publication_wait_timeout {
                oidc_token.publication_status_token_for_wait(timeout)?;
                oidc_token_for_wait = Some(oidc_token.clone());
            }
            oidc_swapped_client = client
                .clone_with_config()
                .with_token_override(oidc_token.token);
            if !json_output {
                install_ui::phase("Using OIDC-exchanged session token for LPM publish");
            }
            &oidc_swapped_client
        } else {
            client
        };

    // Skills staleness check is an LPM network read, so skip it in --check.
    //
    // Gated to skip in `--check` mode: this is a network read against the
    // LPM registry, and `--check` is the local-validation surface. Kept on
    // for `--dry-run` because the staleness diagnostic ("your skills are
    // identical to the previously published version") is part of the
    // LPM-side preflight a dry-run is meant to surface.
    if has_skills && targets_lpm && !check_only {
        let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
            LpmError::Registry("no resolved LPM.dev package name for skills preflight".into())
        })?;
        let name_short = resolved_lpm_name
            .strip_prefix("@lpm.dev/")
            .unwrap_or(resolved_lpm_name);
        let prev = match client.get_skills(name_short, None).await {
            Ok(prev) => Some(prev),
            Err(LpmError::NotFound(_)) => None,
            Err(error) => {
                return Err(LpmError::Registry(format!(
                    "could not check previously published skills for {resolved_lpm_name}: {error}"
                )));
            }
        };
        if let Some(prev) = prev
            && !prev.skills.is_empty()
        {
            let local_digest = author::compute_digest(&skills_dir)?;
            let published_digest = compute_published_skills_digest(&prev.skills);
            if local_digest == published_digest && !json_output {
                install_ui::warn(
                    "Skills are identical to the previously published version — consider updating them",
                );
            }
        }
    }

    // Check-only and dry-run modes stop before publishing.
    if check_only {
        if json_output {
            let json = publish_check_json(quality_result.as_ref(), &targets, &target_names);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        return Ok(());
    }

    if dry_run {
        if targets_lpm {
            let resolved_lpm_name = target_names.get("lpm").ok_or_else(|| {
                LpmError::Registry("no resolved LPM.dev package name for publish preflight".into())
            })?;
            client
                .publish_preflight(resolved_lpm_name, &version)
                .await
                .map_err(|error| {
                    LpmError::Registry(format!(
                        "LPM.dev publish preflight failed for {resolved_lpm_name}@{version}: {error}"
                    ))
                })?;
        }
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "dry_run": true,
                "name": name,
                "version": version,
                "files": tarball_files.len(),
                "tarball_size": tarball_size,
                "quality": quality_result,
                "targets": targets.iter().map(|t| {
                    let key = t.key();
                    let name = target_names.get(&key);
                    serde_json::json!({"registry": key, "name": name})
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            let eco = detected_ecosystem.clone();

            let summary = DryRunSummary {
                name: &name,
                version: &version,
                target_names: &target_names,
                file_count: tarball_files.len(),
                tarball_size,
                quality_result: quality_result.as_ref(),
                has_skills,
                ecosystem: &eco,
                targets: &targets,
            };
            print_dry_run_summary(&summary);
        }
        return Ok(());
    }

    // Prompt before a real human-facing publish unless explicitly confirmed.
    if !json_output && !yes {
        println!();
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            let safe_name = lpm_common::sanitize_terminal_inline(&name);
            let safe_version = lpm_common::sanitize_terminal_inline(&version);
            let prompt_msg = if targets.len() > 1 {
                format!(
                    "Publish {safe_name}@{safe_version} to {}?",
                    targets
                        .iter()
                        .map(|t| t.display_name())
                        .collect::<Vec<_>>()
                        .join(" + ")
                )
            } else {
                format!("Publish {safe_name}@{safe_version}?")
            };
            let confirm = cliclack::confirm(prompt_msg)
                .initial_value(true)
                .interact()
                .map_err(|e| LpmError::Registry(e.to_string()))?;

            if !confirm {
                install_ui::skipped("Publish cancelled");
                return Ok(());
            }
        }
    }

    let provenance_context = if matches!(provenance_request, ProvenanceRequest::File(_)) {
        None
    } else {
        materialize_provenance_request(provenance_request).await?
    };

    // Publish sequentially so per-target auth prompts and summaries stay deterministic.
    // All per-target errors are caught and collected — the loop NEVER aborts early.
    let mut results: Vec<PublishResult> = Vec::with_capacity(targets.len());

    for target in &targets {
        let start = std::time::Instant::now();

        match target {
            PublishTarget::Lpm => {
                // Wrap the entire LPM publish path so any error becomes a PublishResult
                let lpm_result: Result<serde_json::Value, LpmError> = async {
                    let lpm_name = target_names.get("lpm").map_or(name.as_str(), |s| s.as_str());

                    let lpm_tarball = target_tarball_data(
                        lpm_name,
                        &name,
                        &tarball_data,
                        &rewritten_tarballs,
                    )?;

                    // Recompute dist hashes from the final rewritten tarball so metadata
                    // matches the actual uploaded artifact (not the pre-rewrite original).
                    let mut lpm_version_data = version_data.clone();
                    if lpm_name != name.as_str() {
                        let lpm_hashes = publish_common::compute_hashes(lpm_tarball);
                        lpm_version_data["dist"] = serde_json::json!({
                            "shasum": lpm_hashes.shasum,
                            "integrity": lpm_hashes.integrity,
                        });
                    }

                    // Generate per-target provenance from the final rewritten tarball
                    if let Some(ref provenance) = provenance_context {
                        let ResolvedProvenance::Generate(context) = provenance else {
                            return Err(LpmError::Registry(
                                "--provenance-file is only supported for npm-compatible publish targets"
                                    .into(),
                            ));
                        };
                        let final_hashes = publish_common::compute_hashes(lpm_tarball);
                        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
                        let slsa = provenance::build_slsa_statement(
                            &context.ci,
                            lpm_name,
                            &version,
                            &sha512_hex,
                        );
                        let slsa_json = serde_json::to_vec(&slsa)
                            .map_err(|e| LpmError::Registry(format!("failed to serialize SLSA statement: {e}")))?;

                        // --provenance is strict: fail if Sigstore fails
                        let bundle = sigstore::sign_and_record(&context.jwt, &slsa_json).await
                            .map_err(|e| LpmError::Registry(format!(
                                "Sigstore provenance failed: {e}. \
                                 Publish aborted because --provenance requires successful provenance generation."
                            )))?;

                        if !json_output {
                            install_ui::done("Sigstore provenance generated and recorded in Rekor");
                        }
                        let bundle_json = serde_json::to_value(&bundle).unwrap_or_default();
                        lpm_version_data["_provenance"] = bundle_json.clone();
                        lpm_version_data["_npmProvenanceAttestations"] = bundle_json;
                    }

                    let upload_spinner = if json_output {
                        None
                    } else {
                        Some(install_ui::spin_line(format_upload_message("lpm.dev")))
                    };
                    let response = publish_to_lpm(
                        client,
                        project_dir,
                        lpm_name,
                        &version,
                        &readme,
                        lpm_tarball,
                        &tarball_files,
                        &lpm_version_data,
                        &quality_result,
                        json_output,
                        &detected_ecosystem,
                        &swift_manifest,
                    )
                    .await?;
                    drop(upload_spinner);
                    if !json_output {
                        print_upload_details(lpm_name, &version, lpm_visibility(&pkg_json), "latest");
                    }
                    Ok(response)
                }
                .await;

                let duration = start.elapsed();
                let lpm_name = target_names
                    .get("lpm")
                    .map_or(name.as_str(), |s| s.as_str());
                match lpm_result {
                    Ok(resp) => {
                        let publication_status =
                            LpmPublicationStatus::from_registry_response(&resp);
                        let current_latest_version = resp
                            .get("currentLatestVersion")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string);
                        if !json_output {
                            if let Some(url) = lpm_package_url(lpm_name) {
                                publish_detail("url", install_ui::url(&url));
                            }
                            if let Some(notice) = publication_status
                                .as_ref()
                                .and_then(format_lpm_publication_notice)
                            {
                                install_ui::warn_line(notice);
                            }
                            if !matches!(
                                publication_status.as_ref(),
                                Some(LpmPublicationStatus::Active)
                            ) {
                                publish_detail(
                                    "current latest",
                                    install_ui::yellow(
                                        current_latest_version.as_deref().unwrap_or("none"),
                                    ),
                                );
                            }
                            if let Some(warnings) = resp.get("warnings").and_then(|w| w.as_array())
                            {
                                for w in warnings {
                                    if let Some(msg) = w.as_str() {
                                        install_ui::warn_untrusted(
                                            &lpm_common::sanitize_terminal_inline(msg),
                                        );
                                    }
                                }
                            }
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: true,
                            error: None,
                            auth: None,
                            publication_status,
                            current_latest_version,
                            publication_wait: None,
                            duration,
                        });
                    }
                    Err(e) => {
                        if !json_output {
                            let error = e.to_string();
                            install_ui::warn_untrusted(&format!(
                                "LPM publish failed: {}",
                                lpm_common::sanitize_terminal_inline(&error)
                            ));
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: false,
                            error: Some(e.to_string()),
                            auth: None,
                            publication_status: None,
                            current_latest_version: None,
                            publication_wait: None,
                            duration,
                        });
                    }
                }
            }
            PublishTarget::Npm
            | PublishTarget::GitHub
            | PublishTarget::GitLab
            | PublishTarget::Custom(_) => {
                // Wrap the entire npm-like target path so any error becomes a PublishResult.
                // This ensures the loop always continues to the next target.
                let npm_target_result: Result<PublishResult, LpmError> = async {
                    let npm_name_str = target_names.get(&target.key()).ok_or_else(|| {
                        LpmError::Registry(format!(
                            "no name resolved for {}",
                            target.display_name()
                        ))
                    })?;

                    // Resolve registry URL, token, display name per target
                    let (registry_url, token, display, auth_source) = match target {
                        PublishTarget::Npm => {
                            let registry_url = publish_npm::resolve_npm_registry(npm_config);
                            let npm_auth =
                                npm_auth::resolve_publish_auth(npm_name_str, &registry_url)
                                    .await?;
                            (
                                registry_url,
                                npm_auth.token().to_string(),
                                "npm",
                                Some(npm_auth.source().as_str()),
                            )
                        }
                        PublishTarget::GitHub => (
                            "https://npm.pkg.github.com".to_string(),
                            auth::get_github_token().ok_or_else(|| {
                                LpmError::Registry(
                                    "no GitHub Packages token found. Run `gh auth login --hostname github.com`, run `lpm login --github --token <pat>`, or set GITHUB_TOKEN.".into(),
                                )
                            })?,
                            "GitHub Packages",
                            None,
                        ),
                        PublishTarget::GitLab => {
                            let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
                            let project_id = gl_cfg
                                .and_then(|c| c.project_id.as_deref())
                                .ok_or_else(|| {
                                    LpmError::Registry(
                                        "GitLab publish requires publish.gitlab.projectId in lpm.json"
                                            .into(),
                                    )
                                })?;
                            let gitlab_host = gl_cfg
                                .and_then(|c| c.registry.as_deref())
                                .unwrap_or("https://gitlab.com");
                            // A project lpm.json can override the GitLab host while still
                            // naming `gitlab` as a publish target. Warn before the
                            // GitLab token is sent to a non-default host.
                            if gitlab_host.trim_end_matches('/') != "https://gitlab.com" {
                                tracing::warn!(
                                    target_url = %gitlab_host,
                                    "publish.gitlab.registry overridden — GitLab token will be sent to a non-default host; \
                                     confirm this is intentional",
                                );
                            }
                            let url = format!(
                                "{}/api/v4/projects/{}/packages/npm",
                                gitlab_host.trim_end_matches('/'),
                                urlencoding::encode(project_id)
                            );
                            (
                                url,
                                auth::get_gitlab_token_for_host(gitlab_host).ok_or_else(|| {
                                    LpmError::Registry(
                                        "no GitLab Packages token found. For gitlab.com, run `glab auth login`; otherwise run `lpm login --gitlab --token <token>` or set GITLAB_TOKEN/CI_JOB_TOKEN.".into(),
                                    )
                                })?,
                                "GitLab Packages",
                                None,
                            )
                        }
                        PublishTarget::Custom(url) => (
                            url.clone(),
                            auth::get_custom_registry_token(url).ok_or_else(|| {
                                LpmError::Registry(format!(
                                    "no token found for {url}. Run `lpm login --login-registry {url} --token <token>`."
                                ))
                            })?,
                            "custom",
                            None,
                        ),
                        _ => unreachable!(),
                    };

                    if auth_source == Some("oidc") && !json_output {
                        install_ui::phase("Using npm Trusted Publishing (OIDC)");
                    }

                    // Per-target access
                    let npm_access = match target {
                        PublishTarget::GitHub => github_config
                            .and_then(|c| c.access.clone())
                            .unwrap_or_else(|| {
                                publish_npm::resolve_npm_access(npm_name_str, npm_config)
                            }),
                        PublishTarget::GitLab => gitlab_config
                            .and_then(|c| c.access.clone())
                            .unwrap_or_else(|| {
                                publish_npm::resolve_npm_access(npm_name_str, npm_config)
                            }),
                        _ => publish_npm::resolve_npm_access(npm_name_str, npm_config),
                    };
                    if provenance_context.is_some() && npm_access != "public" {
                        return Err(LpmError::Registry(format!(
                            "npm provenance requires public access for {npm_name_str}. \
                             Set publish.npm.access to \"public\" or omit restricted access."
                        )));
                    }
                    let npm_tag = publish_npm::resolve_npm_tag(npm_config);

                    // OTP preemption
                    let registry_key_for_otp = match target {
                        PublishTarget::Npm => "npmjs.org",
                        PublishTarget::GitHub => "github.com",
                        PublishTarget::GitLab => "gitlab.com",
                        _ => "",
                    };
                    let otp_preempt = npm_config
                        .and_then(|c| c.otp_required)
                        .unwrap_or(false)
                        || auth::is_otp_required(registry_key_for_otp);

                    let target_key = target.key();
                    let target_artifact =
                        if let Some(artifact) = precomputed_npm_artifacts.remove(&target_key) {
                            artifact
                        } else {
                            let final_tarball = target_tarball_data(
                                npm_name_str,
                                &name,
                                &tarball_data,
                                &rewritten_tarballs,
                            )?;
                            prepare_npm_target_artifact(NpmTargetArtifactInput {
                                npm_name: npm_name_str,
                                version: &version,
                                base_version_data: &version_data,
                                final_tarball_data: std::sync::Arc::clone(final_tarball),
                                provenance_context: provenance_context.as_ref(),
                                target_label: display,
                                json_output,
                            })
                            .await?
                        };

                    let upload_spinner = if json_output {
                        None
                    } else {
                        Some(install_ui::spin_line(format_upload_message(display)))
                    };
                    let npm_result = publish_npm::publish_to_npm(
                        &token,
                        npm_name_str,
                        &version,
                        &target_artifact.version_data,
                        &target_artifact.tarball_data,
                        target_artifact.provenance_attachment.as_ref(),
                        &npm_access,
                        &npm_tag,
                        &registry_url,
                        otp_preempt,
                        json_output,
                        yes,
                    )
                    .await?;
                    drop(upload_spinner);
                    if !json_output {
                        print_upload_details(
                            npm_name_str,
                            &version,
                            visibility_from_access(&npm_access),
                            &npm_tag,
                        );
                    }

                    if npm_result.success {
                        if !json_output {
                            let package_url = match target {
                                PublishTarget::Npm => {
                                    Some(format!(
                                        "https://www.npmjs.com/package/{}",
                                        npm_name_str
                                    ))
                                }
                                PublishTarget::GitHub => npm_name_str
                                    .strip_prefix('@')
                                    .and_then(|s| s.split_once('/'))
                                    .map(|(scope, pkg)| {
                                        format!("https://github.com/users/{scope}/packages/npm/package/{pkg}")
                                    }),
                                PublishTarget::GitLab => {
                                    let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
                                    let host = gl_cfg
                                        .and_then(|c| c.registry.as_deref())
                                        .unwrap_or("https://gitlab.com");
                                    gl_cfg
                                        .and_then(|c| c.project_id.as_deref())
                                        .map(|pid| format!("{host}/projects/{pid}/packages"))
                                }
                                _ => None,
                            };
                            if let Some(url) = package_url {
                                publish_detail("url", install_ui::url(&url));
                            }
                        }
                    } else if !json_output {
                        let err_msg = npm_result.error.as_deref().unwrap_or("unknown error");
                        install_ui::warn_untrusted(&format!(
                            "{} publish failed: {}",
                            lpm_common::sanitize_terminal_inline(display),
                            lpm_common::sanitize_terminal_inline(err_msg)
                        ));
                    }

                    Ok(PublishResult {
                        target: target.key(),
                        success: npm_result.success,
                        error: npm_result.error,
                        auth: auth_source,
                        publication_status: None,
                        current_latest_version: None,
                        publication_wait: None,
                        duration: npm_result.duration,
                    })
                }
                .await;

                // Catch any error from the npm-like target and convert to a failed PublishResult.
                // This ensures the loop always continues to the next target.
                match npm_target_result {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        let duration = start.elapsed();
                        if !json_output {
                            let error = e.to_string();
                            install_ui::warn_untrusted(&format!(
                                "{} publish failed: {}",
                                lpm_common::sanitize_terminal_inline(target.display_name()),
                                lpm_common::sanitize_terminal_inline(&error)
                            ));
                        }
                        results.push(PublishResult {
                            target: target.key(),
                            success: false,
                            error: Some(e.to_string()),
                            auth: None,
                            publication_status: None,
                            current_latest_version: None,
                            publication_wait: None,
                            duration,
                        });
                    }
                }
            }
        }
    }

    if wait_for_publication {
        let lpm_name = target_names
            .get("lpm")
            .map_or(name.as_str(), String::as_str);
        if let Some(result) = results
            .iter_mut()
            .find(|result| result.target == "lpm" && result.success)
        {
            if !json_output {
                install_ui::phase("Waiting for LPM.dev Registry publication");
            }
            let timeout = publication_wait_timeout.unwrap_or(DEFAULT_PUBLICATION_WAIT_TIMEOUT);
            let wait_result = if result.publication_status == Some(LpmPublicationStatus::Active) {
                PublicationWaitResult::active()
                    .with_current_latest_version(result.current_latest_version.clone())
            } else {
                wait_for_lpm_publication_with_oidc(
                    client,
                    lpm_name,
                    &version,
                    timeout,
                    oidc_token_for_wait.as_ref(),
                )
                .await
            };
            if let Some(status) = wait_result.status.clone() {
                result.publication_status = Some(status);
            }
            if let Some(current_latest_version) = wait_result.current_latest_version.clone() {
                result.current_latest_version = Some(current_latest_version);
            }
            if !json_output {
                if wait_result.success {
                    install_ui::done("LPM.dev Registry publication is active");
                } else if let Some(error) = wait_result.error.as_deref() {
                    install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(error));
                }
            }
            result.publication_wait = Some(wait_result);
        }
    }

    // Final summary after every target has had a chance to publish.
    let any_failed = results.iter().any(|r| !r.success);
    let any_wait_failed = results.iter().any(|result| {
        result
            .publication_wait
            .as_ref()
            .is_some_and(|wait| !wait.success)
    });
    let command_failed = any_failed || any_wait_failed;
    let succeeded = results.iter().filter(|r| r.success).count();
    let lpm_publication_status = results
        .iter()
        .find(|result| result.target == "lpm" && result.success)
        .and_then(|result| result.publication_status.as_ref());

    if json_output {
        let json = serde_json::json!({
            "success": !command_failed,
            "results": results.iter().map(publish_result_json).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if targets.len() > 1 && any_failed {
        install_ui::warn_line(format_multi_publish_partial_summary(
            succeeded,
            targets.len(),
            lpm_publication_status,
        ));
        for (target, result) in targets.iter().zip(results.iter()) {
            if !result.success {
                install_ui::detail_line(format_publish_retry_detail(target));
            }
        }
    } else if !any_wait_failed && targets.len() > 1 {
        let elapsed = install_ui::format_duration(publish_started.elapsed());
        install_ui::done_line(format_multi_publish_success_summary(
            targets.len(),
            &elapsed,
            lpm_publication_status,
        ));
    } else if !any_wait_failed && !any_failed {
        let target = &targets[0];
        let key = target.key();
        let published_name = target_names.get(&key).map_or(name.as_str(), |s| s.as_str());
        let elapsed = install_ui::format_duration(publish_started.elapsed());
        install_ui::done_line(format_single_publish_success_summary(
            published_name,
            &version,
            &elapsed,
            lpm_publication_status,
        ));
    }

    if command_failed {
        if json_output {
            Err(LpmError::ExitCode(1))
        } else if any_failed {
            Err(LpmError::Registry(
                "one or more publish targets failed".into(),
            ))
        } else {
            Err(LpmError::Registry(
                "the upload succeeded, but LPM.dev Registry publication was not confirmed; do not publish the same version again"
                    .into(),
            ))
        }
    } else {
        Ok(())
    }
}

fn prepare_rewritten_target_tarballs(
    targets: &[PublishTarget],
    target_names: &HashMap<String, String>,
    package_json_name: &str,
    base_tarball_data: &[u8],
    scan_secrets: bool,
) -> Result<HashMap<String, publish_common::RewrittenTarball>, LpmError> {
    let mut rewritten_tarballs = HashMap::with_capacity(targets.len());
    for target in targets {
        let target_name = target_names.get(&target.key()).ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        if target_name == package_json_name || rewritten_tarballs.contains_key(target_name) {
            continue;
        }

        let rewritten = publish_common::rewrite_tarball_name_for_publish(
            base_tarball_data,
            package_json_name,
            target_name,
            scan_secrets,
        )?
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "target tarball rewrite was skipped for renamed package {target_name}"
            ))
        })?;
        validate_publish_tarball_size(rewritten.data.len())?;
        rewritten_tarballs.insert(target_name.clone(), rewritten);
    }
    Ok(rewritten_tarballs)
}

fn target_tarball_data<'a>(
    target_name: &str,
    package_json_name: &str,
    base_tarball_data: &'a std::sync::Arc<Vec<u8>>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
) -> Result<&'a std::sync::Arc<Vec<u8>>, LpmError> {
    if target_name == package_json_name {
        return Ok(base_tarball_data);
    }
    rewritten_tarballs
        .get(target_name)
        .map(|tarball| &tarball.data)
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "missing prepared tarball for renamed package {target_name}"
            ))
        })
}

fn target_secret_scan<'a>(
    target_name: &str,
    package_json_name: &str,
    base_secret_scan: Option<&'a lpm_security::behavioral::secrets::SecretScanResult>,
    rewritten_tarballs: &'a HashMap<String, publish_common::RewrittenTarball>,
) -> Result<&'a lpm_security::behavioral::secrets::SecretScanResult, LpmError> {
    let scan = if target_name == package_json_name {
        base_secret_scan
    } else {
        rewritten_tarballs
            .get(target_name)
            .and_then(|tarball| tarball.secret_scan.as_ref())
    };
    scan.ok_or_else(|| {
        LpmError::Registry(format!(
            "publish artifact for {target_name} was prepared without a secret scan"
        ))
    })
}

async fn precompute_file_provenance_artifacts(
    input: NpmFilePreflightInput<'_>,
) -> Result<HashMap<String, NpmTargetArtifact>, LpmError> {
    let ProvenanceRequest::File(path) = input.provenance_request else {
        return Ok(HashMap::new());
    };
    let file = load_provenance_file(path)?;
    let provenance = ResolvedProvenance::File(file);
    let npm_target_count = input
        .targets
        .iter()
        .filter(|target| is_npm_compatible_target(target))
        .count();
    let mut artifacts = HashMap::with_capacity(npm_target_count);

    for target in input.targets {
        if !is_npm_compatible_target(target) {
            continue;
        }
        let key = target.key();
        let npm_name = input.target_names.get(&key).ok_or_else(|| {
            LpmError::Registry(format!("no name resolved for {}", target.display_name()))
        })?;
        let tarball_data = target_tarball_data(
            npm_name,
            input.package_json_name,
            input.tarball_data,
            input.rewritten_tarballs,
        )?;
        let artifact = prepare_npm_target_artifact(NpmTargetArtifactInput {
            npm_name,
            version: input.version,
            base_version_data: input.version_data,
            final_tarball_data: std::sync::Arc::clone(tarball_data),
            provenance_context: Some(&provenance),
            target_label: target.display_name(),
            json_output: input.json_output,
        })
        .await?;
        artifacts.insert(key, artifact);
    }

    Ok(artifacts)
}

fn is_npm_compatible_target(target: &PublishTarget) -> bool {
    matches!(
        target,
        PublishTarget::Npm
            | PublishTarget::GitHub
            | PublishTarget::GitLab
            | PublishTarget::Custom(_)
    )
}

pub(super) fn lpm_package_url(name: &str) -> Option<String> {
    let package = name.strip_prefix("@lpm.dev/")?;
    let (owner, package_name) = package.split_once('.')?;
    if owner.is_empty()
        || package_name.is_empty()
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(format!("https://lpm.dev/{package}"))
}
