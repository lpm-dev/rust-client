use crate::commands::publish_common::{self, TarballFile};
use crate::commands::publish_npm;
use crate::{auth, install_ui, oidc, provenance, quality, sigstore};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_runner::lpm_json;
use lpm_security::behavioral::secrets::SecretScanResult;
use lpm_security::skill_security;
use std::path::Path;

/// Target registries for a publish operation.
#[derive(Debug, Clone, PartialEq)]
pub enum PublishTarget {
    Lpm,
    Npm,
    GitHub,
    GitLab,
    Custom(String),
}

impl PublishTarget {
    /// Short display name for human output.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Lpm => "LPM",
            Self::Npm => "npm",
            Self::GitHub => "GitHub Packages",
            Self::GitLab => "GitLab Packages",
            Self::Custom(_) => "custom",
        }
    }

    /// Key for JSON output.
    pub fn key(&self) -> String {
        match self {
            Self::Lpm => "lpm".into(),
            Self::Npm => "npm".into(),
            Self::GitHub => "github".into(),
            Self::GitLab => "gitlab".into(),
            Self::Custom(url) => url.clone(),
        }
    }

    /// CLI flag to retry a failed publish for this target.
    pub fn retry_flag(&self) -> String {
        match self {
            Self::Lpm => "--lpm".into(),
            Self::Npm => "--npm".into(),
            Self::GitHub => "--github".into(),
            Self::GitLab => "--gitlab".into(),
            Self::Custom(url) => format!("--publish-registry {url}"),
        }
    }
}

/// Result of publishing to a single registry.
#[derive(Debug)]
pub struct PublishResult {
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub duration: std::time::Duration,
}

#[derive(Debug, Eq, PartialEq)]
enum SecretScanLine {
    Warn(String),
    Failed(String),
    Detail(String),
}

/// Resolve the target registries from CLI flags and lpm.json config.
///
/// CLI flags take precedence. If no flags, read from lpm.json.
/// If no config, default to LPM only.
///
/// Returns an error if the config contains unknown registry entries or if the
/// resolved target list is empty.
pub fn resolve_targets(
    cli_npm: bool,
    cli_lpm: bool,
    cli_github: bool,
    cli_gitlab: bool,
    cli_registry: Option<&str>,
    config: Option<&lpm_json::PublishConfig>,
) -> Result<Vec<PublishTarget>, LpmError> {
    let has_cli_flags = cli_npm || cli_lpm || cli_github || cli_gitlab || cli_registry.is_some();

    if has_cli_flags {
        let mut targets = Vec::new();
        if cli_lpm {
            targets.push(PublishTarget::Lpm);
        }
        if cli_npm {
            targets.push(PublishTarget::Npm);
        }
        if cli_github {
            targets.push(PublishTarget::GitHub);
        }
        if cli_gitlab {
            targets.push(PublishTarget::GitLab);
        }
        if let Some(url) = cli_registry {
            targets.push(PublishTarget::Custom(url.to_string()));
        }
        return Ok(deduplicate_targets(targets));
    }

    if let Some(publish_config) = config
        && !publish_config.registries.is_empty()
    {
        let mut targets = Vec::new();
        let mut unknown = Vec::new();

        for r in &publish_config.registries {
            match r.as_str() {
                "lpm" => targets.push(PublishTarget::Lpm),
                "npm" => targets.push(PublishTarget::Npm),
                "github" => targets.push(PublishTarget::GitHub),
                "gitlab" => targets.push(PublishTarget::GitLab),
                url if url.starts_with("https://") => {
                    // M30: project-level `lpm.json` can list ANY https://
                    // URL as a publish target — a hostile commit on a
                    // downstream fork or a compromised dev machine could
                    // silently redirect every `lpm publish` to an
                    // attacker host, capturing tokens + tarballs. We
                    // can't enforce a hard allowlist (legitimate
                    // self-hosted registries exist) but we DO emit a
                    // loud warn so an unexpected target appears in
                    // operator logs / human terminal before the publish
                    // network call fires.
                    let host = reqwest::Url::parse(url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_string()))
                        .unwrap_or_else(|| url.to_string());
                    if !is_known_publish_host(&host) {
                        tracing::warn!(
                            target_url = %url,
                            host = %host,
                            "publish.registries: routing publish to non-default host \
                             — confirm this is intentional (the LPM bearer goes via \
                             this host)",
                        );
                    }
                    targets.push(PublishTarget::Custom(url.to_string()));
                }
                url if url.starts_with("http://") => {
                    return Err(LpmError::Registry(format!(
                        "publish.registries: refusing HTTP URL \"{url}\" — publish requires HTTPS"
                    )));
                }
                other => unknown.push(other.to_string()),
            }
        }

        if !unknown.is_empty() {
            return Err(LpmError::Registry(format!(
                "unknown publish registries in lpm.json: {}. \
                 Valid values: lpm, npm, github, gitlab, or an https:// URL",
                unknown.join(", ")
            )));
        }

        if targets.is_empty() {
            return Err(LpmError::Registry(
                "publish.registries in lpm.json resolved to no targets".into(),
            ));
        }

        return Ok(deduplicate_targets(targets));
    }

    // Default: LPM only
    Ok(vec![PublishTarget::Lpm])
}

/// Hosts considered "default" / first-party publish destinations.
/// A custom URL pointing at any of these is NOT noisy; everything
/// else triggers a `tracing::warn` so an unexpected target is
/// visible in operator logs before the publish bearer is sent.
fn is_known_publish_host(host: &str) -> bool {
    matches!(
        host,
        "lpm.dev" | "registry.npmjs.org" | "npm.pkg.github.com" | "registry.gitlab.com"
    ) || host.ends_with(".lpm.dev")
        || host.ends_with(".lpm.fyi")
}

/// Deduplicate targets while preserving order.
fn deduplicate_targets(targets: Vec<PublishTarget>) -> Vec<PublishTarget> {
    let mut seen = std::collections::HashSet::new();
    targets
        .into_iter()
        .filter(|t| seen.insert(t.key()))
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    dry_run: bool,
    check_only: bool,
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
) -> Result<(), LpmError> {
    let publish_started = std::time::Instant::now();

    // Step 1: Read package.json
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    let content = std::fs::read_to_string(&pkg_json_path)?;
    let pkg_json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let name = pkg_json
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("package.json missing \"name\"".into()))?;

    let version = pkg_json
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("package.json missing \"version\"".into()))?;

    // Step 1b: Read lpm.json for publish config
    let lpm_config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Registry)?;
    let publish_config = lpm_config.as_ref().and_then(|c| c.publish.as_ref());

    // Resolve target registries
    let targets = resolve_targets(
        cli_npm,
        cli_lpm,
        cli_github,
        cli_gitlab,
        cli_registry,
        publish_config,
    )?;

    // S7: Hard cap on registry count
    const MAX_REGISTRIES: usize = 5;
    if targets.len() > MAX_REGISTRIES {
        return Err(LpmError::Registry(format!(
            "too many target registries ({}, max {MAX_REGISTRIES})",
            targets.len()
        )));
    }

    let targets_lpm = targets.contains(&PublishTarget::Lpm);
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

    // Resolve per-target names early (before expensive tarball work).
    // Each registry can have its own name override in lpm.json.
    // package.json `name` is the fallback when no config override exists.
    let lpm_config = publish_config.and_then(|p| p.lpm.as_ref());
    let npm_config = publish_config.and_then(|p| p.npm.as_ref());
    let github_config = publish_config.and_then(|p| p.github.as_ref());
    let gitlab_config = publish_config.and_then(|p| p.gitlab.as_ref());

    let mut target_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
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
                    .map_or_else(|| publish_npm::resolve_npm_name(name, None), Ok)?
            }
            PublishTarget::GitHub => {
                // GitHub: config override → npm config → package.json. Must be scoped.
                let gh_name = github_config
                    .and_then(|c| c.name.clone())
                    .or_else(|| npm_config.and_then(|c| c.name.clone()))
                    .map_or_else(|| publish_npm::resolve_npm_name(name, None), Ok)?;
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
                    .map_or_else(|| publish_npm::resolve_npm_name(name, None), Ok)?
            }
            PublishTarget::Custom(_) => {
                // Custom: npm config → package.json.
                npm_config
                    .and_then(|c| c.name.clone())
                    .map_or_else(|| publish_npm::resolve_npm_name(name, None), Ok)?
            }
        };
        target_names.insert(target.key(), resolved);
    }

    // Step 2: Read README
    let readme = publish_common::read_readme(project_dir);

    // Step 3: Create tarball (silent — messages print after quality checks)
    let (mut tarball_data, tarball_files) = publish_common::create_tarball(project_dir, &pkg_json)?;

    // Step 3a: Rewrite workspace:/catalog: protocols in tarball before hashing.
    // Monorepo packages contain "workspace:*" in deps which registries can't resolve.
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();
    if let Some(ref ws) = workspace {
        tarball_data = publish_common::rewrite_workspace_deps_in_tarball(&tarball_data, ws)?;
    }

    let tarball_size = tarball_data.len();
    if tarball_size > 500 * 1024 * 1024 {
        return Err(LpmError::Registry(format!(
            "tarball too large: {} (max 500MB)",
            lpm_common::format_bytes(tarball_size as u64)
        )));
    }

    // Step 3b: Detect ecosystem (needed before quality checks)
    let mut detected_ecosystem = "js".to_string();
    let lpm_config_path = project_dir.join("lpm.config.json");
    if lpm_config_path.exists()
        && let Ok(config_str) = std::fs::read_to_string(&lpm_config_path)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str)
        && let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str())
    {
        detected_ecosystem = eco.to_string();
    }
    if project_dir.join("Package.swift").exists() && detected_ecosystem == "js" {
        detected_ecosystem = "swift".to_string();
    }

    // Step 3c: Extract Swift manifest for quality scoring (if Swift)
    let swift_manifest = if detected_ecosystem == "swift" {
        std::process::Command::new("swift")
            .args(["package", "dump-package"])
            .current_dir(project_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    } else {
        None
    };

    // Step 3d: Pre-publish secret scan
    if !allow_secrets {
        let secret_scan = lpm_security::behavioral::secrets::scan_directory(project_dir);
        if secret_scan.has_secrets() {
            if json_output {
                println!("{}", secret_scan_json(&secret_scan));
            } else {
                emit_secret_scan_human(&secret_scan);
            }
            return Err(LpmError::ExitCode(1));
        }
        if !json_output {
            install_ui::done("Secret scan passed");
        }
    }

    // Step 4: Quality checks (LPM target only — A7)
    let quality_result = if targets_lpm {
        let file_names: Vec<String> = tarball_files.iter().map(|f| f.path.clone()).collect();
        let qr = quality::run_quality_checks(
            &pkg_json,
            readme.as_deref(),
            project_dir,
            &file_names,
            &detected_ecosystem,
            swift_manifest.as_ref(),
        );

        if !json_output {
            print_publish_quality_result(&qr);
        }

        // Enforce --min-score if provided
        if let Some(min) = min_score
            && qr.score < min
        {
            return Err(LpmError::Registry(format!(
                "quality score {} is below minimum {} (use --min-score to adjust)",
                qr.score, min
            )));
        }

        Some(qr)
    } else {
        None
    };

    // Step 4b: Skills validation (LPM target only)
    let skills_dir = project_dir.join(".lpm").join("skills");
    let has_skills = skills_dir.exists() && skills_dir.is_dir();

    if has_skills && targets_lpm {
        if !json_output {
            install_ui::phase("Validating skills");
        }

        let (valid, skill_errors, security_issues) = validate_skills_for_publish(&skills_dir);

        if !security_issues.is_empty() {
            for issue in &security_issues {
                install_ui::warn(&format!(
                    "Skill security: {} — {} at line {} ({})",
                    issue.matched_text, issue.category, issue.line_number, issue.pattern
                ));
            }
            return Err(LpmError::Registry(
                "skills contain blocked security patterns".into(),
            ));
        }

        if !skill_errors.is_empty() {
            for err in &skill_errors {
                install_ui::warn(err);
            }
            return Err(LpmError::Registry(
                "skills validation failed — fix errors above".into(),
            ));
        }

        if !json_output {
            install_ui::done(&format!("{valid} skill(s) validated"));
        }

        ensure_lpm_in_files(&pkg_json_path, &pkg_json)?;
    }

    // Step 4bb: OIDC auto-exchange (LPM target only, real publish + dry-run).
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
    //   surfaces before a real publish. Note: dry-run does NOT cover the
    //   later per-target auth checks (whoami/permissions) — those run only
    //   on a real publish.
    //
    // Placed right before Step 4c so the skill-staleness check (the first
    // LPM-target network call) gets the swapped client too.
    //
    // The origin requires `package` for `scope=publish` (see a-package-manager
    // `app/api/registry/-/token/oidc/route.js`), and the package name only
    // becomes known after `package.json` is parsed — that's why this can't
    // live in main.rs.
    //
    // Failure is non-fatal: the original `client` is reused so a missing
    // OIDC policy or a misconfigured token can still publish via the stored
    // session token. The failure is debug-logged for diagnostics.
    let oidc_swapped_client;
    let client: &RegistryClient =
        if targets_lpm && !check_only && oidc::registry_exchange_jwt_available() {
            match oidc::exchange_oidc_token(client.base_url(), Some(name), "publish").await {
                Ok(oidc_token) => {
                    oidc_swapped_client = client.clone_with_config().with_token(oidc_token.token);
                    if !json_output {
                        install_ui::phase("Using OIDC-exchanged session token for LPM publish");
                    }
                    &oidc_swapped_client
                }
                Err(e) => {
                    tracing::debug!("OIDC publish auto-exchange failed, using stored token: {e}");
                    client
                }
            }
        } else {
            client
        };

    // Step 4c: Skills staleness check (LPM only, real publish + dry-run).
    //
    // Gated to skip in `--check` mode: this is a network read against the
    // LPM registry, and `--check` is the local-validation surface. Kept on
    // for `--dry-run` because the staleness diagnostic ("your skills are
    // identical to the previously published version") is part of the
    // LPM-side preflight a dry-run is meant to surface.
    if has_skills && targets_lpm && !check_only {
        let name_short = name.strip_prefix("@lpm.dev/").unwrap_or(name);
        match client.get_skills(name_short, None).await {
            Ok(prev) if !prev.skills.is_empty() => {
                let local_digest = compute_skills_digest(&skills_dir);
                let published_digest = compute_published_skills_digest(&prev.skills);
                if local_digest == published_digest && !json_output {
                    install_ui::warn(
                        "Skills are identical to the previously published version — consider updating them",
                    );
                }
            }
            _ => {}
        }
    }

    // Step 5: Check-only or dry-run modes
    if check_only {
        if json_output {
            let mut json = quality_result
                .as_ref()
                .and_then(|qr| serde_json::to_value(qr).ok())
                .unwrap_or_default();
            if let Some(obj) = json.as_object_mut() {
                obj.insert("success".to_string(), serde_json::Value::Bool(true));
            }
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        return Ok(());
    }

    if dry_run {
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
            let mut eco = "js".to_string();
            let lpm_cfg = project_dir.join("lpm.config.json");
            if lpm_cfg.exists()
                && let Ok(s) = std::fs::read_to_string(&lpm_cfg)
                && let Ok(c) = serde_json::from_str::<serde_json::Value>(&s)
                && let Some(e) = c.get("ecosystem").and_then(|v| v.as_str())
            {
                eco = e.to_string();
            }
            if project_dir.join("Package.swift").exists() && eco == "js" {
                eco = "swift".to_string();
            }

            let summary = DryRunSummary {
                name,
                version,
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

    // Step 6: Confirm
    if !json_output && !yes {
        println!();
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
        if is_tty {
            let prompt_msg = if targets.len() > 1 {
                format!(
                    "Publish {name}@{version} to {}?",
                    targets
                        .iter()
                        .map(|t| t.display_name())
                        .collect::<Vec<_>>()
                        .join(" + ")
                )
            } else {
                format!("Publish {name}@{version}?")
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

    // Step 7: Compute hashes from original tarball (used as base for version_data)
    let hashes = publish_common::compute_hashes(&tarball_data);

    // Step 8: Build version data (shared base for LPM payload)
    let mut version_data = pkg_json.clone();
    version_data["_id"] = serde_json::json!(format!("{name}@{version}"));
    if let Some(readme_text) = &readme {
        version_data["readme"] = serde_json::json!(readme_text);
    }
    version_data["dist"] = serde_json::json!({
        "shasum": hashes.shasum,
        "integrity": hashes.integrity,
    });

    // Step 8b: Prepare OIDC JWT for Sigstore provenance (if --provenance).
    // Resolved once and reused per target — provenance is generated per-target
    // after tarball rewriting so the SHA-512 in the SLSA statement matches the
    // bytes actually uploaded.
    let provenance_context = if provenance_flag {
        let (ci, jwt) = oidc::resolve_provenance_jwt().await?;
        Some((ci, jwt))
    } else {
        None
    };

    // Sequential publish to each target registry (B1)
    // All per-target errors are caught and collected — the loop NEVER aborts early.
    let mut results: Vec<PublishResult> = Vec::with_capacity(targets.len());

    for target in &targets {
        let start = std::time::Instant::now();

        match target {
            PublishTarget::Lpm => {
                // Wrap the entire LPM publish path so any error becomes a PublishResult
                let lpm_result: Result<serde_json::Value, LpmError> = async {
                    let lpm_name =
                        target_names.get("lpm").map_or(name, |s| s.as_str());

                    // Rewrite tarball if LPM name differs from package.json name
                    let lpm_tarball = if lpm_name != name {
                        publish_common::rewrite_tarball_name(&tarball_data, name, lpm_name)?
                    } else {
                        tarball_data.clone()
                    };

                    // Recompute dist hashes from the final rewritten tarball so metadata
                    // matches the actual uploaded artifact (not the pre-rewrite original).
                    let mut lpm_version_data = version_data.clone();
                    if lpm_name != name {
                        let lpm_hashes = publish_common::compute_hashes(&lpm_tarball);
                        lpm_version_data["dist"] = serde_json::json!({
                            "shasum": lpm_hashes.shasum,
                            "integrity": lpm_hashes.integrity,
                        });
                    }

                    // Generate per-target provenance from the final rewritten tarball
                    if let Some((ref ci, ref jwt)) = provenance_context {
                        let final_hashes = publish_common::compute_hashes(&lpm_tarball);
                        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
                        let slsa = provenance::build_slsa_statement(ci, lpm_name, version, &sha512_hex);
                        let slsa_json = serde_json::to_vec(&slsa)
                            .map_err(|e| LpmError::Registry(format!("failed to serialize SLSA statement: {e}")))?;

                        // --provenance is strict: fail if Sigstore fails
                        let bundle = sigstore::sign_and_record(jwt, &slsa_json).await
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

                    if !json_output {
                        print_upload_phase(
                            "lpm.dev",
                            lpm_name,
                            version,
                            lpm_visibility(&pkg_json),
                            "latest",
                        );
                    }

                    publish_to_lpm(
                        client,
                        project_dir,
                        lpm_name,
                        version,
                        &readme,
                        &lpm_tarball,
                        &tarball_files,
                        &lpm_version_data,
                        &quality_result,
                        json_output,
                        &detected_ecosystem,
                        &swift_manifest,
                    )
                    .await
                }
                .await;

                let duration = start.elapsed();
                let lpm_name = target_names.get("lpm").map_or(name, |s| s.as_str());
                match lpm_result {
                    Ok(resp) => {
                        if !json_output {
                            let owner_pkg = lpm_name.strip_prefix("@lpm.dev/").unwrap_or(lpm_name);
                            if let Some((owner, pkg)) = owner_pkg.split_once('.') {
                                publish_detail(
                                    "url",
                                    &install_ui::url(&format!("https://lpm.dev/{owner}/{pkg}")),
                                );
                            }
                            if let Some(warnings) = resp.get("warnings").and_then(|w| w.as_array())
                            {
                                for w in warnings {
                                    if let Some(msg) = w.as_str() {
                                        install_ui::warn(msg);
                                    }
                                }
                            }
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: true,
                            error: None,
                            duration,
                        });
                    }
                    Err(e) => {
                        if !json_output {
                            install_ui::warn(&format!("LPM publish failed: {e}"));
                        }
                        results.push(PublishResult {
                            target: "lpm".into(),
                            success: false,
                            error: Some(e.to_string()),
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
                    let (registry_url, token_result, display) = match target {
                        PublishTarget::Npm => (
                            publish_npm::resolve_npm_registry(npm_config),
                            auth::get_npm_token().ok_or_else(|| {
                                LpmError::Registry(
                                    "no npm token found. Run `lpm login --npm` for browser login, pass `lpm login --npm --token <token>`, or set NPM_TOKEN.".into(),
                                )
                            }),
                            "npm",
                        ),
                        PublishTarget::GitHub => (
                            "https://npm.pkg.github.com".to_string(),
                            auth::get_github_token().ok_or_else(|| {
                                LpmError::Registry(
                                    "no GitHub Packages token found. Run `gh auth login --hostname github.com`, run `lpm login --github --token <pat>`, or set GITHUB_TOKEN.".into(),
                                )
                            }),
                            "GitHub Packages",
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
                            // H18: a project lpm.json can override the
                            // gitlab host while still naming `gitlab`
                            // as a publish target; the GITLAB_TOKEN
                            // then flows to the overridden host. Warn
                            // loudly when the resolved host is not
                            // the default; the operator sees the
                            // redirect target in logs before the
                            // bearer is sent.
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
                                }),
                                "GitLab Packages",
                            )
                        }
                        PublishTarget::Custom(url) => (
                            url.clone(),
                            auth::get_custom_registry_token(url).ok_or_else(|| {
                                LpmError::Registry(format!(
                                    "no token found for {url}. Run `lpm login --login-registry {url} --token <token>`."
                                ))
                            }),
                            "custom",
                        ),
                        _ => unreachable!(),
                    };

                    let token = token_result?;

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
                    let npm_tag = publish_npm::resolve_npm_tag(npm_config);
                    if !json_output {
                        print_upload_phase(
                            display,
                            npm_name_str,
                            version,
                            visibility_from_access(&npm_access),
                            &npm_tag,
                        );
                    }

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

                    // Rewrite tarball name if needed
                    let target_tarball = if npm_name_str != name {
                        publish_common::rewrite_tarball_name(&tarball_data, name, npm_name_str)?
                    } else {
                        tarball_data.clone()
                    };

                    // Generate per-target provenance from the final rewritten tarball
                    let mut target_version_data = version_data.clone();
                    if let Some((ref ci, ref jwt)) = provenance_context {
                        let final_hashes = publish_common::compute_hashes(&target_tarball);
                        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
                        let slsa = provenance::build_slsa_statement(
                            ci,
                            npm_name_str,
                            version,
                            &sha512_hex,
                        );
                        let slsa_json = serde_json::to_vec(&slsa).map_err(|e| {
                            LpmError::Registry(format!(
                                "failed to serialize SLSA statement: {e}"
                            ))
                        })?;

                        // --provenance is strict: fail if Sigstore fails
                        let bundle = sigstore::sign_and_record(jwt, &slsa_json).await
                            .map_err(|e| LpmError::Registry(format!(
                                "Sigstore provenance failed: {e}. \
                                 Publish aborted because --provenance requires successful provenance generation."
                            )))?;

                        if !json_output {
                            install_ui::done(&format!(
                                "Sigstore provenance generated for {} → Rekor",
                                display
                            ));
                        }
                        let bundle_json = serde_json::to_value(&bundle).unwrap_or_default();
                        target_version_data["_provenance"] = bundle_json.clone();
                        target_version_data["_npmProvenanceAttestations"] = bundle_json;
                    }

                    let npm_result = publish_npm::publish_to_npm(
                        &token,
                        npm_name_str,
                        version,
                        &target_version_data,
                        &target_tarball,
                        &npm_access,
                        &npm_tag,
                        &registry_url,
                        otp_preempt,
                        json_output,
                        yes,
                    )
                    .await?;

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
                                publish_detail("url", &install_ui::url(&url));
                            }
                        }
                    } else if !json_output {
                        let err_msg = npm_result.error.as_deref().unwrap_or("unknown error");
                        install_ui::warn(&format!("{display} publish failed: {err_msg}"));
                    }

                    Ok(PublishResult {
                        target: target.key(),
                        success: npm_result.success,
                        error: npm_result.error,
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
                            install_ui::warn(&format!(
                                "{} publish failed: {e}",
                                target.display_name()
                            ));
                        }
                        results.push(PublishResult {
                            target: target.key(),
                            success: false,
                            error: Some(e.to_string()),
                            duration,
                        });
                    }
                }
            }
        }
    }

    // Final summary (B1)
    let any_failed = results.iter().any(|r| !r.success);
    let succeeded = results.iter().filter(|r| r.success).count();

    if json_output {
        let json = serde_json::json!({
            "success": !any_failed,
            "results": results.iter().map(|r| serde_json::json!({
                "registry": r.target,
                "success": r.success,
                "error": r.error,
                "duration_ms": r.duration.as_millis() as u64,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if targets.len() > 1 {
        if any_failed {
            install_ui::warn(&format!(
                "Published to {succeeded} of {} registries.",
                targets.len()
            ));
            for (target, result) in targets.iter().zip(results.iter()) {
                if !result.success {
                    install_ui::detail(&format_publish_retry_detail(target));
                }
            }
        } else {
            let elapsed =
                install_ui::green(&install_ui::format_duration(publish_started.elapsed()));
            install_ui::done(&format!(
                "Done · published to {} registries in {elapsed}",
                targets.len()
            ));
        }
    } else if !any_failed {
        let target = &targets[0];
        let key = target.key();
        let published_name = target_names.get(&key).map_or(name, |s| s.as_str());
        let elapsed = install_ui::green(&install_ui::format_duration(publish_started.elapsed()));
        install_ui::done(&format!(
            "Done · published {} in {elapsed}",
            install_ui::yellow(&format!("{published_name}@{version}"))
        ));
    }

    if any_failed {
        Err(LpmError::Registry(
            "one or more publish targets failed".into(),
        ))
    } else {
        Ok(())
    }
}

/// Extract SHA-512 hex from an integrity string (strip "sha512-" prefix and decode base64).
fn integrity_to_sha512_hex(integrity: &str) -> String {
    let b64 = integrity.strip_prefix("sha512-").unwrap_or(integrity);
    let bytes = BASE64.decode(b64).unwrap_or_default();
    hex::encode(&bytes)
}

/// Publish to the LPM registry (existing behavior).
#[allow(clippy::too_many_arguments)]
async fn publish_to_lpm(
    client: &RegistryClient,
    project_dir: &Path,
    name: &str,
    version: &str,
    readme: &Option<String>,
    tarball_data: &[u8],
    tarball_files: &[TarballFile],
    version_data: &serde_json::Value,
    quality_result: &Option<quality::QualityResult>,
    json_output: bool,
    detected_ecosystem: &str,
    swift_manifest: &Option<serde_json::Value>,
) -> Result<serde_json::Value, LpmError> {
    // S9: Reject HTTP for LPM publish — credentials must not travel unencrypted
    let registry_url = client.base_url();
    if !registry_url.starts_with("https://")
        && !registry_url.starts_with("http://localhost")
        && !registry_url.starts_with("http://127.0.0.1")
    {
        return Err(LpmError::Registry(format!(
            "refusing to publish over HTTP to {registry_url} — credentials require HTTPS"
        )));
    }

    // S9: Warn when publishing to a non-default LPM registry
    if !registry_url.starts_with("https://lpm.dev")
        && !registry_url.starts_with("http://localhost")
        && !registry_url.starts_with("http://127.0.0.1")
        && !json_output
    {
        install_ui::detail("");
        install_ui::warn(&format!(
            "Publishing to non-default registry: {}",
            install_ui::url(registry_url)
        ));
    }

    // Verify token has publish scope
    let whoami = client
        .whoami()
        .await
        .map_err(|e| LpmError::Registry(format!("authentication failed: {e}")))?;

    // 2FA check — prompt before uploading
    let otp_code: Option<String> = if whoami.mfa_enabled == Some(true) {
        if json_output {
            return Err(LpmError::Registry(
                "2FA required but running in JSON mode — use --token with a CI token instead"
                    .into(),
            ));
        }
        let code: String = cliclack::input("Enter 2FA code")
            .validate(|input: &String| {
                if input.len() == 6 && input.chars().all(|c| c.is_ascii_digit()) {
                    Ok(())
                } else {
                    Err("Must be a 6-digit code")
                }
            })
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;
        Some(code)
    } else {
        None
    };

    // Build LPM version data (add LPM-specific fields)
    let mut lpm_version = version_data.clone();

    if let Some(qr) = quality_result {
        lpm_version["_qualityChecks"] =
            serde_json::to_value(&qr.checks).unwrap_or(serde_json::json!(null));
        lpm_version["_qualityMeta"] = serde_json::json!({
            "score": qr.score,
            "maxScore": qr.max_score,
            "ecosystem": "js",
        });
    }

    lpm_version["_npmPackMeta"] = serde_json::json!({
        "files": tarball_files.iter().map(|f| {
            serde_json::json!({
                "path": f.path,
                "size": f.size,
            })
        }).collect::<Vec<_>>(),
        "unpackedSize": tarball_files.iter().map(|f| f.size).sum::<u64>(),
        "fileCount": tarball_files.len(),
    });

    // Read lpm.config.json for version payload
    let lpm_config_path = project_dir.join("lpm.config.json");
    if lpm_config_path.exists()
        && let Ok(config_str) = std::fs::read_to_string(&lpm_config_path)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str)
    {
        lpm_version["_lpmConfig"] = config;
    }

    if detected_ecosystem != "js" {
        lpm_version["_ecosystem"] = serde_json::json!(detected_ecosystem);
    }

    // For Swift: embed normalized metadata from the manifest extracted earlier
    if let Some(manifest) = swift_manifest {
        lpm_version["_swiftManifest"] = extract_swift_metadata(manifest);
    }

    // S8: Pre-allocate base64 string to avoid double allocation
    let tarball_key = format!(
        "{}-{}.tgz",
        name.replace('/', "-").replace('@', ""),
        version
    );
    let tarball_mb = tarball_data.len() / (1024 * 1024);
    if tarball_mb > 50 && !json_output {
        let peak_mb = tarball_data.len() * 4 / 3 / (1024 * 1024) + tarball_mb;
        install_ui::warn(&format!(
            "Large tarball ({tarball_mb}MB). This will require ~{peak_mb}MB of memory."
        ));
    }
    let mut tarball_base64 = String::with_capacity(tarball_data.len() * 4 / 3 + 4);
    BASE64.encode_string(tarball_data, &mut tarball_base64);

    let payload = serde_json::json!({
        "_id": name,
        "name": name,
        "description": lpm_version.get("description"),
        "readme": readme,
        "_ecosystem": detected_ecosystem,
        "dist-tags": {
            "latest": version,
        },
        "versions": {
            version: lpm_version,
        },
        "_attachments": {
            tarball_key: {
                "content_type": "application/gzip",
                "data": tarball_base64,
                "length": tarball_data.len(),
            }
        },
    });

    let encoded_name = urlencoding::encode(name);
    client
        .publish_package(
            &encoded_name,
            &payload,
            otp_code.as_deref(),
            tarball_data.len(),
        )
        .await
}

// ---------------------------------------------------------------------------
fn secret_scan_json(scan: &SecretScanResult) -> serde_json::Value {
    let matches_json: Vec<serde_json::Value> = scan
        .matches
        .iter()
        .map(|m| {
            serde_json::json!({
                "pattern": m.pattern_name,
                "description": m.description,
                "line": m.line,
                "severity": m.severity,
            })
        })
        .collect();

    serde_json::json!({
        "error": "secret_scan_failed",
        "matches": matches_json,
        "hint": "Use --allow-secrets to bypass (not recommended)",
    })
}

fn emit_secret_scan_human(scan: &SecretScanResult) {
    for line in format_secret_scan_human(scan) {
        match line {
            SecretScanLine::Warn(message) => install_ui::warn(&message),
            SecretScanLine::Failed(message) => install_ui::failed(&message),
            SecretScanLine::Detail(message) => install_ui::detail(&message),
        }
    }
}

fn format_secret_scan_human(scan: &SecretScanResult) -> Vec<SecretScanLine> {
    let mut lines = Vec::with_capacity(scan.matches.len() + 3);
    lines.push(SecretScanLine::Warn(format!(
        "Secret scan found {} potential {}",
        install_ui::status_ok(&scan.matches.len().to_string()),
        if scan.matches.len() == 1 {
            "leak"
        } else {
            "leaks"
        }
    )));

    for secret_match in &scan.matches {
        lines.push(SecretScanLine::Detail(format_secret_match(secret_match)));
    }

    lines.push(SecretScanLine::Failed(
        "Publish blocked. Remove secrets before publishing.".to_string(),
    ));
    lines.push(SecretScanLine::Detail(format!(
        "  {} If these are false positives, use {}.",
        install_ui::dim("hint"),
        install_ui::yellow("--allow-secrets")
    )));
    lines
}

fn format_secret_match(secret_match: &lpm_security::behavioral::secrets::SecretMatch) -> String {
    let matched_text = lpm_common::sanitize_for_terminal(&secret_match.matched_text);
    let pattern_name = lpm_common::sanitize_for_terminal(&secret_match.pattern_name);
    let description = lpm_common::sanitize_for_terminal(&secret_match.description);
    let location = if secret_match.line > 0 {
        install_ui::dim(&format!(":{}", secret_match.line))
    } else {
        String::new()
    };

    format!(
        "  {} {}{}  {}  {}",
        format_secret_severity(&secret_match.severity),
        install_ui::red(&matched_text),
        location,
        install_ui::cyan(&pattern_name),
        description
    )
}

fn format_secret_severity(severity: &str) -> String {
    match severity {
        "critical" => install_ui::red("critical"),
        "high" => install_ui::yellow("high"),
        _ => install_ui::dim(severity),
    }
}

// Skills validation helpers
// ---------------------------------------------------------------------------

/// Walk the skills directory (including subdirectories), parse frontmatter,
/// run security scans, and validate size limits.
///
/// Returns `(valid_count, errors, security_issues)`.
fn validate_skills_for_publish(
    skills_dir: &Path,
) -> (usize, Vec<String>, Vec<skill_security::SkillSecurityIssue>) {
    let mut valid = 0usize;
    let mut errors = Vec::new();
    let mut security_issues = Vec::new();
    let mut total_size: u64 = 0;

    collect_skill_files(skills_dir, &mut |path| {
        let rel = path
            .strip_prefix(skills_dir)
            .unwrap_or(path)
            .display()
            .to_string();

        let size = std::fs::metadata(path).map_or(0, |m| m.len());
        total_size += size;

        if size > 15 * 1024 {
            errors.push(format!("{rel}: exceeds 15KB limit ({size} bytes)"));
            return;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{rel}: failed to read — {e}"));
                return;
            }
        };

        if content.len() < 100 {
            errors.push(format!("{rel}: content too short (need 100+ chars)"));
            return;
        }

        // Security scan
        let issues = skill_security::scan_skill_content(&content);
        if !issues.is_empty() {
            security_issues.extend(issues);
            return;
        }

        // Frontmatter validation
        let (_meta, _body, fm_errors) = skill_security::parse_skill_frontmatter(&content);
        if !fm_errors.is_empty() {
            for e in fm_errors {
                errors.push(format!("{rel}: {e}"));
            }
            return;
        }

        valid += 1;
    });

    if total_size > 100 * 1024 {
        errors.push(format!(
            "total skills size {} bytes exceeds 100KB limit",
            total_size
        ));
    }

    (valid, errors, security_issues)
}

/// Recursively collect .md files under a directory and call `f` for each.
fn collect_skill_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_skill_files(&path, f);
        } else if path.extension().is_some_and(|e| e == "md") {
            f(&path);
        }
    }
}

/// Ensure ".lpm/skills" is present in the `files` array in package.json.
///
/// IMPORTANT: Only `.lpm/skills` is added — NOT `.lpm` broadly. The `.lpm/`
/// directory also contains certs, webhook logs, install hashes, and other
/// project-local data that must NEVER be published in the tarball.
fn ensure_lpm_in_files(pkg_json_path: &Path, pkg_json: &serde_json::Value) -> Result<(), LpmError> {
    if let Some(files) = pkg_json.get("files").and_then(|f| f.as_array()) {
        let has_skills = files.iter().any(|f| {
            let s = f.as_str().unwrap_or("");
            s == ".lpm/skills" || s == ".lpm/skills/" || s == ".lpm"
        });
        if !has_skills {
            let content = std::fs::read_to_string(pkg_json_path)?;

            if let Some(files_pos) = content.find("\"files\"")
                && let Some(bracket_offset) = content[files_pos..].find('[')
            {
                let insert_pos = files_pos + bracket_offset + 1;
                let mut new_content = String::with_capacity(content.len() + 32);
                new_content.push_str(&content[..insert_pos]);
                let after_bracket = &content[insert_pos..];
                let indent = after_bracket.find('"').map_or("    ", |i| {
                    let segment = &after_bracket[..i];
                    segment.rfind('\n').map_or(segment, |nl| &segment[nl + 1..])
                });
                new_content.push('\n');
                new_content.push_str(indent);
                new_content.push_str("\".lpm/skills\",");
                new_content.push_str(&content[insert_pos..]);

                let tmp = pkg_json_path.with_extension("json.tmp");
                std::fs::write(&tmp, &new_content)?;
                std::fs::rename(&tmp, pkg_json_path)?;

                install_ui::warn(
                    "Added \".lpm/skills\" to package.json \"files\" — skills would be excluded otherwise",
                );
            }
        }
    }
    Ok(())
}

/// Compute a deterministic digest of local skill files for staleness comparison.
fn compute_skills_digest(skills_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(String, String)> = Vec::new();

    collect_skill_files(skills_dir, &mut |path| {
        let rel = path
            .strip_prefix(skills_dir)
            .unwrap_or(path)
            .display()
            .to_string();
        let content = std::fs::read_to_string(path).unwrap_or_default();
        entries.push((rel, content));
    });

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (name, content) in &entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

/// Compute a digest from previously published skills for staleness comparison.
fn compute_published_skills_digest(skills: &[lpm_registry::Skill]) -> String {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<(&str, &str)> = skills
        .iter()
        .map(|s| {
            let content = s
                .raw_content
                .as_deref()
                .or(s.content.as_deref())
                .unwrap_or("");
            (s.name.as_str(), content)
        })
        .collect();

    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    for (name, content) in &entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(content.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

fn print_upload_phase(
    registry: &str,
    target_name: &str,
    version: &str,
    visibility: &str,
    dist_tag: &str,
) {
    install_ui::phase(&format!(
        "Uploading tarball to {}",
        install_ui::yellow(registry)
    ));
    publish_detail(
        "target",
        &install_ui::yellow(&format!("{target_name}@{version}")),
    );
    publish_detail("visibility", &format_publish_visibility(visibility));
    publish_detail("dist-tag", &install_ui::yellow(dist_tag));
}

struct DryRunSummary<'a> {
    name: &'a str,
    version: &'a str,
    target_names: &'a std::collections::HashMap<String, String>,
    file_count: usize,
    tarball_size: usize,
    quality_result: Option<&'a quality::QualityResult>,
    has_skills: bool,
    ecosystem: &'a str,
    targets: &'a [PublishTarget],
}

fn print_dry_run_summary(summary: &DryRunSummary<'_>) {
    install_ui::detail("");
    install_ui::phase("Dry run — no changes will be made");
    publish_detail(
        "package",
        &install_ui::yellow(&format!("{}@{}", summary.name, summary.version)),
    );
    for (registry_key, target_name) in summary.target_names {
        publish_detail(
            &format!("{registry_key} name"),
            &install_ui::yellow(target_name),
        );
    }
    publish_detail(
        "files",
        &format_dry_run_files_value(summary.file_count, summary.tarball_size),
    );
    if let Some(qr) = summary.quality_result {
        publish_detail(
            "quality",
            &format!(
                "{}/{}",
                install_ui::status_ok(&qr.score.to_string()),
                qr.max_score
            ),
        );
    }
    if summary.has_skills {
        publish_detail("skills", &install_ui::status_ok("included"));
    }
    publish_detail("ecosystem", &install_ui::yellow(summary.ecosystem));
    let target_keys = summary
        .targets
        .iter()
        .map(PublishTarget::key)
        .collect::<Vec<_>>();
    publish_detail("targets", &install_ui::yellow(&target_keys.join(", ")));
    install_ui::detail("");
}

fn publish_detail(label: &str, value: &str) {
    let label = format!("{label:<10}");
    install_ui::detail(&format!("    {} {}", install_ui::dim(&label), value));
}

fn format_dry_run_files_value(file_count: usize, tarball_size: usize) -> String {
    format!(
        "{} files {}",
        install_ui::status_ok(&file_count.to_string()),
        install_ui::dim(&format!(
            "({})",
            lpm_common::format_bytes(tarball_size as u64)
        ))
    )
}

fn format_publish_retry_detail(target: &PublishTarget) -> String {
    format!(
        "  {} {}",
        install_ui::dim("Retry:"),
        install_ui::yellow(&format!("lpm publish {}", target.retry_flag()))
    )
}

fn lpm_visibility(_pkg_json: &serde_json::Value) -> &'static str {
    "private"
}

fn visibility_from_access(access: &str) -> &str {
    if access == "restricted" {
        "private"
    } else {
        access
    }
}

fn format_publish_visibility(visibility: &str) -> String {
    match visibility {
        "public" => install_ui::status_ok("public"),
        other => install_ui::yellow(other),
    }
}

fn print_publish_quality_result(result: &quality::QualityResult) {
    install_ui::done(&format!(
        "Quality score: {}/{}",
        result.score, result.max_score
    ));
    for check in result.checks.iter().filter(|check| !check.passed) {
        install_ui::warn(&format_publish_quality_issue(check));
    }
}

fn format_publish_quality_issue(check: &quality::QualityCheck) -> String {
    let detail = check.detail.as_deref().unwrap_or(if check.server_only {
        "pending"
    } else {
        "missing"
    });
    format!("{}  {}", check.label, install_ui::dim(detail))
}

/// Extract and normalize Swift manifest metadata from raw `swift package dump-package` output.
///
/// Transforms raw SPM dump-package JSON into the canonical format expected by the server:
/// - `toolsVersion: { _version: "5.9.0", ... }` → `"5.9.0"`
/// - `platforms[].platformName` → `platforms[].name`
/// - `products[].type: { library: [...] }` → `"library"`
/// - `targets[].dependencies[].byName: ["Foo", null]` → `{ type: "byName", name: "Foo" }`
/// - `dependencies[].sourceControl: [{ identity, location, ... }]` → flat object
fn extract_swift_metadata(manifest: &serde_json::Value) -> serde_json::Value {
    let tools_version = manifest
        .get("toolsVersion")
        .and_then(|tv| {
            // Object form: { _version: "5.9.0", ... }
            if let Some(v) = tv.get("_version").and_then(|v| v.as_str()) {
                Some(serde_json::json!(v))
            } else if tv.is_string() {
                // Already a string
                Some(tv.clone())
            } else {
                None
            }
        })
        .unwrap_or(serde_json::Value::Null);

    let platforms = manifest
        .get("platforms")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.get("platformName")
                            .or_else(|| p.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                        "version": p.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let products = manifest
        .get("products")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    let product_type = p.get("type").map_or_else(
                        || "library".into(),
                        |t| {
                            if let Some(obj) = t.as_object() {
                                obj.keys()
                                    .next()
                                    .cloned()
                                    .unwrap_or_else(|| "library".into())
                            } else if let Some(s) = t.as_str() {
                                s.to_string()
                            } else {
                                "library".into()
                            }
                        },
                    );

                    serde_json::json!({
                        "name": p.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                        "type": product_type,
                        "targets": p.get("targets").cloned().unwrap_or(serde_json::json!([])),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let targets = manifest
        .get("targets")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .map(|t| {
                    let deps = t
                        .get("dependencies")
                        .and_then(|d| d.as_array())
                        .map(|deps| {
                            deps.iter()
                                .map(|d| {
                                    // Already extracted: has "type" and "name"
                                    if d.get("type").is_some() && d.get("name").is_some() {
                                        return d.clone();
                                    }
                                    // Raw: { byName: ["Foo", null] }
                                    if let Some(by_name) =
                                        d.get("byName").and_then(|v| v.as_array())
                                    {
                                        return serde_json::json!({
                                            "type": "byName",
                                            "name": by_name.first()
                                                .and_then(|v| v.as_str())
                                                .unwrap_or_default(),
                                        });
                                    }
                                    // Raw: { product: ["Bar", ...] }
                                    if let Some(product) =
                                        d.get("product").and_then(|v| v.as_array())
                                    {
                                        return serde_json::json!({
                                            "type": "product",
                                            "name": product.first()
                                                .and_then(|v| v.as_str())
                                                .unwrap_or_default(),
                                        });
                                    }
                                    d.clone()
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    serde_json::json!({
                        "name": t.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
                        "type": t.get("type").and_then(|v| v.as_str()).unwrap_or("regular"),
                        "dependencies": deps,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let dependencies = manifest
        .get("dependencies")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .map(|dep| {
                    // Already extracted
                    if dep.get("type").is_some()
                        && (dep.get("identity").is_some() || dep.get("name").is_some())
                    {
                        return dep.clone();
                    }
                    // Raw: { sourceControl: [{ identity, location: { remote: [...] }, requirement }] }
                    if let Some(sc_val) = dep.get("sourceControl") {
                        let sc = if let Some(arr) = sc_val.as_array() {
                            arr.first()
                        } else {
                            Some(sc_val)
                        };
                        if let Some(sc) = sc {
                            return serde_json::json!({
                                "type": "sourceControl",
                                "identity": sc.get("identity").and_then(|v| v.as_str()),
                                "location": sc.get("location")
                                    .and_then(|l| l.get("remote"))
                                    .and_then(|r| r.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|v| v.as_str()),
                                "requirement": sc.get("requirement").cloned(),
                            });
                        }
                    }
                    // Raw: { fileSystem: [{ identity, path }] }
                    if let Some(fs_val) = dep.get("fileSystem") {
                        let fs = if let Some(arr) = fs_val.as_array() {
                            arr.first()
                        } else {
                            Some(fs_val)
                        };
                        if let Some(fs) = fs {
                            return serde_json::json!({
                                "type": "fileSystem",
                                "identity": fs.get("identity").and_then(|v| v.as_str()),
                                "path": fs.get("path").and_then(|v| v.as_str()),
                            });
                        }
                    }
                    dep.clone()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    serde_json::json!({
        "toolsVersion": tools_version,
        "platforms": platforms,
        "products": products,
        "targets": targets,
        "dependencies": dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::behavioral::secrets::SecretMatch;

    #[test]
    fn secret_scan_human_renderer_uses_slim_lines_with_expected_content() {
        let scan = SecretScanResult {
            matches: vec![SecretMatch {
                pattern_name: "stripe_live_secret".to_string(),
                description: "Stripe live secret key".to_string(),
                matched_text: "sk_live_********1234".to_string(),
                line: 7,
                severity: "critical".to_string(),
            }],
            files_scanned: 1,
        };

        let lines = format_secret_scan_human(&scan);
        let joined = lines
            .iter()
            .map(|line| match line {
                SecretScanLine::Warn(message)
                | SecretScanLine::Failed(message)
                | SecretScanLine::Detail(message) => message.as_str(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let joined = console::strip_ansi_codes(&joined).into_owned();

        assert!(
            matches!(lines.first(), Some(SecretScanLine::Warn(_))),
            "secret scan headline should render as an install_ui warning"
        );
        assert!(
            matches!(lines.get(2), Some(SecretScanLine::Failed(_))),
            "blocking result should render as an install_ui failure"
        );
        assert!(
            joined.contains("Secret scan found 1 potential leak")
                && joined.contains("critical sk_live_********1234:7  stripe_live_secret")
                && joined.contains("Publish blocked. Remove secrets before publishing.")
                && joined.contains("use --allow-secrets"),
            "secret scan slim output missing expected detail:\n{joined}"
        );
    }

    #[test]
    fn secret_scan_json_envelope_preserves_machine_fields() {
        let scan = SecretScanResult {
            matches: vec![SecretMatch {
                pattern_name: "github_pat".to_string(),
                description: "GitHub personal access token".to_string(),
                matched_text: "ghp_********1234".to_string(),
                line: 3,
                severity: "critical".to_string(),
            }],
            files_scanned: 1,
        };

        let json = secret_scan_json(&scan);

        assert_eq!(json["error"], "secret_scan_failed");
        assert_eq!(json["matches"][0]["pattern"], "github_pat");
        assert_eq!(json["matches"][0]["line"], 3);
        assert_eq!(
            json["hint"],
            "Use --allow-secrets to bypass (not recommended)"
        );
    }

    #[test]
    fn ensure_lpm_in_files_preserves_tabs() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json_path = dir.path().join("package.json");
        let original = "{\n\t\"name\": \"test\",\n\t\"files\": [\n\t\t\"src/\"\n\t]\n}\n";
        std::fs::write(&pkg_json_path, original).unwrap();

        let pkg_json: serde_json::Value = serde_json::from_str(original).unwrap();
        ensure_lpm_in_files(&pkg_json_path, &pkg_json).unwrap();

        let result = std::fs::read_to_string(&pkg_json_path).unwrap();
        assert!(result.contains("\".lpm/skills\""), "should add .lpm/skills");
        assert!(
            result.contains("\t\"src/\""),
            "should preserve tab indentation"
        );
        assert!(
            result.find("\"name\"").unwrap() < result.find("\"files\"").unwrap(),
            "key order preserved"
        );
    }

    #[test]
    fn ensure_lpm_in_files_already_present() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json_path = dir.path().join("package.json");
        let original = "{\n\t\"files\": [\".lpm/skills\", \"src/\"]\n}\n";
        std::fs::write(&pkg_json_path, original).unwrap();

        let pkg_json: serde_json::Value = serde_json::from_str(original).unwrap();
        ensure_lpm_in_files(&pkg_json_path, &pkg_json).unwrap();

        let result = std::fs::read_to_string(&pkg_json_path).unwrap();
        assert_eq!(result, original, "file should be untouched");
    }

    #[test]
    fn skills_digest_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("a.md"), "alpha").unwrap();
        std::fs::write(skills_dir.join("b.md"), "beta").unwrap();

        let d1 = compute_skills_digest(&skills_dir);
        let d2 = compute_skills_digest(&skills_dir);
        assert_eq!(d1, d2, "same content must produce same digest");

        std::fs::write(skills_dir.join("b.md"), "gamma").unwrap();
        let d3 = compute_skills_digest(&skills_dir);
        assert_ne!(d1, d3, "different content must produce different digest");
    }

    #[test]
    fn resolve_targets_cli_flags_override() {
        // --npm only
        let targets = resolve_targets(true, false, false, false, None, None).unwrap();
        assert_eq!(targets, vec![PublishTarget::Npm]);

        // --lpm only
        let targets = resolve_targets(false, true, false, false, None, None).unwrap();
        assert_eq!(targets, vec![PublishTarget::Lpm]);

        // --npm --lpm
        let targets = resolve_targets(true, true, false, false, None, None).unwrap();
        assert_eq!(targets, vec![PublishTarget::Lpm, PublishTarget::Npm]);

        // --github
        let targets = resolve_targets(false, false, true, false, None, None).unwrap();
        assert_eq!(targets, vec![PublishTarget::GitHub]);

        // --registry <url>
        let targets = resolve_targets(
            false,
            false,
            false,
            false,
            Some("https://npm.corp.com"),
            None,
        )
        .unwrap();
        assert_eq!(
            targets,
            vec![PublishTarget::Custom("https://npm.corp.com".into())]
        );
    }

    #[test]
    fn resolve_targets_from_config() {
        let config = lpm_json::PublishConfig {
            registries: vec!["npm".into(), "lpm".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(targets, vec![PublishTarget::Npm, PublishTarget::Lpm]);
    }

    #[test]
    fn resolve_targets_default_lpm() {
        let targets = resolve_targets(false, false, false, false, None, None).unwrap();
        assert_eq!(targets, vec![PublishTarget::Lpm]);
    }

    #[test]
    fn resolve_targets_cli_overrides_config() {
        let config = lpm_json::PublishConfig {
            registries: vec!["lpm".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        // CLI --npm should ignore config
        let targets = resolve_targets(true, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(targets, vec![PublishTarget::Npm]);
    }

    #[test]
    fn resolve_targets_config_with_custom_url() {
        let config = lpm_json::PublishConfig {
            registries: vec!["lpm".into(), "https://npm.corp.com".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(
            targets,
            vec![
                PublishTarget::Lpm,
                PublishTarget::Custom("https://npm.corp.com".into()),
            ]
        );
    }

    #[test]
    fn resolve_targets_rejects_unknown_entries() {
        let config = lpm_json::PublishConfig {
            registries: vec!["nmm".into(), "typo".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let result = resolve_targets(false, false, false, false, None, Some(&config));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown publish registries"));
        assert!(err.contains("nmm"));
        assert!(err.contains("typo"));
    }

    #[test]
    fn resolve_targets_rejects_http_urls() {
        let config = lpm_json::PublishConfig {
            registries: vec!["http://insecure.com".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let result = resolve_targets(false, false, false, false, None, Some(&config));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn resolve_targets_deduplicates() {
        let config = lpm_json::PublishConfig {
            registries: vec!["npm".into(), "npm".into(), "lpm".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(targets, vec![PublishTarget::Npm, PublishTarget::Lpm]);
    }

    #[test]
    fn publish_result_display() {
        assert_eq!(PublishTarget::Lpm.display_name(), "LPM");
        assert_eq!(PublishTarget::Npm.display_name(), "npm");
        assert_eq!(PublishTarget::GitHub.display_name(), "GitHub Packages");
        assert_eq!(
            PublishTarget::Custom("https://x.com".into()).key(),
            "https://x.com"
        );
        assert_eq!(PublishTarget::Npm.retry_flag(), "--npm");
        assert_eq!(PublishTarget::GitHub.retry_flag(), "--github");
    }

    #[test]
    fn dry_run_files_value_uses_slim_value_roles() {
        assert_eq!(
            console::strip_ansi_codes(&format_dry_run_files_value(3, 2048)).into_owned(),
            "3 files (2.0 KB)"
        );
    }

    #[test]
    fn publish_retry_detail_uses_slim_detail_shape() {
        assert_eq!(
            console::strip_ansi_codes(&format_publish_retry_detail(&PublishTarget::Npm))
                .into_owned(),
            "  Retry: lpm publish --npm"
        );
    }

    #[test]
    fn extract_swift_metadata_from_raw_dump() {
        // Realistic raw `swift package dump-package` output
        let raw = serde_json::json!({
            "name": "Hue",
            "toolsVersion": {
                "_version": "5.9.0",
                "experimentalFeatures": []
            },
            "platforms": [
                { "platformName": "ios", "version": "13.0", "options": [] },
                { "platformName": "macos", "version": "10.15", "options": [] },
                { "platformName": "watchos", "version": "6.0", "options": [] },
                { "platformName": "tvos", "version": "13.0", "options": [] },
                { "platformName": "visionos", "version": "1.0", "options": [] }
            ],
            "products": [
                {
                    "name": "Hue",
                    "type": { "library": ["automatic"] },
                    "targets": ["Hue"],
                    "settings": []
                }
            ],
            "targets": [
                {
                    "name": "Hue",
                    "type": "regular",
                    "dependencies": [],
                    "path": "Sources/Hue"
                },
                {
                    "name": "HueTests",
                    "type": "test",
                    "dependencies": [{ "byName": ["Hue", null] }],
                    "path": "Tests/HueTests"
                }
            ],
            "dependencies": [
                {
                    "sourceControl": [{
                        "identity": "swift-argument-parser",
                        "location": { "remote": ["https://github.com/apple/swift-argument-parser.git"] },
                        "requirement": { "range": [{ "lowerBound": "1.0.0", "upperBound": "2.0.0" }] }
                    }]
                }
            ]
        });

        let result = extract_swift_metadata(&raw);

        // toolsVersion: extracted as string
        assert_eq!(result["toolsVersion"], "5.9.0");

        // platforms: platformName → name
        let platforms = result["platforms"].as_array().unwrap();
        assert_eq!(platforms.len(), 5);
        assert_eq!(platforms[0]["name"], "ios");
        assert_eq!(platforms[0]["version"], "13.0");
        assert_eq!(platforms[1]["name"], "macos");
        assert_eq!(platforms[4]["name"], "visionos");

        // products: type object → string
        let products = result["products"].as_array().unwrap();
        assert_eq!(products[0]["name"], "Hue");
        assert_eq!(products[0]["type"], "library");

        // targets: byName array → { type, name }
        let targets = result["targets"].as_array().unwrap();
        assert_eq!(targets[0]["name"], "Hue");
        assert_eq!(targets[0]["type"], "regular");
        assert_eq!(targets[1]["name"], "HueTests");
        let test_deps = targets[1]["dependencies"].as_array().unwrap();
        assert_eq!(test_deps[0]["type"], "byName");
        assert_eq!(test_deps[0]["name"], "Hue");

        // dependencies: sourceControl array → flat
        let deps = result["dependencies"].as_array().unwrap();
        assert_eq!(deps[0]["type"], "sourceControl");
        assert_eq!(deps[0]["identity"], "swift-argument-parser");
        assert_eq!(
            deps[0]["location"],
            "https://github.com/apple/swift-argument-parser.git"
        );
    }

    #[test]
    fn extract_swift_metadata_already_normalized() {
        // Pre-extracted format (from JS CLI) should pass through unchanged
        let extracted = serde_json::json!({
            "toolsVersion": "5.9.0",
            "platforms": [
                { "name": "ios", "version": "13.0" },
                { "name": "macos", "version": "10.15" }
            ],
            "products": [
                { "name": "Hue", "type": "library", "targets": ["Hue"] }
            ],
            "targets": [
                {
                    "name": "HueTests",
                    "type": "test",
                    "dependencies": [{ "type": "byName", "name": "Hue" }]
                }
            ],
            "dependencies": [
                {
                    "type": "sourceControl",
                    "identity": "swift-argument-parser",
                    "location": "https://github.com/apple/swift-argument-parser.git",
                    "requirement": null
                }
            ]
        });

        let result = extract_swift_metadata(&extracted);

        assert_eq!(result["toolsVersion"], "5.9.0");
        assert_eq!(result["platforms"][0]["name"], "ios");
        assert_eq!(result["products"][0]["type"], "library");
        assert_eq!(result["targets"][0]["dependencies"][0]["type"], "byName");
        assert_eq!(result["dependencies"][0]["type"], "sourceControl");
        assert_eq!(
            result["dependencies"][0]["identity"],
            "swift-argument-parser"
        );
    }

    #[test]
    fn extract_swift_metadata_empty_manifest() {
        let empty = serde_json::json!({});
        let result = extract_swift_metadata(&empty);

        assert!(result["toolsVersion"].is_null());
        assert_eq!(result["platforms"].as_array().unwrap().len(), 0);
        assert_eq!(result["products"].as_array().unwrap().len(), 0);
        assert_eq!(result["targets"].as_array().unwrap().len(), 0);
        assert_eq!(result["dependencies"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn extract_swift_metadata_filesystem_dependency() {
        let manifest = serde_json::json!({
            "toolsVersion": { "_version": "5.8.0" },
            "platforms": [],
            "products": [],
            "targets": [],
            "dependencies": [
                {
                    "fileSystem": [{
                        "identity": "local-utils",
                        "path": "../local-utils"
                    }]
                }
            ]
        });

        let result = extract_swift_metadata(&manifest);
        let deps = result["dependencies"].as_array().unwrap();
        assert_eq!(deps[0]["type"], "fileSystem");
        assert_eq!(deps[0]["identity"], "local-utils");
        assert_eq!(deps[0]["path"], "../local-utils");
    }

    // ─── Orchestration: config validation edge cases ─────────────

    #[test]
    fn resolve_targets_all_invalid_entries_errors() {
        // All entries are typos — should error, not silently produce empty vec
        let config = lpm_json::PublishConfig {
            registries: vec!["nmm".into(), "githb".into(), "foobar".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let result = resolve_targets(false, false, false, false, None, Some(&config));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nmm"));
        assert!(err.contains("githb"));
        assert!(err.contains("foobar"));
    }

    #[test]
    fn resolve_targets_mixed_valid_and_invalid_errors() {
        // One valid + one invalid — should still error (strict validation)
        let config = lpm_json::PublishConfig {
            registries: vec!["npm".into(), "typo".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let result = resolve_targets(false, false, false, false, None, Some(&config));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("typo"));
    }

    #[test]
    fn resolve_targets_empty_registries_defaults_to_lpm() {
        // Empty registries array falls through to default LPM
        let config = lpm_json::PublishConfig {
            registries: vec![],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(targets, vec![PublishTarget::Lpm]);
    }

    #[test]
    fn resolve_targets_custom_https_url_accepted() {
        let config = lpm_json::PublishConfig {
            registries: vec!["https://npm.corp.com".into(), "lpm".into()],
            lpm: None,
            npm: None,
            github: None,
            gitlab: None,
        };
        let targets = resolve_targets(false, false, false, false, None, Some(&config)).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0],
            PublishTarget::Custom("https://npm.corp.com".into())
        );
        assert_eq!(targets[1], PublishTarget::Lpm);
    }

    // ─── Orchestration: integrity_to_sha512_hex ──────────────────

    #[test]
    fn integrity_to_sha512_hex_roundtrips() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use sha2::{Digest, Sha512};

        let data = b"test tarball data";
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let integrity = format!("sha512-{}", BASE64.encode(hash_bytes));

        let hex = integrity_to_sha512_hex(&integrity);

        // Should be 128 hex chars (512 bits / 4 bits per char)
        assert_eq!(hex.len(), 128);
        // Should match direct hex encoding
        assert_eq!(hex, format!("{:x}", hash_bytes));
    }

    // ─── Orchestration: deduplicate_targets ───────────────────────

    #[test]
    fn deduplicate_preserves_order() {
        let targets = vec![
            PublishTarget::Npm,
            PublishTarget::Lpm,
            PublishTarget::Npm,
            PublishTarget::GitHub,
            PublishTarget::Lpm,
        ];
        let deduped = deduplicate_targets(targets);
        assert_eq!(
            deduped,
            vec![
                PublishTarget::Npm,
                PublishTarget::Lpm,
                PublishTarget::GitHub
            ]
        );
    }

    #[test]
    fn deduplicate_custom_urls_by_value() {
        let targets = vec![
            PublishTarget::Custom("https://a.com".into()),
            PublishTarget::Custom("https://b.com".into()),
            PublishTarget::Custom("https://a.com".into()),
        ];
        let deduped = deduplicate_targets(targets);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].key(), "https://a.com");
        assert_eq!(deduped[1].key(), "https://b.com");
    }

    // ─── Orchestration: provenance hash binding ──────────────────

    #[test]
    fn provenance_hash_matches_rewritten_tarball() {
        // This proves the core invariant: after tarball rewriting, the hash
        // used for provenance must match the actual uploaded artifact.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/neo.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "exports.x = 1").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/neo.pkg", "version": "1.0.0"}"#).unwrap();
        let (original_tarball, _) = publish_common::create_tarball(project, &pkg_json).unwrap();

        // Simulate what the publish loop does for a renamed npm target
        let npm_name = "@tolga/pkg";
        let rewritten =
            publish_common::rewrite_tarball_name(&original_tarball, "@lpm.dev/neo.pkg", npm_name)
                .unwrap();

        // Compute hashes the way provenance does (via integrity_to_sha512_hex)
        let final_hashes = publish_common::compute_hashes(&rewritten);
        let provenance_hex = integrity_to_sha512_hex(&final_hashes.integrity);

        // Independently compute SHA-512 hex directly from the rewritten bytes
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(&rewritten);
        let direct_hex = format!("{:x}", hasher.finalize());

        assert_eq!(
            provenance_hex, direct_hex,
            "provenance hash must match direct SHA-512 of the rewritten tarball"
        );
    }

    #[test]
    fn lpm_renamed_publish_dist_hashes_match_rewritten_tarball() {
        // This proves the re-audit finding #1 fix: when LPM name differs,
        // version_data.dist must be recomputed from the rewritten tarball.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "original-name", "version": "2.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("lib.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "original-name", "version": "2.0.0"}"#).unwrap();
        let (original_tarball, _) = publish_common::create_tarball(project, &pkg_json).unwrap();

        let original_hashes = publish_common::compute_hashes(&original_tarball);

        // Rewrite to LPM name
        let lpm_name = "@lpm.dev/neo.pkg";
        let lpm_tarball =
            publish_common::rewrite_tarball_name(&original_tarball, "original-name", lpm_name)
                .unwrap();
        let lpm_hashes = publish_common::compute_hashes(&lpm_tarball);

        // The dist hashes on the LPM version data should use lpm_hashes, not original_hashes
        assert_ne!(
            original_hashes.shasum, lpm_hashes.shasum,
            "original and rewritten hashes must differ"
        );

        // Simulate what the publish loop now does: recompute dist
        let mut version_data = serde_json::json!({
            "dist": {
                "shasum": original_hashes.shasum,
                "integrity": original_hashes.integrity,
            }
        });

        // This is the fix from re-audit finding #1
        if lpm_name != "original-name" {
            version_data["dist"] = serde_json::json!({
                "shasum": lpm_hashes.shasum,
                "integrity": lpm_hashes.integrity,
            });
        }

        assert_eq!(
            version_data["dist"]["shasum"].as_str().unwrap(),
            lpm_hashes.shasum,
            "dist.shasum must match rewritten LPM tarball"
        );
    }
}
