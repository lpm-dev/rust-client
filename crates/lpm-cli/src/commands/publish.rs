use crate::{auth, oidc, output, provenance, quality, sigstore};
use crate::commands::publish_common::{self, TarballFile};
use crate::commands::publish_npm;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_runner::lpm_json;
use lpm_security::skill_security;
use owo_colors::OwoColorize;
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

/// Resolve the target registries from CLI flags and lpm.json config.
///
/// CLI flags take precedence. If no flags, read from lpm.json.
/// If no config, default to LPM only.
pub fn resolve_targets(
	cli_npm: bool,
	cli_lpm: bool,
	cli_github: bool,
	cli_gitlab: bool,
	cli_registry: Option<&str>,
	config: Option<&lpm_json::PublishConfig>,
) -> Vec<PublishTarget> {
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
		return targets;
	}

	if let Some(publish_config) = config {
		if !publish_config.registries.is_empty() {
			return publish_config
				.registries
				.iter()
				.filter_map(|r| match r.as_str() {
					"lpm" => Some(PublishTarget::Lpm),
					"npm" => Some(PublishTarget::Npm),
					"github" => Some(PublishTarget::GitHub),
					"gitlab" => Some(PublishTarget::GitLab),
					url if url.starts_with("https://") => {
						Some(PublishTarget::Custom(url.to_string()))
					}
					_ => None,
				})
				.collect();
		}
	}

	// Default: LPM only
	vec![PublishTarget::Lpm]
}

pub async fn run(
	client: &RegistryClient,
	project_dir: &Path,
	dry_run: bool,
	check_only: bool,
	yes: bool,
	json_output: bool,
	min_score: Option<u32>,
	cli_npm: bool,
	cli_lpm: bool,
	cli_github: bool,
	cli_gitlab: bool,
	cli_registry: Option<&str>,
	provenance_flag: bool,
) -> Result<(), LpmError> {
	if !json_output {
		output::print_header();
	}

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
	let lpm_config = lpm_json::read_lpm_json(project_dir)
		.map_err(|e| LpmError::Registry(e))?;
	let publish_config = lpm_config.as_ref().and_then(|c| c.publish.as_ref());

	// Resolve target registries
	let targets = resolve_targets(cli_npm, cli_lpm, cli_github, cli_gitlab, cli_registry, publish_config);

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
				"GitLab Packages requires publish.gitlab.projectId in lpm.json".into()
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

	let mut target_names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
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
					.map(Ok)
					.unwrap_or_else(|| publish_npm::resolve_npm_name(name, None))?
			}
			PublishTarget::GitHub => {
				// GitHub: config override → npm config → package.json. Must be scoped.
				let gh_name = github_config
					.and_then(|c| c.name.clone())
					.or_else(|| npm_config.and_then(|c| c.name.clone()))
					.map(Ok)
					.unwrap_or_else(|| publish_npm::resolve_npm_name(name, None))?;
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
					.map(Ok)
					.unwrap_or_else(|| publish_npm::resolve_npm_name(name, None))?
			}
			PublishTarget::Custom(_) => {
				// Custom: npm config → package.json.
				npm_config
					.and_then(|c| c.name.clone())
					.map(Ok)
					.unwrap_or_else(|| publish_npm::resolve_npm_name(name, None))?
			}
		};
		target_names.insert(target.key(), resolved);
	}

	// Step 2: Read README
	let readme = publish_common::read_readme(project_dir);

	// Step 3: Create tarball (silent — messages print after quality checks)
	let (tarball_data, tarball_files) = publish_common::create_tarball(project_dir, &pkg_json)?;

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
	if lpm_config_path.exists() {
		if let Ok(config_str) = std::fs::read_to_string(&lpm_config_path) {
			if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
				if let Some(eco) = config.get("ecosystem").and_then(|v| v.as_str()) {
					detected_ecosystem = eco.to_string();
				}
			}
		}
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
			print_quality_checks(&qr);
		}

		// Enforce --min-score if provided
		if let Some(min) = min_score {
			if qr.score < min {
				return Err(LpmError::Registry(format!(
					"quality score {} is below minimum {} (use --min-score to adjust)",
					qr.score, min
				)));
			}
		}

		Some(qr)
	} else {
		None
	};

	// Now print the action messages
	if !json_output {
		let target_str = targets
			.iter()
			.map(|t| t.display_name())
			.collect::<Vec<_>>()
			.join(" + ");

		// Show per-target names so the user sees what goes where
		if target_names.is_empty() {
			output::info(&format!("Publishing {}@{} → {target_str}", name.bold(), version));
		} else {
			let names_display = targets
				.iter()
				.map(|t| {
					let key = t.key();
					if let Some(target_name) = target_names.get(&key) {
						format!("{}: {target_name}", t.display_name())
					} else {
						format!("{}: {name}", t.display_name())
					}
				})
				.collect::<Vec<_>>()
				.join(", ");
			output::info(&format!("Publishing {}@{}", name.bold(), version));
			output::info(&format!("Targets: {names_display}"));
		}
		output::info(&format!(
			"Packing tarball... {} files ({}) → tarball {}",
			tarball_files.len(),
			lpm_common::format_bytes(tarball_files.iter().map(|f| f.size).sum::<u64>()),
			lpm_common::format_bytes(tarball_size as u64),
		));
		if let Some(ref qr) = quality_result {
			print_quality_summary(qr);
		}
	}

	// Step 4b: Skills validation (LPM target only)
	let skills_dir = project_dir.join(".lpm").join("skills");
	let has_skills = skills_dir.exists() && skills_dir.is_dir();

	if has_skills && targets_lpm {
		if !json_output {
			output::info("Validating skills...");
		}

		let (valid, skill_errors, security_issues) =
			validate_skills_for_publish(&skills_dir);

		if !security_issues.is_empty() {
			for issue in &security_issues {
				output::warn(&format!(
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
				output::warn(err);
			}
			return Err(LpmError::Registry(
				"skills validation failed — fix errors above".into(),
			));
		}

		if !json_output {
			output::success(&format!("{valid} skill(s) validated"));
		}

		ensure_lpm_in_files(&pkg_json_path, &pkg_json)?;
	}

	// Step 4c: Skills staleness check (LPM only)
	if has_skills && targets_lpm {
		let name_short = name.strip_prefix("@lpm.dev/").unwrap_or(name);
		match client.get_skills(name_short, None).await {
			Ok(prev) if !prev.skills.is_empty() => {
				let local_digest = compute_skills_digest(&skills_dir);
				let published_digest = compute_published_skills_digest(&prev.skills);
				if local_digest == published_digest {
					if !json_output {
						output::warn(
							"Skills are identical to the previously published version — consider updating them",
						);
					}
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
			if lpm_cfg.exists() {
				if let Ok(s) = std::fs::read_to_string(&lpm_cfg) {
					if let Ok(c) = serde_json::from_str::<serde_json::Value>(&s) {
						if let Some(e) = c.get("ecosystem").and_then(|v| v.as_str()) {
							eco = e.to_string();
						}
					}
				}
			}
			if project_dir.join("Package.swift").exists() && eco == "js" {
				eco = "swift".to_string();
			}

			eprintln!();
			eprintln!("  {} Dry run — no changes will be made.\n", "ℹ".blue());
			eprintln!("  {} {}", "Package:".dimmed(), format!("{name}@{version}").bold());
			for (registry_key, target_name) in &target_names {
				eprintln!("  {} {}", format!("{registry_key} name:").dimmed(), target_name.bold());
			}
			eprintln!("  {} {} files ({})", "Files:".dimmed(), tarball_files.len(), lpm_common::format_bytes(tarball_size as u64));
			if let Some(ref qr) = quality_result {
				eprintln!("  {} {}", "Quality:".dimmed(), format!("{}/{}", qr.score, qr.max_score));
			}
			if has_skills {
				eprintln!("  {} included", "Skills:".dimmed());
			}
			eprintln!("  {} {}", "Ecosystem:".dimmed(), eco);
			let target_names: Vec<String> = targets.iter().map(|t| t.key()).collect();
			eprintln!("  {} {}", "Targets:".dimmed(), target_names.join(", "));
			eprintln!();
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
					targets.iter().map(|t| t.display_name()).collect::<Vec<_>>().join(" + ")
				)
			} else {
				format!("Publish {name}@{version}?")
			};
			let confirm = cliclack::confirm(prompt_msg)
				.initial_value(true)
				.interact()
				.map_err(|e| LpmError::Registry(e.to_string()))?;

			if !confirm {
				output::info("Publish cancelled.");
				return Ok(());
			}
		}
	}

	// Step 7: Compute hashes (shared between LPM and npm)
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

	// Step 8b: Sigstore provenance (C5/C7)
	let sigstore_bundle = if provenance_flag {
		// C7: --provenance requires a CI environment with OIDC
		let ci = oidc::detect_ci_environment().ok_or_else(|| {
			LpmError::Registry(
				"--provenance requires a CI environment with OIDC support \
				 (GitHub Actions with `permissions: id-token: write`, or GitLab CI)"
					.into(),
			)
		})?;

		if !json_output {
			output::info("Generating Sigstore provenance...");
		}

		// Get raw OIDC JWT (not exchanged with LPM — sent directly to Fulcio)
		let oidc_jwt = match ci {
			oidc::CiEnvironment::GitHubActions => {
				// Fetch JWT with sigstore audience
				let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
					.map_err(|_| LpmError::Registry("ACTIONS_ID_TOKEN_REQUEST_URL not set".into()))?;
				let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
					.map_err(|_| LpmError::Registry("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set".into()))?;
				let url = format!("{request_url}&audience=sigstore");
				let resp = reqwest::Client::new()
					.get(&url)
					.bearer_auth(&request_token)
					.send()
					.await
					.map_err(|e| LpmError::Registry(format!("GitHub OIDC fetch failed: {e}")))?;
				let body: serde_json::Value = resp.json().await
					.map_err(|e| LpmError::Registry(format!("GitHub OIDC parse error: {e}")))?;
				body.get("value")
					.and_then(|v| v.as_str())
					.map(|s| s.to_string())
					.ok_or_else(|| LpmError::Registry("GitHub OIDC response missing 'value'".into()))?
			}
			oidc::CiEnvironment::GitLabCI => {
				std::env::var("SIGSTORE_ID_TOKEN")
					.or_else(|_| std::env::var("LPM_GITLAB_OIDC_TOKEN"))
					.map_err(|_| LpmError::Registry(
						"GitLab CI: set SIGSTORE_ID_TOKEN or LPM_GITLAB_OIDC_TOKEN env var for provenance".into()
					))?
			}
		};

		// Extract SHA-512 hex from integrity string (strip "sha512-" prefix and decode base64)
		let sha512_hex = {
			let b64 = hashes.integrity.strip_prefix("sha512-").unwrap_or(&hashes.integrity);
			let bytes = BASE64.decode(b64).unwrap_or_default();
			hex::encode(&bytes)
		};

		// Build SLSA statement
		let npm_name_for_prov = target_names.values().next().map(|s| s.as_str()).unwrap_or(name);
		let slsa = provenance::build_slsa_statement(&ci, npm_name_for_prov, version, &sha512_hex);
		let slsa_json = serde_json::to_vec(&slsa)
			.map_err(|e| LpmError::Registry(format!("failed to serialize SLSA statement: {e}")))?;

		// Sign with Fulcio + record in Rekor
		match sigstore::sign_and_record(&oidc_jwt, &slsa_json).await {
			Ok(bundle) => {
				if !json_output {
					output::success("Sigstore provenance generated and recorded in Rekor");
				}
				Some(bundle)
			}
			Err(e) => {
				// Sigstore failure is non-fatal — warn and continue without provenance
				output::warn(&format!("Sigstore provenance failed: {e}"));
				output::warn("Publishing without provenance attestation");
				None
			}
		}
	} else {
		None
	};

	// Attach provenance to version data if available (C5)
	if let Some(ref bundle) = sigstore_bundle {
		let bundle_json = serde_json::to_value(bundle).unwrap_or_default();
		// For LPM registry
		version_data["_provenance"] = bundle_json.clone();
		// For npm registry (npm's expected field name)
		version_data["_npmProvenanceAttestations"] = bundle_json;
	}

	// Sequential publish to each target registry (B1)
	let mut results: Vec<PublishResult> = Vec::with_capacity(targets.len());

	for target in &targets {
		let start = std::time::Instant::now();

		match target {
			PublishTarget::Lpm => {
				let lpm_name = target_names.get("lpm").map(|s| s.as_str()).unwrap_or(name);

				// Rewrite tarball if LPM name differs from package.json name
				let lpm_tarball = if lpm_name != name {
					publish_common::rewrite_tarball_name(&tarball_data, name, lpm_name)?
				} else {
					tarball_data.clone()
				};

				let lpm_result = publish_to_lpm(
					client, project_dir, lpm_name, version, &readme,
					&lpm_tarball, &tarball_files, &version_data,
					&quality_result, json_output,
					&detected_ecosystem, &swift_manifest,
				)
				.await;

				let duration = start.elapsed();
				match lpm_result {
					Ok(resp) => {
						if !json_output {
							println!();
							output::success(&format!(
								"Published {}@{} → LPM ({:.1}s)",
								lpm_name.bold(), version.bold(), duration.as_secs_f64()
							));
							let owner_pkg = lpm_name.strip_prefix("@lpm.dev/").unwrap_or(lpm_name);
							if let Some((owner, pkg)) = owner_pkg.split_once('.') {
								eprintln!("  {}", format!("https://lpm.dev/{owner}/{pkg}").dimmed());
							}
							if let Some(warnings) = resp.get("warnings").and_then(|w| w.as_array()) {
								for w in warnings {
									if let Some(msg) = w.as_str() { output::warn(msg); }
								}
							}
							if let Some(ref qr) = quality_result {
								println!("  Quality: {}/{}", qr.score, qr.max_score);
							}
						}
						results.push(PublishResult {
							target: "lpm".into(), success: true, error: None, duration,
						});
					}
					Err(e) => {
						if !json_output {
							output::warn(&format!("LPM publish failed: {e}"));
						}
						results.push(PublishResult {
							target: "lpm".into(), success: false,
							error: Some(e.to_string()), duration,
						});
					}
				}
			}
			PublishTarget::Npm | PublishTarget::GitHub | PublishTarget::GitLab | PublishTarget::Custom(_) => {
				// Per-target name from pre-resolved map
				let npm_name_str = target_names.get(&target.key())
					.ok_or_else(|| LpmError::Registry(format!("no name resolved for {}", target.display_name())))?;

				// Resolve registry URL, token, display name, access, and tag per target
				let (registry_url, token_result, display) = match target {
					PublishTarget::Npm => (
						publish_npm::resolve_npm_registry(npm_config),
						auth::get_npm_token().ok_or_else(|| LpmError::Registry(
							"no npm token found. Run `lpm login --npm --token <token>` or set NPM_TOKEN env var.".into()
						)),
						"npm",
					),
					PublishTarget::GitHub => (
						"https://npm.pkg.github.com".to_string(),
						auth::get_github_token().ok_or_else(|| LpmError::Registry(
							"no GitHub token found. Run `lpm login --github --token <pat>` or set GITHUB_TOKEN env var.".into()
						)),
						"GitHub Packages",
					),
					PublishTarget::GitLab => {
						let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
						let project_id = gl_cfg
							.and_then(|c| c.project_id.as_deref())
							.ok_or_else(|| LpmError::Registry(
								"GitLab publish requires publish.gitlab.projectId in lpm.json".into()
							))?;
						let gitlab_host = gl_cfg
							.and_then(|c| c.registry.as_deref())
							.unwrap_or("https://gitlab.com");
						let url = format!(
							"{}/api/v4/projects/{}/packages/npm",
							gitlab_host.trim_end_matches('/'),
							urlencoding::encode(project_id)
						);
						(
							url,
							auth::get_gitlab_token().ok_or_else(|| LpmError::Registry(
								"no GitLab token found. Run `lpm login --gitlab --token <token>` or set GITLAB_TOKEN env var.".into()
							)),
							"GitLab Packages",
						)
					}
					PublishTarget::Custom(url) => (
						url.clone(),
						auth::get_custom_registry_token(url).ok_or_else(|| LpmError::Registry(
							format!("no token found for {url}. Run `lpm login --login-registry {url} --token <token>`.")
						)),
						"custom",
					),
					_ => unreachable!(),
				};

				let token = token_result?;

				// Per-target access: github config → gitlab config → npm config → default
				let npm_access = match target {
					PublishTarget::GitHub => {
						github_config.and_then(|c| c.access.clone())
							.unwrap_or_else(|| publish_npm::resolve_npm_access(npm_name_str, npm_config))
					}
					PublishTarget::GitLab => {
						gitlab_config.and_then(|c| c.access.clone())
							.unwrap_or_else(|| publish_npm::resolve_npm_access(npm_name_str, npm_config))
					}
					_ => publish_npm::resolve_npm_access(npm_name_str, npm_config),
				};
				let npm_tag = publish_npm::resolve_npm_tag(npm_config);

				// Check if OTP is needed: lpm.json config OR stored during login
				let registry_key_for_otp = match target {
					PublishTarget::Npm => "npmjs.org",
					PublishTarget::GitHub => "github.com",
					PublishTarget::GitLab => "gitlab.com",
					_ => "",
				};
				let otp_preempt = npm_config.and_then(|c| c.otp_required).unwrap_or(false)
					|| auth::is_otp_required(registry_key_for_otp);

				if !json_output {
					output::info(&format!(
						"Publishing {}@{} → {} ({})",
						npm_name_str.bold(), version, display, registry_url.dimmed()
					));
				}

				// Rewrite tarball package.json name if it differs from the target name.
				// npm validates that the tarball's package.json name matches the payload.
				let target_tarball = if npm_name_str != name {
					publish_common::rewrite_tarball_name(&tarball_data, name, npm_name_str)?
				} else {
					tarball_data.clone()
				};

				let npm_result = publish_npm::publish_to_npm(
					&token, npm_name_str, version, &version_data, &target_tarball,
					&npm_access, &npm_tag, &registry_url, otp_preempt, json_output, yes,
				)
				.await?;

				if npm_result.success {
					if !json_output {
						output::success(&format!(
							"Published {}@{} → {} ({:.1}s)",
							npm_name_str.bold(), version.bold(),
							display, npm_result.duration.as_secs_f64()
						));

						// Show package URL for known registries
						let package_url = match target {
							PublishTarget::Npm => {
								Some(format!("https://www.npmjs.com/package/{}", npm_name_str))
							}
							PublishTarget::GitHub => {
								// @owner/pkg → https://github.com/users/owner/packages/npm/package/pkg
								if let Some((scope, pkg)) = npm_name_str.strip_prefix('@').and_then(|s| s.split_once('/')) {
									Some(format!("https://github.com/users/{scope}/packages/npm/package/{pkg}"))
								} else {
									None
								}
							}
							PublishTarget::GitLab => {
								let gl_cfg = publish_config.and_then(|p| p.gitlab.as_ref());
								let host = gl_cfg.and_then(|c| c.registry.as_deref()).unwrap_or("https://gitlab.com");
								gl_cfg.and_then(|c| c.project_id.as_deref()).map(|pid| {
									format!("{host}/projects/{pid}/packages")
								})
							}
							_ => None,
						};
						if let Some(url) = package_url {
							eprintln!("  {}", url.dimmed());
						}
					}
				} else if !json_output {
					let err_msg = npm_result.error.as_deref().unwrap_or("unknown error");
					output::warn(&format!("{display} publish failed: {err_msg}"));
				}

				results.push(PublishResult {
					target: target.key(),
					success: npm_result.success,
					error: npm_result.error,
					duration: npm_result.duration,
				});
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
		println!();
		if any_failed {
			output::warn(&format!(
				"Published to {succeeded} of {} registries.",
				targets.len()
			));
			for (target, result) in targets.iter().zip(results.iter()) {
				if !result.success {
					eprintln!("  Retry: {} publish {}", "lpm".dimmed(), target.retry_flag());
				}
			}
		} else {
			output::success(&format!("Published to {} registries.", targets.len()));
		}
		println!();
	} else if !any_failed {
		println!();
	}

	if any_failed {
		Err(LpmError::Registry("one or more publish targets failed".into()))
	} else {
		Ok(())
	}
}

/// Publish to the LPM registry (existing behavior).
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
	if !registry_url.starts_with("https://") && !registry_url.starts_with("http://localhost") && !registry_url.starts_with("http://127.0.0.1") {
		return Err(LpmError::Registry(
			format!("refusing to publish over HTTP to {registry_url} — credentials require HTTPS")
		));
	}

	// S9: Warn when publishing to a non-default LPM registry
	if !registry_url.starts_with("https://lpm.dev") && !registry_url.starts_with("http://localhost") && !registry_url.starts_with("http://127.0.0.1") {
		if !json_output {
			eprintln!();
			eprintln!(
				"  {} Publishing to non-default registry: {}",
				"⚠".yellow().bold(),
				registry_url.bold()
			);
		}
	}

	// Verify token has publish scope
	let whoami = client.whoami().await.map_err(|e| {
		LpmError::Registry(format!("authentication failed: {e}"))
	})?;

	let username = whoami
		.profile_username
		.as_deref()
		.or(whoami.username.as_deref())
		.unwrap_or("unknown");

	if !json_output {
		output::info(&format!("Publishing as {}", username.bold()));
	}

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
		lpm_version["_qualityChecks"] = serde_json::to_value(&qr.checks)
			.unwrap_or(serde_json::json!(null));
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
	if lpm_config_path.exists() {
		if let Ok(config_str) = std::fs::read_to_string(&lpm_config_path) {
			if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str) {
				lpm_version["_lpmConfig"] = config;
			}
		}
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
		output::warn(&format!(
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

	if !json_output {
		output::info("Uploading...");
	}

	let encoded_name = urlencoding::encode(name);
	client
		.publish_package(&encoded_name, &payload, otp_code.as_deref(), tarball_data.len())
		.await
}

// ---------------------------------------------------------------------------
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

		let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
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
		} else if path.extension().map(|e| e == "md").unwrap_or(false) {
			f(&path);
		}
	}
}

/// Ensure ".lpm/skills" is present in the `files` array in package.json.
///
/// IMPORTANT: Only `.lpm/skills` is added — NOT `.lpm` broadly. The `.lpm/`
/// directory also contains certs, webhook logs, install hashes, and other
/// project-local data that must NEVER be published in the tarball.
fn ensure_lpm_in_files(
	pkg_json_path: &Path,
	pkg_json: &serde_json::Value,
) -> Result<(), LpmError> {
	if let Some(files) = pkg_json.get("files").and_then(|f| f.as_array()) {
		let has_skills = files.iter().any(|f| {
			let s = f.as_str().unwrap_or("");
			s == ".lpm/skills" || s == ".lpm/skills/" || s == ".lpm"
		});
		if !has_skills {
			let content = std::fs::read_to_string(pkg_json_path)?;

			if let Some(files_pos) = content.find("\"files\"") {
				if let Some(bracket_offset) = content[files_pos..].find('[') {
					let insert_pos = files_pos + bracket_offset + 1;
					let mut new_content = String::with_capacity(content.len() + 32);
					new_content.push_str(&content[..insert_pos]);
					let after_bracket = &content[insert_pos..];
					let indent = after_bracket
						.find('"')
						.map(|i| {
							let segment = &after_bracket[..i];
							segment
								.rfind('\n')
								.map(|nl| &segment[nl + 1..])
								.unwrap_or(segment)
						})
						.unwrap_or("    ");
					new_content.push('\n');
					new_content.push_str(indent);
					new_content.push_str("\".lpm/skills\",");
					new_content.push_str(&content[insert_pos..]);

					let tmp = pkg_json_path.with_extension("json.tmp");
					std::fs::write(&tmp, &new_content)?;
					std::fs::rename(&tmp, pkg_json_path)?;

					output::warn(
						"Added \".lpm/skills\" to package.json \"files\" — skills would be excluded otherwise",
					);
				}
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

/// Print the quality score summary line.
fn print_quality_summary(result: &quality::QualityResult) {
	let tier = match result.score {
		90..=100 => "Excellent".green().to_string(),
		70..=89 => "Good".blue().to_string(),
		50..=69 => "Fair".yellow().to_string(),
		_ => "Needs Work".dimmed().to_string(),
	};
	output::info(&format!(
		"Quality: {}/{} ({})",
		result.score.to_string().bold(),
		result.max_score,
		tier,
	));
}

/// Print the detailed quality checks table.
fn print_quality_checks(result: &quality::QualityResult) {
	println!();
	let mut categories: std::collections::BTreeMap<&str, Vec<&quality::QualityCheck>> =
		std::collections::BTreeMap::new();
	for check in &result.checks {
		categories
			.entry(&check.category)
			.or_default()
			.push(check);
	}

	for (category, checks) in &categories {
		let cat_score: u32 = checks.iter().map(|c| c.points).sum();
		let cat_max: u32 = checks.iter().map(|c| c.max_points).sum();
		println!("  {} ({}/{})", category.bold(), cat_score, cat_max);

		for check in checks {
			let icon = if check.server_only {
				"~".dimmed().to_string()
			} else if check.passed {
				"✔".green().to_string()
			} else {
				"✖".red().to_string()
			};
			let pts_str = format!("{}/{}", check.points, check.max_points);
			let pts = pts_str.dimmed();
			print!("    {icon} {} {pts}", check.id);
			if !check.passed && !check.server_only {
				let tip = format!("← +{} pts", check.max_points);
				print!(" {}", tip.dimmed());
			}
			if let Some(detail) = &check.detail {
				print!(" {}", detail.dimmed());
			}
			println!();
		}
	}
	println!();
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
					let product_type = p.get("type").map(|t| {
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
					}).unwrap_or_else(|| "library".into());

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
									if let Some(by_name) = d.get("byName").and_then(|v| v.as_array()) {
										return serde_json::json!({
											"type": "byName",
											"name": by_name.first()
												.and_then(|v| v.as_str())
												.unwrap_or_default(),
										});
									}
									// Raw: { product: ["Bar", ...] }
									if let Some(product) = d.get("product").and_then(|v| v.as_array()) {
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
		assert!(result.contains("\t\"src/\""), "should preserve tab indentation");
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
		let targets = resolve_targets(true, false, false, false, None, None);
		assert_eq!(targets, vec![PublishTarget::Npm]);

		// --lpm only
		let targets = resolve_targets(false, true, false, false, None, None);
		assert_eq!(targets, vec![PublishTarget::Lpm]);

		// --npm --lpm
		let targets = resolve_targets(true, true, false, false, None, None);
		assert_eq!(targets, vec![PublishTarget::Lpm, PublishTarget::Npm]);

		// --github
		let targets = resolve_targets(false, false, true, false, None, None);
		assert_eq!(targets, vec![PublishTarget::GitHub]);

		// --registry <url>
		let targets = resolve_targets(false, false, false, false, Some("https://npm.corp.com"), None);
		assert_eq!(targets, vec![PublishTarget::Custom("https://npm.corp.com".into())]);
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
		let targets = resolve_targets(false, false, false, false, None, Some(&config));
		assert_eq!(targets, vec![PublishTarget::Npm, PublishTarget::Lpm]);
	}

	#[test]
	fn resolve_targets_default_lpm() {
		let targets = resolve_targets(false, false, false, false, None, None);
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
		let targets = resolve_targets(true, false, false, false, None, Some(&config));
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
		let targets = resolve_targets(false, false, false, false, None, Some(&config));
		assert_eq!(targets, vec![
			PublishTarget::Lpm,
			PublishTarget::Custom("https://npm.corp.com".into()),
		]);
	}

	#[test]
	fn publish_result_display() {
		assert_eq!(PublishTarget::Lpm.display_name(), "LPM");
		assert_eq!(PublishTarget::Npm.display_name(), "npm");
		assert_eq!(PublishTarget::GitHub.display_name(), "GitHub Packages");
		assert_eq!(PublishTarget::Custom("https://x.com".into()).key(), "https://x.com");
		assert_eq!(PublishTarget::Npm.retry_flag(), "--npm");
		assert_eq!(PublishTarget::GitHub.retry_flag(), "--github");
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
		assert_eq!(result["dependencies"][0]["identity"], "swift-argument-parser");
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
}
