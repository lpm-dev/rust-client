use crate::output;
use crate::prompt::prompt_err;
#[cfg(test)]
use crate::upgrade_engine::PeerViolation;
use crate::upgrade_engine::{self, PatchInvalidation, PeerImpact, SemverClass};
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use lpm_semver::Version;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;

// ── Mode resolution ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedMode {
    Interactive,
    NonInteractive,
}

fn resolve_mode(
    interactive: bool,
    yes: bool,
    json_output: bool,
    is_tty: bool,
) -> Result<ResolvedMode, LpmError> {
    if interactive && yes {
        return Err(LpmError::Script(
            "`-i` and `-y` are mutually exclusive \
			 (one forces interactive, the other forces non-interactive)"
                .into(),
        ));
    }
    if interactive && json_output {
        return Err(LpmError::Script(
            "`-i` cannot be combined with `--json` — \
			 interactive prompts cannot render structured output"
                .into(),
        ));
    }
    if yes || json_output {
        return Ok(ResolvedMode::NonInteractive);
    }
    if interactive {
        return Ok(ResolvedMode::Interactive);
    }
    if is_tty {
        Ok(ResolvedMode::Interactive)
    } else {
        Ok(ResolvedMode::NonInteractive)
    }
}

fn validate_major_for_mode(major: bool, mode: ResolvedMode) -> Result<(), LpmError> {
    if major && mode == ResolvedMode::Interactive {
        return Err(LpmError::Script(
            "`--major` cannot be combined with interactive mode. \
			 In interactive mode, major upgrades appear as separate rows \
			 alongside the safe within-major option — toggle them on individually. \
			 Pass `-y --major` for batch behavior, or just `lpm upgrade` \
			 and select the MAJOR rows you want."
                .into(),
        ));
    }
    Ok(())
}

// ── Candidate types ─────────────────────────────────────────────────

/// Distinguishes the two rows a single package can produce in interactive
/// mode (D-design-1 dual-row model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    WithinMajor,
    AbsoluteLatest,
}

/// Phase 7 enriched candidate — drives both the interactive multiselect
/// and the JSON output.
#[derive(Clone)]
struct EnrichedCandidate {
    name: String,
    from: String,
    current_range: String,
    new_range: String,
    to: String,
    is_dev: bool,
    target_kind: TargetKind,
    semver_class: SemverClass,
    has_install_scripts: bool,
    peer_impact: PeerImpact,
    patch_invalidation: Option<PatchInvalidation>,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Upgrade outdated LPM dependencies to their latest versions.
///
/// Phase 32 Phase 7: TTY-aware interactive mode with enrichment.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    major: bool,
    dry_run: bool,
    interactive: bool,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound("no package.json found".into()));
    }

    // Read file once, parse as Value for deps extraction AND as typed
    // PackageJson for the patches map.
    let original_content = std::fs::read_to_string(&pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
    let doc: serde_json::Value = serde_json::from_str(&original_content)
        .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

    let pkg_typed = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    let patched_deps = pkg_typed
        .lpm
        .as_ref()
        .map(|c| c.patched_dependencies.clone())
        .unwrap_or_default();

    // Resolve mode + validate flag combinations
    let is_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mode = resolve_mode(interactive, yes, json_output, is_tty)?;
    validate_major_for_mode(major, mode)?;

    // Extract deps, filter to @lpm.dev/, parse names upfront
    let all_deps = extract_deps_from_value(&doc);
    let lpm_deps: Vec<(String, String, bool, PackageName)> = all_deps
        .into_iter()
        .filter_map(|(name, range, is_dev)| {
            if !name.starts_with("@lpm.dev/") {
                return None;
            }
            let pkg_name = PackageName::parse(&name).ok()?;
            Some((name, range, is_dev, pkg_name))
        })
        .collect();

    // Read lockfile ONCE
    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(&lockfile_path).ok()
    } else {
        None
    };

    // Fetch all metadata concurrently
    let fetch_futures: Vec<_> = lpm_deps
        .iter()
        .map(|(name, range, is_dev, pkg_name)| async move {
            let result = client.get_package_metadata(pkg_name).await;
            (name.as_str(), range.as_str(), *is_dev, result)
        })
        .collect();
    let fetch_results = futures::future::join_all(fetch_futures).await;

    let mut candidates: Vec<EnrichedCandidate> = Vec::new();
    let mut fetch_errors: usize = 0;

    for (name, current_range, is_dev, metadata_result) in fetch_results {
        let metadata = match metadata_result {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("failed to fetch metadata for {}: {}", name, e);
                fetch_errors += 1;
                continue;
            }
        };

        let latest = match metadata.latest_version_tag() {
            Some(v) => v.to_string(),
            None => continue,
        };

        if !is_valid_version_string(&latest) {
            tracing::warn!(
                "skipping {}: registry returned invalid version string {:?}",
                name,
                latest
            );
            continue;
        }

        let available_versions: Vec<String> = metadata.versions.keys().cloned().collect();

        let installed_ver = lockfile
            .as_ref()
            .and_then(|lf| lf.find_package(name).map(|p| p.version.as_str()));

        // Build enrichment data from the target version's metadata.
        // We use the LATEST version's metadata for enrichment since that's
        // what the user will get post-upgrade.
        let enrich = |target_version: &str| -> (bool, PeerImpact, Option<PatchInvalidation>) {
            let meta = metadata.version(target_version);
            let has_scripts = meta
                .map(upgrade_engine::target_has_install_scripts)
                .unwrap_or(false);
            let peer_deps = meta
                .map(|m| m.peer_dependencies.clone())
                .unwrap_or_default();
            let peer_impact = upgrade_engine::compute_peer_impact(&peer_deps, lockfile.as_ref());
            let from_ver = installed_ver.unwrap_or("0.0.0");
            let patch_inv = upgrade_engine::detect_patch_invalidation(
                &patched_deps,
                name,
                from_ver,
                target_version,
            );
            (has_scripts, peer_impact, patch_inv)
        };

        match mode {
            ResolvedMode::NonInteractive => {
                // Today's behavior: single candidate per dep
                let (target_version, new_range) =
                    compute_upgrade(current_range, &latest, &available_versions, major);
                let target_version = match target_version {
                    Some(v) => v,
                    None => continue,
                };

                let should_skip = if let Some(installed) = installed_ver {
                    installed == target_version
                } else {
                    current_range == new_range
                };
                if should_skip {
                    continue;
                }

                let from = installed_ver
                    .map(str::to_string)
                    .unwrap_or_else(|| version_from_range(current_range));
                let semver_class = upgrade_engine::classify_semver_change(&from, &target_version);
                let (has_scripts, peer_impact, patch_inv) = enrich(&target_version);

                candidates.push(EnrichedCandidate {
                    name: name.to_string(),
                    from,
                    current_range: current_range.to_string(),
                    new_range,
                    to: target_version,
                    is_dev,
                    target_kind: if major {
                        TargetKind::AbsoluteLatest
                    } else {
                        TargetKind::WithinMajor
                    },
                    semver_class,
                    has_install_scripts: has_scripts,
                    peer_impact,
                    patch_invalidation: patch_inv,
                });
            }
            ResolvedMode::Interactive => {
                // D-design-1 dual-row: compute within-major AND absolute-latest
                let (within_target, within_range) =
                    compute_upgrade(current_range, &latest, &available_versions, false);
                let (abs_target, abs_range) =
                    compute_upgrade(current_range, &latest, &available_versions, true);

                let from = installed_ver
                    .map(str::to_string)
                    .unwrap_or_else(|| version_from_range(current_range));

                // Emit within-major row if it's a real upgrade
                if let Some(ref wt) = within_target {
                    let should_skip = if let Some(installed) = installed_ver {
                        installed == wt.as_str()
                    } else {
                        current_range == within_range
                    };
                    if !should_skip {
                        let semver_class = upgrade_engine::classify_semver_change(&from, wt);
                        let (has_scripts, peer_impact, patch_inv) = enrich(wt);
                        candidates.push(EnrichedCandidate {
                            name: name.to_string(),
                            from: from.clone(),
                            current_range: current_range.to_string(),
                            new_range: within_range.clone(),
                            to: wt.clone(),
                            is_dev,
                            target_kind: TargetKind::WithinMajor,
                            semver_class,
                            has_install_scripts: has_scripts,
                            peer_impact,
                            patch_invalidation: patch_inv,
                        });
                    }
                }

                // Emit absolute-latest row if it differs from the within-major
                if let Some(ref at) = abs_target {
                    let same_as_within = within_target.as_deref() == Some(at.as_str());
                    if !same_as_within {
                        let should_skip = if let Some(installed) = installed_ver {
                            installed == at.as_str()
                        } else {
                            current_range == abs_range
                        };
                        if !should_skip {
                            let semver_class = upgrade_engine::classify_semver_change(&from, at);
                            let (has_scripts, peer_impact, patch_inv) = enrich(at);
                            candidates.push(EnrichedCandidate {
                                name: name.to_string(),
                                from: from.clone(),
                                current_range: current_range.to_string(),
                                new_range: abs_range.clone(),
                                to: at.clone(),
                                is_dev,
                                target_kind: TargetKind::AbsoluteLatest,
                                semver_class,
                                has_install_scripts: has_scripts,
                                peer_impact,
                                patch_invalidation: patch_inv,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort for deterministic output
    candidates.sort_by(|a, b| {
        a.name.cmp(&b.name).then(a.to.cmp(&b.to)) // within-major first since it's lower
    });

    // Warn about fetch errors
    if fetch_errors > 0 && !json_output {
        output::warn(&format!(
            "Could not check {} package(s) (network errors)",
            fetch_errors
        ));
    }

    if candidates.is_empty() {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "upgraded": 0,
                "packages": [],
                "fetch_errors": fetch_errors,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::success("All LPM packages are up to date");
        }
        return Ok(());
    }

    // ── Selection ───────────────────────────────────────────────────

    let selected: Vec<EnrichedCandidate> = match mode {
        ResolvedMode::NonInteractive => candidates.clone(),
        ResolvedMode::Interactive => {
            let selection = select_candidates_interactively(&candidates)?;
            if selection.is_empty() {
                output::info("No packages selected. package.json is unchanged.");
                return Ok(());
            }
            selection
        }
    };

    // Deduplicate: if both within-major and absolute-latest rows were
    // selected for the same package, take the highest target version.
    let deduped = deduplicate_by_highest_target(&selected);

    // ── Display + dry-run gate ──────────────────────────────────────

    if json_output {
        let pkgs: Vec<serde_json::Value> = deduped.iter().map(candidate_to_json).collect();
        let json = serde_json::json!({
            "success": true,
            "dry_run": dry_run,
            "upgraded": deduped.len(),
            "packages": pkgs,
            "fetch_errors": fetch_errors,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
        if dry_run {
            return Ok(());
        }
    } else {
        println!();
        for u in &deduped {
            let dev_tag = if u.is_dev { " (dev)" } else { "" };
            let class_label = format_class_label(u.semver_class);
            let hint = format_candidate_hint(u);
            let hint_suffix = if hint.is_empty() {
                String::new()
            } else {
                format!("  {}", hint.dimmed())
            };
            println!(
                "  {} {} → {} {}{}{}",
                u.name.bold(),
                u.from.dimmed(),
                format_version_colored(&u.to, u.semver_class),
                class_label,
                dev_tag.dimmed(),
                hint_suffix,
            );
        }
        println!();

        if dry_run {
            output::info(&format!(
                "{} package(s) would be upgraded (dry run)",
                deduped.len()
            ));
            return Ok(());
        }
    }

    // ── Mutate package.json ─────────────────────────────────────────

    let mut updated_content = original_content.clone();
    for u in &deduped {
        updated_content = updated_content.replace(
            &format!("\"{}\": \"{}\"", u.name, u.current_range),
            &format!("\"{}\": \"{}\"", u.name, u.new_range),
        );
    }

    let tmp_path = pkg_json_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &updated_content)
        .map_err(|e| LpmError::Script(format!("failed to write temp package.json: {e}")))?;
    std::fs::rename(&tmp_path, &pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to rename temp package.json: {e}")))?;

    if !json_output {
        output::success(&format!(
            "updated {} package(s) in package.json",
            deduped.len()
        ));
    }

    // ── Run install with backup-and-restore ──────────────────────────

    if !json_output {
        output::info("running lpm install...");
    }

    let install_result = crate::commands::install::run_with_options(
        client,
        project_dir,
        json_output,
        false, // offline
        false, // force
        false, // allow_new
        None,  // linker_override
        false, // no_skills
        false, // no_editor_setup
        false, // no_security_summary
        false, // auto_build
        None,  // target_set
        None,  // direct_versions_out
    )
    .await;

    if let Err(e) = install_result {
        if let Err(restore_err) = std::fs::write(&pkg_json_path, &original_content) {
            tracing::error!(
                "failed to restore package.json after install failure: {}",
                restore_err
            );
        } else if !json_output {
            output::warn("install failed — restored original package.json");
        }
        return Err(e);
    }

    if !json_output {
        output::success(&format!("{} package(s) upgraded", deduped.len()));
    }

    Ok(())
}

// ── Interactive multiselect ─────────────────────────────────────────

fn select_candidates_interactively(
    candidates: &[EnrichedCandidate],
) -> Result<Vec<EnrichedCandidate>, LpmError> {
    println!();
    let pkg_count = {
        let mut names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        names.dedup();
        names.len()
    };
    let target_count = candidates.len();
    if target_count == pkg_count {
        output::info(&format!("{pkg_count} package(s) can be upgraded."));
    } else {
        output::info(&format!(
            "{target_count} upgrade targets across {pkg_count} packages."
        ));
    }
    println!();

    let mut ms =
        cliclack::multiselect("Select packages to upgrade  (space=toggle  a=all  enter=confirm)");

    let initial_indices: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            upgrade_engine::default_pre_check(
                c.semver_class,
                c.has_install_scripts,
                &c.peer_impact,
                c.patch_invalidation.as_ref(),
            )
        })
        .map(|(i, _)| i)
        .collect();

    for (i, c) in candidates.iter().enumerate() {
        let label = format_candidate_row_for_tui(c);
        let hint = format_candidate_hint(c);
        ms = ms.item(i, label, hint);
    }
    ms = ms.initial_values(initial_indices);

    let chosen_indices: Vec<usize> = ms.interact().map_err(prompt_err)?;

    let selected: Vec<EnrichedCandidate> = chosen_indices
        .into_iter()
        .filter_map(|i| candidates.get(i).cloned())
        .collect();
    Ok(selected)
}

// ── Deduplication ───────────────────────────────────────────────────

/// When both the within-major and absolute-latest rows are selected for
/// the same package, keep only the one with the higher target version.
fn deduplicate_by_highest_target(selected: &[EnrichedCandidate]) -> Vec<EnrichedCandidate> {
    let mut best: HashMap<String, EnrichedCandidate> = HashMap::new();
    for c in selected {
        let key = format!("{}|{}", c.name, c.current_range);
        let replace = match best.get(&key) {
            None => true,
            Some(existing) => {
                // Higher version wins. If both parse, compare structurally;
                // if either fails to parse, compare lexicographically.
                match (Version::parse(&c.to), Version::parse(&existing.to)) {
                    (Ok(a), Ok(b)) => a > b,
                    _ => c.to > existing.to,
                }
            }
        };
        if replace {
            best.insert(key, c.clone());
        }
    }
    let mut result: Vec<EnrichedCandidate> = best.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_candidate_row_for_tui(c: &EnrichedCandidate) -> String {
    let dev_tag = if c.is_dev { " (dev)" } else { "" };
    let class_label = format_class_label(c.semver_class);
    let kind_tag = match c.target_kind {
        TargetKind::AbsoluteLatest => " (latest)",
        TargetKind::WithinMajor => "",
    };
    format!(
        "{:<40} {} → {} {}{}{}",
        c.name, c.from, c.to, class_label, kind_tag, dev_tag,
    )
}

fn format_candidate_hint(c: &EnrichedCandidate) -> String {
    let mut parts: Vec<String> = Vec::new();

    if c.has_install_scripts {
        parts.push("[!] install scripts (will need approve-builds)".into());
    }

    if !c.peer_impact.ok {
        let mut peer_parts: Vec<String> = Vec::new();
        for v in &c.peer_impact.violations {
            peer_parts.push(format!("{}={}≠{}", v.name, v.have, v.want));
        }
        for m in &c.peer_impact.missing {
            peer_parts.push(format!("{} missing", m));
        }
        if !peer_parts.is_empty() {
            parts.push(format!(
                "peer: {} (current lockfile)",
                peer_parts.join(", ")
            ));
        }
    }

    if let Some(ref inv) = c.patch_invalidation {
        parts.push(format!("orphans patch {}", inv.key));
    }

    parts.join("  •  ")
}

fn format_class_label(class: SemverClass) -> String {
    match class {
        SemverClass::Patch => "patch".green().to_string(),
        SemverClass::Minor => "minor".yellow().to_string(),
        SemverClass::Major => "MAJOR".red().to_string(),
        SemverClass::Prerelease => "pre".dimmed().to_string(),
        SemverClass::Unknown => "?".dimmed().to_string(),
    }
}

fn format_version_colored(version: &str, class: SemverClass) -> String {
    match class {
        SemverClass::Patch => version.green().to_string(),
        SemverClass::Minor => version.yellow().to_string(),
        SemverClass::Major => version.red().to_string(),
        SemverClass::Prerelease => version.dimmed().to_string(),
        SemverClass::Unknown => version.dimmed().to_string(),
    }
}

fn candidate_to_json(c: &EnrichedCandidate) -> serde_json::Value {
    serde_json::json!({
        "name": c.name,
        "from": c.from,
        "to": c.to,
        "new_range": c.new_range,
        "is_dev": c.is_dev,
        "semver_class": c.semver_class,
        "has_install_scripts": c.has_install_scripts,
        "peer_impact": c.peer_impact,
        "patch_invalidation": c.patch_invalidation,
    })
}

// ── Preserved helpers from the original upgrade.rs ──────────────────

/// Extract dependencies and devDependencies from a parsed JSON Value.
fn extract_deps_from_value(doc: &serde_json::Value) -> Vec<(String, String, bool)> {
    let mut deps = Vec::new();
    if let Some(obj) = doc.get("dependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), false));
            }
        }
    }
    if let Some(obj) = doc.get("devDependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), true));
            }
        }
    }
    deps
}

/// Compute the upgrade target version and new range.
///
/// In default (non-major) mode, stays within the current major version.
/// In major mode, uses the absolute latest.
fn compute_upgrade(
    current_range: &str,
    latest: &str,
    available_versions: &[String],
    major: bool,
) -> (Option<String>, String) {
    let prefix = if current_range.starts_with('^') {
        "^"
    } else if current_range.starts_with('~') {
        "~"
    } else {
        ""
    };

    if major {
        let new_range = format!("{prefix}{latest}");
        return (Some(latest.to_string()), new_range);
    }

    let range_body = current_range.trim_start_matches(['^', '~']);
    let current_major = range_body
        .split('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok());

    let current_major = match current_major {
        Some(m) => m,
        None => {
            let new_range = format!("{prefix}{latest}");
            return (Some(latest.to_string()), new_range);
        }
    };

    let mut same_major_versions: Vec<Version> = available_versions
        .iter()
        .filter_map(|v| Version::parse(v).ok())
        .filter(|v| v.major() == current_major && !v.is_prerelease())
        .collect();

    if same_major_versions.is_empty() {
        return (None, current_range.to_string());
    }

    lpm_semver::sort_versions(&mut same_major_versions);
    let best = same_major_versions.last().unwrap();
    let best_str = best.to_string();
    let new_range = format!("{prefix}{best_str}");

    (Some(best_str), new_range)
}

/// Extract a best-effort version string from a range like `"^1.2.0"`.
/// Strips `^`, `~`, `>=`, `=` prefixes and returns the body. If the
/// body doesn't look like a version (e.g., `"*"`), returns it as-is
/// — the caller's `classify_semver_change` will return `Unknown`.
///
/// **D-impl-1 audit fix:** when no lockfile exists, `installed_ver` is
/// `None` and the old code used `"?"` as the "from" version, which
/// `classify_semver_change` can't parse → `Unknown` → patches/minors
/// don't get pre-checked. This helper extracts a real version from
/// the manifest range so classification works correctly even without
/// a lockfile.
fn version_from_range(range: &str) -> String {
    range
        .trim_start_matches(['^', '~', '>', '<', '='])
        .trim()
        .to_string()
}

fn is_valid_version_string(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    v.chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '+')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compute_upgrade (preserved from original) ───────────────────

    #[test]
    fn default_mode_stays_within_major() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("^1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "^1.5.0");
    }

    #[test]
    fn major_mode_jumps_to_latest() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("^1.2.0", "2.0.0", &available, true);
        assert_eq!(target, Some("2.0.0".to_string()));
        assert_eq!(new_range, "^2.0.0");
    }

    #[test]
    fn default_mode_same_major_as_latest() {
        let available = vec!["2.0.0".into(), "2.1.0".into(), "2.3.0".into()];
        let (target, new_range) = compute_upgrade("^2.0.0", "2.3.0", &available, false);
        assert_eq!(target, Some("2.3.0".to_string()));
        assert_eq!(new_range, "^2.3.0");
    }

    #[test]
    fn default_mode_tilde_prefix_preserved() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("~1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "~1.5.0");
    }

    #[test]
    fn default_mode_no_prefix() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "1.5.0");
    }

    #[test]
    fn default_mode_skips_prereleases() {
        let available = vec![
            "1.2.0".into(),
            "1.6.0-beta.1".into(),
            "1.5.0".into(),
            "2.0.0".into(),
        ];
        let (target, _) = compute_upgrade("^1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
    }

    // ── resolve_mode ────────────────────────────────────────────────

    #[test]
    fn resolve_mode_default_tty_is_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, true).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_default_no_tty_is_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, false).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_yes_forces_non_interactive_in_tty() {
        assert_eq!(
            resolve_mode(false, true, false, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_forces_interactive_no_tty() {
        assert_eq!(
            resolve_mode(true, false, false, false).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_json_forces_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, true, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_and_yes_is_hard_error() {
        assert!(resolve_mode(true, true, false, true).is_err());
    }

    #[test]
    fn resolve_mode_interactive_and_json_is_hard_error() {
        assert!(resolve_mode(true, false, true, false).is_err());
    }

    #[test]
    fn validate_major_for_mode_rejects_major_in_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::Interactive).is_err());
    }

    #[test]
    fn validate_major_for_mode_accepts_major_in_non_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::NonInteractive).is_ok());
    }

    #[test]
    fn validate_major_for_mode_accepts_no_major_in_either() {
        assert!(validate_major_for_mode(false, ResolvedMode::Interactive).is_ok());
        assert!(validate_major_for_mode(false, ResolvedMode::NonInteractive).is_ok());
    }

    // ── formatting helpers ──────────────────────────────────────────

    fn make_candidate(
        class: SemverClass,
        has_scripts: bool,
        peer_ok: bool,
        has_patch_inv: bool,
    ) -> EnrichedCandidate {
        let peer_impact = if peer_ok {
            PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            }
        } else {
            PeerImpact {
                ok: false,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![PeerViolation {
                    name: "react".into(),
                    have: "17.0.2".into(),
                    want: "^18.0.0".into(),
                }],
            }
        };
        let patch_invalidation = if has_patch_inv {
            Some(PatchInvalidation {
                key: "lodash@4.17.20".into(),
                patch_path: "patches/lodash.patch".into(),
                from_version: "4.17.20".into(),
                to_version: "4.17.21".into(),
            })
        } else {
            None
        };
        EnrichedCandidate {
            name: "@lpm.dev/test.pkg".into(),
            from: "1.2.0".into(),
            current_range: "^1.2.0".into(),
            new_range: "^1.2.4".into(),
            to: "1.2.4".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: class,
            has_install_scripts: has_scripts,
            peer_impact,
            patch_invalidation,
        }
    }

    #[test]
    fn format_row_includes_class_label() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let row = format_candidate_row_for_tui(&c);
        assert!(row.contains("1.2.0"));
        assert!(row.contains("1.2.4"));
    }

    #[test]
    fn format_hint_marks_install_scripts() {
        let c = make_candidate(SemverClass::Patch, true, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("[!]"));
        assert!(hint.contains("install scripts"));
    }

    #[test]
    fn format_hint_marks_peer_violation() {
        let c = make_candidate(SemverClass::Minor, false, false, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("react"));
        assert!(hint.contains("current lockfile"));
    }

    #[test]
    fn format_hint_marks_patch_invalidation() {
        let c = make_candidate(SemverClass::Minor, false, true, true);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("orphans patch"));
        assert!(hint.contains("lodash@4.17.20"));
    }

    #[test]
    fn format_hint_is_empty_when_clean() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.is_empty());
    }

    // ── dual-row model (D-design-1) ─────────────────────────────────

    #[test]
    fn deduplicate_takes_major_when_both_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
        };
        let major = EnrichedCandidate {
            to: "4.0.0".into(),
            new_range: "^4.0.0".into(),
            target_kind: TargetKind::AbsoluteLatest,
            semver_class: SemverClass::Major,
            ..minor.clone()
        };
        let deduped = deduplicate_by_highest_target(&[minor, major]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "4.0.0");
    }

    #[test]
    fn deduplicate_keeps_minor_when_only_minor_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
        };
        let deduped = deduplicate_by_highest_target(&[minor]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "3.9.0");
    }

    // ── extract_deps_from_value (preserved) ─────────────────────────

    #[test]
    fn extract_deps_from_json_value() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"dependencies":{"foo":"^1.0.0"},"devDependencies":{"bar":"~2.0.0"}}"#,
        )
        .unwrap();
        let deps = extract_deps_from_value(&doc);
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|(n, r, d)| n == "foo" && r == "^1.0.0" && !d)
        );
        assert!(
            deps.iter()
                .any(|(n, r, d)| n == "bar" && r == "~2.0.0" && *d)
        );
    }

    // ── version validation (preserved) ──────────────────────────────

    #[test]
    fn valid_version_strings() {
        assert!(is_valid_version_string("1.5.0"));
        assert!(is_valid_version_string("2.0.0-rc.1"));
        assert!(is_valid_version_string("1.0.0-beta.2"));
        assert!(is_valid_version_string("1.0.0+build.123"));
    }

    #[test]
    fn invalid_version_strings() {
        assert!(!is_valid_version_string(""));
        assert!(!is_valid_version_string("1.0.0 && rm -rf /"));
        assert!(!is_valid_version_string("1.0.0; echo pwned"));
        assert!(!is_valid_version_string("$(whoami)"));
    }

    // ── D-impl-1: no-lockfile classification regression ─────────────
    // Bug: when no lockfile exists, `from` was "?" → classify returned
    // Unknown → patches/minors not pre-checked. Contract: the class
    // must be derived from the range body, not from "?".

    #[test]
    fn version_from_range_strips_caret() {
        assert_eq!(version_from_range("^1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_tilde() {
        assert_eq!(version_from_range("~1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_gte() {
        assert_eq!(version_from_range(">=1.0.0"), "1.0.0");
    }

    #[test]
    fn version_from_range_no_prefix() {
        assert_eq!(version_from_range("1.2.0"), "1.2.0");
    }

    #[test]
    fn no_lockfile_patch_upgrade_classifies_as_patch_not_unknown() {
        // The user-visible contract: ^1.0.0 → 1.0.1 is a patch upgrade
        // even when no lockfile is present. The "from" should be derived
        // from the range body "1.0.0", not "?".
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.0.1");
        assert_eq!(
            class,
            SemverClass::Patch,
            "no-lockfile ^1.0.0 → 1.0.1 must classify as Patch, not Unknown"
        );
        assert!(
            class.default_checked(),
            "Patch must be default-checked in the multiselect"
        );
    }

    #[test]
    fn no_lockfile_minor_upgrade_classifies_as_minor_not_unknown() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.5.0");
        assert_eq!(
            class,
            SemverClass::Minor,
            "no-lockfile ^1.0.0 → 1.5.0 must classify as Minor, not Unknown"
        );
        assert!(class.default_checked());
    }

    #[test]
    fn no_lockfile_major_upgrade_classifies_as_major() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "2.0.0");
        assert_eq!(class, SemverClass::Major);
        assert!(!class.default_checked());
    }
}
