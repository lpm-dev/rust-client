use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
struct UninstallResult {
    removed: Vec<String>,
    not_found: Vec<String>,
}

fn remove_from_manifest(
    doc: &mut Value,
    packages: &[String],
    json_output: bool,
) -> UninstallResult {
    let mut removed = Vec::new();
    let mut not_found = Vec::new();

    for name in packages {
        let mut found = false;

        for key in &["dependencies", "devDependencies"] {
            if let Some(deps) = doc.get_mut(*key)
                && let Some(obj) = deps.as_object_mut()
                && obj.remove(name).is_some()
            {
                found = true;
                if !json_output {
                    output::info(&format!("Removed {} from {}", name.bold(), key));
                }
            }
        }

        if found {
            removed.push(name.clone());
        } else {
            not_found.push(name.clone());
        }
    }

    UninstallResult { removed, not_found }
}

fn cleanup_removed_packages(project_dir: &Path, removed: &[String]) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if lockfile_path.exists() {
        std::fs::remove_file(&lockfile_path)?;
    }

    let node_modules = project_dir.join("node_modules");
    for name in removed {
        let link = node_modules.join(name);
        if link.symlink_metadata().is_ok()
            && (link.is_dir()
                || link
                    .symlink_metadata()
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false))
        {
            #[cfg(unix)]
            std::fs::remove_file(&link)
                .or_else(|_| std::fs::remove_dir(&link))
                .ok();
            #[cfg(windows)]
            std::fs::remove_dir(&link).ok();
        }
    }

    Ok(())
}

/// Phase 32 Phase 2 M3: per-manifest uninstall helper.
///
/// Reads `pkg_json_path`, removes the requested package entries from
/// `dependencies`/`devDependencies`, and writes the manifest back atomically.
/// Does NOT touch the lockfile or `node_modules` — those are the caller's
/// job and happen ONCE at the install root, not per-member.
fn uninstall_from_manifest(
    pkg_json_path: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<UninstallResult, LpmError> {
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(format!(
            "no package.json at {}",
            pkg_json_path.display()
        )));
    }

    let content = std::fs::read_to_string(pkg_json_path)?;
    let mut doc: Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let result = remove_from_manifest(&mut doc, packages, json_output);
    if result.removed.is_empty() {
        return Ok(result);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(pkg_json_path, format!("{updated}\n"))?;
    Ok(result)
}

/// Legacy single-project uninstall — thin wrapper around
/// [`uninstall_from_manifest`] + [`cleanup_removed_packages`]. Production
/// callers go through [`run`] which uses the per-target helpers directly.
/// Kept as a stable internal helper that the existing pre-Phase-2 test
/// suite exercises end-to-end.
#[allow(dead_code)] // used by tests; production callers use the per-target helpers
fn uninstall_from_project(
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<UninstallResult, LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    let result = uninstall_from_manifest(&pkg_json_path, packages, json_output)?;
    if !result.removed.is_empty() {
        cleanup_removed_packages(project_dir, &result.removed)?;
    }
    Ok(result)
}

pub async fn run(
    _client: &RegistryClient,
    cwd: &Path,
    packages: &[String],
    filters: &[String],
    workspace_root_flag: bool,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if packages.is_empty() {
        return Err(LpmError::Registry(
            "specify at least one package to uninstall".to_string(),
        ));
    }

    // Phase 32 Phase 2 M3: route through the shared target resolver, which
    // handles all 8 cells of the install/uninstall decision matrix
    // (standalone, workspace member dir, -w, --filter, etc.).
    let targets = crate::commands::install_targets::resolve_install_targets(
        cwd,
        filters,
        workspace_root_flag,
        true, // has_packages
    )?;

    // Empty result from --filter (mirrors Phase 1 D3 / install M2 semantics).
    //
    // Phase 2 audit follow-through: surface the D2 substring → glob migration
    // hint when any filter looks like a bare name that would have
    // substring-matched pre-Phase-32. Same behavior as `lpm install --filter`
    // and `lpm run --filter`.
    if targets.member_manifests.is_empty() {
        let hint = crate::commands::filter::format_no_match_hint(filters);

        if fail_if_no_match {
            let base = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base}\n\n{h}"),
                None => base.to_string(),
            }));
        }
        if !json_output {
            output::warn("No packages matched the filter; nothing to uninstall.");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    // Multi-member informational preview (no interactive prompt in Phase 2).
    if targets.multi_member && !json_output {
        output::info(&format!(
            "Removing {} package(s) from {} workspace member(s):",
            packages.len(),
            targets.member_manifests.len(),
        ));
        for path in &targets.member_manifests {
            let label = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            println!("  {}", label.dimmed());
        }
    }

    // Run uninstall against every target manifest. Aggregate results so we
    // can report a single deduped (removed, not_found) summary at the end.
    //
    // Phase 2 audit correction: lockfile + node_modules cleanup happens
    // PER TARGET at the member's own dir. LPM uses per-directory lockfiles
    // and per-directory node_modules, so a multi-member uninstall must
    // clean each member's own state — not the workspace root's.
    let mut all_removed: Vec<String> = Vec::new();
    let mut all_not_found: Vec<String> = Vec::new();
    for manifest_path in &targets.member_manifests {
        let per_member = uninstall_from_manifest(manifest_path, packages, json_output)?;

        if !per_member.removed.is_empty() {
            // Clean THIS member's lockfile and node_modules. install_root_for
            // returns the manifest's parent directory.
            let member_dir = crate::commands::install_targets::install_root_for(manifest_path);
            cleanup_removed_packages(member_dir, &per_member.removed)?;
        }

        all_removed.extend(per_member.removed);
        all_not_found.extend(per_member.not_found);
    }

    // A package is "not found" only if no target manifest had it. If at
    // least one target removed it, drop it from the not_found set.
    let removed_set: std::collections::HashSet<&str> =
        all_removed.iter().map(String::as_str).collect();
    all_not_found.retain(|name| !removed_set.contains(name.as_str()));

    // Dedupe both lists for stable output.
    all_removed.sort();
    all_removed.dedup();
    all_not_found.sort();
    all_not_found.dedup();

    if all_removed.is_empty() {
        if !json_output {
            output::warn("No packages were removed (not found in any target manifest)");
        }
        return Ok(());
    }

    if json_output {
        let target_set: Vec<String> = targets
            .member_manifests
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let json = serde_json::json!({
            "success": true,
            "removed": all_removed,
            "not_found": all_not_found,
            "target_set": target_set,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        if !all_not_found.is_empty() {
            output::warn(&format!(
                "Not found in any targeted manifest: {}",
                all_not_found.join(", ")
            ));
        }
        println!();
        output::success(&format!(
            "Removed {} package(s)",
            all_removed.len().to_string().bold()
        ));
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_package_json(project_dir: &Path, value: &Value) {
        std::fs::write(
            project_dir.join("package.json"),
            format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn remove_from_manifest_tracks_removed_and_not_found() {
        let mut manifest = json!({
            "dependencies": {
                "foo": "1.0.0",
                "bar": "2.0.0"
            },
            "devDependencies": {
                "baz": "3.0.0"
            }
        });
        let packages = vec!["foo".to_string(), "baz".to_string(), "missing".to_string()];

        let result = remove_from_manifest(&mut manifest, &packages, true);

        assert_eq!(
            result,
            UninstallResult {
                removed: vec!["foo".to_string(), "baz".to_string()],
                not_found: vec!["missing".to_string()],
            }
        );
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(manifest["devDependencies"].get("baz").is_none());
        assert_eq!(manifest["dependencies"]["bar"], "2.0.0");
    }

    #[test]
    fn uninstall_from_project_removes_targeted_dependency_and_lockfile_only_when_changed() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0",
                    "bar": "2.0.0"
                },
                "devDependencies": {
                    "baz": "3.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("foo")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("bar")).unwrap();

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        assert_eq!(result.removed, vec!["foo".to_string()]);
        assert!(
            !dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should be removed when manifest changes"
        );
        assert!(
            !dir.path().join("node_modules").join("foo").exists(),
            "removed package directory should be cleaned up"
        );
        assert!(
            dir.path().join("node_modules").join("bar").exists(),
            "unrelated node_modules entries must be preserved"
        );

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
        assert_eq!(manifest["dependencies"]["bar"], "2.0.0");
        assert_eq!(manifest["devDependencies"]["baz"], "3.0.0");
    }

    #[test]
    fn uninstall_from_project_preserves_files_when_package_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "bar": "2.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();

        let original_manifest = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let result = uninstall_from_project(dir.path(), &["missing".to_string()], true).unwrap();

        assert!(result.removed.is_empty());
        assert_eq!(result.not_found, vec!["missing".to_string()]);
        assert!(
            dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists(),
            "lockfile should remain when nothing was removed"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            original_manifest,
            "package.json should not be rewritten when no dependency matched"
        );
    }

    // ── Phase 32 Phase 0.1 gap-filling additions ────────────────────────

    #[test]
    fn remove_from_manifest_handles_scoped_package_names() {
        let mut manifest = json!({
            "dependencies": {
                "@lpm.dev/acme.foo": "1.0.0",
                "@scope/bar": "2.0.0",
                "plain": "3.0.0"
            }
        });

        let result = remove_from_manifest(
            &mut manifest,
            &["@lpm.dev/acme.foo".to_string(), "@scope/bar".to_string()],
            true,
        );

        assert_eq!(
            result.removed,
            vec!["@lpm.dev/acme.foo".to_string(), "@scope/bar".to_string()]
        );
        assert!(result.not_found.is_empty());
        assert!(manifest["dependencies"].get("@lpm.dev/acme.foo").is_none());
        assert!(manifest["dependencies"].get("@scope/bar").is_none());
        assert_eq!(manifest["dependencies"]["plain"], "3.0.0");
    }

    #[test]
    fn remove_from_manifest_does_not_touch_peer_or_optional_dependencies() {
        // Documents intentional behavior: only `dependencies` and `devDependencies`
        // are managed by uninstall. Peer and optional dependency entries are left
        // alone because removing them blindly would break consumers.
        let mut manifest = json!({
            "dependencies": { "foo": "1.0.0" },
            "peerDependencies": { "foo": ">=1.0.0" },
            "optionalDependencies": { "foo": "1.0.0" }
        });

        let result = remove_from_manifest(&mut manifest, &["foo".to_string()], true);

        assert_eq!(result.removed, vec!["foo".to_string()]);
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(
            manifest["peerDependencies"].get("foo").is_some(),
            "peerDependencies must be left untouched by uninstall"
        );
        assert!(
            manifest["optionalDependencies"].get("foo").is_some(),
            "optionalDependencies must be left untouched by uninstall"
        );
    }

    #[test]
    fn remove_from_manifest_handles_missing_dependency_sections_gracefully() {
        // A manifest with no `dependencies` or `devDependencies` should still
        // succeed (every requested package becomes not_found).
        let mut manifest = json!({ "name": "demo" });

        let result = remove_from_manifest(&mut manifest, &["foo".to_string()], true);

        assert!(result.removed.is_empty());
        assert_eq!(result.not_found, vec!["foo".to_string()]);
    }

    #[test]
    fn uninstall_from_project_removes_multiple_packages_at_once() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0",
                    "bar": "2.0.0",
                    "keep": "3.0.0"
                },
                "devDependencies": {
                    "baz": "4.0.0"
                }
            }),
        );
        std::fs::write(dir.path().join(lpm_lockfile::LOCKFILE_NAME), "lock").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("foo")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("bar")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("baz")).unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("keep")).unwrap();

        let result = uninstall_from_project(
            dir.path(),
            &["foo".to_string(), "bar".to_string(), "baz".to_string()],
            true,
        )
        .unwrap();

        assert_eq!(
            result.removed,
            vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
        );
        assert!(result.not_found.is_empty());

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
        assert!(manifest["dependencies"].get("bar").is_none());
        assert!(manifest["devDependencies"].get("baz").is_none());
        assert_eq!(manifest["dependencies"]["keep"], "3.0.0");

        assert!(!dir.path().join("node_modules").join("foo").exists());
        assert!(!dir.path().join("node_modules").join("bar").exists());
        assert!(!dir.path().join("node_modules").join("baz").exists());
        assert!(dir.path().join("node_modules").join("keep").exists());
        assert!(!dir.path().join(lpm_lockfile::LOCKFILE_NAME).exists());
    }

    #[test]
    fn uninstall_from_project_removes_dev_only_dependency() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "keep": "1.0.0"
                },
                "devDependencies": {
                    "vitest": "2.0.0"
                }
            }),
        );

        let result = uninstall_from_project(dir.path(), &["vitest".to_string()], true).unwrap();

        assert_eq!(result.removed, vec!["vitest".to_string()]);
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["devDependencies"].get("vitest").is_none());
        assert_eq!(manifest["dependencies"]["keep"], "1.0.0");
    }

    #[test]
    fn uninstall_from_project_preserves_unrelated_manifest_sections() {
        // Important: the writer uses serde_json::to_string_pretty which can
        // reorder keys. This test asserts that NON-TARGET sections survive
        // the rewrite even if formatting is not byte-identical.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "version": "1.0.0",
                "scripts": {
                    "build": "tsup",
                    "test": "vitest"
                },
                "dependencies": {
                    "foo": "1.0.0"
                },
                "peerDependencies": {
                    "react": ">=18"
                },
                "optionalDependencies": {
                    "fsevents": "*"
                },
                "lpm": {
                    "trustedDependencies": ["esbuild"]
                }
            }),
        );

        uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["name"], "demo");
        assert_eq!(manifest["version"], "1.0.0");
        assert_eq!(manifest["scripts"]["build"], "tsup");
        assert_eq!(manifest["scripts"]["test"], "vitest");
        assert_eq!(manifest["peerDependencies"]["react"], ">=18");
        assert_eq!(manifest["optionalDependencies"]["fsevents"], "*");
        assert_eq!(manifest["lpm"]["trustedDependencies"][0], "esbuild");
        assert!(manifest["dependencies"].get("foo").is_none());
    }

    #[test]
    fn uninstall_from_project_errors_when_package_json_missing() {
        let dir = tempfile::tempdir().unwrap();
        // No package.json written.

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true);

        assert!(result.is_err(), "missing package.json must be a hard error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("package.json"),
            "error message should mention package.json, got: {err}"
        );
    }

    #[test]
    fn uninstall_from_project_errors_when_package_json_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{not valid json").unwrap();
        let original = std::fs::read_to_string(dir.path().join("package.json")).unwrap();

        let result = uninstall_from_project(dir.path(), &["foo".to_string()], true);

        assert!(
            result.is_err(),
            "malformed package.json must be a hard error, never silent"
        );
        // Critical: do NOT overwrite a malformed manifest with serialized output.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            original,
            "malformed manifest must be left as-is on parse failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_from_project_removes_symlink_in_node_modules() {
        // The cleanup path treats symlinks specially (must remove via remove_file
        // on unix, not remove_dir, because symlinks are file nodes). This test
        // exercises that path.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": {
                    "foo": "1.0.0"
                }
            }),
        );

        // Create a real package elsewhere and symlink it into node_modules/foo
        let store_pkg = dir.path().join("store").join("foo");
        std::fs::create_dir_all(&store_pkg).unwrap();
        std::fs::write(store_pkg.join("index.js"), "module.exports={}").unwrap();

        let node_modules = dir.path().join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();
        std::os::unix::fs::symlink(&store_pkg, node_modules.join("foo")).unwrap();
        assert!(
            node_modules.join("foo").symlink_metadata().is_ok(),
            "symlink should exist before uninstall"
        );

        uninstall_from_project(dir.path(), &["foo".to_string()], true).unwrap();

        assert!(
            node_modules.join("foo").symlink_metadata().is_err(),
            "symlinked node_modules entry must be removed"
        );
        // The store target must NOT be touched — only the link.
        assert!(
            store_pkg.join("index.js").exists(),
            "symlink target (store package) must not be deleted"
        );
    }

    #[tokio::test]
    async fn run_returns_error_for_empty_packages_list() {
        // The public `run` entrypoint must reject an empty packages list.
        // The client is unused on this code path (uninstall never hits the
        // network) so a default-constructed client is safe.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        // Phase 2 M3: signature gained filters/-w/fail_if_no_match params.
        let result = run(&client, dir.path(), &[], &[], false, false, true).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("at least one package"),
            "error should explain the constraint, got: {err}"
        );
    }

    // ── Phase 32 Phase 2 M3: workspace-aware uninstall behavior ────────────

    #[tokio::test]
    async fn run_uninstall_in_standalone_project_targets_cwd_manifest() {
        // Standalone project (no workspace) — Phase 2 dispatch falls through
        // to the legacy single-target path via resolve_install_targets.
        let dir = tempfile::tempdir().unwrap();
        write_package_json(
            dir.path(),
            &json!({
                "name": "demo",
                "dependencies": { "foo": "1.0.0" }
            }),
        );
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &[],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok(), "uninstall should succeed: {result:?}");

        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(manifest["dependencies"].get("foo").is_none());
    }

    #[tokio::test]
    async fn run_uninstall_with_w_flag_in_standalone_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        // -w in a standalone project must surface the resolve_install_targets error
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &[],
            true,
            false,
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workspace"));
    }

    #[tokio::test]
    async fn run_uninstall_with_filter_in_standalone_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_package_json(dir.path(), &json!({"name": "demo"}));
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["web".to_string()],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workspace"));
    }

    /// Helper: build a real on-disk workspace fixture with the given members.
    /// Each member starts with a small dependency set so uninstall has
    /// something to remove.
    #[allow(clippy::type_complexity)] // test fixture builder; tuple shape mirrors caller usage
    fn write_workspace_fixture(root: &std::path::Path, members: &[(&str, &str, &[(&str, &str)])]) {
        std::fs::create_dir_all(root).unwrap();
        let workspace_globs: Vec<String> =
            members.iter().map(|(_, p, _)| (*p).to_string()).collect();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": workspace_globs,
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        for (name, path, deps) in members {
            let dir = root.join(path);
            std::fs::create_dir_all(&dir).unwrap();
            let mut deps_obj = serde_json::Map::new();
            for (k, v) in *deps {
                deps_obj.insert((*k).to_string(), json!(*v));
            }
            let pkg = json!({
                "name": name,
                "version": "0.0.0",
                "dependencies": deps_obj,
            });
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn run_uninstall_with_filter_removes_only_from_targeted_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("web", "packages/web", &[("foo", "1.0.0"), ("bar", "2.0.0")]),
                ("admin", "packages/admin", &[("foo", "1.0.0")]),
            ],
        );

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["web".to_string()],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok(), "expected success: {result:?}");

        // web should have foo removed, bar preserved
        let web: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/web/package.json")).unwrap(),
        )
        .unwrap();
        assert!(web["dependencies"].get("foo").is_none());
        assert_eq!(web["dependencies"]["bar"], "2.0.0");

        // admin should be untouched (foo still present)
        let admin: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/admin/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(admin["dependencies"]["foo"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_with_glob_filter_removes_from_each_matching_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("ui-button", "packages/ui-button", &[("foo", "1.0.0")]),
                ("ui-card", "packages/ui-card", &[("foo", "1.0.0")]),
                ("auth", "packages/auth", &[("foo", "1.0.0")]),
            ],
        );

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["ui-*".to_string()],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok());

        // Both ui members lost foo
        for member in ["ui-button", "ui-card"] {
            let pkg: Value = serde_json::from_str(
                &std::fs::read_to_string(
                    dir.path().join(format!("packages/{member}/package.json")),
                )
                .unwrap(),
            )
            .unwrap();
            assert!(pkg["dependencies"].get("foo").is_none());
        }
        // auth still has foo (didn't match the filter)
        let auth: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/auth/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(auth["dependencies"]["foo"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_with_w_flag_targets_root_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[("web", "packages/web", &[("local-only", "1.0.0")])],
        );
        // Add a root-level dep to the workspace root manifest
        let root_pkg_path = dir.path().join("package.json");
        let mut root_pkg: Value =
            serde_json::from_str(&std::fs::read_to_string(&root_pkg_path).unwrap()).unwrap();
        root_pkg["dependencies"] = json!({ "shared-tool": "1.0.0" });
        std::fs::write(
            &root_pkg_path,
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["shared-tool".to_string()],
            &[],
            true, // -w
            false,
            true,
        )
        .await;
        assert!(result.is_ok());

        let root_after: Value =
            serde_json::from_str(&std::fs::read_to_string(&root_pkg_path).unwrap()).unwrap();
        assert!(root_after["dependencies"].get("shared-tool").is_none());

        // web member's local-only dep is untouched
        let web: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/web/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(web["dependencies"]["local-only"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_w_and_filter_together_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["foo".to_string()],
            true, // -w + --filter together
            false,
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("`-w`") && err.contains("`--filter`"));
    }

    #[tokio::test]
    async fn run_uninstall_at_workspace_root_with_packages_no_flag_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        // No -w, no --filter, packages provided, cwd at workspace root → ambiguous
        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &[],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }

    #[tokio::test]
    async fn run_uninstall_in_member_dir_no_flag_targets_current_member() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("foo", "packages/foo", &[("lodash", "4.0.0")]),
                ("bar", "packages/bar", &[("lodash", "4.0.0")]),
            ],
        );
        let foo_dir = dir.path().join("packages/foo");

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            &foo_dir,
            &["lodash".to_string()],
            &[],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok(), "expected success: {result:?}");

        // foo lost lodash
        let foo: Value =
            serde_json::from_str(&std::fs::read_to_string(foo_dir.join("package.json")).unwrap())
                .unwrap();
        assert!(foo["dependencies"].get("lodash").is_none());

        // bar still has lodash
        let bar: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/bar/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(bar["dependencies"]["lodash"], "4.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_with_fail_flag_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["does-not-exist".to_string()],
            false,
            true, // fail_if_no_match
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--fail-if-no-match"));
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_without_fail_flag_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["does-not-exist".to_string()],
            false,
            false,
            true,
        )
        .await;
        assert!(
            result.is_ok(),
            "no-match without --fail flag should be OK: {result:?}"
        );

        // bar is still in foo's manifest (nothing was removed)
        let foo: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/foo/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(foo["dependencies"]["bar"], "1.0.0");
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_with_fail_flag_includes_d2_hint_for_bare_names() {
        // Phase 2 audit regression: when --fail-if-no-match fires AND the
        // filter list contains bare names that would have substring-matched
        // pre-Phase-32, the error message must surface the D2 migration hint.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            // bare name filter that matches nothing — exact 'core' substring scenario
            // GPT cited in the audit
            &["core".to_string()],
            false,
            true, // fail_if_no_match
            true,
        )
        .await;
        assert!(result.is_err(), "fail_if_no_match must error on no match");

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("D2"),
            "error must reference design decision D2, got: {err}"
        );
        assert!(
            err.contains("\"*core*\"") || err.contains("\"*/core\""),
            "error must suggest at least one glob form, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_uninstall_filter_no_match_for_glob_filter_does_not_emit_d2_hint() {
        // Negative case: if the user is already using a glob, they don't
        // need the migration hint (they're not coming from substring matching).
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);
        let client = lpm_registry::RegistryClient::new();

        let result = run(
            &client,
            dir.path(),
            &["bar".to_string()],
            &["nonexistent-*".to_string()], // glob that matches nothing
            false,
            true,
            true,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("D2"),
            "glob-only filter must NOT trigger the D2 migration hint, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_uninstall_lockfile_cleanup_happens_per_member_not_at_workspace_root() {
        // Phase 2 audit correction: LPM uses per-directory lockfiles. A
        // multi-member uninstall must clean each TARGETED member's own
        // lockfile — and must NOT touch the workspace root lockfile (or any
        // unrelated member's lockfile).
        //
        // The original Phase 2 implementation set install_root = workspace_root
        // and removed only the workspace root lockfile. That was wrong:
        // member node_modules/lockfiles were left stale, and the workspace
        // root lockfile (if any) might not even be related to the members.
        //
        // This test asserts the corrected behavior:
        //   1. Each TARGETED member's lockfile is removed.
        //   2. The workspace root lockfile is NOT touched.
        //   3. Unrelated members' lockfiles are NOT touched.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            dir.path(),
            &[
                ("ui-a", "packages/ui-a", &[("foo", "1.0.0")]),
                ("ui-b", "packages/ui-b", &[("foo", "1.0.0")]),
                ("auth", "packages/auth", &[("foo", "1.0.0")]), // unrelated to filter
            ],
        );

        // Place lockfiles in: workspace root + each member dir
        let root_lock = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        let ui_a_lock = dir
            .path()
            .join("packages")
            .join("ui-a")
            .join(lpm_lockfile::LOCKFILE_NAME);
        let ui_b_lock = dir
            .path()
            .join("packages")
            .join("ui-b")
            .join(lpm_lockfile::LOCKFILE_NAME);
        let auth_lock = dir
            .path()
            .join("packages")
            .join("auth")
            .join(lpm_lockfile::LOCKFILE_NAME);

        for path in [&root_lock, &ui_a_lock, &ui_b_lock, &auth_lock] {
            std::fs::write(path, "stub-lock-content").unwrap();
        }

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            dir.path(),
            &["foo".to_string()],
            &["ui-*".to_string()], // matches ui-a and ui-b only
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok(), "uninstall should succeed: {result:?}");

        // CRITICAL: targeted members' lockfiles must be removed
        assert!(
            !ui_a_lock.exists(),
            "ui-a lockfile must be removed (it's a filter target)"
        );
        assert!(
            !ui_b_lock.exists(),
            "ui-b lockfile must be removed (it's a filter target)"
        );

        // CRITICAL: unrelated members' lockfiles must be preserved
        assert!(
            auth_lock.exists(),
            "auth lockfile must be preserved (not in filter target set)"
        );

        // CRITICAL: workspace root lockfile must NOT be touched
        assert!(
            root_lock.exists(),
            "workspace root lockfile must NOT be touched by a member-targeted uninstall"
        );
    }

    // ── Phase 2 audit fix: install pipeline runs at member dir for filtered installs ──

    #[tokio::test]
    async fn run_uninstall_targets_member_dir_lockfile_for_in_member_dir_default() {
        // When the user is `cd packages/foo && lpm uninstall bar`, the
        // lockfile that gets cleaned is packages/foo/lpm.lock — NOT the
        // workspace root lockfile.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_fixture(dir.path(), &[("foo", "packages/foo", &[("bar", "1.0.0")])]);

        let foo_dir = dir.path().join("packages").join("foo");
        let foo_lock = foo_dir.join(lpm_lockfile::LOCKFILE_NAME);
        let root_lock = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        std::fs::write(&foo_lock, "stub").unwrap();
        std::fs::write(&root_lock, "stub").unwrap();

        let client = lpm_registry::RegistryClient::new();
        let result = run(
            &client,
            &foo_dir,
            &["bar".to_string()],
            &[],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_ok());

        assert!(
            !foo_lock.exists(),
            "member lockfile must be removed when uninstalling from inside the member dir"
        );
        assert!(
            root_lock.exists(),
            "workspace root lockfile must NOT be touched by an in-member uninstall"
        );
    }
}
