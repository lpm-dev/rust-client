use crate::{install_ui, output};
use lpm_common::{LpmError, PackageName};
use lpm_registry::{RegistryClient, RouteTable};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Collect every dependency the source package would install into the
/// consumer's `package.json`, in stable insertion order with duplicates
/// removed.
///
/// Mirrors the install path in [`handle_dependencies`]:
///
/// 1. Walk `lpm.config.json#dependencies` (config-conditional map),
///    selecting deps for each `inline_config` value. Comma-separated
///    multi-select values fan out across all selections.
/// 2. If step 1 produced nothing, fall back to the package's own
///    `package.json#dependencies + peerDependencies`. This is the
///    legacy path for source packages that ship a plain `package.json`
///    rather than a config-driven manifest.
///
/// `@lpm.dev/*` entries flow through unchanged: source-package deps
/// install identically regardless of whether they resolve through npm,
/// a private registry, or lpm.dev. Auth and access checks happen when
/// the selected package manager (`--pm`) runs its install step; we
/// don't pre-filter here.
///
/// Used by both [`handle_dependencies`] (the actual installer) and
/// [`count_dependencies`] (the dry-run / `--no-install-deps` UX) so the
/// preview, the skip-count message, and the install all walk the same
/// list. Without this shared spine, a config-aware package whose
/// `lpm.config.json#dependencies` was empty but whose `package.json`
/// carried real deps would silently disagree across the three surfaces.
fn collect_source_pkg_deps(
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    extract_dir: &Path,
) -> Result<Vec<(String, crate::save_spec::UserSaveIntent)>, LpmError> {
    // Authoring contract: declaring `dependencies` in `lpm.config.json` —
    // even with conditional branches that produce zero matches for a
    // given consumer config — opts out of the legacy `package.json`
    // fallback. Mirrors how `files[]` works: declared = source of truth.
    // Without this rule, a consumer who picks a config that doesn't
    // match any conditional branch would silently pull every entry
    // from the package's own `package.json#dependencies`, which the
    // author almost certainly didn't intend.
    let dep_config_present = lpm_config
        .as_ref()
        .and_then(|c| c.get("dependencies"))
        .is_some();

    // Each entry is parsed once into `(name, intent)`. Dedup is by parsed
    // `name`, not the raw entry string — so `["react", "react@^18"]` in
    // the same conditional collapses to a single entry (first-wins, per
    // the "explicit user input wins" rule, which here means the
    // first declaration the author wrote).
    let mut deps: Vec<(String, crate::save_spec::UserSaveIntent)> = Vec::new();
    let push_if_new = |deps: &mut Vec<(String, crate::save_spec::UserSaveIntent)>,
                       raw: &str|
     -> Result<(), LpmError> {
        let (name, intent) = crate::save_spec::parse_user_save_intent(raw)?;
        if !deps.iter().any(|(existing, _)| existing == &name) {
            deps.push((name, intent));
        }
        Ok(())
    };

    // 1. Conditional deps from `lpm.config.json#dependencies`.
    if let Some(config) = lpm_config
        && let Some(dep_config) = config.get("dependencies").and_then(|d| d.as_object())
    {
        for (config_key, dep_map) in dep_config {
            let config_value = inline_config.get(config_key).map_or("", |s| s.as_str());
            if config_value.is_empty() {
                continue;
            }

            let selected_values: Vec<&str> = if config_value.contains(',') {
                config_value.split(',').map(|v| v.trim()).collect()
            } else {
                vec![config_value]
            };

            for value in &selected_values {
                if let Some(arr) = dep_map.get(*value).and_then(|d| d.as_array()) {
                    for dep in arr {
                        if let Some(raw) = dep.as_str() {
                            push_if_new(&mut deps, raw)?;
                        }
                    }
                }
            }
        }
    }

    // 2. Legacy fallback: package's own `package.json` deps + peerDeps.
    //    Fires only when `lpm.config.json#dependencies` is absent
    //    entirely. A declared-but-unmatched `dependencies` block is a
    //    deliberate "no deps for this configuration" signal from the
    //    author, not a request to fall back.
    //
    //    The package's `package.json` already carries explicit version
    //    ranges per the npm spec (`{"react": "^18"}`). Reconstruct each
    //    entry as `name@range` and push it through the same parser so
    //    the downstream save-spec logic preserves it verbatim.
    if !dep_config_present {
        let pkg_json_path = extract_dir.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_json_path)
            && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content)
        {
            for section in ["dependencies", "peerDependencies"] {
                if let Some(map) = doc.get(section).and_then(|d| d.as_object()) {
                    for (name, version) in map {
                        let raw = match version.as_str() {
                            Some(v) if !v.is_empty() => format!("{name}@{v}"),
                            _ => name.clone(),
                        };
                        push_if_new(&mut deps, &raw)?;
                    }
                }
            }
        }
    }

    Ok(deps)
}

/// Count how many dependencies would be installed without actually installing them.
///
/// Returns `collect_source_pkg_deps(...).len()` so dry-run preview and
/// `--no-install-deps` skip-count agree with the install path.
pub(super) fn count_dependencies(
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    extract_dir: &Path,
) -> Result<usize, LpmError> {
    Ok(collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?.len())
}

/// Refuse to copy a deps-declaring source package into a project with no
/// `package.json`.
///
/// Without a manifest, the dep entries the source declares have
/// nowhere to land — the user would end up with copied source files
/// importing packages they can't install. Block the run before any
/// side effect with a remediation hint pointing at `lpm init` /
/// `npm init -y`.
///
/// Gates (must all hold to fire):
/// - `!no_install_deps`: the user explicitly opting out of dep
///   install acknowledges they'll handle it themselves; respect that.
/// - `lpm_config.is_some()`: simple-path tarballs (no
///   `lpm.config.json`) intentionally skip auto-install; the
///   bare-imports notice surfaces what the user needs.
/// - `!project_dir/package.json exists`: the actual blocking
///   condition — no manifest to mutate.
/// - `collect_source_pkg_deps(...).len() > 0`: a deps-free source
///   package (just files, no imports) is safe to land in a no-
///   manifest project.
pub(super) fn preflight_no_manifest_with_deps(
    project_dir: &Path,
    extract_dir: &Path,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    no_install_deps: bool,
) -> Result<(), LpmError> {
    if no_install_deps {
        return Ok(());
    }
    if lpm_config.is_none() {
        return Ok(());
    }
    if project_dir.join("package.json").exists() {
        return Ok(());
    }
    if collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?.is_empty() {
        return Ok(());
    }

    Err(LpmError::Script(
        "this source package declares dependencies, but the project has no \
         `package.json` to record them in.\n\n  \
         Run `lpm init` (or `npm init -y`) first to create a manifest, \
         then re-run `lpm add`.\n\n  \
         To copy the source files without installing the declared dependencies, \
         pass `--no-install-deps` and resolve the imports yourself."
            .to_string(),
    ))
}

/// Compute the version spec to write into the consumer's `package.json`
/// for each collected source-package dependency.
///
/// Pure function over already-resolved metadata so it can be unit-tested
/// without spinning up a registry client. The orchestration (network
/// fetch, intent collection) lives in `handle_dependencies`.
///
/// Author-controlled specs (`Exact` / `Range` / `Wildcard` / `Workspace`)
/// short-circuit through [`crate::save_spec::decide_saved_dependency_spec`]
/// without touching `resolved_latest`. Bare names and dist-tags require
/// a resolved `Version` — missing entries fail fast with a remediation
/// hint pointing at explicit-version pinning or `lpm login`.
fn build_save_decisions(
    entries: &[(String, crate::save_spec::UserSaveIntent)],
    resolved_latest: &HashMap<String, lpm_semver::Version>,
    save_config: crate::save_spec::SaveConfig,
) -> Result<Vec<(String, String)>, LpmError> {
    // Sentinel never read for direct intents (Wildcard/Workspace/Exact/
    // Range), which short-circuit before `decide_saved_dependency_spec` touches
    // `resolved`). Using a real-but-fake Version keeps the function
    // signature simple — alternative is a duplicate split in this loop.
    let sentinel = lpm_semver::Version::parse("0.0.0").expect("0.0.0 is a valid Version");

    let mut out = Vec::with_capacity(entries.len());
    for (name, intent) in entries {
        let resolved = match intent {
            crate::save_spec::UserSaveIntent::Bare
            | crate::save_spec::UserSaveIntent::DistTag(_) => {
                resolved_latest.get(name).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "could not resolve a version for source-package dependency '{name}'. \
                         The package may not exist in the configured registry, or your auth \
                         may not grant access. Pin an explicit version in the source package's \
                         lpm.config.json#dependencies (e.g., \"{name}@^1.0\"), or run `lpm login` \
                         if it's an @lpm.dev/* dep."
                    ))
                })?
            }
            _ => &sentinel,
        };
        let decision = crate::save_spec::decide_saved_dependency_spec(
            intent,
            resolved,
            crate::save_spec::SaveFlags::default(),
            save_config,
        );
        out.push((name.clone(), decision.spec_to_write));
    }
    Ok(out)
}

/// Handle npm/LPM dependencies from lpm.config.json.
///
/// Source-package deps install identically regardless of registry origin
/// — npm, private, or `@lpm.dev/*` all flow through `package.json` ➜
/// install via the selected package manager (`--pm`). Auth and access
/// checks happen at the install step, not here.
///
/// Save-spec policy mirrors `lpm install`:
/// - Author-provided ranges (`"react@^18"`, `"lodash@4.17.21"`) are
///   preserved verbatim.
/// - Bare names (`"react"`) and dist-tags (`"react@latest"`) resolve
///   against the registry; the resolved version flows into the
///   user's project save-policy default — typically `^resolvedLatest`,
///   or whatever `~/.lpm/config.toml > save-prefix|save-exact` says.
/// - Resolution is **per-package routed** through `RouteTable` so
///   `.npmrc`-declared private registries, the LPM Worker, and the
///   public npm registry all work for bare/dist-tag entries. Mirrors
///   the resolver walker's three-arm dispatch.
/// - Resolution **fails the whole call** before mutating
///   `package.json`. Without this fail-fast posture, a stuck resolve
///   would leave the manifest with stranded entries that the trailing
///   install can't recover.
///
/// **Rollback ownership lives at the caller** ([`run`]). The
/// `ManifestTransaction` snapshot opens before file copy, dependency
/// mutation, and the bare-imports notice, so failures roll back source
/// files alongside the manifest + lockfiles. This function therefore does
/// not own a tx of its own — every error path returns `Err`, which
/// the caller's `?` propagates and the caller's tx Drops.
///
/// `effective_pm` is pre-resolved at the call site (handles
/// `--pm auto`) so this function picks dispatch arms by exact match
/// without re-running detection.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_dependencies(
    client: &RegistryClient,
    route_table: &RouteTable,
    project_dir: &Path,
    extract_dir: &Path,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    ecosystem: &str,
    _yes: bool,
    json_output: bool,
    effective_pm: &str,
) -> Result<Vec<(String, String)>, LpmError> {
    let entries = collect_source_pkg_deps(lpm_config, inline_config, extract_dir)?;

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    if !json_output {
        install_ui::phase("Installing declared dependencies");
    }

    // Resolve latest version for each Bare / DistTag entry up-front,
    // dispatching per-package through `RouteTable`. The walker's
    // three-arm pattern (LPM batch / npm fan-out / custom registries)
    // is overkill for the typical < 10 source-package deps; serial
    // routed fetches are simpler and the bound is small enough that
    // wall time is dominated by network setup, not parallelism.
    let mut resolved: HashMap<String, lpm_semver::Version> = HashMap::new();
    for (name, intent) in &entries {
        let tag = match intent {
            crate::save_spec::UserSaveIntent::DistTag(t) => t.as_str(),
            crate::save_spec::UserSaveIntent::Bare => "latest",
            _ => continue,
        };

        // `@lpm.dev/*` packages take the LPM-direct metadata route —
        // same call the source package itself uses at the top of
        // `add::run`. Everything else (npm-published, private-
        // registry-declared via .npmrc) goes through
        // `get_npm_metadata_routed`, which dispatches by the route
        // table to the correct upstream.
        let pkg_meta = if name.starts_with("@lpm.dev/") {
            let pkg = PackageName::parse(name).map_err(|e| {
                LpmError::Registry(format!("invalid @lpm.dev/* dep name '{name}': {e}"))
            })?;
            client.get_package_metadata(&pkg).await.map_err(|e| {
                LpmError::Registry(format!(
                    "could not resolve '{name}' against lpm.dev: {e}. \
                     Pin an explicit version (e.g., \"{name}@^1.0\") in the source \
                     package's lpm.config.json#dependencies, or run `lpm login` to \
                     authenticate."
                ))
            })?
        } else {
            let route = route_table.route_for_package(name);
            client
                .get_npm_metadata_routed(name, route)
                .await
                .map_err(|e| {
                    LpmError::Registry(format!(
                        "could not resolve '{name}' against the registry: {e}. \
                         Either the package doesn't exist there or your auth \
                         doesn't grant access. Pin an explicit version \
                         (e.g., \"{name}@^1.0\") in the source package's \
                         lpm.config.json#dependencies."
                    ))
                })?
        };
        let resolved_version_str = pkg_meta.resolve_version_spec(tag).map_err(|e| {
            LpmError::Registry(format!("resolving '{name}@{tag}' against registry: {e}"))
        })?;
        let version = lpm_semver::Version::parse(&resolved_version_str).map_err(|e| {
            LpmError::Registry(format!(
                "registry returned non-semver version '{resolved_version_str}' for '{name}': {e}"
            ))
        })?;
        resolved.insert(name.clone(), version);
    }

    // Build the (name, spec_to_write) list using the shared save-spec
    // decision helper. Honors `~/.lpm/config.toml` + `./lpm.toml` save
    // policy — same precedence chain `lpm install <pkg>` uses.
    let save_config = crate::save_config::SaveConfigLoader::load_for_project(project_dir)?;
    let decisions = build_save_decisions(&entries, &resolved, save_config)?;

    let pkg_json_path = project_dir.join("package.json");

    // No `package.json` ⇒ no manifest to mutate. The caller's tx
    // already snapshotted the manifest as `optional` (records `None`
    // for missing files), so this early-return is purely the user-
    // facing warning surface.
    if !pkg_json_path.exists() {
        output::warn(
            "no package.json found -- dependencies not installed. Run `lpm install` manually.",
        );
        let _ = ecosystem;
        return Ok(Vec::new());
    }

    // Mutate `package.json` with the resolved specs. The caller's
    // [`ManifestTransaction`] owns the rollback boundary — any `?`
    // error from here on propagates up and the caller's `tx` drops
    // without `commit()`, restoring every snapshotted path (manifest,
    // LPM lockfiles, the selected PM's lockfile, every Step-8 dest
    // file) and invalidating `.lpm/install-hash`.
    {
        let content = std::fs::read_to_string(&pkg_json_path)
            .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
        let mut doc: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| LpmError::Registry(format!("failed to parse package.json: {e}")))?;

        let deps = doc.as_object_mut().and_then(|o| {
            o.entry("dependencies")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        });

        if let Some(deps) = deps {
            for (name, spec) in &decisions {
                // "do not rewrite existing entries on bare
                // reinstall" semantics: if the consumer already pinned
                // a range for this dep, we keep theirs.
                deps.entry(name.clone())
                    .or_insert_with(|| serde_json::Value::String(spec.clone()));
            }
        }

        let updated = serde_json::to_string_pretty(&doc)
            .map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;
        lpm_common::write_file_atomic(&pkg_json_path, format!("{updated}\n"))
            .map_err(|e| LpmError::Registry(format!("failed to write package.json: {e}")))?;
    }

    // Dispatch to the selected package manager. EVERY failure path
    // returns `Err`, which drops the caller's tx and rolls back the
    // manifest + lockfiles + dest files + invalidates
    // `.lpm/install-hash`. Warning and continuing here would leave users with a
    // half-applied manifest the trailing install never finished
    // filling in.
    match effective_pm {
        "lpm" => {
            // Use the injected client so post-add `lpm install` carries
            // the selected registry and shared session.
            crate::commands::install::run_with_options(
                client,
                project_dir,
                json_output,
                false,                                                 // offline
                crate::commands::install::FrozenLockfileMode::Never,
                false,                                                 // force
                false,                                                 // allow_new
                false, // strict_integrity
                None,  // strict_peer_dependencies_override
                None,  // linker_override
                false, // no_skills
                false, // no_editor_setup
                true,  // no_security_summary
                false, // auto_build
                None,  // target_set: shadcn-style add never targets multiple workspace members
                None, // direct_versions_out: shadcn-style add does not finalize placeholders
                None, // requested_add_count: `lpm add` is source-copy, not install add-path reporting
                None, // script_policy_override: `lpm add` does not expose policy flags
                None, // advisor_override: `lpm add` does not expose `--advisor`
                None, // min_release_age_override: shadcn-style add uses the chain
                crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm add` does not expose drift-override flags
                // verify-policy: `lpm add` does not expose its own
                // `--unverified-provenance{,-all}` flags; honors the
                // operator-persistent posture chain (env +
                // `[sigstore] verify` config) for uniformity with
                // `lpm install`.
                crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
                crate::commands::install::InstallOmitPolicy::default(),
                // `lpm add` does not surface its
                // own sandbox-mode flags. The env / config / default
                // chain inside `rebuild::run` still applies.
                false, // strict_sandbox
                false, // no_sandbox
                false, // verbose: internal pipeline, no user-facing Done footer
                false, // audit_after_install: internal pipeline never runs audit
            )
            .await
            .map_err(|e| {
                LpmError::Script(format!(
                    "lpm install failed: {e}. package.json + lockfiles rolled back to pre-add state."
                ))
            })?;
        }
        pm_name @ ("npm" | "pnpm" | "yarn" | "bun") => {
            let status = std::process::Command::new(pm_name)
                .arg("install")
                .current_dir(project_dir)
                .status()
                .map_err(|e| {
                    LpmError::Script(format!(
                        "{pm_name} install failed to spawn: {e}. \
                         package.json + lockfile rolled back to pre-add state."
                    ))
                })?;
            if !status.success() {
                return Err(LpmError::Script(format!(
                    "{pm_name} install exited with non-zero status. \
                     package.json + lockfile rolled back to pre-add state."
                )));
            }
        }
        other => {
            return Err(LpmError::Script(format!(
                "unknown package manager: {other}. Use: lpm, npm, pnpm, yarn, bun, auto"
            )));
        }
    }

    // Trailing install succeeded — return Ok and let the caller commit
    // the wider tx after the bare-imports notice.
    let _ = ecosystem; // Ecosystem used for future per-ecosystem dep handling

    Ok(decisions)
}

/// Lockfile paths to snapshot for the selected package manager.
///
/// Returns the per-PM lockfile(s) so a partial install — the install
/// step that fails after writing a partial lockfile — gets rolled back
/// alongside `package.json`. Without this, rolling back the manifest
/// alone would leave a manifest/lockfile split-brain on `--pm npm`,
/// `--pm pnpm`, `--pm yarn`, or `--pm bun`.
///
/// Returns an empty vec for `lpm` (its lockfiles `lpm.lock` and
/// `lpm.lockb` are already snapshotted by the caller) and for unknown
/// values (the dispatch arm errors on those before any tx mutation).
pub(super) fn pm_lockfile_paths(pm: &str, project_dir: &Path) -> Vec<PathBuf> {
    match pm {
        "npm" => vec![project_dir.join("package-lock.json")],
        "pnpm" => vec![project_dir.join("pnpm-lock.yaml")],
        "yarn" => vec![project_dir.join("yarn.lock")],
        // bun ships both binary (`.lockb`, default) and text (`.lock`,
        // newer) formats depending on version. Snapshot both as
        // optional so whichever bun writes is rolled back; the absent
        // one's snapshot records `None` and is a no-op on rollback.
        "bun" => vec![project_dir.join("bun.lock"), project_dir.join("bun.lockb")],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    // -----------------------------------------------------------------
    // Source-package dependency collection
    //
    // Source packages can declare deps from any registry — npm, private,
    // or `@lpm.dev/*`. The collector must NOT pre-filter by name; auth
    // and access checks happen when the selected package manager (`--pm`)
    // runs its install step.
    // -----------------------------------------------------------------

    mod source_pkg_deps {
        use super::*;
        use crate::save_spec::UserSaveIntent;

        fn write_pkg_json(dir: &Path, body: serde_json::Value) {
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&body).unwrap(),
            )
            .unwrap();
        }

        /// Project name strings out of a `(name, intent)` collection so
        /// the older "did this package end up in the result" assertions
        /// stay readable after the Tier-2 refactor.
        fn names(deps: &[(String, UserSaveIntent)]) -> Vec<String> {
            deps.iter().map(|(n, _)| n.clone()).collect()
        }

        #[test]
        fn config_json_path_collects_lpm_dev_and_npm_deps_together() {
            // A source package declares a mix of registries under the
            // same conditional. All three must survive to the install
            // step — the collector is registry-agnostic by contract.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": [
                            "lucide-react",
                            "@lpm.dev/owner.icon-helpers",
                            "@private-scope/icon-utils",
                        ]
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            let names = names(&deps);

            assert!(
                names.contains(&"lucide-react".to_string()),
                "npm-published deps must flow through: {names:?}"
            );
            assert!(
                names.contains(&"@lpm.dev/owner.icon-helpers".to_string()),
                "@lpm.dev/* deps must flow through: {names:?}"
            );
            assert!(
                names.contains(&"@private-scope/icon-utils".to_string()),
                "private-registry-style names must flow through: {names:?}"
            );
            assert_eq!(deps.len(), 3, "no duplicates introduced: {names:?}");

            // Bare names (no `@version`) should land as `Bare` intent —
            // the helper that consumes this list resolves bare entries
            // against the registry to write `^resolvedLatest`, while
            // explicit ranges short-circuit verbatim.
            for (_, intent) in &deps {
                assert!(
                    matches!(intent, UserSaveIntent::Bare),
                    "bare entries must classify as Bare, got {intent:?}"
                );
            }
        }

        #[test]
        fn config_json_preserves_author_provided_version_ranges() {
            // Authors who pin a specific range get it preserved verbatim
            // through to package.json — no resolve, no caret default.
            // Mirrors `lpm install zod@^4.3.0` semantics from.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": [
                            "lucide-react@^0.400.0",   // Range
                            "@lpm.dev/owner.tools@1.2.3", // Exact
                            "react@latest",            // DistTag
                            "lodash@*",                // explicit Wildcard
                        ]
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            assert_eq!(deps.len(), 4, "{deps:?}");

            let by_name: HashMap<String, UserSaveIntent> = deps.into_iter().collect();
            assert_eq!(
                by_name.get("lucide-react"),
                Some(&UserSaveIntent::Range("^0.400.0".to_string())),
            );
            assert_eq!(
                by_name.get("@lpm.dev/owner.tools"),
                Some(&UserSaveIntent::Exact("1.2.3".to_string())),
            );
            assert_eq!(
                by_name.get("react"),
                Some(&UserSaveIntent::DistTag("latest".to_string())),
            );
            assert_eq!(by_name.get("lodash"), Some(&UserSaveIntent::Wildcard));
        }

        #[test]
        fn dedup_is_by_name_first_entry_wins() {
            // Author writes the same package twice with different
            // intents — say a pinned range under one conditional and a
            // bare name under another. First-write-wins keeps the more
            // restrictive declaration when the order is "specific then
            // general," matching how authors typically read top-down.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "ui": {
                        "minimal": ["react@^18.2.0", "react"]
                    }
                }
            });
            let inline = HashMap::from([("ui".to_string(), "minimal".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert_eq!(deps.len(), 1, "duplicates collapse: {deps:?}");
            assert_eq!(
                deps[0],
                (
                    "react".to_string(),
                    UserSaveIntent::Range("^18.2.0".to_string())
                ),
                "first declaration's intent wins"
            );
        }

        #[test]
        fn legacy_package_json_fallback_collects_lpm_dev_and_npm_deps_together() {
            // When `lpm.config.json#dependencies` is absent or its
            // conditionals don't match, the collector falls back to
            // the package's own `package.json#dependencies` +
            // `peerDependencies`. The same registry-agnostic rule
            // applies: every name flows through, and the package.json
            // version range is preserved as the intent (so the trailing
            // install writes that exact range, not `*`).
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "name": "source-pkg",
                    "version": "1.0.0",
                    "dependencies": {
                        "react": "^18",
                        "@lpm.dev/owner.runtime": "^1",
                    },
                    "peerDependencies": {
                        "@private-scope/peer-shim": "^2",
                    }
                }),
            );

            let deps = collect_source_pkg_deps(&None, &HashMap::new(), extract.path()).unwrap();
            let by_name: HashMap<String, UserSaveIntent> = deps.iter().cloned().collect();

            assert_eq!(
                by_name.get("react"),
                Some(&UserSaveIntent::Range("^18".to_string())),
                "package.json version range must be preserved as the intent"
            );
            assert_eq!(
                by_name.get("@lpm.dev/owner.runtime"),
                Some(&UserSaveIntent::Range("^1".to_string())),
                "@lpm.dev/* in legacy fallback must flow through with its declared range"
            );
            assert_eq!(
                by_name.get("@private-scope/peer-shim"),
                Some(&UserSaveIntent::Range("^2".to_string())),
                "peerDependencies must flow through with their declared range"
            );
            assert_eq!(deps.len(), 3, "{deps:?}");
        }

        #[test]
        fn legacy_fallback_does_not_fire_when_config_json_yielded_deps() {
            // Once `lpm.config.json#dependencies` produces any deps,
            // the legacy fallback is skipped. Without this, a config-
            // json package would also pull in its own package.json
            // deps, doubling up.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "should-not-appear": "*" }
                }),
            );

            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert_eq!(names(&deps), vec!["lucide-react".to_string()]);
            assert!(
                !names(&deps).contains(&"should-not-appear".to_string()),
                "legacy fallback must not fire when config-json produced deps: {deps:?}"
            );
        }

        #[test]
        fn legacy_fallback_does_not_fire_when_dependencies_field_present_but_unmatched() {
            // Author contract: declaring `dependencies` in
            // `lpm.config.json` — even with conditional branches that
            // don't match the consumer's selected config — opts out of
            // the legacy package.json fallback. The author's empty/
            // unmatched signal IS the answer ("no deps for this
            // config"), not a cue to silently fall back.
            //
            // Pre-tightening, the gate was `deps.is_empty()` which
            // fired the fallback whenever no conditional matched —
            // contradicting the schema description and pulling
            // package.json deps the author didn't ask for.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": {
                        "would-leak-without-gate": "*",
                        "@lpm.dev/owner.would-also-leak": "*",
                    }
                }),
            );

            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            // Consumer picks a value that doesn't match any inner key.
            let inline = HashMap::from([("icons".to_string(), "phosphor".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();

            assert!(
                deps.is_empty(),
                "declared `dependencies` with no matching conditional must yield zero deps, NOT trigger the legacy fallback: {deps:?}"
            );
        }

        #[test]
        fn legacy_fallback_fires_only_when_dependencies_field_absent() {
            // The fallback IS the right answer when `lpm.config.json`
            // ships without a `dependencies` field — the author hasn't
            // declared a config-driven contract, so we read the
            // package's own `package.json` deps as the source of truth.
            // Tests both shapes: lpm_config = None (no config file) and
            // lpm_config = Some(...) without a `dependencies` key.
            let extract = tempfile::tempdir().unwrap();
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "react": "^18" }
                }),
            );

            // Shape A: no lpm.config.json at all.
            let deps_a = collect_source_pkg_deps(&None, &HashMap::new(), extract.path()).unwrap();
            assert_eq!(names(&deps_a), vec!["react".to_string()]);
            assert_eq!(deps_a[0].1, UserSaveIntent::Range("^18".to_string()));

            // Shape B: lpm.config.json present but no `dependencies` field.
            let lpm_config_no_deps = serde_json::json!({
                "ecosystem": "js",
                "files": [{ "src": "src/**" }]
            });
            let deps_b =
                collect_source_pkg_deps(&Some(lpm_config_no_deps), &HashMap::new(), extract.path())
                    .unwrap();
            assert_eq!(names(&deps_b), vec!["react".to_string()]);
            assert_eq!(deps_b[0].1, UserSaveIntent::Range("^18".to_string()));
        }

        #[test]
        fn count_dependencies_agrees_with_collect() {
            // Preview / `--no-install-deps` skip-count must report the
            // same number the install path will actually install. The
            // `count_dependencies` must follow the same collector as the
            // install path; config-only counting or registry filtering
            // would undercount.
            let extract = tempfile::tempdir().unwrap();

            // Case A: config-json path, mixed registries.
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": ["lucide-react", "@lpm.dev/owner.helpers"]
                    }
                }
            });
            let inline_a = HashMap::from([("icons".to_string(), "lucide".to_string())]);
            let count_a =
                count_dependencies(&Some(lpm_config.clone()), &inline_a, extract.path()).unwrap();
            let collect_a = collect_source_pkg_deps(&Some(lpm_config), &inline_a, extract.path())
                .unwrap()
                .len();
            assert_eq!(count_a, collect_a, "count must agree with collect");
            assert_eq!(count_a, 2, "both @lpm.dev/* and npm names counted");

            // Case B: legacy-fallback path triggered (empty config-json
            // conditionals + populated package.json).
            write_pkg_json(
                extract.path(),
                serde_json::json!({
                    "dependencies": { "react": "*", "@lpm.dev/owner.runtime": "*" }
                }),
            );
            let count_b = count_dependencies(&None, &HashMap::new(), extract.path()).unwrap();
            let collect_b = collect_source_pkg_deps(&None, &HashMap::new(), extract.path())
                .unwrap()
                .len();
            assert_eq!(count_b, collect_b);
            assert_eq!(count_b, 2);
        }

        #[test]
        fn multi_select_values_fan_out_across_selections() {
            // Comma-separated multi-select values pull deps from each
            // matching inner key. Regression: the comma-split logic
            // must not drop names that happen to share any prefix.
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": {
                        "lucide": ["lucide-react"],
                        "heroicons": ["@heroicons/react"],
                    }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide,heroicons".to_string())]);

            let deps = collect_source_pkg_deps(&Some(lpm_config), &inline, extract.path()).unwrap();
            let names = names(&deps);

            assert!(names.contains(&"lucide-react".to_string()));
            assert!(names.contains(&"@heroicons/react".to_string()));
            assert_eq!(deps.len(), 2);
        }

        // ───── build_save_decisions ────────────────────────────────────
        //
        // Decision-layer tests inject a fake `resolved_latest` so they
        // don't need a real registry. The collector → resolver →
        // build_save_decisions chain runs end-to-end in workflow tests;
        // here we exercise the policy logic in isolation.

        fn v(s: &str) -> lpm_semver::Version {
            lpm_semver::Version::parse(s).unwrap()
        }

        #[test]
        fn build_save_decisions_bare_name_gets_caret_resolved() {
            // The default: a bare name resolves to the latest
            // version and writes back as `^x.y.z`. This is the
            // user-visible improvement over a broad `*` write.
            let entries = vec![("react".to_string(), UserSaveIntent::Bare)];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(
                out,
                vec![("react".to_string(), "^18.3.1".to_string())],
                "bare name must resolve to caret range"
            );
        }

        #[test]
        fn build_save_decisions_explicit_range_preserved_verbatim() {
            // Author-pinned range short-circuits before any resolve —
            // we don't even consult `resolved_latest` for these intents.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::Range("^18.0.0".to_string()),
            )];
            let resolved = HashMap::new(); // intentionally empty

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(out, vec![("react".to_string(), "^18.0.0".to_string())]);
        }

        #[test]
        fn build_save_decisions_explicit_exact_preserved_verbatim() {
            let entries = vec![(
                "lodash".to_string(),
                UserSaveIntent::Exact("4.17.21".to_string()),
            )];
            let out = build_save_decisions(
                &entries,
                &HashMap::new(),
                crate::save_spec::SaveConfig::default(),
            )
            .unwrap();
            assert_eq!(out, vec![("lodash".to_string(), "4.17.21".to_string())]);
        }

        #[test]
        fn build_save_decisions_explicit_wildcard_preserved() {
            // The author asked for `*` — a deliberate "any version"
            // signal. preserves user wildcards verbatim.
            let entries = vec![("any-thing".to_string(), UserSaveIntent::Wildcard)];
            let out = build_save_decisions(
                &entries,
                &HashMap::new(),
                crate::save_spec::SaveConfig::default(),
            )
            .unwrap();
            assert_eq!(out, vec![("any-thing".to_string(), "*".to_string())]);
        }

        #[test]
        fn build_save_decisions_dist_tag_resolved_to_caret() {
            // `react@latest` and `react@beta` both resolve via the
            // registry (the helper expects the caller to have already
            // followed the tag → version indirection). Stable resolved
            // versions get the caret default; prereleases pin exact for
            // safety.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::DistTag("latest".to_string()),
            )];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();
            assert_eq!(out, vec![("react".to_string(), "^18.3.1".to_string())]);
        }

        #[test]
        fn build_save_decisions_dist_tag_prerelease_pins_exact() {
            // Prerelease-exact safety: a `next` tag resolving to a
            // prerelease shouldn't auto-widen via caret. Without this,
            // installing `@latest` could later jump to a stable `^1.0`
            // and surprise the consumer with a major bump.
            let entries = vec![(
                "react".to_string(),
                UserSaveIntent::DistTag("next".to_string()),
            )];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("19.0.0-rc.1"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();
            assert_eq!(
                out,
                vec![("react".to_string(), "19.0.0-rc.1".to_string())],
                "prereleases pin exact, no caret widening"
            );
        }

        #[test]
        fn build_save_decisions_fails_fast_when_bare_unresolved() {
            // If the registry doesn't return a version for a bare entry
            // — package missing, auth blocked, network down — we MUST
            // fail before the caller mutates package.json. Otherwise
            // the consumer ends up with a stranded entry the trailing
            // install can't recover.
            let entries = vec![("nonexistent".to_string(), UserSaveIntent::Bare)];
            let resolved = HashMap::new();

            let err =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .expect_err("missing resolved version must error");

            let msg = format!("{err}");
            assert!(
                msg.contains("nonexistent"),
                "error must name the unresolvable package: {msg}"
            );
            assert!(
                msg.contains("Pin an explicit version") || msg.contains("@^1.0"),
                "error must hint at the explicit-version workaround: {msg}"
            );
        }

        #[test]
        fn build_save_decisions_honors_save_exact_config() {
            // User config `save-exact = true` (set in `~/.lpm/config.toml`)
            // applies to source-package deps the same way it applies to
            // `lpm install <pkg>` — bare entries write the exact version,
            // not a caret range.
            let entries = vec![("react".to_string(), UserSaveIntent::Bare)];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));

            let save_config = crate::save_spec::SaveConfig {
                save_exact: true,
                ..Default::default()
            };
            let out = build_save_decisions(&entries, &resolved, save_config).unwrap();

            assert_eq!(
                out,
                vec![("react".to_string(), "18.3.1".to_string())],
                "save-exact config writes exact, no prefix"
            );
        }

        #[test]
        fn build_save_decisions_mix_of_intents_in_one_pass() {
            // End-to-end: a single source package's collected entries
            // span every intent variant the author can produce. The
            // helper has to handle all four in one call.
            let entries = vec![
                ("react".to_string(), UserSaveIntent::Bare),
                (
                    "lucide-react".to_string(),
                    UserSaveIntent::Range("^0.400.0".to_string()),
                ),
                (
                    "lodash".to_string(),
                    UserSaveIntent::Exact("4.17.21".to_string()),
                ),
                (
                    "@lpm.dev/owner.tools".to_string(),
                    UserSaveIntent::DistTag("latest".to_string()),
                ),
            ];
            let mut resolved = HashMap::new();
            resolved.insert("react".to_string(), v("18.3.1"));
            resolved.insert("@lpm.dev/owner.tools".to_string(), v("2.0.0"));

            let out =
                build_save_decisions(&entries, &resolved, crate::save_spec::SaveConfig::default())
                    .unwrap();

            assert_eq!(
                out,
                vec![
                    ("react".to_string(), "^18.3.1".to_string()),
                    ("lucide-react".to_string(), "^0.400.0".to_string()),
                    ("lodash".to_string(), "4.17.21".to_string()),
                    ("@lpm.dev/owner.tools".to_string(), "^2.0.0".to_string()),
                ],
            );
        }

        // Hard-error before any side effects when a deps-declaring
        // source package would land in a project with no manifest.
        // The preflight runs before prompts and file copies.

        #[test]
        fn preflight_errors_when_config_json_declares_deps_and_no_manifest() {
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            let err = preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                false,
            )
            .expect_err("preflight must hard-error");

            let msg = format!("{err}");
            assert!(
                msg.contains("lpm init") || msg.contains("npm init"),
                "error must point at `lpm init` / `npm init -y`: {msg}"
            );
            assert!(
                msg.contains("no `package.json`") || msg.contains("no package.json"),
                "error must explain the missing manifest: {msg}"
            );
            assert!(
                msg.contains("--no-install-deps"),
                "error must surface the --no-install-deps escape hatch: {msg}"
            );
        }

        #[test]
        fn preflight_errors_when_legacy_package_json_fallback_yields_deps_and_no_consumer_manifest()
        {
            // The source ships an `lpm.config.json` without a
            // `dependencies` field but the package's own
            // `package.json` declares deps. The legacy fallback in
            // `collect_source_pkg_deps` picks those up; preflight
            // should still fire.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            std::fs::write(
                extract.path().join("package.json"),
                r#"{"name":"src-pkg","version":"1.0.0","dependencies":{"react":"^18"}}"#,
            )
            .unwrap();

            let lpm_config = serde_json::json!({ "ecosystem": "js", "files": [] });

            let err = preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &HashMap::new(),
                false,
            )
            .expect_err("preflight must catch legacy-fallback deps too");
            assert!(format!("{err}").contains("lpm init"));
        }

        #[test]
        fn preflight_passes_when_consumer_has_package_json() {
            let project = tempfile::tempdir().unwrap();
            std::fs::write(project.path().join("package.json"), "{}").unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                false,
            )
            .expect("manifest exists, preflight must pass");
        }

        #[test]
        fn preflight_passes_when_source_declares_no_deps() {
            // Files-only source package (just shadcn-style components,
            // no dep declarations) is safe to land in a no-manifest
            // project — bare imports surface separately.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({ "ecosystem": "js", "files": [] });

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &HashMap::new(),
                false,
            )
            .expect("no deps + no manifest must pass");
        }

        #[test]
        fn preflight_passes_under_no_install_deps_flag() {
            // The user explicitly opted out of dep installation, so
            // they accept responsibility for the consequences.
            // Preflight respects that and lets the run proceed.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();
            let lpm_config = serde_json::json!({
                "dependencies": {
                    "icons": { "lucide": ["lucide-react"] }
                }
            });
            let inline = HashMap::from([("icons".to_string(), "lucide".to_string())]);

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &Some(lpm_config),
                &inline,
                true, // no_install_deps
            )
            .expect("--no-install-deps must bypass preflight");
        }

        #[test]
        fn preflight_passes_for_simple_path_no_lpm_config() {
            // Simple-path tarballs (no `lpm.config.json`) intentionally
            // skip auto-install entirely; the bare-imports notice at
            // The bare-imports notice surfaces what the user needs. Preflight has
            // nothing to enforce here.
            let project = tempfile::tempdir().unwrap();
            let extract = tempfile::tempdir().unwrap();

            preflight_no_manifest_with_deps(
                project.path(),
                extract.path(),
                &None,
                &HashMap::new(),
                false,
            )
            .expect("simple-path with no lpm.config.json must pass");
        }

        // ── pm_lockfile_paths ─────────────────────────────────────────
        //
        // The per-PM lockfile snapshot list governs how broad the
        // rollback boundary is. Each arm needs its own lockfile in the
        // snapshot or an `npm install` (or pnpm/yarn/bun) partial-write
        // followed by failure leaves a manifest/lockfile split-brain.

        #[test]
        fn pm_lockfile_paths_lpm_returns_empty() {
            // `lpm.lock` and `lpm.lockb` are already snapshotted by the
            // caller (the LPM lockfiles are the manifest-tx defaults);
            // returning them here would double-list and is needless.
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("lpm", dir.path());
            assert!(paths.is_empty(), "{paths:?}");
        }

        #[test]
        fn pm_lockfile_paths_npm_returns_package_lock() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("npm", dir.path());
            assert_eq!(paths, vec![dir.path().join("package-lock.json")]);
        }

        #[test]
        fn pm_lockfile_paths_pnpm_returns_pnpm_lock_yaml() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("pnpm", dir.path());
            assert_eq!(paths, vec![dir.path().join("pnpm-lock.yaml")]);
        }

        #[test]
        fn pm_lockfile_paths_yarn_returns_yarn_lock() {
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("yarn", dir.path());
            assert_eq!(paths, vec![dir.path().join("yarn.lock")]);
        }

        #[test]
        fn pm_lockfile_paths_bun_returns_both_text_and_binary_lockfiles() {
            // bun ships both `.lock` (newer text format) and `.lockb`
            // (older binary format); which one bun writes depends on
            // version + flags. Snapshot both as optional so whichever
            // bun touches is rolled back.
            let dir = tempfile::tempdir().unwrap();
            let paths = pm_lockfile_paths("bun", dir.path());
            assert_eq!(
                paths,
                vec![dir.path().join("bun.lock"), dir.path().join("bun.lockb"),]
            );
        }

        #[test]
        fn pm_lockfile_paths_unknown_returns_empty() {
            // Defensive: `auto` is resolved to a concrete PM before the
            // snapshot, so this branch isn't reached in production.
            // But returning empty for unknown values keeps the
            // contract simple — the dispatch arm handles the unknown-
            // pm error message.
            let dir = tempfile::tempdir().unwrap();
            assert!(pm_lockfile_paths("unknown", dir.path()).is_empty());
            assert!(pm_lockfile_paths("auto", dir.path()).is_empty());
            assert!(pm_lockfile_paths("", dir.path()).is_empty());
        }
    }
}
