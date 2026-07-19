use super::*;

/// A workspace member dependency that lives at a source directory inside the
/// current workspace and must be linked locally instead of fetched from the
/// registry. Produced by [`extract_workspace_protocol_deps`] and consumed by
/// [`link_workspace_members`].
///
/// (workspace:^ resolver bug):
/// Previously, [`lpm_workspace::resolve_workspace_protocol`] rewrote
/// `"@scope/member": "workspace:^"` into `"@scope/member": "^1.5.0"` and left
/// the entry in `deps`, which then went to the registry resolver and 404'd
/// against npm/upstream because unpublished workspace members can't be fetched
/// remotely. Post-fix, [`extract_workspace_protocol_deps`] strips these
/// entries from `deps` BEFORE the resolver runs and returns them as
/// `WorkspaceMemberLink`s; [`link_workspace_members`] then symlinks them into
/// `node_modules/<name>` directly from the member's source directory after
/// the install pipeline finishes.
#[derive(Debug, Clone)]
pub(super) struct WorkspaceMemberLink {
    /// Package name as declared in the member's package.json (e.g., `@test/core`).
    pub(super) name: String,
    /// Concrete version from the member's own package.json `version` field.
    /// Used only for diagnostics — there is no resolver constraint to satisfy.
    pub(super) version: String,
    /// Absolute path to the member's source directory (the parent of its
    /// `package.json`). The post-link symlink target.
    pub(super) source_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub(super) struct DirectWorkspaceMemberProvider {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) source_dir: PathBuf,
    pub(super) source: String,
}

pub(super) struct WorkspaceInstallContext {
    pub(super) workspace: Option<lpm_workspace::Workspace>,
    pub(super) workspace_member_deps: Vec<WorkspaceMemberLink>,
    pub(super) direct_workspace_member_deps: Vec<DirectWorkspaceMemberProvider>,
    pub(super) all_workspace_members: Vec<WorkspaceMemberLink>,
    pub(super) catalog_resolutions: Vec<lpm_workspace::CatalogProtocolResolution>,
}

pub(super) fn prepare_workspace_install_context(
    project_dir: &Path,
    pkg: &lpm_workspace::PackageJson,
    deps: &mut HashMap<String, String>,
    requested_v2_mode: bool,
    json_output: bool,
) -> Result<WorkspaceInstallContext, LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();

    let (mut workspace_member_deps, catalog_resolutions) = if let Some(ref ws) = workspace {
        let extracted = extract_workspace_protocol_deps(deps, ws)?;
        if !extracted.is_empty() && !json_output {
            for member in &extracted {
                tracing::debug!(
                    "workspace member (local): {} @ {} from {}",
                    member.name,
                    member.version,
                    member.source_dir.display()
                );
            }
        }

        let catalog_resolutions =
            resolve_install_catalogs(deps, &ws.root_package.catalogs, json_output)?;
        (extracted, catalog_resolutions)
    } else {
        let catalog_resolutions = resolve_install_catalogs(deps, &pkg.catalogs, json_output)?;
        (Vec::new(), catalog_resolutions)
    };

    let all_workspace_members = all_workspace_members(workspace.as_ref());

    let overlapped_provider_sources = pre_extract_file_link_workspace_members(
        deps,
        &mut workspace_member_deps,
        &all_workspace_members,
        project_dir,
        json_output,
    );
    let direct_workspace_member_deps = workspace_member_deps
        .iter()
        .filter_map(|member| {
            let overlapped_source = overlapped_provider_sources.get(&member.name);
            if !requested_v2_mode && overlapped_source.is_none() {
                return None;
            }
            Some(DirectWorkspaceMemberProvider {
                name: member.name.clone(),
                version: member.version.clone(),
                source_dir: member.source_dir.clone(),
                source: overlapped_source
                    .cloned()
                    .unwrap_or_else(|| workspace_member_source(project_dir, &member.source_dir)),
            })
        })
        .collect();

    Ok(WorkspaceInstallContext {
        workspace,
        workspace_member_deps,
        direct_workspace_member_deps,
        all_workspace_members,
        catalog_resolutions,
    })
}

fn resolve_install_catalogs(
    deps: &mut HashMap<String, String>,
    catalogs: &HashMap<String, HashMap<String, String>>,
    json_output: bool,
) -> Result<Vec<lpm_workspace::CatalogProtocolResolution>, LpmError> {
    if catalogs.is_empty() {
        return Ok(Vec::new());
    }

    let resolved = lpm_workspace::resolve_catalog_protocol(deps, catalogs)
        .map_err(catalog_protocol_error_to_lpm)?;
    if !resolved.is_empty() && !json_output {
        for entry in &resolved {
            tracing::debug!("catalog: {} -> {}", entry.package_name, entry.specifier);
        }
    }
    Ok(resolved)
}

fn all_workspace_members(workspace: Option<&lpm_workspace::Workspace>) -> Vec<WorkspaceMemberLink> {
    workspace
        .map(|ws| {
            ws.members
                .iter()
                .filter_map(|m| {
                    let name = m.package.name.as_deref()?.to_string();
                    let version = m.package.version.as_deref().unwrap_or("0.0.0").to_string();
                    Some(WorkspaceMemberLink {
                        name,
                        version,
                        source_dir: m.path.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Interactive confirmation for multi-member workspace mutations.
///
/// Prints the target set (always, in human mode) and asks "Proceed? [y/N]"
/// only when every precondition for a genuinely-interactive run is met:
/// `yes` flag is false, `json_output` is false, and stdin is a real TTY.
/// Any one of those being true bypasses the prompt without error — the
/// preview still prints so terminal users and log readers see what's about
/// to happen.
///
/// Returns `Err(LpmError::Script)` with a clear "aborted by user" message
/// when the user declines, so callers propagate via `?` and no manifest is
/// touched. I/O errors on stdin fall through to abort for safety.
///
/// closes the gap between the
/// original plan (which specified a prompt) and the initial ship
/// (which was preview-only). See the install step status doc's entry.
pub(crate) fn confirm_multi_member_mutation(
    verb: &str,
    package_count: usize,
    manifests: &[PathBuf],
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    use std::io::{BufRead, IsTerminal, Write};

    // Preview line: print in human mode regardless of prompt path so users
    // still see the target set even when `--yes` or CI skips the prompt.
    if !json_output {
        output::info(&format!(
            "{} {} package(s) across {} workspace member(s):",
            verb,
            package_count,
            manifests.len(),
        ));
        for path in manifests {
            let label = path.parent().and_then(|p| p.file_name()).map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().to_string(),
            );
            println!("  {}", label.dimmed());
        }
    }

    // Three bypass paths, in order of decreasing "caller intent": explicit
    // `--yes`, JSON mode, and non-interactive stdin. Any of them skip the
    // prompt entirely. The preview above already ran, so the user still has
    // a paper trail of what we mutated.
    if yes || json_output || !std::io::stdin().is_terminal() {
        return Ok(());
    }

    // Interactive prompt. Default is No — a blank enter aborts, matching
    // every destructive prompt in the codebase.
    let prompt = format!(
        "Proceed with {} {} package(s) across {} members? [y/N] ",
        verb.to_lowercase(),
        package_count,
        manifests.len(),
    );
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => {
            // EOF or I/O error — treat as decline for safety.
            return Err(LpmError::Script(
                "aborted: no input received on stdin (use `--yes` to skip the confirmation)".into(),
            ));
        }
        Ok(_) => {}
    }
    let answer = line.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err(LpmError::Script(format!(
            "aborted by user; no package.json was modified. Pass `--yes` / `-y` to \
             skip this prompt in scripts (got: {:?})",
            line.trim()
        )))
    }
}

/// Strip `workspace:*` / `workspace:^` / `workspace:~` / `workspace:<exact>`
/// dependencies from `deps` and return them as a list of locally-resolvable
/// links. The resolver never sees these entries — they bypass the registry
/// entirely and are linked from disk by [`link_workspace_members`].
///
/// this replaces the previous
/// "[`lpm_workspace::resolve_workspace_protocol`] rewrites in place, then the
/// resolver fetches from the registry" pattern, which 404'd whenever a
/// workspace member was unpublished (the common case in monorepos that
/// internally develop libraries before any release).
///
/// Returns `Err(LpmError::Workspace)` if a `workspace:` reference points at a
/// package name that is not in the workspace's discovered member list. This
/// preserves the validation behavior of `resolve_workspace_protocol` so that
/// typos in cross-member deps still hard-error instead of silently shipping
/// no dependency.
///
/// Members are matched by their declared `package.json` `name` field, not by
/// directory name. The version field is read from the member's own
/// `package.json` (defaulting to `0.0.0` if absent, mirroring how
/// `resolve_workspace_protocol` handled the same case).
pub(super) fn extract_workspace_protocol_deps(
    deps: &mut HashMap<String, String>,
    workspace: &lpm_workspace::Workspace,
) -> Result<Vec<WorkspaceMemberLink>, LpmError> {
    // First pass: identify the names of workspace: entries. We can't mutate
    // `deps` while iterating it, so we collect the names + their original
    // protocol strings, then validate + remove in a second pass.
    let mut workspace_names: Vec<(String, String)> = deps
        .iter()
        .filter(|(_, range)| range.starts_with("workspace:"))
        .map(|(name, range)| (name.clone(), range.clone()))
        .collect();

    // Deterministic order so the returned list (and any error message) is
    // stable for tests + JSON output. HashMap iteration order is randomized.
    workspace_names.sort_by(|a, b| a.0.cmp(&b.0));

    if workspace_names.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(workspace_names.len());
    for (name, range) in &workspace_names {
        let member = workspace
            .members
            .iter()
            .find(|m| m.package.name.as_deref() == Some(name.as_str()))
            .ok_or_else(|| {
                let mut available: Vec<&str> = workspace
                    .members
                    .iter()
                    .filter_map(|m| m.package.name.as_deref())
                    .collect();
                available.sort();
                let available_str = if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                };
                LpmError::Workspace(format!(
                    "{range} references package '{name}' which is not a workspace member. \
                     Available members: {available_str}"
                ))
            })?;

        let version = member
            .package
            .version
            .as_deref()
            .unwrap_or("0.0.0")
            .to_string();

        extracted.push(WorkspaceMemberLink {
            name: name.clone(),
            version,
            source_dir: member.path.clone(),
        });
    }

    // Validation passed for every entry — now remove them from `deps`.
    for (name, _) in &workspace_names {
        deps.remove(name);
    }

    Ok(extracted)
}

pub(super) fn reject_workspace_self_dependency(
    pkg: &lpm_workspace::PackageJson,
) -> Result<(), LpmError> {
    let Some(package_name) = pkg.name.as_deref() else {
        return Ok(());
    };

    for (section, deps) in [
        ("dependencies", &pkg.dependencies),
        ("devDependencies", &pkg.dev_dependencies),
        ("peerDependencies", &pkg.peer_dependencies),
        ("optionalDependencies", &pkg.optional_dependencies),
    ] {
        let Some(spec) = deps.get(package_name) else {
            continue;
        };
        if spec.starts_with("workspace:") {
            return Err(LpmError::Workspace(format!(
                "workspace member `{package_name}` depends on itself via {section}.{package_name} = `{spec}`"
            )));
        }
    }

    Ok(())
}

pub(super) fn workspace_member_cache_info(
    member: &WorkspaceMemberLink,
) -> Result<Option<lpm_resolver::CachedPackageInfo>, LpmError> {
    let Some(version) = lpm_resolver::NpmVersion::parse(&member.version).ok() else {
        return Ok(None);
    };
    let pkg_json_path = member.source_dir.join("package.json");
    let Ok(pkg) = lpm_workspace::read_package_json(&pkg_json_path) else {
        return Ok(None);
    };
    let version_str = version.to_string();

    let mut deps = HashMap::with_capacity(pkg.dependencies.len() + pkg.optional_dependencies.len());
    let mut aliases = HashMap::new();
    let mut optional_names = HashSet::with_capacity(pkg.optional_dependencies.len());
    {
        let mut insert_dep = |local_name: String, raw_spec: String| -> Result<(), LpmError> {
            let effective_spec = lpm_resolver::normalize_jsr_dependency(&local_name, &raw_spec)
                .map_err(|err| {
                    LpmError::Workspace(format!(
                        "workspace member `{}` dependency `{local_name}` has invalid spec \
                         `{raw_spec}` in {}: {err}",
                        member.name,
                        pkg_json_path.display(),
                    ))
                })?
                .unwrap_or(raw_spec);

            match lpm_resolver::ranges::parse_npm_alias(&effective_spec) {
                Some(alias) => {
                    aliases.insert(local_name.clone(), alias.target);
                    deps.insert(local_name, alias.range);
                }
                None => {
                    deps.insert(local_name, effective_spec);
                }
            }
            Ok(())
        };
        for (name, spec) in pkg.dependencies {
            insert_dep(name, spec)?;
        }
        for (name, spec) in pkg.optional_dependencies {
            optional_names.insert(name.clone());
            insert_dep(name, spec)?;
        }
    }

    let mut deps_by_version = HashMap::with_capacity(1);
    deps_by_version.insert(version_str.clone(), deps);

    let mut peer_deps = HashMap::new();
    if !pkg.peer_dependencies.is_empty() {
        peer_deps.insert(
            version_str.clone(),
            pkg.peer_dependencies
                .into_iter()
                .map(|(name, raw)| {
                    let spec = lpm_resolver::PeerDependencySpec::new(&name, raw);
                    (name, spec)
                })
                .collect(),
        );
    }

    let mut optional_dep_names = HashMap::new();
    if !optional_names.is_empty() {
        optional_dep_names.insert(version_str.clone(), optional_names);
    }

    let mut optional_peer_names = HashMap::new();
    let optional_peers: HashSet<String> = pkg
        .peer_dependencies_meta
        .into_iter()
        .filter_map(|(name, meta)| meta.optional.then_some(name))
        .collect();
    if !optional_peers.is_empty() {
        optional_peer_names.insert(version_str.clone(), optional_peers);
    }

    let mut aliases_by_version = HashMap::new();
    if !aliases.is_empty() {
        aliases_by_version.insert(version_str.clone(), aliases);
    }

    let mut node_engines = HashMap::new();
    if let Some(required) = pkg.engines.get("node") {
        node_engines.insert(version_str.clone(), required.clone());
    }

    let mut dist = HashMap::with_capacity(1);
    dist.insert(version_str, lpm_resolver::CachedDistInfo::default());

    Ok(Some(lpm_resolver::CachedPackageInfo {
        // Local workspace metadata is authoritative; avoid registry upgrade probes under policy checks.
        modified: Some("1970-01-01T00:00:00.000Z".to_string()),
        modified_unix: Some(0),
        trust_metadata_complete: true,
        versions_complete: true,
        covered_ranges: std::collections::HashSet::new(),
        latest_version: None,
        versions: vec![version],
        deps: deps_by_version,
        peer_deps,
        optional_dep_names,
        optional_peer_names,
        node_engines,
        bundled_dep_names: HashMap::new(),
        platform: HashMap::new(),
        dist,
        aliases: aliases_by_version,
    }))
}

pub(super) fn seed_workspace_resolver_cache(
    shared_cache: &lpm_resolver::SharedCache,
    members: &[WorkspaceMemberLink],
) -> Result<(), LpmError> {
    for member in members {
        let Some(info) = workspace_member_cache_info(member)? else {
            continue;
        };
        let key = lpm_resolver::CanonicalKey::from_dep_name(&member.name);
        shared_cache.insert(key, Arc::new(info));
    }
    Ok(())
}

pub(super) fn workspace_member_source(project_dir: &Path, source_dir: &Path) -> String {
    let source_path =
        pathdiff::diff_paths(source_dir, project_dir).unwrap_or_else(|| source_dir.to_path_buf());
    let source = source_path.to_string_lossy().replace('\\', "/");
    format!("directory+{source}")
}

pub(super) fn rewrite_workspace_resolved_sources(
    packages: &mut [InstallPackage],
    workspace_members: &[WorkspaceMemberLink],
    project_dir: &Path,
) {
    if workspace_members.is_empty() {
        return;
    }
    let members_by_name: HashMap<&str, &WorkspaceMemberLink> = workspace_members
        .iter()
        .map(|member| (member.name.as_str(), member))
        .collect();

    for package in packages {
        let Some(member) = members_by_name.get(package.name.as_str()) else {
            continue;
        };
        if package.version != member.version {
            continue;
        }
        package.source = workspace_member_source(project_dir, &member.source_dir);
        package.is_lpm = false;
        package.integrity = None;
        package.tarball_url = None;
        package.metadata_checked_for_tarball = false;
    }
}

pub(super) fn append_workspace_links_from_local_packages(
    project_dir: &Path,
    packages: &[InstallPackage],
    workspace_member_deps: &mut Vec<WorkspaceMemberLink>,
    all_workspace_members: &[WorkspaceMemberLink],
    skip_workspace_members: &[DirectWorkspaceMemberProvider],
) {
    if all_workspace_members.is_empty() {
        return;
    }
    let canonicalize_path = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let skipped: HashSet<(String, PathBuf)> = skip_workspace_members
        .iter()
        .map(|m| (m.name.clone(), canonicalize_path(&m.source_dir)))
        .collect();
    let mut seen: HashSet<(String, PathBuf)> = workspace_member_deps
        .iter()
        .map(|m| (m.name.clone(), canonicalize_path(&m.source_dir)))
        .collect();

    for package in packages {
        let Ok(source) = package.source_kind() else {
            continue;
        };
        let local_path = match source {
            lpm_lockfile::Source::Directory { path } | lpm_lockfile::Source::Link { path } => {
                project_dir.join(path)
            }
            _ => continue,
        };
        let canonical_source = canonicalize_path(&local_path);
        let Some(member) = all_workspace_members.iter().find(|member| {
            member.name == package.name
                && member.version == package.version
                && canonicalize_path(&member.source_dir) == canonical_source
        }) else {
            continue;
        };
        if skipped.contains(&(member.name.clone(), canonical_source.clone())) {
            continue;
        }
        if seen.insert((member.name.clone(), canonical_source)) {
            workspace_member_deps.push(member.clone());
        }
    }
}

pub(super) fn merge_workspace_member_links(
    workspace_member_deps: &mut Vec<WorkspaceMemberLink>,
    links: impl IntoIterator<Item = WorkspaceMemberLink>,
) {
    let canonicalize_path = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let mut seen: HashSet<(String, PathBuf)> = workspace_member_deps
        .iter()
        .map(|m| (m.name.clone(), canonicalize_path(&m.source_dir)))
        .collect();

    for entry in links {
        let key = (entry.name.clone(), canonicalize_path(&entry.source_dir));
        if seen.insert(key) {
            workspace_member_deps.push(entry);
        }
    }
}

///
///
/// Walk root deps for `file:` / `link:` specs whose target realpaths
/// to a workspace member. For each match: REMOVE the entry from
/// `deps` (so the resolver / lockfile fast-path doesn't see a "root
/// dep with no lockfile entry"), and APPEND a `WorkspaceMemberLink`
/// to `workspace_member_deps` under the consumer's local name (so
/// `link_workspace_members` plants `node_modules/<local>` at the
/// project root).
///
/// Pre-the invariant the dedupe lived inside
/// `pre_resolve_non_registry_deps`, which only runs on the ONLINE
/// install path. The offline path bailed because:
/// - `try_lockfile_fast_path`'s "every root dep has a lockfile
///   entry" check failed (the -deduped dep was never written to
///   the lockfile during the online run).
/// - Without the user saw the misleading "—offline requires a
///   lockfile" error even though their lockfile existed and was
///   fresh.
///
/// Running this pre-pass BEFORE the offline/online dispatch makes
/// both modes converge on the same `(deps, workspace_member_deps)`
/// shape. The online path's pre_resolve still runs dedupe on
/// transitive file:/link: deps inside member manifests — that
/// branch is unchanged because it operates one layer deeper.
///
/// Dedupe key for `workspace_member_deps`: `(local_name, canonical
/// source_dir)`. Aliased references where two distinct local names
/// resolve to the same member source dir get distinct entries so
/// each gets its own `node_modules/<local>` symlink.
pub(super) fn pre_extract_file_link_workspace_members(
    deps: &mut HashMap<String, String>,
    workspace_member_deps: &mut Vec<WorkspaceMemberLink>,
    all_workspace_members: &[WorkspaceMemberLink],
    project_dir: &Path,
    json_output: bool,
) -> HashMap<String, String> {
    if all_workspace_members.is_empty() {
        return HashMap::new();
    }
    // Canonicalize where possible; fall back to the lexical path on
    // error (EACCES, ENOENT on intermediate components, broken symlink
    // somewhere in the chain). **Invariant invariant — the fallback
    // is deliberately safe in one direction only:** a non-canonicalizable
    // path can't match a successfully-canonicalized member's path
    // (different shape), so dedupe correctly skips it and the dep
    // flows through normal pre_resolve as a directory-source
    // InstallPackage. Worst case is a duplicate symlink (member + extra
    // wrapper at the same name), never a missing dep. Tightening this
    // to a hard error would break workspaces whose members live behind
    // permission-restricted intermediate dirs (rare but real on
    // monorepo CI).
    let canonicalize_path = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    // Pre-canonicalize each member's source_dir once for the realpath
    // comparison loop. For a typical workspace (≤100 members) this is
    // ≤100 syscalls regardless of the number of root deps.
    let canonical_members: Vec<(PathBuf, &WorkspaceMemberLink)> = all_workspace_members
        .iter()
        .map(|m| (canonicalize_path(&m.source_dir), m))
        .collect();

    let mut to_remove: Vec<(String, WorkspaceMemberLink, String)> = Vec::new();
    for (local_name, raw) in deps.iter() {
        let path_str = if let Some(p) = raw.strip_prefix("file:") {
            p
        } else if let Some(p) = raw.strip_prefix("link:") {
            p
        } else {
            continue;
        };
        let abs = project_dir.join(path_str);
        let Ok(realpath) = abs.canonicalize() else {
            continue;
        };
        // Only `file:` deps that target a directory participate in
        // (file: tarballs are content-integrity-locked, never workspace
        // members). `link:` always targets a directory.
        if raw.starts_with("file:") {
            let Ok(meta) = std::fs::metadata(&realpath) else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
        }
        let Some((_, matched)) = canonical_members.iter().find(|(p, _)| *p == realpath) else {
            continue;
        };
        to_remove.push((
            local_name.clone(),
            WorkspaceMemberLink {
                name: local_name.clone(),
                version: matched.version.clone(),
                source_dir: matched.source_dir.clone(),
            },
            raw.clone(),
        ));
    }

    // Apply the extraction: remove the dep + push the member link
    // (deduped against existing workspace_member_deps).
    let existing: std::collections::HashSet<(String, PathBuf)> = workspace_member_deps
        .iter()
        .map(|m| (m.name.clone(), canonicalize_path(&m.source_dir)))
        .collect();
    let mut seen = existing;
    let mut provider_sources = HashMap::with_capacity(to_remove.len());
    for (dep_name, member_link, raw_spec) in to_remove {
        deps.remove(&dep_name);
        let source = if let Some(path) = raw_spec.strip_prefix("file:") {
            format!("directory+{path}")
        } else if let Some(path) = raw_spec.strip_prefix("link:") {
            format!("link+{path}")
        } else {
            continue;
        };
        provider_sources.insert(dep_name.clone(), source);
        let key = (
            member_link.name.clone(),
            canonicalize_path(&member_link.source_dir),
        );
        if seen.insert(key) {
            if !json_output {
                output::info(&format!(
                    "note: file/link dep '{dep_name}' ({raw_spec}) resolves to workspace \
                     member '{}'; using workspace symlink instead",
                    member_link.name,
                ));
            }
            workspace_member_deps.push(member_link);
        }
    }
    provider_sources
}

///
///
/// BFS over `workspace_member_deps` (the seed set: extracted top-
/// level + any / the invariant additions merged in by the caller),
/// reading each member's `package.json` and following every
/// `workspace:` dep to its target in `all_workspace_members`. New
/// targets are appended to `workspace_member_deps` and enqueued so
/// chains like `root → foo (workspace:*) → bar (workspace:*) → baz
/// (workspace:*)` all end up root-linked.
///
/// **Round 5 (online path)** added this BFS after pre_resolve +
/// merge of `additional_workspace_links`. **Round 6** factored it
/// into a helper so the offline path can run it too — pre-the invariant
/// `run_link_and_finish` received the EXTRACTED top-level slice
/// directly and missed transitive `workspace:` refs entirely. The
/// regression reproduced this with `lpm install --offline`: a workspace
/// where root depends on foo via `workspace:*` and foo's manifest
/// declares `bar: workspace:*` — online install planted both root
/// symlinks, offline install planted only `foo`.
///
/// **Invariant invariant — `(name, realpath)` dedupe + fail-closed
/// on ghost members.** Pre-the invariant this BFS dedupe-keyed by canonical
/// source path alone. That regressed the the invariant alias contract: if
/// the consumer aliases a workspace member through `file:` (root has
/// `"aliasfoo": "file:./packages/foo"`) AND a different member has
/// a transitive `workspace:` ref to the canonical name (bar's pkg.json
/// declares `"foo": "workspace:*"`), the seed set already contained
/// foo's realpath under the alias name, so the BFS skipped queueing
/// the canonical `node_modules/foo` link. `require('foo')` from
/// inside bar then failed at runtime. Invariant keys visited by
/// `(name, canonical realpath)` matching `pre_extract_file_link_workspace_members`'s
/// dedupe (install.rs ~628) so distinct local names for the same
/// member realpath each get their own root symlink.
///
/// Pre-the invariant the BFS also silently skipped transitive `workspace:`
/// refs that didn't match any member. That's inconsistent with both
/// `extract_workspace_protocol_deps` (root, errors) and
/// `recurse_local_source_deps`'s the invariant reject (transitive
/// file:/link: walker, errors). Invariant errors with the same shape
/// as the the invariant reject — available-member list + source manifest
/// path — so misconfigured workspace graphs fail at install time
/// rather than break at runtime.
pub(super) fn expand_workspace_member_deps_with_transitives(
    workspace_member_deps: &mut Vec<WorkspaceMemberLink>,
    all_workspace_members: &[WorkspaceMemberLink],
) -> Result<(), LpmError> {
    if all_workspace_members.is_empty() {
        return Ok(());
    }
    let canonicalize_path = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    // Visited key: `(local_name, canonical realpath)`. Distinct local
    // names sharing one source dir (alias case — e.g.,
    // `"aliasfoo": "file:./packages/foo"` plus `"foo": "workspace:*"`)
    // each carry their own entry so `link_workspace_members` plants
    // both `node_modules/aliasfoo` and `node_modules/foo`. Same as
    // the dedupe shape in `pre_extract_file_link_workspace_members`.
    let mut visited: std::collections::HashSet<(String, PathBuf)> = workspace_member_deps
        .iter()
        .map(|m| (m.name.clone(), canonicalize_path(&m.source_dir)))
        .collect();
    let mut queue: std::collections::VecDeque<WorkspaceMemberLink> =
        workspace_member_deps.iter().cloned().collect();
    while let Some(member) = queue.pop_front() {
        let pkg_json_path = member.source_dir.join("package.json");
        let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        for field in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            let Some(deps_obj) = value.get(field).and_then(|v| v.as_object()) else {
                continue;
            };
            for (local_name, raw) in deps_obj {
                let Some(raw_s) = raw.as_str() else {
                    continue;
                };
                if !raw_s.starts_with("workspace:") {
                    continue;
                }
                let Some(target_member) =
                    all_workspace_members.iter().find(|m| m.name == *local_name)
                else {
                    // **Invariant invariant — fail closed.** Mirror
                    // the the invariant reject in `recurse_local_source_deps`
                    // (file:/link: walker) so unresolved transitive
                    // `workspace:` refs surface a typed error at the
                    // manifest-read boundary instead of producing a
                    // silent success with missing root symlinks.
                    let mut available: Vec<&str> = all_workspace_members
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect();
                    available.sort();
                    let available_str = if available.is_empty() {
                        "(this project is not a workspace)".to_string()
                    } else {
                        available.join(", ")
                    };
                    return Err(LpmError::Workspace(format!(
                        "transitive `workspace:` dep `{}` (\"{}\") declared in {} \
                         references package `{}` which is not a workspace member. \
                         Available members: {}. Workspace transitives only resolve \
                         when the named package is a workspace member.",
                        local_name,
                        raw_s,
                        pkg_json_path.display(),
                        local_name,
                        available_str,
                    )));
                };
                let canonical = canonicalize_path(&target_member.source_dir);
                let key = (local_name.clone(), canonical);
                if !visited.insert(key) {
                    continue;
                }
                let entry = WorkspaceMemberLink {
                    name: local_name.clone(),
                    version: target_member.version.clone(),
                    source_dir: target_member.source_dir.clone(),
                };
                workspace_member_deps.push(entry.clone());
                queue.push_back(entry);
            }
        }
    }
    Ok(())
}

pub(super) fn enforce_required_workspace_member_engines(
    workspace_member_deps: &[WorkspaceMemberLink],
    policy: &crate::engine_check::DependencyEnginePolicy,
) -> Result<(), LpmError> {
    let mut checked_sources = HashSet::with_capacity(workspace_member_deps.len());
    for member in workspace_member_deps {
        if !checked_sources.insert(member.source_dir.as_path()) {
            continue;
        }
        let Some(required) = read_pkg_json_node_engine(
            &member.source_dir,
            &format!("workspace member at {}", member.source_dir.display()),
        )?
        else {
            continue;
        };
        policy.enforce_dependency(&member.name, &member.version, &required, false)?;
    }
    Ok(())
}

/// Symlink workspace member dependencies into `<project_dir>/node_modules/<name>`.
///
/// Called AFTER `link_packages` (or `link_packages_hoisted`) so that the
/// linker's stale-symlink cleanup pass — which removes any
/// `node_modules/<name>` entry not in `direct_names` — has already run. Our
/// workspace symlinks are not in `direct_names` because workspace members are
/// stripped from `deps` before resolution by [`extract_workspace_protocol_deps`],
/// so they would be wiped on every install if we created them BEFORE the
/// linker. The post-link order also means the helper has to be idempotent
/// across re-runs (it cleans any pre-existing entry at the link path).
///
/// Convert one
/// [`patch_engine::AppliedPatch`] into the persisted state-file shape,
/// rewriting absolute paths to project-dir-relative for portability.
/// Pulls `original_integrity` straight from the engine result so the
/// state file (and `lpm graph --why`) carries the actual hash, not a
/// placeholder.
/// Returns the number of symlinks created.
pub(super) fn link_workspace_members(
    project_dir: &Path,
    members: &[WorkspaceMemberLink],
) -> Result<usize, LpmError> {
    if members.is_empty() {
        return Ok(0);
    }

    let mut node_modules_roots = vec![project_dir.join("node_modules")];
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir)
        && workspace.root != project_dir
    {
        node_modules_roots.push(workspace.root.join("node_modules"));
    }

    for node_modules in &node_modules_roots {
        std::fs::create_dir_all(node_modules).map_err(LpmError::Io)?;
    }

    let mut linked = 0usize;
    for member in members {
        for node_modules in &node_modules_roots {
            lpm_linker::link_workspace_member(node_modules, &member.name, &member.source_dir)
                .map_err(|e| {
                    LpmError::Workspace(format!(
                        "failed to link workspace member {}: {e}",
                        member.name
                    ))
                })?;
        }
        linked += 1;
    }
    Ok(linked)
}
