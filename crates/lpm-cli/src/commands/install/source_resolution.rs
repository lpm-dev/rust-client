use super::*;

/// disambiguates a `file:` target
/// after the pre-flight stat. Cached in [`pre_resolve_non_registry_deps`]
/// so the dispatch step doesn't re-stat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileKindClassification {
    /// Regular file → local-tarball arm.
    Tarball,
    /// Directory → directory-dep arm.
    Directory,
}

/// the kind of a single
/// transitive dep declared inside a local source's `package.json`.
///
/// Used by [`pre_resolve_non_registry_deps`] to:
/// - Append registry deps to the consumer's `deps` map (so the
///   resolver — PubGrub or fusion — picks them up).
/// - Recursively pre-resolve `Directory`/`Link` deps into nested
///   wrappers under `.lpm/`.
/// - Drive the post-resolve fix-up of `InstallPackage.dependencies`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DepKind {
    /// Registry-style spec — `^1.2.3`, `npm:foo@^1`, `latest`,
    /// etc. Pubgrub/fusion handles it.
    Registry,
    /// `workspace:` protocol. v1/local-source installs resolve this
    /// through a project-root workspace symlink; v2 direct workspace
    /// installs promote it to a source-backed graph edge.
    Workspace,
    /// `file:` directory dep (the path is a directory). For -
    /// transitive purposes, file: tarballs are NOT included — they
    /// don't contribute to the wrapper-target resolution and
    /// they're already integrity-locked elsewhere.
    FileDir,
    /// `link:` dep (always a directory).
    Link,
}

/// a single dep entry from a
/// local source's `package.json`. Captured during pre-resolve so the
/// post-resolve fix-up can populate the parent
/// `InstallPackage.dependencies` field with resolved versions.
///
#[derive(Debug, Clone)]
pub(super) struct SourceDep {
    /// The dep KEY as it appears in the source's `package.json`.
    /// What `require(local_name)` from inside the source uses.
    pub(super) local_name: String,
    /// Raw spec string from the source's package.json
    /// (`"^1.2.3"`, `"file:./util"`, `"link:../foo"`, etc.).
    pub(super) raw_spec: String,
    /// Classification used to drive both the recursive pre-resolve
    /// and the post-resolve fix-up.
    pub(super) kind: DepKind,
    /// Whether this edge was declared in `optionalDependencies`.
    pub(super) optional: bool,
    /// Exact `InstallPackage::source` string for a resolved
    /// directory/link target. Registry-style dependencies leave this
    /// empty and resolve through the registry package index.
    pub(super) target_source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkspaceTransitiveMode {
    RootSymlinkOnly,
    SourceGraph,
}

/// return shape for
/// [`pre_resolve_non_registry_deps`].
///
/// Carries the immediate non-registry InstallPackages PLUS a
/// per-package side-band map of source-deps consumed by the
/// post-resolve fix-up at install.rs:2663+ (resolver-agnostic per
/// of the plan doc).
///
/// The `source_deps` map is keyed by the InstallPackage's `source`
/// field (e.g., `"directory+./packages/foo"`) — unique across the
/// entire pre-resolve output even when two paths produce the same
/// `name@version`. Registry InstallPackages are not in the map
/// (their dependencies are populated by the resolver).
///
/// The
/// `additional_workspace_links` field carries every workspace member
/// the pre_resolve pass discovered through overlap detection
/// (immediate file:/link: arms + transitive walker) OR through the
/// the invariant transitive `workspace:` arm. Pre-the invariant, those code paths
/// silently SKIPPED InstallPackage construction (relying on the
/// existing top-level extracted set via `link_workspace_members` to
/// plant the root symlink) — but the extracted set only contains
/// members the consumer's manifest explicitly referenced via
/// `workspace:*`. The regression reproduced two end-to-end breakages:
///
/// 1. Root depends on `foo` via `file:./packages/foo` and `foo` is a
///    workspace member: dedupe fired, install exited 0, but
///    `node_modules/foo` was missing.
/// 2. Root depends on `foo` via `workspace:*` and foo's manifest
///    declares `bar: workspace:*` (sibling member): install
///    succeeded, `node_modules/foo` existed, `node_modules/bar` did
///    NOT — runtime resolution of `bar` from inside foo fails.
///
/// Invariant fix: pre_resolve now collects every member it deduped or
/// matched into this field. The caller at the install-pipeline level
/// merges it into `workspace_member_deps` before passing to
/// `link_workspace_members`, dedup'd by `(name, realpath)`. Empty
/// for non-workspace projects.
#[derive(Debug)]
pub(super) struct NonRegistryPreResolveResult {
    pub(super) install_pkgs: Vec<InstallPackage>,
    /// `source_string → list of (local_name, raw_spec, kind)`. Used
    /// by [`apply_post_resolve_directory_link_fixup`] to fill in
    /// each directory/link InstallPackage's `dependencies` field.
    pub(super) source_deps: HashMap<String, Vec<SourceDep>>,
    /// Workspace members discovered through dedupe or the the invariant
    /// transitive `workspace:` arm. Each entry's `name` is the LOCAL
    /// name (the parent's dep key) so `link_workspace_members`
    /// creates `node_modules/<local>` rather than
    /// `node_modules/<canonical>` — matches consumer expectation
    /// when the local name aliases the workspace member.
    pub(super) additional_workspace_links: Vec<WorkspaceMemberLink>,
    pub(super) optional_registry_roots: HashSet<String>,
}

#[derive(Debug, Default)]
pub(super) struct V2WorkspaceRootPreResolveResult {
    pub(super) install_pkgs: Vec<InstallPackage>,
    pub(super) source_deps: HashMap<String, Vec<SourceDep>>,
    pub(super) additional_workspace_links: Vec<WorkspaceMemberLink>,
    pub(super) optional_registry_roots: HashSet<String>,
}

#[derive(Debug, Default)]
pub(super) struct LocalSourceExpansionResult {
    pub(super) source_deps: HashMap<String, Vec<SourceDep>>,
    pub(super) additional_workspace_links: Vec<WorkspaceMemberLink>,
}

#[derive(Debug, Default)]
struct RegistryRootOptionality {
    optional: HashSet<String>,
    required: HashSet<String>,
}

pub(super) struct InstallRoutingContext {
    pub(super) route_table: RouteTable,
    pub(super) eager_origins: Vec<lpm_registry::OriginKey>,
    pub(super) setup_route_table_ms: u128,
}

pub(super) fn prepare_install_routing_context(
    project_dir: &Path,
    deps: &HashMap<String, String>,
    client: &RegistryClient,
    pkg_name: &str,
    is_add_invocation: bool,
    json_output: bool,
) -> Result<InstallRoutingContext, LpmError> {
    let setup_route_t = Instant::now();
    let route_table = lpm_registry::RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;
    let setup_route_table_ms = setup_route_t.elapsed().as_millis();

    if !json_output {
        for warning in route_table.npmrc_warnings() {
            output::warn(warning);
        }
    }
    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
             DISABLED for this install across ALL registries. This is a \
             security risk.",
            tagged.source, tagged.line
        ));
    }
    for warning in route_table.npmrc_security_warnings() {
        output::warn(warning);
    }

    let top_level_specs = top_level_registry_specs(deps);
    let eager_origins = route_table.effective_registry_origins(
        &top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );
    maybe_emit_install_resolving_phase(
        client,
        pkg_name,
        &eager_origins,
        is_add_invocation,
        json_output,
    );

    Ok(InstallRoutingContext {
        route_table,
        eager_origins,
        setup_route_table_ms,
    })
}

fn top_level_registry_specs(deps: &HashMap<String, String>) -> Vec<String> {
    deps.iter()
        .filter_map(
            |(local_name, range)| match lpm_resolver::Specifier::parse(range) {
                Ok(lpm_resolver::Specifier::SemverRange(_)) => Some(local_name.clone()),
                Ok(lpm_resolver::Specifier::NpmAlias { target, .. }) => Some(target),
                _ => None,
            },
        )
        .collect()
}

fn maybe_emit_install_resolving_phase(
    client: &RegistryClient,
    pkg_name: &str,
    eager_origins: &[lpm_registry::OriginKey],
    is_add_invocation: bool,
    json_output: bool,
) {
    if json_output {
        return;
    }

    let hosts_label = if eager_origins.is_empty() {
        install_ui::yellow(&install_ui::short_registry_host(client.base_url()))
    } else {
        eager_origins
            .iter()
            .map(|origin| {
                let host = origin
                    .host_lower
                    .strip_prefix("registry.")
                    .unwrap_or(&origin.host_lower)
                    .to_owned();
                install_ui::yellow(&host)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let line = if is_add_invocation {
        format!("Resolving dependencies from {hosts_label}")
    } else {
        format!(
            "Resolving dependencies from {hosts_label} for {}",
            install_ui::bold(pkg_name)
        )
    };
    install_ui::phase(&line);
}

pub(super) fn configure_install_client_for_routing(
    client: &RegistryClient,
    route_table: &RouteTable,
    eager_origins: &[lpm_registry::OriginKey],
    json_output: bool,
) -> Result<RegistryClient, LpmError> {
    let owned_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), eager_origins)?;
    if !json_output && let Some(line) = owned_client.render_effective_tls_summary() {
        output::info(&line);
    }
    Ok(owned_client)
}

pub(super) fn expand_local_source_install_packages(
    project_dir: &Path,
    deps: &mut HashMap<String, String>,
    install_pkgs: &mut Vec<InstallPackage>,
    workspace_members: &[WorkspaceMemberLink],
    json_output: bool,
    workspace_transitives: WorkspaceTransitiveMode,
) -> Result<LocalSourceExpansionResult, LpmError> {
    let mut source_deps_out: HashMap<String, Vec<SourceDep>> = HashMap::new();
    let mut visited_realpaths: HashMap<PathBuf, String> =
        HashMap::with_capacity(install_pkgs.len());
    for p in &*install_pkgs {
        if let Ok(s) = p.source_kind() {
            let path_opt = match s {
                lpm_lockfile::Source::Directory { path } => Some(path),
                lpm_lockfile::Source::Link { path } => Some(path),
                _ => None,
            };
            if let Some(path) = path_opt
                && let Ok(rp) = project_dir.join(&path).canonicalize()
            {
                visited_realpaths
                    .entry(rp)
                    .or_insert_with(|| p.source.clone());
            }
        }
    }

    let immediate_dir_link: Vec<(String, PathBuf)> = install_pkgs
        .iter()
        .filter_map(|p| match p.source_kind() {
            Ok(lpm_lockfile::Source::Directory { path }) => {
                Some((p.source.clone(), project_dir.join(path)))
            }
            Ok(lpm_lockfile::Source::Link { path }) => {
                Some((p.source.clone(), project_dir.join(path)))
            }
            _ => None,
        })
        .collect();

    let mut node_modules_warned: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();
    let mut additional_workspace_links: Vec<WorkspaceMemberLink> = Vec::new();
    for (parent_source_string, parent_abs) in immediate_dir_link {
        let Ok(realpath) = parent_abs.canonicalize() else {
            continue;
        };
        recurse_local_source_deps(
            project_dir,
            &realpath,
            &parent_source_string,
            deps,
            install_pkgs,
            &mut source_deps_out,
            &mut visited_realpaths,
            1,
            3,
            workspace_members,
            json_output,
            &mut node_modules_warned,
            &mut additional_workspace_links,
            workspace_transitives,
            false,
        )?;
    }

    Ok(LocalSourceExpansionResult {
        source_deps: source_deps_out,
        additional_workspace_links,
    })
}

pub(super) fn pre_resolve_v2_direct_workspace_member_deps(
    project_dir: &Path,
    deps: &mut HashMap<String, String>,
    direct_workspace_member_deps: &[DirectWorkspaceMemberProvider],
    all_workspace_members: &[WorkspaceMemberLink],
    json_output: bool,
) -> Result<V2WorkspaceRootPreResolveResult, LpmError> {
    if direct_workspace_member_deps.is_empty() {
        return Ok(V2WorkspaceRootPreResolveResult::default());
    }

    let dependency_names_before_expansion: HashSet<String> = deps.keys().cloned().collect();
    let mut install_pkgs = Vec::with_capacity(direct_workspace_member_deps.len());
    for member in direct_workspace_member_deps {
        let node_engine = read_pkg_json_node_engine(
            &member.source_dir,
            &format!("workspace member at {}", member.source_dir.display()),
        )?;
        install_pkgs.push(InstallPackage {
            name: member.name.clone(),
            version: member.version.clone(),
            source: member.source.clone(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec![member.name.clone()]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        });
    }

    let LocalSourceExpansionResult {
        source_deps,
        additional_workspace_links,
    } = expand_local_source_install_packages(
        project_dir,
        deps,
        &mut install_pkgs,
        all_workspace_members,
        json_output,
        WorkspaceTransitiveMode::SourceGraph,
    )?;
    let optional_registry_roots = merge_optional_registry_roots(
        &dependency_names_before_expansion,
        &HashSet::new(),
        registry_root_optionality(&install_pkgs, &source_deps),
    );

    Ok(V2WorkspaceRootPreResolveResult {
        install_pkgs,
        source_deps,
        additional_workspace_links,
        optional_registry_roots,
    })
}

/// derive the canonical registry URL
/// for a package name from the active [`RouteTable`].
///
/// motivated keying [`lpm_lockfile::Source::source_id`]
/// by URL so the same `name@version` resolved from different
/// registries (npmjs.org vs Verdaccio vs an `.npmrc`-overridden
/// private mirror) gets distinct identity. Pre-this-fix, the install
/// pipeline produced source strings from a hardcoded
/// `is_lpm`-branched 2-value choice — so a `.npmrc`-rerouted package
/// still reported `registry+https://registry.npmjs.org` and the
/// granularity in the type system wasn't realized in practice.
///
/// Resolution order matches [`RouteTable::route_for_package`]:
/// - `@lpm.dev/*` → `"https://lpm.dev"` (LPM Worker, by invariant)
/// - npmrc-mapped (scope-mapped or default-registry) → `target.base_url`
/// - Otherwise → `"https://registry.npmjs.org"` (NpmDirect / Proxy)
pub(super) fn registry_source_url_for(name: &str, route_table: &RouteTable) -> String {
    match route_table.route_for_package(name) {
        UpstreamRoute::LpmWorker => "https://lpm.dev".to_string(),
        UpstreamRoute::NpmDirect => "https://registry.npmjs.org".to_string(),
        UpstreamRoute::Custom { target, .. } => target.base_url.as_ref().to_string(),
    }
}

/// — `true` iff `project_dir` is on a legacy v1
/// layout that must be wiped before a v2 install can run cleanly.
///
/// Either signal is enough — a project running v1 isolated has
/// `<project>/.lpm/wrappers/`, hoisted has `<project>/.lpm/hoisted/`,
/// and a project mid-mode-switch may have both. v2 has neither
/// (project node_modules holds only symlinks into the global store),
/// so the predicate also returns `false` on a clean v2 install (which
/// is what makes it idempotent on re-runs after migration).
///
/// Detection lives in this module rather than `lpm-linker`'s
/// `LayoutPaths` because migration is an install-pipeline concern —
/// the linker shouldn't know about lpm-rs upgrade lifecycle.
pub(super) fn needs_v2_migration(project_dir: &Path) -> bool {
    project_dir.join(".lpm").join("wrappers").exists()
        || project_dir.join(".lpm").join("hoisted").exists()
}

/// migration sequence (design).
///
/// Wipe order matters for the install-state freshness gate:
/// 1. `<project>/.lpm/wrappers/` (legacy isolated wrapper root).
/// 2. `<project>/.lpm/hoisted/` (legacy hoisted state).
/// 3. `<project>/node_modules/` entirely, INCLUDING `.bin/`. Bin
///    shims regenerate from the post-migration install layout; a
///    stale `.bin/` would point at deleted wrapper paths and crash
///    every `npx <bin>` afterwards.
/// 4. `<project>/.lpm/install-hash` — the prior hash assumed v1
///    layout. Without removal, the freshness check would short-
///    circuit and skip the v2 install.
///
/// Each step is idempotent: a non-existent path is a no-op. A crash
/// mid-migration leaves a half-wiped project; the next install
/// re-runs the same wipes (no-ops) and re-attempts the v2 install.
///
/// `~/.lpm/store/v1/` is intentionally NOT wiped here — it may still
/// serve other projects on the same machine. `lpm store clean` is the
/// blunt-wipe escape hatch for users who want to discard it.
pub(super) fn migrate_v1_to_v2(project_dir: &Path) -> std::io::Result<()> {
    let dot_lpm = project_dir.join(".lpm");
    for stale in [dot_lpm.join("wrappers"), dot_lpm.join("hoisted")] {
        if stale.exists() {
            std::fs::remove_dir_all(&stale)?;
        }
    }
    let nm = project_dir.join("node_modules");
    if nm.exists() {
        std::fs::remove_dir_all(&nm)?;
    }
    let install_hash = dot_lpm.join("install-hash");
    if install_hash.exists() {
        std::fs::remove_file(&install_hash)?;
    }
    Ok(())
}

/// pre-resolve
/// non-registry dependencies from the manifest before the PubGrub
/// resolver runs.
///
/// Supported source arms:
/// 1. **[`Specifier::Tarball`]** (remote HTTPS tarball URL): download the bytes (verifying integrity if declared
///    via SRI), extract into the integrity-keyed CAS path (skips on
///    fast-path hit — `store_tarball_at_cas_path`), read the
///    `package.json` to learn `(name, version)`, build an
///    [`InstallPackage`] with `source = "tarball+<url>"`.
/// 2. **[`Specifier::File`]** with `is_file()` target (local tarball):
///    read the bytes from disk (path resolved
///    against `project_dir`), compute SHA-256, extract into the
///    content-keyed local-tarball CAS path (skips on fast-path hit
///    — `store_local_tarball_at_cas_path`), read the `package.json`
///    to learn `(name, version)`, build an [`InstallPackage`] with
///    `source = "tarball+file:<path>"`.
///
/// In both arms the resulting entry is removed from `deps` so the
/// resolver only sees registry-style specs.
///
/// **Explicit-error arms**:
/// - [`Specifier::File`] with `is_dir()` target -> directory dep.
/// - [`Specifier::Link`] -> linked directory dep.
/// - [`Specifier::Git`] -> git source.
///
/// Surfacing an actionable error at the manifest boundary is
/// preferable to letting the dep fall through to the resolver and
/// surface as an opaque "invalid semver range" from `node_semver`.
///
/// Current limitations:
/// - Both `Source::Tarball` arms are graph leaves — transitive deps
///   from the embedded `package.json` are NOT yet fed back into the
///   resolver. Real-world local tarballs (CI artifacts, single-file
///   utility packages) are typically self-contained.
/// - Lockfile fast-path doesn't fire when the lockfile contains
///   non-Registry source entries — falls back to fresh-resolve.
///   Correctness fine; warm-restart perf follow-up.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) async fn pre_resolve_non_registry_deps(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    project_dir: &Path,
    deps: &mut HashMap<String, String>,
    json_output: bool,
    strict_integrity: bool, // slice of
    // workspace members extracted by `extract_workspace_protocol_deps`
    // before pre_resolve runs. Each member's `source_dir` is
    // realpath-compared against every directory/link dep's source
    // realpath to detect overlap. Empty slice for non-workspace
    // installs (the common case); the detection becomes a
    // no-op.
    workspace_members: &[WorkspaceMemberLink],
) -> Result<NonRegistryPreResolveResult, LpmError> {
    pre_resolve_non_registry_deps_with_optional_registry_roots(
        client,
        store,
        project_dir,
        deps,
        json_output,
        strict_integrity,
        workspace_members,
        &HashSet::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn pre_resolve_non_registry_deps_with_optional_registry_roots(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    project_dir: &Path,
    deps: &mut HashMap<String, String>,
    json_output: bool,
    strict_integrity: bool,
    workspace_members: &[WorkspaceMemberLink],
    inherited_optional_registry_roots: &HashSet<String>,
) -> Result<NonRegistryPreResolveResult, LpmError> {
    // Gate the manifest boundary for non-registry specifiers.
    //
    // Supported:
    // - Tarball-URL (`https://...`)
    // - File-tarball (`file:./foo.tgz` is_file())
    // - File-dir (`file:../packages/foo` is_dir())
    //
    // Still rejected with explicit, actionable errors:
    // - Link (`link:...`)
    // - Git (`git+...`, `github:...`)
    //
    // SemverRange / NpmAlias / Workspace flow through unchanged.
    //
    // The pre-flight loop pre-classifies `Specifier::File` via stat
    // (regular file → path; directory → path; missing/exotic →
    // typed error). The classification is cached in `file_kinds` so
    // the partition `retain` below dispatches without re-statting.
    let mut file_kinds: HashMap<String, FileKindClassification> = HashMap::new();
    for (local_name, raw) in deps.iter() {
        match lpm_resolver::Specifier::parse(raw) {
            // Surface manifest-boundary parser errors before the
            // resolver turns them into confusing range or fetch failures.
            // Other parse errors stay on the previously swallow path to
            // preserve behavior for malformed shapes that were previously
            // tolerated upstream.
            Err(
                err @ (lpm_resolver::SpecifierParseError::UnknownProtocol { .. }
                | lpm_resolver::SpecifierParseError::WindowsDriveLetterPath(_)
                | lpm_resolver::SpecifierParseError::JsrMissingScope
                | lpm_resolver::SpecifierParseError::InvalidJsrPackageName { .. }
                | lpm_resolver::SpecifierParseError::JsrMissingPackageName { .. }),
            ) => {
                return Err(LpmError::Registry(format!(
                    "dep '{local_name}' in package.json has invalid spec '{raw}': {err}"
                )));
            }
            Err(_)
            | Ok(lpm_resolver::Specifier::SemverRange(_))
            | Ok(lpm_resolver::Specifier::NpmAlias { .. })
            | Ok(lpm_resolver::Specifier::Workspace(_))
            | Ok(lpm_resolver::Specifier::Tarball { .. }) => {}
            Ok(lpm_resolver::Specifier::Git { url, .. }) => {
                return Err(LpmError::Registry(format!(
                    "dep '{local_name}' uses git specifier '{url}', which is not \
                     yet supported. Workaround: vendor the package or publish it \
                     to a registry."
                )));
            }
            Ok(lpm_resolver::Specifier::File { path }) => {
                // Disambiguate file: target via
                // stat. Result is cached in `file_kinds` for the
                // partition step below to avoid a second stat.
                let abs_path = project_dir.join(&path);
                match tokio::fs::metadata(&abs_path).await {
                    Ok(meta) if meta.is_file() => {
                        file_kinds.insert(local_name.clone(), FileKindClassification::Tarball);
                    }
                    Ok(meta) if meta.is_dir() => {
                        // () — directory dep is now
                        // SUPPORTED. Pass-through to the processing
                        // loop below.
                        file_kinds.insert(local_name.clone(), FileKindClassification::Directory);
                    }
                    Ok(_) => {
                        // Symlink-to-something-else / device file / etc.
                        return Err(LpmError::Registry(format!(
                            "dep '{local_name}' uses file: specifier '{path}' which \
                             resolves to neither a regular file nor a directory ({}). \
                             Expected a `.tgz` tarball or a directory containing \
                             package.json.",
                            abs_path.display()
                        )));
                    }
                    Err(e) => {
                        return Err(LpmError::Registry(format!(
                            "dep '{local_name}' uses file: specifier '{path}' but the \
                             resolved path ({}) is unreadable: {e}",
                            abs_path.display()
                        )));
                    }
                }
            }
            Ok(lpm_resolver::Specifier::Link { path }) => {
                // () — link: deps land here. Unlike
                // file: (which can be tarball OR directory), link: is
                // ALWAYS a directory. Verify via stat; non-directory
                // targets surface an actionable manifest-boundary error.
                //
                // The pre-flight loop only validates here; the
                // partition + processing happen below alongside
                // directory: deps (link: shares the same wrapper-
                // routing path with `l-` prefix instead of `f-` —
                // `Source::Link.source_id()` already produces this).
                let abs_path = project_dir.join(&path);
                match tokio::fs::metadata(&abs_path).await {
                    Ok(meta) if meta.is_dir() => {
                        // Valid link: target — processed below.
                    }
                    Ok(meta) if meta.is_file() => {
                        return Err(LpmError::Registry(format!(
                            "dep '{local_name}' uses link: specifier '{path}' which \
                             resolves to a regular file ({}). link: requires a directory \
                             containing package.json. Use `file:./<name>.tgz` for a local \
                             tarball or `file:./<dir>` for a directory you want copied.",
                            abs_path.display()
                        )));
                    }
                    Ok(_) => {
                        // Symlink-to-something-else / device file / etc.
                        return Err(LpmError::Registry(format!(
                            "dep '{local_name}' uses link: specifier '{path}' which \
                             resolves to neither a regular file nor a directory ({}). \
                             link: requires a directory containing package.json.",
                            abs_path.display()
                        )));
                    }
                    Err(e) => {
                        return Err(LpmError::Registry(format!(
                            "dep '{local_name}' uses link: specifier '{path}' but the \
                             resolved path ({}) is unreadable: {e}",
                            abs_path.display()
                        )));
                    }
                }
            }
        }
    }

    // Partition the manifest deps into the four non-registry arms.
    // Each arm has its own fetch/materialize site below; the resolver
    // only sees what's left in `deps`.
    let mut tarball_url_specs: Vec<(String, String, Option<String>)> = Vec::new();
    let mut file_tarball_specs: Vec<(String, String)> = Vec::new();
    let mut directory_specs: Vec<(String, String)> = Vec::new();
    let mut link_specs: Vec<(String, String)> = Vec::new();
    deps.retain(
        |local_name, raw| match lpm_resolver::Specifier::parse(raw) {
            Ok(lpm_resolver::Specifier::Tarball { url, integrity }) => {
                tarball_url_specs.push((local_name.clone(), url, integrity));
                false
            }
            Ok(lpm_resolver::Specifier::File { path }) => {
                // Pre-flight loop above populated `file_kinds` with
                // the stat result for every File specifier that
                // didn't error. `expect` documents the invariant.
                match file_kinds
                    .get(local_name)
                    .expect("pre-flight loop classifies every File specifier or returns Err")
                {
                    FileKindClassification::Tarball => {
                        file_tarball_specs.push((local_name.clone(), path));
                    }
                    FileKindClassification::Directory => {
                        directory_specs.push((local_name.clone(), path));
                    }
                }
                false
            }
            Ok(lpm_resolver::Specifier::Link { path }) => {
                // Pre-flight loop above already verified the link:
                // target is a directory or returned an error; the
                // partition unconditionally adds to link_specs.
                link_specs.push((local_name.clone(), path));
                false
            }
            _ => true,
        },
    );

    if tarball_url_specs.is_empty()
        && file_tarball_specs.is_empty()
        && directory_specs.is_empty()
        && link_specs.is_empty()
    {
        return Ok(NonRegistryPreResolveResult {
            install_pkgs: Vec::new(),
            source_deps: HashMap::new(),
            additional_workspace_links: Vec::new(),
            optional_registry_roots: inherited_optional_registry_roots.clone(),
        });
    }

    let mut install_pkgs = Vec::with_capacity(
        tarball_url_specs.len()
            + file_tarball_specs.len()
            + directory_specs.len()
            + link_specs.len(),
    );

    // workspace members
    // discovered through dedupe (immediate + transitive) and the
    // the invariant transitive `workspace:` arm. The caller merges this
    // into `workspace_member_deps` before passing to
    // `link_workspace_members` so each discovered member gets a root
    // symlink. Empty for non-workspace projects (the / the invariant
    // checks short-circuit on empty `workspace_members`).
    let mut additional_workspace_links: Vec<WorkspaceMemberLink> = Vec::new();

    // ── Arm 1: — remote tarball URLs ──────────────────────
    for (local_name, url, declared_integrity) in tarball_url_specs {
        // () — strict-integrity gate. When set,
        // a tarball-URL dep without a manifest-declared SRI is a
        // hard error rather than trust-on-first-use. Recommended
        // for CI to prevent supply-chain surprises on fresh installs.
        // Lockfile-resident integrity is unaffected — once the
        // SRI is in `lpm.lock`, it's the source of truth and
        // strict-integrity has nothing more to enforce.
        if strict_integrity && declared_integrity.is_none() {
            return Err(LpmError::Registry(format!(
                "--strict-integrity: dep '{local_name}' uses tarball URL {url} without a \
                 declared SRI. Add `#sha512-...` (or `#sha256-...`) to the URL in your \
                 manifest, or remove --strict-integrity to allow trust-on-first-use."
            )));
        }

        // H7: trust-on-first-use SRI capture. With no declared
        // integrity, whatever the server returns gets pinned into the
        // lockfile and trusted on every subsequent install. Surface
        // the trust posture loudly so the operator sees what they're
        // agreeing to: the project is now bound to whoever owned the
        // server at the moment of first install. `--strict-integrity`
        // above already hard-fails when this is unacceptable; the
        // warn lands on the default permissive path so silent TOFU
        // becomes visible TOFU.
        if declared_integrity.is_none() {
            tracing::warn!(
                target: "lpm_cli::install",
                local_name = %local_name,
                tarball_url = %url,
                "tarball+URL dep without declared SRI — trusting whatever the server returns AND pinning the computed hash into lpm.lock (trust-on-first-use). Pin via `#sha512-...` on the URL, or pass `--strict-integrity` to refuse."
            );
            if !json_output {
                output::warn(&format!(
                    "tarball+URL dep '{local_name}' has no declared SRI — pinning trust-on-first-use to {url}"
                ));
            }
        }

        // Step 1+2: download (with optional SRI verify) and extract
        // into the CAS. A verified declared SRI remains the exact source
        // identity; trust-on-first-use uses the computed SHA-512 SRI. If the
        // corresponding CAS dir exists, extraction is skipped.
        let (data, computed_sri) = client
            .download_tarball_with_integrity(&url, declared_integrity.as_deref())
            .await?;
        let source_sri = declared_integrity.as_deref().unwrap_or(&computed_sri);
        let cas_path = store.store_tarball_at_cas_path(source_sri, &data)?;

        let (real_name, real_version, node_engine) =
            read_pkg_json_name_version(&cas_path, &format!("tarball at {url}"))?;

        // Dep-key vs fetched-name policy: warn rather than reject. The manifest dep key
        // controls node_modules layout (via `root_link_names`); the
        // fetched-package name controls store identity. Surface the
        // divergence so users notice unintended renames.
        if local_name != real_name && !json_output {
            output::warn(&format!(
                "dep '{local_name}' resolves to package '{real_name}' from {url}; \
                 using local key as the link name in node_modules"
            ));
        }

        install_pkgs.push(InstallPackage {
            name: real_name,
            version: real_version,
            source: format!("tarball+{url}"),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec![local_name]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: Some(source_sri.to_string()),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine,
            optional: false,
            tarball_url: Some(url),
            metadata_checked_for_tarball: false,
        });
    }

    // ── Arm 2: — local-file tarballs ────────────────
    //
    // No network. Path resolved against `project_dir`. Identity is
    // content-only (SHA-256 of bytes); the user-typed path lives in
    // the wire-format `tarball+file:<path>` source for the lockfile,
    // but the store key is the content hash so two paths to the
    // same bytes dedupe. Strict-integrity has no effect here — the
    // content hash IS the integrity, computed every time.
    for (local_name, raw_path) in file_tarball_specs {
        // Reject relative paths that escape the project root via `..`
        // components. The lockfile parser allows the `tarball+file:`
        // shape with `../`, so a tampered manifest could otherwise
        // read e.g. `/etc/passwd.tgz` into the LPM CAS. Absolute paths
        // are still accepted because they are an explicit user choice
        // (shared CI cache, etc.) and don't constitute traversal
        // surprise.
        if let Err(reason) = validate_local_tarball_raw_path(&raw_path) {
            return Err(LpmError::Registry(format!(
                "dep '{local_name}' has invalid file: path '{raw_path}': {reason}"
            )));
        }
        let abs_path = project_dir.join(&raw_path);

        // Cap reads at lpm-extractor's hard ceiling (500 MB). A
        // multi-GB local "tarball" is almost always a misconfigured
        // dep — failing fast at the manifest boundary is friendlier
        // than OOMing the extractor mid-walk.
        const MAX_LOCAL_TARBALL_BYTES: u64 = 500 * 1024 * 1024;
        let data = read_local_tarball_bounded(&abs_path, MAX_LOCAL_TARBALL_BYTES)
            .await
            .map_err(|e| {
                LpmError::Registry(format!(
                    "dep '{local_name}' file: tarball at {} is unreadable: {e}",
                    abs_path.display()
                ))
            })?;

        // SHA-256 of the bytes — the CAS key and persisted source identity
        // for tarball-local.
        let content_sha256_hex = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        };

        let cas_path = store.store_local_tarball_at_cas_path(&content_sha256_hex, &data)?;

        let (real_name, real_version, node_engine) = read_pkg_json_name_version(
            &cas_path,
            &format!("local tarball at {}", abs_path.display()),
        )?;

        if local_name != real_name && !json_output {
            output::warn(&format!(
                "dep '{local_name}' resolves to package '{real_name}' from local \
                 tarball {}; using local key as the link name in node_modules",
                abs_path.display()
            ));
        }

        // Wire-format source: `tarball+file:<raw-path>` — the user-
        // typed path is preserved verbatim so the lockfile records
        // what the manifest declared. The CAS slot is keyed by
        // content hash, so two consumers with the same bytes from
        // different paths dedupe at the store layer; the lockfile
        // entry remains per-consumer.
        let source = format!("tarball+file:{raw_path}");

        // SRI for the lockfile `integrity` field — the actual
        // content hash in canonical SRI form. Allows `lpm install
        // --strict-integrity` to verify local tarballs the same way it
        // does remote ones.
        let integrity_sri = lpm_common::integrity::Integrity::from_bytes(
            lpm_common::integrity::HashAlgorithm::Sha256,
            &data,
        )
        .to_string();

        install_pkgs.push(InstallPackage {
            name: real_name,
            version: real_version,
            source,
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec![local_name]),
            is_direct: true,
            is_lpm: false,
            peers: Vec::new(),
            integrity: Some(integrity_sri),
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine,
            optional: false,
            // tarball_url is fresh-URL writeback (registry-
            // specific). Local tarballs have no remote URL, so leave
            // `None`. Documented caveat: warm-restart fast-path
            // doesn't fire for `Source::Tarball { file: }` lockfile
            // entries.
            tarball_url: None,
            metadata_checked_for_tarball: false,
        });
    }

    // ── (): node_modules-warn dedupe set ─────────
    //
    // Tracks realpaths already warned-about in this install so the
    // SAME source doesn't warn multiple times when:
    // - Two separate immediate deps share the same realpath
    // (file: + link: at the same dir).
    // - Diamond pattern hits the same source from two parents.
    // - Recursive walker visits a transitive that's also an
    // immediate.
    // Threaded into the immediate arms below AND into
    // `recurse_local_source_deps` for transitive coverage.
    let mut node_modules_warned: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();

    // ── Arm 3: — directory deps ─────────────────────
    //
    // No network, no extraction. The source dir IS the package; the
    // linker materializes per-file symlinks pointing at it ( work
    // in lpm-linker). This loop's job is pre-resolve only:
    // 1. Realpath the source to produce a stable identity.
    // 2. Detect workspace overlap — short-circuit if
    // this source IS already a workspace member.
    // 3. -warn on top-level node_modules/.
    // 4. Read the source's package.json for (name, version).
    // 5. Build an InstallPackage so the linker layer () gets
    // a `Source::Directory` it can route through `wrapper_id`.
    //
    // (-transitive) wired the recursive walker that feeds
    // transitive deps back through this same path.
    for (local_name, raw_path) in directory_specs {
        let abs_path = project_dir.join(&raw_path);
        let realpath = abs_path.canonicalize().map_err(|e| {
            LpmError::Registry(format!(
                "dep '{local_name}' file: directory at {} could not be canonicalized: {e}",
                abs_path.display()
            ))
        })?;

        let (real_name, real_version, node_engine) = read_pkg_json_name_version(
            &realpath,
            &format!("file: directory at {}", realpath.display()),
        )?;

        // : workspace overlap detection. Realpath of source
        // matched against every workspace member; on match dedupe
        // (skip building InstallPackage — workspace member is
        // already extracted and will be linked by
        // `link_workspace_members`).
        match detect_workspace_overlap(
            &realpath,
            &real_version,
            workspace_members,
            &local_name,
            &format!("file:{raw_path}"),
        )? {
            WorkspaceOverlap::DedupeWith(member) => {
                if !json_output {
                    output::info(&format!(
                        "note: file: dep '{local_name}' at {} resolves to workspace \
                         member '{}'; using workspace symlink instead",
                        raw_path, member.name,
                    ));
                }
                // **Invariant invariant.** Previously this branch
                // SKIPPED InstallPackage construction and assumed
                // `link_workspace_members` would plant the root
                // symlink — but that helper only walks the EXTRACTED
                // top-level subset, so deps the consumer wrote as
                // `file:` (not `workspace:*`) silently ended up
                // without a `node_modules/<local>` entry. Push the
                // matched member into `additional_workspace_links`
                // under the consumer's local_name so the caller can
                // merge it into the slice that drives root linking.
                additional_workspace_links.push(WorkspaceMemberLink {
                    name: local_name.clone(),
                    version: member.version.clone(),
                    source_dir: member.source_dir.clone(),
                });
                continue;
            }
            WorkspaceOverlap::NoOverlap => {}
        }

        // finalization — warn-once per realpath.
        maybe_warn_pkg_node_modules(
            &realpath,
            &local_name,
            json_output,
            &mut node_modules_warned,
        );

        // Same dep-key vs fetched-name policy as the tarball arms
        // (umbrella— locked as warn-not-reject).
        if local_name != real_name && !json_output {
            output::warn(&format!(
                "dep '{local_name}' resolves to package '{real_name}' from local \
                 directory {}; using local key as the link name in node_modules",
                realpath.display()
            ));
        }

        // Wire-format source: `directory+<raw-path>`. Path is stored
        // RELATIVE to the consumer's project dir (lockfile-portable
        // across machines that share the same project layout).
        // Canonicalization happens at install time, not at lockfile
        // load time.
        install_pkgs.push(InstallPackage {
            name: real_name,
            version: real_version,
            source: format!("directory+{raw_path}"),
            // Populated by the post-resolve fix-up after the resolver
            // produces concrete versions for every registry dep
            // referenced by this source.
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec![local_name]),
            is_direct: true,
            is_lpm: false,
            // Directory deps have mutable content — no integrity SRI
            // applies (any value would invalidate on the next edit).
            // 's install-hash extension folds in the source's
            // package.json content as the freshness signal instead.
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        });
    }

    // ── Arm 4: link: deps ─────────────────────────
    //
    // Structurally identical to the directory arm with one
    // difference: source kind is `Source::Link` (wrapper_id picks up
    // the `l-` prefix via `Source::Link.source_id()`). The linker
    // materializes per-file symlinks. Link deps are always wrapper-routed;
    // they never use the `--no-symlink` copy fallback that file: allows.
    //
    // -transitive (day 5) folds in transitive resolution for
    // both file: directory AND link: deps in a single pass.
    // + (day 6) apply identically to link: as to directory.
    for (local_name, raw_path) in link_specs {
        let abs_path = project_dir.join(&raw_path);
        let realpath = abs_path.canonicalize().map_err(|e| {
            LpmError::Registry(format!(
                "dep '{local_name}' link: dep at {} could not be canonicalized: {e}",
                abs_path.display()
            ))
        })?;

        let (real_name, real_version, node_engine) =
            read_pkg_json_name_version(&realpath, &format!("link: dep at {}", realpath.display()))?;

        // : workspace overlap detection — same logic as the
        // directory arm.
        match detect_workspace_overlap(
            &realpath,
            &real_version,
            workspace_members,
            &local_name,
            &format!("link:{raw_path}"),
        )? {
            WorkspaceOverlap::DedupeWith(member) => {
                if !json_output {
                    output::info(&format!(
                        "note: link: dep '{local_name}' at {} resolves to workspace \
                         member '{}'; using workspace symlink instead",
                        raw_path, member.name,
                    ));
                }
                // Invariant invariant — see file: arm above for
                // the rationale. Same fix: push the matched member
                // under the consumer's local_name so the caller
                // creates `node_modules/<local>` at the project root.
                additional_workspace_links.push(WorkspaceMemberLink {
                    name: local_name.clone(),
                    version: member.version.clone(),
                    source_dir: member.source_dir.clone(),
                });
                continue;
            }
            WorkspaceOverlap::NoOverlap => {}
        }

        // finalization — warn-once per realpath.
        maybe_warn_pkg_node_modules(
            &realpath,
            &local_name,
            json_output,
            &mut node_modules_warned,
        );

        // Same dep-key vs fetched-name policy as every other arm.
        if local_name != real_name && !json_output {
            output::warn(&format!(
                "dep '{local_name}' resolves to package '{real_name}' from link: \
                 source {}; using local key as the link name in node_modules",
                realpath.display()
            ));
        }

        // Wire-format source: `link+<raw-path>` (per `crates/lpm-
        // lockfile/src/source.rs` module docs). The user-typed path
        // is preserved verbatim; canonicalization happens at install
        // time.
        install_pkgs.push(InstallPackage {
            name: real_name,
            version: real_version,
            source: format!("link+{raw_path}"),
            // Populated by the post-resolve fix-up after the resolver
            // produces concrete versions for every registry dep
            // referenced by this source.
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: Some(vec![local_name]),
            is_direct: true,
            is_lpm: false,
            // Link deps share directory deps' mutable-content posture
            // — no integrity SRI; folds the source's package.json
            // content into the install-hash freshness signal.
            peers: Vec::new(),
            integrity: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            platform: None,
            node_engine,
            optional: false,
            tarball_url: None,
            metadata_checked_for_tarball: false,
        });
    }

    // ── (-transitive) ────────────────────────────────
    //
    // For each immediate directory/link InstallPackage, recursively
    // walk its source's package.json:
    // - Append registry-style transitive deps to `deps` (the
    // consumer's resolver-input map) so pubgrub/fusion picks them
    // up.
    // - Build nested InstallPackages for transitive file: directory
    // and link: deps. Bounded at depth 3, realpath cycle-detect.
    // - Stash per-source-string dep specs in `source_deps_out` for
    // the post-resolve fix-up at install.rs:2663+.
    //
    let dependency_names_before_expansion: HashSet<String> = deps.keys().cloned().collect();
    let LocalSourceExpansionResult {
        source_deps: source_deps_out,
        additional_workspace_links,
    } = expand_local_source_install_packages(
        project_dir,
        deps,
        &mut install_pkgs,
        workspace_members,
        json_output,
        WorkspaceTransitiveMode::RootSymlinkOnly,
    )?;
    let optional_registry_roots = merge_optional_registry_roots(
        &dependency_names_before_expansion,
        inherited_optional_registry_roots,
        registry_root_optionality(&install_pkgs, &source_deps_out),
    );

    Ok(NonRegistryPreResolveResult {
        install_pkgs,
        source_deps: source_deps_out,
        additional_workspace_links,
        optional_registry_roots,
    })
}

/// follow-up — extract the lowercase-hex form of
/// a SHA-256 SRI's raw hash bytes.
///
/// The local-tarball CAS keys by 64-char lowercase hex (the same
/// shape `sha2::Sha256::finalize()` produces); the lockfile carries
/// integrity in canonical SRI form (`sha256-<base64>`). This helper
/// bridges the two representations so the post-resolve dispatcher
/// can route a `Source::Tarball { file:... }` package to its
/// content-keyed CAS slot without a redundant rehash.
///
/// Returns `None` if the SRI is unparseable or uses an unsupported
/// algorithm — caller treats that the same as a missing-SRI case, with no
/// fallback to a different subtree.
pub(super) fn sri_to_sha256_hex(sri: &str) -> Option<String> {
    let int = lpm_common::integrity::Integrity::parse(sri).ok()?;
    if int.algorithm != lpm_common::integrity::HashAlgorithm::Sha256 {
        // Local tarballs are stored sha256-keyed by construction
        // (computed in pre_resolve via sha2::Sha256). A non-sha256
        // SRI on a `file:` source should never appear in practice;
        // refuse to silently route to the wrong subtree.
        return None;
    }
    Some(int.hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// Reject a `tarball+file:<raw_path>` manifest entry whose raw path
/// contains `..` traversal components. The lockfile parser accepts
/// the `./` / `../` / `/` shape on this scheme; without this check a
/// tampered manifest entry like `tarball+file:../../etc/passwd.tgz`
/// would be read into the LPM CAS as a "package", surfacing arbitrary
/// host-filesystem content under the store's content-addressable
/// layout. Absolute paths are still accepted (legitimate shared-cache
/// pattern) — they're an explicit user choice, not a traversal
/// surprise.
pub(super) fn validate_local_tarball_raw_path(raw_path: &str) -> Result<(), String> {
    let p = Path::new(raw_path);
    if p.is_absolute() {
        return Ok(());
    }
    for component in p.components() {
        if component == Component::ParentDir {
            return Err(
                "relative file: path contains `..` component, which is not permitted; \
                 use an absolute path if the tarball lives outside the project root"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Read a local file with a hard byte ceiling, returning the bytes.
///
/// Streams via `tokio::fs::File` + `take(limit)` so an oversized file
/// fails before allocating the full buffer. Returns an error when the
/// file exceeds `limit` bytes — distinguished from a generic I/O
/// error for a clearer manifest-boundary message.
pub(super) async fn read_local_tarball_bounded(
    path: &Path,
    limit: u64,
) -> Result<Vec<u8>, std::io::Error> {
    use tokio::io::AsyncReadExt;

    let f = tokio::fs::File::open(path).await?;
    let len = f.metadata().await?.len();
    if len > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file is {len} bytes; exceeds local-tarball ceiling of {limit} bytes"),
        ));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(limit).read_to_end(&mut buf).await?;
    Ok(buf)
}

/// Read `package.json` from an extracted package directory and
/// return `(name, version, engines.node)` as owned values.
///
/// Shared between the remote-tarball-URL arm and the local-file-
/// tarball arm of [`pre_resolve_non_registry_deps`]; the two used to
/// inline this logic with identical error shapes. `source_label` is
/// embedded in error messages so the user knows which arm produced
/// them (`"tarball at https://..."` vs `"local tarball at ..."`).
pub(super) fn read_pkg_json_name_version(
    cas_path: &Path,
    source_label: &str,
) -> Result<(String, String, Option<String>), LpmError> {
    let pkg_json = read_pkg_json(cas_path, source_label)?;
    let name = pkg_json
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{source_label} has no `name` field in package.json"
            ))
        })?
        .to_string();
    let version = pkg_json
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "{source_label} has no `version` field in package.json"
            ))
        })?
        .to_string();
    let node_engine = package_json_node_engine(&pkg_json);
    Ok((name, version, node_engine))
}

pub(super) fn read_pkg_json_node_engine(
    package_dir: &Path,
    source_label: &str,
) -> Result<Option<String>, LpmError> {
    let pkg_json = read_pkg_json(package_dir, source_label)?;
    Ok(package_json_node_engine(&pkg_json))
}

fn read_pkg_json(cas_path: &Path, source_label: &str) -> Result<serde_json::Value, LpmError> {
    let pkg_json_path = cas_path.join("package.json");
    let pkg_json_str = std::fs::read_to_string(&pkg_json_path).map_err(|e| {
        LpmError::Registry(format!(
            "failed to read package.json from {source_label}: {e}"
        ))
    })?;
    serde_json::from_str(&pkg_json_str)
        .map_err(|e| LpmError::Registry(format!("invalid package.json in {source_label}: {e}")))
}

fn package_json_node_engine(pkg_json: &serde_json::Value) -> Option<String> {
    pkg_json
        .get("engines")
        .and_then(|engines| engines.get("node"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// read a local source's
/// `package.json` and return its transitive deps with their kind
/// classification.
///
/// Walks `dependencies` + `devDependencies` + `peerDependencies` +
/// `optionalDependencies`. Each entry is classified as:
/// The resolver only special-cases `npm:` aliases at the root level;
/// everything else gets fed into [`lpm_resolver::ranges::NpmRange::parse`],
/// which rejects URL and git specs as invalid semver ranges. Unsupported
/// transitive shapes must fail here before they reach the resolver.
///
/// Allowed shapes:
/// - `DepKind::Registry` for SemverRange / NpmAlias —
///   the resolver handles these cleanly.
/// - `DepKind::Workspace` for `workspace:` protocol.
/// - `DepKind::FileDir` for `file:` specs whose target is a
///   directory.
/// - `DepKind::Link` for `link:` specs (always a directory).
///
/// Rejected shapes (typed [`LpmError::Registry`] error from
/// [`classify_source_dep`]):
/// - `https://` Tarball — would crash the resolver.
/// - `file:` whose target is a regular file (tarball) — same.
/// - `git+…` / git host shorthand — same.
/// - `Specifier::parse` errors (empty path, invalid host
///   shorthand, etc.).
///
/// Errors propagate so callers can surface a clear manifest-
/// boundary error if a local source's `package.json` is missing,
/// unparseable, or contains an unsupported transitive dep spec.
/// Sync-only — these are local file ops; sync recursion in
/// [`recurse_local_source_deps`] is cleaner than the async
/// alternative.
pub(super) fn read_source_dep_specs(source_dir: &Path) -> Result<Vec<SourceDep>, LpmError> {
    let pkg_json_path = source_dir.join("package.json");
    let pkg_json_str = std::fs::read_to_string(&pkg_json_path).map_err(|e| {
        LpmError::Registry(format!(
            "failed to read package.json from local source at {}: {e}",
            source_dir.display()
        ))
    })?;
    let pkg_json: serde_json::Value = serde_json::from_str(&pkg_json_str).map_err(|e| {
        LpmError::Registry(format!(
            "invalid package.json in local source at {}: {e}",
            source_dir.display()
        ))
    })?;

    let optional_names = pkg_json
        .get("optionalDependencies")
        .and_then(|value| value.as_object())
        .map(|deps| deps.keys().map(String::as_str).collect::<HashSet<_>>())
        .unwrap_or_default();
    let mut out = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(deps) = pkg_json.get(field).and_then(|v| v.as_object()) else {
            continue;
        };
        for (local_name, raw) in deps {
            if field == "dependencies" && optional_names.contains(local_name.as_str()) {
                continue;
            }
            let Some(raw_str) = raw.as_str() else {
                continue;
            };
            let normalized_spec = lpm_resolver::normalize_jsr_dependency(local_name, raw_str)
                .map_err(|e| {
                    LpmError::Registry(format!(
                        "invalid transitive dep spec for `{local_name}` (\"{raw_str}\") declared in {}: {e}",
                        source_dir.display(),
                    ))
                })?;
            let effective_raw = normalized_spec.as_deref().unwrap_or(raw_str);
            // Invariant invariant: classify_source_dep now
            // returns a typed error for tarball-URL / file:tarball /
            // git transitives. Propagate at the manifest-read
            // boundary so the user sees a clear actionable message
            // pointing at the offending source dir + dep key,
            // instead of a deep "invalid semver range" error from
            // inside the resolver.
            let kind = classify_source_dep(source_dir, effective_raw, local_name)?;
            out.push(SourceDep {
                local_name: local_name.clone(),
                raw_spec: normalized_spec.unwrap_or_else(|| raw_str.to_string()),
                kind,
                optional: field == "optionalDependencies",
                target_source: None,
            });
        }
    }
    Ok(out)
}

/// Classify a single transitive dep spec from inside a local-source
/// `package.json` into [`DepKind`].
///
/// Uses [`lpm_resolver::Specifier::parse`] for canonical classification
/// — the same parser the IMMEDIATE arm of [`pre_resolve_non_registry_deps`]
/// uses at the root manifest depth. This keeps classification
/// behavior bit-identical between immediate and transitive arms.
///
/// **Allowed shapes (route through -transitive):**
/// - SemverRange / NpmAlias → [`DepKind::Registry`]; the
///   spec is appended to the consumer's `deps` map and the root
///   resolver (PubGrub or fusion) picks it up.
/// - Workspace → [`DepKind::Workspace`]; the local-source walker
///   resolves it against the workspace member set.
/// - `link:<path>` → [`DepKind::Link`]; recursed into and produces
///   a transitive InstallPackage.
/// - `file:<path>` whose target is a directory → [`DepKind::FileDir`];
///   same as `link:` for recursion purposes.
///
/// **Rejected shapes (hard error at manifest read time):**
/// - `https://…tgz` Tarball — these are not valid semver ranges for
///   [`lpm_resolver::ranges::NpmRange::parse`]. The immediate arm handles
///   tarball URLs at depth 0; transitive coverage requires deeper resolver
///   support.
/// - `file:<path>` whose target is a regular file (a tarball) —
///   same reason as above.
/// - `git+…` / git shorthand (`github:user/repo`, etc.) — same
///   resolver-crash story.
/// - `Specifier::parse` errors propagate as a typed manifest-
///   boundary error.
///
/// `dep_name` is the dep's KEY in the parent `package.json`
/// (`require(dep_name)`); included in the error message so the user
/// can locate the offending entry without grepping. `base_dir` is
/// the parent source's realpath, used for the file: stat AND the
/// error message.
pub(super) fn classify_source_dep(
    base_dir: &Path,
    raw: &str,
    dep_name: &str,
) -> Result<DepKind, LpmError> {
    if raw.starts_with("workspace:") {
        return Ok(DepKind::Workspace);
    }

    let unsupported_transitive = |kind: &str| -> LpmError {
        LpmError::Registry(format!(
            "transitive non-registry dep `{dep_name}` (\"{raw}\", a {kind}) declared in \
             {} is not supported in v1 — only registry, file: directory, and link: \
             specifiers may appear in a local-source's transitive dependency graph. \
             Tarball-URL, file:tarball, and git transitives crash the resolver because \
             they're not valid semver ranges. Workaround: hoist the dep to your \
             project's package.json (immediate non-registry deps work).",
            base_dir.display(),
        ))
    };

    match lpm_resolver::Specifier::parse(raw) {
        Ok(lpm_resolver::Specifier::SemverRange(_))
        | Ok(lpm_resolver::Specifier::NpmAlias { .. }) => Ok(DepKind::Registry),
        Ok(lpm_resolver::Specifier::Workspace(_)) => Ok(DepKind::Workspace),
        Ok(lpm_resolver::Specifier::Link { .. }) => Ok(DepKind::Link),
        Ok(lpm_resolver::Specifier::File { path }) => {
            // file: must be stat'd to disambiguate directory (FileDir,
            // walked) from regular file / tarball (rejected — see above).
            // Invariant invariant: distinguish the regular-file case
            // (likely a tarball, by far the most common shape) from
            // exotic file types (devices, fifos, sockets) so the error
            // message accurately describes what the user pointed at.
            let abs = base_dir.join(&path);
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.is_dir() => Ok(DepKind::FileDir),
                Ok(meta) if meta.is_file() => {
                    Err(unsupported_transitive("file: tarball (regular file)"))
                }
                Ok(_) => Err(unsupported_transitive(
                    "file: target of an unsupported file type (not a directory or regular file)",
                )),
                Err(e) => Err(LpmError::Registry(format!(
                    "transitive `file:` dep `{dep_name}` (\"{raw}\") declared in {} \
                     cannot be stat'd: {e}",
                    base_dir.display(),
                ))),
            }
        }
        Ok(lpm_resolver::Specifier::Tarball { .. }) => Err(unsupported_transitive("tarball URL")),
        Ok(lpm_resolver::Specifier::Git { .. }) => Err(unsupported_transitive("git source")),
        Err(e) => Err(LpmError::Registry(format!(
            "invalid transitive dep spec for `{dep_name}` (\"{raw}\") declared in {}: {e}",
            base_dir.display(),
        ))),
    }
}

/// outcome of comparing
/// a directory/link source's realpath against every workspace member.
///
/// Used by [`pre_resolve_non_registry_deps`] (and its recursive
/// walker) to either skip building an InstallPackage when the source
/// IS a workspace member, or to surface a hard error on version
/// drift between the workspace's recorded version and the source's
/// current `package.json` version.
pub(super) enum WorkspaceOverlap<'a> {
    /// No workspace member overlaps this source — proceed with
    /// normal directory/link InstallPackage construction.
    NoOverlap,
    /// Source realpath matches a workspace member; versions agree.
    /// The caller emits an info note and SKIPS building the
    /// InstallPackage — the workspace member is already extracted
    /// and will be linked by `link_workspace_members` after the
    /// install pipeline finishes.
    DedupeWith(&'a WorkspaceMemberLink),
}

/// Detect whether a directory/link source's realpath overlaps a
/// workspace member.
///
/// Path-comparison shape:
/// - **Realpath both sides** before comparing — tolerates relative
///   paths, symlinks, and `..` traversal that don't normalize to
///   identical lexical strings.
/// - **Windows case-fold** before comparing — `C:\Foo` and `c:\foo`
///   are the same dir on Windows. Lowercase the lossy string
///   representation before comparing on `target_os = "windows"`.
///   Non-Windows: byte-equal comparison suffices.
///
/// Version semantics: when realpaths match, read the source's
/// current `package.json` version and compare against the workspace
/// member's recorded version. A mismatch is a hard error
/// (`LpmError::Workspace`) — that means the workspace member's
/// metadata drifted from the source between workspace-discovery
/// time and pre_resolve time, which would silently corrupt the
/// install (the member's version is what's stamped into the
/// lockfile + `node_modules/<name>` symlink target).
///
/// Returns `WorkspaceOverlap::NoOverlap` if no member matches, or
/// `DedupeWith(member)` on a clean match. Errors are reserved for
/// the version-mismatch case.
pub(super) fn detect_workspace_overlap<'a>(
    source_realpath: &Path,
    source_version: &str,
    workspace_members: &'a [WorkspaceMemberLink],
    dep_local_name: &str,
    dep_raw_path: &str,
) -> Result<WorkspaceOverlap<'a>, LpmError> {
    if workspace_members.is_empty() {
        return Ok(WorkspaceOverlap::NoOverlap);
    }
    for member in workspace_members {
        // Canonicalize the member's source_dir for the comparison.
        // The dir was discovered by lpm-workspace; re-canonicalizing
        // here costs one stat per member but avoids storing
        // realpaths upstream just for this comparison.
        let Ok(member_realpath) = member.source_dir.canonicalize() else {
            // Member's source_dir is missing/unreadable —
            // workspace discovery should have caught this, so we
            // fall through to "no overlap" rather than masking the
            // upstream bug with a confusing error here.
            continue;
        };
        if !path_equal_with_case_fold(source_realpath, &member_realpath) {
            continue;
        }
        // Realpath matched. Verify version consistency.
        if member.version != source_version {
            return Err(LpmError::Workspace(format!(
                "dep '{dep_local_name}' uses '{dep_raw_path}' which resolves to \
                 workspace member '{name}', but versions disagree (workspace \
                 member declares version='{ws_ver}'; source's package.json \
                 declares version='{src_ver}'). Re-run `lpm install` from the \
                 workspace root to sync, or update one of the package.json \
                 files so both agree.",
                name = member.name,
                ws_ver = member.version,
                src_ver = source_version,
            )));
        }
        return Ok(WorkspaceOverlap::DedupeWith(member));
    }
    Ok(WorkspaceOverlap::NoOverlap)
}

/// Compare two paths for equality with platform-appropriate case
/// folding. Used by [`detect_workspace_overlap`] so a `file:` dep
/// that resolves to the same directory under a different
/// case-presentation (`C:\Foo` vs `c:\foo` on Windows) is detected
/// as the same.
///
/// Non-Windows: byte-equal `==`. Windows: lowercase the lossy
/// string representation and compare. The lossy form is acceptable
/// here because the comparison is for filesystem-level identity,
/// not display.
pub(super) fn path_equal_with_case_fold(a: &Path, b: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        a == b
    }
}

/// emit a warn-once for a
/// local source whose top-level `node_modules/` will be ignored.
///
/// The `materialize_directory_source` already excludes
/// `node_modules/` from the wrapper materialization (and any depth
/// deeper); 's contribution is the user-facing communication.
/// Each unique source realpath gets at most one warn per install
/// regardless of how many times it's encountered (immediate dep,
/// transitive dep, diamond from multiple parents) — keeps the
/// warn signal-to-noise high.
///
/// `warned_set` carries the dedupe state across the entire
/// pre_resolve invocation (immediate arms + recursive walker).
pub(super) fn maybe_warn_pkg_node_modules(
    source_realpath: &Path,
    dep_local_name: &str,
    json_output: bool,
    warned_set: &mut std::collections::HashSet<PathBuf>,
) {
    if json_output {
        return;
    }
    if !source_realpath.join("node_modules").is_dir() {
        return;
    }
    if !warned_set.insert(source_realpath.to_path_buf()) {
        // Already warned for this realpath in this install.
        return;
    }
    output::warn(&format!(
        "dep '{dep_local_name}' source at {} contains node_modules/ — \
         ignored (untracked host state would silently change install \
         output). Run `lpm install` in {} to populate the source's \
         own deps.",
        source_realpath.display(),
        source_realpath.display()
    ));
}

#[allow(clippy::too_many_arguments)]
fn promote_workspace_member_source_graph(
    project_dir: &Path,
    spec: &mut SourceDep,
    matched_member: &WorkspaceMemberLink,
    root_link_name: Option<&str>,
    consumer_deps_map: &mut HashMap<String, String>,
    install_pkgs_out: &mut Vec<InstallPackage>,
    source_deps_out: &mut HashMap<String, Vec<SourceDep>>,
    visited: &mut HashMap<PathBuf, String>,
    current_depth: u32,
    max_depth: u32,
    workspace_members: &[WorkspaceMemberLink],
    json_output: bool,
    node_modules_warned: &mut std::collections::HashSet<PathBuf>,
    additional_workspace_links: &mut Vec<WorkspaceMemberLink>,
    workspace_transitives: WorkspaceTransitiveMode,
    inherited_optional: bool,
) -> Result<(), LpmError> {
    let realpath = match matched_member.source_dir.canonicalize() {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };
    let source_string = workspace_member_source(project_dir, &matched_member.source_dir);
    if let Some(existing_source) = visited.get(&realpath) {
        spec.target_source = Some(existing_source.clone());
        if let Some(root_link_name) = root_link_name
            && let Some(package) = install_pkgs_out
                .iter_mut()
                .find(|package| package.source == *existing_source)
        {
            let root_links = package.root_link_names.get_or_insert_default();
            if !root_links.iter().any(|name| name == root_link_name) {
                root_links.push(root_link_name.to_string());
            }
        }
        return Ok(());
    }
    visited.insert(realpath.clone(), source_string.clone());
    spec.target_source = Some(source_string.clone());
    let node_engine = read_pkg_json_node_engine(
        &matched_member.source_dir,
        &format!(
            "workspace member at {}",
            matched_member.source_dir.display()
        ),
    )?;
    install_pkgs_out.push(InstallPackage {
        name: matched_member.name.clone(),
        version: matched_member.version.clone(),
        source: source_string.clone(),
        dependencies: Vec::new(),
        aliases: HashMap::new(),
        root_link_names: Some(root_link_name.into_iter().map(str::to_string).collect()),
        is_direct: false,
        is_lpm: false,
        peers: Vec::new(),
        integrity: None,
        registry_signatures: Vec::new(),
        registry_published_at: None,
        platform: None,
        node_engine,
        optional: inherited_optional || spec.optional,
        tarball_url: None,
        metadata_checked_for_tarball: false,
    });
    recurse_local_source_deps(
        project_dir,
        &realpath,
        &source_string,
        consumer_deps_map,
        install_pkgs_out,
        source_deps_out,
        visited,
        current_depth + 1,
        max_depth,
        workspace_members,
        json_output,
        node_modules_warned,
        additional_workspace_links,
        workspace_transitives,
        inherited_optional || spec.optional,
    )
}

/// recursively pre-resolve a
/// directory/link source's transitive deps.
///
/// For each immediate file:/link: dep produced by
/// [`pre_resolve_non_registry_deps`], this walks the source's
/// `package.json` and:
///
/// - **Stashes the source's dep specs** in `source_deps_out` keyed
///   by the parent's `source` string for the post-resolve fix-up.
/// - **Appends registry-style transitive deps to `consumer_deps_map`**
///   — pubgrub/fusion will pick them up. Existing entries take
///   precedence (consumer's own declaration or earlier-walked
///   transitive wins). This is the simple/lossy approach: foo's
///   `lodash@^4` and consumer's `lodash@^5` collapse to a single
///   resolved version (umbrella).
/// - **Recursively pre-resolves transitive `file:`/`link:` directory
///   deps** as new InstallPackages. Bounded at `max_depth` levels
///   from the consumer (default 3 — matches 's depth bound and
///   umbrella prepare-runner posture). Realpath cycle-detect via
///   `visited` so `A → B → A` doesn't infinite-loop.
///
/// `current_depth` is the depth of the deps we're ABOUT TO process.
/// Starts at 1 for an IMMEDIATE-level call (the consumer is depth 0,
/// and we're walking the deps an immediate dep declares). At depth
/// >= max_depth, the function early-returns without processing.
#[allow(clippy::too_many_arguments)]
pub(super) fn recurse_local_source_deps(
    project_dir: &Path,
    source_dir: &Path,
    parent_source_string: &str,
    consumer_deps_map: &mut HashMap<String, String>,
    install_pkgs_out: &mut Vec<InstallPackage>,
    source_deps_out: &mut HashMap<String, Vec<SourceDep>>,
    visited: &mut HashMap<PathBuf, String>,
    current_depth: u32,
    max_depth: u32,
    // ( + ): workspace overlap detection +
    // node_modules-warn dedupe propagated from the immediate arms
    // so transitive directory/link deps get the same treatment.
    workspace_members: &[WorkspaceMemberLink],
    json_output: bool,
    node_modules_warned: &mut std::collections::HashSet<PathBuf>,
    // the invariant invariant: transitive dedupe + the
    // the invariant transitive `workspace:` arm push the matched member
    // here so the install-pipeline caller can merge it into the slice
    // that drives `link_workspace_members`. Pre-the invariant these branches
    // silently dropped the member from the root-symlink set.
    additional_workspace_links: &mut Vec<WorkspaceMemberLink>,
    workspace_transitives: WorkspaceTransitiveMode,
    inherited_optional: bool,
) -> Result<(), LpmError> {
    if current_depth > max_depth {
        return Ok(());
    }
    let mut specs = read_source_dep_specs(source_dir)?;

    for spec in specs.iter_mut() {
        match spec.kind {
            DepKind::Registry => {
                // First-come-first-serve: consumer's own decl wins,
                // and the FIRST transitive dep encountered for a
                // given local_name wins over later ones. Acceptable
                // First match wins for deterministic resolver input.
                consumer_deps_map
                    .entry(spec.local_name.clone())
                    .or_insert_with(|| spec.raw_spec.clone());
            }
            DepKind::Workspace => {
                let matched_member = workspace_members.iter().find(|m| m.name == spec.local_name);
                let Some(matched_member) = matched_member else {
                    let mut available: Vec<&str> =
                        workspace_members.iter().map(|m| m.name.as_str()).collect();
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
                         when the consumer's project is a workspace AND the named \
                         package is a member.",
                        spec.local_name,
                        spec.raw_spec,
                        source_dir.display(),
                        spec.local_name,
                        available_str,
                    )));
                };
                let optional_path = inherited_optional || spec.optional;
                let graph_backed_root_link = matches!(
                    workspace_transitives,
                    WorkspaceTransitiveMode::RootSymlinkOnly
                ) && optional_path;
                if !graph_backed_root_link {
                    additional_workspace_links.push(WorkspaceMemberLink {
                        name: spec.local_name.clone(),
                        version: matched_member.version.clone(),
                        source_dir: matched_member.source_dir.clone(),
                    });
                }
                if matches!(
                    workspace_transitives,
                    WorkspaceTransitiveMode::RootSymlinkOnly
                ) && !optional_path
                {
                    continue;
                }
                let root_link_name = graph_backed_root_link.then(|| spec.local_name.clone());

                promote_workspace_member_source_graph(
                    project_dir,
                    spec,
                    matched_member,
                    root_link_name.as_deref(),
                    consumer_deps_map,
                    install_pkgs_out,
                    source_deps_out,
                    visited,
                    current_depth,
                    max_depth,
                    workspace_members,
                    json_output,
                    node_modules_warned,
                    additional_workspace_links,
                    workspace_transitives,
                    optional_path,
                )?;
            }
            DepKind::FileDir | DepKind::Link => {
                let path_str = if let Some(p) = spec.raw_spec.strip_prefix("file:") {
                    p
                } else if let Some(p) = spec.raw_spec.strip_prefix("link:") {
                    p
                } else {
                    // Unreachable per classify_source_dep contract.
                    continue;
                };
                let abs = source_dir.join(path_str);
                let realpath = match abs.canonicalize() {
                    Ok(p) => p,
                    Err(_) => continue, // skipped — install pipeline surfaces real errors
                };
                if let Some(existing_source) = visited.get(&realpath) {
                    spec.target_source = Some(existing_source.clone());
                    continue;
                }
                let (real_name, real_version, node_engine) = read_pkg_json_name_version(
                    &realpath,
                    &format!("transitive local source at {}", realpath.display()),
                )?;
                // (): workspace overlap on
                // transitive deps too. Same dedupe-or-error logic
                // as the immediate arms.
                match detect_workspace_overlap(
                    &realpath,
                    &real_version,
                    workspace_members,
                    &spec.local_name,
                    &spec.raw_spec,
                )? {
                    WorkspaceOverlap::DedupeWith(member) => {
                        if !json_output {
                            output::info(&format!(
                                "note: transitive '{}' at {} resolves to workspace \
                                 member '{}'; using workspace symlink instead",
                                spec.local_name,
                                realpath.display(),
                                member.name,
                            ));
                        }
                        let optional_path = inherited_optional || spec.optional;
                        let graph_backed_root_link = matches!(
                            workspace_transitives,
                            WorkspaceTransitiveMode::RootSymlinkOnly
                        ) && optional_path;
                        if !graph_backed_root_link {
                            additional_workspace_links.push(WorkspaceMemberLink {
                                name: spec.local_name.clone(),
                                version: member.version.clone(),
                                source_dir: member.source_dir.clone(),
                            });
                        }
                        if matches!(workspace_transitives, WorkspaceTransitiveMode::SourceGraph)
                            || graph_backed_root_link
                        {
                            let root_link_name =
                                graph_backed_root_link.then(|| spec.local_name.clone());
                            promote_workspace_member_source_graph(
                                project_dir,
                                spec,
                                member,
                                root_link_name.as_deref(),
                                consumer_deps_map,
                                install_pkgs_out,
                                source_deps_out,
                                visited,
                                current_depth,
                                max_depth,
                                workspace_members,
                                json_output,
                                node_modules_warned,
                                additional_workspace_links,
                                workspace_transitives,
                                optional_path,
                            )?;
                        }
                        continue;
                    }
                    WorkspaceOverlap::NoOverlap => {}
                }
                // (): warn-once on top-level
                // node_modules/ for transitives too — the dedupe set
                // is shared with the immediate arms above.
                maybe_warn_pkg_node_modules(
                    &realpath,
                    &spec.local_name,
                    json_output,
                    node_modules_warned,
                );
                let source_string = match spec.kind {
                    DepKind::FileDir => format!("directory+{path_str}"),
                    DepKind::Link => format!("link+{path_str}"),
                    DepKind::Registry | DepKind::Workspace => unreachable!(),
                };
                spec.target_source = Some(source_string.clone());
                visited.insert(realpath.clone(), source_string.clone());
                install_pkgs_out.push(InstallPackage {
                    name: real_name,
                    version: real_version,
                    source: source_string.clone(),
                    // Populated by the post-resolve fix-up after the
                    // resolver has produced concrete versions for
                    // every registry dep referenced from this
                    // source.
                    dependencies: Vec::new(),
                    aliases: HashMap::new(),
                    // TRANSITIVE — not at the project root. This is
                    // what differentiates a transitive directory/
                    // link InstallPackage from an immediate one.
                    root_link_names: Some(Vec::new()),
                    is_direct: false,
                    is_lpm: false,
                    peers: Vec::new(),
                    integrity: None,
                    registry_signatures: Vec::new(),
                    registry_published_at: None,
                    platform: None,
                    node_engine,
                    optional: inherited_optional || spec.optional,
                    tarball_url: None,
                    metadata_checked_for_tarball: false,
                });
                // Recurse into THIS dep's source at depth + 1.
                recurse_local_source_deps(
                    project_dir,
                    &realpath,
                    &source_string,
                    consumer_deps_map,
                    install_pkgs_out,
                    source_deps_out,
                    visited,
                    current_depth + 1,
                    max_depth,
                    workspace_members,
                    json_output,
                    node_modules_warned,
                    additional_workspace_links,
                    workspace_transitives,
                    inherited_optional || spec.optional,
                )?;
            }
        }
    }
    source_deps_out.insert(parent_source_string.to_string(), specs);
    Ok(())
}

/// post-resolve fix-up that
/// populates each directory/link `InstallPackage.dependencies`
/// field.
///
/// **Resolver-agnostic** (per plan): runs after the merged
/// `packages` vec is assembled (i.e., after both `resolved_to_install_packages`
/// AND the non-registry merge), regardless of which resolver
/// produced the registry portion.
///
/// For each directory/link InstallPackage, looks up its source-deps
/// in `source_deps` and produces `(local_name, target_segment_value)`
/// pairs for the linker:
///
/// - Registry dep → `(local_name, resolved_version)`. The resolved
///   version comes from another InstallPackage in `packages` whose
///   name matches. The linker uses this to build
///   `<safe>@<resolved_version>/...` symlink targets.
/// - FileDir/Link dep → `(local_name, source_id)` from the exact
///   `target_source` recorded by the recursive local-source walker.
///
/// Missing-from-packages registry deps are skipped (the resolver
/// failed to provide a version, which is a separate bug surfaced
/// upstream). Missing-from-source_deps directory/link InstallPackages
/// (not in the map) are left with empty dependencies — common for
/// CAS-backed deps the work doesn't touch.
pub(super) fn apply_post_resolve_directory_link_fixup(
    packages: &mut [InstallPackage],
    source_deps: &HashMap<String, Vec<SourceDep>>,
) {
    // Build indexes over the merged list. Registry/tarball entries
    // are still resolved by package name here; directory/link edges
    // resolve by exact source string so same-name local forks do not
    // collapse onto the first package encountered.
    let mut name_to_version: HashMap<String, String> = HashMap::new();
    let mut source_to_source_id: HashMap<String, String> = HashMap::new();
    for p in packages.iter() {
        if let Ok(s) = p.source_kind() {
            match s {
                lpm_lockfile::Source::Directory { .. } | lpm_lockfile::Source::Link { .. } => {
                    if let Some(sid) = p.wrapper_id_for_source() {
                        source_to_source_id.entry(p.source.clone()).or_insert(sid);
                    }
                }
                _ => {
                    name_to_version
                        .entry(p.name.clone())
                        .or_insert(p.version.clone());
                }
            }
        }
    }

    // Walk and patch.
    for p in packages.iter_mut() {
        let Ok(s) = p.source_kind() else {
            continue;
        };
        let is_local = matches!(
            s,
            lpm_lockfile::Source::Directory { .. } | lpm_lockfile::Source::Link { .. }
        );
        if !is_local {
            continue;
        }
        let Some(specs) = source_deps.get(&p.source) else {
            // No stashed source-deps for this entry — leave
            // `dependencies` as-is (Vec::new() from pre_resolve).
            continue;
        };
        let mut deps_out: Vec<(String, String)> = Vec::with_capacity(specs.len());
        let mut aliases_out: HashMap<String, String> = HashMap::new();
        for spec in specs {
            match spec.kind {
                DepKind::Registry => {
                    let alias = lpm_resolver::ranges::parse_npm_alias(&spec.raw_spec);
                    let lookup_name = alias
                        .as_ref()
                        .map_or(spec.local_name.as_str(), |a| a.target.as_str());
                    if let Some(version) = name_to_version.get(lookup_name) {
                        deps_out.push((spec.local_name.clone(), version.clone()));
                        if let Some(alias) = alias {
                            aliases_out.insert(spec.local_name.clone(), alias.target);
                        }
                    }
                    // Missing → resolver didn't fulfill this spec
                    // (e.g., optionalDependencies platform-skip).
                    // Drop silently; the linker won't try to
                    // create a symlink without a corresponding
                    // wrapper.
                }
                DepKind::FileDir | DepKind::Link | DepKind::Workspace => {
                    if let Some(target_source) = &spec.target_source
                        && let Some(sid) = source_to_source_id.get(target_source)
                    {
                        deps_out.push((spec.local_name.clone(), sid.clone()));
                    }
                }
            }
        }
        p.dependencies = deps_out;
        p.aliases.extend(aliases_out);
    }

    apply_local_source_optionality(packages, source_deps);
}

fn apply_local_source_optionality(
    packages: &mut [InstallPackage],
    source_deps: &HashMap<String, Vec<SourceDep>>,
) {
    let local_sources = all_local_sources(source_deps);
    let required_sources = required_local_sources(packages, source_deps);
    for package in packages {
        if local_sources.contains(package.source.as_str()) {
            package.optional = !required_sources.contains(package.source.as_str());
        }
    }
}

fn all_local_sources(source_deps: &HashMap<String, Vec<SourceDep>>) -> HashSet<&str> {
    let mut local_sources: HashSet<&str> = HashSet::with_capacity(source_deps.len() * 2);
    for (source, specs) in source_deps {
        local_sources.insert(source);
        for spec in specs {
            if let Some(target_source) = spec.target_source.as_deref() {
                local_sources.insert(target_source);
            }
        }
    }
    local_sources
}

fn required_local_sources<'a>(
    packages: &[InstallPackage],
    source_deps: &'a HashMap<String, Vec<SourceDep>>,
) -> HashSet<&'a str> {
    let local_sources = all_local_sources(source_deps);
    let mut required_sources: HashSet<&str> = HashSet::with_capacity(local_sources.len());
    let mut queue = VecDeque::with_capacity(local_sources.len());
    for package in packages.iter() {
        if !package.is_direct {
            continue;
        }
        let Some(&source) = local_sources.get(package.source.as_str()) else {
            continue;
        };
        if required_sources.insert(source) {
            queue.push_back(source);
        }
    }

    while let Some(source) = queue.pop_front() {
        let Some(specs) = source_deps.get(source) else {
            continue;
        };
        for spec in specs {
            if spec.optional {
                continue;
            }
            let Some(target_source) = spec.target_source.as_deref() else {
                continue;
            };
            let Some(&target_source) = local_sources.get(target_source) else {
                continue;
            };
            if required_sources.insert(target_source) {
                queue.push_back(target_source);
            }
        }
    }
    required_sources
}

fn registry_root_optionality(
    packages: &[InstallPackage],
    source_deps: &HashMap<String, Vec<SourceDep>>,
) -> RegistryRootOptionality {
    let required_sources = required_local_sources(packages, source_deps);
    let mut optionality = RegistryRootOptionality::default();
    for (source, specs) in source_deps {
        let parent_required = required_sources.contains(source.as_str());
        for spec in specs {
            if !matches!(spec.kind, DepKind::Registry) {
                continue;
            }
            if parent_required && !spec.optional {
                optionality.required.insert(spec.local_name.clone());
            } else {
                optionality.optional.insert(spec.local_name.clone());
            }
        }
    }
    optionality
}

fn merge_optional_registry_roots(
    dependency_names_before_expansion: &HashSet<String>,
    inherited_optional: &HashSet<String>,
    source_optionality: RegistryRootOptionality,
) -> HashSet<String> {
    let mut optional = inherited_optional.clone();
    optional.extend(source_optionality.optional);
    for name in source_optionality.required {
        optional.remove(&name);
    }
    for name in dependency_names_before_expansion {
        if !inherited_optional.contains(name) {
            optional.remove(name);
        }
    }
    optional
}
