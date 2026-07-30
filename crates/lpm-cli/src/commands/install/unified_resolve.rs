//! Unified workspace resolution.
//!
//! A recursive workspace install runs one install pipeline per target,
//! and without coordination every pipeline re-resolves a heavily
//! overlapping dependency graph. This module lets compatible targets
//! share ONE resolver pass: the first target that reaches fresh
//! resolution resolves the union of every compatible target's direct
//! dependencies, then each target consumes a per-target slice of the
//! union graph instead of resolving again.
//!
//! Correctness model:
//! - Targets are grouped by a resolution-context fingerprint (their
//!   manifest's overrides / resolutions / resolution-relevant `lpm`
//!   config). Only identical contexts share a pass — overrides and
//!   release-age policy are read from the target's own manifest, so a
//!   union resolve is only equivalent when those inputs are equal.
//! - Within a group, targets whose direct specs conflict on the same
//!   label are excluded (they resolve alone).
//! - Every consumer verifies coverage before trusting a slice: each of
//!   its pipeline-normalized registry labels must appear in the union
//!   root with a byte-identical spec, otherwise it falls back to its
//!   own resolve. Precomputation therefore only affects the hit rate,
//!   never correctness.
//! - Targets with an existing lockfile, `--force`, `--offline`, or an
//!   active frozen-lockfile mode never participate: their existing
//!   flows are untouched.

use super::*;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex as StdMutex;
use tokio::sync::Notify;

tokio::task_local! {
    static ACTIVE_WORKSPACE_RESOLVE: Arc<WorkspaceResolvePlan>;
}

pub(super) async fn scope_if<F>(plan: Option<Arc<WorkspaceResolvePlan>>, future: F) -> F::Output
where
    F: Future,
{
    match plan {
        Some(plan) => ACTIVE_WORKSPACE_RESOLVE.scope(plan, future).await,
        None => future.await,
    }
}

pub(super) struct WorkspaceResolvePlan {
    groups_by_target: HashMap<PathBuf, Arc<ResolveGroup>>,
}

pub(super) struct ResolveGroup {
    union_deps: HashMap<String, String>,
    state: StdMutex<GroupResolveState>,
    notify: Notify,
}

enum GroupResolveState {
    Pending,
    Resolving,
    Published(Arc<UnifiedResolveOutcome>),
    Failed,
}

/// Union graph published by the triggering target. `packages` is the
/// pre-filter lockfile superset — consumers re-run the per-target
/// omit / engine / platform filters on their slice.
pub(super) struct UnifiedResolveOutcome {
    packages: Vec<InstallPackage>,
    index_by_label: HashMap<String, usize>,
    index_by_name_version: HashMap<(String, String), usize>,
    direct_spec_by_label: HashMap<String, String>,
    ambient_peer_installs: Vec<String>,
    auto_isolated_peer_conflicts: bool,
    effective_linker_mode: lpm_linker::LinkerMode,
}

/// Slice of the union graph handed to one target's resolution phase.
pub(in crate::commands::install) struct PreresolvedWorkspacePackages {
    pub(in crate::commands::install) packages: Vec<InstallPackage>,
    pub(in crate::commands::install) ambient_peer_installs: Vec<String>,
    pub(in crate::commands::install) auto_isolated_peer_conflicts: bool,
    pub(in crate::commands::install) linker_mode: lpm_linker::LinkerMode,
}

pub(super) enum UnifiedResolveRole {
    None,
    Trigger(TriggerRole),
    Waiter(Arc<ResolveGroup>),
}

impl UnifiedResolveRole {
    /// Release-age canonical keys for the union labels a trigger added
    /// on top of its own baseline. `None` for non-trigger roles.
    pub(super) fn union_extra_release_age_canonicals(
        &self,
        deps: &HashMap<String, String>,
    ) -> Option<Vec<lpm_resolver::CanonicalKey>> {
        let UnifiedResolveRole::Trigger(trigger) = self else {
            return None;
        };
        let extras: HashMap<String, String> = deps
            .iter()
            .filter(|(label, _)| !trigger.baseline_labels.contains(*label))
            .map(|(label, spec)| (label.clone(), spec.clone()))
            .collect();
        Some(direct_release_age_canonicals(&extras))
    }
}

pub(super) struct TriggerRole {
    group: Arc<ResolveGroup>,
    // Labels the trigger's own pipeline had before the union widened
    // `deps`. The trigger's slice starts from these; anything else it
    // genuinely needs (e.g. registry deps injected for its workspace
    // links) is reached through package edges during reduction.
    baseline_labels: HashSet<String>,
    published: bool,
}

impl Drop for TriggerRole {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // The trigger errored before publishing; release every waiter
        // to its own resolve instead of leaving it parked forever.
        *self
            .group
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = GroupResolveState::Failed;
        self.group.notify.notify_waiters();
    }
}

/// Build the resolve plan for one recursive run. Returns `None` when no
/// two targets can share a pass.
pub(super) fn build_workspace_resolve_plan(
    workspace: &lpm_workspace::Workspace,
    target_paths: &[(PathBuf, bool)],
) -> Option<Arc<WorkspaceResolvePlan>> {
    if target_paths.len() < 2 {
        return None;
    }
    if std::env::var("LPM_WORKSPACE_UNIFIED_RESOLVE").as_deref() == Ok("0") {
        return None;
    }
    let catalogs = &workspace.root_package.catalogs;
    // Labels naming a workspace package can be linked instead of
    // registry-resolved (bare-name member deps have no `workspace:`
    // marker), so they never enter a union.
    let workspace_package_names: HashSet<&str> = workspace
        .members
        .iter()
        .filter_map(|member| member.package.name.as_deref())
        .chain(workspace.root_package.name.as_deref())
        .collect();
    type FingerprintMembers = Vec<(PathBuf, HashMap<String, String>)>;
    let mut by_fingerprint: Vec<(String, FingerprintMembers)> = Vec::new();
    for (path, is_root) in target_paths {
        let pkg = if *is_root {
            &workspace.root_package
        } else {
            match workspace.members.iter().find(|member| &member.path == path) {
                Some(member) => &member.package,
                None => continue,
            }
        };
        let Some(deps) = union_candidate_deps(pkg, catalogs, &workspace_package_names) else {
            continue;
        };
        let fingerprint = resolution_context_fingerprint(pkg);
        match by_fingerprint
            .iter_mut()
            .find(|(existing, _)| *existing == fingerprint)
        {
            Some((_, members)) => members.push((path.clone(), deps)),
            None => by_fingerprint.push((fingerprint, vec![(path.clone(), deps)])),
        }
    }

    let mut groups_by_target = HashMap::new();
    for (_, members) in by_fingerprint {
        if members.len() < 2 {
            continue;
        }
        let mut union: HashMap<String, String> = HashMap::new();
        let mut admitted: Vec<PathBuf> = Vec::new();
        'member: for (path, deps) in members {
            for (label, spec) in &deps {
                if union.get(label).is_some_and(|existing| existing != spec) {
                    continue 'member;
                }
            }
            union.extend(deps);
            admitted.push(path);
        }
        if admitted.len() < 2 || union.is_empty() {
            continue;
        }
        let group = Arc::new(ResolveGroup {
            union_deps: union,
            state: StdMutex::new(GroupResolveState::Pending),
            notify: Notify::new(),
        });
        for path in admitted {
            groups_by_target.insert(path, Arc::clone(&group));
        }
    }
    if groups_by_target.is_empty() {
        return None;
    }
    Some(Arc::new(WorkspaceResolvePlan { groups_by_target }))
}

/// A target's union-candidate direct deps: manifest deps with the same
/// jsr / catalog normalization the pipeline applies, restricted to
/// plain registry specs. Divergence from pipeline normalization is
/// caught by the consumer coverage check, not assumed away.
fn union_candidate_deps(
    pkg: &lpm_workspace::PackageJson,
    catalogs: &HashMap<String, HashMap<String, String>>,
    workspace_package_names: &HashSet<&str>,
) -> Option<HashMap<String, String>> {
    let mut deps = manifest_install_deps(pkg);
    normalize_jsr_manifest_deps(&mut deps).ok()?;
    lpm_workspace::resolve_catalog_protocol(&mut deps, catalogs).ok()?;
    deps.retain(|label, spec| {
        !workspace_package_names.contains(label.as_str()) && is_union_registry_spec(spec)
    });
    Some(deps)
}

fn is_union_registry_spec(spec: &str) -> bool {
    const NON_REGISTRY_PREFIXES: [&str; 12] = [
        "workspace:",
        "catalog:",
        "file:",
        "link:",
        "portal:",
        "git+",
        "git://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "http://",
        "https://",
    ];
    !NON_REGISTRY_PREFIXES
        .iter()
        .any(|prefix| spec.starts_with(prefix))
}

/// Everything in a target's manifest that changes what its OWN resolve
/// would produce. Targets share a union pass only on exact equality.
/// Engine policy is intentionally absent: it is sourced from the
/// workspace root for every target.
fn resolution_context_fingerprint(pkg: &lpm_workspace::PackageJson) -> String {
    fn sorted(map: &HashMap<String, String>) -> BTreeMap<&str, &str> {
        map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }
    let lpm = pkg.lpm.as_ref();
    let patched: BTreeMap<&str, String> = lpm
        .map(|lpm| {
            lpm.patched_dependencies
                .iter()
                .map(|(name, entry)| (name.as_str(), format!("{entry:?}")))
                .collect()
        })
        .unwrap_or_default();
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        sorted(&pkg.overrides),
        sorted(&pkg.resolutions),
        lpm.map(|l| sorted(&l.overrides)),
        patched,
        lpm.and_then(|l| l.minimum_release_age),
        lpm.map(|l| {
            let mut exclude = l.minimum_release_age_exclude.clone();
            exclude.sort();
            exclude
        }),
        lpm.and_then(|l| l.minimum_release_age_policy.as_deref()),
        lpm.map(|l| format!("{:?}", l.peer_dependency_rules)),
        lpm.and_then(|l| l.auto_install_peers),
        lpm.and_then(|l| l.strict_peer_dependencies),
        lpm.and_then(|l| l.linker.as_deref()),
        lpm.and_then(|l| l.strict_deps.as_deref()),
    )
}

/// Decide this target's role. Called once per pipeline, after workspace
/// and catalog normalization of `deps` and before the resolver policy
/// is derived — a trigger widens `deps` to the group union here so
/// release-age and routing see every union root.
pub(super) fn prepare_role(
    project_dir: &Path,
    lockfile_path: &Path,
    force: bool,
    offline: bool,
    frozen_lockfile_active: bool,
    deps: &mut HashMap<String, String>,
) -> UnifiedResolveRole {
    let Ok(Some(group)) = ACTIVE_WORKSPACE_RESOLVE
        .try_with(|plan| plan.groups_by_target.get(project_dir).map(Arc::clone))
    else {
        return UnifiedResolveRole::None;
    };
    if force || offline || frozen_lockfile_active || lpm_lockfile::Lockfile::exists(lockfile_path) {
        return UnifiedResolveRole::None;
    }
    let mut state = group
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match *state {
        GroupResolveState::Pending => {
            *state = GroupResolveState::Resolving;
            drop(state);
            let baseline_labels: HashSet<String> = deps.keys().cloned().collect();
            for (label, spec) in &group.union_deps {
                if !deps.contains_key(label) {
                    deps.insert(label.clone(), spec.clone());
                }
            }
            UnifiedResolveRole::Trigger(TriggerRole {
                group: Arc::clone(&group),
                baseline_labels,
                published: false,
            })
        }
        GroupResolveState::Resolving | GroupResolveState::Published(_) => {
            drop(state);
            UnifiedResolveRole::Waiter(group)
        }
        GroupResolveState::Failed => UnifiedResolveRole::None,
    }
}

/// Waiter side: await the group outcome and slice it for this target.
/// `None` means "resolve yourself" (trigger failed, or coverage
/// mismatch between this target's normalized deps and the union root).
pub(super) async fn preresolved_for_waiter(
    role: &UnifiedResolveRole,
    deps: &HashMap<String, String>,
) -> Option<PreresolvedWorkspacePackages> {
    let UnifiedResolveRole::Waiter(group) = role else {
        return None;
    };
    let outcome = loop {
        let notified = group.notify.notified();
        {
            let state = group
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*state {
                GroupResolveState::Published(outcome) => break Arc::clone(outcome),
                GroupResolveState::Failed => return None,
                GroupResolveState::Pending | GroupResolveState::Resolving => {}
            }
        }
        notified.await;
    };
    slice_for_labels(&outcome, own_registry_labels(deps, &HashSet::new()), &[])
}

fn own_registry_labels<'a>(
    deps: &'a HashMap<String, String>,
    exclude: &HashSet<String>,
) -> Vec<(&'a String, &'a String)> {
    deps.iter()
        .filter(|(label, spec)| !exclude.contains(*label) && is_union_registry_spec(spec))
        .collect()
}

fn slice_for_labels(
    outcome: &UnifiedResolveOutcome,
    labels: Vec<(&String, &String)>,
    extra_edge_roots: &[usize],
) -> Option<PreresolvedWorkspacePackages> {
    let mut direct_labels_by_index: HashMap<usize, Vec<String>> = HashMap::new();
    let mut queue: Vec<usize> = Vec::with_capacity(labels.len() + extra_edge_roots.len());
    for (label, spec) in labels {
        if outcome.direct_spec_by_label.get(label) != Some(spec) {
            return None;
        }
        let index = *outcome.index_by_label.get(label)?;
        direct_labels_by_index
            .entry(index)
            .or_default()
            .push(label.clone());
        queue.push(index);
    }
    queue.extend_from_slice(extra_edge_roots);

    let mut selected: HashSet<usize> = HashSet::new();
    while let Some(index) = queue.pop() {
        if !selected.insert(index) {
            continue;
        }
        let package = &outcome.packages[index];
        for (local, value) in &package.dependencies {
            if looks_like_source_dependency_key(value) {
                continue;
            }
            let name = package.aliases.get(local).unwrap_or(local);
            if let Some(&next) = outcome
                .index_by_name_version
                .get(&(name.clone(), value.clone()))
            {
                queue.push(next);
            }
        }
        for (peer_name, peer_version) in &package.peers {
            if let Some(&next) = outcome
                .index_by_name_version
                .get(&(peer_name.clone(), peer_version.clone()))
            {
                queue.push(next);
            }
        }
    }

    let mut ordered: Vec<usize> = selected.into_iter().collect();
    ordered.sort_unstable();
    let packages: Vec<InstallPackage> = ordered
        .into_iter()
        .map(|index| {
            let mut package = outcome.packages[index].clone();
            match direct_labels_by_index.get(&index) {
                Some(labels) => {
                    let mut labels = labels.clone();
                    labels.sort();
                    package.is_direct = true;
                    package.root_link_names = Some(labels);
                }
                None => {
                    package.is_direct = false;
                    package.root_link_names = None;
                }
            }
            package
        })
        .collect();
    let names: HashSet<&str> = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    Some(PreresolvedWorkspacePackages {
        ambient_peer_installs: outcome
            .ambient_peer_installs
            .iter()
            .filter(|name| names.contains(name.as_str()))
            .cloned()
            .collect(),
        auto_isolated_peer_conflicts: outcome.auto_isolated_peer_conflicts,
        linker_mode: outcome.effective_linker_mode,
        packages,
    })
}

fn is_registry_package(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Registry { .. })
    )
}

/// Trigger side, immediately after its resolution phase returned the
/// union graph: publish the outcome for waiters, then reduce the
/// trigger's own package sets to its slice so its lockfile, firewall
/// checks, fetches, and links cover exactly its own graph.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish_and_reduce_trigger(
    role: &mut UnifiedResolveRole,
    deps: &HashMap<String, String>,
    packages: &mut Vec<InstallPackage>,
    packages_for_lockfile: &mut Vec<InstallPackage>,
    ambient_peer_installs_for_lockfile: &mut Vec<String>,
    auto_isolated_peer_conflicts: bool,
    effective_linker_mode: lpm_linker::LinkerMode,
) {
    let UnifiedResolveRole::Trigger(trigger) = role else {
        return;
    };

    let mut index_by_label = HashMap::new();
    let mut index_by_name_version = HashMap::new();
    for (index, package) in packages_for_lockfile.iter().enumerate() {
        if !is_registry_package(package) {
            continue;
        }
        index_by_name_version
            .entry((package.name.clone(), package.version.clone()))
            .or_insert(index);
        if let Some(labels) = &package.root_link_names {
            for label in labels {
                index_by_label.entry(label.clone()).or_insert(index);
            }
        }
    }
    let direct_spec_by_label: HashMap<String, String> = deps
        .iter()
        .filter(|(_, spec)| is_union_registry_spec(spec))
        .map(|(label, spec)| (label.clone(), spec.clone()))
        .collect();
    let outcome = Arc::new(UnifiedResolveOutcome {
        packages: packages_for_lockfile.clone(),
        index_by_label,
        index_by_name_version,
        direct_spec_by_label,
        ambient_peer_installs: ambient_peer_installs_for_lockfile.clone(),
        auto_isolated_peer_conflicts,
        effective_linker_mode,
    });
    {
        *trigger
            .group
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            GroupResolveState::Published(Arc::clone(&outcome));
        trigger.published = true;
    }
    trigger.group.notify.notify_waiters();

    // The trigger's slice starts from the labels it had before the
    // union widened `deps`, plus every registry subtree its
    // non-registry packages (workspace links, tarballs) reference by
    // edge — those edges are what its linker will walk.
    let own_labels: Vec<(&String, &String)> = deps
        .iter()
        .filter(|(label, spec)| {
            trigger.baseline_labels.contains(*label) && is_union_registry_spec(spec)
        })
        .collect();
    let mut extra_edge_roots: Vec<usize> = Vec::new();
    for package in packages_for_lockfile.iter() {
        if is_registry_package(package) {
            continue;
        }
        for (local, value) in &package.dependencies {
            if looks_like_source_dependency_key(value) {
                continue;
            }
            let name = package.aliases.get(local).unwrap_or(local);
            if let Some(&index) = outcome
                .index_by_name_version
                .get(&(name.clone(), value.clone()))
            {
                extra_edge_roots.push(index);
            }
        }
    }
    let Some(own) = slice_for_labels(&outcome, own_labels, &extra_edge_roots) else {
        // Unreachable by construction (the trigger's own labels are
        // union roots); keep the union result rather than failing.
        tracing::warn!(
            "workspace unified resolve: trigger slice was not derivable; keeping union graph"
        );
        return;
    };

    let mut slice_flags: HashMap<String, (bool, Option<Vec<String>>)> =
        HashMap::with_capacity(own.packages.len());
    for package in &own.packages {
        slice_flags.insert(
            install_pkg_key(package),
            (package.is_direct, package.root_link_names.clone()),
        );
    }

    let non_registry: Vec<InstallPackage> = packages_for_lockfile
        .iter()
        .filter(|package| !is_registry_package(package))
        .cloned()
        .collect();
    *packages_for_lockfile = own.packages;
    packages_for_lockfile.extend(non_registry);

    packages.retain(|package| {
        !is_registry_package(package) || slice_flags.contains_key(&install_pkg_key(package))
    });
    for package in packages.iter_mut() {
        if let Some((is_direct, root_link_names)) = slice_flags.get(&install_pkg_key(package)) {
            package.is_direct = *is_direct;
            package.root_link_names = root_link_names.clone();
        }
    }
    ambient_peer_installs_for_lockfile.retain(|name| {
        packages_for_lockfile
            .iter()
            .any(|package| &package.name == name)
    });
}
