use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use lpm_registry::{RegistryClient, RouteTable};

use super::policy::apply_peer_override_target_greedy;
use super::version::{VersionPick, find_best_version_with_policy};
use super::{
    SharedMetadataConcurrency,
    resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots,
};
use crate::overrides::{OverrideHit, OverrideSet};
use crate::package::CanonicalKey;
use crate::policy::ResolverPolicy;
use crate::provider::{CachedPackageInfo, SharedCache, is_platform_compatible};
use crate::ranges::NpmRange;
use crate::resolve::{ResolveError, ResolveResult, ResolvedPackage, RootDependencies};
use crate::specifier::Specifier;

const MAX_AMBIENT_PEER_EXPANSION_PASSES: usize = 4;

pub enum WorkspaceResolveOutcome {
    Projected {
        results: Vec<Option<ResolveResult>>,
        timing: crate::resolve::WorkspaceUnionStageTiming,
    },
    RequiresIsolatedResolution,
}

struct RootSlot {
    synthetic: String,
    local: String,
    target: String,
    optional: bool,
    alias: bool,
}

struct UnionRoots {
    dependencies: RootDependencies,
    slots: Vec<Option<Vec<RootSlot>>>,
    eligible_importer_count: usize,
    root_specifier_isolated_count: usize,
}

type PeerRequirement = (usize, String, NpmRange, bool);

#[allow(clippy::too_many_arguments)]
pub async fn resolve_greedy_fused_workspace_with_cache_options_and_policy(
    client: Arc<RegistryClient>,
    roots: Vec<RootDependencies>,
    overrides: OverrideSet,
    route_table: RouteTable,
    npm_fanout: usize,
    shared_cache: SharedCache,
    auto_install_peers: bool,
    include_optional_dependencies: bool,
    policies: Vec<ResolverPolicy>,
    shared_fact_cache: Option<SharedCache>,
    shared_metadata_concurrency: Option<SharedMetadataConcurrency>,
) -> Result<WorkspaceResolveOutcome, ResolveError> {
    if roots.len() != policies.len() {
        return Err(ResolveError::Internal(format!(
            "workspace union received {} roots but {} policies",
            roots.len(),
            policies.len()
        )));
    }
    let Some(first_policy) = policies.first() else {
        tracing::debug!(
            reason = "empty-union-group",
            "workspace union resolution retained isolated importer fallbacks"
        );
        return Ok(WorkspaceResolveOutcome::RequiresIsolatedResolution);
    };
    let group_key = first_policy.workspace_resolution_key();
    if policies
        .iter()
        .any(|policy| policy.workspace_resolution_key() != group_key)
    {
        tracing::debug!(
            importers = policies.len(),
            reason = "policy-key-mismatch",
            "workspace union resolution retained isolated importer fallbacks"
        );
        return Ok(WorkspaceResolveOutcome::RequiresIsolatedResolution);
    }
    let UnionRoots {
        mut dependencies,
        slots,
        eligible_importer_count,
        root_specifier_isolated_count,
    } = union_root_dependencies(&roots)?;
    if eligible_importer_count < 2 {
        tracing::debug!(
            importers = roots.len(),
            eligible_importers = eligible_importer_count,
            reason = "fewer-than-two-eligible-importers",
            "workspace union resolution retained isolated importer fallbacks"
        );
        return Ok(WorkspaceResolveOutcome::Projected {
            results: (0..roots.len()).map(|_| None).collect(),
            timing: crate::resolve::WorkspaceUnionStageTiming {
                importer_count: usize_to_u64_saturating(roots.len()),
                eligible_importer_count: usize_to_u64_saturating(eligible_importer_count),
                isolated_importer_count: usize_to_u64_saturating(roots.len()),
                root_specifier_isolated_count: usize_to_u64_saturating(
                    root_specifier_isolated_count,
                ),
                ..Default::default()
            },
        });
    };
    let union_policy = first_policy.for_workspace_union();
    let mut supplemental_peers = HashSet::new();
    let mut expansion_pass = 0usize;
    loop {
        let union = resolve_greedy_fused_with_cache_options_policy_and_selected_events_roots(
            Arc::clone(&client),
            dependencies.clone(),
            overrides.clone(),
            route_table.clone(),
            npm_fanout,
            None,
            Arc::clone(&shared_cache),
            auto_install_peers,
            include_optional_dependencies,
            union_policy.clone(),
            None,
            shared_fact_cache.as_ref().map(Arc::clone),
            shared_metadata_concurrency.clone(),
        )
        .await?;
        let pass = project_union_result(union, &slots, &overrides, auto_install_peers, &policies)?;
        if pass.missing_ambient_peers.is_empty() {
            return Ok(pass.into_outcome(
                expansion_pass,
                root_specifier_isolated_count,
                false,
                0,
                0,
            ));
        }
        if expansion_pass >= MAX_AMBIENT_PEER_EXPANSION_PASSES {
            let isolated_importers = pass.ambient_peer_pending_importer_count;
            tracing::warn!(
                expansion_pass,
                max_expansion_passes = MAX_AMBIENT_PEER_EXPANSION_PASSES,
                isolated_importers,
                reason = "ambient-peer-expansion-cap",
                "workspace union ambient-peer expansion reached its cap; falling back to isolated resolution for unconverged importers"
            );
            return Ok(pass.into_outcome(
                expansion_pass,
                root_specifier_isolated_count,
                true,
                isolated_importers,
                0,
            ));
        }

        let mut added = 0usize;
        for (position, identity) in pass.missing_ambient_peers.iter().enumerate() {
            if !supplemental_peers.insert(identity.clone()) {
                continue;
            }
            let synthetic = format!("lpm-workspace-peer-{expansion_pass}-{position}");
            dependencies
                .dependencies
                .insert(synthetic, format!("npm:{}@{}", identity.0, identity.1));
            added += 1;
        }
        if added == 0 {
            tracing::debug!(
                expansion_pass,
                reason = "ambient-peer-expansion-stalled",
                "workspace union resolution retained isolated importer fallbacks"
            );
            let isolated_importers = pass.ambient_peer_pending_importer_count;
            return Ok(pass.into_outcome(
                expansion_pass,
                root_specifier_isolated_count,
                false,
                0,
                isolated_importers,
            ));
        }
        tracing::debug!(
            expansion_pass,
            added,
            "workspace union resolution expanding ambient peer packages"
        );
        expansion_pass += 1;
    }
}

fn union_root_dependencies(roots: &[RootDependencies]) -> Result<UnionRoots, ResolveError> {
    let dependency_count = roots
        .iter()
        .map(|root| root.dependencies.len())
        .sum::<usize>();
    let mut dependencies = HashMap::with_capacity(dependency_count);
    let mut optional_names = HashSet::with_capacity(dependency_count);
    let mut all_slots = Vec::with_capacity(roots.len());
    let mut root_specifier_isolated_count = 0usize;

    for (root_index, root) in roots.iter().enumerate() {
        let mut entries = root.dependencies.iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(right.0));
        let mut parsed_slots = Vec::with_capacity(entries.len());
        let mut ineligible = None;
        for (slot_index, (local, raw)) in entries.into_iter().enumerate() {
            let (target, range, alias) = match Specifier::parse(raw).map_err(|error| {
                ResolveError::Internal(format!(
                    "failed to parse workspace root dependency {local:?}: {error}"
                ))
            })? {
                Specifier::SemverRange(range) => (local.clone(), range, false),
                Specifier::NpmAlias { target, range } => (target, range, true),
                specifier => {
                    ineligible = Some((local.as_str(), non_registry_specifier_kind(&specifier)));
                    break;
                }
            };
            let synthetic = format!("lpm-workspace-root-{root_index}-{slot_index}");
            let optional = root.optional_names.contains(local);
            parsed_slots.push((
                RootSlot {
                    synthetic,
                    local: local.clone(),
                    target,
                    optional,
                    alias,
                },
                range,
            ));
        }
        if let Some((dependency, specifier_kind)) = ineligible {
            root_specifier_isolated_count += 1;
            tracing::debug!(
                importer_index = root_index,
                dependency,
                specifier_kind,
                reason = "ineligible-root-specifier",
                "workspace union importer requires isolated resolution"
            );
            all_slots.push(None);
            continue;
        }
        let mut slots = Vec::with_capacity(parsed_slots.len());
        for (slot, range) in parsed_slots {
            if slot.optional {
                optional_names.insert(slot.synthetic.clone());
            }
            dependencies.insert(
                slot.synthetic.clone(),
                format!("npm:{}@{range}", slot.target),
            );
            slots.push(slot);
        }
        all_slots.push(Some(slots));
    }

    let eligible_importer_count = all_slots.iter().filter(|slots| slots.is_some()).count();
    Ok(UnionRoots {
        dependencies: RootDependencies::with_optional_names(dependencies, optional_names),
        slots: all_slots,
        eligible_importer_count,
        root_specifier_isolated_count,
    })
}

fn non_registry_specifier_kind(specifier: &Specifier) -> &'static str {
    match specifier {
        Specifier::Workspace(_) => "workspace",
        Specifier::Tarball { .. } => "tarball",
        Specifier::File { .. } => "file",
        Specifier::Link { .. } => "link",
        Specifier::Git { .. } => "git",
        Specifier::SemverRange(_) | Specifier::NpmAlias { .. } => "registry",
    }
}

struct WorkspaceProjectionPass {
    projected: Vec<Option<ResolveResult>>,
    missing_ambient_peers: Vec<(String, String)>,
    union_stage_timing: crate::resolve::StageTiming,
    eligible_importer_count: usize,
    release_age_policy_isolated_count: usize,
    projection_isolated_count: usize,
    ambient_peer_pending_importer_count: usize,
}

impl WorkspaceProjectionPass {
    fn into_outcome(
        mut self,
        expansion_pass_count: usize,
        root_specifier_isolated_count: usize,
        expansion_capped: bool,
        ambient_peer_cap_isolated_count: usize,
        ambient_peer_stalled_isolated_count: usize,
    ) -> WorkspaceResolveOutcome {
        let projected_importer_count = self.projected.iter().flatten().count();
        let timing = crate::resolve::WorkspaceUnionStageTiming {
            importer_count: usize_to_u64_saturating(self.projected.len()),
            eligible_importer_count: usize_to_u64_saturating(self.eligible_importer_count),
            projected_importer_count: usize_to_u64_saturating(projected_importer_count),
            isolated_importer_count: usize_to_u64_saturating(
                self.projected
                    .len()
                    .saturating_sub(projected_importer_count),
            ),
            ambient_peer_expansion_pass_count: usize_to_u64_saturating(expansion_pass_count),
            ambient_peer_expansion_capped: expansion_capped,
            root_specifier_isolated_count: usize_to_u64_saturating(root_specifier_isolated_count),
            release_age_policy_isolated_count: usize_to_u64_saturating(
                self.release_age_policy_isolated_count,
            ),
            projection_isolated_count: usize_to_u64_saturating(self.projection_isolated_count),
            ambient_peer_cap_isolated_count: usize_to_u64_saturating(
                ambient_peer_cap_isolated_count,
            ),
            ambient_peer_stalled_isolated_count: usize_to_u64_saturating(
                ambient_peer_stalled_isolated_count,
            ),
        };
        if let Some(result) = self.projected.iter_mut().flatten().next() {
            result.stage_timing = self.union_stage_timing;
            result.stage_timing.workspace_union = timing;
        }
        WorkspaceResolveOutcome::Projected {
            results: self.projected,
            timing,
        }
    }
}

enum ImporterProjection {
    Projected(Box<ResolveResult>),
    NeedsAmbientPeers(Vec<(String, String)>),
    RequiresIsolatedResolution,
}

#[derive(Clone, Copy)]
struct ImporterProjectionContext<'a> {
    union: &'a ResolveResult,
    package_index: &'a HashMap<(String, String), Vec<usize>>,
    overrides: &'a OverrideSet,
    auto_install_peers: bool,
    policy: &'a ResolverPolicy,
    importer_index: usize,
}

fn project_union_result(
    union: ResolveResult,
    slots: &[Option<Vec<RootSlot>>],
    overrides: &OverrideSet,
    auto_install_peers: bool,
    policies: &[ResolverPolicy],
) -> Result<WorkspaceProjectionPass, ResolveError> {
    let union_stage_timing = union.stage_timing;
    let package_index = package_indices(&union.packages);
    let mut projected = Vec::with_capacity(slots.len());
    let mut missing_ambient_peers = Vec::new();
    let mut release_age_policy_isolated_count = 0usize;
    let mut projection_isolated_count = 0usize;
    let mut ambient_peer_pending_importer_count = 0usize;
    for (root_index, root_slots) in slots.iter().enumerate() {
        let Some(root_slots) = root_slots else {
            projected.push(None);
            continue;
        };
        let context = ImporterProjectionContext {
            union: &union,
            package_index: &package_index,
            overrides,
            auto_install_peers,
            policy: &policies[root_index],
            importer_index: root_index,
        };
        let result = project_importer(root_slots, &context)?;
        let result = match result {
            ImporterProjection::Projected(result)
                if projection_satisfies_release_age_policy(&result, &policies[root_index]) =>
            {
                Some(*result)
            }
            ImporterProjection::Projected(_) => {
                release_age_policy_isolated_count += 1;
                tracing::debug!(
                    importer_index = root_index,
                    reason = "release-age-policy",
                    "workspace union importer requires isolated resolution"
                );
                None
            }
            ImporterProjection::NeedsAmbientPeers(missing) => {
                ambient_peer_pending_importer_count += 1;
                missing_ambient_peers.extend(missing);
                None
            }
            ImporterProjection::RequiresIsolatedResolution => {
                projection_isolated_count += 1;
                None
            }
        };
        projected.push(result);
    }
    missing_ambient_peers.sort_unstable();
    missing_ambient_peers.dedup();
    Ok(WorkspaceProjectionPass {
        projected,
        missing_ambient_peers,
        union_stage_timing,
        eligible_importer_count: slots.iter().flatten().count(),
        release_age_policy_isolated_count,
        projection_isolated_count,
        ambient_peer_pending_importer_count,
    })
}

fn projection_satisfies_release_age_policy(
    result: &ResolveResult,
    policy: &ResolverPolicy,
) -> bool {
    result.root_resolutions.values().all(|resolution| {
        let canonical = CanonicalKey::from_dep_name(&resolution.package);
        if !policy.release_age_applies_to_package(&canonical) {
            return true;
        }
        let Ok(version) = crate::NpmVersion::parse(&resolution.version) else {
            return false;
        };
        let status = if let Some(info) = result.cache.get(&canonical) {
            let published_at = info
                .dist
                .get(&resolution.version)
                .and_then(|dist| dist.published_at.as_deref());
            policy.release_time_status_for_package_version(&canonical, &version, published_at)
        } else {
            policy.release_time_status_for_package_version(&canonical, &version, None)
        };
        matches!(status, crate::ReleaseTimeStatus::Allowed)
    })
}

fn package_indices(packages: &[ResolvedPackage]) -> HashMap<(String, String), Vec<usize>> {
    let mut index = HashMap::with_capacity(packages.len());
    for (position, package) in packages.iter().enumerate() {
        index
            .entry((
                package.package.canonical_name(),
                package.version.to_string(),
            ))
            .or_insert_with(Vec::new)
            .push(position);
    }
    index
}

fn project_importer(
    slots: &[RootSlot],
    context: &ImporterProjectionContext<'_>,
) -> Result<ImporterProjection, ResolveError> {
    let union = context.union;
    let package_index = context.package_index;
    let importer_index = context.importer_index;
    let mut included = HashSet::with_capacity(union.packages.len());
    let mut required = HashSet::with_capacity(union.packages.len());
    let mut root_aliases = HashMap::with_capacity(slots.len());
    let mut root_resolutions = HashMap::with_capacity(slots.len());
    let mut seeds = Vec::with_capacity(slots.len());

    for slot in slots {
        if slot.alias {
            root_aliases.insert(slot.local.clone(), slot.target.clone());
        }
        let Some(resolution) = union.root_resolutions.get(&slot.synthetic) else {
            if slot.optional {
                continue;
            }
            tracing::debug!(
                importer_index,
                dependency = slot.local,
                reason = "missing-required-root",
                "workspace union importer requires isolated resolution"
            );
            return Ok(ImporterProjection::RequiresIsolatedResolution);
        };
        root_resolutions.insert(slot.local.clone(), resolution.clone());
        seeds.push((
            (resolution.package.clone(), resolution.version.clone()),
            !slot.optional,
        ));
    }
    add_dependency_closure(
        &mut included,
        &mut required,
        seeds,
        &union.packages,
        package_index,
        &union.cache,
    );

    let projection_overrides = context.overrides.clone();
    let peer_context = ImporterProjectionContext {
        overrides: &projection_overrides,
        ..*context
    };
    let peer_projection = project_peer_context(&mut included, &mut required, &peer_context)?;
    let (peer_bindings, ambient_peer_installs, peer_conflicts) = match peer_projection {
        PeerProjectionOutcome::Projected(projection) => projection,
        PeerProjectionOutcome::NeedsAmbientPeers(missing) => {
            return Ok(ImporterProjection::NeedsAmbientPeers(missing));
        }
        PeerProjectionOutcome::RequiresIsolatedResolution => {
            return Ok(ImporterProjection::RequiresIsolatedResolution);
        }
    };

    let mut packages = included
        .iter()
        .copied()
        .map(|index| {
            let mut package = union.packages[index].clone();
            package.optional = !required.contains(&index);
            package.peers = peer_bindings.get(&index).cloned().unwrap_or_default();
            package
        })
        .collect::<Vec<_>>();
    packages.sort_by_cached_key(|package| (package.package.to_string(), package.version.clone()));
    let package_names = packages
        .iter()
        .map(|package| package.package.canonical_name())
        .collect::<HashSet<_>>();
    let mut applied_overrides = union
        .applied_overrides
        .iter()
        .filter(|hit| package_names.contains(&hit.package))
        .cloned()
        .collect::<Vec<_>>();
    for hit in projection_overrides.take_hits() {
        if !applied_overrides.contains(&hit) {
            applied_overrides.push(hit);
        }
    }
    applied_overrides.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then(left.raw_key.cmp(&right.raw_key))
    });

    Ok(ImporterProjection::Projected(Box::new(ResolveResult {
        packages,
        cache: union.cache.clone(),
        applied_overrides,
        platform_skipped: union.platform_skipped,
        root_aliases,
        root_resolutions,
        ambient_peer_installs,
        peer_conflicts,
        stage_timing: Default::default(),
    })))
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn add_dependency_closure(
    included: &mut HashSet<usize>,
    required: &mut HashSet<usize>,
    seeds: Vec<((String, String), bool)>,
    packages: &[ResolvedPackage],
    package_index: &HashMap<(String, String), Vec<usize>>,
    cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
) {
    let mut queue = VecDeque::with_capacity(seeds.len());
    queue.extend(seeds);
    while let Some((identity, required_path)) = queue.pop_front() {
        let Some(indices) = package_index.get(&identity) else {
            continue;
        };
        for &index in indices {
            let was_included = included.insert(index);
            let became_required = required_path && required.insert(index);
            if !was_included && !became_required {
                continue;
            }
            let package = &packages[index];
            let canonical = CanonicalKey::from(&package.package);
            let version = package.version.to_string();
            let optional_names = cache
                .get(&canonical)
                .and_then(|info| info.optional_dep_names.get(&version));
            for (local, child_version) in &package.dependencies {
                let target = package.aliases.get(local).unwrap_or(local);
                let edge_required =
                    required_path && !optional_names.is_some_and(|names| names.contains(local));
                queue.push_back(((target.clone(), child_version.clone()), edge_required));
            }
        }
    }
}

type PeerProjection = (
    HashMap<usize, Vec<(String, String)>>,
    Vec<String>,
    Vec<super::PeerConflictReport>,
);

enum PeerProjectionOutcome {
    Projected(PeerProjection),
    NeedsAmbientPeers(Vec<(String, String)>),
    RequiresIsolatedResolution,
}

fn project_peer_context(
    included: &mut HashSet<usize>,
    required: &mut HashSet<usize>,
    context: &ImporterProjectionContext<'_>,
) -> Result<PeerProjectionOutcome, ResolveError> {
    let union = context.union;
    let package_index = context.package_index;
    let importer_index = context.importer_index;
    let mut ambient = Vec::new();
    let mut conflicts = Vec::new();
    loop {
        let mut bindings = HashMap::<usize, Vec<(String, String)>>::new();
        let mut missing = HashMap::<String, Vec<PeerRequirement>>::new();
        let mut positions = included.iter().copied().collect::<Vec<_>>();
        positions.sort_unstable();
        for index in positions {
            let package = &union.packages[index];
            let canonical = CanonicalKey::from(&package.package);
            let version = package.version.to_string();
            let Some(info) = union.cache.get(&canonical) else {
                continue;
            };
            let Some(peer_deps) = info.peer_deps.get(&version) else {
                continue;
            };
            let regular = info.deps.get(&version);
            let optional = info.optional_peer_names.get(&version);
            let aliases = info.aliases.get(&version);
            let mut entries = peer_deps.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (peer_name, raw_range) in entries {
                if regular.is_some_and(|deps| deps.contains_key(peer_name)) {
                    continue;
                }
                let target = aliases
                    .and_then(|values| values.get(peer_name))
                    .unwrap_or(peer_name);
                let range = NpmRange::parse(raw_range).map_err(|error| {
                    ResolveError::Internal(format!(
                        "failed to parse peer range {raw_range:?} for {target}: {error}"
                    ))
                })?;
                let Some(range) = apply_projected_peer_override(
                    package,
                    target,
                    range,
                    context.overrides,
                    context.policy,
                    &union.cache,
                    importer_index,
                )?
                else {
                    return Ok(PeerProjectionOutcome::RequiresIsolatedResolution);
                };
                if let Some(version) =
                    newest_included_provider(included, &union.packages, target, &range)
                {
                    bindings
                        .entry(index)
                        .or_default()
                        .push((peer_name.clone(), version));
                } else {
                    missing.entry(target.clone()).or_default().push((
                        index,
                        peer_name.clone(),
                        range,
                        optional.is_some_and(|names| names.contains(peer_name)),
                    ));
                }
            }
        }

        if !context.auto_install_peers {
            normalize_peer_bindings(&mut bindings);
            return Ok(PeerProjectionOutcome::Projected((
                bindings, ambient, conflicts,
            )));
        }

        let mut synthesized = Vec::new();
        let mut canonical_names = missing.keys().cloned().collect::<Vec<_>>();
        canonical_names.sort();
        for canonical in canonical_names {
            let requirements = &missing[&canonical];
            let required_requirements = requirements
                .iter()
                .filter(|requirement| !requirement.3)
                .collect::<Vec<_>>();
            if required_requirements.is_empty() {
                continue;
            }
            let Some((version, unsatisfied)) =
                select_union_peer_candidate(&canonical, &required_requirements, &union.cache)
            else {
                tracing::debug!(
                    importer_index,
                    peer = canonical,
                    reason = "no-ambient-peer-candidate",
                    "workspace union importer requires isolated resolution"
                );
                return Ok(PeerProjectionOutcome::RequiresIsolatedResolution);
            };
            synthesized.push(((canonical.clone(), version.clone()), true));
            ambient.push(canonical.clone());
            if !unsatisfied.is_empty() {
                conflicts.push(super::PeerConflictReport {
                    canonical,
                    chosen_version: version,
                    unsatisfied_consumers: unsatisfied
                        .into_iter()
                        .map(|requirement| {
                            let consumer = union.packages[requirement.0].package.canonical_name();
                            (consumer, requirement.2.to_string())
                        })
                        .collect(),
                });
            }
        }
        if synthesized.is_empty() {
            normalize_peer_bindings(&mut bindings);
            ambient.sort();
            ambient.dedup();
            conflicts.sort_by(|left, right| left.canonical.cmp(&right.canonical));
            return Ok(PeerProjectionOutcome::Projected((
                bindings, ambient, conflicts,
            )));
        }
        let missing_ambient_peers = synthesized
            .iter()
            .filter_map(|(identity, _)| {
                (!package_index.contains_key(identity)).then_some(identity.clone())
            })
            .collect::<Vec<_>>();
        if !missing_ambient_peers.is_empty() {
            return Ok(PeerProjectionOutcome::NeedsAmbientPeers(
                missing_ambient_peers,
            ));
        }
        let before = included.len();
        add_dependency_closure(
            included,
            required,
            synthesized,
            &union.packages,
            package_index,
            &union.cache,
        );
        if included.len() == before {
            tracing::debug!(
                importer_index,
                reason = "ambient-peer-closure-did-not-grow",
                "workspace union importer requires isolated resolution"
            );
            return Ok(PeerProjectionOutcome::RequiresIsolatedResolution);
        }
    }
}

fn apply_projected_peer_override(
    consumer: &ResolvedPackage,
    target: &str,
    range: NpmRange,
    overrides: &OverrideSet,
    policy: &ResolverPolicy,
    cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    importer_index: usize,
) -> Result<Option<NpmRange>, ResolveError> {
    if !overrides.may_match_package(target) {
        return Ok(Some(range));
    }
    let canonical = CanonicalKey::from_dep_name(target);
    let Some(info) = cache.get(&canonical) else {
        tracing::debug!(
            importer_index,
            peer = target,
            reason = "peer-override-metadata-missing",
            "workspace union importer requires isolated resolution"
        );
        return Ok(None);
    };
    let VersionPick::Picked(natural) =
        find_best_version_with_policy(&canonical, info, &range, policy)
    else {
        return Ok(Some(range));
    };
    let parent = consumer.package.canonical_name();
    let Some(entry) = overrides
        .find_match(target, &natural, Some(&parent))
        .cloned()
    else {
        return Ok(Some(range));
    };
    let Some(forced) = apply_peer_override_target_greedy(&canonical, info, &entry.target, policy)
    else {
        tracing::warn!(
            "override {} could not select an eligible peer version for {}",
            entry.raw_key,
            target
        );
        return Ok(Some(range));
    };
    let forced_range = NpmRange::parse(&forced.to_string()).map_err(|error| {
        ResolveError::Internal(format!(
            "override produced invalid peer version range '{forced}' for {target}: {error}"
        ))
    })?;
    overrides.record_hit(OverrideHit {
        raw_key: entry.raw_key,
        source: entry.source,
        package: target.to_string(),
        from_version: natural.to_string(),
        to_version: forced.to_string(),
        via_parent: Some(parent),
    });
    Ok(Some(forced_range))
}

fn newest_included_provider(
    included: &HashSet<usize>,
    packages: &[ResolvedPackage],
    canonical: &str,
    range: &NpmRange,
) -> Option<String> {
    included
        .iter()
        .filter_map(|index| {
            let package = &packages[*index];
            (package.package.canonical_name() == canonical && range.satisfies(&package.version))
                .then_some(&package.version)
        })
        .max()
        .map(ToString::to_string)
}

fn select_union_peer_candidate<'a>(
    canonical: &str,
    requirements: &[&'a PeerRequirement],
    cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
) -> Option<(String, Vec<&'a PeerRequirement>)> {
    let info = cache.get(&CanonicalKey::from_dep_name(canonical))?;
    let mut best = None::<(crate::NpmVersion, usize, Vec<usize>)>;
    for candidate in &info.versions {
        if info
            .platform
            .get(&candidate.to_string())
            .is_some_and(|platform| !is_platform_compatible(platform))
        {
            continue;
        }
        let misses = requirements
            .iter()
            .enumerate()
            .filter_map(|(index, requirement)| {
                (!requirement.2.satisfies(candidate)).then_some(index)
            })
            .collect::<Vec<_>>();
        let hits = requirements.len().saturating_sub(misses.len());
        if hits == 0 {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, best_hits, _)| hits > *best_hits)
        {
            best = Some((candidate.clone(), hits, misses));
        }
    }
    best.map(|(version, _, misses)| {
        (
            version.to_string(),
            misses
                .into_iter()
                .map(|index| requirements[index])
                .collect(),
        )
    })
}

fn normalize_peer_bindings(bindings: &mut HashMap<usize, Vec<(String, String)>>) {
    for values in bindings.values_mut() {
        values.sort_by(|left, right| left.0.cmp(&right.0));
        values.dedup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::CachedDistInfo;

    type DependencyFixture<'a> = (&'a str, &'a str);
    type PackageFixture<'a> = (
        &'a str,
        &'a [DependencyFixture<'a>],
        &'a [DependencyFixture<'a>],
    );

    fn cached_package(versions: &[PackageFixture<'_>]) -> Arc<CachedPackageInfo> {
        let parsed_versions = versions
            .iter()
            .map(|(version, _, _)| crate::NpmVersion::parse(version).unwrap())
            .collect::<Vec<_>>();
        Arc::new(CachedPackageInfo {
            modified: None,
            modified_unix: None,
            trust_metadata_complete: true,
            versions_complete: true,
            covered_ranges: HashSet::new(),
            workspace_versions: HashSet::new(),
            platform_metadata_complete: true,
            latest_version: parsed_versions.first().cloned(),
            versions: parsed_versions,
            deps: versions
                .iter()
                .map(|(version, dependencies, _)| {
                    (
                        (*version).to_string(),
                        dependencies
                            .iter()
                            .map(|(name, range)| ((*name).to_string(), (*range).to_string()))
                            .collect(),
                    )
                })
                .collect(),
            peer_deps: versions
                .iter()
                .map(|(version, _, peers)| {
                    (
                        (*version).to_string(),
                        peers
                            .iter()
                            .map(|(name, range)| ((*name).to_string(), (*range).to_string()))
                            .collect(),
                    )
                })
                .collect(),
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            node_engines: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: versions
                .iter()
                .map(|(version, _, _)| ((*version).to_string(), CachedDistInfo::default()))
                .collect(),
            aliases: HashMap::new(),
        })
    }

    fn cached_package_with_publish_time(name: &str, published_at: &str) -> Arc<CachedPackageInfo> {
        let mut info = cached_package(&[("1.0.0", &[], &[])]);
        Arc::make_mut(&mut info)
            .dist
            .get_mut("1.0.0")
            .unwrap_or_else(|| panic!("{name} fixture should contain 1.0.0"))
            .published_at = Some(published_at.to_string());
        info
    }

    async fn resolve_roots_with_policies(
        roots: Vec<RootDependencies>,
        cache_entries: Vec<(&str, Arc<CachedPackageInfo>)>,
        policies: Vec<ResolverPolicy>,
    ) -> WorkspaceResolveOutcome {
        resolve_roots_with_policies_and_overrides(
            roots,
            cache_entries,
            policies,
            OverrideSet::empty(),
        )
        .await
    }

    async fn resolve_roots_with_policies_and_overrides(
        roots: Vec<RootDependencies>,
        cache_entries: Vec<(&str, Arc<CachedPackageInfo>)>,
        policies: Vec<ResolverPolicy>,
        overrides: OverrideSet,
    ) -> WorkspaceResolveOutcome {
        let cache: SharedCache = Arc::new(dashmap::DashMap::new());
        for (name, info) in cache_entries {
            cache.insert(CanonicalKey::from_dep_name(name), info);
        }
        resolve_greedy_fused_workspace_with_cache_options_and_policy(
            Arc::new(RegistryClient::new().with_cache_dir(None)),
            roots,
            overrides,
            RouteTable::from_mode_only(lpm_registry::RouteMode::Direct),
            8,
            cache,
            true,
            true,
            policies,
            None,
            None,
        )
        .await
        .unwrap()
    }

    async fn resolve_roots(
        roots: Vec<RootDependencies>,
        cache_entries: Vec<(&str, Arc<CachedPackageInfo>)>,
    ) -> Vec<ResolveResult> {
        let policies = vec![ResolverPolicy::default(); roots.len()];
        let outcome = resolve_roots_with_policies(roots, cache_entries, policies).await;
        match outcome {
            WorkspaceResolveOutcome::Projected { results, .. } => results
                .into_iter()
                .map(|result| result.expect("fixture projection should remain union-compatible"))
                .collect(),
            WorkspaceResolveOutcome::RequiresIsolatedResolution => {
                panic!("fixture should support union projection")
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_projects_only_each_importers_dependency_closure() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("shared".to_string(), "^1.0.0".to_string()),
                ("web-only".to_string(), "^2.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "shared".to_string(),
                "^1.0.0".to_string(),
            )])),
        ];
        let results = resolve_roots(
            roots,
            vec![
                ("shared", cached_package(&[("1.0.0", &[], &[])])),
                ("web-only", cached_package(&[("2.0.0", &[], &[])])),
            ],
        )
        .await;

        let package_names = results
            .iter()
            .map(|result| {
                result
                    .packages
                    .iter()
                    .map(|package| package.package.canonical_name())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            package_names,
            vec![
                vec!["shared".to_string(), "web-only".to_string()],
                vec!["shared".to_string()],
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_preserves_conflicting_root_versions_per_importer() {
        let roots = vec![
            RootDependencies::required(HashMap::from([(
                "shared".to_string(),
                "^1.0.0".to_string(),
            )])),
            RootDependencies::required(HashMap::from([(
                "shared".to_string(),
                "^2.0.0".to_string(),
            )])),
        ];
        let results = resolve_roots(
            roots,
            vec![(
                "shared",
                cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
            )],
        )
        .await;

        let versions = results
            .iter()
            .map(|result| result.packages[0].version.to_string())
            .collect::<Vec<_>>();
        assert_eq!(versions, vec!["1.0.0", "2.0.0"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_auto_installs_missing_peer_only_in_its_importer() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("runtime".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let results = resolve_roots(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("runtime", "^1.0.0")])]),
                ),
                (
                    "runtime",
                    cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
                ),
            ],
        )
        .await;

        assert!(results[0].ambient_peer_installs.is_empty());
        assert_eq!(results[1].ambient_peer_installs, vec!["runtime"]);
        assert!(
            results[1]
                .packages
                .iter()
                .any(|package| package.package.canonical_name() == "runtime"
                    && package.version.to_string() == "1.0.0")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_keeps_peer_projection_when_overrides_target_an_unrelated_package() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("runtime".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let policies = vec![ResolverPolicy::default(); roots.len()];
        let overrides = OverrideSet::parse(
            &HashMap::new(),
            &HashMap::from([("unrelated".to_string(), "1.0.0".to_string())]),
            &HashMap::new(),
        )
        .expect("unrelated override should parse");
        let outcome = resolve_roots_with_policies_and_overrides(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("runtime", "^1.0.0")])]),
                ),
                ("runtime", cached_package(&[("1.0.0", &[], &[])])),
            ],
            policies,
            overrides,
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("unrelated overrides should not disable the union traversal")
        };
        assert!(results.iter().all(Option::is_some));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_applies_peer_overrides_inside_each_projection() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("runtime".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let policies = vec![ResolverPolicy::default(); roots.len()];
        let overrides = OverrideSet::parse(
            &HashMap::new(),
            &HashMap::from([("runtime".to_string(), "1.0.0".to_string())]),
            &HashMap::new(),
        )
        .expect("peer override should parse");
        let outcome = resolve_roots_with_policies_and_overrides(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("runtime", "*")])]),
                ),
                (
                    "runtime",
                    cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
                ),
            ],
            policies,
            overrides,
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("peer overrides should stay inside the union traversal")
        };
        for result in results {
            let result = result.expect("peer override should preserve the projection");
            let consumer = result
                .packages
                .iter()
                .find(|package| package.package.canonical_name() == "consumer")
                .expect("projection should contain consumer");
            assert_eq!(
                consumer.peers,
                vec![("runtime".to_string(), "1.0.0".to_string())]
            );
            assert!(result.applied_overrides.iter().any(|hit| {
                hit.package == "runtime" && hit.from_version == "2.0.0" && hit.to_version == "1.0.0"
            }));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_expands_for_an_importers_unresolved_ambient_peer() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("runtime".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let policies = vec![ResolverPolicy::default(); roots.len()];
        let outcome = resolve_roots_with_policies(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("runtime", "*")])]),
                ),
                (
                    "runtime",
                    cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
                ),
            ],
            policies,
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("the ambient peer should expand the union traversal")
        };
        assert!(results[0].is_some());
        let second = results[1]
            .as_ref()
            .expect("the importer should project after union expansion");
        assert_eq!(second.ambient_peer_installs, vec!["runtime"]);
        assert!(second.packages.iter().any(|package| {
            package.package.canonical_name() == "runtime" && package.version.to_string() == "2.0.0"
        }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_repeats_expansion_for_transitive_ambient_peers() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("runtime".to_string(), "1.0.0".to_string()),
                ("host".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let results = resolve_roots(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("runtime", "*")])]),
                ),
                (
                    "runtime",
                    cached_package(&[("2.0.0", &[], &[("host", "*")]), ("1.0.0", &[], &[])]),
                ),
                (
                    "host",
                    cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
                ),
            ],
        )
        .await;

        assert_eq!(
            results[1].ambient_peer_installs,
            vec!["host".to_string(), "runtime".to_string()]
        );
        assert!(results[1].packages.iter().any(|package| {
            package.package.canonical_name() == "runtime" && package.version.to_string() == "2.0.0"
        }));
        assert!(results[1].packages.iter().any(|package| {
            package.package.canonical_name() == "host" && package.version.to_string() == "2.0.0"
        }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_isolates_only_importer_with_non_registry_root() {
        let roots = vec![
            RootDependencies::required(HashMap::from([(
                "local".to_string(),
                "file:../local".to_string(),
            )])),
            RootDependencies::required(HashMap::from([(
                "shared".to_string(),
                "1.0.0".to_string(),
            )])),
            RootDependencies::required(HashMap::from([(
                "shared".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let outcome = resolve_roots_with_policies(
            roots,
            vec![("shared", cached_package(&[("1.0.0", &[], &[])]))],
            vec![ResolverPolicy::default(); 3],
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("one non-registry root must not disable compatible sibling importers")
        };
        assert!(results[0].is_none());
        let timing = results[1]
            .as_ref()
            .expect("eligible importer should be projected")
            .stage_timing
            .workspace_union;
        assert!(results[2].is_some());
        assert_eq!(timing.importer_count, 3);
        assert_eq!(timing.eligible_importer_count, 2);
        assert_eq!(timing.projected_importer_count, 2);
        assert_eq!(timing.isolated_importer_count, 1);
        assert_eq!(timing.root_specifier_isolated_count, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_falls_back_importer_when_ambient_peer_expansion_exceeds_cap() {
        let roots = vec![
            RootDependencies::required(HashMap::from([
                ("consumer".to_string(), "1.0.0".to_string()),
                ("peer-a".to_string(), "1.0.0".to_string()),
                ("peer-b".to_string(), "1.0.0".to_string()),
                ("peer-c".to_string(), "1.0.0".to_string()),
                ("peer-d".to_string(), "1.0.0".to_string()),
                ("peer-e".to_string(), "1.0.0".to_string()),
            ])),
            RootDependencies::required(HashMap::from([(
                "consumer".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let outcome = resolve_roots_with_policies(
            roots,
            vec![
                (
                    "consumer",
                    cached_package(&[("1.0.0", &[], &[("peer-a", "*")])]),
                ),
                (
                    "peer-a",
                    cached_package(&[("2.0.0", &[], &[("peer-b", "*")]), ("1.0.0", &[], &[])]),
                ),
                (
                    "peer-b",
                    cached_package(&[("2.0.0", &[], &[("peer-c", "*")]), ("1.0.0", &[], &[])]),
                ),
                (
                    "peer-c",
                    cached_package(&[("2.0.0", &[], &[("peer-d", "*")]), ("1.0.0", &[], &[])]),
                ),
                (
                    "peer-d",
                    cached_package(&[("2.0.0", &[], &[("peer-e", "*")]), ("1.0.0", &[], &[])]),
                ),
                (
                    "peer-e",
                    cached_package(&[("2.0.0", &[], &[]), ("1.0.0", &[], &[])]),
                ),
            ],
            vec![ResolverPolicy::default(); 2],
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("the union should preserve projections that converged before the cap")
        };
        let timing = results[0]
            .as_ref()
            .expect("converged importer should remain projected")
            .stage_timing
            .workspace_union;
        assert!(results[1].is_none());
        assert_eq!(timing.ambient_peer_expansion_pass_count, 4);
        assert!(timing.ambient_peer_expansion_capped);
        assert_eq!(timing.ambient_peer_cap_isolated_count, 1);
        assert_eq!(timing.isolated_importer_count, 1);
    }

    #[test]
    fn workspace_projection_retains_timing_when_every_importer_is_isolated() {
        let outcome = WorkspaceProjectionPass {
            projected: vec![None, None],
            missing_ambient_peers: Vec::new(),
            union_stage_timing: Default::default(),
            eligible_importer_count: 2,
            release_age_policy_isolated_count: 0,
            projection_isolated_count: 0,
            ambient_peer_pending_importer_count: 2,
        }
        .into_outcome(4, 0, true, 2, 0);

        let WorkspaceResolveOutcome::Projected { results, timing } = outcome else {
            panic!("isolated projections should preserve the union outcome")
        };
        assert!(results.iter().all(Option::is_none));
        assert_eq!(timing.ambient_peer_expansion_pass_count, 4);
        assert!(timing.ambient_peer_expansion_capped);
        assert_eq!(timing.ambient_peer_cap_isolated_count, 2);
        assert_eq!(timing.isolated_importer_count, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn union_resolution_falls_back_only_the_importer_with_a_too_new_direct_root() {
        const CUTOFF_UNIX: i64 = 1_735_776_000;
        let roots = vec![
            RootDependencies::required(HashMap::from([(
                "recent".to_string(),
                "1.0.0".to_string(),
            )])),
            RootDependencies::required(HashMap::from([(
                "stable".to_string(),
                "1.0.0".to_string(),
            )])),
        ];
        let policies = vec![
            ResolverPolicy::with_cutoff_unix_and_release_age_packages(
                86_400,
                CUTOFF_UNIX,
                Default::default(),
                [CanonicalKey::from_dep_name("recent")],
            ),
            ResolverPolicy::with_cutoff_unix_and_release_age_packages(
                86_400,
                CUTOFF_UNIX,
                Default::default(),
                [CanonicalKey::from_dep_name("stable")],
            ),
        ];
        let outcome = resolve_roots_with_policies(
            roots,
            vec![
                (
                    "recent",
                    cached_package_with_publish_time("recent", "2025-01-03T00:00:00.000Z"),
                ),
                (
                    "stable",
                    cached_package_with_publish_time("stable", "2020-01-01T00:00:00.000Z"),
                ),
            ],
            policies,
        )
        .await;

        let WorkspaceResolveOutcome::Projected { results, .. } = outcome else {
            panic!("direct-scoped release-age policies should share the union traversal")
        };
        assert!(results[0].is_none());
        assert!(results[1].is_some());
    }
}
