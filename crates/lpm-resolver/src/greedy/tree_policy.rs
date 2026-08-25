use super::prelude::*;
use super::types::Edge;
use std::future::Future;
use std::pin::Pin;

const RELEASE_AGE_LOOKAHEAD_FETCH_LIMIT: usize = 8;

pub(super) trait TreeManifestProvider {
    fn cached_manifest(&self, _canonical: &CanonicalKey) -> Option<Arc<CachedPackageInfo>> {
        None
    }

    fn ensure_manifest<'a>(
        &'a self,
        canonical: &'a CanonicalKey,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>> + Send + 'a>>;

    fn prefetch_manifests<'a>(
        &'a self,
        _canonicals: &'a [CanonicalKey],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeStatus {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Default)]
pub(super) struct TreeStatusCache {
    entries: AHashMap<(CanonicalKey, NpmVersion), TreeStatus>,
    release_age_lookahead_fetches: usize,
}

impl TreeStatusCache {
    fn get(&self, key: &(CanonicalKey, NpmVersion)) -> Option<TreeStatus> {
        self.entries.get(key).copied()
    }

    fn insert(&mut self, key: (CanonicalKey, NpmVersion), status: TreeStatus) {
        self.entries.insert(key, status);
    }

    fn try_spend_release_age_lookahead_fetch(&mut self) -> bool {
        if self.release_age_lookahead_fetches >= RELEASE_AGE_LOOKAHEAD_FETCH_LIMIT {
            return false;
        }
        self.release_age_lookahead_fetches += 1;
        true
    }

    #[cfg(test)]
    pub(super) fn release_age_lookahead_fetches(&self) -> usize {
        self.release_age_lookahead_fetches
    }
}

pub(super) async fn preferred_tree_compatible_version<P>(
    edge: &Edge,
    info: &CachedPackageInfo,
    policy: &ResolverPolicy,
    provider: &P,
    cache: &mut TreeStatusCache,
) -> Option<NpmVersion>
where
    P: TreeManifestProvider + Sync,
{
    if edge.parent != 0 {
        return None;
    }
    if !policy.release_age_checks_all_packages() && !policy.requires_trust_history() {
        return None;
    }

    let mut visited = AHashSet::with_capacity(32);
    match pick_tree_compatible_version(
        &edge.canonical,
        &edge.range,
        info,
        policy,
        provider,
        &mut visited,
        cache,
    )
    .await
    {
        TreePick::Picked(version) => Some(version),
        TreePick::Incompatible | TreePick::Unknown => None,
    }
}

enum TreePick {
    Picked(NpmVersion),
    Incompatible,
    Unknown,
}

fn pick_tree_compatible_version<'a, P>(
    canonical: &'a CanonicalKey,
    range: &'a NpmRange,
    info: &'a CachedPackageInfo,
    policy: &'a ResolverPolicy,
    provider: &'a P,
    visited: &'a mut AHashSet<(CanonicalKey, NpmVersion)>,
    cache: &'a mut TreeStatusCache,
) -> Pin<Box<dyn Future<Output = TreePick> + Send + 'a>>
where
    P: TreeManifestProvider + Sync,
{
    Box::pin(async move {
        let mut saw_candidate = false;
        for version in super::version::versions_by_npm_preference(info, range) {
            saw_candidate = true;
            if !candidate_allowed(canonical, info, version, policy) {
                continue;
            }
            match required_dependency_tree_status(
                canonical, version, info, policy, provider, visited, cache,
            )
            .await
            {
                TreeStatus::Compatible => return TreePick::Picked(version.clone()),
                TreeStatus::Incompatible => continue,
                TreeStatus::Unknown => return TreePick::Unknown,
            }
        }

        if saw_candidate {
            TreePick::Incompatible
        } else {
            TreePick::Unknown
        }
    })
}

fn required_dependency_tree_status<'a, P>(
    canonical: &'a CanonicalKey,
    version: &'a NpmVersion,
    info: &'a CachedPackageInfo,
    policy: &'a ResolverPolicy,
    provider: &'a P,
    visited: &'a mut AHashSet<(CanonicalKey, NpmVersion)>,
    cache: &'a mut TreeStatusCache,
) -> Pin<Box<dyn Future<Output = TreeStatus> + Send + 'a>>
where
    P: TreeManifestProvider + Sync,
{
    Box::pin(async move {
        let visit_key = (canonical.clone(), version.clone());
        if !visited.insert(visit_key.clone()) {
            return TreeStatus::Compatible;
        }
        if let Some(status) = cache.get(&visit_key) {
            visited.remove(&visit_key);
            return status;
        }

        let version_str = version.to_string();
        let Some(dependencies) = info.dependencies(&version_str) else {
            visited.remove(&visit_key);
            cache.insert(visit_key, TreeStatus::Compatible);
            return TreeStatus::Compatible;
        };
        let entries = dependencies.collect::<Vec<_>>();
        let prefetch_canonicals: Vec<CanonicalKey> = entries
            .iter()
            .filter_map(|dependency| {
                if dependency.bundled
                    || dependency.optional
                    || super::version::is_workspace_specifier(dependency.range)
                    || NpmRange::parse(dependency.range).is_err()
                {
                    return None;
                }
                Some(CanonicalKey::from_dep_name(
                    dependency.alias.unwrap_or(dependency.name),
                ))
            })
            .collect();
        let release_age_tree_policy = policy.release_age_checks_all_packages();
        if policy.requires_trust_history() || release_age_tree_policy {
            provider.prefetch_manifests(&prefetch_canonicals).await;
        }

        for dependency in entries {
            if dependency.bundled || dependency.optional {
                continue;
            }
            let local_name = dependency.name;
            let range_str = dependency.range;
            if super::version::is_workspace_specifier(range_str) {
                continue;
            }
            let Ok(range) = NpmRange::parse(range_str) else {
                continue;
            };
            let child_canonical =
                CanonicalKey::from_dep_name(dependency.alias.unwrap_or(local_name));
            let child_info = if policy.requires_trust_history() {
                match provider.ensure_manifest(&child_canonical).await {
                    Ok(info) => info,
                    Err(_) => {
                        visited.remove(&visit_key);
                        cache.insert(visit_key, TreeStatus::Unknown);
                        return TreeStatus::Unknown;
                    }
                }
            } else if let Some(info) = provider.cached_manifest(&child_canonical) {
                info
            } else if release_age_tree_policy && cache.try_spend_release_age_lookahead_fetch() {
                match provider.ensure_manifest(&child_canonical).await {
                    Ok(info) => info,
                    Err(_) => {
                        visited.remove(&visit_key);
                        cache.insert(visit_key, TreeStatus::Unknown);
                        return TreeStatus::Unknown;
                    }
                }
            } else {
                visited.remove(&visit_key);
                cache.insert(visit_key, TreeStatus::Unknown);
                return TreeStatus::Unknown;
            };
            match pick_tree_compatible_version(
                &child_canonical,
                &range,
                &child_info,
                policy,
                provider,
                visited,
                cache,
            )
            .await
            {
                TreePick::Picked(_) => {}
                TreePick::Incompatible => {
                    visited.remove(&visit_key);
                    cache.insert(visit_key, TreeStatus::Incompatible);
                    return TreeStatus::Incompatible;
                }
                TreePick::Unknown => {
                    visited.remove(&visit_key);
                    cache.insert(visit_key, TreeStatus::Unknown);
                    return TreeStatus::Unknown;
                }
            }
        }

        visited.remove(&visit_key);
        cache.insert(visit_key, TreeStatus::Compatible);
        TreeStatus::Compatible
    })
}

fn candidate_allowed(
    canonical: &CanonicalKey,
    info: &CachedPackageInfo,
    version: &NpmVersion,
    policy: &ResolverPolicy,
) -> bool {
    matches!(
        release_age_status_for_version(canonical, info, version, policy),
        ReleaseTimeStatus::Allowed
    ) && (!policy.trust_policy().is_no_downgrade()
        || trust_downgrade_violation(info, version).is_none())
}
