use super::prelude::*;
use super::types::Edge;
use std::cell::{Cell, RefCell};
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
    ) -> Pin<Box<dyn Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>> + 'a>>;

    fn prefetch_manifests<'a>(
        &'a self,
        _canonicals: &'a [CanonicalKey],
    ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
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
    entries: RefCell<AHashMap<(CanonicalKey, NpmVersion), TreeStatus>>,
    release_age_lookahead_fetches: Cell<usize>,
}

impl TreeStatusCache {
    fn get(&self, key: &(CanonicalKey, NpmVersion)) -> Option<TreeStatus> {
        self.entries.borrow().get(key).copied()
    }

    fn insert(&self, key: (CanonicalKey, NpmVersion), status: TreeStatus) {
        self.entries.borrow_mut().insert(key, status);
    }

    fn try_spend_release_age_lookahead_fetch(&self) -> bool {
        let used = self.release_age_lookahead_fetches.get();
        if used >= RELEASE_AGE_LOOKAHEAD_FETCH_LIMIT {
            return false;
        }
        self.release_age_lookahead_fetches.set(used + 1);
        true
    }

    #[cfg(test)]
    pub(super) fn release_age_lookahead_fetches(&self) -> usize {
        self.release_age_lookahead_fetches.get()
    }
}

pub(super) async fn preferred_tree_compatible_version<P>(
    edge: &Edge,
    info: &CachedPackageInfo,
    policy: &ResolverPolicy,
    provider: &P,
    cache: &TreeStatusCache,
) -> Option<NpmVersion>
where
    P: TreeManifestProvider,
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
    cache: &'a TreeStatusCache,
) -> Pin<Box<dyn Future<Output = TreePick> + 'a>>
where
    P: TreeManifestProvider,
{
    Box::pin(async move {
        let mut saw_candidate = false;
        for version in &info.versions {
            if !range.satisfies(version) {
                continue;
            }
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
    cache: &'a TreeStatusCache,
) -> Pin<Box<dyn Future<Output = TreeStatus> + 'a>>
where
    P: TreeManifestProvider,
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
        let Some(deps) = info.deps.get(&version_str) else {
            visited.remove(&visit_key);
            cache.insert(visit_key, TreeStatus::Compatible);
            return TreeStatus::Compatible;
        };
        let aliases = info.aliases.get(&version_str);
        let optional_names = info.optional_dep_names.get(&version_str);
        let bundled_names = info.bundled_dep_names.get(&version_str);
        let mut entries: Vec<(&String, &String)> = deps.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        let prefetch_canonicals: Vec<CanonicalKey> = entries
            .iter()
            .filter_map(|(local_name, range_str)| {
                if bundled_names.is_some_and(|names| names.contains(*local_name))
                    || optional_names.is_some_and(|names| names.contains(*local_name))
                    || super::version::is_workspace_specifier(range_str)
                    || NpmRange::parse(range_str).is_err()
                {
                    return None;
                }
                Some(match aliases.and_then(|alias| alias.get(*local_name)) {
                    Some(target) => CanonicalKey::from_dep_name(target),
                    None => CanonicalKey::from_dep_name(local_name),
                })
            })
            .collect();
        let release_age_tree_policy = policy.release_age_checks_all_packages();
        if policy.requires_trust_history() || release_age_tree_policy {
            provider.prefetch_manifests(&prefetch_canonicals).await;
        }

        for (local_name, range_str) in entries {
            if bundled_names.is_some_and(|names| names.contains(local_name)) {
                continue;
            }
            if optional_names.is_some_and(|names| names.contains(local_name)) {
                continue;
            }
            if super::version::is_workspace_specifier(range_str) {
                continue;
            }
            let Ok(range) = NpmRange::parse(range_str) else {
                continue;
            };
            let child_canonical = match aliases.and_then(|alias| alias.get(local_name)) {
                Some(target) => CanonicalKey::from_dep_name(target),
                None => CanonicalKey::from_dep_name(local_name),
            };
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
