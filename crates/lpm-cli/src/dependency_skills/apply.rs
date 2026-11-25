use super::git_exclude::{ExcludeOutcome, sync_exclude_block};
use super::links::{Recorded, TargetDir, TargetEntry, passes_through_link, remove_if_empty};
use super::plan::{Candidate, CandidateStatus, HoldReason, Plan, Prepared};
use super::policy::Targets;
use super::snapshot::{snapshot_digest, sweep, write_snapshot};
use super::state::{
    FileStamp, LinkKind, LinkRecord, LinkState, LinkedSkillRecord, StoredState, read_state,
    remove_root_if_empty, remove_state, write_state,
};
use lpm_common::LpmError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A skill whose links changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillChange {
    pub(crate) skill: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) targets: Vec<String>,
}

/// An allowed skill that isn't linked as its package now ships it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldSkill {
    pub(crate) skill: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) reason: HoldReason,
    pub(crate) detail: String,
    /// The earlier version whose copy stays linked meanwhile.
    pub(crate) kept_version: Option<String>,
}

/// What reconciling a project's links did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileReport {
    pub(crate) linked: Vec<SkillChange>,
    pub(crate) updated: Vec<SkillChange>,
    pub(crate) removed: Vec<SkillChange>,
    pub(crate) held: Vec<HeldSkill>,
    pub(crate) unchanged: usize,
    pub(crate) warnings: Vec<String>,
}

impl ReconcileReport {
    pub(crate) fn is_quiet(&self) -> bool {
        self.linked.is_empty()
            && self.updated.is_empty()
            && self.removed.is_empty()
            && self.held.is_empty()
            && self.warnings.is_empty()
    }
}

/// The inputs a reconcile records, so the next one can tell whether
/// anything it depends on changed.
pub(crate) struct Inputs {
    pub(crate) fingerprint: String,
    pub(crate) policy: String,
    pub(crate) lockfile: Option<FileStamp>,
}

/// What the links should hold for one skill.
pub(crate) enum Desired<'a> {
    /// The checked bytes of the version installed now.
    Fresh(&'a Candidate, &'a Prepared),
    /// The copy linked earlier, which stays while the version installed now
    /// waits for data or a more specific approval.
    Kept(LinkedSkillRecord),
}

/// What reconciling `plan` leaves linked, given `previous`, and the allowed
/// skills it holds back. `policy` is the digest of the plan's policy.
pub(crate) fn desired_skills<'a>(
    project_dir: &Path,
    plan: &'a Plan,
    previous: &'a LinkState,
    policy: &str,
) -> (BTreeMap<&'a str, Desired<'a>>, Vec<HeldSkill>) {
    let mut desired = BTreeMap::new();
    let mut held = Vec::new();
    for candidate in &plan.candidates {
        match &candidate.status {
            CandidateStatus::Linkable(prepared) => {
                let replaced = desired.insert(
                    candidate.skill.as_str(),
                    Desired::Fresh(candidate, prepared),
                );
                debug_assert!(replaced.is_none(), "planning resolves name conflicts");
            }
            CandidateStatus::Held { reason, detail } => {
                let kept = previous
                    .skills
                    .get(&candidate.skill)
                    .filter(|record| {
                        keeps_earlier_copy(
                            project_dir,
                            candidate,
                            *reason,
                            record,
                            previous,
                            policy,
                        )
                    })
                    .cloned();
                held.push(HeldSkill {
                    skill: candidate.skill.clone(),
                    package: candidate.package.clone(),
                    version: candidate.version.clone(),
                    reason: *reason,
                    detail: detail.clone(),
                    kept_version: kept.as_ref().map(|record| record.version.clone()),
                });
                if let Some(record) = kept {
                    desired.insert(candidate.skill.as_str(), Desired::Kept(record));
                }
            }
            CandidateStatus::NotAllowed | CandidateStatus::Denied => {}
        }
    }
    for (skill, record) in &previous.skills {
        let Some(detail) = plan.unlisted.get(&record.package) else {
            continue;
        };
        if desired.contains_key(skill.as_str())
            || revoked(plan, skill, &record.package)
            || !plan
                .unlisted_allows
                .get(&record.package)
                .is_some_and(|skills| skills.contains(skill))
        {
            continue;
        }
        let kept = previous.policy == policy
            && snapshot_digest(project_dir, skill).as_deref() == Some(record.digest.as_str());
        held.push(HeldSkill {
            skill: skill.clone(),
            package: record.package.clone(),
            version: record.version.clone(),
            reason: HoldReason::Unreadable,
            detail: detail.clone(),
            kept_version: kept.then(|| record.version.clone()),
        });
        if kept {
            desired.insert(skill.as_str(), Desired::Kept(record.clone()));
        }
    }
    (desired, held)
}

/// Whether the plan decided against `package`'s `skill` outright: a deny,
/// or a problem that keeps any copy of it out, or a name conflict, which
/// keeps every package's copy out. Such a decision outweighs an unreadable
/// instance's earlier copy; another package's denial doesn't.
fn revoked(plan: &Plan, skill: &str, package: &str) -> bool {
    plan.candidates.iter().any(|candidate| {
        candidate.skill == skill
            && match &candidate.status {
                CandidateStatus::Held {
                    reason: HoldReason::NameConflict,
                    ..
                } => true,
                CandidateStatus::Denied
                | CandidateStatus::Held {
                    reason: HoldReason::Invalid | HoldReason::Blocked | HoldReason::Hooks,
                    ..
                } => candidate.package == package,
                _ => false,
            }
    })
}

/// Whether the copy `record` linked earlier stays while `candidate`, the
/// version installed now, is held for `reason`: the policy must still
/// approve that copy as it approved it then, and the copy must be intact.
/// Waiting for data, or for the installed skill to become readable, that
/// means the same policy; waiting for a more specific approval, an
/// allowing entry that names the skill as specifically as the earlier
/// copy's own grants needed.
fn keeps_earlier_copy(
    project_dir: &Path,
    candidate: &Candidate,
    reason: HoldReason,
    record: &LinkedSkillRecord,
    previous: &LinkState,
    policy: &str,
) -> bool {
    let approved = match reason {
        HoldReason::NeedsData | HoldReason::Unreadable => previous.policy == policy,
        HoldReason::NeedsPackageName | HoldReason::NeedsSkillName => {
            candidate.naming >= record.requires
        }
        HoldReason::Invalid
        | HoldReason::Blocked
        | HoldReason::Hooks
        | HoldReason::NameConflict => false,
    };
    approved
        && record.package == candidate.package
        && snapshot_digest(project_dir, &candidate.skill).as_deref() == Some(record.digest.as_str())
}

/// Why a run leaves dependency-skill links alone after a newer LPM
/// recorded them.
pub(crate) fn newer_state_warning(reason: &str) -> String {
    format!("{reason}, so this LPM leaves dependency skill links alone; update LPM to manage them")
}

/// Applies `plan` to the project: writes changed copies, links them into
/// every target, removes what LPM linked earlier that the plan no longer
/// wants, keeps the links out of Git, and records the result. The caller
/// holds the project's link lock from before it read the policy.
pub(crate) fn apply(
    project_dir: &Path,
    plan: &Plan,
    inputs: Inputs,
    _lock: &lpm_common::ExclusiveLockHandle,
) -> Result<ReconcileReport, LpmError> {
    let mut report = ReconcileReport {
        warnings: plan.problems.clone(),
        ..ReconcileReport::default()
    };
    let previous = match read_state(project_dir) {
        StoredState::Present(state) => state,
        StoredState::Missing => LinkState::default(),
        StoredState::Unusable(reason) => {
            report.warnings.push(format!(
                "{reason}; only links LPM can prove it made are replaced"
            ));
            LinkState::default()
        }
        StoredState::Newer(reason) => {
            report.warnings.push(newer_state_warning(&reason));
            return Ok(report);
        }
    };
    let targets = match plan.policy.as_ref() {
        Some(policy) if policy.is_active() => {
            let resolved = resolve_targets(project_dir, &policy.targets);
            for target in unreachable_targets(project_dir, &policy.targets, &resolved) {
                report.warnings.push(format!(
                    "{target} passes through a link, so LPM doesn't link skills into it"
                ));
            }
            resolved
        }
        _ => Vec::new(),
    };
    let (desired, held) = desired_skills(project_dir, plan, &previous, &inputs.policy);
    let unreadable = !plan.unlisted.is_empty()
        || plan.incomplete
        || held
            .iter()
            .any(|skill| skill.reason == HoldReason::Unreadable);
    for (package, detail) in &plan.unlisted {
        if !held.iter().any(|skill| &skill.package == package) {
            report.warnings.push(format!("{package}: {detail}"));
        }
    }
    report.held = held;

    let mut next = LinkState {
        fingerprint: inputs.fingerprint,
        policy: inputs.policy,
        lockfile: inputs.lockfile,
        created_directories: previous.created_directories.clone(),
        ..LinkState::default()
    };
    let mut complete = !unreadable;
    let mut directories = TargetDirs::default();
    for (skill, wanted) in desired {
        let earlier = previous.skills.get(skill);
        let (mut record, change) = match wanted {
            Desired::Kept(record) => (record, None),
            Desired::Fresh(candidate, prepared) => {
                let digest = &prepared.checked.digest;
                let copy = snapshot_digest(project_dir, skill);
                if copy.as_deref() != Some(digest.as_str())
                    && let Err(error) = write_snapshot(project_dir, skill, &prepared.entries)
                {
                    complete = false;
                    report.warnings.push(format!(
                        "skill `{skill}` from {}@{} could not be copied, so it isn't linked until a later run copies it: {error}",
                        candidate.package, candidate.version,
                    ));
                    continue;
                }
                let change = match earlier {
                    None => Some(ChangeKind::Linked),
                    Some(record)
                        if record.digest != *digest || record.package != candidate.package =>
                    {
                        Some(ChangeKind::Updated)
                    }
                    Some(_) => None,
                };
                (
                    LinkedSkillRecord {
                        package: candidate.package.clone(),
                        version: candidate.version.clone(),
                        integrity: candidate.integrity.clone(),
                        digest: digest.clone(),
                        permission: prepared.permission.as_str().to_string(),
                        requires: prepared.requires,
                        links: Vec::new(),
                        blocked: Vec::new(),
                    },
                    change,
                )
            }
        };
        record.links.clear();
        record.blocked.clear();
        let mut linked_targets = Vec::with_capacity(targets.len());
        for target in &targets {
            let path = format!("{target}/{skill}");
            let recorded = earlier.and_then(|earlier| {
                earlier
                    .links
                    .iter()
                    .find(|link| link.path == path)
                    .map(|link| Recorded {
                        kind: link.kind,
                        digest: &earlier.digest,
                    })
            });
            let outcome = directories
                .create(project_dir, target, &mut next.created_directories)
                .and_then(|directory| {
                    link_entry(project_dir, directory, skill, &record.digest, recorded)
                        .map_err(|error| error.to_string())
                });
            match outcome {
                Ok(Some(kind)) => {
                    record.links.push(LinkRecord {
                        path,
                        kind,
                        digest: None,
                    });
                    linked_targets.push(target.clone());
                }
                Ok(None) => {
                    report.warnings.push(format!(
                        "{path} already holds a skill LPM didn't link; it was left alone"
                    ));
                    record.blocked.push(path);
                }
                Err(error) => {
                    report.warnings.push(format!(
                        "skill `{skill}` could not be linked into {target}: {error}"
                    ));
                    record.blocked.push(path);
                    complete = false;
                }
            }
        }
        if record.links.is_empty() && record.blocked.is_empty() {
            continue;
        }
        if !record.links.is_empty() {
            let summary = SkillChange {
                skill: skill.to_string(),
                package: record.package.clone(),
                version: record.version.clone(),
                targets: linked_targets,
            };
            match change {
                Some(ChangeKind::Linked) => report.linked.push(summary),
                Some(ChangeKind::Updated) => report.updated.push(summary),
                None => report.unchanged += 1,
            }
        }
        next.skills.insert(skill.to_string(), record);
    }

    remove_stale(
        project_dir,
        &previous,
        &mut next,
        &targets,
        &mut directories,
        &mut report,
    );
    remove_unused_directories(project_dir, &mut next);
    sweep(project_dir, |name| next.skills.contains_key(name));

    let entries: Vec<String> = next
        .skills
        .values()
        .flat_map(|record| record.links.iter().map(|link| link.path.clone()))
        .collect();
    if let ExcludeOutcome::Failed(reason) = sync_exclude_block(project_dir, &entries)
        && !entries.is_empty()
    {
        report.warnings.push(format!(
            "linked skills could not be kept out of Git ({reason}); add {} to your ignore file",
            entries.join(", ")
        ));
    }

    if !complete {
        next.fingerprint.clear();
    }
    let active = plan
        .policy
        .as_ref()
        .is_some_and(|policy| policy.is_active());
    if active
        || !next.skills.is_empty()
        || !next.stale.is_empty()
        || !next.created_directories.is_empty()
    {
        write_state(project_dir, &next)?;
    } else {
        remove_state(project_dir)?;
        remove_root_if_empty(project_dir);
    }
    Ok(report)
}

#[derive(Clone, Copy)]
enum ChangeKind {
    Linked,
    Updated,
}

/// Target directories opened once per reconcile: created on first use when
/// linking, and opened as they are when removing.
#[derive(Default)]
struct TargetDirs {
    created: BTreeMap<String, Result<TargetDir, String>>,
    opened: BTreeMap<String, Result<Option<TargetDir>, String>>,
}

impl TargetDirs {
    fn create(
        &mut self,
        project_dir: &Path,
        target: &str,
        created_directories: &mut Vec<String>,
    ) -> Result<&TargetDir, String> {
        self.created
            .entry(target.to_string())
            .or_insert_with(|| {
                TargetDir::create(project_dir, target, created_directories)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn open(&mut self, project_dir: &Path, target: &str) -> Result<Option<&TargetDir>, String> {
        if let Some(Ok(directory)) = self.created.get(target) {
            return Ok(Some(directory));
        }
        self.opened
            .entry(target.to_string())
            .or_insert_with(|| {
                TargetDir::open(project_dir, target).map_err(|error| error.to_string())
            })
            .as_ref()
            .map(Option::as_ref)
            .map_err(Clone::clone)
    }
}

/// Makes `skill`'s entry in `directory` LPM's link to its copy, `digest`,
/// replacing a Git placeholder, or a copy LPM recorded there and that
/// still holds what LPM wrote. A copy already holding `digest`'s files
/// where LPM recorded a copy stays as it is, as a run interrupted between
/// writing it and recording it leaves it. `Ok(None)` when something else
/// is there, including a marked copy LPM has no record of: matching files
/// prove nothing about who put them there.
fn link_entry(
    project_dir: &Path,
    directory: &TargetDir,
    skill: &str,
    digest: &str,
    recorded: Option<Recorded<'_>>,
) -> Result<Option<LinkKind>, LpmError> {
    let recorded_kind = recorded.map(|recorded| recorded.kind);
    let replaceable = match directory.inspect(project_dir, skill) {
        TargetEntry::Missing => return directory.link(project_dir, skill, digest).map(Some),
        TargetEntry::Link => return Ok(Some(LinkKind::Link)),
        TargetEntry::Copy(found) if found == digest && recorded_kind == Some(LinkKind::Copy) => {
            return Ok(Some(LinkKind::Copy));
        }
        TargetEntry::Placeholder => true,
        TargetEntry::Copy(_) => recorded_kind == Some(LinkKind::Copy),
        TargetEntry::Occupied => {
            recorded_kind == Some(LinkKind::Link) && directory.is_moved_link(skill)
        }
    };
    if replaceable && directory.remove(project_dir, skill, recorded)? {
        directory.link(project_dir, skill, digest).map(Some)
    } else {
        Ok(None)
    }
}

/// The project-relative directories `targets` names now: `.agents/skills`,
/// plus `.claude/skills` when the project has a `.claude` directory, or the
/// explicit list; without any that passes through a link. A skills folder
/// linked to another one, as projects sharing one folder between agents
/// do, already shows what LPM links into the folder it points at, and
/// LPM never writes through links.
pub(crate) fn resolve_targets(project_dir: &Path, targets: &Targets) -> Vec<String> {
    target_candidates(project_dir, targets)
        .into_iter()
        .filter(|target| !passes_through_link(project_dir, target))
        .collect()
}

fn target_candidates(project_dir: &Path, targets: &Targets) -> Vec<String> {
    match targets {
        Targets::Explicit(targets) => targets.clone(),
        Targets::Auto => {
            let mut candidates = vec![".agents/skills".to_string()];
            if std::fs::symlink_metadata(project_dir.join(".claude")).is_ok_and(|metadata| {
                metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata)
            }) {
                candidates.push(".claude/skills".to_string());
            }
            candidates
        }
    }
}

/// The targets [`resolve_targets`] leaves out that don't lead to one it
/// keeps, so agents reading them don't see what LPM links.
fn unreachable_targets(project_dir: &Path, targets: &Targets, resolved: &[String]) -> Vec<String> {
    let mut candidates = target_candidates(project_dir, targets);
    candidates.retain(|target| !resolved.contains(target));
    if candidates.is_empty() {
        return candidates;
    }
    let kept: Vec<std::path::PathBuf> = resolved
        .iter()
        .filter_map(|target| {
            super::links::project_path(project_dir, target)
                .canonicalize()
                .ok()
        })
        .collect();
    candidates.retain(|target| {
        super::links::project_path(project_dir, target)
            .canonicalize()
            .map_or(true, |path| !kept.contains(&path))
    });
    candidates
}

/// Removes the entries LPM made earlier that `next` no longer holds, from
/// the skills it dropped, the targets it dropped, and removals that failed
/// before; a removal that fails again stays recorded for the next
/// reconcile. Then removes any link in a target directory that points at
/// an LPM copy of a skill it doesn't hold. Copies are only removed where
/// recorded, and nothing is reached through a linked directory.
fn remove_stale(
    project_dir: &Path,
    previous: &LinkState,
    next: &mut LinkState,
    targets: &[String],
    directories: &mut TargetDirs,
    report: &mut ReconcileReport,
) {
    let current: BTreeSet<String> = next
        .skills
        .values()
        .flat_map(|record| record.links.iter().map(|link| link.path.clone()))
        .collect();
    let mut scanned: BTreeSet<String> = targets.iter().cloned().collect();
    let recorded = previous
        .skills
        .iter()
        .map(|(skill, record)| (skill, record.links.as_slice(), Some(record)));
    let failed_before = previous
        .stale
        .iter()
        .map(|(skill, links)| (skill, links.as_slice(), None));
    for (skill, links, record) in recorded.chain(failed_before) {
        let mut removed_targets = Vec::new();
        for link in links {
            if current.contains(&link.path) {
                continue;
            }
            let Some((target, _)) = link.path.rsplit_once('/') else {
                continue;
            };
            scanned.insert(target.to_string());
            let digest = record
                .map(|record| record.digest.as_str())
                .or(link.digest.as_deref());
            let pending = || LinkRecord {
                digest: digest.map(str::to_string),
                ..link.clone()
            };
            let removal = match directories.open(project_dir, target) {
                Ok(None) => Ok(true),
                Ok(Some(directory)) => directory
                    .remove(
                        project_dir,
                        skill,
                        Some(Recorded {
                            kind: link.kind,
                            digest: digest.unwrap_or_default(),
                        }),
                    )
                    .map_err(|error| error.to_string()),
                Err(reason) => {
                    report
                        .warnings
                        .push(format!("{} was left alone for now: {reason}", link.path));
                    next.stale.entry(skill.clone()).or_default().push(pending());
                    continue;
                }
            };
            match removal {
                Ok(true) => removed_targets.push(target.to_string()),
                Ok(false) => report.warnings.push(format!(
                    "{} no longer holds LPM's copy of `{skill}`; it was left alone",
                    link.path
                )),
                Err(error) => {
                    report
                        .warnings
                        .push(format!("{} could not be removed: {error}", link.path));
                    next.stale.entry(skill.clone()).or_default().push(pending());
                }
            }
        }
        if let Some(record) = record
            && !next.skills.contains_key(skill)
        {
            report.removed.push(SkillChange {
                skill: skill.clone(),
                package: record.package.clone(),
                version: record.version.clone(),
                targets: removed_targets,
            });
        }
    }
    for target in scanned {
        let Ok(Some(directory)) = directories.open(project_dir, &target) else {
            continue;
        };
        for name in directory.skill_names() {
            if next.skills.contains_key(&name) || next.stale.contains_key(&name) {
                continue;
            }
            if matches!(
                directory.inspect(project_dir, &name),
                TargetEntry::Link | TargetEntry::Placeholder
            ) {
                let _ = directory.remove(project_dir, &name, None);
            }
        }
    }
}

/// Removes the directories LPM created that no link uses any more, deepest
/// first, when they are empty.
fn remove_unused_directories(project_dir: &Path, next: &mut LinkState) {
    let in_use: Vec<&str> = next
        .skills
        .values()
        .flat_map(|record| record.links.iter().map(|link| link.path.as_str()))
        .chain(next.stale.values().flatten().map(|link| link.path.as_str()))
        .collect();
    let mut directories = std::mem::take(&mut next.created_directories);
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.len()));
    let mut kept = Vec::with_capacity(directories.len());
    for directory in directories {
        let prefix = format!("{directory}/");
        let used = in_use.iter().any(|path| path.starts_with(&prefix));
        if used || !remove_if_empty(project_dir, &directory) {
            kept.push(directory);
        }
    }
    kept.sort();
    next.created_directories = kept;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_an_interrupted_update_left_where_lpm_recorded_its_older_copy_is_taken_over() {
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join(".agents/skills/deploy");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("SKILL.md"), "new").unwrap();
        let incoming = lpm_skill::skill_files_digest([("SKILL.md", b"new".as_slice())]);
        std::fs::write(
            entry.join(super::super::links::COPY_MARKER),
            serde_json::json!({ "skill": "deploy", "digest": incoming }).to_string(),
        )
        .unwrap();
        let directory =
            TargetDir::create(project.path(), ".agents/skills", &mut Vec::new()).unwrap();
        let older = Recorded {
            kind: LinkKind::Copy,
            digest: "sha256:the-copy-lpm-linked-before",
        };

        let linked = link_entry(project.path(), &directory, "deploy", &incoming, Some(older));

        assert!(matches!(linked, Ok(Some(LinkKind::Copy))), "{linked:?}");
        assert_eq!(
            std::fs::read_to_string(entry.join("SKILL.md")).unwrap(),
            "new"
        );
    }
}
