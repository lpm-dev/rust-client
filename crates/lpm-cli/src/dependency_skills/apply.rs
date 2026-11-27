use super::git_exclude::{ExcludeOutcome, sync_exclude_block};
use super::links::{Recorded, TargetDir, TargetEntry, passes_through_link, remove_if_empty};
use super::plan::{Candidate, CandidateStatus, HoldReason, Plan, Prepared};
use super::policy::Targets;
use super::snapshot::{snapshot_digest, sweep, write_snapshot};
use super::state::{
    FileStamp, LinkKind, LinkRecord, LinkState, LinkedSkillRecord, StoredState,
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
    pub(crate) members: Vec<String>,
    pub(crate) recheck: super::checks::Recheck,
    /// The security provider's verdicts, when one checks npm packages: an
    /// earlier copy of an npm package stays only while its own release is
    /// clean.
    pub(crate) verdicts: Option<super::checks::Book>,
    /// The release check copies linked now pass, when the provider checks.
    pub(crate) checked_as: Option<String>,
}

/// The security provider's verdicts and the release check they answer
/// for, when one checks npm packages.
#[derive(Clone, Copy)]
pub(crate) struct Verdicts<'a> {
    pub(crate) book: &'a super::checks::Book,
    pub(crate) checked_as: Option<&'a str>,
}

/// What the links should hold for one skill.
pub(crate) enum Desired<'a> {
    /// The checked bytes of the version installed now.
    Fresh(&'a Candidate, &'a Prepared),
    /// The copy linked earlier, which stays while the version installed now
    /// waits for data or a more specific approval.
    Kept(&'a LinkedSkillRecord),
}

/// What reconciling `plan` leaves linked, given `previous`, and the allowed
/// skills it holds back. `policy` is the digest of the plan's policy, and
/// `verdicts` the security provider's, when one checks npm packages. A
/// skill linked fresh claims its name before any earlier copy another
/// package keeps.
pub(crate) fn desired_skills<'a>(
    project_dir: &Path,
    plan: &'a Plan,
    previous: &'a LinkState,
    policy: &str,
    targets: &[String],
    verdicts: Option<Verdicts<'_>>,
) -> (BTreeMap<&'a str, Desired<'a>>, Vec<HeldSkill>) {
    let mut desired = BTreeMap::new();
    let mut held = Vec::new();
    for candidate in &plan.candidates {
        if let CandidateStatus::Linkable(prepared) = &candidate.status {
            let replaced = desired.insert(
                candidate.skill.as_str(),
                Desired::Fresh(candidate, prepared),
            );
            debug_assert!(replaced.is_none(), "planning resolves name conflicts");
        }
    }
    let clean = |record: &LinkedSkillRecord| {
        verdicts.is_none_or(|verdicts| release_is_clean(verdicts, record))
    };
    for candidate in &plan.candidates {
        let CandidateStatus::Held { reason, detail } = &candidate.status else {
            continue;
        };
        let kept = held_copy(
            project_dir,
            candidate,
            *reason,
            previous,
            policy,
            targets,
            |skill| desired.contains_key(skill),
        )
        .filter(|record| {
            clean(record)
                && verdicts.is_none_or(|verdicts| {
                    (!plan.unlisted.contains_key(&record.package)
                        || installed_release_allows(verdicts, plan, record))
                        && instances_allow_commands(verdicts, plan, record)
                })
        });
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
    for (skill, record) in &previous.skills {
        let Some(detail) = unlisted_hold(plan, skill, record, |skill| desired.contains_key(skill))
        else {
            continue;
        };
        let kept = keeps_unlisted_copy(project_dir, skill, record, previous, policy, targets)
            && clean(record)
            && verdicts.is_none_or(|verdicts| installed_release_allows(verdicts, plan, record));
        held.push(HeldSkill {
            skill: skill.clone(),
            package: record.package.clone(),
            version: record.version.clone(),
            reason: HoldReason::Unreadable,
            detail: detail.clone(),
            kept_version: kept.then(|| record.version.clone()),
        });
        if kept {
            desired.insert(skill.as_str(), Desired::Kept(record));
        }
    }
    (desired, held)
}

/// The copy linked earlier that stays while `candidate` is held for
/// `reason`, before the security provider's verdict on it weighs in: none
/// when another skill already `taken` its name, or when none of its links
/// in `targets` is still intact.
fn held_copy<'a>(
    project_dir: &Path,
    candidate: &Candidate,
    reason: HoldReason,
    previous: &'a LinkState,
    policy: &str,
    targets: &[String],
    taken: impl Fn(&str) -> bool,
) -> Option<&'a LinkedSkillRecord> {
    let record = previous.skills.get(&candidate.skill)?;
    (!taken(&candidate.skill)
        && keeps_earlier_copy(project_dir, candidate, reason, record, previous, policy)
        && has_intact_link(project_dir, &candidate.skill, record, targets))
    .then_some(record)
}

/// Whether one of the links `record` recorded for `skill` in `targets` is
/// still there and LPM's: a kept copy stays only where it is linked.
fn has_intact_link(
    project_dir: &Path,
    skill: &str,
    record: &LinkedSkillRecord,
    targets: &[String],
) -> bool {
    record.links.iter().any(|link| {
        link.path.rsplit_once('/').is_some_and(|(target, name)| {
            name == skill
                && targets.iter().any(|wanted| wanted == target)
                && kept_link_intact(
                    project_dir,
                    target,
                    skill,
                    Recorded {
                        kind: link.kind,
                        digest: &record.digest,
                    },
                )
        })
    })
}

/// Why `skill`'s copy, linked earlier from `record`'s package, is held
/// because that package's skills couldn't be listed, unless the policy
/// couldn't allow them whatever they are, another skill already `taken` its
/// name, the plan decided against it outright, or an instance of the
/// package that could be listed ships the skill, which then decides the
/// copy.
fn unlisted_hold<'a>(
    plan: &'a Plan,
    skill: &str,
    record: &LinkedSkillRecord,
    taken: impl Fn(&str) -> bool,
) -> Option<&'a String> {
    let detail = plan.unlisted.get(&record.package)?;
    (plan
        .unlisted_allows
        .get(&record.package)
        .is_some_and(|skills| skills.contains(skill))
        && !taken(skill)
        && !revoked(plan, skill, &record.package)
        && !plan.candidates.iter().any(|candidate| {
            candidate.skill == skill
                && candidate.package == record.package
                && !matches!(candidate.status, CandidateStatus::NotAllowed)
        }))
    .then_some(detail)
}

/// Whether a copy whose package's skills couldn't be listed stays: while
/// the policy is unchanged, the copy is intact, and one of its links in
/// `targets` is.
fn keeps_unlisted_copy(
    project_dir: &Path,
    skill: &str,
    record: &LinkedSkillRecord,
    previous: &LinkState,
    policy: &str,
    targets: &[String],
) -> bool {
    previous.policy == policy
        && reviewed_here(record)
        && snapshot_digest(project_dir, skill).as_deref() == Some(record.digest.as_str())
        && has_intact_link(project_dir, skill, record, targets)
}

/// Whether the security provider's last verdict on the npm release `record`
/// linked is clean, however old, under the release check the copy passed
/// when it linked: a copy stays only while its own release is. An LPM.dev
/// package's copy answers to LPM.dev review instead.
fn release_is_clean(verdicts: Verdicts<'_>, record: &LinkedSkillRecord) -> bool {
    super::plan::is_lpm_dev(&record.package)
        || (checked_as(verdicts.checked_as, record)
            && verdicts
                .book
                .entry(&record.package, &record.version)
                .is_some_and(|entry| entry.verdict == super::socket::Verdict::Clean))
}

/// Whether, under the security provider, every instance of `record`'s
/// package installed now lets its copy stay while one of them can't be
/// listed: each must be an npm release a verdict covers, as a listed one
/// must be to keep a copy, none may be flagged, and a copy that pre-approves
/// anything stays only while every instance is its own release, since its
/// commands run what is installed. An LPM.dev package's copy answers to
/// LPM.dev review instead.
fn installed_release_allows(
    verdicts: Verdicts<'_>,
    plan: &Plan,
    record: &LinkedSkillRecord,
) -> bool {
    if super::plan::is_lpm_dev(&record.package) {
        return true;
    }
    let Some(installs) = plan.installs.get(&record.package) else {
        return false;
    };
    let grants = record.permission != lpm_skill::SkillPermission::None.as_str();
    installs.iter().all(|install| {
        let Some((name, version)) = &install.release else {
            return false;
        };
        let flagged = verdicts
            .book
            .entry(name, version)
            .is_some_and(|entry| matches!(entry.verdict, super::socket::Verdict::Malware { .. }));
        !flagged
            && (!grants
                || verdicts.book.vouches_now(name, version)
                    && (*name == record.package
                        && *version == record.version
                        && install.version == record.version
                        && install.integrity == record.integrity))
    })
}

/// Whether, under the security provider, the copy `record` keeps may keep
/// pre-approving its package's command: a copy that pre-approves nothing
/// may; one that does only while every installed instance of the package,
/// any of which the command may run, is an npm release whose last verdict,
/// however old, is clean. With no instance recorded, nothing vouches for
/// what the command runs.
fn instances_allow_commands(
    verdicts: Verdicts<'_>,
    plan: &Plan,
    record: &LinkedSkillRecord,
) -> bool {
    if record.permission == lpm_skill::SkillPermission::None.as_str()
        || super::plan::is_lpm_dev(&record.package)
    {
        return true;
    }
    let Some(installs) = plan.installs.get(&record.package) else {
        return false;
    };
    installs.iter().all(|install| {
        install.release.as_ref().is_some_and(|(name, version)| {
            verdicts.book.vouches_now(name, version)
                && verdicts
                    .book
                    .entry(name, version)
                    .is_some_and(|entry| entry.verdict == super::socket::Verdict::Clean)
        })
    })
}

/// Whether `record`'s copy passed the release check `current` names.
fn checked_as(current: Option<&str>, record: &LinkedSkillRecord) -> bool {
    current.is_some() && record.checked_as.as_deref() == current
}

/// The npm releases of the copies linked earlier that `plan` would keep,
/// if their verdicts allow, and, for a package one of whose instances
/// can't be listed, the releases of every instance installed now: those
/// verdicts decide whether the copies stay, so they are asked about and
/// rechecked like the releases installed now. A copy no verdict can keep,
/// such as one linked under another release check, is never asked about.
pub(crate) fn retained_releases(
    project_dir: &Path,
    plan: &Plan,
    previous: &LinkState,
    policy: &str,
    current: Option<&str>,
) -> BTreeSet<(String, String)> {
    let targets = link_targets(project_dir, plan);
    let fresh: BTreeSet<&str> = plan
        .candidates
        .iter()
        .filter(|candidate| matches!(candidate.status, CandidateStatus::Linkable(_)))
        .map(|candidate| candidate.skill.as_str())
        .collect();
    let taken = |skill: &str| fresh.contains(skill);
    let mut releases = BTreeSet::new();
    let mut retain = |record: &LinkedSkillRecord, unlisted: bool| {
        if super::plan::is_lpm_dev(&record.package) || !checked_as(current, record) {
            return;
        }
        let Some(installed) = deciding_installs(plan, record, unlisted) else {
            return;
        };
        releases.insert((record.package.clone(), record.version.clone()));
        releases.extend(installed);
    };
    for candidate in &plan.candidates {
        if let CandidateStatus::Held { reason, .. } = &candidate.status
            && let Some(record) = held_copy(
                project_dir,
                candidate,
                *reason,
                previous,
                policy,
                &targets,
                taken,
            )
        {
            retain(record, plan.unlisted.contains_key(&record.package));
        }
    }
    for (skill, record) in &previous.skills {
        if unlisted_hold(plan, skill, record, taken).is_some()
            && keeps_unlisted_copy(project_dir, skill, record, previous, policy, &targets)
        {
            retain(record, true);
        }
    }
    releases
}

/// The releases of `record`'s package installed now whose verdicts decide
/// whether its copy stays, besides its own, or `None` when no verdict
/// could keep it: what [`installed_release_allows`] and
/// [`instances_allow_commands`] check before reading any verdict, for a
/// package one of whose instances couldn't be listed (`unlisted`) or a copy
/// that pre-approves commands.
fn deciding_installs(
    plan: &Plan,
    record: &LinkedSkillRecord,
    unlisted: bool,
) -> Option<Vec<(String, String)>> {
    let grants = record.permission != lpm_skill::SkillPermission::None.as_str();
    if !unlisted && !grants {
        return Some(Vec::new());
    }
    let installs = plan.installs.get(&record.package)?;
    let mut releases = Vec::with_capacity(installs.len());
    for install in installs {
        let release = install.release.as_ref()?;
        if unlisted
            && grants
            && !(release.0 == record.package
                && release.1 == record.version
                && install.version == record.version
                && install.integrity == record.integrity)
        {
            return None;
        }
        releases.push(release.clone());
    }
    Some(releases)
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
                    reason:
                        HoldReason::Invalid
                        | HoldReason::Blocked
                        | HoldReason::Hooks
                        | HoldReason::Malware,
                    ..
                } => candidate.package == package,
                _ => false,
            }
    })
}

/// Whether the copy `record` linked earlier stays while `candidate`, the
/// version installed now, is held for `reason`: the policy must still
/// approve that copy as it approved it then, and the copy must be intact.
/// Waiting for data, LPM.dev review, a security check, or the installed
/// skill to become readable, that means the same policy; waiting for a
/// more specific approval, an allowing entry that names the skill as
/// specifically as the earlier copy's own grants needed. A copy of the
/// very release installed now, waiting for a security check, also stays
/// under an edited policy that still names it that specifically; a copy of
/// another release stays then only if it pre-approves nothing, since the
/// commands it would pre-approve now run the release Socket hasn't
/// cleared.
fn keeps_earlier_copy(
    project_dir: &Path,
    candidate: &Candidate,
    reason: HoldReason,
    record: &LinkedSkillRecord,
    previous: &LinkState,
    policy: &str,
) -> bool {
    let approved = match reason {
        HoldReason::NeedsData | HoldReason::NotReviewed | HoldReason::Unreadable => {
            previous.policy == policy
        }
        HoldReason::AwaitingCheck
            if record.version == candidate.version && record.integrity == candidate.integrity =>
        {
            previous.policy == policy
                || (!candidate.undecided && candidate.naming >= record.requires)
        }
        HoldReason::AwaitingCheck => {
            previous.policy == policy
                && record.permission == lpm_skill::SkillPermission::None.as_str()
        }
        HoldReason::NeedsPackageName | HoldReason::NeedsSkillName => {
            candidate.naming >= record.requires
        }
        HoldReason::Invalid
        | HoldReason::Blocked
        | HoldReason::Hooks
        | HoldReason::NameConflict
        | HoldReason::Malware
        | HoldReason::NotCheckable => false,
    };
    approved
        && record.package == candidate.package
        && reviewed_here(record)
        && snapshot_digest(project_dir, &candidate.skill).as_deref() == Some(record.digest.as_str())
}

/// Whether `record`'s copy may stay under the registry LPM uses now: an
/// LPM.dev package's copy only under the registry whose review approved it.
fn reviewed_here(record: &LinkedSkillRecord) -> bool {
    !super::plan::is_lpm_dev(&record.package)
        || record.reviewed_by.as_deref()
            == Some(crate::commands::skills::reviews::issuing_registry())
}

/// Whether the link a kept copy recorded at `target` is still there and
/// LPM's: a copy kept while its skill is held stays only where it is
/// linked, and is never linked anywhere new, not even where its link went
/// missing.
fn kept_link_intact(project_dir: &Path, target: &str, skill: &str, recorded: Recorded<'_>) -> bool {
    TargetDir::open(project_dir, target)
        .ok()
        .flatten()
        .is_some_and(|directory| {
            directory
                .inspect(project_dir, skill)
                .is_intact(recorded.kind, recorded.digest)
        })
}

/// Why a run leaves dependency-skill links alone after a newer LPM
/// recorded them.
pub(crate) fn newer_state_warning(reason: &str) -> String {
    format!("{reason}, so this LPM leaves dependency skill links alone; update LPM to manage them")
}

/// Applies `plan` to the project: writes changed copies, links them into
/// every target, removes what LPM linked earlier that the plan no longer
/// wants, keeps the links out of Git, and records the result. `stored` is
/// the state as read under the project's link lock, which the caller holds
/// from before it read the policy.
pub(crate) fn apply(
    project_dir: &Path,
    plan: &Plan,
    stored: StoredState,
    inputs: Inputs,
    _lock: &lpm_common::ExclusiveLockHandle,
) -> Result<ReconcileReport, LpmError> {
    let mut report = ReconcileReport {
        warnings: plan.problems.clone(),
        ..ReconcileReport::default()
    };
    let previous = match stored {
        StoredState::Present(state) => *state,
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
    let targets = link_targets(project_dir, plan);
    if plan.considered {
        let wanted = plan
            .policy
            .as_ref()
            .map_or(&Targets::Auto, |policy| &policy.targets);
        for target in unreachable_targets(project_dir, wanted, &targets) {
            report.warnings.push(format!(
                "{target} passes through a link, so LPM doesn't link skills into it"
            ));
        }
    }
    let (desired, held) = desired_skills(
        project_dir,
        plan,
        &previous,
        &inputs.policy,
        &targets,
        inputs.verdicts.as_ref().map(|book| Verdicts {
            book,
            checked_as: inputs.checked_as.as_deref(),
        }),
    );
    let checked_as = inputs
        .verdicts
        .is_some()
        .then_some(inputs.checked_as)
        .flatten();
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
        members: inputs.members,
        created_directories: previous.created_directories.clone(),
        recheck_at: inputs.recheck.at,
        expires_at: inputs.recheck.expires_at,
        verdicts_stamp: inputs
            .verdicts
            .as_ref()
            .and_then(super::checks::Book::stamp),
        ..LinkState::default()
    };
    let mut complete = !unreadable;
    let mut directories = TargetDirs::default();
    for (skill, wanted) in desired {
        let earlier = previous.skills.get(skill);
        let kept = matches!(wanted, Desired::Kept(_));
        let (mut record, change) = match wanted {
            Desired::Kept(record) => (record.clone(), None),
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
                        reviewed_by: super::plan::is_lpm_dev(&candidate.package).then(|| {
                            crate::commands::skills::reviews::issuing_registry().to_string()
                        }),
                        checked_as: checked_as
                            .clone()
                            .filter(|_| !super::plan::is_lpm_dev(&candidate.package)),
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
            if kept {
                if let Some(recorded) = recorded
                    && kept_link_intact(project_dir, target, skill, recorded)
                {
                    record.links.push(LinkRecord {
                        path,
                        kind: recorded.kind,
                        digest: None,
                    });
                    linked_targets.push(target.clone());
                }
                continue;
            }
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
    if plan.considered
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

/// The target folders reconciling `plan` links into: none when nothing
/// could link.
pub(crate) fn link_targets(project_dir: &Path, plan: &Plan) -> Vec<String> {
    if plan.considered {
        resolve_targets(
            project_dir,
            plan.policy
                .as_ref()
                .map_or(&Targets::Auto, |policy| &policy.targets),
        )
    } else {
        Vec::new()
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
    use super::super::plan::{Naming, PackageInstall};
    use super::*;

    fn record(permission: lpm_skill::SkillPermission) -> LinkedSkillRecord {
        LinkedSkillRecord {
            package: "tool".into(),
            version: "1.0.0".into(),
            integrity: Some("sha512-one".into()),
            digest: "sha256:copy".into(),
            permission: permission.as_str().into(),
            requires: Naming::Package,
            reviewed_by: None,
            checked_as: None,
            links: Vec::new(),
            blocked: Vec::new(),
        }
    }

    fn install(version: &str, integrity: &str, release: Option<&str>) -> PackageInstall {
        PackageInstall {
            version: version.into(),
            integrity: Some(integrity.into()),
            release: release.map(|version| ("tool".to_string(), version.to_string())),
        }
    }

    /// Verdicts: `tool@1.0.0` clean, `tool@3.0.0` flagged, `tool@2.0.0`
    /// never answered.
    fn tool_verdicts() -> super::super::checks::Book {
        let observed = |verdict| super::super::socket::Observed { verdict, at_ms: 1 };
        let mut book = super::super::checks::Book::default();
        book.absorb(&super::super::socket::Answers {
            verdicts: std::collections::HashMap::from([
                (
                    ("tool".to_string(), "1.0.0".to_string()),
                    observed(super::super::socket::Verdict::Clean),
                ),
                (
                    ("tool".to_string(), "3.0.0".to_string()),
                    observed(super::super::socket::Verdict::Malware {
                        alert: "malware".into(),
                    }),
                ),
            ]),
            failure: None,
            at_ms: 1,
        });
        book
    }

    fn installed(installs: Vec<PackageInstall>) -> Plan {
        Plan {
            installs: BTreeMap::from([("tool".to_string(), installs)]),
            ..Plan::default()
        }
    }

    #[test]
    fn a_copy_stays_beside_an_unlisted_instance_only_while_every_instance_is_checkable_and_clean() {
        let granting = record(lpm_skill::SkillPermission::Broad);
        let plain = record(lpm_skill::SkillPermission::None);
        let own = install("1.0.0", "sha512-one", Some("1.0.0"));
        let book = tool_verdicts();
        let verdicts = Verdicts {
            book: &book,
            checked_as: None,
        };
        let allows = |installs: Vec<PackageInstall>, record: &LinkedSkillRecord| {
            installed_release_allows(verdicts, &installed(installs), record)
        };

        assert!(allows(vec![own.clone()], &granting));
        assert!(
            !allows(vec![install("1.0.0", "sha512-one", None)], &granting),
            "a patched or otherwise uncheckable install keeps no copy"
        );
        assert!(!allows(vec![install("1.0.0", "sha512-one", None)], &plain));
        let newer = install("2.0.0", "sha512-two", Some("2.0.0"));
        assert!(
            !allows(vec![own.clone(), newer.clone()], &granting),
            "another installed version runs the command the copy pre-approves"
        );
        assert!(allows(vec![own.clone(), newer], &plain));
        let flagged = install("3.0.0", "sha512-three", Some("3.0.0"));
        assert!(!allows(vec![own, flagged], &plain));
        assert!(
            !installed_release_allows(verdicts, &Plan::default(), &plain),
            "a package with nothing recorded as installed keeps no copy"
        );
    }

    #[test]
    fn a_command_granting_copy_stays_only_while_every_installed_instance_has_a_clean_verdict() {
        let granting = record(lpm_skill::SkillPermission::Broad);
        let plain = record(lpm_skill::SkillPermission::None);
        let own = install("1.0.0", "sha512-one", Some("1.0.0"));
        let book = tool_verdicts();
        let verdicts = Verdicts {
            book: &book,
            checked_as: None,
        };
        let allows = |installs: Vec<PackageInstall>| {
            instances_allow_commands(verdicts, &installed(installs), &granting)
        };

        assert!(allows(vec![own.clone()]));
        assert!(!allows(vec![
            own.clone(),
            install("3.0.0", "sha512-three", Some("3.0.0"))
        ]));
        assert!(
            !allows(vec![
                own.clone(),
                install("2.0.0", "sha512-two", Some("2.0.0"))
            ]),
            "a version Socket hasn't answered for may run the command"
        );
        assert!(!allows(vec![own, install("1.0.0", "sha512-one", None)]));
        assert!(
            !instances_allow_commands(verdicts, &Plan::default(), &granting),
            "with no instance recorded, nothing vouches for what the command runs"
        );
        assert!(instances_allow_commands(verdicts, &Plan::default(), &plain));
        let mut unverified = super::super::checks::Book::default().merged_with(tool_verdicts());
        unverified.note_refresh_failed();
        assert!(
            !instances_allow_commands(
                Verdicts {
                    book: &unverified,
                    checked_as: None,
                },
                &installed(vec![install("1.0.0", "sha512-one", Some("1.0.0"))]),
                &granting
            ),
            "a verdict the shared cache couldn't be read to confirm keeps no command grant"
        );
    }

    #[test]
    fn the_releases_deciding_a_kept_copy_are_every_instance_its_verdicts_must_cover() {
        let granting = record(lpm_skill::SkillPermission::Broad);
        let plain = record(lpm_skill::SkillPermission::None);
        let own = install("1.0.0", "sha512-one", Some("1.0.0"));
        let newer = install("2.0.0", "sha512-two", Some("2.0.0"));
        let release = |version: &str| ("tool".to_string(), version.to_string());
        let both = installed(vec![own.clone(), newer]);

        assert_eq!(deciding_installs(&both, &plain, false), Some(Vec::new()));
        assert_eq!(
            deciding_installs(&both, &granting, false),
            Some(vec![release("1.0.0"), release("2.0.0")])
        );
        assert_eq!(
            deciding_installs(&both, &plain, true),
            Some(vec![release("1.0.0"), release("2.0.0")])
        );
        assert_eq!(
            deciding_installs(&both, &granting, true),
            None,
            "beside an unlisted instance, a granting copy needs every instance to be its own"
        );
        assert_eq!(
            deciding_installs(&installed(vec![own.clone()]), &granting, true),
            Some(vec![release("1.0.0")])
        );
        assert_eq!(
            deciding_installs(
                &installed(vec![own, install("1.0.0", "sha512-one", None)]),
                &granting,
                false
            ),
            None
        );
        for unlisted in [false, true] {
            assert_eq!(
                deciding_installs(&Plan::default(), &granting, unlisted),
                None,
                "no recorded instance, no verdict that could keep it"
            );
        }
        assert_eq!(
            deciding_installs(&Plan::default(), &plain, false),
            Some(Vec::new())
        );
    }

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
