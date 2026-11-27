use super::apply::{Desired, desired_skills};
use super::links::TargetDir;
use super::plan::{CandidateStatus, HoldReason, Plan, PlanMode, SkillDetails, plan_project};
use super::policy::{ParsedPolicy, Targets, policy_digest, read_policy};
use super::state::{LinkState, StoredState, read_state};
use super::{Settings, apply, snapshot, still_blocked};
use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::Path;

/// Where one skill an installed dependency ships stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkillStatus {
    /// LPM linked this version of it for agents.
    Linked,
    /// The policy allows it, and the next install or sync links it.
    Allowed,
    NotAllowed,
    Denied,
    Held(HoldReason),
}

impl SkillStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Allowed => "allowed",
            Self::NotAllowed => "not_allowed",
            Self::Denied => "denied",
            Self::Held(_) => "held",
        }
    }

    /// The status as one word, a hold's reason in place of `held`.
    pub(crate) fn detailed(self) -> &'static str {
        match self {
            Self::Held(reason) => reason.as_str(),
            other => other.as_str(),
        }
    }

    /// Whether linking the skill as the policy now stands may pre-approve
    /// what it asks for: it links, or what holds it can clear on its own.
    pub(crate) fn may_grant(self) -> bool {
        match self {
            Self::Linked | Self::Allowed => true,
            Self::Held(reason) => reason.clears_on_its_own(),
            Self::NotAllowed | Self::Denied => false,
        }
    }

    /// Whether the policy lets the skill link: now, or once what holds it
    /// clears, such as a name conflict or a problem a later version fixes.
    /// A hold for a more specific allowing entry doesn't count: the policy
    /// itself keeps that skill out.
    pub(crate) fn allowed_by_policy(self) -> bool {
        match self {
            Self::Linked | Self::Allowed => true,
            Self::Held(reason) => !matches!(
                reason,
                HoldReason::NeedsPackageName | HoldReason::NeedsSkillName
            ),
            Self::NotAllowed | Self::Denied => false,
        }
    }
}

/// What reconciling the project now would do to one skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlannedChange {
    /// Link it for the first time.
    Link,
    /// Link this version in place of the one linked now.
    Update,
    /// Keep the earlier version linked while this one is held.
    Keep,
    /// Hold it, with nothing linked.
    Hold,
    /// Remove the links LPM made for it.
    Unlink,
}

impl PlannedChange {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Update => "update",
            Self::Keep => "keep",
            Self::Hold => "hold",
            Self::Unlink => "unlink",
        }
    }
}

/// One skill an installed dependency ships, as the policy and LPM's links
/// see it.
#[derive(Debug, Clone)]
pub(crate) struct InspectedSkill {
    pub(crate) skill: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) status: SkillStatus,
    /// What reconciling would do to it; `None` when nothing changes.
    pub(crate) change: Option<PlannedChange>,
    /// Why a held skill is held, or what would keep an unallowed one from
    /// linking.
    pub(crate) detail: Option<String>,
    pub(crate) blocker: Option<HoldReason>,
    pub(crate) details: Option<SkillDetails>,
    /// The project-relative paths LPM linked it at.
    pub(crate) links: Vec<String>,
    /// A direct dependency of the project, or of the workspace member that
    /// installed it.
    pub(crate) direct: bool,
    /// Whether the policy couldn't decide it.
    pub(crate) undecided: bool,
    /// How many deny entries can't be decided for it yet.
    pub(crate) open_denials: usize,
    /// How specifically the allowing entries that hold or can't be decided
    /// yet would name it: what it may come to pre-approve.
    pub(crate) naming: super::plan::Naming,
    /// What the policy decided for every installed instance of its package.
    pub(crate) instances: Vec<super::plan::InstanceRuling>,
}

/// Every skill installed dependencies ship, with the project's policy.
#[derive(Debug, Clone)]
pub(crate) struct Inspection {
    pub(crate) allow: Vec<String>,
    pub(crate) deny: Vec<String>,
    pub(crate) targets: Vec<String>,
    pub(crate) problems: Vec<String>,
    /// The packages whose skills couldn't be listed, with why: what they
    /// ship and how the policy decides it is unknown until they can be.
    pub(crate) unlisted: Vec<(String, String)>,
    pub(crate) other_packages: bool,
    pub(crate) skills: Vec<InspectedSkill>,
}

/// Inspects `project_dir` under `manifest`'s policy. Reads and checks every
/// skill installed dependencies ship; writes nothing.
pub(crate) fn inspect_project(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
) -> Result<Inspection, LpmError> {
    inspect(project_dir, manifest, settings, None)
}

/// [`inspect_project`] for the skills `packages` ship, reading no other
/// package.
pub(crate) fn inspect_packages(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
    packages: &HashSet<String>,
) -> Result<Inspection, LpmError> {
    inspect(project_dir, manifest, settings, Some(packages))
}

fn inspect(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
    packages: Option<&HashSet<String>>,
) -> Result<Inspection, LpmError> {
    let parsed = read_policy(manifest);
    let allow = parsed
        .policy
        .as_ref()
        .map(|policy| {
            policy
                .allow
                .iter()
                .map(|entry| entry.text.clone())
                .collect()
        })
        .unwrap_or_default();
    let deny = parsed
        .policy
        .as_ref()
        .map(|policy| policy.deny.iter().map(|entry| entry.text.clone()).collect())
        .unwrap_or_default();
    let targets = apply::resolve_targets(
        project_dir,
        parsed
            .policy
            .as_ref()
            .map_or(&Targets::Auto, |policy| &policy.targets),
    );
    let policy = if settings.other_packages {
        policy_digest(parsed.policy.as_ref())
    } else {
        policy_digest(None)
    };
    let state = match read_state(project_dir) {
        StoredState::Present(state) => state,
        _ => LinkState::default(),
    };
    let plan = plan_project(
        project_dir,
        parsed,
        manifest,
        PlanMode::Inspect,
        packages,
        &state.recorded_skills(),
    )?;
    Ok(Inspection {
        allow,
        deny,
        targets,
        problems: plan.problems.clone(),
        unlisted: plan
            .unlisted
            .iter()
            .map(|(package, detail)| (package.clone(), detail.clone()))
            .collect(),
        other_packages: settings.other_packages,
        skills: inspected_skills(project_dir, &plan, &state, &policy, settings),
    })
}

fn inspected_skills(
    project_dir: &Path,
    plan: &Plan,
    state: &LinkState,
    policy: &str,
    settings: Settings,
) -> Vec<InspectedSkill> {
    let (desired, _) = if settings.other_packages {
        desired_skills(project_dir, plan, state, policy)
    } else {
        Default::default()
    };
    plan.candidates
        .iter()
        .map(|candidate| {
            let recorded = state
                .skills
                .get(&candidate.skill)
                .filter(|record| record.package == candidate.package);
            let links = recorded
                .map(|record| record.links.iter().map(|link| link.path.clone()).collect())
                .unwrap_or_default();
            let wanted = desired
                .get(candidate.skill.as_str())
                .filter(|wanted| source_of(wanted).0 == candidate.package);
            let change = match (wanted, recorded) {
                (Some(Desired::Kept(_)), _) => Some(PlannedChange::Keep),
                (Some(wanted), Some(record)) if record.digest == digest_of(wanted) => None,
                (Some(_), Some(_)) => Some(PlannedChange::Update),
                (Some(_), None) => Some(PlannedChange::Link),
                (None, Some(_)) => Some(PlannedChange::Unlink),
                (None, None) if matches!(candidate.status, CandidateStatus::Held { .. }) => {
                    Some(PlannedChange::Hold)
                }
                (None, None) => None,
            };
            let (status, detail) = match &candidate.status {
                CandidateStatus::Linkable(prepared) => {
                    let current = recorded.is_some_and(|record| {
                        record.version == candidate.version
                            && record.digest == prepared.checked.digest
                    });
                    (
                        if current {
                            SkillStatus::Linked
                        } else {
                            SkillStatus::Allowed
                        },
                        None,
                    )
                }
                CandidateStatus::NotAllowed => (SkillStatus::NotAllowed, None),
                CandidateStatus::Denied => (SkillStatus::Denied, None),
                CandidateStatus::Held { reason, detail } => {
                    (SkillStatus::Held(*reason), Some(detail.clone()))
                }
            };
            let (blocker, detail) = match (&candidate.blocker, detail) {
                (Some((reason, blocker_detail)), None) => {
                    (Some(*reason), Some(blocker_detail.clone()))
                }
                (_, detail) => (None, detail),
            };
            InspectedSkill {
                skill: candidate.skill.clone(),
                package: candidate.package.clone(),
                version: candidate.version.clone(),
                status,
                change,
                detail,
                blocker,
                details: candidate.details.clone(),
                links,
                direct: candidate.direct,
                undecided: candidate.undecided,
                open_denials: candidate.open_denials,
                naming: candidate.possible_naming,
                instances: candidate.instances.clone(),
            }
        })
        .collect()
}

/// The digest of the files a desired skill links.
fn digest_of<'a>(wanted: &'a Desired<'_>) -> &'a str {
    match wanted {
        Desired::Fresh(_, prepared) => &prepared.checked.digest,
        Desired::Kept(record) => &record.digest,
    }
}

/// The package and version a desired skill links from.
fn source_of<'a>(wanted: &'a Desired<'_>) -> (&'a str, &'a str) {
    match wanted {
        Desired::Fresh(candidate, _) => (&candidate.package, &candidate.version),
        Desired::Kept(record) => (&record.package, &record.version),
    }
}

/// What differs between the project's links and what its policy links now,
/// one line per difference; empty when they match. A target entry that
/// something else still holds is no difference: syncing leaves it alone.
pub(crate) fn drift(project_dir: &Path, settings: Settings) -> Result<Vec<String>, LpmError> {
    let manifest = match super::plan::read_manifest(project_dir) {
        Ok(manifest) => manifest,
        Err(_) if !super::state::state_exists(project_dir) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let parsed = if settings.other_packages {
        read_policy(&manifest)
    } else {
        ParsedPolicy::default()
    };
    let state = match read_state(project_dir) {
        StoredState::Present(state) => state,
        StoredState::Missing => LinkState::default(),
        StoredState::Unusable(reason) => return Ok(vec![reason]),
        StoredState::Newer(reason) => return Ok(vec![apply::newer_state_warning(&reason)]),
    };
    let policy = policy_digest(parsed.policy.as_ref());
    let plan = plan_project(
        project_dir,
        parsed,
        &manifest,
        PlanMode::Apply,
        None,
        &state.recorded_skills(),
    )?;
    let targets = plan
        .policy
        .as_ref()
        .filter(|policy| policy.is_active())
        .map(|policy| apply::resolve_targets(project_dir, &policy.targets))
        .unwrap_or_default();
    let (desired, _) = desired_skills(project_dir, &plan, &state, &policy);
    let mut differences = Vec::new();
    for (skill, wanted) in &desired {
        let (package, version) = source_of(wanted);
        let Some(record) = state.skills.get(*skill) else {
            differences.push(format!("{skill} from {package}@{version} is not linked"));
            continue;
        };
        if record.digest != digest_of(wanted) || record.package != package {
            differences.push(format!(
                "{skill} is linked from {}@{}, not {package}@{version}",
                record.package, record.version
            ));
            continue;
        }
        if snapshot::snapshot_digest(project_dir, skill).as_deref() != Some(record.digest.as_str())
        {
            differences.push(format!("LPM's copy of {skill} is missing or changed"));
        }
        for target in &targets {
            let path = format!("{target}/{skill}");
            if record.blocked.contains(&path) {
                if !still_blocked(project_dir, skill, &path) {
                    differences.push(format!(
                        "{path} is free now, and {skill} isn't linked there yet"
                    ));
                }
                continue;
            }
            let intact = record
                .links
                .iter()
                .find(|link| link.path == path)
                .is_some_and(|link| {
                    TargetDir::open(project_dir, target)
                        .ok()
                        .flatten()
                        .is_some_and(|directory| {
                            directory
                                .inspect(project_dir, skill)
                                .is_intact(link.kind, &record.digest)
                        })
                });
            if !intact {
                differences.push(format!("{path} is missing or isn't LPM's link"));
            }
        }
        for link in &record.links {
            let targeted = link
                .path
                .rsplit_once('/')
                .is_some_and(|(target, _)| targets.iter().any(|wanted| wanted == target));
            if !targeted {
                differences.push(format!(
                    "{} links {skill} in a folder that is no longer a target",
                    link.path
                ));
            }
        }
    }
    for (skill, record) in &state.skills {
        if !desired.contains_key(skill.as_str()) {
            differences.push(format!(
                "{skill} from {}@{} is linked but the policy no longer links it",
                record.package, record.version
            ));
        }
    }
    for (skill, links) in &state.stale {
        for link in links {
            differences.push(format!("{} for {skill} couldn't be removed yet", link.path));
        }
    }
    Ok(differences)
}
