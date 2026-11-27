use super::discovery::{read_skill_directory, skill_directory_listing};
use super::policy::{ParsedPolicy, SkillsPolicy};
use crate::commands::audit::discovery::{DiscoveredPackage, ManagerKind};
use crate::commands::audit::inventory::PackageInventory;
use lpm_common::LpmError;
use lpm_security::query::{
    DepGraph, DepGraphEntry, PackageContext, PseudoClass, Selector, Truth, evaluate_with_key,
};
use lpm_skill::{CheckedSkill, SkillDirectoryEntry, SkillPermission, check_skill_directory};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

/// Why an allowed skill isn't linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldReason {
    /// A selector reads data the package lacks, such as a behavioral
    /// analysis or a security verdict, so the policy can't be decided.
    NeedsData,
    /// The skill directory breaks a structural rule.
    Invalid,
    /// The security scan found a blocking pattern.
    Blocked,
    /// The skill has scan warnings, and no allowing entry names its
    /// package.
    NeedsPackageName,
    /// The skill pre-approves tools or commands, and no allowing entry names
    /// the skill.
    NeedsSkillName,
    /// The skill declares hooks, which are never linked.
    Hooks,
    /// Another allowed package ships a skill with the same name.
    NameConflict,
    /// The skill directory couldn't be read.
    Unreadable,
}

impl HoldReason {
    /// Whether the hold can clear without a new version of the package or
    /// a change to the policy: data arriving, a conflict ending, a folder
    /// becoming readable.
    pub(crate) fn clears_on_its_own(self) -> bool {
        match self {
            Self::NeedsData | Self::NameConflict | Self::Unreadable => true,
            Self::Invalid
            | Self::Blocked
            | Self::NeedsPackageName
            | Self::NeedsSkillName
            | Self::Hooks => false,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NeedsData => "needs_data",
            Self::Invalid => "invalid",
            Self::Blocked => "blocked",
            Self::NeedsPackageName => "needs_package_name",
            Self::NeedsSkillName => "needs_skill_name",
            Self::Hooks => "hooks",
            Self::NameConflict => "name_conflict",
            Self::Unreadable => "unreadable",
        }
    }
}

/// A skill ready to link: the bytes it was checked as, and what the check
/// found.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) entries: Vec<SkillDirectoryEntry>,
    pub(crate) checked: CheckedSkill,
    pub(crate) permission: SkillPermission,
    /// How specifically an allowing entry must name the skill to link it.
    pub(crate) requires: Naming,
}

#[derive(Debug)]
pub(crate) enum CandidateStatus {
    Linkable(Box<Prepared>),
    /// No allowing entry matches.
    NotAllowed,
    /// A deny entry matches.
    Denied,
    Held {
        reason: HoldReason,
        detail: String,
    },
}

/// One skill one installed package ships, and what the policy makes of it.
#[derive(Debug)]
pub(crate) struct Candidate {
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) integrity: Option<String>,
    pub(crate) skill: String,
    pub(crate) status: CandidateStatus,
    /// How specifically the allowing entries that hold name it: what keeps
    /// an earlier copy under a changed policy.
    pub(crate) naming: Naming,
    /// How specifically the allowing entries that hold or can't be decided
    /// yet would name it: what the skill may come to pre-approve.
    pub(crate) possible_naming: Naming,
    /// Whether the policy couldn't decide the skill, as when a selector
    /// reads data the package lacks.
    pub(crate) undecided: bool,
    /// How many deny entries can't be decided for the skill yet: each may
    /// deny it once the data it reads arrives.
    pub(crate) open_denials: usize,
    /// What the policy decided for every installed instance of the skill's
    /// package, this one included, by version.
    pub(crate) instances: Vec<InstanceRuling>,
    /// What the skill's check found, when it was checked: always for an
    /// allowed skill, and for every skill when inspecting.
    pub(crate) details: Option<SkillDetails>,
    /// When inspecting a skill the policy doesn't allow, the problem that
    /// would keep it from linking even if it did.
    pub(crate) blocker: Option<(HoldReason, String)>,
    /// A direct dependency of the project, or of the workspace member that
    /// installed it.
    pub(crate) direct: bool,
}

/// What a skill's check found.
#[derive(Debug, Clone)]
pub(crate) struct SkillDetails {
    pub(crate) description: String,
    pub(crate) hidden: bool,
    pub(crate) allowed_tools: Vec<String>,
    pub(crate) permission: SkillPermission,
    pub(crate) warnings: usize,
    /// The narrowest allowing entry that links the skill.
    pub(crate) suggested: String,
    /// How specifically an allowing entry must name the skill to link it.
    pub(crate) requires: Naming,
}

/// Whether a plan links skills or only reports on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanMode {
    /// Plan what the policy links; with no allowing entry, read nothing.
    Apply,
    /// Check every skill installed dependencies ship, allowed or not.
    Inspect,
}

/// What the project's policy makes of every skill its installed
/// dependencies ship. Planning reads and never writes.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub(crate) policy: Option<SkillsPolicy>,
    pub(crate) problems: Vec<String>,
    pub(crate) candidates: Vec<Candidate>,
    /// Packages whose `skills` folder couldn't be listed, with why. What
    /// they linked earlier stays while the policy is unchanged, and the
    /// next run tries again.
    pub(crate) unlisted: BTreeMap<String, String>,
    /// For each package among [`Self::unlisted`], the skills earlier links
    /// recorded that the policy could still allow from one of its unlisted
    /// instances, named as specifically as each needs: only their copies may
    /// stay.
    pub(crate) unlisted_allows: BTreeMap<String, BTreeSet<String>>,
    /// Whether a selector looked at a package the plan couldn't settle now,
    /// such as a parent whose install can't be confirmed, so the next run
    /// plans again.
    pub(crate) incomplete: bool,
}

/// What the policy decided for one installed instance of a package's skill.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InstanceRuling {
    pub(crate) version: String,
    /// `allowed`, `undecided`, `denied` or `not_allowed`.
    pub(crate) ruling: &'static str,
    pub(crate) open_denials: usize,
    /// Whether it links now or may once data arrives: the policy allows it
    /// or can't decide yet, nothing in it keeps it out, and the entries that
    /// may allow it name it as specifically as it needs.
    pub(crate) may_link: bool,
}

/// How much an allowing entry singles a candidate out.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Naming {
    None,
    Package,
    Skill,
}

pub(crate) fn read_manifest(project_dir: &Path) -> Result<serde_json::Value, LpmError> {
    let path = project_dir.join("package.json");
    let content = lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
    serde_json::from_str(lpm_common::strip_utf8_bom_str(&content))
        .map_err(|error| LpmError::Registry(format!("invalid {}: {error}", path.display())))
}

/// The skills earlier links recorded, by package, with how specifically an
/// entry had to name each: what a plan judges for a package whose skills
/// couldn't be listed.
pub(crate) type RecordedSkills = BTreeMap<String, Vec<(String, Naming)>>;

/// Plans `project_dir`'s dependency skills under `policy`. In a workspace
/// root the plan covers the root and every member. With no allowing entry,
/// nothing is read. `packages` limits the plan to the skills those
/// packages ship.
pub(crate) fn plan_project(
    project_dir: &Path,
    parsed: ParsedPolicy,
    manifest: &serde_json::Value,
    mode: PlanMode,
    packages: Option<&HashSet<String>>,
    recorded: &RecordedSkills,
) -> Result<Plan, LpmError> {
    let ParsedPolicy { policy, problems } = parsed;
    let mut plan = Plan {
        policy,
        problems,
        ..Plan::default()
    };
    let empty = SkillsPolicy {
        allow: Vec::new(),
        deny: Vec::new(),
        targets: super::policy::Targets::Auto,
        deny_unreadable: false,
    };
    let policy = match plan.policy.as_ref() {
        Some(policy) if policy.is_active() => policy,
        _ if mode == PlanMode::Inspect => plan.policy.as_ref().unwrap_or(&empty),
        _ => return Ok(plan),
    };
    let needs_analysis = policy
        .allow
        .iter()
        .chain(&policy.deny)
        .any(|entry| uses_behavioral_tags(&entry.selector));

    let mut importers = vec![(project_dir.to_path_buf(), root_dependency_names(manifest))];
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir)
        && same_directory(&workspace.root, project_dir)
    {
        for member in workspace.members {
            let member_manifest = read_manifest(&member.path).ok();
            if member_manifest
                .as_ref()
                .is_some_and(|manifest| manifest.pointer("/lpm/skills").is_some())
            {
                plan.problems
                    .push(member_policy_problem(project_dir, &member.path));
            }
            let names = member_manifest
                .map(|manifest| root_dependency_names(&manifest))
                .unwrap_or_default();
            importers.push((member.path, names));
        }
    }
    let mut discoveries = Vec::with_capacity(importers.len());
    for (directory, names) in importers {
        let discovery = match PackageInventory::discover_within(&directory, project_dir) {
            Ok(discovery) => discovery,
            Err(LpmError::NotFound(_)) => {
                crate::commands::audit::discovery::DiscoveryResult::nothing_installed(directory)
            }
            Err(error) => return Err(error),
        };
        discoveries.push((discovery, names));
    }
    let named = match (packages, mode) {
        (Some(packages), _) => Some(packages.clone()),
        (None, PlanMode::Apply) => named_packages(policy),
        (None, PlanMode::Inspect) => None,
    };
    let is_lpm_project = discoveries
        .iter()
        .any(|(discovery, _)| discovery.manager == ManagerKind::Lpm);
    let build = |lpm_root: Option<&lpm_common::LpmRoot>| -> Result<Found, LpmError> {
        let store_version = lpm_store::StoreVersion::from_env();
        let importers: Vec<Importer> = discoveries
            .into_iter()
            .map(|(discovery, root_dependency_names)| {
                let is_lpm = discovery.manager == ManagerKind::Lpm;
                let named = named.as_ref();
                let mut inventory = PackageInventory::from_discovery_with_options(
                    discovery,
                    store_version,
                    lpm_root,
                    needs_analysis,
                );
                inventory.retain_installed();
                inventory.retain_packages(|package| {
                    package.installed
                        != Some(crate::commands::audit::discovery::Installation::Absent)
                });
                Importer {
                    inventory,
                    is_lpm,
                    root_dependency_names,
                    named: named.cloned(),
                }
            })
            .collect();
        Ok(candidates_from_importers(
            &importers,
            lpm_root,
            Rules { policy, recorded },
            mode,
        ))
    };
    let found = if is_lpm_project {
        let lpm_root = lpm_common::LpmRoot::from_env()?;
        let lock = lpm_root.store_lock();
        lpm_common::with_shared_lock(lock, || build(Some(&lpm_root)))?
    } else {
        build(None)?
    };
    plan.candidates = found.candidates;
    plan.unlisted = found.unlisted;
    plan.unlisted_allows = found.unlisted_allows;
    plan.problems.extend(found.problems);
    plan.incomplete = found.incomplete;
    Ok(plan)
}

fn same_directory(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn member_policy_problem(project_dir: &Path, member: &Path) -> String {
    let relative = member.strip_prefix(project_dir).unwrap_or(member);
    let mut shown = relative.to_string_lossy().replace('\\', "/");
    if !shown.is_empty() {
        shown.push('/');
    }
    format!(
        "{shown}package.json sets `lpm.skills`, but only the workspace root's policy applies; move its entries to the root package.json"
    )
}

/// The names of the only packages the policy can allow, when every
/// allowing entry names its packages with `#name` and no entry reads the
/// skills another package ships; `None` otherwise. Packages outside the set
/// need no reading.
pub(crate) fn named_packages(policy: &SkillsPolicy) -> Option<HashSet<String>> {
    if policy
        .allow
        .iter()
        .chain(&policy.deny)
        .any(|entry| reads_parent_skills(&entry.selector))
    {
        return None;
    }
    let mut names = HashSet::new();
    for entry in &policy.allow {
        names.extend(selector_names(&entry.selector)?);
    }
    Some(names)
}

/// Whether deciding `selector` for a package looks at its parents other
/// than the root: a `parent > child` whose parent is anything but `:root`
/// or `:workspace-root`.
fn reads_parents(selector: &Selector) -> bool {
    match selector {
        Selector::DirectChild { parent, child } => {
            !matches!(
                parent.as_ref(),
                Selector::PseudoClass(PseudoClass::Root | PseudoClass::WorkspaceRoot)
            ) || reads_parents(child)
        }
        Selector::And(parts) | Selector::Or(parts) => parts.iter().any(reads_parents),
        Selector::Not(inner) => reads_parents(inner),
        Selector::Id(_) | Selector::PseudoClass(_) | Selector::Skill(_) => false,
    }
}

/// Whether deciding `selector` for a package reads the skills other
/// packages ship: a `parent > child` whose parent tests `:skills` or
/// `:skill()`.
fn reads_parent_skills(selector: &Selector) -> bool {
    match selector {
        Selector::DirectChild { parent, child } => {
            parent.uses_skills() || reads_parent_skills(child)
        }
        Selector::And(parts) | Selector::Or(parts) => parts.iter().any(reads_parent_skills),
        Selector::Not(inner) => reads_parent_skills(inner),
        Selector::Id(_) | Selector::PseudoClass(_) | Selector::Skill(_) => false,
    }
}

/// Whether `selector` may match one of `packages`: it names one of them,
/// or it doesn't limit the packages it matches.
pub(crate) fn may_match_any(selector: &str, packages: &[(String, String)]) -> bool {
    if packages.is_empty() {
        return false;
    }
    let Ok(selector) = lpm_security::query::parse_selector(selector) else {
        return false;
    };
    selector_names(&selector)
        .is_none_or(|names| packages.iter().any(|(package, _)| names.contains(package)))
}

/// The package names `selector` can match, when it limits them.
fn selector_names(selector: &Selector) -> Option<HashSet<String>> {
    match selector {
        Selector::Id(id) => Some(HashSet::from([bare_id(id).to_string()])),
        Selector::And(parts) => parts
            .iter()
            .filter_map(selector_names)
            .reduce(|left, right| left.intersection(&right).cloned().collect()),
        Selector::Or(parts) => {
            let mut names = HashSet::new();
            for part in parts {
                names.extend(selector_names(part)?);
            }
            Some(names)
        }
        Selector::DirectChild { child, .. } => selector_names(child),
        Selector::Not(_) | Selector::PseudoClass(_) | Selector::Skill(_) => None,
    }
}

/// One project whose installed packages the plan reads: a standalone
/// project, or the root or a member of a workspace.
struct Importer {
    inventory: PackageInventory,
    is_lpm: bool,
    root_dependency_names: HashSet<String>,
    /// The only packages the policy can allow, when it names them.
    named: Option<HashSet<String>>,
}

impl Importer {
    fn open(
        &self,
        package: &DiscoveredPackage,
        project_root: Option<&cap_std::fs::Dir>,
        lpm_root: Option<&lpm_common::LpmRoot>,
    ) -> std::io::Result<cap_std::fs::Dir> {
        crate::commands::audit::inventory::open_package_pristine_directory(
            project_root,
            package,
            lpm_root,
            self.inventory.baseline_index.as_ref(),
        )
    }

    /// Whether [`Self::open`] opens packages in the project, as a manager
    /// other than LPM laid them out, rather than the store's copies.
    fn opens_in_project(&self) -> bool {
        self.inventory.baseline_index.is_none()
    }
}

/// Whether opening `package`'s folder failed because nothing LPM reads is
/// there: no folder, something else in its place, or, for a folder opened
/// in the project (`in_project`), a link LPM never follows. Any other
/// failure, such as a permission error on the store's copy or running out
/// of file handles, may pass, so the package counts as unreadable and
/// keeps what it linked.
fn is_absent(
    error: &std::io::Error,
    project_root: Option<&cap_std::fs::Dir>,
    package: &DiscoveredPackage,
    in_project: bool,
) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) || (in_project
        && project_root.is_some_and(|root| {
            root.symlink_metadata(&package.path)
                .is_ok_and(|metadata| crate::project_fs::is_link(&metadata))
        }))
}

/// A policy decision about one skill of one installed package.
struct Decided {
    importer: usize,
    package: usize,
    skill: String,
    decision: Decision,
    /// How many deny entries can't be decided for the skill yet.
    open_denials: usize,
    /// How specifically the entries that may allow the skill would name it.
    possible_naming: Naming,
    /// A direct dependency of its importer.
    direct: bool,
}

/// The skills the importers' installed packages ship, and the packages
/// whose skills couldn't be listed, with why.
#[derive(Default)]
struct Found {
    candidates: Vec<Candidate>,
    unlisted: BTreeMap<String, String>,
    unlisted_allows: BTreeMap<String, BTreeSet<String>>,
    /// Packages whose skills break a rule the same way every run.
    problems: Vec<String>,
    incomplete: bool,
}

/// What a plan decides by: the policy, and the skills earlier links
/// recorded.
#[derive(Clone, Copy)]
struct Rules<'a> {
    policy: &'a SkillsPolicy,
    recorded: &'a RecordedSkills,
}

/// Every policy decision across the importers, in the order made.
#[derive(Default)]
struct Decisions {
    decided: Vec<Decided>,
    unlisted: BTreeMap<String, String>,
    unlisted_allows: BTreeMap<String, BTreeSet<String>>,
    /// The packages, as `name@version`, whose installs can't be confirmed
    /// and that a candidate or an unlisted package reaches through its
    /// parents, when the policy looks at parents.
    unconfirmed: BTreeSet<String>,
    problems: Vec<String>,
    incomplete: bool,
}

fn candidates_from_importers(
    importers: &[Importer],
    lpm_root: Option<&lpm_common::LpmRoot>,
    rules: Rules<'_>,
    mode: PlanMode,
) -> Found {
    let project_roots: Vec<Option<cap_std::fs::Dir>> = importers
        .iter()
        .map(|importer| {
            crate::commands::audit::inventory::open_project_root(
                &importer.inventory.discovery.project_root,
            )
            .ok()
        })
        .collect();
    let root = RootDependencies::of(importers.first());
    let mut decisions = Decisions::default();
    let mut directories = Vec::with_capacity(importers.len());
    for (index, importer) in importers.iter().enumerate() {
        directories.push(decide_importer(
            importer,
            index,
            project_roots[index].as_ref(),
            lpm_root,
            rules,
            &root,
            &mut decisions,
        ));
    }
    if let Some(problem) = unconfirmed_parents(&decisions.unconfirmed) {
        decisions.incomplete = true;
        decisions.problems.push(problem);
    }
    let Decisions {
        decided,
        unlisted,
        unlisted_allows,
        problems,
        incomplete,
        ..
    } = decisions;
    if decided.is_empty() {
        return Found {
            candidates: Vec::new(),
            unlisted,
            unlisted_allows,
            problems,
            incomplete,
        };
    }

    let package_of =
        |entry: &Decided| &importers[entry.importer].inventory.discovery.packages[entry.package];
    let preferred = preferred_instances(&decided, &package_of);
    let conflicts = name_conflicts(&decided, &preferred, &package_of);
    let mut rulings: HashMap<(&str, String), Vec<InstanceRuling>> = HashMap::new();
    let mut inspected: Vec<Option<(CandidateStatus, Option<SkillDetails>)>> = Vec::new();
    if mode == PlanMode::Inspect {
        inspected.reserve_exact(decided.len());
        for (position, entry) in decided.iter().enumerate() {
            let package = package_of(entry);
            let directory = directories[entry.importer][entry.package]
                .as_ref()
                .ok_or_else(|| LpmError::Registry(format!("{} could not be opened", package.name)));
            let (status, details) = prepare_fully(directory, package, &entry.skill);
            let may_link = matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown)
                && match &status {
                    CandidateStatus::Linkable(_) => true,
                    CandidateStatus::Held { reason, .. } => reason.clears_on_its_own(),
                    CandidateStatus::NotAllowed | CandidateStatus::Denied => false,
                }
                && details
                    .as_ref()
                    .is_none_or(|details| details.requires <= entry.possible_naming);
            rulings
                .entry((package.name.as_str(), entry.skill.clone()))
                .or_default()
                .push(InstanceRuling {
                    version: package.version.clone(),
                    ruling: entry.decision.kind(),
                    open_denials: entry.open_denials,
                    may_link,
                });
            inspected.push(preferred.contains(&position).then_some((status, details)));
        }
        for instances in rulings.values_mut() {
            instances.sort();
        }
    }

    let mut candidates = Vec::with_capacity(preferred.len());
    for (position, entry) in decided.into_iter().enumerate() {
        if !preferred.contains(&position) {
            continue;
        }
        let package = package_of(&entry);
        let skill = entry.skill;
        let instances = rulings
            .remove(&(package.name.as_str(), skill.clone()))
            .unwrap_or_default();
        let directory = directories[entry.importer][entry.package].as_ref();
        let check = |naming: Naming| {
            let directory = directory
                .ok_or_else(|| LpmError::Registry(format!("{} could not be opened", package.name)));
            prepare(directory, package, &skill, naming)
        };
        let full = inspected.get_mut(position).and_then(Option::take);
        let inspect =
            |status: CandidateStatus, full: Option<(CandidateStatus, Option<SkillDetails>)>| {
                match full {
                    Some((checked, details)) => {
                        let blocker = match checked {
                            CandidateStatus::Held { reason, detail } => Some((reason, detail)),
                            _ => None,
                        };
                        (status, details, blocker)
                    }
                    None => (status, None, None),
                }
            };
        let (status, details, blocker) = match entry.decision {
            Decision::NotAllowed => inspect(CandidateStatus::NotAllowed, full),
            Decision::Denied => inspect(CandidateStatus::Denied, full),
            Decision::Allowed(_) | Decision::Unknown if conflicts.contains_key(&skill) => inspect(
                held(
                    HoldReason::NameConflict,
                    format!(
                        "{} also ship a skill named `{skill}`; name one with `#<package>:skill({skill})` and deny the others",
                        conflicts[&skill]
                            .iter()
                            .filter(|name| **name != package.name)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                full,
            ),
            Decision::Unknown => inspect(held(HoldReason::NeedsData, UNDECIDED), full),
            Decision::Allowed(naming) => {
                let (status, details) = match full {
                    Some((status, details)) => {
                        (require_naming(status, details.as_ref(), naming), details)
                    }
                    None => check(naming),
                };
                match (&status, &details) {
                    (
                        CandidateStatus::Held {
                            reason: HoldReason::NeedsPackageName | HoldReason::NeedsSkillName,
                            ..
                        },
                        Some(found),
                    ) if found.requires <= entry.possible_naming => {
                        (held(HoldReason::NeedsData, UNDECIDED_NAMING), details, None)
                    }
                    _ => (status, details, None),
                }
            }
        };
        candidates.push(Candidate {
            package: package.name.clone(),
            version: package.version.clone(),
            integrity: package.integrity.clone(),
            skill,
            status,
            naming: match entry.decision {
                Decision::Allowed(naming) => naming,
                _ => Naming::None,
            },
            possible_naming: match entry.decision {
                Decision::Allowed(naming) => naming.max(entry.possible_naming),
                Decision::Unknown => entry.possible_naming,
                _ => Naming::None,
            },
            undecided: entry.decision == Decision::Unknown,
            open_denials: entry.open_denials,
            instances,
            details,
            blocker,
            direct: entry.direct,
        });
    }
    candidates.sort_by(|left, right| {
        left.skill
            .cmp(&right.skill)
            .then_with(|| left.package.cmp(&right.package))
    });
    Found {
        candidates,
        unlisted,
        unlisted_allows,
        problems,
        incomplete,
    }
}

/// The workspace root's direct dependencies, which `:workspace-root >`
/// selects in every importer: by graph instance, or by name at the top of
/// `node_modules` where the lockfile has no instances.
#[derive(Default)]
struct RootDependencies {
    instances: HashSet<lpm_common::PackageInstanceId>,
    names: HashSet<String>,
}

impl RootDependencies {
    fn of(root: Option<&Importer>) -> Self {
        let Some(root) = root else {
            return Self::default();
        };
        Self {
            instances: root
                .inventory
                .discovery
                .retained_lpm_lockfile()
                .map(|lockfile| {
                    lockfile
                        .root_resolutions
                        .values()
                        .filter_map(|resolution| resolution.instance_id)
                        .collect()
                })
                .unwrap_or_default(),
            names: root.root_dependency_names.clone(),
        }
    }

    fn selects(&self, package: &DiscoveredPackage) -> bool {
        match package.instance_id {
            Some(instance) => self.instances.contains(&instance),
            None => {
                self.names.contains(&package.name)
                    && package.path.strip_prefix("node_modules/") == Some(package.name.as_str())
            }
        }
    }
}

/// The problem naming the packages whose installs can't be confirmed that
/// a selector would look at as parents, if there are any: such a selector
/// stays undecided until they can be.
fn unconfirmed_parents(unconfirmed: &BTreeSet<String>) -> Option<String> {
    const SHOWN: usize = 5;
    if unconfirmed.is_empty() {
        return None;
    }
    let mut listed = unconfirmed
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if unconfirmed.len() > SHOWN {
        listed.push_str(&format!(" and {} more", unconfirmed.len() - SHOWN));
    }
    Some(format!(
        "LPM couldn't confirm the installs of {listed}, so selectors that look at them as parents stay undecided until it can"
    ))
}

/// The packages, as `name@version`, whose installs can't be confirmed among
/// the ancestors of `from` in `graph`, by graph key.
fn uncertain_ancestors<'a>(
    graph: &DepGraph<'a>,
    from: impl IntoIterator<Item = &'a str>,
    packages: &HashMap<&str, &DiscoveredPackage>,
) -> Vec<String> {
    let mut stack: Vec<&str> = from.into_iter().collect();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut found = Vec::new();
    while let Some(key) = stack.pop() {
        for parent in graph.parents.get(key).into_iter().flatten() {
            if !seen.insert(parent) {
                continue;
            }
            stack.push(parent);
            if let Some(package) = packages.get(parent)
                && package.installed
                    == Some(crate::commands::audit::discovery::Installation::Unknown)
            {
                found.push(format!("{}@{}", package.name, package.version));
            }
        }
    }
    found
}

/// Decides every skill one importer's installed packages ship, against that
/// importer's dependency graph. Returns the directory of each package that
/// ships skills, opened once for reading them.
fn decide_importer(
    importer: &Importer,
    importer_index: usize,
    project_root: Option<&cap_std::fs::Dir>,
    lpm_root: Option<&lpm_common::LpmRoot>,
    rules: Rules<'_>,
    root: &RootDependencies,
    decisions: &mut Decisions,
) -> Vec<Option<cap_std::fs::Dir>> {
    use rayon::prelude::*;

    let Rules { policy, recorded } = rules;

    let inventory = &importer.inventory;
    let packages = &inventory.discovery.packages;
    let listed: Vec<Listed> = packages
        .par_iter()
        .map(|package| {
            if importer
                .named
                .as_ref()
                .is_some_and(|named| !named.contains(&package.name))
            {
                return Listed::Unread;
            }
            let uncertain =
                package.installed == Some(crate::commands::audit::discovery::Installation::Unknown);
            let directory = match importer.open(package, project_root, lpm_root) {
                Ok(directory) => directory,
                Err(error)
                    if is_absent(&error, project_root, package, importer.opens_in_project()) =>
                {
                    return if uncertain {
                        Listed::Uncertain {
                            ships_skills: false,
                        }
                    } else {
                        Listed::Nothing
                    };
                }
                Err(error) => return Listed::Failed(error),
            };
            match skill_directory_listing(&directory) {
                Ok(listing) if uncertain => Listed::Uncertain {
                    ships_skills: !listing.names.is_empty(),
                },
                Ok(listing) if !listing.names.is_empty() => Listed::Skills {
                    directory,
                    names: listing.names,
                    unconfirmed: listing.unconfirmed,
                },
                Ok(_) => Listed::Nothing,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    Listed::Refused(error)
                }
                Err(error) => Listed::Failed(error),
            }
        })
        .collect();
    let mut directories = Vec::with_capacity(listed.len());
    let mut skill_names = Vec::with_capacity(listed.len());
    let mut shipped = Vec::with_capacity(listed.len());
    let mut unlisted = Vec::new();
    for (index, (package, listed)) in packages.iter().zip(listed).enumerate() {
        if matches!(
            listed,
            Listed::Uncertain { ships_skills: true } | Listed::Failed(_)
        ) {
            unlisted.push(index);
        }
        let (directory, names, facts) = match listed {
            Listed::Skills {
                directory,
                names,
                unconfirmed,
            } => {
                if unconfirmed {
                    decisions.incomplete = true;
                }
                let facts = if unconfirmed {
                    Shipped::Unknown
                } else {
                    Shipped::Listed
                };
                (Some(directory), names, facts)
            }
            Listed::Nothing => (None, Vec::new(), Shipped::Listed),
            Listed::Unread => (None, Vec::new(), Shipped::Unknown),
            Listed::Uncertain { ships_skills } => {
                if ships_skills {
                    decisions
                        .unlisted
                        .entry(package.name.clone())
                        .or_insert_with(|| UNCERTAIN_INSTALL.to_string());
                }
                (None, Vec::new(), Shipped::Unknown)
            }
            Listed::Failed(error) => {
                decisions
                    .unlisted
                    .entry(package.name.clone())
                    .or_insert_with(|| format!("its skills folder could not be read: {error}"));
                (None, Vec::new(), Shipped::Unknown)
            }
            Listed::Refused(error) => {
                let problem = format!(
                    "{}@{}: {error}, so none of its skills are linked",
                    package.name, package.version
                );
                if !decisions.problems.contains(&problem) {
                    decisions.problems.push(problem);
                }
                (None, Vec::new(), Shipped::Unknown)
            }
        };
        directories.push(directory);
        skill_names.push(names);
        shipped.push(facts);
    }
    if skill_names.iter().all(Vec::is_empty) && unlisted.is_empty() {
        return directories;
    }

    let graph_key_storage: Vec<String> = if importer.is_lpm {
        packages
            .iter()
            .map(DiscoveredPackage::analysis_key)
            .collect()
    } else {
        packages
            .iter()
            .map(|package| package.path.clone())
            .collect()
    };
    let graph_keys: Vec<&str> = graph_key_storage.iter().map(String::as_str).collect();
    let entries: Vec<DepGraphEntry<'_>>;
    let mut graph = if let Some(lockfile) = inventory.discovery.retained_lpm_lockfile() {
        DepGraph::from_lpm_instances(&lockfile.packages, &graph_keys, &lockfile.root_resolutions)
    } else {
        entries = packages
            .iter()
            .map(|package| DepGraphEntry {
                name: &package.name,
                version: &package.version,
                path: &package.path,
                dependencies: &package.dependencies,
            })
            .collect();
        DepGraph::from_instances(&entries, &importer.root_dependency_names)
    };
    graph.set_workspace_root_deps(
        graph_keys
            .iter()
            .zip(packages)
            .filter(|(_, package)| root.selects(package))
            .map(|(key, _)| *key)
            .collect(),
    );
    graph.set_uncertain_installs(
        graph_keys
            .iter()
            .zip(packages)
            .filter(|(_, package)| {
                package.installed == Some(crate::commands::audit::discovery::Installation::Unknown)
            })
            .map(|(key, _)| *key)
            .collect(),
    );

    let contexts: Vec<PackageContext<'_>> = packages
        .iter()
        .enumerate()
        .map(|(index, package)| PackageContext {
            name: &package.name,
            version: &package.version,
            path: &package.path,
            analysis: inventory
                .analyses
                .get(index)
                .and_then(|analysis| analysis.as_deref()),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
            skills: match &shipped[index] {
                Shipped::Listed => Some(&skill_names[index]),
                Shipped::Unknown => None,
            },
            skill: None,
            malware: None,
        })
        .collect();
    let all_packages: HashMap<&str, PackageContext<'_>> = graph_keys
        .iter()
        .copied()
        .zip(contexts.iter())
        .map(|(key, context)| (key, copy_context(context)))
        .collect();

    if policy
        .allow
        .iter()
        .chain(&policy.deny)
        .any(|entry| reads_parents(&entry.selector))
    {
        let by_key: HashMap<&str, &DiscoveredPackage> =
            graph_keys.iter().copied().zip(packages.iter()).collect();
        let reached = skill_names
            .iter()
            .enumerate()
            .filter(|(_, names)| !names.is_empty())
            .map(|(index, _)| index)
            .chain(unlisted.iter().copied())
            .map(|index| graph_keys[index]);
        decisions
            .unconfirmed
            .extend(uncertain_ancestors(&graph, reached, &by_key));
    }
    for &index in &unlisted {
        let package = &packages[index];
        for (skill, requires) in recorded.get(&package.name).into_iter().flatten() {
            let mut candidate = copy_context(&contexts[index]);
            candidate.skill = Some(skill);
            let ruling = decide(policy, &candidate, graph_keys[index], &graph, &all_packages);
            let allows = match ruling.decision {
                Decision::Allowed(naming) => naming >= *requires,
                Decision::Unknown => ruling.possible_naming >= *requires,
                Decision::NotAllowed | Decision::Denied => false,
            };
            if allows {
                decisions
                    .unlisted_allows
                    .entry(package.name.clone())
                    .or_default()
                    .insert(skill.clone());
            }
        }
    }
    for (index, context) in contexts.iter().enumerate() {
        for skill in &skill_names[index] {
            let mut candidate = copy_context(context);
            candidate.skill = Some(skill);
            let ruling = decide(policy, &candidate, graph_keys[index], &graph, &all_packages);
            decisions.decided.push(Decided {
                importer: importer_index,
                package: index,
                skill: skill.clone(),
                decision: ruling.decision,
                open_denials: ruling.open_denials,
                possible_naming: ruling.possible_naming,
                direct: graph.root_deps.contains(graph_keys[index]),
            });
        }
    }
    directories
}

/// Why the skills of a package behind an entry LPM couldn't inspect aren't
/// linked anew.
const UNCERTAIN_INSTALL: &str = "an entry on its way in node_modules couldn't be inspected, so LPM can't tell whether this install holds it";

/// What a package's selector facts know of the skills it ships.
enum Shipped {
    /// The names it lists for candidates.
    Listed,
    /// Nothing the facts can rely on: its skills weren't read, couldn't be
    /// listed, or come from a release whose install is uncertain.
    Unknown,
}

/// What listing one installed package's skills found.
enum Listed {
    Nothing,
    /// Skills it ships; `unconfirmed` when a listed one's `SKILL.md`
    /// couldn't be inspected, so what it ships tells the selectors nothing
    /// and the next run lists it again.
    Skills {
        directory: cap_std::fs::Dir,
        names: Vec<String>,
        unconfirmed: bool,
    },
    /// Not read: the policy can't allow it.
    Unread,
    /// Whether the importer installed the release is unknown, so nothing
    /// new links from it, earlier copies stay, and what it ships tells the
    /// selectors nothing; one that ships skills is reported.
    Uncertain {
        ships_skills: bool,
    },
    /// It couldn't be read now: the earlier copies stay and the next run
    /// reads it again.
    Failed(std::io::Error),
    /// It breaks a rule the same way every time.
    Refused(std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    NotAllowed,
    Denied,
    Unknown,
    Allowed(Naming),
}

impl Decision {
    fn kind(self) -> &'static str {
        match self {
            Self::NotAllowed => "not_allowed",
            Self::Denied => "denied",
            Self::Unknown => "undecided",
            Self::Allowed(_) => "allowed",
        }
    }
}

/// What the policy decides for one skill, how many deny entries it can't
/// decide yet, and how specifically the entries that may allow the skill
/// would name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ruling {
    decision: Decision,
    open_denials: usize,
    possible_naming: Naming,
}

/// What the policy decides for `candidate`.
fn decide(
    policy: &SkillsPolicy,
    candidate: &PackageContext<'_>,
    key: &str,
    graph: &DepGraph<'_>,
    all_packages: &HashMap<&str, PackageContext<'_>>,
) -> Ruling {
    let mut denied = Truth::False;
    let mut open_denials = 0;
    for entry in &policy.deny {
        match evaluate_with_key(&entry.selector, candidate, key, graph, all_packages) {
            Truth::True => {
                return Ruling {
                    decision: Decision::Denied,
                    open_denials: 0,
                    possible_naming: Naming::None,
                };
            }
            Truth::Unknown => {
                denied = Truth::Unknown;
                open_denials += 1;
            }
            Truth::False => {}
        }
    }
    let mut allowed = Truth::False;
    let mut naming = Naming::None;
    let mut possible_naming = Naming::None;
    for entry in &policy.allow {
        let truth = evaluate_with_key(&entry.selector, candidate, key, graph, all_packages);
        if truth != Truth::False {
            possible_naming = possible_naming.max(selector_naming(
                &entry.selector,
                candidate,
                key,
                graph,
                all_packages,
                Truth::Unknown,
            ));
        }
        if truth == Truth::True {
            naming = naming.max(selector_naming(
                &entry.selector,
                candidate,
                key,
                graph,
                all_packages,
                Truth::True,
            ));
        }
        allowed = allowed.max(truth);
    }
    let decision = match (allowed, denied) {
        (Truth::False, _) => Decision::NotAllowed,
        (Truth::True, Truth::False) => Decision::Allowed(naming),
        _ => Decision::Unknown,
    };
    Ruling {
        decision,
        open_denials,
        possible_naming,
    }
}

/// How specifically the parts of `selector` that hold for `candidate` at
/// least as surely as `holds` name it: `#pkg` names the package, and
/// `#pkg:skill(name)` names the skill. With `Truth::Unknown`, a `,` branch
/// that can't be decided yet counts, for how the entry may name it once
/// data arrives.
fn selector_naming(
    selector: &Selector,
    candidate: &PackageContext<'_>,
    key: &str,
    graph: &DepGraph<'_>,
    all_packages: &HashMap<&str, PackageContext<'_>>,
    holds: Truth,
) -> Naming {
    match selector {
        Selector::Id(id) => {
            if id_names(id, candidate.name) {
                Naming::Package
            } else {
                Naming::None
            }
        }
        Selector::And(parts) => {
            let package = parts.iter().any(|part| {
                selector_naming(part, candidate, key, graph, all_packages, holds) >= Naming::Package
            });
            let skill = parts.iter().any(|part| match part {
                Selector::Skill(names) => candidate
                    .skill
                    .is_some_and(|skill| names.iter().any(|name| name == skill)),
                _ => false,
            });
            match (package, skill) {
                (true, true) => Naming::Skill,
                (true, false) => Naming::Package,
                _ => Naming::None,
            }
        }
        Selector::Or(parts) => parts
            .iter()
            .filter(|part| evaluate_with_key(part, candidate, key, graph, all_packages) >= holds)
            .map(|part| selector_naming(part, candidate, key, graph, all_packages, holds))
            .max()
            .unwrap_or(Naming::None),
        Selector::DirectChild { child, .. } => {
            selector_naming(child, candidate, key, graph, all_packages, holds)
        }
        Selector::PseudoClass(_) | Selector::Not(_) | Selector::Skill(_) => Naming::None,
    }
}

/// Whether `#id` names the package `name`, with or without a version.
fn id_names(id: &str, name: &str) -> bool {
    bare_id(id) == name
}

/// The package name in `#id`, without its version.
fn bare_id(id: &str) -> &str {
    let scope_end = if id.starts_with('@') {
        id.find('/').map_or(1, |position| position + 1)
    } else {
        0
    };
    match id[scope_end..].find('@') {
        Some(position) => &id[..scope_end + position],
        None => id,
    }
}

/// One decision per (package name, skill): an instance the policy allows,
/// or may allow once data arrives, over one it doesn't; then a direct
/// dependency's; then the highest version.
fn preferred_instances<'a>(
    decided: &[Decided],
    package_of: &impl Fn(&Decided) -> &'a DiscoveredPackage,
) -> HashSet<usize> {
    let mut best: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let rank = |entry: &Decided| {
        (
            matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown),
            entry.direct,
            lpm_semver::Version::parse(&package_of(entry).version).ok(),
        )
    };
    for (position, entry) in decided.iter().enumerate() {
        let name = package_of(entry).name.as_str();
        let slot = best.entry((name, entry.skill.as_str())).or_insert(position);
        if rank(entry) > rank(&decided[*slot]) {
            *slot = position;
        }
    }
    best.into_values().collect()
}

/// Skill names that more than one package the policy allows, or may allow
/// once data arrives, ships, with the packages.
fn name_conflicts<'a>(
    decided: &[Decided],
    preferred: &HashSet<usize>,
    package_of: &impl Fn(&Decided) -> &'a DiscoveredPackage,
) -> HashMap<String, Vec<String>> {
    let mut providers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (position, entry) in decided.iter().enumerate() {
        if preferred.contains(&position)
            && matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown)
        {
            let names = providers.entry(entry.skill.as_str()).or_default();
            let package = package_of(entry).name.as_str();
            if !names.contains(&package) {
                names.push(package);
            }
        }
    }
    providers
        .into_iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(skill, mut names)| {
            names.sort_unstable();
            (
                skill.to_string(),
                names.into_iter().map(str::to_string).collect(),
            )
        })
        .collect()
}

fn held(reason: HoldReason, detail: impl Into<String>) -> CandidateStatus {
    CandidateStatus::Held {
        reason,
        detail: detail.into(),
    }
}

/// Why a skill whose decision waits on data is held.
const UNDECIDED: &str = "a selector reads data this package lacks: a behavioral analysis, a security verdict, or the skills of a package LPM couldn't list";

/// Why a skill an undecided entry may name specifically enough is held.
const UNDECIDED_NAMING: &str = "an allowing entry that names it as specifically as it needs reads data this package lacks: a behavioral analysis, a security verdict, or the skills of a package LPM couldn't list";

/// [`prepare_fully`], held when the allowing entries name the skill less
/// specifically than `naming` it needs.
fn prepare(
    directory: Result<&cap_std::fs::Dir, LpmError>,
    package: &DiscoveredPackage,
    skill: &str,
    naming: Naming,
) -> (CandidateStatus, Option<SkillDetails>) {
    let (status, details) = prepare_fully(directory, package, skill);
    (require_naming(status, details.as_ref(), naming), details)
}

/// `status`, prepared as if fully named, held when `naming` names the skill
/// less specifically than what it pre-approves needs.
fn require_naming(
    status: CandidateStatus,
    details: Option<&SkillDetails>,
    naming: Naming,
) -> CandidateStatus {
    let (CandidateStatus::Linkable(prepared), Some(details)) = (&status, details) else {
        return status;
    };
    if naming >= prepared.requires {
        return status;
    }
    let detail = if prepared.permission == SkillPermission::None {
        format!(
            "the scan found warnings; allow `{}` to link it",
            details.suggested
        )
    } else {
        format!(
            "it pre-approves {} for agents; allow `{}` to link it",
            prepared.checked.allowed_tools.join(", "),
            details.suggested
        )
    };
    let reason = if prepared.requires == Naming::Skill {
        HoldReason::NeedsSkillName
    } else {
        HoldReason::NeedsPackageName
    };
    held(reason, detail)
}

/// Reads and checks `package`'s `skill` as if an entry named it fully: what
/// it ships, what it pre-approves, and anything that keeps it out.
fn prepare_fully(
    directory: Result<&cap_std::fs::Dir, LpmError>,
    package: &DiscoveredPackage,
    skill: &str,
) -> (CandidateStatus, Option<SkillDetails>) {
    let directory = match directory {
        Ok(directory) => directory,
        Err(error) => return (held(HoldReason::Unreadable, error.to_string()), None),
    };
    let entries = match read_skill_directory(directory, skill) {
        Ok(entries) => entries,
        Err(error) => return (held(HoldReason::Unreadable, error.to_string()), None),
    };
    let checked = match check_skill_directory(skill, &entries) {
        Ok(checked) => checked,
        Err(errors) => return (held(HoldReason::Invalid, errors.join("; ")), None),
    };
    let permission = checked.permission();
    let required = match permission {
        SkillPermission::Broad => Naming::Skill,
        SkillPermission::Hooks => Naming::Package,
        SkillPermission::None if checked.has_warnings() => Naming::Package,
        SkillPermission::None => Naming::None,
    };
    let suggested = if required == Naming::Skill {
        format!("#{}:skill({skill})", package.name)
    } else {
        format!("#{}", package.name)
    };
    let details = SkillDetails {
        description: checked.description.clone(),
        hidden: checked.hidden,
        allowed_tools: checked.allowed_tools.clone(),
        permission,
        warnings: checked
            .findings
            .iter()
            .filter(|finding| finding.issue.severity == lpm_skill::SkillSecuritySeverity::Warning)
            .count(),
        suggested,
        requires: required,
    };
    if checked.is_blocked() {
        let rules: Vec<String> = checked
            .findings
            .iter()
            .filter(|finding| finding.issue.severity == lpm_skill::SkillSecuritySeverity::Block)
            .map(|finding| {
                format!(
                    "{}:{} {}",
                    finding.path, finding.issue.line_number, finding.issue.rule_id
                )
            })
            .collect();
        return (held(HoldReason::Blocked, rules.join(", ")), Some(details));
    }
    if permission == SkillPermission::Hooks {
        return (
            held(
                HoldReason::Hooks,
                "the skill declares hooks, which run commands without the agent deciding to",
            ),
            Some(details),
        );
    }
    (
        CandidateStatus::Linkable(Box::new(Prepared {
            entries,
            checked,
            permission,
            requires: required,
        })),
        Some(details),
    )
}

fn copy_context<'a>(context: &PackageContext<'a>) -> PackageContext<'a> {
    PackageContext {
        name: context.name,
        version: context.version,
        path: context.path,
        analysis: context.analysis,
        has_scripts: context.has_scripts,
        is_built: context.is_built,
        is_vulnerable: context.is_vulnerable,
        is_deprecated: context.is_deprecated,
        is_root: context.is_root,
        is_workspace_root_dep: context.is_workspace_root_dep,
        skills: context.skills,
        skill: context.skill,
        malware: context.malware,
    }
}

fn root_dependency_names(manifest: &serde_json::Value) -> HashSet<String> {
    let mut names = HashSet::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(entries) = manifest.get(section).and_then(serde_json::Value::as_object) {
            names.extend(entries.keys().cloned());
        }
    }
    names
}

fn uses_behavioral_tags(selector: &Selector) -> bool {
    match selector {
        Selector::PseudoClass(class) => {
            class.behavioral_policy().is_some()
                || matches!(
                    class,
                    PseudoClass::Critical | PseudoClass::Medium | PseudoClass::Info
                )
        }
        Selector::And(parts) | Selector::Or(parts) => parts.iter().any(uses_behavioral_tags),
        Selector::Not(inner) => uses_behavioral_tags(inner),
        Selector::DirectChild { parent, child } => {
            uses_behavioral_tags(parent) || uses_behavioral_tags(child)
        }
        Selector::Id(_) | Selector::Skill(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::PolicyEntry;
    use super::*;

    #[test]
    fn a_selector_may_match_an_unlisted_package_it_names_or_doesnt_limit() {
        let unlisted = vec![("tool".to_string(), "unreadable".to_string())];

        assert!(may_match_any("#tool", &unlisted));
        assert!(may_match_any(":skills", &unlisted));
        assert!(!may_match_any("#other", &unlisted));
        assert!(!may_match_any("#tool", &[]));
    }

    #[test]
    fn ids_name_packages_with_or_without_a_version() {
        assert!(id_names("agent-browser", "agent-browser"));
        assert!(id_names("agent-browser@0.44.0", "agent-browser"));
        assert!(id_names("@lpm.dev/acme.ui", "@lpm.dev/acme.ui"));
        assert!(id_names("@lpm.dev/acme.ui@1.0.0", "@lpm.dev/acme.ui"));
        assert!(!id_names("agent", "agent-browser"));
        assert!(!id_names("@scope/a", "a"));
    }

    fn naming_of(selector: &str, skill: &str) -> Naming {
        let selector = lpm_security::query::parse_selector(selector).unwrap();
        let skills = vec![skill.to_string()];
        let context = PackageContext {
            name: "tool",
            version: "1.0.0",
            path: "",
            analysis: None,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
            skills: Some(&skills),
            skill: Some(skill),
            malware: None,
        };
        let graph = DepGraph::empty();
        selector_naming(
            &selector,
            &context,
            "",
            &graph,
            &HashMap::new(),
            Truth::True,
        )
    }

    fn entry(text: &str) -> PolicyEntry {
        PolicyEntry {
            text: text.to_string(),
            selector: lpm_security::query::parse_selector(text).unwrap(),
        }
    }

    fn context<'a>(skills: &'a [String]) -> PackageContext<'a> {
        PackageContext {
            name: "tool",
            version: "1.0.0",
            path: "node_modules/tool",
            analysis: None,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
            skills: Some(skills),
            skill: skills.first().map(String::as_str),
            malware: None,
        }
    }

    #[test]
    fn a_matching_deny_entry_wins_even_when_an_allowing_entry_lacks_data() {
        let policy = SkillsPolicy {
            allow: vec![entry(":skills:not(:network)")],
            deny: vec![entry("#tool")],
            targets: super::super::policy::Targets::Auto,
            deny_unreadable: false,
        };
        let skills = vec!["tool".to_string()];
        let ruling = decide(
            &policy,
            &context(&skills),
            "node_modules/tool",
            &DepGraph::empty(),
            &HashMap::new(),
        );
        assert!(matches!(ruling.decision, Decision::Denied), "{ruling:?}");
    }

    #[test]
    fn an_undecided_skill_carries_the_naming_its_possible_allowing_entries_would_give() {
        let skills = vec!["tool".to_string()];
        let ruling_for = |allow: &[&str]| {
            let policy = SkillsPolicy {
                allow: allow.iter().map(|text| entry(text)).collect(),
                deny: Vec::new(),
                targets: super::super::policy::Targets::Auto,
                deny_unreadable: false,
            };
            decide(
                &policy,
                &context(&skills),
                "node_modules/tool",
                &DepGraph::empty(),
                &HashMap::new(),
            )
        };

        let unnamed = ruling_for(&[":not(:malware)"]);
        assert_eq!(unnamed.decision, Decision::Unknown);
        assert_eq!(unnamed.possible_naming, Naming::None);
        assert_eq!(
            ruling_for(&[":not(:malware)", "#tool:skill(tool):not(:malware)"]).possible_naming,
            Naming::Skill
        );
        let branch = ruling_for(&["#other, #tool:skill(tool):not(:malware)"]);
        assert_eq!(branch.decision, Decision::Unknown);
        assert_eq!(
            branch.possible_naming,
            Naming::Skill,
            "an undecided `,` branch names the skill once the verdict arrives"
        );
        let masked = ruling_for(&[":skills", "#tool:skill(tool):not(:malware)"]);
        assert_eq!(masked.decision, Decision::Allowed(Naming::None));
        assert_eq!(
            masked.possible_naming,
            Naming::Skill,
            "an entry that holds but names it less specifically hides nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_a_missing_package_folder_counts_as_absent_and_other_open_errors_as_unreadable() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("node_modules/real")).unwrap();
        std::fs::create_dir_all(project.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            project.path().join("elsewhere"),
            project.path().join("node_modules/linked"),
        )
        .unwrap();
        let root = cap_std::fs::Dir::open_ambient_dir(project.path(), cap_std::ambient_authority())
            .unwrap();
        let mut linked = discovered("linked");
        linked.path = "node_modules/linked".into();
        let mut real = discovered("real");
        real.path = "node_modules/real".into();
        let other = std::io::Error::other("too many open files");

        assert!(is_absent(
            &std::io::Error::from(std::io::ErrorKind::NotFound),
            Some(&root),
            &real,
            false
        ));
        assert!(is_absent(&other, Some(&root), &linked, true));
        assert!(!is_absent(&other, Some(&root), &linked, false));
        assert!(!is_absent(&other, Some(&root), &real, true));
        assert!(!is_absent(&other, None, &real, true));
    }

    fn discovered(name: &str) -> DiscoveredPackage {
        DiscoveredPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            instance_id: None,
            path: format!("node_modules/{name}"),
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            local_source_dir: None,
            scan_mode: crate::commands::audit::discovery::ScanMode::FullLocal,
            is_dev: false,
            is_optional: false,
            platform_skipped: false,
            installed: None,
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn a_provider_whose_decision_lacks_data_still_contends_for_its_skill_name() {
        let packages = [discovered("a"), discovered("b")];
        let decided = vec![
            Decided {
                importer: 0,
                package: 0,
                skill: "guide".into(),
                decision: Decision::Allowed(Naming::Package),
                open_denials: 0,
                possible_naming: Naming::Package,
                direct: true,
            },
            Decided {
                importer: 0,
                package: 1,
                skill: "guide".into(),
                decision: Decision::Unknown,
                open_denials: 0,
                possible_naming: Naming::None,
                direct: true,
            },
        ];
        let preferred: HashSet<usize> = [0, 1].into_iter().collect();
        let conflicts = name_conflicts(&decided, &preferred, &|entry: &Decided| {
            &packages[entry.package]
        });
        assert_eq!(
            conflicts.get("guide").map(Vec::as_slice),
            Some(["a".to_string(), "b".to_string()].as_slice())
        );
    }

    #[test]
    fn entries_name_a_skill_only_with_both_its_package_and_its_name() {
        assert_eq!(naming_of("#tool", "x"), Naming::Package);
        assert_eq!(naming_of("#tool@1.0.0", "x"), Naming::Package);
        assert_eq!(naming_of("#tool:skill(x)", "x"), Naming::Skill);
        assert_eq!(naming_of("#tool:skill(x, y)", "x"), Naming::Skill);
        assert_eq!(naming_of(":skill(x)", "x"), Naming::None);
        assert_eq!(naming_of(":skills", "x"), Naming::None);
        assert_eq!(naming_of("*", "x"), Naming::None);
        assert_eq!(naming_of("#other, #tool:skill(x)", "x"), Naming::Skill);
        assert_eq!(naming_of(":root > #tool", "x"), Naming::Package);
    }
}
