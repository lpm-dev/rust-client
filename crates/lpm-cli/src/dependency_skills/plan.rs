use super::discovery::{read_skill_directory, skill_directory_listing};
use super::policy::{ParsedPolicy, SkillsPolicy};
use crate::commands::audit::discovery::{DiscoveredPackage, ManagerKind};
use crate::commands::audit::inventory::PackageInventory;
use crate::commands::query::selector_uses_pseudo_class;
use crate::lpm_skills_config::SecurityProvider;
use lpm_common::LpmError;
use lpm_registry::SkillReviewIssue;
use lpm_security::query::{
    DepGraph, DepGraphEntry, PackageContext, PseudoClass, Selector, Truth, evaluate_with_key,
};
use lpm_skill::{CheckedSkill, SkillDirectoryEntry, SkillPermission, check_skill_directory};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

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
    /// The security provider reports the package version as malware.
    Malware,
    /// The security provider hasn't decided the package version: it is
    /// still analyzing it, doesn't know it, or couldn't be asked.
    AwaitingCheck,
    /// No verdict of the security provider covers the package's files: it
    /// wasn't fetched from the npm registry, or the project patches it.
    NotCheckable,
    /// The skill directory couldn't be read.
    Unreadable,
    /// An LPM.dev package's skill directory that LPM.dev review hasn't
    /// approved as it is.
    NotReviewed,
}

impl HoldReason {
    /// Whether the hold can clear without a new version of the package or
    /// a change to the policy: data arriving, a conflict ending, a folder
    /// becoming readable, the security provider deciding.
    pub(crate) fn clears_on_its_own(self) -> bool {
        match self {
            Self::NeedsData
            | Self::NameConflict
            | Self::AwaitingCheck
            | Self::Unreadable
            | Self::NotReviewed => true,
            Self::Invalid
            | Self::Blocked
            | Self::NeedsPackageName
            | Self::NeedsSkillName
            | Self::Hooks
            | Self::Malware
            | Self::NotCheckable => false,
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
            Self::Malware => "malware",
            Self::AwaitingCheck => "awaiting_check",
            Self::NotCheckable => "not_checkable",
            Self::Unreadable => "unreadable",
            Self::NotReviewed => "not_reviewed",
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
    /// The risks LPM.dev review found when it served the skill with a
    /// warning, which may be none it could describe.
    pub(crate) review_warning: Option<Vec<SkillReviewIssue>>,
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
/// dependencies ship. Planning writes nothing in the project; an apply
/// plan may note in LPM's cache that a skill directory awaits review.
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
    /// Every installed instance of each package that ships skills or whose
    /// skills couldn't be listed, when a security provider checks npm
    /// packages: a skill that pre-approves its package's command answers to
    /// every release that command may run.
    pub(crate) installs: BTreeMap<String, Vec<PackageInstall>>,
    /// Whether anything could link: the policy allows packages and npm and
    /// other package skills are on, or LPM.dev package skills are on and
    /// an install materialized some.
    pub(crate) considered: bool,
    /// LPM.dev skill directories the recorded review doesn't name, so a
    /// reconcile marks their records for the registry to be asked again.
    pub(crate) pending_reviews: Vec<PendingReview>,
    /// The LPM.dev packages among [`Self::unlisted`] that link without an
    /// entry: declared by an importer, or delivered by `lpm add`.
    pub(crate) automatic_unlisted: BTreeSet<String>,
    /// The npm releases, as names and versions, whose security verdicts
    /// the plan's decisions rest on: the package of every skill it allows
    /// or can't decide, when a security provider checks them.
    pub(crate) relied: BTreeSet<(String, String)>,
}

/// One installed instance of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageInstall {
    pub(crate) version: String,
    pub(crate) integrity: Option<String>,
    /// The npm release a verdict on it would cover, when one would.
    pub(crate) release: Option<(String, String)>,
}

/// A skill directory an LPM.dev package ships that its review record
/// doesn't name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingReview {
    /// `owner.package`.
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) directory: String,
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

/// Which kinds of dependency skills a plan links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sources {
    /// The reviewed skills of LPM.dev packages.
    pub(crate) lpm_dev: bool,
    /// The skills of npm and other registries' packages the policy allows.
    pub(crate) other: bool,
    /// Who checks the packages behind the second kind before they link.
    pub(crate) provider: SecurityProvider,
    /// Whether the run is offline, so the provider can't be asked.
    pub(crate) offline: bool,
}

/// The project directories whose installs a plan reads: `project_dir`, and
/// in a workspace root every member.
pub(crate) fn importer_directories(project_dir: &Path) -> Vec<PathBuf> {
    let mut directories = vec![project_dir.to_path_buf()];
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir)
        && same_directory(&workspace.root, project_dir)
    {
        directories.extend(workspace.members.into_iter().map(|member| member.path));
    }
    directories
}

/// The skills earlier links recorded, by package, with how specifically an
/// entry had to name each: what a plan judges for a package whose skills
/// couldn't be listed.
pub(crate) type RecordedSkills = BTreeMap<String, Vec<(String, Naming)>>;

/// What a plan reads from earlier runs: the security verdicts LPM keeps,
/// when a provider checks npm packages, and the skills earlier links
/// recorded.
#[derive(Clone, Copy)]
pub(crate) struct History<'a> {
    pub(crate) verdicts: Option<&'a super::checks::Book>,
    pub(crate) recorded: &'a RecordedSkills,
}

/// Plans `project_dir`'s dependency skills under `policy`, linking the
/// kinds `sources` turns on, with what `history` holds. In a workspace root
/// the plan covers the root and every member. With nothing to link, nothing
/// is read. `packages` limits the plan to the skills those packages ship.
pub(crate) fn plan_project(
    project_dir: &Path,
    parsed: ParsedPolicy,
    manifest: &serde_json::Value,
    mode: PlanMode,
    sources: Sources,
    history: History<'_>,
    packages: Option<&HashSet<String>>,
) -> Result<Plan, LpmError> {
    let History {
        verdicts: checks,
        recorded,
    } = history;
    let ParsedPolicy { policy, problems } = parsed;
    let mut plan = Plan {
        policy,
        problems,
        ..Plan::default()
    };
    if plan
        .policy
        .as_ref()
        .is_some_and(|policy| policy.deny_unreadable)
    {
        return Ok(plan);
    }
    let empty = SkillsPolicy {
        allow: Vec::new(),
        deny: Vec::new(),
        targets: super::policy::Targets::Auto,
        deny_unreadable: false,
    };
    let policy = plan.policy.as_ref().unwrap_or(&empty);
    let reads_others = reads_other_packages_skills(policy);
    let directories = importer_directories(project_dir);
    let sets: Vec<Vec<super::lpm_dev::ReviewedSet>> = directories
        .iter()
        .map(|directory| {
            if sources.lpm_dev || reads_others {
                super::lpm_dev::reviewed_sets(directory)
            } else {
                Vec::new()
            }
        })
        .collect();
    let kinds = Sources {
        lpm_dev: sources.lpm_dev && sets.iter().any(|sets| !sets.is_empty()),
        other: sources.other && !policy.allow.is_empty(),
        ..sources
    };
    plan.considered = kinds.lpm_dev || kinds.other;
    if mode == PlanMode::Apply && !plan.considered {
        return Ok(plan);
    }
    let needs_analysis = policy
        .allow
        .iter()
        .chain(&policy.deny)
        .any(|entry| uses_behavioral_tags(&entry.selector));

    let mut discoveries = Vec::with_capacity(directories.len());
    for (index, (directory, sets)) in directories.into_iter().zip(sets).enumerate() {
        let (names, declared) = if index == 0 {
            (
                root_dependency_names(manifest),
                installed_dependency_names(manifest),
            )
        } else {
            let member_manifest = read_manifest(&directory).ok();
            if member_manifest
                .as_ref()
                .is_some_and(|manifest| manifest.pointer("/lpm/skills").is_some())
            {
                plan.problems
                    .push(member_policy_problem(project_dir, &directory));
            }
            member_manifest
                .map(|manifest| {
                    (
                        root_dependency_names(&manifest),
                        installed_dependency_names(&manifest),
                    )
                })
                .unwrap_or_default()
        };
        let discovery = match PackageInventory::discover_within(&directory, project_dir) {
            Ok(discovery) => discovery,
            Err(LpmError::NotFound(_)) => {
                crate::commands::audit::discovery::DiscoveryResult::nothing_installed(directory)
            }
            Err(error) => return Err(error),
        };
        discoveries.push((discovery, names, declared, sets));
    }
    let is_lpm_project = discoveries
        .iter()
        .any(|(discovery, _, _, _)| discovery.manager == ManagerKind::Lpm);
    if sources.provider == SecurityProvider::None
        && (sources.other || mode == PlanMode::Inspect)
        && policy.allow.iter().chain(&policy.deny).any(|entry| {
            selector_uses_pseudo_class(&entry.selector, |class| class == PseudoClass::Malware)
        })
    {
        plan.problems.push(format!(
            "a skills selector uses `:malware`, which reads Socket's verdicts, and no security provider is on, so skills it decides wait as needs_data; `lpm config set {} socket` turns Socket on",
            crate::lpm_skills_config::SECURITY_PROVIDER_SETTING
        ));
    }
    let book = checks.filter(|_| sources.provider == SecurityProvider::Socket);
    let reads_malware = book.is_some()
        && policy.allow.iter().chain(&policy.deny).any(|entry| {
            selector_uses_pseudo_class(&entry.selector, |class| class == PseudoClass::Malware)
        });
    let scope = Scope {
        policy,
        mode,
        enabled: sources,
        read: if mode == PlanMode::Inspect {
            Sources {
                lpm_dev: true,
                other: true,
                ..sources
            }
        } else {
            kinds
        },
        named: match mode {
            PlanMode::Apply => named_packages(policy),
            PlanMode::Inspect => None,
        },
        only: packages,
        reads_others,
        recorded,
        book,
        reads_malware,
    };
    let build = |lpm_root: Option<&lpm_common::LpmRoot>| -> Result<Found, LpmError> {
        let store_version = lpm_store::StoreVersion::from_env();
        let importers: Vec<Importer> = discoveries
            .into_iter()
            .map(|(discovery, root_dependency_names, declared_names, sets)| {
                let is_lpm = discovery.manager == ManagerKind::Lpm;
                let added =
                    crate::added_sources_state::load_skill_versions(&discovery.project_root)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(package, version)| (format!("@lpm.dev/{package}"), version))
                        .collect();
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
                    declared_names,
                    sets,
                    added,
                }
            })
            .collect();
        Ok(candidates_from_importers(&importers, lpm_root, &scope))
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
    plan.installs = found.installs;
    plan.problems.extend(found.problems);
    plan.incomplete = found.incomplete;
    plan.pending_reviews = found.pending_reviews;
    plan.automatic_unlisted = found.automatic_unlisted;
    plan.relied = found.relied;
    Ok(plan)
}

/// What one plan decides with.
struct Scope<'a> {
    policy: &'a SkillsPolicy,
    mode: PlanMode,
    /// The kinds the user's settings link.
    enabled: Sources,
    /// The kinds whose skills the plan reads.
    read: Sources,
    /// The only npm and other packages the policy can allow, when it names
    /// them.
    named: Option<HashSet<String>>,
    /// The only packages the plan reads, when the caller limits it.
    only: Option<&'a HashSet<String>>,
    /// Whether an entry reads the skills other packages ship, through `>`,
    /// so the skills of packages the plan can't link are read for the
    /// selectors.
    reads_others: bool,
    /// The skills earlier links recorded, judged for packages whose skills
    /// couldn't be listed.
    recorded: &'a RecordedSkills,
    /// The security provider's verdicts, when one checks npm packages.
    book: Option<&'a super::checks::Book>,
    /// Whether a selector reads `:malware`, so every candidate's verdict
    /// can change a decision, denied ones included.
    reads_malware: bool,
}

impl Scope<'_> {
    /// Whether the plan reads the skills `package` ships only for the
    /// selectors that look at other packages.
    fn reads_facts(&self, package: &str) -> bool {
        self.reads_others && self.only.is_none_or(|only| only.contains(package))
    }

    /// Whether the plan reads the skills `package` ships.
    fn reads(&self, package: &str) -> bool {
        if self.only.is_some_and(|only| !only.contains(package)) {
            return false;
        }
        if is_lpm_dev(package) {
            self.read.lpm_dev
        } else {
            self.read.other
                && self
                    .named
                    .as_ref()
                    .is_none_or(|named| named.contains(package))
        }
    }
}

pub(crate) fn is_lpm_dev(package: &str) -> bool {
    package.starts_with("@lpm.dev/")
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

/// The names of the only npm and other packages the policy can allow, when
/// every allowing entry names its packages with `#name`; `None` otherwise.
/// Packages outside the set are read only for the selectors that look at
/// the skills other packages ship.
pub(crate) fn named_packages(policy: &SkillsPolicy) -> Option<HashSet<String>> {
    let mut names = HashSet::new();
    for entry in &policy.allow {
        names.extend(selector_names(&entry.selector)?);
    }
    Some(names)
}

/// Whether one of `policy`'s entries reads the skills other packages ship.
pub(crate) fn reads_other_packages_skills(policy: &SkillsPolicy) -> bool {
    policy
        .allow
        .iter()
        .chain(&policy.deny)
        .any(|entry| reads_parent_skills(&entry.selector))
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
    /// The names its manifest declares dependencies under that the install
    /// puts in place: its own peers left out.
    declared_names: HashSet<String>,
    /// The reviewed LPM.dev skills its install materialized.
    sets: Vec<super::lpm_dev::ReviewedSet>,
    /// The LPM.dev packages `lpm add` delivered here, with the version of
    /// their skills, as `lpm-sources.json` records them.
    added: HashSet<(String, String)>,
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

    /// The reviewed set of `package` at `version`: a set of another version
    /// vouches for nothing this one ships.
    fn set_of(&self, package: &str, version: &str) -> Option<usize> {
        self.sets
            .iter()
            .position(|set| set.package == package && set.version == version)
    }

    /// The `lpm.lock` instances the importer's manifest declares, by the
    /// names it declares them under: never a peer LPM installed at its root
    /// for another package, nor one the manifest lists as its own peer.
    fn declared_instances(&self) -> RootReleases {
        RootReleases::of(self, |name, _| self.declared_names.contains(name))
    }

    /// Whether the importer's manifest declares `package`, given
    /// [`Self::declared_instances`]; without instances, a release the root
    /// installs under a declared name, or a package at the top of
    /// `node_modules` under one the lockfile doesn't resolve at the root, an
    /// alias's included.
    fn declares(&self, package: &DiscoveredPackage, declared: &RootReleases) -> bool {
        declared.holds_at_top(package, &self.declared_names)
    }

    /// Whether `lpm skills add` or `lpm add` delivered the set at `index`, so
    /// it links whether or not the package is installed here, and however
    /// deep. A set an install left for a dependency that is gone, left out
    /// or no longer direct doesn't.
    fn delivered_by_add(&self, index: usize) -> bool {
        let set = &self.sets[index];
        set.added
            || self
                .added
                .contains(&(set.package.clone(), set.version.clone()))
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

/// The skills one package ships, with where each one's files come from.
type PackageSkills = Vec<(String, Origin)>;

/// Where a skill's files come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// `skills/<name>/` in the package as it was published.
    Directory,
    /// The flat skill at this index of its LPM.dev package's reviewed set.
    Reviewed(usize),
}

/// A policy decision about one skill of one package.
struct Decided {
    importer: usize,
    /// The package's index in its importer's inventory; `None` for a
    /// reviewed set whose package the importer didn't install, as `lpm add`
    /// delivers.
    package: Option<usize>,
    /// The package's reviewed set in its importer.
    set: Option<usize>,
    skill: String,
    origin: Origin,
    decision: Decision,
    /// How many deny entries can't be decided for the skill yet.
    open_denials: usize,
    /// How specifically the entries that may allow the skill would name it.
    possible_naming: Naming,
    /// A direct dependency of its importer.
    direct: bool,
}

/// What deciding the importers finds besides the decisions themselves.
#[derive(Default)]
struct Judged {
    /// [`Plan::unlisted_allows`].
    unlisted_allows: BTreeMap<String, BTreeSet<String>>,
    /// The packages, as `name@version`, whose installs can't be confirmed
    /// and that a candidate or an unlisted package reaches through its
    /// parents, when the policy looks at parents.
    unconfirmed: BTreeSet<String>,
    /// The LPM.dev packages, as `name@version`, without LPM's record of the
    /// review of their installed version that a candidate or an unlisted
    /// package reaches through its parents, when a selector reads what
    /// parents ship.
    unreviewed: BTreeSet<String>,
}

/// The skills the importers' installed packages ship, the packages whose
/// skills couldn't be listed, with why, and the npm releases whose
/// security verdicts the decisions rest on.
struct Found {
    candidates: Vec<Candidate>,
    unlisted: BTreeMap<String, String>,
    unlisted_allows: BTreeMap<String, BTreeSet<String>>,
    installs: BTreeMap<String, Vec<PackageInstall>>,
    /// Packages whose skills break a rule the same way every run.
    problems: Vec<String>,
    incomplete: bool,
    pending_reviews: Vec<PendingReview>,
    automatic_unlisted: BTreeSet<String>,
    relied: BTreeSet<(String, String)>,
}

/// A decided skill's package: name, version and integrity.
fn identity<'a>(importers: &'a [Importer], entry: &Decided) -> (&'a str, &'a str, Option<&'a str>) {
    let importer = &importers[entry.importer];
    match (entry.package, entry.set) {
        (Some(package), _) => {
            let package = &importer.inventory.discovery.packages[package];
            (
                package.name.as_str(),
                package.version.as_str(),
                package.integrity.as_deref(),
            )
        }
        (None, Some(set)) => {
            let set = &importer.sets[set];
            (set.package.as_str(), set.version.as_str(), None)
        }
        (None, None) => unreachable!("a decided skill comes from a package or a reviewed set"),
    }
}

/// The candidates of every importer, and the npm releases whose security
/// verdicts decide them.
fn candidates_from_importers(
    importers: &[Importer],
    lpm_root: Option<&lpm_common::LpmRoot>,
    scope: &Scope<'_>,
) -> Found {
    let mut scanned: Vec<Scanned> = importers
        .iter()
        .map(|importer| {
            let project_root = crate::commands::audit::inventory::open_project_root(
                &importer.inventory.discovery.project_root,
            )
            .ok();
            scan_importer(importer, project_root.as_ref(), lpm_root, scope)
        })
        .collect();
    let watched: HashSet<String> = if scope.book.is_some() {
        importers
            .iter()
            .zip(&scanned)
            .flat_map(|(importer, scanned)| {
                let packages = &importer.inventory.discovery.packages;
                scanned
                    .unlisted
                    .iter()
                    .map(|(name, _, _)| name.clone())
                    .chain(
                        scanned
                            .skills
                            .iter()
                            .zip(packages)
                            .filter(|(skills, _)| !skills.is_empty())
                            .map(|(_, package)| package.name.clone()),
                    )
                    .filter(|name| !is_lpm_dev(name))
            })
            .collect()
    } else {
        HashSet::new()
    };
    for (importer, scanned) in importers.iter().zip(scanned.iter_mut()) {
        let packages = &importer.inventory.discovery.packages;
        scanned.releases = npm_releases(
            importer,
            |index| watched.contains(&packages[index].name),
            scope,
        );
    }
    let root = RootDependencies::of(importers.first());
    let mut decided = Vec::new();
    let mut judged = Judged::default();
    for (index, (importer, scanned)) in importers.iter().zip(&scanned).enumerate() {
        decide_importer(
            importer,
            index,
            scanned,
            scope,
            &root,
            &mut decided,
            &mut judged,
        );
    }
    let Judged {
        unlisted_allows,
        unconfirmed,
        unreviewed,
    } = judged;
    let unlisted: BTreeMap<String, String> = scanned
        .iter()
        .flat_map(|scanned| {
            scanned
                .unlisted
                .iter()
                .map(|(package, detail, _)| (package.clone(), detail.clone()))
        })
        .collect();
    let mut installs: BTreeMap<String, Vec<PackageInstall>> = BTreeMap::new();
    if !watched.is_empty() {
        for (importer, scanned) in importers.iter().zip(&scanned) {
            for (index, package) in importer.inventory.discovery.packages.iter().enumerate() {
                if !watched.contains(&package.name) {
                    continue;
                }
                installs
                    .entry(package.name.clone())
                    .or_default()
                    .push(PackageInstall {
                        version: package.version.clone(),
                        integrity: package.integrity.clone(),
                        release: scanned.releases[index]
                            .as_ref()
                            .and_then(|release| release.as_ref().ok().cloned()),
                    });
            }
        }
    }
    let mut problems: Vec<String> = Vec::new();
    for problem in scanned.iter().flat_map(|scanned| &scanned.problems) {
        if !problems.contains(problem) {
            problems.push(problem.clone());
        }
    }
    let mut incomplete = scanned.iter().any(|scanned| scanned.incomplete);
    if let Some(problem) = unconfirmed_parents(&unconfirmed) {
        incomplete = true;
        problems.push(problem);
    }
    if let Some(problem) = unreviewed_parents(&unreviewed) {
        problems.push(problem);
    }
    let automatic_unlisted: BTreeSet<String> = importers
        .iter()
        .zip(&scanned)
        .flat_map(|(importer, scanned)| {
            let declared = importer.declared_instances();
            let packages = &importer.inventory.discovery.packages;
            scanned
                .unlisted
                .iter()
                .filter(|(name, _, index)| {
                    is_lpm_dev(name)
                        && scanned.sets[*index].is_some_and(|set| {
                            importer.declares(&packages[*index], &declared)
                                || importer.delivered_by_add(set)
                        })
                })
                .map(|(name, _, _)| name.clone())
                .collect::<Vec<_>>()
        })
        .collect();
    if decided.is_empty() {
        return Found {
            candidates: Vec::new(),
            unlisted,
            unlisted_allows,
            installs,
            problems,
            incomplete,
            pending_reviews: Vec::new(),
            automatic_unlisted,
            relied: BTreeSet::new(),
        };
    }
    let directories: Vec<&[Option<cap_std::fs::Dir>]> = scanned
        .iter()
        .map(|scanned| scanned.directories.as_slice())
        .collect();
    let identity_of = |entry: &Decided| {
        let (name, version, _) = identity(importers, entry);
        (name, version)
    };
    let preferred = preferred_instances(&decided, &identity_of);
    let eligible = |position: usize, entry: &Decided| {
        preferred.contains(&position)
            && matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown)
    };
    // The skills that may link are read before anything else, so only those
    // that can link contest a name, and what they pre-approve is known before
    // the provider is asked about the releases their commands may run.
    // Inspection reads every instance for its own ruling.
    let mut full: Vec<Option<(CandidateStatus, Option<SkillDetails>)>> =
        Vec::with_capacity(decided.len());
    let mut may_link: Vec<bool> = Vec::with_capacity(decided.len());
    {
        for (position, entry) in decided.iter().enumerate() {
            if scope.mode != PlanMode::Inspect && !eligible(position, entry) {
                full.push(None);
                may_link.push(false);
                continue;
            }
            let (name, _, _) = identity(importers, entry);
            let directory = entry
                .package
                .and_then(|package| directories[entry.importer][package].as_ref());
            let (status, details) =
                prepare_fully(directory, name, &entry.skill, review_of(importers, entry));
            may_link.push(
                matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown)
                    && match &status {
                        CandidateStatus::Linkable(_) => true,
                        CandidateStatus::Held { reason, .. } => reason.clears_on_its_own(),
                        CandidateStatus::NotAllowed | CandidateStatus::Denied => false,
                    }
                    && details
                        .as_ref()
                        .is_none_or(|details| details.requires <= entry.possible_naming),
            );
            full.push(preferred.contains(&position).then_some((status, details)));
        }
    }
    let grants_commands = |position: usize| {
        full.get(position)
            .and_then(Option::as_ref)
            .and_then(|(_, details)| details.as_ref())
            .is_some_and(|details| details.permission != SkillPermission::None)
    };
    let mut relied = BTreeSet::new();
    let mut command_holds: Vec<Option<(HoldReason, String)>> = vec![None; decided.len()];
    let (provider_holds, contesting): (Vec<Option<(HoldReason, String)>>, Vec<bool>) = decided
        .iter()
        .enumerate()
        .map(|(position, entry)| {
            let eligible = eligible(position, entry);
            let linkable = eligible && may_link[position];
            let mut hold = None;
            let mut contests = linkable;
            if let Some(release) = entry
                .package
                .and_then(|package| scanned[entry.importer].releases[package].as_ref())
            {
                if let Ok(release) = release
                    && (linkable || scope.reads_malware)
                {
                    relied.insert(release.clone());
                }
                hold = eligible
                    .then(|| provider_hold(scope, release))
                    .flatten()
                    .filter(|(reason, _)| linkable || *reason == HoldReason::Malware);
                contests = linkable && (hold.is_none() || has_clean_verdict(scope, release));
            }
            let (name, _, _) = identity(importers, entry);
            let held_for_good = matches!(
                hold,
                Some((HoldReason::Malware | HoldReason::NotCheckable, _))
            );
            if linkable
                && !held_for_good
                && grants_commands(position)
                && let Some(package_installs) = installs.get(name)
            {
                relied.extend(
                    package_installs
                        .iter()
                        .filter_map(|install| install.release.clone()),
                );
                if let Some(command) = command_hold(scope, name, package_installs) {
                    contests &= package_installs.iter().all(|install| {
                        install
                            .release
                            .as_ref()
                            .is_some_and(|(name, version)| verdict_is_clean(scope, name, version))
                    });
                    command_holds[position] = Some(command);
                }
            }
            (hold, contests)
        })
        .unzip();
    let conflicts = name_conflicts(&decided, &preferred, &contesting, &identity_of);
    let mut rulings: HashMap<(&str, String), Vec<InstanceRuling>> = HashMap::new();
    if scope.mode == PlanMode::Inspect {
        for (position, entry) in decided.iter().enumerate() {
            let (name, version, _) = identity(importers, entry);
            rulings
                .entry((name, entry.skill.clone()))
                .or_default()
                .push(InstanceRuling {
                    version: version.to_string(),
                    ruling: entry.decision.kind(),
                    open_denials: entry.open_denials,
                    may_link: may_link[position],
                });
        }
        for instances in rulings.values_mut() {
            instances.sort();
        }
    }

    let mut candidates = Vec::with_capacity(preferred.len());
    let mut pending_reviews = Vec::new();
    for (position, entry) in decided.iter().enumerate() {
        if !preferred.contains(&position) {
            continue;
        }
        let (package, version, integrity) = identity(importers, entry);
        let importer = &importers[entry.importer];
        let skill = entry.skill.as_str();
        let instances = rulings
            .remove(&(package, skill.to_string()))
            .unwrap_or_default();
        let directory = entry
            .package
            .and_then(|package| directories[entry.importer][package].as_ref());
        let set = entry.set.map(|set| &importer.sets[set]);
        let review = review_of(importers, entry);
        let check = |naming: Naming| prepare(directory, package, skill, naming, review);
        let full = full.get_mut(position).and_then(Option::take);
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
            Decision::Allowed(_) | Decision::Unknown
                if let Some((HoldReason::Malware, detail)) = &provider_holds[position] =>
            {
                inspect(held(HoldReason::Malware, detail.clone()), full)
            }
            Decision::Allowed(_) | Decision::Unknown if conflicts.contains_key(skill) => inspect(
                held(
                    HoldReason::NameConflict,
                    format!(
                        "{} also ship a skill named `{skill}`; name one with `#<package>:skill({skill})` and deny the others",
                        conflicts[skill]
                            .iter()
                            .filter(|name| **name != package)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                full,
            ),
            Decision::Allowed(_) | Decision::Unknown
                if let Some((reason, detail)) = &provider_holds[position] =>
            {
                inspect(held(*reason, detail.clone()), full)
            }
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
        if matches!(review, Review::Directory(None))
            && matches!(
                status,
                CandidateStatus::Held {
                    reason: HoldReason::NotReviewed,
                    ..
                }
            )
            && let Some(set) = set.filter(|set| set.recorded)
            && let Some(short) = package.strip_prefix("@lpm.dev/")
        {
            pending_reviews.push(PendingReview {
                package: short.to_string(),
                version: set.version.clone(),
                directory: skill.to_string(),
            });
        }
        let status = match (status, command_holds[position].take()) {
            (CandidateStatus::Linkable(_), Some((reason, detail))) => held(reason, detail),
            (CandidateStatus::Held { reason, .. }, Some((command, detail)))
                if reason.clears_on_its_own()
                    && matches!(command, HoldReason::Malware | HoldReason::NotCheckable) =>
            {
                held(command, detail)
            }
            (status, _) => status,
        };
        candidates.push(Candidate {
            package: package.to_string(),
            version: version.to_string(),
            integrity: integrity.map(str::to_string),
            skill: skill.to_string(),
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
        installs,
        problems,
        incomplete,
        pending_reviews,
        automatic_unlisted,
        relied,
    }
}

/// Why a skill that pre-approves `package`'s command waits, when one of
/// the package's installed instances, any of which the command may run, has
/// no verdict that lets it link: a flagged one first, then one no verdict
/// can vouch for, then one waiting for an answer.
fn command_hold(
    scope: &Scope<'_>,
    package: &str,
    installs: &[PackageInstall],
) -> Option<(HoldReason, String)> {
    let mut found: Option<(HoldReason, String)> = None;
    for install in installs {
        let hold = match &install.release {
            Some((name, version))
                if scope
                    .book
                    .is_some_and(|book| !book.vouches_now(name, version)) =>
            {
                (
                    HoldReason::AwaitingCheck,
                    format!(
                        "LPM couldn't read the shared verdict cache to confirm that {package}@{}, which the command it pre-approves may run, wasn't flagged since",
                        install.version
                    ),
                )
            }
            None => (
                HoldReason::NotCheckable,
                format!(
                    "the command it pre-approves may run {package}@{}, a copy Socket's verdicts can't vouch for",
                    install.version
                ),
            ),
            Some(release) => match provider_hold(scope, &Ok(release.clone())) {
                None => continue,
                Some((reason, detail)) => (
                    reason,
                    format!(
                        "the command it pre-approves may run {package}@{}: {detail}",
                        install.version
                    ),
                ),
            },
        };
        let rank = |reason: HoldReason| match reason {
            HoldReason::Malware => 0,
            HoldReason::NotCheckable => 1,
            _ => 2,
        };
        if found
            .as_ref()
            .is_none_or(|(current, _)| rank(hold.0) < rank(*current))
        {
            found = Some(hold);
        }
    }
    found
}

/// Whether the security provider's latest verdict on `release` is clean,
/// however old.
fn has_clean_verdict(scope: &Scope<'_>, release: &Result<(String, String), String>) -> bool {
    release
        .as_ref()
        .is_ok_and(|(name, version)| verdict_is_clean(scope, name, version))
}

/// Whether the security provider's latest verdict on `name@version` is
/// clean, however old.
fn verdict_is_clean(scope: &Scope<'_>, name: &str, version: &str) -> bool {
    scope
        .book
        .and_then(|book| book.entry(name, version))
        .is_some_and(|entry| entry.verdict == super::socket::Verdict::Clean)
}

/// Why the security provider holds a skill of the package whose npm
/// release is `release`, or `None` when its verdict lets the skill link.
/// Without a verdict LPM keeps, the skill waits for Socket to be asked.
fn provider_hold(
    scope: &Scope<'_>,
    release: &Result<(String, String), String>,
) -> Option<(HoldReason, String)> {
    use super::socket::Verdict;

    let book = scope.book?;
    let (name, version) = match release {
        Ok(release) => release,
        Err(why) => {
            return Some((
                HoldReason::NotCheckable,
                format!("Socket's verdicts can't vouch for this copy: {why}"),
            ));
        }
    };
    let entry = book.entry(name, version);
    let detail = match entry.map(|entry| &entry.verdict) {
        Some(Verdict::Clean) if !entry.is_some_and(|entry| book.is_due(entry)) => return None,
        Some(Verdict::Clean) => format!(
            "Socket's clean verdict for this version is more than a day old and LPM couldn't ask again: {}",
            unasked_reason(scope, book)
        ),
        Some(Verdict::Malware { alert }) => {
            let kind = if alert == "gptMalware" {
                "possible malware, found by AI analysis"
            } else {
                "known malware"
            };
            return Some((
                HoldReason::Malware,
                format!("Socket flags {name}@{version} as {kind}"),
            ));
        }
        Some(Verdict::Pending) => "Socket hasn't finished analyzing this version".to_string(),
        Some(Verdict::Unknown) => "Socket has no record of this version".to_string(),
        None => format!(
            "LPM couldn't ask Socket about this version: {}",
            unasked_reason(scope, book)
        ),
    };
    Some((HoldReason::AwaitingCheck, detail))
}

/// Why the provider wasn't asked about a version in this plan.
fn unasked_reason(scope: &Scope<'_>, book: &super::checks::Book) -> String {
    if scope.enabled.offline {
        return "the install runs offline".to_string();
    }
    match book.failure() {
        Some(reason) => reason.to_string(),
        None if scope.mode == PlanMode::Inspect => {
            "listing never asks; the next install, `lpm skills link` or `lpm skills sync` asks"
                .to_string()
        }
        None => "it wasn't asked yet".to_string(),
    }
}

/// What one importer's packages ship, before any decision.
struct Scanned {
    /// The directory of each package that ships skills, opened once.
    directories: Vec<Option<cap_std::fs::Dir>>,
    skills: Vec<PackageSkills>,
    /// What each package's selector facts know of the skills it ships.
    shipped: Vec<Shipped>,
    /// Each package's reviewed set in the importer.
    sets: Vec<Option<usize>>,
    /// The reviewed sets whose packages the importer didn't install.
    orphans: Vec<usize>,
    /// The packages whose `skills` folder couldn't be listed, with why and
    /// their index.
    unlisted: Vec<(String, String, usize)>,
    /// Packages whose skills break a rule the same way every run.
    problems: Vec<String>,
    /// Whether a package read for the selectors alone couldn't be read now.
    incomplete: bool,
    /// For each npm package that ships skills, or that shares a name with a
    /// package whose skills couldn't be listed, when a security provider
    /// checks them: the npm release it is a copy of, or why no verdict
    /// covers its files. Filled once every importer is scanned.
    releases: Vec<Option<Result<(String, String), String>>>,
}

fn scan_importer(
    importer: &Importer,
    project_root: Option<&cap_std::fs::Dir>,
    lpm_root: Option<&lpm_common::LpmRoot>,
    scope: &Scope<'_>,
) -> Scanned {
    use rayon::prelude::*;

    let packages = &importer.inventory.discovery.packages;
    let sets: Vec<Option<usize>> = packages
        .iter()
        .map(|package| importer.set_of(&package.name, &package.version))
        .collect();
    type Listed = (
        Option<cap_std::fs::Dir>,
        PackageSkills,
        Option<ListFailure>,
        Shipped,
        bool,
    );
    let listed: Vec<Listed> = packages
        .par_iter()
        .zip(&sets)
        .map(|(package, set)| {
            let reads = scope.reads(&package.name);
            if !reads && !scope.reads_facts(&package.name) {
                return (None, Vec::new(), None, Shipped::Unknown, false);
            }
            let uncertain =
                package.installed == Some(crate::commands::audit::discovery::Installation::Unknown);
            let lpm_dev = is_lpm_dev(&package.name);
            let reviewed = set.filter(|set| importer.sets[*set].recorded);
            if !reads && (uncertain || lpm_dev && reviewed.is_none()) {
                return (None, Vec::new(), None, Shipped::Unknown, false);
            }
            let mut skills: PackageSkills = set
                .map(|set| {
                    importer.sets[set]
                        .skills
                        .iter()
                        .enumerate()
                        .map(|(index, skill)| (skill.name.clone(), Origin::Reviewed(index)))
                        .collect()
                })
                .unwrap_or_default();
            let mut failure = None;
            let directory = match importer.open(package, project_root, lpm_root) {
                Ok(directory) => Some(directory),
                Err(error)
                    if is_absent(&error, project_root, package, importer.opens_in_project()) =>
                {
                    None
                }
                Err(error) => {
                    failure = Some(ListFailure::Unreadable(error));
                    None
                }
            };
            let mut unconfirmed = false;
            if let Some(directory) = directory.as_ref() {
                match skill_directory_listing(directory) {
                    Ok(listing) => {
                        unconfirmed = listing.unconfirmed;
                        skills.extend(
                            listing
                                .names
                                .into_iter()
                                .map(|name| (name, Origin::Directory)),
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                        failure = Some(ListFailure::Refused(error));
                    }
                    Err(error) => failure = Some(ListFailure::Unreadable(error)),
                }
            }
            // A reviewed LPM.dev skill comes from the registry, so what the
            // package ships is known only from LPM's record of the review for
            // the installed version.
            let names_known = failure.is_none() && !unconfirmed && (!lpm_dev || reviewed.is_some());
            let fact_names = |skills: &PackageSkills| -> Vec<String> {
                match reviewed {
                    Some(set) => importer.sets[set]
                        .approved
                        .iter()
                        .cloned()
                        .chain(
                            skills
                                .iter()
                                .filter(|(_, origin)| matches!(origin, Origin::Directory))
                                .map(|(name, _)| name.clone()),
                        )
                        .collect(),
                    None => skills.iter().map(|(name, _)| name.clone()).collect(),
                }
            };
            if !reads {
                let facts = if names_known {
                    Shipped::Names(fact_names(&skills))
                } else {
                    Shipped::Unknown
                };
                return (
                    None,
                    Vec::new(),
                    failure.map(ListFailure::for_facts),
                    facts,
                    unconfirmed,
                );
            }
            if uncertain {
                let failure =
                    failure.or_else(|| (!skills.is_empty()).then_some(ListFailure::Uncertain));
                return (None, Vec::new(), failure, Shipped::Unknown, false);
            }
            let facts = if !names_known {
                Shipped::Unknown
            } else if lpm_dev {
                Shipped::Names(fact_names(&skills))
            } else {
                Shipped::Listed
            };
            if skills.is_empty() {
                (None, skills, failure, facts, unconfirmed)
            } else {
                (directory, skills, failure, facts, unconfirmed)
            }
        })
        .collect();
    let mut directories = Vec::with_capacity(listed.len());
    let mut skills = Vec::with_capacity(listed.len());
    let mut shipped = Vec::with_capacity(listed.len());
    let mut unlisted = Vec::new();
    let mut problems = Vec::new();
    let mut incomplete = false;
    for (index, (package, (directory, package_skills, failure, facts, unconfirmed))) in
        packages.iter().zip(listed).enumerate()
    {
        incomplete |= unconfirmed;
        match failure {
            Some(ListFailure::Uncertain) => {
                unlisted.push((package.name.clone(), UNCERTAIN_INSTALL.to_string(), index));
            }
            Some(ListFailure::Unreadable(error)) => {
                unlisted.push((
                    package.name.clone(),
                    format!("its skills folder could not be read: {error}"),
                    index,
                ));
            }
            Some(ListFailure::Refused(error)) => {
                problems.push(format!(
                    "{}@{}: {error}, so none of its skills are linked",
                    package.name, package.version
                ));
            }
            Some(ListFailure::FactsUnreadable(error)) => {
                incomplete = true;
                problems.push(format!(
                    "{}@{}: its skills folder could not be read ({error}), so selectors that look at the skills it ships stay undecided until it can be",
                    package.name, package.version
                ));
            }
            Some(ListFailure::FactsRefused(error)) => {
                problems.push(format!(
                    "{}@{}: {error}, so selectors that look at the skills it ships stay undecided",
                    package.name, package.version
                ));
            }
            None => {}
        }
        directories.push(directory);
        skills.push(package_skills);
        shipped.push(facts);
    }
    let orphans = (0..importer.sets.len())
        .filter(|set| !sets.contains(&Some(*set)) && importer.delivered_by_add(*set))
        .collect();
    Scanned {
        directories,
        skills,
        shipped,
        sets,
        orphans,
        unlisted,
        problems,
        incomplete,
        releases: Vec::new(),
    }
}

/// The npm release of each package of `importer` that is `wanted`, or why
/// no verdict covers it, when a security provider checks npm packages.
fn npm_releases(
    importer: &Importer,
    wanted: impl Fn(usize) -> bool,
    scope: &Scope<'_>,
) -> Vec<Option<Result<(String, String), String>>> {
    let packages = &importer.inventory.discovery.packages;
    let checked =
        |index: usize| scope.book.is_some() && !is_lpm_dev(&packages[index].name) && wanted(index);
    if !(0..packages.len()).any(checked) {
        return vec![None; packages.len()];
    }
    let lockfile = importer.inventory.discovery.retained_lpm_lockfile();
    let mut by_instance: HashMap<lpm_common::PackageInstanceId, &lpm_lockfile::LockedPackage> =
        HashMap::new();
    let mut by_release: HashMap<(&str, &str), Vec<&lpm_lockfile::LockedPackage>> = HashMap::new();
    let matches_by_release =
        (0..packages.len()).any(|index| checked(index) && packages[index].instance_id.is_none());
    for locked in lockfile.iter().flat_map(|lockfile| &lockfile.packages) {
        if let Some(instance) = locked.instance_id {
            by_instance.insert(instance, locked);
        }
        if matches_by_release {
            by_release
                .entry((locked.name.as_str(), locked.version.as_str()))
                .or_default()
                .push(locked);
        }
    }
    packages
        .iter()
        .enumerate()
        .map(|(index, package)| {
            checked(index).then(|| {
                let locked: Vec<&lpm_lockfile::LockedPackage> = match package.instance_id {
                    Some(instance) => by_instance.get(&instance).copied().into_iter().collect(),
                    None => by_release
                        .get(&(package.name.as_str(), package.version.as_str()))
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|locked| {
                            package.integrity.is_none() || locked.integrity == package.integrity
                        })
                        .collect(),
                };
                super::checks::npm_release(package, &locked)
            })
        })
        .collect()
}

/// The workspace root's direct dependencies, which `:workspace-root >`
/// selects in every importer: by graph instance, or, where the lockfile has
/// no instances, by the release a root name resolves to or by name at the
/// top of `node_modules`.
#[derive(Default)]
struct RootDependencies {
    releases: RootReleases,
    names: HashSet<String>,
}

impl RootDependencies {
    fn of(root: Option<&Importer>) -> Self {
        let Some(root) = root else {
            return Self::default();
        };
        Self {
            releases: RootReleases::of(root, |name, resolution| {
                resolution.instance_id.is_some() || root.root_dependency_names.contains(name)
            }),
            names: root.root_dependency_names.clone(),
        }
    }

    fn selects(&self, package: &DiscoveredPackage) -> bool {
        self.releases.holds_at_top(package, &self.names)
    }
}

/// The releases an importer's lockfile installs at its root under the names
/// a filter accepts: by graph instance, and, for a lockfile without
/// instances, by name and version, whatever name the root gives them.
#[derive(Default)]
struct RootReleases {
    instances: HashSet<lpm_common::PackageInstanceId>,
    /// Package name to versions, for root resolutions without instances.
    legacy: HashMap<String, Vec<String>>,
    /// Every local name the lockfile resolves at the root, accepted or not.
    resolved: HashSet<String>,
}

impl RootReleases {
    fn of(
        importer: &Importer,
        accepts: impl Fn(&str, &lpm_lockfile::LockedRootResolution) -> bool,
    ) -> Self {
        importer
            .inventory
            .discovery
            .retained_lpm_lockfile()
            .map(|lockfile| Self::from_resolutions(&lockfile.root_resolutions, accepts))
            .unwrap_or_default()
    }

    fn from_resolutions(
        resolutions: &lpm_lockfile::RootResolutions,
        accepts: impl Fn(&str, &lpm_lockfile::LockedRootResolution) -> bool,
    ) -> Self {
        let mut releases = Self::default();
        for (name, resolution) in resolutions {
            releases.resolved.insert(name.clone());
            if !accepts(name, resolution) {
                continue;
            }
            match resolution.instance_id {
                Some(instance) => {
                    releases.instances.insert(instance);
                }
                None => releases
                    .legacy
                    .entry(resolution.package.clone())
                    .or_default()
                    .push(resolution.version.clone()),
            }
        }
        releases
    }

    #[inline]
    fn holds(&self, package: &DiscoveredPackage) -> bool {
        self.holds_release(package.instance_id, &package.name, &package.version)
    }

    /// [`Self::holds`], or, for a package without an instance at the top of
    /// `node_modules` under a local name in `names` that the lockfile
    /// doesn't resolve at the root, whether it sits there: a lockfile that
    /// resolves the name says which release the root installs under it.
    fn holds_at_top(&self, package: &DiscoveredPackage, names: &HashSet<String>) -> bool {
        self.holds(package)
            || package.instance_id.is_none()
                && package
                    .path
                    .strip_prefix("node_modules/")
                    .is_some_and(|local| names.contains(local) && !self.resolved.contains(local))
    }

    fn holds_release(
        &self,
        instance: Option<lpm_common::PackageInstanceId>,
        name: &str,
        version: &str,
    ) -> bool {
        match instance {
            Some(instance) => self.instances.contains(&instance),
            None => self
                .legacy
                .get(name)
                .is_some_and(|versions| versions.iter().any(|held| held == version)),
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

/// The ancestors of `from` in `graph`, by graph key.
fn ancestors<'a>(
    graph: &DepGraph<'a>,
    from: impl IntoIterator<Item = &'a str>,
) -> HashSet<&'a str> {
    let mut stack: Vec<&str> = from.into_iter().collect();
    let mut seen: HashSet<&str> = HashSet::new();
    while let Some(key) = stack.pop() {
        for parent in graph.parents.get(key).into_iter().flatten() {
            if seen.insert(parent) {
                stack.push(parent);
            }
        }
    }
    seen
}

/// The problem naming the LPM.dev parents without LPM's record of what their
/// installed versions ship, if there are any.
fn unreviewed_parents(unreviewed: &BTreeSet<String>) -> Option<String> {
    const SHOWN: usize = 5;
    if unreviewed.is_empty() {
        return None;
    }
    let mut listed = unreviewed
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if unreviewed.len() > SHOWN {
        listed.push_str(&format!(" and {} more", unreviewed.len() - SHOWN));
    }
    Some(format!(
        "LPM has no record of the reviewed skills of {listed} on this machine (LPM.dev serves them, and LPM fetches them only for direct dependencies), so selectors that look at what they ship stay undecided"
    ))
}

/// Decides every skill one importer's installed packages ship, and the
/// reviewed sets whose packages it didn't install, against that importer's
/// dependency graph and the security verdicts LPM keeps.
fn decide_importer(
    importer: &Importer,
    importer_index: usize,
    scanned: &Scanned,
    scope: &Scope<'_>,
    root: &RootDependencies,
    decided: &mut Vec<Decided>,
    judged: &mut Judged,
) {
    let inventory = &importer.inventory;
    let packages = &inventory.discovery.packages;
    let declared = importer.declared_instances();
    let Scanned {
        skills,
        shipped,
        sets,
        orphans,
        releases,
        ..
    } = scanned;
    if skills.iter().all(Vec::is_empty) && orphans.is_empty() && scanned.unlisted.is_empty() {
        return;
    }
    let skill_names: Vec<Vec<String>> = skills
        .iter()
        .map(|skills| skills.iter().map(|(name, _)| name.clone()).collect())
        .collect();

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
                Shipped::Names(names) => Some(names),
                Shipped::Unknown => None,
            },
            skill: None,
            malware: if is_lpm_dev(&package.name) {
                Some(false)
            } else {
                malware_verdict(scope, releases[index].as_ref())
            },
        })
        .collect();
    let all_packages: HashMap<&str, PackageContext<'_>> = graph_keys
        .iter()
        .copied()
        .zip(contexts.iter())
        .map(|(key, context)| (key, copy_context(context)))
        .collect();

    if scope
        .policy
        .allow
        .iter()
        .chain(&scope.policy.deny)
        .any(|entry| reads_parents(&entry.selector))
    {
        let index_of: HashMap<&str, usize> = graph_keys
            .iter()
            .copied()
            .enumerate()
            .map(|(index, key)| (key, index))
            .collect();
        let reached = skill_names
            .iter()
            .enumerate()
            .filter(|(_, names)| !names.is_empty())
            .map(|(index, _)| index)
            .chain(scanned.unlisted.iter().map(|&(_, _, index)| index))
            .map(|index| graph_keys[index]);
        for key in ancestors(&graph, reached) {
            let Some(&index) = index_of.get(key) else {
                continue;
            };
            let package = &packages[index];
            let release = format!("{}@{}", package.name, package.version);
            if package.installed == Some(crate::commands::audit::discovery::Installation::Unknown) {
                judged.unconfirmed.insert(release);
            } else if scope.reads_others
                && is_lpm_dev(&package.name)
                && !sets[index].is_some_and(|set| importer.sets[set].recorded)
            {
                judged.unreviewed.insert(release);
            }
        }
    }
    for &(_, _, index) in &scanned.unlisted {
        let package = &packages[index];
        let lpm_dev = is_lpm_dev(&package.name);
        let enabled = if lpm_dev {
            scope.enabled.lpm_dev
        } else {
            scope.enabled.other
        };
        if !enabled {
            continue;
        }
        let automatic = lpm_dev
            && sets[index].is_some_and(|set| {
                importer.declares(package, &declared) || importer.delivered_by_add(set)
            });
        let set = sets[index].map(|set| &importer.sets[set]);
        for (skill, requires) in scope.recorded.get(&package.name).into_iter().flatten() {
            let mut candidate = copy_context(&contexts[index]);
            candidate.skill = Some(skill);
            let ruling = decide(
                scope.policy,
                &candidate,
                graph_keys[index],
                &graph,
                &all_packages,
                automatic_naming(automatic, set, skill),
            );
            let allows = match ruling.decision {
                Decision::Allowed(naming) => naming >= *requires,
                Decision::Unknown => ruling.possible_naming >= *requires,
                Decision::NotAllowed | Decision::Denied => false,
            };
            if allows {
                judged
                    .unlisted_allows
                    .entry(package.name.clone())
                    .or_default()
                    .insert(skill.clone());
            }
        }
    }
    for (index, context) in contexts.iter().enumerate() {
        let lpm_dev = is_lpm_dev(context.name);
        let enabled = if lpm_dev {
            scope.enabled.lpm_dev
        } else {
            scope.enabled.other
        };
        let automatic = lpm_dev
            && sets[index].is_some_and(|set| {
                importer.declares(&packages[index], &declared) || importer.delivered_by_add(set)
            });
        let set = sets[index].map(|set| &importer.sets[set]);
        for (skill, origin) in &skills[index] {
            let mut candidate = copy_context(context);
            candidate.skill = Some(skill);
            let ruling = if enabled {
                decide(
                    scope.policy,
                    &candidate,
                    graph_keys[index],
                    &graph,
                    &all_packages,
                    automatic_naming(automatic, set, skill),
                )
            } else {
                Ruling::NOT_ALLOWED
            };
            decided.push(Decided {
                importer: importer_index,
                package: Some(index),
                set: sets[index],
                skill: skill.clone(),
                origin: *origin,
                decision: ruling.decision,
                open_denials: ruling.open_denials,
                possible_naming: ruling.possible_naming,
                direct: graph.root_deps.contains(graph_keys[index]),
            });
        }
    }
    for &set_index in orphans {
        let set = &importer.sets[set_index];
        let names: Vec<String> = set.skills.iter().map(|skill| skill.name.clone()).collect();
        let context = PackageContext {
            name: &set.package,
            version: &set.version,
            path: "",
            analysis: None,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
            skills: Some(&names),
            skill: None,
            malware: Some(false),
        };
        for (index, skill) in names.iter().enumerate() {
            let mut candidate = copy_context(&context);
            candidate.skill = Some(skill);
            let ruling = if scope.enabled.lpm_dev {
                decide(
                    scope.policy,
                    &candidate,
                    "",
                    &graph,
                    &all_packages,
                    automatic_naming(true, Some(set), skill),
                )
            } else {
                Ruling::NOT_ALLOWED
            };
            decided.push(Decided {
                importer: importer_index,
                package: None,
                set: Some(set_index),
                skill: skill.clone(),
                origin: Origin::Reviewed(index),
                decision: ruling.decision,
                open_denials: ruling.open_denials,
                possible_naming: ruling.possible_naming,
                direct: true,
            });
        }
    }
}

/// What the security provider's verdict says to a `:malware` selector
/// about the package whose npm release is `release`: `None` without a
/// decided verdict for exactly that release.
fn malware_verdict(
    scope: &Scope<'_>,
    release: Option<&Result<(String, String), String>>,
) -> Option<bool> {
    let (name, version) = release?.as_ref().ok()?;
    match scope.book?.entry(name, version)?.verdict {
        super::socket::Verdict::Clean => Some(false),
        super::socket::Verdict::Malware { .. } => Some(true),
        super::socket::Verdict::Pending | super::socket::Verdict::Unknown => None,
    }
}

/// Why the skills of a package behind an entry LPM couldn't inspect aren't
/// linked anew.
const UNCERTAIN_INSTALL: &str = "an entry on its way in node_modules couldn't be inspected, so LPM can't tell whether this install holds it";

/// What a package's selector facts know of the skills it ships.
enum Shipped {
    /// The names it lists for candidates.
    Listed,
    /// These names, read only for the selectors: the policy reads what
    /// other packages ship, but can't link this one's.
    Names(Vec<String>),
    /// Nothing the facts can rely on: its skills weren't read, couldn't be
    /// listed, or come from a release whose install is uncertain.
    Unknown,
}

/// Why listing one installed package's skills failed.
enum ListFailure {
    /// Whether the importer installed the release, which ships skills, is
    /// unknown: nothing new links from it, and earlier copies stay.
    Uncertain,
    /// It couldn't be read now: the earlier copies stay and the next run
    /// reads it again.
    Unreadable(std::io::Error),
    /// It breaks a rule the same way every time.
    Refused(std::io::Error),
    /// A package read only for the selectors that look at the skills other
    /// packages ship couldn't be read now: those selectors stay undecided
    /// and the next run reads it again.
    FactsUnreadable(std::io::Error),
    /// Such a package breaks a rule the same way every time.
    FactsRefused(std::io::Error),
}

impl ListFailure {
    /// The failure for a package read only for the selectors.
    fn for_facts(self) -> Self {
        match self {
            Self::Unreadable(error) | Self::FactsUnreadable(error) => Self::FactsUnreadable(error),
            Self::Refused(error) | Self::FactsRefused(error) => Self::FactsRefused(error),
            Self::Uncertain => Self::Uncertain,
        }
    }
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

impl Ruling {
    const NOT_ALLOWED: Self = Self {
        decision: Decision::NotAllowed,
        open_denials: 0,
        possible_naming: Naming::None,
    };
}

/// Decides one skill: a matching `deny` entry wins; otherwise it is
/// allowed as specifically as the allowing entries name it. `automatic`
/// allows it with no entry, as LPM.dev dependencies are, as specifically as
/// [`automatic_naming`] says.
fn decide(
    policy: &SkillsPolicy,
    candidate: &PackageContext<'_>,
    key: &str,
    graph: &DepGraph<'_>,
    all_packages: &HashMap<&str, PackageContext<'_>>,
    automatic: Option<Naming>,
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
    if let Some(automatic) = automatic {
        allowed = Truth::True;
        naming = naming.max(automatic);
        possible_naming = possible_naming.max(automatic);
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

/// How specifically an LPM.dev skill that links with no entry is named: at
/// its package's level, unless review served it with a warning, so only an
/// entry that names the package links it.
fn automatic_naming(
    automatic: bool,
    set: Option<&super::lpm_dev::ReviewedSet>,
    skill: &str,
) -> Option<Naming> {
    automatic.then(|| {
        if set.is_some_and(|set| set.review_warned(skill)) {
            Naming::None
        } else {
            Naming::Package
        }
    })
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
    identity_of: &impl Fn(&Decided) -> (&'a str, &'a str),
) -> HashSet<usize> {
    let mut best: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let rank = |entry: &Decided| {
        (
            matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown),
            entry.direct,
            lpm_semver::Version::parse(identity_of(entry).1).ok(),
        )
    };
    for (position, entry) in decided.iter().enumerate() {
        let name = identity_of(entry).0;
        let slot = best.entry((name, entry.skill.as_str())).or_insert(position);
        if rank(entry) > rank(&decided[*slot]) {
            *slot = position;
        }
    }
    best.into_values().collect()
}

/// Skill names that more than one `contesting` package the policy allows,
/// or may allow once data arrives, ships, with the packages. A package the
/// security provider holds back doesn't contest, since its skill doesn't
/// link, unless only its clean verdict's age holds it: which package links
/// a name never depends on how old a verdict is.
fn name_conflicts<'a>(
    decided: &[Decided],
    preferred: &HashSet<usize>,
    contesting: &[bool],
    identity_of: &impl Fn(&Decided) -> (&'a str, &'a str),
) -> HashMap<String, Vec<String>> {
    let mut providers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (position, entry) in decided.iter().enumerate() {
        if preferred.contains(&position)
            && contesting[position]
            && matches!(entry.decision, Decision::Allowed(_) | Decision::Unknown)
        {
            let names = providers.entry(entry.skill.as_str()).or_default();
            let package = identity_of(entry).0;
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

/// Who vouches for the content of `entry`'s skill.
fn review_of<'a>(importers: &'a [Importer], entry: &Decided) -> Review<'a> {
    let (package, _, _) = identity(importers, entry);
    let set = entry.set.map(|set| &importers[entry.importer].sets[set]);
    match (entry.origin, set) {
        (Origin::Reviewed(index), Some(set)) => match &set.skills[index].document {
            Err(problem) => Review::Unusable(problem),
            Ok(document) if set.skills[index].verified => {
                Review::Reviewed(document, set.skills[index].warning.as_deref())
            }
            Ok(document) => Review::Unverified(document),
        },
        (Origin::Directory, _) if is_lpm_dev(package) => {
            let skill = entry.skill.as_str();
            Review::Directory(set.and_then(|set| {
                Some(Approved {
                    digest: set.directories.get(skill)?,
                    warning: set.directory_warnings.get(skill).map(Vec::as_slice),
                })
            }))
        }
        _ => Review::Local,
    }
}

/// Who vouches for a skill's content.
#[derive(Debug, Clone, Copy)]
enum Review<'a> {
    /// No registry review: LPM's checks and scan decide, here.
    Local,
    /// An LPM.dev package's `skills/<name>/`: what LPM.dev review approved
    /// of it, if anything.
    Directory(Option<Approved<'a>>),
    /// An LPM.dev package's flat skill, reviewed: its linked document, and
    /// what review warned about.
    Reviewed(&'a str, Option<&'a [SkillReviewIssue]>),
    /// An LPM.dev package's flat skill whose review LPM has no record of on
    /// this machine: its linked document.
    Unverified(&'a str),
    /// An LPM.dev package's flat skill that can't link: why.
    Unusable(&'a str),
}

/// The files LPM.dev review approved for a skill directory, by digest, and
/// what it warned about when it served them with a warning.
#[derive(Debug, Clone, Copy)]
struct Approved<'a> {
    digest: &'a str,
    warning: Option<&'a [SkillReviewIssue]>,
}

impl<'a> Review<'a> {
    /// What LPM.dev review warned about in the content it approved.
    fn warning(self) -> Option<&'a [SkillReviewIssue]> {
        match self {
            Review::Reviewed(_, warning) => warning,
            Review::Directory(approved) => approved?.warning,
            Review::Local | Review::Unverified(_) | Review::Unusable(_) => None,
        }
    }
}

/// Why a skill whose decision waits on data is held.
const UNDECIDED: &str = "a selector reads data this package lacks: a behavioral analysis, a security verdict, or the skills of a package LPM couldn't list";

/// Why a skill an undecided entry may name specifically enough is held.
const UNDECIDED_NAMING: &str = "an allowing entry that names it as specifically as it needs reads data this package lacks: a behavioral analysis, a security verdict, or the skills of a package LPM couldn't list";

/// [`prepare_fully`], held when the allowing entries name the skill less
/// specifically than `naming` it needs.
fn prepare(
    directory: Option<&cap_std::fs::Dir>,
    package: &str,
    skill: &str,
    naming: Naming,
    review: Review<'_>,
) -> (CandidateStatus, Option<SkillDetails>) {
    let (status, details) = prepare_fully(directory, package, skill, review);
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
    let detail = if prepared.permission == SkillPermission::None && details.review_warning.is_some()
    {
        format!(
            "LPM.dev review warned about it; allow `{}` to link it",
            details.suggested
        )
    } else if prepared.permission == SkillPermission::None {
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

/// Reads and checks one skill of `package` as if an entry named it fully:
/// what it ships, what it pre-approves, and anything that keeps it out.
/// LPM.dev review stands in for the scan: a reviewed skill's findings are
/// reported, not held, but its structure, hooks and grants follow the same
/// rules.
fn prepare_fully(
    directory: Option<&cap_std::fs::Dir>,
    package: &str,
    skill: &str,
    review: Review<'_>,
) -> (CandidateStatus, Option<SkillDetails>) {
    let entries = match review {
        Review::Unusable(problem) => return (held(HoldReason::Invalid, problem), None),
        Review::Reviewed(document, _) | Review::Unverified(document) => vec![SkillDirectoryEntry {
            path: lpm_skill::SKILL_DOCUMENT.to_string(),
            kind: lpm_skill::SkillEntryKind::File,
            size: document.len() as u64,
            content: Some(document.as_bytes().to_vec()),
        }],
        Review::Local | Review::Directory(_) => {
            let Some(directory) = directory else {
                return (
                    held(
                        HoldReason::Unreadable,
                        format!("{package} could not be opened"),
                    ),
                    None,
                );
            };
            match read_skill_directory(directory, skill) {
                Ok(entries) => entries,
                Err(error) => return (held(HoldReason::Unreadable, error.to_string()), None),
            }
        }
    };
    let checked = match check_skill_directory(skill, &entries) {
        Ok(checked) => checked,
        Err(errors) => return (held(HoldReason::Invalid, errors.join("; ")), None),
    };
    let permission = checked.permission();
    let reviewed = !matches!(review, Review::Local);
    let review_warning = review.warning();
    let required = match permission {
        SkillPermission::Broad => Naming::Skill,
        SkillPermission::Hooks => Naming::Package,
        SkillPermission::None if review_warning.is_some() => Naming::Package,
        SkillPermission::None if checked.has_warnings() && !reviewed => Naming::Package,
        SkillPermission::None => Naming::None,
    };
    let suggested = if required == Naming::Skill {
        format!("#{package}:skill({skill})")
    } else {
        format!("#{package}")
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
        review_warning: review_warning.map(<[SkillReviewIssue]>::to_vec),
        suggested,
        requires: required,
    };
    if let Review::Unverified(_) = review {
        return (
            held(
                HoldReason::NotReviewed,
                "LPM has no record of LPM.dev's review of this version on this machine; an install with LPM.dev package skills on fetches it",
            ),
            Some(details),
        );
    }
    if let Review::Directory(approved) = review
        && approved.map(|approved| approved.digest) != Some(checked.digest.as_str())
    {
        let detail = if approved.is_some() {
            format!("LPM.dev review approved other files for `skills/{skill}/` in this version")
        } else {
            format!("LPM.dev hasn't reviewed `skills/{skill}/` in this version")
        };
        return (held(HoldReason::NotReviewed, detail), Some(details));
    }
    if !reviewed && checked.is_blocked() {
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
    let mut names = installed_dependency_names(manifest);
    if let Some(entries) = manifest
        .get("peerDependencies")
        .and_then(serde_json::Value::as_object)
    {
        names.extend(entries.keys().cloned());
    }
    names
}

/// The names a manifest declares dependencies under that an install puts
/// in place for it: never its own `peerDependencies`, which a consumer
/// provides.
fn installed_dependency_names(manifest: &serde_json::Value) -> HashSet<String> {
    let mut names = HashSet::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
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
    fn a_command_hold_names_a_flagged_instance_first_then_an_uncheckable_one_then_a_waiting_one() {
        let now_ms = super::super::checks::now_ms();
        let observed = |verdict| super::super::socket::Observed {
            verdict,
            at_ms: now_ms,
        };
        let mut book = super::super::checks::Book::default();
        book.absorb(&super::super::socket::Answers {
            verdicts: HashMap::from([
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
            at_ms: now_ms,
        });
        let policy = SkillsPolicy {
            allow: Vec::new(),
            deny: Vec::new(),
            targets: super::super::policy::Targets::Auto,
            deny_unreadable: false,
        };
        let scope = Scope {
            policy: &policy,
            mode: PlanMode::Apply,
            enabled: Sources {
                lpm_dev: true,
                other: true,
                provider: SecurityProvider::Socket,
                offline: false,
            },
            read: Sources {
                lpm_dev: true,
                other: true,
                provider: SecurityProvider::Socket,
                offline: false,
            },
            named: None,
            only: None,
            reads_others: false,
            recorded: &RecordedSkills::new(),
            book: Some(&book),
            reads_malware: false,
        };
        let install = |version: &str, checkable: bool| PackageInstall {
            version: version.to_string(),
            integrity: None,
            release: checkable.then(|| ("tool".to_string(), version.to_string())),
        };
        let reason = |installs: &[PackageInstall]| {
            command_hold(&scope, "tool", installs).map(|(reason, _)| reason)
        };

        let clean = install("1.0.0", true);
        let unanswered = install("2.0.0", true);
        let flagged = install("3.0.0", true);
        let patched = install("4.0.0", false);
        assert_eq!(reason(std::slice::from_ref(&clean)), None);
        assert_eq!(
            reason(&[clean.clone(), unanswered.clone()]),
            Some(HoldReason::AwaitingCheck)
        );
        assert_eq!(
            reason(&[unanswered.clone(), patched.clone()]),
            Some(HoldReason::NotCheckable)
        );
        assert_eq!(
            reason(&[unanswered, patched, flagged, clean.clone()]),
            Some(HoldReason::Malware)
        );

        let mut unverified = super::super::checks::Book::default().merged_with(book.clone());
        unverified.note_refresh_failed();
        assert!(
            command_hold(&scope, "tool", std::slice::from_ref(&clean)).is_none(),
            "Socket answered for it during this run"
        );
        let scope = Scope {
            book: Some(&unverified),
            ..scope
        };
        assert_eq!(
            command_hold(&scope, "tool", std::slice::from_ref(&clean)).map(|(reason, _)| reason),
            Some(HoldReason::AwaitingCheck),
            "a verdict the shared cache couldn't be read to confirm no longer vouches for a command"
        );
    }

    #[test]
    fn a_legacy_root_release_counts_under_every_name_the_root_installs_it_under() {
        let root = |package: &str| lpm_lockfile::LockedRootResolution {
            package: package.to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        let resolutions = lpm_lockfile::RootResolutions::from([
            ("ui".to_string(), root("@lpm.dev/acme.ui")),
            ("@lpm.dev/acme.ui".to_string(), root("@lpm.dev/acme.ui")),
            ("peer".to_string(), root("peer")),
        ]);

        let declared = RootReleases::from_resolutions(&resolutions, |name, _| name == "ui");

        assert!(declared.holds_release(None, "@lpm.dev/acme.ui", "1.0.0"));
        assert!(!declared.holds_release(None, "@lpm.dev/acme.ui", "2.0.0"));
        assert!(!declared.holds_release(None, "peer", "1.0.0"));
    }

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
            None,
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
                None,
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
    fn a_legacy_lockfile_infers_a_root_dependency_from_its_path_only_for_names_it_doesnt_resolve() {
        let resolutions = lpm_lockfile::RootResolutions::from([(
            "tool".to_string(),
            lpm_lockfile::LockedRootResolution {
                package: "tool".to_string(),
                version: "1.0.0".to_string(),
                ..Default::default()
            },
        )]);
        let roots = RootDependencies {
            releases: RootReleases::from_resolutions(&resolutions, |_, _| true),
            names: HashSet::from(["tool".to_string(), "other".to_string()]),
        };
        let mut newer = discovered("tool");
        newer.version = "2.0.0".to_string();
        let mut aliased = discovered("@acme/other");
        aliased.path = "node_modules/other".to_string();

        assert!(roots.selects(&discovered("tool")));
        assert!(
            !roots.selects(&newer),
            "the root resolves tool to 1.0.0, so a 2.0.0 at node_modules/tool is a member's"
        );
        assert!(
            roots.selects(&aliased),
            "a name the root doesn't resolve is inferred from where it sits"
        );
        assert!(!roots.selects(&discovered("stray")));
    }

    #[test]
    fn a_provider_whose_decision_lacks_data_still_contends_for_its_skill_name() {
        let packages = [discovered("a"), discovered("b")];
        let decided = vec![
            Decided {
                importer: 0,
                package: Some(0),
                set: None,
                skill: "guide".into(),
                origin: Origin::Directory,
                decision: Decision::Allowed(Naming::Package),
                open_denials: 0,
                possible_naming: Naming::Package,
                direct: true,
            },
            Decided {
                importer: 0,
                package: Some(1),
                set: None,
                skill: "guide".into(),
                origin: Origin::Directory,
                decision: Decision::Unknown,
                open_denials: 0,
                possible_naming: Naming::None,
                direct: true,
            },
        ];
        let preferred: HashSet<usize> = [0, 1].into_iter().collect();
        let identity_of = |entry: &Decided| {
            let package = &packages[entry.package.unwrap()];
            (package.name.as_str(), package.version.as_str())
        };
        let conflicts = name_conflicts(&decided, &preferred, &[true, true], &identity_of);
        assert_eq!(
            conflicts.get("guide").map(Vec::as_slice),
            Some(["a".to_string(), "b".to_string()].as_slice())
        );

        assert!(name_conflicts(&decided, &preferred, &[true, false], &identity_of).is_empty());
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
