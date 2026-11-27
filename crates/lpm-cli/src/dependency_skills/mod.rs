//! Agent Skills that installed dependencies ship as `skills/<name>/SKILL.md`
//! directories, and the links that show the ones a project allows to coding
//! agents.
//!
//! A project allows skills with selectors in `package.json > lpm > skills`.
//! Installs plan which installed skills those select, check and scan each
//! one, copy the checked bytes to `.lpm/linked-skills/<skill>`, and link
//! that copy into `.agents/skills` (and `.claude/skills` when the project
//! has `.claude`). LPM only replaces or removes entries it can prove it made,
//! keeps its links out of Git through the repository's local exclude file,
//! and records what it linked in `.lpm/linked-skills/state.json`.

mod apply;
mod checks;
mod discovery;
mod edit;
mod git_exclude;
mod inspect;
mod links;
mod lpm_dev;
mod plan;
mod policy;
mod snapshot;
mod socket;
mod state;
#[cfg(test)]
mod tests;

pub(crate) use apply::{ReconcileReport, SkillChange};
pub(crate) use checks::credentials_changed as socket_credentials_changed;
pub(crate) use discovery::{read_skill_directory, skill_directory_names};
pub(crate) use edit::{ManifestEdit, PolicyList};
pub(crate) use inspect::{
    InspectedSkill, Inspection, Inspector, PlannedChange, SkillStatus, drift, inspect_project,
};
pub(crate) use lpm_dev::review_warning_note;
pub(crate) use plan::read_manifest;
#[cfg(test)]
pub(crate) use plan::{HoldReason, Naming};
pub(crate) use plan::{InstanceRuling, SkillDetails, may_match_any};
pub(crate) use policy::validate_selector;
pub(crate) use socket::login_organization as socket_organization;
pub(crate) use state::{LinkKind, LinkedSkillRecord};

use crate::lpm_skills_config::LpmSkillsPreference;
use cap_fs_ext::DirExt as _;
use lpm_common::LpmError;
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Bumped when the rules that decide which skills link change, so that
/// every project reconciles again.
const RULES_VERSION: &str = "dependency-skills-2";

/// What this run does with dependency skills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settings {
    /// "LPM.dev package skills": link the reviewed skills of LPM.dev
    /// dependencies. Off, the links LPM made for them are removed.
    pub(crate) lpm_dev_packages: bool,
    /// "npm and other package skills": follow the project's allow-list.
    /// Off, the links LPM made are removed.
    pub(crate) other_packages: bool,
    /// Who checks the packages behind those skills before they link.
    pub(crate) security_provider: crate::lpm_skills_config::SecurityProvider,
    /// Whether the run is offline: the security provider isn't asked, and
    /// verdicts coming due don't count against the links.
    pub(crate) offline: bool,
    /// The dependency kinds the install left out, as `--prod` does. The
    /// same lockfile then installs fewer packages, so links reconciled
    /// under other omissions are reconciled again.
    pub(crate) omitted: crate::commands::install::InstallOmitPolicy,
}

impl Settings {
    /// `None` when the run skips skill work, as `--no-skills` does;
    /// `--skills` turns every kind on; otherwise the user's config decides.
    pub(crate) fn resolve(preference: LpmSkillsPreference) -> Result<Option<Self>, LpmError> {
        match preference {
            LpmSkillsPreference::Disabled => Ok(None),
            LpmSkillsPreference::Enabled => {
                let config = crate::commands::config::GlobalConfig::load_checked()?;
                Ok(Some(Self {
                    lpm_dev_packages: true,
                    other_packages: true,
                    security_provider: crate::lpm_skills_config::security_provider(&config)?,
                    offline: false,
                    omitted: Default::default(),
                }))
            }
            LpmSkillsPreference::Config => Ok(Some(Self::from_config(
                &crate::commands::config::GlobalConfig::load_checked()?,
            )?)),
        }
    }

    /// The user's skill settings in `config`.
    pub(crate) fn from_config(
        config: &crate::commands::config::GlobalConfig,
    ) -> Result<Self, LpmError> {
        Ok(Self {
            lpm_dev_packages: LpmSkillsPreference::Config.resolve(config)?,
            other_packages: crate::lpm_skills_config::other_package_skills_enabled(config)?,
            security_provider: crate::lpm_skills_config::security_provider(config)?,
            offline: false,
            omitted: Default::default(),
        })
    }

    fn sources(self) -> plan::Sources {
        plan::Sources {
            lpm_dev: self.lpm_dev_packages,
            other: self.other_packages,
            provider: self.security_provider,
            offline: self.offline,
        }
    }

    /// These settings for an install that left out `omitted`.
    pub(crate) fn omitting(self, omitted: crate::commands::install::InstallOmitPolicy) -> Self {
        Self { omitted, ..self }
    }

    /// The security provider's verdicts LPM keeps, when Socket checks npm
    /// packages.
    pub(crate) fn verdicts(self) -> Option<checks::Book> {
        (self.security_provider == crate::lpm_skills_config::SecurityProvider::Socket)
            .then(checks::Book::load)
    }

    /// These settings for a run that is `offline` or not.
    pub(crate) fn offline(self, offline: bool) -> Self {
        Self { offline, ..self }
    }
}

/// Whether the project's links already match its policy, its lockfile, the
/// reviewed LPM.dev skills its installs materialized and these settings,
/// and are intact, so an install can skip reconciling. Reads nothing past
/// the manifest when LPM linked nothing and nothing could link.
///
/// A policy with problems is never ready, so every install warns until it
/// is fixed. Links a newer LPM recorded count as ready: this one leaves
/// them alone.
#[cfg(test)]
pub(crate) fn links_ready(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
) -> bool {
    !matches!(
        readiness(
            project_dir,
            manifest,
            settings,
            &[project_dir.to_path_buf()]
        ),
        Readiness::Stale
    )
}

enum Readiness {
    Ready,
    Stale,
    RecordedByNewer(String),
}

/// [`links_ready`]'s verdict, looking for materialized LPM.dev skills in
/// `importers` when LPM linked nothing yet.
fn readiness(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
    importers: &[PathBuf],
) -> Readiness {
    let parsed = policy::read_policy(manifest);
    let problems =
        (settings.lpm_dev_packages || settings.other_packages) && !parsed.problems.is_empty();
    let policy = parsed.policy;
    let ready = match state::read_state(project_dir) {
        state::StoredState::Newer(reason) => return Readiness::RecordedByNewer(reason),
        state::StoredState::Missing => {
            !problems && !could_link(policy.as_ref(), settings, importers)
        }
        state::StoredState::Unusable(_) => false,
        state::StoredState::Present(recorded) => {
            let importers = recorded_importers(project_dir, &recorded);
            let lockfile = lockfile_stamp(project_dir, recorded.lockfile.as_ref());
            let ready = !problems
                && recorded.fingerprint
                    == fingerprint(
                        project_dir,
                        policy.as_ref(),
                        settings,
                        lockfile.as_ref(),
                        &importers,
                    )
                && recorded.stale.is_empty()
                && !recheck_due(&recorded, settings)
                && links_intact(project_dir, &recorded);
            if ready
                && let Some(stamp) = lockfile
                && recorded.lockfile.as_ref() != Some(&stamp)
                && stamp_is_settled(&stamp)
            {
                keep_settled_stamp(project_dir, stamp);
            }
            ready
        }
    };
    if ready {
        Readiness::Ready
    } else {
        Readiness::Stale
    }
}

/// Whether the links are due to be reconciled for the security verdicts
/// they rest on: one expired, taking the copies it kept with it; the
/// verdict cache changed since they read it, as when another project
/// recorded a verdict or a failure that kept Socket from answering cleared;
/// or, online, one came due to be asked again.
fn recheck_due(recorded: &state::LinkState, settings: Settings) -> bool {
    if settings.security_provider != crate::lpm_skills_config::SecurityProvider::Socket {
        return false;
    }
    let now = checks::now_secs();
    if recorded.expires_at.is_some_and(|at| now >= at) {
        return true;
    }
    if recorded.recheck_at.is_some() && checks::cache_stamp() != Ok(recorded.verdicts_stamp) {
        return true;
    }
    if settings.offline {
        return false;
    }
    recorded.recheck_at.is_some_and(|at| now >= at)
}

/// Whether `policy` and `settings` could link anything in `importers`:
/// the policy allows packages and npm and other package skills are on, or
/// LPM.dev package skills are on and an install materialized some.
fn could_link(
    policy: Option<&policy::SkillsPolicy>,
    settings: Settings,
    importers: &[PathBuf],
) -> bool {
    if policy.is_some_and(|policy| policy.deny_unreadable) {
        return false;
    }
    (settings.other_packages && policy.is_some_and(policy::SkillsPolicy::is_active))
        || (settings.lpm_dev_packages
            && importers
                .iter()
                .any(|importer| lpm_dev::has_reviewed_sets(importer)))
}

/// The project directories a recorded reconcile followed: the project and
/// the workspace members it recorded.
fn recorded_importers(project_dir: &Path, recorded: &state::LinkState) -> Vec<PathBuf> {
    member_importers(project_dir, &recorded.members)
}

/// The project and `members`, project-relative, as the directories whose
/// LPM.dev skills the fingerprint covers. Reconciling and checking
/// readiness both build it from the recorded members, so a member the
/// state can't record never makes the two disagree.
fn member_importers(project_dir: &Path, members: &[String]) -> Vec<PathBuf> {
    std::iter::once(project_dir.to_path_buf())
        .chain(
            members
                .iter()
                .map(|member| links::project_path(project_dir, member)),
        )
        .collect()
}

/// [`links_ready`] from the manifest's text, for the install fast lanes,
/// whose installs may have materialized LPM.dev skills in any of
/// `importers`: the project, or a workspace root and its members, which the
/// caller already knows. A manifest that never mentions `"skills"` where
/// LPM linked nothing and no importer holds LPM.dev skills is ready without
/// parsing.
pub(crate) fn links_ready_for_manifest_text(
    project_dir: &Path,
    manifest: &str,
    settings: Settings,
    importers: &[PathBuf],
) -> bool {
    if !may_name_skills(manifest)
        && !state::state_exists(project_dir)
        && !(settings.lpm_dev_packages
            && importers
                .iter()
                .any(|importer| lpm_dev::has_reviewed_sets(importer)))
    {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(manifest)).is_ok_and(
        |manifest| {
            !matches!(
                readiness(project_dir, &manifest, settings, importers),
                Readiness::Stale
            )
        },
    )
}

/// Whether every recorded skill's copy still holds the bytes LPM checked,
/// each of its entries is still LPM's, and each target entry that was
/// taken is still taken.
fn links_intact(project_dir: &Path, recorded: &state::LinkState) -> bool {
    let mut directories: std::collections::BTreeMap<&str, Option<links::TargetDir>> =
        std::collections::BTreeMap::new();
    for record in recorded.skills.values() {
        for link in &record.links {
            if let Some((target, _)) = link.path.rsplit_once('/') {
                directories
                    .entry(target)
                    .or_insert_with(|| links::TargetDir::open(project_dir, target).ok().flatten());
            }
        }
    }
    recorded.skills.iter().all(|(skill, record)| {
        snapshot::snapshot_digest(project_dir, skill).as_deref() == Some(record.digest.as_str())
            && record.links.iter().all(|link| {
                link.path
                    .rsplit_once('/')
                    .and_then(|(target, _)| directories.get(target)?.as_ref())
                    .is_some_and(|directory| {
                        directory
                            .inspect(project_dir, skill)
                            .is_intact(link.kind, &record.digest)
                    })
            })
            && record
                .blocked
                .iter()
                .all(|path| still_blocked(project_dir, skill, path))
    })
}

/// Whether linking `skill` at `path`, a target entry that was taken or
/// couldn't be made, would still be refused: something still holds it, or
/// its directory still can't be reached through plain directories.
fn still_blocked(project_dir: &Path, skill: &str, path: &str) -> bool {
    let Some((target, _)) = path.rsplit_once('/') else {
        return false;
    };
    match links::TargetDir::open(project_dir, target) {
        Err(_) => true,
        Ok(None) => false,
        Ok(Some(directory)) => directory.inspect(project_dir, skill) != links::TargetEntry::Missing,
    }
}

/// The absolute paths of the target entries LPM linked dependency skills
/// at, so inventories of agent folders don't count them as unmanaged.
pub(crate) fn linked_entry_paths(project_dir: &Path) -> Vec<std::path::PathBuf> {
    match state::read_state(project_dir) {
        state::StoredState::Present(recorded) => recorded
            .skills
            .values()
            .flat_map(|record| record.links.iter())
            .map(|link| links::project_path(project_dir, &link.path))
            .collect(),
        _ => Vec::new(),
    }
}

/// A dependency skill LPM linked, read back from its copy.
pub(crate) struct LinkedSkillDetails {
    pub(crate) name: String,
    pub(crate) record: LinkedSkillRecord,
    pub(crate) copy: std::path::PathBuf,
    /// The copy checked again as installs check skills; `None` when it
    /// can't be read, no longer passes, or no longer holds the bytes LPM
    /// linked.
    pub(crate) checked: Option<lpm_skill::CheckedSkill>,
    /// Each recorded entry, with whether it is still LPM's and still shows
    /// the copy.
    pub(crate) links: Vec<(state::LinkRecord, bool)>,
    /// What LPM.dev review warned about when it approved the copy.
    pub(crate) review_warning: Option<Vec<lpm_registry::SkillReviewIssue>>,
}

impl LinkedSkillDetails {
    /// The copy holds what LPM linked and every entry still shows it.
    pub(crate) fn healthy(&self) -> bool {
        self.checked.is_some() && self.links.iter().all(|(_, intact)| *intact)
    }
}

/// Every dependency skill LPM linked in the project, each copy checked
/// again with the strict rules installs apply.
pub(crate) fn linked_skill_details(project_dir: &Path) -> Vec<LinkedSkillDetails> {
    let state::StoredState::Present(recorded) = state::read_state(project_dir) else {
        return Vec::new();
    };
    let root = state::open_root(project_dir).ok().flatten();
    let mut directories: std::collections::BTreeMap<String, Option<links::TargetDir>> =
        std::collections::BTreeMap::new();
    recorded
        .skills
        .into_iter()
        .map(|(name, record)| {
            let checked = root
                .as_ref()
                .and_then(|root| root.open_dir_nofollow(&name).ok())
                .and_then(|copy| discovery::read_skill_tree(&copy).ok())
                .and_then(|entries| lpm_skill::check_skill_directory(&name, &entries).ok())
                .filter(|checked| checked.digest == record.digest);
            let links = record
                .links
                .iter()
                .map(|link| {
                    let intact = link.path.rsplit_once('/').is_some_and(|(target, _)| {
                        directories
                            .entry(target.to_string())
                            .or_insert_with(|| {
                                links::TargetDir::open(project_dir, target).ok().flatten()
                            })
                            .as_ref()
                            .is_some_and(|directory| {
                                directory
                                    .inspect(project_dir, &name)
                                    .is_intact(link.kind, &record.digest)
                            })
                    });
                    (link.clone(), intact)
                })
                .collect();
            let review_warning = record.reviewed_by.as_deref().and_then(|registry| {
                lpm_dev::recorded_review_warning(
                    registry,
                    &record.package,
                    &record.version,
                    &name,
                    &record.digest,
                )
            });
            LinkedSkillDetails {
                copy: state::snapshot_dir(project_dir, &name),
                name,
                record,
                checked,
                links,
                review_warning,
            }
        })
        .collect()
}

/// The dependency skill LPM linked at `path`, an entry in one of the
/// project's targets: its name and package.
pub(crate) fn linked_entry_owner(project_dir: &Path, path: &Path) -> Option<(String, String)> {
    let state::StoredState::Present(recorded) = state::read_state(project_dir) else {
        return None;
    };
    recorded.skills.into_iter().find_map(|(skill, record)| {
        record
            .links
            .iter()
            .any(|link| links::project_path(project_dir, &link.path) == path)
            .then_some((skill, record.package))
    })
}

/// Every dependency skill LPM linked in the project.
pub(crate) fn linked_skills(project_dir: &Path) -> Vec<(String, LinkedSkillRecord)> {
    match state::read_state(project_dir) {
        state::StoredState::Present(recorded) => recorded.skills.into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Points out the skills that `packages`, just installed into
/// `project_dir` by name, ship and the project could link but doesn't, with
/// the entries that link them. LPM.dev packages are left out: their
/// reviewed skills link without an entry. Prints nothing when the run skips
/// skill work or the user turned these skills off, and reads nothing more
/// when none of `packages` ships a skill.
pub(crate) fn print_unlinked_skill_hints(
    project_dir: &Path,
    packages: &[&str],
    preference: LpmSkillsPreference,
) {
    let Ok(Some(settings)) = Settings::resolve(preference) else {
        return;
    };
    if !settings.other_packages {
        return;
    }
    let shipping: std::collections::HashSet<String> = packages
        .iter()
        .filter(|package| !plan::is_lpm_dev(package) && ships_skills(project_dir, package))
        .map(|package| (*package).to_string())
        .collect();
    if shipping.is_empty() {
        return;
    }
    let root = skills_root(project_dir);
    let Ok(manifest) = plan::read_manifest(&root) else {
        return;
    };
    let Ok(inspection) = inspect::inspect_packages(&root, &manifest, settings, &shipping) else {
        return;
    };
    for hint in unlinked_skill_hints(packages, &inspection.skills) {
        crate::output::info(&lpm_common::sanitize_terminal_inline(&hint));
    }
}

/// Whether the package installed at `node_modules/<package>` ships a skill.
fn ships_skills(project_dir: &Path, package: &str) -> bool {
    let mut path = project_dir.join("node_modules");
    path.extend(package.split('/'));
    cap_std::fs::Dir::open_ambient_dir(&path, cap_std::ambient_authority())
        .ok()
        .and_then(|directory| skill_directory_names(&directory).ok())
        .is_some_and(|names| !names.is_empty())
}

/// One line per package of `packages` naming the skills it ships that the
/// policy doesn't allow yet and nothing keeps from linking, with the
/// narrowest entries that link them. Denied skills, skills that could never
/// link and skills the policy already allows are left out.
fn unlinked_skill_hints(packages: &[&str], skills: &[inspect::InspectedSkill]) -> Vec<String> {
    let mut hints = Vec::new();
    for package in packages {
        let mut names: Vec<&str> = Vec::new();
        let mut selectors: Vec<&str> = Vec::new();
        for skill in skills.iter().filter(|skill| {
            skill.package == *package
                && skill.status == inspect::SkillStatus::NotAllowed
                && skill.blocker.is_none()
        }) {
            let Some(details) = skill.details.as_ref() else {
                continue;
            };
            if !names.contains(&skill.skill.as_str()) {
                names.push(&skill.skill);
            }
            if !selectors.contains(&details.suggested.as_str()) {
                selectors.push(&details.suggested);
            }
        }
        if names.is_empty() {
            continue;
        }
        let quoted: Vec<String> = selectors
            .iter()
            .map(|selector| format!("'{selector}'"))
            .collect();
        hints.push(format!(
            "{package} ships {} {}; let agents use {} with: lpm skills link {}",
            if names.len() == 1 {
                "the skill"
            } else {
                "the skills"
            },
            names.join(", "),
            if names.len() == 1 { "it" } else { "them" },
            quoted.join(" "),
        ));
    }
    hints
}

/// Refuses a change to the skills policy while a newer LPM's record of the
/// links is in place: this LPM couldn't apply the change.
pub(crate) fn ensure_links_are_ours(project_dir: &Path) -> Result<(), LpmError> {
    match state::read_state(project_dir) {
        state::StoredState::Newer(reason) => Err(LpmError::Script(format!(
            "{reason}; update LPM before changing which dependency skills it links"
        ))),
        _ => Ok(()),
    }
}

/// Where dependency skills live for `project_dir`: its workspace root in a
/// workspace, else the project itself.
pub(crate) fn skills_root(project_dir: &Path) -> std::path::PathBuf {
    lpm_workspace::find_workspace_root(project_dir)
        .ok()
        .flatten()
        .unwrap_or_else(|| project_dir.to_path_buf())
}

/// Reconciles the project's dependency-skill links with its policy. Skills
/// never fail an install: what goes wrong becomes a warning in the report.
pub(crate) fn reconcile_project(project_dir: &Path, settings: Settings) -> ReconcileReport {
    let _span = tracing::info_span!("install.dependency_skills").entered();
    try_reconcile(project_dir, settings).unwrap_or_else(|error| ReconcileReport {
        warnings: vec![format!("dependency skills were not linked: {error}")],
        ..ReconcileReport::default()
    })
}

/// Reconciles the project's links now, for the commands that change or
/// check them: unlike [`reconcile_project`], it plans even when the links
/// look current, and reports failure as an error.
pub(crate) fn reconcile_now(
    project_dir: &Path,
    settings: Settings,
) -> Result<ReconcileReport, LpmError> {
    let lock = state::acquire_lock(project_dir)?;
    let manifest = plan::read_manifest(project_dir)?;
    reconcile_locked(project_dir, manifest, settings, lock, checks::Asking::Now)
}

fn try_reconcile(project_dir: &Path, settings: Settings) -> Result<ReconcileReport, LpmError> {
    let unlocked = match skill_work(project_dir, settings)? {
        Some(work) => readiness(project_dir, &work.manifest, settings, &work.importers),
        None => Readiness::Ready,
    };
    match unlocked {
        Readiness::Stale => {}
        Readiness::Ready => return Ok(ReconcileReport::default()),
        Readiness::RecordedByNewer(reason) => return Ok(left_to_newer(&reason)),
    }
    let lock = state::acquire_lock(project_dir)?;
    let Some(work) = skill_work(project_dir, settings)? else {
        return Ok(ReconcileReport::default());
    };
    match readiness(project_dir, &work.manifest, settings, &work.importers) {
        Readiness::Stale => reconcile_locked(
            project_dir,
            work.manifest,
            settings,
            lock,
            checks::Asking::WhenDue,
        ),
        Readiness::Ready => Ok(ReconcileReport::default()),
        Readiness::RecordedByNewer(reason) => Ok(left_to_newer(&reason)),
    }
}

fn left_to_newer(reason: &str) -> ReconcileReport {
    ReconcileReport {
        warnings: vec![apply::newer_state_warning(reason)],
        ..ReconcileReport::default()
    }
}

/// Whether `project_dir` may have dependency-skill work, judged without
/// parsing JSON or reading the user's settings: LPM linked something
/// there, its manifest mentions `"skills"`, or an install materialized
/// reviewed LPM.dev skills in it or, at a workspace root, in a member.
pub(crate) fn may_have_skill_work(project_dir: &Path) -> bool {
    if state::state_exists(project_dir) || lpm_dev::has_reviewed_sets(project_dir) {
        return true;
    }
    let Ok(text) = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) else {
        return false;
    };
    may_name_skills(&text)
        || (may_be_workspace_root(project_dir, &text)
            && plan::importer_directories(project_dir)
                .iter()
                .skip(1)
                .any(|member| lpm_dev::has_reviewed_sets(member)))
}

/// Whether manifest text may hold a skills policy: it says `"skills"`, or
/// holds a `\u` escape, the only other way JSON can spell the key.
fn may_name_skills(text: &str) -> bool {
    text.contains("\"skills\"") || text.contains("\\u")
}

/// Whether the project whose manifest reads `text` may be a workspace
/// root, judged without parsing it: it says `"workspaces"` or holds a `\u`
/// escape, which can spell the key too, or a `pnpm-workspace.yaml` sits
/// beside it.
fn may_be_workspace_root(project_dir: &Path, text: &str) -> bool {
    text.contains("\"workspaces\"")
        || text.contains("\\u")
        || std::fs::symlink_metadata(project_dir.join("pnpm-workspace.yaml")).is_ok()
}

/// What a reconcile reads: the project's manifest, and the directories
/// whose installs may have materialized LPM.dev skills.
struct SkillWork {
    manifest: serde_json::Value,
    importers: Vec<PathBuf>,
}

/// The project's skill work, or `None` when there is none: LPM linked
/// nothing, the manifest never mentions `"skills"`, and no install in the
/// project, or in a member when it is a workspace root, materialized
/// LPM.dev skills. A missing manifest is no work unless LPM linked
/// something.
fn skill_work(project_dir: &Path, settings: Settings) -> Result<Option<SkillWork>, LpmError> {
    let has_state = state::state_exists(project_dir);
    let path = project_dir.join("package.json");
    let text =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(text) => text,
            Err(_) if !has_state => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    let importers = if settings.lpm_dev_packages && may_be_workspace_root(project_dir, &text) {
        plan::importer_directories(project_dir)
    } else {
        vec![project_dir.to_path_buf()]
    };
    let has_sets = settings.lpm_dev_packages
        && importers
            .iter()
            .any(|importer| lpm_dev::has_reviewed_sets(importer));
    if !has_state && !has_sets && !may_name_skills(&text) {
        return Ok(None);
    }
    let manifest = serde_json::from_str(lpm_common::strip_utf8_bom_str(&text))
        .map_err(|error| LpmError::Registry(format!("invalid {}: {error}", path.display())))?;
    Ok(Some(SkillWork {
        manifest,
        importers,
    }))
}

/// Plans and applies the links `manifest` asks for; the caller holds the
/// project's link `lock` from before it read `manifest`. When the plan
/// rests on security verdicts `asking` wants asked for, the lock is let go
/// while Socket answers, and the plan is made again from the manifest as it
/// is then.
fn reconcile_locked(
    project_dir: &Path,
    manifest: serde_json::Value,
    settings: Settings,
    lock: lpm_common::ExclusiveLockHandle,
    asking: checks::Asking,
) -> Result<ReconcileReport, LpmError> {
    let socket = settings.security_provider == crate::lpm_skills_config::SecurityProvider::Socket;
    let mut lock = lock;
    let mut manifest = manifest;
    let mut book = if socket {
        checks::Book::load()
    } else {
        checks::Book::default()
    };
    let mut rounds = 0;
    let mut asked = std::collections::BTreeSet::new();
    let mut unsaved = None;
    let mut refreshed = 0;
    let checked_as = socket.then(checks::release_check).flatten();
    loop {
        let (plan, inputs, stored) = plan_locked(project_dir, &manifest, settings, &book)?;
        let mut releases = plan.relied.clone();
        if socket && let state::StoredState::Present(previous) = &stored {
            releases.extend(apply::retained_releases(
                project_dir,
                &plan,
                previous,
                &inputs.policy,
                checked_as.as_deref(),
            ));
        }
        if socket && !settings.offline && rounds < MAX_ASK_ROUNDS {
            let packages: Vec<(String, String)> = checks::to_ask(&book, &releases, asking)
                .into_iter()
                .filter(|release| !asked.contains(release))
                .collect();
            if !packages.is_empty() {
                drop(lock);
                let (answers, error) = checks::ask(&packages);
                book.absorb(&answers);
                unsaved = unsaved.or(error);
                rounds += 1;
                asked.extend(packages);
                lock = state::acquire_lock(project_dir)?;
                manifest = plan::read_manifest(project_dir)?;
                continue;
            }
        }
        if socket && refreshed < MAX_VERDICT_REFRESHES && !releases.is_empty() {
            let current = checks::Book::load();
            if current.read_failed() && !book.refresh_failed() {
                book.note_refresh_failed();
                refreshed += 1;
                continue;
            }
            if book.differs_for(&current, &releases) {
                book = book.merged_with(current);
                refreshed += 1;
                continue;
            }
            book.caught_up_with(&current);
        }
        let recheck = checks::recheck(&book, &releases);
        let stale = if socket {
            checks::stale(&book, &releases)
        } else {
            0
        };
        let failure = book.failure().map(str::to_string);
        let mut inputs = apply::Inputs {
            recheck,
            verdicts: socket.then_some(book),
            checked_as,
            ..inputs
        };
        if inputs
            .verdicts
            .as_ref()
            .is_some_and(checks::Book::refresh_failed)
        {
            inputs.fingerprint.clear();
        }
        record_pending_reviews(&plan.pending_reviews);
        let mut report = apply::apply(project_dir, &plan, stored, inputs, &lock)?;
        if stale > 0 {
            report.warnings.push(format!(
                "Socket's verdicts for {stale} {} are more than a day old and LPM couldn't ask again ({}); their skills stay as they were and no new one links until Socket answers",
                if stale == 1 { "package" } else { "packages" },
                if settings.offline {
                    "the install runs offline"
                } else {
                    failure
                        .as_deref()
                        .unwrap_or("they came up after this run asked Socket; the next run asks")
                }
            ));
        }
        if let Some(error) = unsaved {
            report.warnings.push(format!(
                "Socket's answers couldn't be saved, so other projects ask again: {error}"
            ));
        }
        return Ok(report);
    }
}

/// How many times one reconcile plans again because another project
/// recorded a newer verdict it relies on, before it applies what it has.
const MAX_VERDICT_REFRESHES: usize = 2;

/// How many rounds one reconcile asks Socket: a second asks only about
/// releases the first round's answers brought into play, such as the other
/// installed versions of a package whose skill turned out to pre-approve
/// its command.
const MAX_ASK_ROUNDS: usize = 2;

/// The plan for `manifest`, what it is reconciled from, and the state as
/// read under the link lock.
fn plan_locked(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
    book: &checks::Book,
) -> Result<(plan::Plan, apply::Inputs, state::StoredState), LpmError> {
    let parsed = policy::read_policy(manifest);
    let stored = state::read_state(project_dir);
    let (recorded, recorded_skills) = match &stored {
        state::StoredState::Present(recorded) => {
            (recorded.lockfile.as_ref(), recorded.recorded_skills())
        }
        _ => (None, plan::RecordedSkills::new()),
    };
    let lockfile = lockfile_stamp(project_dir, recorded);
    let members: Vec<String> = plan::importer_directories(project_dir)
        .iter()
        .skip(1)
        .filter_map(|member| relative_member(project_dir, member))
        .collect();
    let inputs = apply::Inputs {
        fingerprint: fingerprint(
            project_dir,
            parsed.policy.as_ref(),
            settings,
            lockfile.as_ref(),
            &member_importers(project_dir, &members),
        ),
        policy: policy::policy_digest(parsed.policy.as_ref()),
        lockfile,
        members,
        recheck: checks::Recheck::default(),
        verdicts: None,
        checked_as: None,
    };
    let plan = plan::plan_project(
        project_dir,
        parsed,
        manifest,
        plan::PlanMode::Apply,
        settings.sources(),
        plan::History {
            verdicts: Some(book),
            recorded: &recorded_skills,
        },
        None,
    )?;
    Ok((plan, inputs, stored))
}

/// Marks each review record that leaves one of its package's skill
/// directories unnamed, so a later install asks the registry again. A
/// record that can't be marked only means that install doesn't ask.
fn record_pending_reviews(pending: &[plan::PendingReview]) {
    for review in pending {
        if let Err(error) = crate::commands::skills::reviews::mark_pending(
            &review.package,
            &review.version,
            &review.directory,
        ) {
            tracing::debug!(
                "couldn't mark the review of {}@{} to be asked again: {error}",
                review.package,
                review.version
            );
        }
    }
}

/// `member`, a workspace member directory under `project_dir`, as the
/// project-relative path the state records.
fn relative_member(project_dir: &Path, member: &Path) -> Option<String> {
    let relative = member.strip_prefix(project_dir).ok()?;
    let parts: Vec<&str> = relative
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<_>>()?;
    policy::normalize_relative_dir(&parts.join("/")).ok()
}

/// What the links were reconciled from: the rules, the CLI, the settings,
/// the policy and the directories it resolves to, the lockfile, and the
/// reviewed LPM.dev skills materialized in `importers`.
fn fingerprint(
    project_dir: &Path,
    policy: Option<&policy::SkillsPolicy>,
    settings: Settings,
    lockfile: Option<&state::FileStamp>,
    importers: &[PathBuf],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RULES_VERSION);
    hasher.update([0]);
    hasher.update(env!("CARGO_PKG_VERSION"));
    hasher.update([
        0,
        u8::from(settings.lpm_dev_packages),
        u8::from(settings.other_packages),
        u8::from(settings.omitted.dev),
        u8::from(settings.omitted.optional),
    ]);
    hasher.update(settings.security_provider.as_str());
    hasher.update([0]);
    if settings.security_provider == crate::lpm_skills_config::SecurityProvider::Socket {
        hasher.update(
            socket::cache_scope()
                .as_deref()
                .unwrap_or("unusable endpoint"),
        );
        hasher.update([0]);
        hasher.update(checks::mirror().as_deref().unwrap_or_default());
        hasher.update([0]);
        hasher.update(checks::credential_key());
        hasher.update([0]);
    }
    match policy {
        Some(policy) => hasher.update(policy.fingerprint_text()),
        None => hasher.update("no-policy"),
    }
    let targets = policy.map_or(&policy::Targets::Auto, |policy| &policy.targets);
    for target in apply::resolve_targets(project_dir, targets) {
        hasher.update([0]);
        hasher.update(target);
    }
    hasher.update([0]);
    if settings.lpm_dev_packages || policy.is_some_and(plan::reads_other_packages_skills) {
        hasher.update(lpm_dev::sets_fingerprint(importers));
    }
    hasher.update([0]);
    match lockfile {
        Some(stamp) => hasher.update(&stamp.digest),
        None => hasher.update("no-lockfile"),
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// How long before its digest was taken a file must have last changed for
/// an equal size and modification time to prove it unchanged since: a
/// write within the clock's granularity of an earlier one can keep both.
const RACY_WINDOW_NANOS: u64 = 2_000_000_000;

/// `lpm.lock`'s identity, read again only when its size or modification
/// time differs from `recorded`'s, or `recorded` was taken too soon after
/// the file changed to prove anything.
fn lockfile_stamp(
    project_dir: &Path,
    recorded: Option<&state::FileStamp>,
) -> Option<state::FileStamp> {
    let path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let metadata = std::fs::metadata(&path).ok()?;
    let size = metadata.len();
    let modified_nanos = nanos_since_epoch(metadata.modified().ok()?)?;
    if let Some(recorded) = recorded
        && recorded.size == size
        && recorded.modified_nanos == modified_nanos
        && stamp_is_settled(recorded)
    {
        return Some(recorded.clone());
    }
    let checked_nanos = nanos_since_epoch(std::time::SystemTime::now())?;
    Some(state::FileStamp {
        size,
        modified_nanos,
        checked_nanos,
        digest: hash_file(&path)?,
    })
}

/// Whether `stamp` was taken long enough after the file last changed to
/// prove it unchanged while its size and modification time stay the same.
fn stamp_is_settled(stamp: &state::FileStamp) -> bool {
    stamp.modified_nanos.saturating_add(RACY_WINDOW_NANOS) < stamp.checked_nanos
}

/// Records `stamp` in place of a stamp of the same lockfile taken too soon
/// to trust, so later runs skip hashing the lockfile again. Skipped when
/// another process holds the links, which records its own.
fn keep_settled_stamp(project_dir: &Path, stamp: state::FileStamp) {
    let Ok(Some(_lock)) = state::try_acquire_lock(project_dir) else {
        return;
    };
    if let state::StoredState::Present(mut recorded) = state::read_state(project_dir)
        && recorded
            .lockfile
            .as_ref()
            .is_some_and(|current| current.digest == stamp.digest)
    {
        recorded.lockfile = Some(stamp);
        let _ = state::write_state(project_dir, &recorded);
    }
}

fn nanos_since_epoch(time: std::time::SystemTime) -> Option<u64> {
    let elapsed = time.duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_nanos()).ok()
}

fn hash_file(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Prints what reconciling did, for an install's human output.
pub(crate) fn print_report(report: &ReconcileReport) {
    for change in &report.linked {
        crate::output::info(&lpm_common::sanitize_terminal_inline(&format!(
            "Linked skill {} from {}@{} for agents ({})",
            change.skill,
            change.package,
            change.version,
            change.targets.join(", ")
        )));
    }
    for change in &report.updated {
        crate::output::info(&lpm_common::sanitize_terminal_inline(&format!(
            "Updated skill {} from {}@{}",
            change.skill, change.package, change.version
        )));
    }
    for change in &report.removed {
        crate::output::info(&lpm_common::sanitize_terminal_inline(&format!(
            "Removed skill {} ({}@{})",
            change.skill, change.package, change.version
        )));
    }
    for held in &report.held {
        crate::output::warn(&lpm_common::sanitize_terminal_inline(&held_message(held)));
    }
    for warning in &report.warnings {
        crate::output::warn(&lpm_common::sanitize_terminal_inline(warning));
    }
}

/// What happened to a held skill, as one line: whether a copy linked
/// earlier stays, and from which version.
fn held_message(held: &apply::HeldSkill) -> String {
    let source = format!(
        "Skill {} from {}@{}",
        held.skill, held.package, held.version
    );
    match held.kept_version.as_deref() {
        None => format!("{source} is not linked: {}", held.detail),
        Some(kept) if kept == held.version => {
            format!("{source} stays linked as it was: {}", held.detail)
        }
        Some(kept) => format!(
            "{source} is not linked: {}; the copy from {kept} stays linked",
            held.detail
        ),
    }
}

/// The report as the `dependency_skills` object of an install's JSON
/// output. Warnings go to the envelope's `warnings` instead.
pub(crate) fn report_json(report: &ReconcileReport) -> serde_json::Value {
    let change = |change: &SkillChange| {
        serde_json::json!({
            "skill": change.skill,
            "package": change.package,
            "version": change.version,
            "targets": change.targets,
        })
    };
    serde_json::json!({
        "linked": report.linked.iter().map(change).collect::<Vec<_>>(),
        "updated": report.updated.iter().map(change).collect::<Vec<_>>(),
        "removed": report.removed.iter().map(change).collect::<Vec<_>>(),
        "held": report.held.iter().map(|held| serde_json::json!({
            "skill": held.skill,
            "package": held.package,
            "version": held.version,
            "reason": held.reason.as_str(),
            "detail": held.detail,
            "kept_version": held.kept_version,
        })).collect::<Vec<_>>(),
        "unchanged": report.unchanged,
    })
}
