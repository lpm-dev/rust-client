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
mod discovery;
mod git_exclude;
mod links;
mod plan;
mod policy;
mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub(crate) use apply::{ReconcileReport, SkillChange};
pub(crate) use discovery::skill_directory_names;

use crate::lpm_skills_config::LpmSkillsPreference;
use lpm_common::LpmError;
use sha2::{Digest as _, Sha256};
use std::io::Read as _;
use std::path::Path;

/// Bumped when the rules that decide which skills link change, so that
/// every project reconciles again.
const RULES_VERSION: &str = "dependency-skills-1";

/// What this run does with dependency skills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settings {
    /// "npm and other package skills": follow the project's allow-list.
    /// Off, the links LPM made are removed.
    pub(crate) other_packages: bool,
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
            LpmSkillsPreference::Enabled => Ok(Some(Self {
                other_packages: true,
                omitted: Default::default(),
            })),
            LpmSkillsPreference::Config => {
                let config = crate::commands::config::GlobalConfig::load_checked()?;
                Ok(Some(Self {
                    other_packages: crate::lpm_skills_config::other_package_skills_enabled(
                        &config,
                    )?,
                    omitted: Default::default(),
                }))
            }
        }
    }

    /// These settings for an install that left out `omitted`.
    pub(crate) fn omitting(self, omitted: crate::commands::install::InstallOmitPolicy) -> Self {
        Self { omitted, ..self }
    }
}

/// Whether the project's links already match its policy, its lockfile and
/// these settings, and are intact, so an install can skip reconciling.
/// Reads nothing past the manifest when the project has no policy and LPM
/// linked nothing.
///
/// Links a newer LPM recorded count as ready: this one leaves them alone.
pub(crate) fn links_ready(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
) -> bool {
    !matches!(readiness(project_dir, manifest, settings), Readiness::Stale)
}

enum Readiness {
    Ready,
    Stale,
    RecordedByNewer(String),
}

fn readiness(project_dir: &Path, manifest: &serde_json::Value, settings: Settings) -> Readiness {
    let parsed = if settings.other_packages {
        policy::read_policy(manifest)
    } else {
        policy::ParsedPolicy::default()
    };
    let active = parsed
        .policy
        .as_ref()
        .is_some_and(policy::SkillsPolicy::is_active);
    let ready = match state::read_state(project_dir) {
        state::StoredState::Newer(reason) => return Readiness::RecordedByNewer(reason),
        state::StoredState::Missing => !active && parsed.problems.is_empty(),
        state::StoredState::Unusable(_) => false,
        state::StoredState::Present(recorded) => {
            let lockfile = lockfile_stamp(project_dir, recorded.lockfile.as_ref());
            let ready = parsed.problems.is_empty()
                && recorded.fingerprint
                    == fingerprint(
                        project_dir,
                        parsed.policy.as_ref(),
                        settings,
                        lockfile.as_ref(),
                    )
                && recorded.stale.is_empty()
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

/// [`links_ready`] from the manifest's text, for the install fast lanes: a
/// manifest that never mentions `"skills"` in a project where LPM linked
/// nothing is ready without parsing.
pub(crate) fn links_ready_for_manifest_text(
    project_dir: &Path,
    manifest: &str,
    settings: Settings,
) -> bool {
    if !may_name_skills(manifest) && !state::state_exists(project_dir) {
        return true;
    }
    serde_json::from_str::<serde_json::Value>(lpm_common::strip_utf8_bom_str(manifest))
        .is_ok_and(|manifest| links_ready(project_dir, &manifest, settings))
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

fn try_reconcile(project_dir: &Path, settings: Settings) -> Result<ReconcileReport, LpmError> {
    let unlocked = match manifest_with_skill_work(project_dir)? {
        Some(manifest) => readiness(project_dir, &manifest, settings),
        None => Readiness::Ready,
    };
    match unlocked {
        Readiness::Stale => {}
        Readiness::Ready => return Ok(ReconcileReport::default()),
        Readiness::RecordedByNewer(reason) => return Ok(left_to_newer(&reason)),
    }
    let lock = state::acquire_lock(project_dir)?;
    let Some(manifest) = manifest_with_skill_work(project_dir)? else {
        return Ok(ReconcileReport::default());
    };
    match readiness(project_dir, &manifest, settings) {
        Readiness::Stale => reconcile_locked(project_dir, &manifest, settings, &lock),
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
/// parsing anything: LPM linked something there, or its manifest mentions
/// `"skills"`.
pub(crate) fn may_have_skill_work(project_dir: &Path) -> bool {
    state::state_exists(project_dir)
        || lpm_common::read_text_file_capped(
            &project_dir.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .is_ok_and(|text| may_name_skills(&text))
}

/// Whether manifest text may hold a skills policy: it says `"skills"`, or
/// holds a `\u` escape, the only other way JSON can spell the key.
fn may_name_skills(text: &str) -> bool {
    text.contains("\"skills\"") || text.contains("\\u")
}

/// The project's manifest, or `None` when there is no skill work: LPM
/// linked nothing and the manifest never mentions `"skills"`, or is gone.
fn manifest_with_skill_work(project_dir: &Path) -> Result<Option<serde_json::Value>, LpmError> {
    let has_state = state::state_exists(project_dir);
    let path = project_dir.join("package.json");
    let text =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(text) => text,
            Err(_) if !has_state => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    if !has_state && !may_name_skills(&text) {
        return Ok(None);
    }
    serde_json::from_str(lpm_common::strip_utf8_bom_str(&text))
        .map(Some)
        .map_err(|error| LpmError::Registry(format!("invalid {}: {error}", path.display())))
}

/// Plans and applies the links `manifest` asks for; the caller holds the
/// project's link lock from before it read `manifest`.
fn reconcile_locked(
    project_dir: &Path,
    manifest: &serde_json::Value,
    settings: Settings,
    lock: &lpm_common::ExclusiveLockHandle,
) -> Result<ReconcileReport, LpmError> {
    let parsed = if settings.other_packages {
        policy::read_policy(manifest)
    } else {
        policy::ParsedPolicy::default()
    };
    let (recorded, recorded_skills) = match state::read_state(project_dir) {
        state::StoredState::Present(recorded) => {
            let skills = recorded.recorded_skills();
            (recorded.lockfile, skills)
        }
        _ => (None, plan::RecordedSkills::new()),
    };
    let lockfile = lockfile_stamp(project_dir, recorded.as_ref());
    let inputs = apply::Inputs {
        fingerprint: fingerprint(
            project_dir,
            parsed.policy.as_ref(),
            settings,
            lockfile.as_ref(),
        ),
        policy: policy::policy_digest(parsed.policy.as_ref()),
        lockfile,
    };
    let plan = plan::plan_project(project_dir, parsed, manifest, &recorded_skills)?;
    apply::apply(project_dir, &plan, inputs, lock)
}

/// What the links were reconciled from: the rules, the CLI, the settings,
/// the active policy and the directories it resolves to, and the lockfile.
fn fingerprint(
    project_dir: &Path,
    policy: Option<&policy::SkillsPolicy>,
    settings: Settings,
    lockfile: Option<&state::FileStamp>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RULES_VERSION);
    hasher.update([0]);
    hasher.update(env!("CARGO_PKG_VERSION"));
    hasher.update([
        0,
        u8::from(settings.other_packages),
        u8::from(settings.omitted.dev),
        u8::from(settings.omitted.optional),
    ]);
    match policy.filter(|policy| policy.is_active()) {
        Some(policy) => {
            hasher.update(policy.fingerprint_text());
            for target in apply::resolve_targets(project_dir, &policy.targets) {
                hasher.update([0]);
                hasher.update(target);
            }
        }
        None => hasher.update("inactive"),
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
