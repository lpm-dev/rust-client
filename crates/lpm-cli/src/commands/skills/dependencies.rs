//! `lpm skills deps`, `link`, `unlink` and `sync`: the skills installed
//! dependencies ship, and the project policy that links them for agents.

use super::{plural, require_confirmation};
use crate::dependency_skills::{
    InspectedSkill, Inspection, InstanceRuling, ManifestEdit, PlannedChange, PolicyList,
    ReconcileReport, Settings, SkillStatus,
};
use crate::install_ui;
use crate::lpm_skills_config::LpmSkillsPreference;
use clap::Args;
use lpm_common::LpmError;
use lpm_skill::SkillPermission;
use std::path::Path;

#[derive(Debug, Args, Default)]
pub struct DepsArgs {
    /// Show only the skills of this package, or the skills with this name.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
}

#[derive(Debug, Args, Default)]
pub struct LinkArgs {
    /// Selectors to allow, such as `#agent-browser` or
    /// `#agent-browser:skill(agent-browser)`. Without one, pick from the
    /// skills installed dependencies ship.
    #[arg(value_name = "SELECTOR")]
    pub selectors: Vec<String>,
    /// Print what would be allowed and linked without changing files.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive change.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct UnlinkArgs {
    /// Selectors to stop linking: an equal `allow` entry is removed, and
    /// anything else is added to `deny`.
    #[arg(value_name = "SELECTOR", required_unless_present = "all")]
    pub selectors: Vec<String>,
    /// Stop linking every dependency skill: drop every `allow` entry and
    /// keep the `deny` entries.
    #[arg(long, conflicts_with = "selectors")]
    pub all: bool,
    /// Print what would change without changing files.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive change.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct SyncArgs {
    /// Report whether the links match the policy, and fail when they don't,
    /// without changing files.
    #[arg(long)]
    pub check: bool,
}

fn settings() -> Result<Settings, LpmError> {
    Ok(
        Settings::resolve(LpmSkillsPreference::Config)?.unwrap_or(Settings {
            other_packages: true,
            omitted: Default::default(),
        }),
    )
}

pub(super) fn deps(project_dir: &Path, args: &DepsArgs, json_output: bool) -> Result<(), LpmError> {
    let root = crate::dependency_skills::skills_root(project_dir);
    let settings = settings()?;
    let manifest = crate::dependency_skills::read_manifest(&root)?;
    let mut inspection = crate::dependency_skills::inspect_project(&root, &manifest, settings)?;
    if let Some(name) = &args.name {
        inspection
            .skills
            .retain(|skill| &skill.package == name || &skill.skill == name);
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection_json(&root, &inspection)).unwrap()
        );
        return Ok(());
    }
    print_inspection(&inspection);
    Ok(())
}

fn inspection_json(root: &Path, inspection: &Inspection) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "project": root.display().to_string(),
        "enabled": inspection.other_packages,
        "policy": {
            "allow": inspection.allow,
            "deny": inspection.deny,
            "targets": inspection.targets,
        },
        "problems": inspection.problems,
        "unlisted": inspection
            .unlisted
            .iter()
            .map(|(package, detail)| serde_json::json!({ "package": package, "detail": detail }))
            .collect::<Vec<_>>(),
        "count": inspection.skills.len(),
        "skills": inspection.skills.iter().map(skill_json).collect::<Vec<_>>(),
    })
}

fn skill_json(skill: &InspectedSkill) -> serde_json::Value {
    let details = skill.details.as_ref();
    serde_json::json!({
        "skill": skill.skill,
        "package": skill.package,
        "version": skill.version,
        "status": skill.status.as_str(),
        "change": skill.change.map(PlannedChange::as_str),
        "reason": match skill.status {
            SkillStatus::Held(reason) => Some(reason.as_str()),
            _ => skill.blocker.map(|reason| reason.as_str()),
        },
        "detail": skill.detail,
        "description": details.map(|details| details.description.as_str()),
        "hidden": details.is_some_and(|details| details.hidden),
        "allowed_tools": details.map(|details| details.allowed_tools.clone()).unwrap_or_default(),
        "permission": details.map(|details| details.permission.as_str()),
        "warnings": details.map_or(0, |details| details.warnings),
        "suggested_selector": details
            .filter(|_| skill.blocker.is_none())
            .map(|details| details.suggested.as_str()),
        "links": skill.links,
    })
}

fn print_inspection(inspection: &Inspection) {
    if inspection.skills.is_empty() {
        crate::output::info("No installed dependency ships a skills/<name>/SKILL.md directory");
    } else {
        let mut table = install_ui::Table::new();
        for skill in &inspection.skills {
            table.row([
                install_ui::field(&skill.skill),
                install_ui::dim(&format!("{}@{}", skill.package, skill.version)),
                status_label(skill),
                install_ui::dim(&skill_note(skill)),
            ]);
        }
        table.print_stdout();
    }
    print_problems(inspection);
    if !inspection.other_packages {
        install_ui::warn(
            "npm and other package skills are turned off for you; turn them on with `lpm config npm-skills --set true`",
        );
    }
    if let Some(skill) = inspection.skills.iter().find(|skill| {
        skill.status == SkillStatus::NotAllowed
            && skill.blocker.is_none()
            && skill.details.is_some()
    }) {
        let selector = &skill.details.as_ref().expect("checked above").suggested;
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  Link one with: lpm skills link '{}'",
            selector
        ));
    }
}

/// Warns about what keeps the policy from being read in full and about the
/// packages whose skills couldn't be listed.
fn print_problems(inspection: &Inspection) {
    for problem in &inspection.problems {
        install_ui::warn_untrusted(problem);
    }
    for (package, detail) in &inspection.unlisted {
        install_ui::warn_untrusted(&format!(
            "{package}: {detail}; LPM reads it again on the next install"
        ));
    }
}

fn status_label(skill: &InspectedSkill) -> install_ui::TerminalFragment {
    match skill.status {
        SkillStatus::Linked => install_ui::green("linked"),
        SkillStatus::Allowed => install_ui::cyan("allowed"),
        SkillStatus::NotAllowed => install_ui::dim("not allowed"),
        SkillStatus::Denied => install_ui::dim("denied"),
        SkillStatus::Held(_) => install_ui::yellow("held"),
    }
}

fn skill_note(skill: &InspectedSkill) -> String {
    if let Some(detail) = &skill.detail {
        return detail.clone();
    }
    match (&skill.status, &skill.details) {
        (SkillStatus::NotAllowed, Some(details)) => {
            let grant = permission_summary(details.permission, &details.allowed_tools);
            format!("allow `{}`{grant}", details.suggested)
        }
        (SkillStatus::Linked, _) => skill.links.join(", "),
        _ => String::new(),
    }
}

fn permission_summary(permission: SkillPermission, tools: &[String]) -> String {
    match permission {
        SkillPermission::None => String::new(),
        _ if tools.is_empty() => String::new(),
        _ => format!("; pre-approves {}", tools.join(", ")),
    }
}

pub(super) async fn link(
    project_dir: &Path,
    args: LinkArgs,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = crate::dependency_skills::skills_root(project_dir);
    let settings = settings()?;
    crate::dependency_skills::ensure_links_are_ours(&root)?;
    let mut selectors = args
        .selectors
        .iter()
        .map(|text| crate::dependency_skills::validate_selector(text).map_err(LpmError::Registry))
        .collect::<Result<Vec<_>, _>>()?;
    if selectors.is_empty() {
        selectors = pick_selectors(&root, settings, json_output)?;
        if selectors.is_empty() {
            return Ok(());
        }
    }

    let mut edit = ManifestEdit::read(&root)?;
    let before = edit.value.clone();
    let added = edit.add(PolicyList::Allow, &selectors)?;
    let preview = crate::dependency_skills::inspect_project(&root, &edit.value, settings)?;
    let changes = previewed_changes(&preview);
    if args.dry_run {
        print_policy_preview(json_output, "link", &added, &[], &changes);
        return Ok(());
    }
    if !json_output {
        print_policy_preview(false, "link", &added, &[], &changes);
    }
    if !added.is_empty() {
        let grants = if args.yes || !super::is_interactive(json_output) {
            0
        } else {
            new_grants(
                &crate::dependency_skills::inspect_project(&root, &before, settings)?,
                &preview,
            )
        };
        let prompt = if grants == 0 {
            "Allow these skills for agents in package.json?".to_string()
        } else {
            grants_prompt(grants)
        };
        require_confirmation(
            args.yes,
            json_output,
            "lpm skills link",
            format!("allow {} in package.json", added.join(", ")),
            &prompt,
        )?;
    }
    let report = write_and_reconcile(&root, &edit, !added.is_empty(), settings).await?;
    print_mutation_result(json_output, &added, &[], &report, settings);
    Ok(())
}

/// How many skills pre-approve tools for agents under the policy `after`
/// previews that they didn't pre-approve under the one `before` previews:
/// those that link, or whose hold can clear on its own, and whose allowing
/// entries, decided or not, name them as specifically as their grants need.
/// A release that pre-approves other tools than the one before counts.
fn new_grants(before: &Inspection, after: &Inspection) -> usize {
    let grants = |skill: &InspectedSkill| {
        skill.status.may_grant()
            && skill.details.as_ref().is_some_and(|details| {
                details.permission != SkillPermission::None && skill.naming >= details.requires
            })
    };
    let grant = |skill: &InspectedSkill| {
        (
            skill.skill.clone(),
            skill.package.clone(),
            skill
                .details
                .as_ref()
                .map(|details| details.allowed_tools.clone())
                .unwrap_or_default(),
        )
    };
    let granted: std::collections::BTreeSet<_> = before
        .skills
        .iter()
        .filter(|skill| grants(skill))
        .map(grant)
        .collect();
    after
        .skills
        .iter()
        .filter(|skill| grants(skill) && !granted.contains(&grant(skill)))
        .count()
}

/// Writes `edit` when `changed`, and reconciles the links, inside the
/// project's install transaction: the write refuses a manifest that changed
/// since the edit read it, and nothing else writes it until the links match.
async fn write_and_reconcile(
    root: &Path,
    edit: &ManifestEdit,
    changed: bool,
    settings: Settings,
) -> Result<ReconcileReport, LpmError> {
    crate::commands::trust::scope_project_policy_mutation(root, async {
        crate::dependency_skills::ensure_links_are_ours(root)?;
        if changed {
            edit.write()?;
        }
        crate::dependency_skills::reconcile_now(root, settings)
    })
    .await
}

pub(super) async fn unlink(
    project_dir: &Path,
    args: UnlinkArgs,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = crate::dependency_skills::skills_root(project_dir);
    let settings = settings()?;
    crate::dependency_skills::ensure_links_are_ours(&root)?;
    let selectors = args
        .selectors
        .iter()
        .map(|text| crate::dependency_skills::validate_selector(text).map_err(LpmError::Registry))
        .collect::<Result<Vec<_>, _>>()?;
    let mut edit = ManifestEdit::read(&root)?;
    let shared = Settings {
        other_packages: true,
        ..settings
    };
    let (removed, denied) = if args.all {
        (edit.clear(PolicyList::Allow), Vec::new())
    } else {
        let removed = edit.remove(PolicyList::Allow, &selectors);
        let removed_canonical: Vec<String> = removed
            .iter()
            .filter_map(|text| crate::dependency_skills::validate_selector(text).ok())
            .collect();
        let remaining = crate::dependency_skills::inspect_project(&root, &edit.value, shared)?;
        let linked = linked_after(&remaining);
        let mut deny = Vec::with_capacity(selectors.len());
        for selector in selectors {
            if !removed_canonical.contains(&selector)
                || crate::dependency_skills::may_match_any(&selector, &remaining.unlisted)
                || {
                    let mut trial = edit.clone();
                    trial.add(PolicyList::Deny, std::slice::from_ref(&selector))?;
                    linked_after(&crate::dependency_skills::inspect_project(
                        &root,
                        &trial.value,
                        shared,
                    )?) != linked
                }
            {
                deny.push(selector);
            }
        }
        let denied = edit.add(PolicyList::Deny, &deny)?;
        (removed, denied)
    };
    let preview = crate::dependency_skills::inspect_project(&root, &edit.value, settings)?;
    let changes = previewed_changes(&preview);
    if args.dry_run {
        print_policy_preview(json_output, "unlink", &removed, &denied, &changes);
        return Ok(());
    }
    if !json_output {
        print_policy_preview(false, "unlink", &removed, &denied, &changes);
    }
    let changed = !removed.is_empty() || !denied.is_empty();
    if changed {
        require_confirmation(
            args.yes,
            json_output,
            "lpm skills unlink",
            "change the skills policy in package.json".into(),
            "Stop linking these skills for agents?",
        )?;
    }
    let report = write_and_reconcile(&root, &edit, changed, settings).await?;
    print_mutation_result(json_output, &removed, &denied, &report, settings);
    Ok(())
}

pub(super) fn sync(project_dir: &Path, args: &SyncArgs, json_output: bool) -> Result<(), LpmError> {
    let root = crate::dependency_skills::skills_root(project_dir);
    let settings = settings()?;
    if args.check {
        let differences = crate::dependency_skills::drift(&root, settings)?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": differences.is_empty(),
                    "in_sync": differences.is_empty(),
                    "differences": differences,
                }))
                .unwrap()
            );
            return if differences.is_empty() {
                Ok(())
            } else {
                Err(LpmError::ExitCode(1))
            };
        }
        if differences.is_empty() {
            install_ui::done("Dependency skill links match the project's policy");
            return Ok(());
        }
        for difference in &differences {
            install_ui::warn_untrusted(difference);
        }
        return Err(LpmError::Script(format!(
            "{} dependency skill {} out of date; run `lpm skills sync`",
            differences.len(),
            plural(differences.len(), "link is", "links are")
        )));
    }
    let report = crate::dependency_skills::reconcile_now(&root, settings)?;
    print_mutation_result(json_output, &[], &[], &report, settings);
    Ok(())
}

/// Lets the user pick skills that direct dependencies ship and the policy
/// doesn't link yet; returns `#<package>:skill(<name>)` for each, so a pick
/// links that skill and none the package adds later.
fn pick_selectors(
    root: &Path,
    settings: Settings,
    json_output: bool,
) -> Result<Vec<String>, LpmError> {
    if !super::is_interactive(json_output) {
        return Err(LpmError::Registry(
            "pass a selector, such as `lpm skills link '#agent-browser'`; `lpm skills deps` lists the skills installed packages ship".into(),
        ));
    }
    let manifest = crate::dependency_skills::read_manifest(root)?;
    let inspection = crate::dependency_skills::inspect_project(root, &manifest, settings)?;
    print_problems(&inspection);
    let choices = pickable(&inspection.skills);
    for skill in inspection
        .skills
        .iter()
        .filter(|skill| skill.direct && skill.blocker.is_some())
    {
        install_ui::warn_untrusted(&format!(
            "{} from {}@{} can't be linked: {}",
            skill.skill,
            skill.package,
            skill.version,
            skill.detail.as_deref().unwrap_or_default()
        ));
    }
    if choices.is_empty() {
        crate::output::info(
            "No direct dependency ships a skill this project could link and doesn't yet; name others with `lpm skills link '#<package>'`",
        );
        return Ok(Vec::new());
    }
    let mut prompt =
        cliclack::multiselect("Link skills for agents  (space=toggle  a=all  enter=confirm)");
    for (index, skill) in choices.iter().enumerate() {
        let details = skill.details.as_ref().expect("filtered above");
        prompt = prompt.item(
            index,
            crate::prompt::untrusted(format!(
                "{}  ({}@{})",
                skill.skill, skill.package, skill.version
            )),
            crate::prompt::untrusted(format!(
                "{}{}",
                details.description,
                permission_summary(details.permission, &details.allowed_tools)
            )),
        );
    }
    let picked: Vec<usize> = prompt.interact().map_err(crate::prompt::prompt_err)?;
    let mut selectors: Vec<String> = Vec::with_capacity(picked.len());
    for index in picked {
        let selector = skill_selector(&choices[index].package, &choices[index].skill);
        if !selectors.contains(&selector) {
            selectors.push(selector);
        }
    }
    Ok(selectors)
}

/// The skills the picker offers: those direct dependencies ship that the
/// policy doesn't allow and nothing keeps from linking.
fn pickable(skills: &[InspectedSkill]) -> Vec<&InspectedSkill> {
    skills
        .iter()
        .filter(|skill| {
            skill.direct
                && skill.status == SkillStatus::NotAllowed
                && skill.blocker.is_none()
                && skill.details.is_some()
        })
        .collect()
}

/// The skills a previewed policy leaves linked or lets link later: those it
/// links now or keeps at an earlier copy, those it allows but holds until
/// the hold clears, and those another installed version of may link, each
/// with the version and status it would have,
/// whether the policy decided it, how many deny entries may still match it,
/// and what the policy decided for each installed instance of its package,
/// so a deny that only swaps one version or one hold for another, leaves
/// the decision open, may deny it once data arrives, or changes another
/// installed version's fate, counts as a change.
fn linked_after(preview: &Inspection) -> std::collections::BTreeSet<Outcome> {
    preview
        .skills
        .iter()
        .filter(|skill| {
            skill.status.allowed_by_policy()
                || skill.change == Some(PlannedChange::Keep)
                || skill.instances.iter().any(|instance| instance.may_link)
        })
        .map(|skill| Outcome {
            skill: skill.skill.clone(),
            package: skill.package.clone(),
            version: skill.version.clone(),
            status: skill.status.detailed(),
            undecided: skill.undecided,
            open_denials: skill.open_denials,
            instances: skill.instances.clone(),
        })
        .collect()
}

/// What a previewed policy makes of one skill it lets link, for telling two
/// previews apart.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Outcome {
    skill: String,
    package: String,
    version: String,
    status: &'static str,
    undecided: bool,
    open_denials: usize,
    instances: Vec<InstanceRuling>,
}

/// The selector that allows exactly one skill of one package.
fn skill_selector(package: &str, skill: &str) -> String {
    format!("#{package}:skill({skill})")
}

/// The skills whose links a policy change would change.
fn previewed_changes(preview: &Inspection) -> Vec<InspectedSkill> {
    preview
        .skills
        .iter()
        .filter(|skill| skill.change.is_some())
        .cloned()
        .collect()
}

fn print_policy_preview(
    json_output: bool,
    action: &str,
    removed_or_added: &[String],
    denied: &[String],
    changes: &[InspectedSkill],
) {
    if json_output {
        let mut report = serde_json::json!({
            "success": true,
            "dry_run": true,
            "action": action,
            "skills": changes.iter().map(skill_json).collect::<Vec<_>>(),
        });
        if action == "link" {
            report["added"] = serde_json::json!(removed_or_added);
        } else {
            report["removed"] = serde_json::json!(removed_or_added);
            report["denied"] = serde_json::json!(denied);
        }
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    for entry in removed_or_added {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            if action == "link" { "allow" } else { "remove" },
            entry
        ));
    }
    for entry in denied {
        install_ui::detail_line(crate::install_ui::terminal_line!("  deny {}", entry));
    }
    for skill in changes {
        let Some(change) = skill.change else {
            continue;
        };
        let grant = skill
            .details
            .as_ref()
            .map(|details| permission_summary(details.permission, &details.allowed_tools))
            .unwrap_or_default();
        let detail = skill.detail.as_deref().unwrap_or_default();
        let line = match change {
            PlannedChange::Link | PlannedChange::Update => format!(
                "  {} {} from {}@{}{grant}",
                change.as_str(),
                skill.skill,
                skill.package,
                skill.version
            ),
            PlannedChange::Unlink => format!(
                "  unlink {} from {}@{}",
                skill.skill, skill.package, skill.version
            ),
            PlannedChange::Keep => format!(
                "  hold {} from {}@{}, keeping the version linked now: {detail}{grant}",
                skill.skill, skill.package, skill.version
            ),
            PlannedChange::Hold => format!(
                "  hold {} from {}@{}: {detail}{grant}",
                skill.skill, skill.package, skill.version
            ),
        };
        install_ui::detail_line(crate::install_ui::terminal_line!("{}", line));
    }
}

fn print_mutation_result(
    json_output: bool,
    changed: &[String],
    denied: &[String],
    report: &ReconcileReport,
    settings: Settings,
) {
    if json_output {
        let mut envelope = serde_json::json!({
            "success": true,
            "policy_changes": changed,
            "denied": denied,
            "dependency_skills": crate::dependency_skills::report_json(report),
        });
        if !report.warnings.is_empty() {
            envelope["warnings"] = serde_json::json!(report.warnings);
        }
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        return;
    }
    crate::dependency_skills::print_report(report);
    if !settings.other_packages {
        install_ui::warn(
            "npm and other package skills are turned off for you, so their entries link nothing until you turn them on with `lpm config npm-skills --set true`",
        );
    } else if report.is_quiet() {
        install_ui::done("Dependency skill links already match the project's policy");
    }
}

/// The confirmation `lpm skills link` asks when `grants` of the skills it
/// would link pre-approve commands for agents.
fn grants_prompt(grants: usize) -> String {
    format!(
        "Allow these skills for agents? {grants} {} commands for agents.",
        plural(grants, "skill pre-approves", "skills pre-approve")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency_skills::{HoldReason, Naming, SkillDetails};

    #[test]
    fn the_link_prompt_counts_the_skills_that_pre_approve_commands_in_agreement() {
        assert_eq!(
            grants_prompt(1),
            "Allow these skills for agents? 1 skill pre-approves commands for agents."
        );
        assert_eq!(
            grants_prompt(2),
            "Allow these skills for agents? 2 skills pre-approve commands for agents."
        );
    }

    fn skill(name: &str, direct: bool, status: SkillStatus) -> InspectedSkill {
        InspectedSkill {
            skill: name.into(),
            package: format!("{name}-package"),
            version: "1.0.0".into(),
            status,
            change: None,
            detail: None,
            blocker: None,
            details: Some(SkillDetails {
                description: String::new(),
                hidden: false,
                allowed_tools: Vec::new(),
                permission: SkillPermission::None,
                warnings: 0,
                suggested: format!("#{name}-package"),
                requires: Naming::None,
            }),
            links: Vec::new(),
            direct,
            undecided: false,
            open_denials: 0,
            naming: Naming::None,
            instances: Vec::new(),
        }
    }

    fn granting(
        name: &str,
        status: SkillStatus,
        requires: Naming,
        naming: Naming,
    ) -> InspectedSkill {
        let mut skill = skill(name, true, status);
        let details = skill.details.as_mut().unwrap();
        details.permission = SkillPermission::Broad;
        details.allowed_tools = vec!["Bash(git:*)".into()];
        details.requires = requires;
        skill.naming = naming;
        skill.change = Some(PlannedChange::Link);
        skill
    }

    fn inspection(skills: Vec<InspectedSkill>) -> Inspection {
        Inspection {
            allow: Vec::new(),
            deny: Vec::new(),
            targets: Vec::new(),
            problems: Vec::new(),
            unlisted: Vec::new(),
            other_packages: true,
            skills,
        }
    }

    #[test]
    fn only_grants_the_edit_introduces_and_its_naming_allows_are_counted() {
        let waiting_unnamed = || {
            let mut skill = granting(
                "deploy",
                SkillStatus::Held(HoldReason::NeedsData),
                Naming::Skill,
                Naming::None,
            );
            skill.undecided = true;
            skill
        };
        let before = inspection(vec![waiting_unnamed()]);

        assert_eq!(
            new_grants(
                &inspection(vec![granting(
                    "deploy",
                    SkillStatus::NotAllowed,
                    Naming::Skill,
                    Naming::None,
                )]),
                &inspection(vec![waiting_unnamed()]),
            ),
            0,
            "an entry that can't name the skill never grants what it needs named"
        );
        assert_eq!(
            new_grants(
                &before,
                &inspection(vec![granting(
                    "deploy",
                    SkillStatus::Allowed,
                    Naming::Skill,
                    Naming::Skill
                )])
            ),
            1
        );

        let older = granting(
            "tool",
            SkillStatus::Allowed,
            Naming::Package,
            Naming::Package,
        );
        let mut newer = older.clone();
        newer.version = "2.0.0".into();
        newer.details.as_mut().unwrap().allowed_tools =
            vec!["Bash(git:*)".into(), "Bash(rm:*)".into()];
        assert_eq!(
            new_grants(
                &inspection(vec![older.clone()]),
                &inspection(vec![older.clone()])
            ),
            0
        );
        assert_eq!(
            new_grants(&inspection(vec![older]), &inspection(vec![newer])),
            1,
            "a release that pre-approves more is a new grant"
        );
    }

    #[test]
    fn a_policy_that_links_another_version_or_holds_for_another_reason_counts_as_a_change() {
        let newer = skill("tool", true, SkillStatus::Allowed);
        let mut older = newer.clone();
        older.version = "0.9.0".into();
        let mut open = newer.clone();
        open.undecided = true;
        assert_ne!(
            linked_after(&inspection(vec![newer.clone()])),
            linked_after(&inspection(vec![open]))
        );
        let conflicted = skill("tool", true, SkillStatus::Held(HoldReason::NameConflict));
        let waiting = skill("tool", true, SkillStatus::Held(HoldReason::NeedsData));

        assert_ne!(
            linked_after(&inspection(vec![newer.clone()])),
            linked_after(&inspection(vec![older]))
        );
        assert_ne!(
            linked_after(&inspection(vec![conflicted])),
            linked_after(&inspection(vec![waiting]))
        );
        let mut deniable = newer.clone();
        deniable.open_denials = 1;
        assert_ne!(
            linked_after(&inspection(vec![newer.clone()])),
            linked_after(&inspection(vec![deniable]))
        );
        let mut older_instance_denied = newer.clone();
        older_instance_denied.instances = vec![
            InstanceRuling {
                version: "0.9.0".into(),
                ruling: "denied",
                open_denials: 0,
                may_link: false,
            },
            InstanceRuling {
                version: "1.0.0".into(),
                ruling: "allowed",
                open_denials: 0,
                may_link: true,
            },
        ];
        assert_ne!(
            linked_after(&inspection(vec![newer.clone()])),
            linked_after(&inspection(vec![older_instance_denied]))
        );
        assert_eq!(
            linked_after(&inspection(vec![newer.clone()])),
            linked_after(&inspection(vec![newer]))
        );
    }

    #[test]
    fn another_installed_version_counts_while_the_preferred_one_waits_for_naming() {
        let instances = |older: &'static str| {
            vec![
                InstanceRuling {
                    version: "1.0.0".into(),
                    ruling: older,
                    open_denials: 0,
                    may_link: older == "allowed",
                },
                InstanceRuling {
                    version: "2.0.0".into(),
                    ruling: "allowed",
                    open_denials: 0,
                    may_link: false,
                },
            ]
        };
        let mut waiting = skill("tool", true, SkillStatus::Held(HoldReason::NeedsSkillName));
        waiting.version = "2.0.0".into();
        waiting.instances = instances("allowed");
        let mut older_denied = waiting.clone();
        older_denied.instances = instances("denied");

        assert_ne!(
            linked_after(&inspection(vec![waiting])),
            linked_after(&inspection(vec![older_denied]))
        );
    }

    #[test]
    fn the_picker_offers_only_unallowed_linkable_skills_of_direct_dependencies() {
        let mut blocked = skill("blocked", true, SkillStatus::NotAllowed);
        blocked.blocker = Some(HoldReason::Hooks);
        let skills = vec![
            skill("direct", true, SkillStatus::NotAllowed),
            skill("transitive", false, SkillStatus::NotAllowed),
            skill("linked", true, SkillStatus::Linked),
            skill("denied", true, SkillStatus::Denied),
            blocked,
        ];

        let offered: Vec<&str> = pickable(&skills)
            .into_iter()
            .map(|skill| skill.skill.as_str())
            .collect();

        assert_eq!(offered, ["direct"]);
    }

    #[test]
    fn a_pick_allows_only_that_skill_of_its_package() {
        assert_eq!(
            skill_selector("agent-browser", "agent-browser"),
            "#agent-browser:skill(agent-browser)"
        );
        assert_eq!(
            skill_selector("@scope/tool", "deploy"),
            "#@scope/tool:skill(deploy)"
        );
    }
}
