//! Unified management for package-published and standalone agent skills.
//!
//! Package-published skills remain in `.lpm/skills/<package>/`. Standalone
//! skills have a separate LPM-managed store and are explicitly materialized
//! into supported agent directories.

pub(crate) mod author;
mod dashboard;
mod inventory;
mod managed;
pub(crate) mod package;
mod path_security;
mod source;

use crate::install_ui;
use clap::{Args, Subcommand, ValueEnum};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::Path;

#[derive(Debug, Subcommand)]
pub enum SkillsCmd {
    /// Add a package-published LPM.dev skill set or a standalone agent skill.
    #[command(visible_alias = "install")]
    Add(AddArgs),
    /// List package-published, LPM-managed, and externally discovered skills.
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Show source, security, context, and agent-target details for a skill.
    View(ViewArgs),
    /// Open a local browser dashboard for inspecting and managing skills.
    #[command(visible_alias = "ui")]
    Dashboard(DashboardArgs),
    /// Validate flat `.lpm/skills/*.md` files against LPM.dev publishing rules.
    Validate,
    /// Remove installed LPM.dev package skill sets while preserving authored files.
    Clean(CleanArgs),
    /// Diagnose managed agent targets and externally discovered broken links.
    Doctor(DoctorArgs),
    /// Resolve managed standalone sources again and preview their changes.
    Update(ManageArgs),
    /// Remove managed standalone skills and their agent targets.
    #[command(visible_alias = "rm")]
    Remove(ManageArgs),
    /// Restore managed standalone skills to their recorded agent targets.
    Enable(ManageArgs),
    /// Remove managed standalone skills from agent targets without deleting their store content.
    Disable(ManageArgs),
    /// Remove stale managed targets and records after a preview and confirmation.
    Prune(PruneArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// `@lpm.dev/owner.package`, a GitHub URL or `owner/repo`, or a local skill directory.
    #[arg(value_name = "SOURCE")]
    pub source: Option<String>,
    /// Select a standalone skill by name. Repeat or use `*` for every discovered skill.
    #[arg(long, value_name = "NAME")]
    pub skill: Vec<String>,
    /// Select a standalone agent target. Repeat for each target.
    #[arg(long, value_enum, value_name = "AGENT")]
    pub agent: Vec<AgentTarget>,
    /// Store standalone skills in this project.
    #[arg(long, conflicts_with = "global")]
    pub project: bool,
    /// Store standalone skills under the LPM home directory.
    #[arg(long, conflicts_with = "project")]
    pub global: bool,
    /// Copy standalone files into agent directories instead of linking them.
    #[arg(long)]
    pub copy: bool,
    /// Discover and preview skills without installing them.
    #[arg(long)]
    pub list: bool,
    /// Search outside the standard skill locations in a standalone source.
    #[arg(long)]
    pub full_depth: bool,
    /// Print every planned filesystem change without mutating it.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct ListArgs {
    /// Include global managed and external skill locations.
    #[arg(long)]
    pub global: bool,
    /// Restrict the inventory to a category.
    #[arg(long, value_enum)]
    pub kind: Option<SkillKind>,
    /// Restrict managed and external results to an agent target.
    #[arg(long, value_enum)]
    pub agent: Option<AgentTarget>,
}

#[derive(Debug, Args)]
pub struct ViewArgs {
    /// Managed skill name, package name, or `package/skill` selector.
    #[arg(value_name = "SELECTOR")]
    pub selector: String,
    /// Include global managed and external skill locations when looking up the selector.
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args, Default)]
pub struct DashboardArgs {
    /// Include global managed and external skill locations.
    #[arg(long)]
    pub global: bool,
    /// Do not open the dashboard in the default browser.
    #[arg(long)]
    pub no_open: bool,
    /// Bind an exact localhost port instead of selecting a free port.
    #[arg(long, value_name = "PORT", value_parser = parse_dashboard_port)]
    pub port: Option<u16>,
    /// Disable dashboard mutations while keeping inspection available.
    #[arg(long)]
    pub read_only: bool,
}

#[derive(Debug, Args, Default)]
pub struct DoctorArgs {
    /// Include global managed and external skill locations.
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args, Default)]
pub struct ManageArgs {
    /// Managed skill names. Omit only with `--all` in a TTY.
    #[arg(value_name = "SKILL")]
    pub selectors: Vec<String>,
    /// Restrict the operation to these agent targets.
    #[arg(long, value_enum, value_name = "AGENT")]
    pub agent: Vec<AgentTarget>,
    /// Operate on global managed skills instead of the current project.
    #[arg(long)]
    pub global: bool,
    /// Select every managed skill in the chosen scope.
    #[arg(long)]
    pub all: bool,
    /// Print the mutation plan without applying it.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct PruneArgs {
    /// Prune global managed state instead of project-managed state.
    #[arg(long)]
    pub global: bool,
    /// Print the stale targets and records without applying the cleanup.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct CleanArgs {
    /// Print installed package skill sets that would be removed without changing files.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm cleanup outside an interactive terminal.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum AgentTarget {
    Codex,
    ClaudeCode,
    Cursor,
}

impl AgentTarget {
    const ALL: [Self; 3] = [Self::Codex, Self::ClaudeCode, Self::Cursor];

    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum SkillKind {
    Package,
    Managed,
    External,
}

pub async fn run(
    client: &RegistryClient,
    action: SkillsCmd,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        SkillsCmd::Add(args) => run_add(client, args, project_dir, json_output).await,
        SkillsCmd::List(args) => list_skills(project_dir, &args, json_output),
        SkillsCmd::View(args) => view_skill(project_dir, &args, json_output),
        SkillsCmd::Dashboard(args) => dashboard::run(project_dir, args, json_output).await,
        SkillsCmd::Validate => validate_skills(project_dir, json_output),
        SkillsCmd::Clean(args) => clean_skills(project_dir, args, json_output),
        SkillsCmd::Doctor(args) => managed::doctor(project_dir, args.global, json_output),
        SkillsCmd::Update(args) => managed::update(project_dir, args, json_output).await,
        SkillsCmd::Remove(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Remove, json_output)
        }
        SkillsCmd::Enable(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Enable, json_output)
        }
        SkillsCmd::Disable(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Disable, json_output)
        }
        SkillsCmd::Prune(args) => managed::prune(project_dir, args, json_output),
    }
}

async fn run_add(
    client: &RegistryClient,
    mut args: AddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let source_input = prompt_for_source(args.source.take(), json_output)?;
    if source_input.starts_with("@lpm.dev/") {
        return add_package_skills(client, &source_input, &args, project_dir, json_output).await;
    }

    let tree = source::load(&source_input, project_dir).await?;
    let discovered = source::discover(&tree, args.full_depth)?;
    if args.list {
        print_discovery(&tree, &discovered, json_output);
        return Ok(());
    }

    let selected = select_skills(&args.skill, &discovered, json_output)?;
    let scope = choose_scope(args.project, args.global, json_output)?;
    let agents = choose_agents(&selected, &args.agent, json_output)?;
    source::ensure_agents_are_compatible(&selected, &agents)?;

    let store = managed::Store::for_scope(scope, project_dir)?;
    let plan = managed::plan_install(&store, &tree, &selected, &agents, args.copy)?;
    if args.dry_run || !json_output {
        print_standalone_plan(&tree, &selected, &plan, json_output);
    }
    if args.dry_run {
        return Ok(());
    }
    source::ensure_skills_are_safe(&selected)?;
    let warning_count = selected
        .iter()
        .flat_map(|skill| &skill.findings)
        .filter(|finding| {
            finding.severity == lpm_security::skill_security::SkillSecuritySeverity::Warning
        })
        .count();
    let confirmation = if warning_count == 0 {
        "Install the planned standalone skills?".to_string()
    } else {
        format!(
            "Install after reviewing {warning_count} security {}?",
            plural(warning_count, "warning", "warnings")
        )
    };
    require_confirmation(args.yes, json_output, &confirmation)?;
    let changes = plan.changes.clone();
    managed::apply_install(&store, &tree, &selected, plan)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "managed",
                "installed": selected.iter().map(|skill| skill.name.as_str()).collect::<Vec<_>>(),
                "scope": scope.as_str(),
                "agents": agents.iter().map(|agent| agent.slug()).collect::<Vec<_>>(),
                "source": tree.descriptor,
                "skills": selected.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
                "changes": changes,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Installed {} managed {} for {}",
            selected.len(),
            plural(selected.len(), "skill", "skills"),
            agents
                .iter()
                .map(|agent| agent.label())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    Ok(())
}

fn prompt_for_source(source: Option<String>, json_output: bool) -> Result<String, LpmError> {
    if let Some(source) = source {
        return Ok(source);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "a source is required outside a TTY; pass `lpm skills add <source>`".into(),
        ));
    }
    let kind: &str = cliclack::select("What kind of skill source do you want to add?")
        .item("package", "LPM.dev package", "@lpm.dev/owner.package")
        .item(
            "standalone",
            "GitHub or local skill directory",
            "owner/repo, HTTPS URL, or path",
        )
        .initial_value("standalone")
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    let placeholder = if kind == "package" {
        "@lpm.dev/owner.package"
    } else {
        "owner/repo, https://github.com/owner/repo, or ./skills"
    };
    let source: String = cliclack::input("Source")
        .placeholder(placeholder)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    let source = source.trim();
    if source.is_empty() {
        return Err(LpmError::Registry("a skill source is required".into()));
    }
    if kind == "package" && !source.starts_with("@lpm.dev/") {
        return Err(LpmError::Registry(
            "LPM.dev package sources must start with `@lpm.dev/`".into(),
        ));
    }
    Ok(source.to_string())
}

async fn add_package_skills(
    client: &RegistryClient,
    package: &str,
    args: &AddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if !args.skill.is_empty()
        || !args.agent.is_empty()
        || args.project
        || args.global
        || args.copy
        || args.full_depth
    {
        return Err(LpmError::Registry(
            "`--skill`, `--agent`, scope, `--copy`, and `--full-depth` apply only to standalone skills; package-published skills are materialized as one package-owned set".into(),
        ));
    }
    let name = lpm_common::PackageName::parse(package)?;
    let response = client.get_skills(&name.short(), None).await?;
    let target = project_dir.join(".lpm").join("skills").join(name.short());
    package::validate(&response.skills)?;

    if args.list || args.dry_run {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "kind": "package",
                    "package": name.scoped(),
                    "directory": target,
                    "skills": response.skills.iter().map(|skill| serde_json::json!({
                        "name": skill.name,
                        "description": skill.description,
                        "size": skill.size_bytes,
                    })).collect::<Vec<_>>(),
                    "dry_run": args.dry_run,
                }))
                .unwrap()
            );
        } else {
            println!("{}", name.scoped().cyan());
            for skill in &response.skills {
                println!("  {}", skill.name);
            }
            install_ui::phase(&format!("would materialize {}", target.display()));
        }
        return Ok(());
    }
    require_confirmation(
        args.yes,
        json_output,
        "Materialize these package-published skills?",
    )?;
    let result = package::materialize(
        project_dir,
        &name.short(),
        response.version.as_deref(),
        &response.skills,
    )?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "package",
                "package": name.scoped(),
                "installed": result.installed,
                "directory": result.directory,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Materialized {} package-published {}",
            result.installed,
            plural(result.installed, "skill", "skills")
        ));
        eprintln!("  {}", result.directory.display().to_string().dimmed());
    }
    Ok(())
}

fn select_skills<'a>(
    requested: &[String],
    discovered: &'a [source::DiscoveredSkill],
    json_output: bool,
) -> Result<Vec<&'a source::DiscoveredSkill>, LpmError> {
    if discovered.is_empty() {
        return Err(LpmError::Registry(
            "no standard SKILL.md skills found".into(),
        ));
    }
    if requested.iter().any(|name| name == "*") {
        return Ok(discovered.iter().collect());
    }
    if !requested.is_empty() {
        let wanted: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let selected: Vec<_> = discovered
            .iter()
            .filter(|skill| wanted.contains(skill.name.as_str()))
            .collect();
        if selected.len() != wanted.len() {
            let available = discovered
                .iter()
                .map(|skill| skill.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LpmError::Registry(format!(
                "requested skill was not discovered; available: {available}"
            )));
        }
        return Ok(selected);
    }
    if discovered.len() == 1 {
        return Ok(vec![&discovered[0]]);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "multiple skills were discovered; pass `--skill <name>` or `--skill '*'`".into(),
        ));
    }
    let mut prompt = cliclack::multiselect("Select skills  (space=toggle  a=all  enter=confirm)");
    for skill in discovered {
        prompt = prompt.item(
            skill.name.clone(),
            skill.name.clone(),
            format!("{} · ~{} tokens", skill.description, skill.context_tokens),
        );
    }
    let selected_names: Vec<String> = prompt.interact().map_err(crate::prompt::prompt_err)?;
    if selected_names.is_empty() {
        return Err(LpmError::Registry("no skills selected".into()));
    }
    let selected_names: BTreeSet<_> = selected_names.into_iter().collect();
    Ok(discovered
        .iter()
        .filter(|skill| selected_names.contains(&skill.name))
        .collect())
}

fn choose_scope(
    project: bool,
    global: bool,
    json_output: bool,
) -> Result<managed::Scope, LpmError> {
    if project {
        return Ok(managed::Scope::Project);
    }
    if global {
        return Ok(managed::Scope::Global);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "standalone installs outside a TTY require `--project` or `--global`".into(),
        ));
    }
    let choice: &str = cliclack::select("Install scope")
        .item("project", "Project", "shared in this repository")
        .item("global", "Global", "available across projects")
        .initial_value("project")
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    Ok(if choice == "global" {
        managed::Scope::Global
    } else {
        managed::Scope::Project
    })
}

fn choose_agents(
    skills: &[&source::DiscoveredSkill],
    requested: &[AgentTarget],
    json_output: bool,
) -> Result<Vec<AgentTarget>, LpmError> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "standalone installs outside a TTY require at least one `--agent`".into(),
        ));
    }
    let compatible: Vec<_> = AgentTarget::ALL
        .into_iter()
        .filter(|agent| skills.iter().all(|skill| skill.supports(*agent)))
        .collect();
    if compatible.is_empty() {
        return Err(LpmError::Registry(
            "the selected skills have no common compatible agent target".into(),
        ));
    }
    let mut prompt = cliclack::multiselect("Install for agents  (space=toggle  enter=confirm)");
    for agent in compatible.iter().copied() {
        prompt = prompt.item(agent, agent.label(), "standard Agent Skills location");
    }
    let initial = if compatible.contains(&AgentTarget::Codex) {
        AgentTarget::Codex
    } else {
        compatible[0]
    };
    let agents: Vec<AgentTarget> = prompt
        .initial_values(vec![initial])
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if agents.is_empty() {
        return Err(LpmError::Registry("no agent targets selected".into()));
    }
    Ok(agents)
}

fn require_confirmation(yes: bool, json_output: bool, prompt: &str) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "non-interactive mutation requires `--yes` after reviewing `--dry-run`".into(),
        ));
    }
    let confirmed = cliclack::confirm(prompt)
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if confirmed {
        Ok(())
    } else {
        Err(LpmError::Script(
            "skill operation cancelled; no files changed".into(),
        ))
    }
}

fn is_interactive(json_output: bool) -> bool {
    !json_output && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn parse_dashboard_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "dashboard port must be an integer from 1 to 65535".to_string())?;
    if port == 0 {
        Err(
            "dashboard port must be from 1 to 65535; omit `--port` to select one automatically"
                .into(),
        )
    } else {
        Ok(port)
    }
}

fn print_discovery(
    tree: &source::SourceTree,
    discovered: &[source::DiscoveredSkill],
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "source": tree.descriptor,
                "skills": discovered.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
            }))
            .unwrap()
        );
    } else {
        for skill in discovered {
            println!(
                "{}  {} · ~{} tokens",
                skill.name,
                skill.description.dimmed(),
                skill.context_tokens
            );
            for finding in &skill.findings {
                println!(
                    "  {} {} · {} · {}:{}",
                    security_severity_label(finding.severity),
                    install_ui::cyan(&finding.rule_id),
                    finding.category,
                    finding.path,
                    finding.line
                );
            }
        }
    }
}

fn print_standalone_plan(
    tree: &source::SourceTree,
    selected: &[&source::DiscoveredSkill],
    plan: &managed::InstallPlan,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": true,
                "source": tree.descriptor,
                "skills": selected.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
                "changes": plan.changes,
            }))
            .unwrap()
        );
        return;
    }
    install_ui::phase(&format!("Source: {}", tree.descriptor.display()));
    for skill in selected {
        println!(
            "  {}  {}",
            skill.name.yellow(),
            format!("~{} tokens", skill.context_tokens).dimmed()
        );
        for finding in &skill.findings {
            println!(
                "    {} {} · {} · {}:{}",
                security_severity_label(finding.severity),
                install_ui::cyan(&finding.rule_id),
                finding.category,
                finding.path,
                finding.line
            );
        }
    }
    install_ui::phase("Planned filesystem changes:");
    for change in &plan.changes {
        println!("  {} {}", change.action, change.path.display());
    }
}

fn list_skills(project_dir: &Path, args: &ListArgs, json_output: bool) -> Result<(), LpmError> {
    let packages = package_inventory(project_dir)?;
    let managed = managed::inventory(project_dir, args.global)?;
    let external = managed::external_inventory(project_dir, args.global)?;
    let kind_matches = |kind| args.kind.is_none_or(|wanted| wanted == kind);
    let managed: Vec<_> = managed
        .into_iter()
        .filter(|item| {
            kind_matches(SkillKind::Managed)
                && args.agent.is_none_or(|agent| item.agents.contains(&agent))
        })
        .collect();
    let external: Vec<_> = external
        .into_iter()
        .filter(|item| {
            kind_matches(SkillKind::External) && args.agent.is_none_or(|agent| item.agent == agent)
        })
        .collect();
    let packages: Vec<_> = if kind_matches(SkillKind::Package) {
        packages
    } else {
        Vec::new()
    };
    let package_total: usize = packages.iter().map(|(_, skills)| skills.len()).sum();
    let total = package_total + managed.len() + external.len();

    if json_output {
        let mut map = serde_json::Map::new();
        map.insert("success".into(), serde_json::Value::Bool(true));
        for (package, skills) in &packages {
            map.insert(
                package.clone(),
                serde_json::Value::Array(
                    skills
                        .iter()
                        .map(|(name, size)| serde_json::json!({"name": name, "size": size}))
                        .collect(),
                ),
            );
        }
        map.insert("count".into(), serde_json::json!(total));
        map.insert(
            "counts".into(),
            serde_json::json!({
                "package": package_total,
                "managed": managed.len(),
                "external": external.len(),
            }),
        );
        map.insert(
            "skills".into(),
            serde_json::json!({
                "package": packages.iter().flat_map(|(package, skills)| skills.iter().map(move |(name, size)| serde_json::json!({"package": package, "name": name, "size": size}))).collect::<Vec<_>>(),
                "managed": managed,
                "external": external,
            }),
        );
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
        return Ok(());
    }

    if !packages.is_empty() {
        print_package_inventory(&packages);
    }
    if !managed.is_empty() {
        println!("{}", install_ui::section("managed"));
        for skill in &managed {
            println!("  {:<24} {}", skill.name, skill.summary().dimmed());
        }
        println!();
    }
    if !external.is_empty() {
        println!("{}", install_ui::section("external"));
        for skill in &external {
            println!("  {:<24} {}", skill.name, skill.summary().dimmed());
        }
        println!();
    }
    if total == 0 {
        install_ui::warn("No skills installed or discovered");
    } else if managed.is_empty() && external.is_empty() {
        install_ui::done(&format!(
            "{package_total} {} installed across {} {}",
            plural(package_total, "skill", "skills"),
            packages.len(),
            plural(packages.len(), "package", "packages"),
        ));
    } else {
        install_ui::done(&format!("{total} skills in the unified inventory"));
    }
    Ok(())
}

fn view_skill(project_dir: &Path, args: &ViewArgs, json_output: bool) -> Result<(), LpmError> {
    let packages = package_inventory(project_dir)?;
    if let Some((package, skill)) = args.selector.split_once('/')
        && let Some((_, skills)) = packages.iter().find(|(name, _)| name == package)
        && let Some((name, size)) = skills.iter().find(|(name, _)| name == skill)
    {
        print_package_view(package, name, *size, json_output);
        return Ok(());
    }
    if let Some((package, skills)) = packages.iter().find(|(name, _)| *name == args.selector)
        && skills.len() == 1
    {
        print_package_view(package, &skills[0].0, skills[0].1, json_output);
        return Ok(());
    }
    managed::view(project_dir, &args.selector, args.global, json_output)
}

fn print_package_view(package: &str, name: &str, size: u64, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "package",
                "package": format!("@lpm.dev/{package}"),
                "name": name,
                "size": size,
            }))
            .unwrap()
        );
    } else {
        println!("{}", format!("@lpm.dev/{package}/{name}").cyan());
        println!("  kind: package-published");
        println!("  size: {}", lpm_common::format_bytes(size));
        println!("  path: .lpm/skills/{package}/{name}.md");
    }
}

type PackageSkills = Vec<(String, u64)>;
type PackageInventory = Vec<(String, PackageSkills)>;

fn package_inventory(project_dir: &Path) -> Result<PackageInventory, LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    let mut packages = Vec::new();
    let entries = match std::fs::read_dir(skills_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(packages),
        Err(error) => return Err(LpmError::Io(error)),
    };
    for package in entries {
        let package = package?;
        let package_metadata = std::fs::symlink_metadata(package.path())?;
        if package_metadata.file_type().is_symlink() || !package_metadata.is_dir() {
            continue;
        }
        let mut skills = Vec::new();
        for skill in std::fs::read_dir(package.path())? {
            let skill = skill?;
            let path = skill.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && path.extension().is_some_and(|extension| extension == "md")
            {
                skills.push((
                    path.file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    metadata.len(),
                ));
            }
        }
        skills.sort_by(|left, right| left.0.cmp(&right.0));
        if !skills.is_empty() {
            packages.push((package.file_name().to_string_lossy().to_string(), skills));
        }
    }
    packages.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(packages)
}

fn print_package_inventory(packages: &[(String, Vec<(String, u64)>)]) {
    let width = packages
        .iter()
        .flat_map(|(_, skills)| skills.iter().map(|(name, _)| name.len() + ".md".len()))
        .max()
        .unwrap_or(0);
    for (package, skills) in packages {
        println!("{}", install_ui::cyan(&format!("@lpm.dev/{package}")));
        for (name, size) in skills {
            let file_name = format!("{name}.md");
            println!(
                "  {file_name:<width$}  {}",
                lpm_common::format_bytes(*size).dimmed()
            );
        }
        println!();
    }
}

fn validate_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    let report = author::validate_directory(&skills_dir)?;
    if json_output {
        let security = report
            .security_issues
            .iter()
            .map(|located| {
                serde_json::json!({
                    "path": located.path,
                    "rule_id": located.issue.rule_id,
                    "category": located.issue.category,
                    "severity": located.issue.severity,
                    "line": located.issue.line_number,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": report.is_valid(),
                "directory_found": report.directory_found,
                "valid": report.valid_files.len(),
                "files": report.valid_files,
                "errors": report.errors,
                "security_findings": security,
                "total_size_bytes": report.total_size_bytes,
                "ignored_package_sets": report.ignored_package_sets,
                "quality_impact": if report.valid_files.len() >= 3 { 10 } else if !report.valid_files.is_empty() { 7 } else { 0 },
            }))
            .map_err(|error| LpmError::Registry(format!("failed to serialize validation result: {error}")))?
        );
    } else {
        if !report.directory_found {
            install_ui::warn("No .lpm/skills/ directory found");
        } else {
            install_ui::phase("Validating package skills in .lpm/skills/");
            for file in &report.valid_files {
                eprintln!("  {} {file}", install_ui::status_ok("valid"));
            }
        }
        if report.ignored_package_sets > 0 {
            install_ui::warn(&format!(
                "Ignored {} installed LPM.dev package skill {}",
                report.ignored_package_sets,
                plural(report.ignored_package_sets, "set", "sets")
            ));
        }
        for error in &report.errors {
            install_ui::warn(error);
        }
        for located in &report.security_issues {
            install_ui::warn(&format!(
                "{}: {} security finding at line {} ({})",
                located.path,
                located.issue.category,
                located.issue.line_number,
                located.issue.rule_id
            ));
        }
        if report.is_valid() {
            if report.valid_files.is_empty() {
                install_ui::warn("No publisher-authored .lpm/skills/*.md files found");
            } else {
                install_ui::done(&format!(
                    "{} package {} valid · {}",
                    report.valid_files.len(),
                    plural(report.valid_files.len(), "skill", "skills"),
                    lpm_common::format_bytes(report.total_size_bytes)
                ));
            }
        }
    }
    if report.is_valid() {
        Ok(())
    } else if json_output {
        Err(LpmError::ExitCode(1))
    } else {
        Err(LpmError::Script(format!(
            "{} skill validation error(s)",
            report.error_count()
        )))
    }
}

#[derive(Debug, Serialize)]
struct PackageCleanTarget {
    package: String,
    version: Option<String>,
    directory: String,
    files: usize,
    size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PreservedCleanPath {
    path: String,
    reason: String,
}

#[derive(Debug, Default)]
struct PackageCleanPlan {
    directory_found: bool,
    targets: Vec<PackageCleanTarget>,
    publisher_files: Vec<String>,
    skipped: Vec<PreservedCleanPath>,
}

fn clean_skills(project_dir: &Path, args: CleanArgs, json_output: bool) -> Result<(), LpmError> {
    let _lock = package::acquire_mutation_lock(project_dir)?;
    let skills_dir = project_dir.join(".lpm").join("skills");
    let plan = plan_package_clean(&skills_dir)?;
    if !json_output {
        print_package_clean_plan(&plan);
    }

    if args.dry_run || plan.targets.is_empty() {
        if json_output {
            print_clean_json(&plan, args.dry_run, &[], 0, 0)?;
        } else if args.dry_run {
            install_ui::done("Dry run complete · no files changed");
        } else if !plan.directory_found {
            install_ui::warn("No .lpm/skills/ directory found");
        } else {
            install_ui::warn("No installed LPM.dev package skill sets to clean");
        }
        return Ok(());
    }

    require_confirmation(
        args.yes,
        json_output,
        &format!(
            "Remove {} installed LPM.dev package skill {}?",
            plan.targets.len(),
            plural(plan.targets.len(), "set", "sets")
        ),
    )?;

    let mut removed = Vec::with_capacity(plan.targets.len());
    let mut files_removed = 0usize;
    let mut bytes_removed = 0u64;
    for target in &plan.targets {
        let directory = std::path::PathBuf::from(&target.directory);
        let metadata = std::fs::symlink_metadata(&directory).map_err(|error| {
            LpmError::Registry(format!(
                "refusing to clean package skill directory whose type changed after preview: {} ({error})",
                directory.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LpmError::Registry(format!(
                "refusing to clean package skill directory whose type changed after preview: {}",
                directory.display()
            )));
        }
        let expected_package = target
            .package
            .strip_prefix("@lpm.dev/")
            .unwrap_or(&target.package);
        if directory.file_name().and_then(|name| name.to_str()) != Some(expected_package)
            || !package::is_materialized_directory(&directory)
        {
            return Err(LpmError::Registry(format!(
                "refusing to clean package skill directory whose ownership changed after preview: {}",
                directory.display()
            )));
        }
        std::fs::remove_dir_all(&directory)?;
        removed.push(target.package.clone());
        files_removed += target.files;
        bytes_removed = bytes_removed.saturating_add(target.size_bytes);
    }

    if json_output {
        print_clean_json(&plan, false, &removed, files_removed, bytes_removed)?;
    } else {
        install_ui::done(&format!(
            "Removed {} package skill {} · {files_removed} {} · {}",
            removed.len(),
            plural(removed.len(), "set", "sets"),
            plural(files_removed, "file", "files"),
            lpm_common::format_bytes(bytes_removed)
        ));
        eprintln!("  Run lpm install to restore them.");
    }
    Ok(())
}

fn plan_package_clean(skills_dir: &Path) -> Result<PackageCleanPlan, LpmError> {
    let metadata = match std::fs::symlink_metadata(skills_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PackageCleanPlan::default());
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing to clean package skill path that is not a regular directory: {}",
            skills_dir.display()
        )));
    }

    let mut plan = PackageCleanPlan {
        directory_found: true,
        ..PackageCleanPlan::default()
    };
    let mut entries = std::fs::read_dir(skills_dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let display = path.display().to_string();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            plan.skipped.push(PreservedCleanPath {
                path: display,
                reason: "symlinked entries are never cleaned".into(),
            });
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "md")
        {
            plan.publisher_files.push(display);
        } else if metadata.is_dir() {
            let package_name = entry.file_name().to_string_lossy().to_string();
            match package::read_manifest(&path, &package_name) {
                package::PackageManifestStatus::Valid(manifest)
                    if package::is_materialized_directory(&path) =>
                {
                    let (files, size_bytes) = directory_stats(&path)?;
                    plan.targets.push(PackageCleanTarget {
                        package: format!("@lpm.dev/{}", manifest.package),
                        version: manifest.version,
                        directory: display,
                        files,
                        size_bytes,
                    });
                }
                package::PackageManifestStatus::Valid(_) => {
                    plan.skipped.push(PreservedCleanPath {
                        path: display,
                        reason:
                            "directory content no longer matches its LPM CLI ownership manifest"
                                .into(),
                    });
                }
                package::PackageManifestStatus::Missing => {
                    plan.skipped.push(PreservedCleanPath {
                        path: display,
                        reason: "directory has no LPM CLI ownership manifest".into(),
                    });
                }
                package::PackageManifestStatus::Invalid => {
                    plan.skipped.push(PreservedCleanPath {
                        path: display,
                        reason: "directory has an invalid LPM CLI ownership manifest".into(),
                    });
                }
            }
        } else {
            plan.skipped.push(PreservedCleanPath {
                path: display,
                reason: "unrecognized content is preserved".into(),
            });
        }
    }
    Ok(plan)
}

fn directory_stats(directory: &Path) -> Result<(usize, u64), LpmError> {
    let mut files = 0usize;
    let mut size_bytes = 0u64;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || metadata.is_file() {
            files += 1;
            size_bytes = size_bytes.saturating_add(metadata.len());
        } else if metadata.is_dir() {
            let (nested_files, nested_size) = directory_stats(&path)?;
            files += nested_files;
            size_bytes = size_bytes.saturating_add(nested_size);
        }
    }
    Ok((files, size_bytes))
}

fn print_package_clean_plan(plan: &PackageCleanPlan) {
    if !plan.targets.is_empty() {
        install_ui::phase("Installed LPM.dev package skill sets");
        for target in &plan.targets {
            let version = target
                .version
                .as_deref()
                .map_or_else(String::new, |version| format!("@{version}"));
            eprintln!(
                "  {}{version} · {} {} · {}",
                target.package,
                target.files,
                plural(target.files, "file", "files"),
                lpm_common::format_bytes(target.size_bytes)
            );
        }
    }
    if !plan.publisher_files.is_empty() {
        install_ui::phase("Preserved");
        eprintln!(
            "  {} publisher-authored skill {}",
            plan.publisher_files.len(),
            plural(plan.publisher_files.len(), "file", "files")
        );
    }
    for skipped in &plan.skipped {
        install_ui::warn(&format!("Preserving {} — {}", skipped.path, skipped.reason));
    }
}

fn print_clean_json(
    plan: &PackageCleanPlan,
    dry_run: bool,
    removed: &[String],
    files_removed: usize,
    bytes_removed: u64,
) -> Result<(), LpmError> {
    let output = serde_json::json!({
        "success": true,
        "dry_run": dry_run,
        "cleaned": !removed.is_empty(),
        "removed": removed,
        "files_removed": files_removed,
        "bytes_removed": bytes_removed,
        "would_remove": plan.targets,
        "preserved_publisher_files": plan.publisher_files,
        "skipped": plan.skipped,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| LpmError::Registry(format!(
            "failed to serialize cleanup result: {error}"
        )))?
    );
    Ok(())
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn security_severity_label(
    severity: lpm_security::skill_security::SkillSecuritySeverity,
) -> String {
    match severity {
        lpm_security::skill_security::SkillSecuritySeverity::Warning => {
            install_ui::section("warning")
        }
        lpm_security::skill_security::SkillSecuritySeverity::Block => install_ui::red("block"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_package_skill(name: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: A complete package skill for validation\n---\n# Guide\n\n{}",
            "This package guidance explains the supported workflow with concrete examples and enough detail for an agent to use it correctly."
        )
    }

    #[test]
    fn select_skills_rejects_a_missing_requested_name() {
        let discovered = vec![source::DiscoveredSkill::for_test("release-notes")];
        let error = select_skills(&["missing".into()], &discovered, true).unwrap_err();
        assert!(error.to_string().contains("available: release-notes"));
    }

    #[test]
    fn package_inventory_ignores_non_markdown_files() {
        let project = tempfile::tempdir().unwrap();
        let package = project.path().join(".lpm/skills/example.package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("guide.md"), "guide").unwrap();
        std::fs::write(package.join("note.txt"), "note").unwrap();

        let inventory = package_inventory(project.path()).unwrap();

        assert_eq!(
            inventory,
            vec![("example.package".into(), vec![("guide".into(), 5)])]
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_inventory_ignores_symlinked_skill_files() {
        let project = tempfile::tempdir().unwrap();
        let package = project.path().join(".lpm/skills/example.package");
        std::fs::create_dir_all(&package).unwrap();
        let external = project.path().join("external.md");
        std::fs::write(&external, "external").unwrap();
        std::os::unix::fs::symlink(&external, package.join("linked.md")).unwrap();

        let inventory = package_inventory(project.path()).unwrap();

        assert!(inventory.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn package_skill_file_counter_does_not_follow_symlinked_directories() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        let package = skills.join("example.package");
        let external = project.path().join("external");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("one.md"), "one").unwrap();
        std::fs::write(external.join("two.md"), "two").unwrap();
        std::os::unix::fs::symlink(&external, package.join("linked")).unwrap();

        let (count, _) = directory_stats(&package).unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn validate_skills_accepts_flat_publisher_files() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(
            skills.join("getting-started.md"),
            valid_package_skill("getting-started"),
        )
        .unwrap();

        let result = validate_skills(project.path(), false);

        assert!(
            result.is_ok(),
            "flat publisher skills must validate: {result:?}"
        );
    }

    #[test]
    fn validate_skills_rejects_nested_publisher_files() {
        let project = tempfile::tempdir().unwrap();
        let nested = project.path().join(".lpm/skills/guides");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("getting-started.md"),
            valid_package_skill("getting-started"),
        )
        .unwrap();

        let result = validate_skills(project.path(), false);

        assert!(result.is_err(), "nested publisher skills must be rejected");
    }

    #[test]
    fn clean_skills_preserves_publisher_files() {
        let project = tempfile::tempdir().unwrap();
        let skill = project.path().join(".lpm/skills/getting-started.md");
        std::fs::create_dir_all(skill.parent().unwrap()).unwrap();
        std::fs::write(&skill, valid_package_skill("getting-started")).unwrap();

        clean_skills(
            project.path(),
            CleanArgs {
                dry_run: false,
                yes: true,
            },
            false,
        )
        .unwrap();

        assert!(
            skill.exists(),
            "cleanup must preserve publisher-authored files"
        );
    }

    #[test]
    fn clean_skills_removes_only_manifest_owned_package_directories() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[lpm_registry::Skill {
                name: "guide".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some(valid_package_skill("guide")),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();
        let untracked = skills.join("team-notes");
        std::fs::create_dir_all(&untracked).unwrap();
        std::fs::write(untracked.join("notes.md"), "keep").unwrap();

        clean_skills(
            project.path(),
            CleanArgs {
                dry_run: false,
                yes: true,
            },
            false,
        )
        .unwrap();

        assert!(!skills.join("owner.package").exists());
        assert!(untracked.exists());
    }

    #[test]
    fn clean_skills_dry_run_does_not_remove_manifest_owned_directories() {
        let project = tempfile::tempdir().unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[lpm_registry::Skill {
                name: "guide".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some(valid_package_skill("guide")),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();

        clean_skills(
            project.path(),
            CleanArgs {
                dry_run: true,
                yes: false,
            },
            false,
        )
        .unwrap();

        assert!(project.path().join(".lpm/skills/owner.package").exists());
    }

    #[test]
    fn clean_skills_preserves_a_package_directory_with_untracked_content() {
        let project = tempfile::tempdir().unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[lpm_registry::Skill {
                name: "guide".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some(valid_package_skill("guide")),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();
        let directory = project.path().join(".lpm/skills/owner.package");
        std::fs::write(directory.join("notes.txt"), "preserve me").unwrap();

        clean_skills(
            project.path(),
            CleanArgs {
                dry_run: false,
                yes: true,
            },
            false,
        )
        .unwrap();

        assert!(directory.join("notes.txt").exists());
        assert!(directory.join("guide.md").exists());
    }

    #[test]
    fn dashboard_port_zero_is_rejected_in_favor_of_automatic_selection() {
        let error = parse_dashboard_port("0").unwrap_err();

        assert!(error.contains("omit `--port`"));
    }
}
