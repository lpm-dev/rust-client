//! `lpm firewall bypass`: exceptions that let specific package versions past
//! LPM Firewall blocks without turning the firewall off.

use crate::firewall_bypass::{
    AddedVerdict, BlockClass, BypassKind, FirewallBypassRule, FirewallBypassScope,
    FirewallBypassSpec, MAX_SPECS_PER_APPROVAL, bypass_add_command, project_policy_root, rule_json,
};
use crate::install_ui;
use crate::security_approval;
use clap::Subcommand;
use lpm_common::{LpmError, Timestamp};
use lpm_registry::RegistryClient;
use lpm_registry::client::{
    AuthPosture, NpmFirewallAction, NpmFirewallBatchPackage, NpmFirewallDecision,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const BYPASS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Subcommand)]
pub enum FirewallCmd {
    /// Let specific package versions past LPM Firewall blocks, without
    /// turning the firewall off.
    Bypass {
        #[command(subcommand)]
        action: BypassCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum BypassCmd {
    /// Allow package versions that LPM Firewall blocks. Asks for Touch ID,
    /// Windows Hello, or your password.
    ///
    /// A spec is `name` (every version), `name@1.2.3`, or `name@<range>`
    /// such as `react@^18.19.0`. Name and range rules never cover malware or
    /// unscanned versions; an exact version covers malware only with
    /// `--allow-malware`.
    Add {
        #[arg(required = true, value_name = "SPEC")]
        specs: Vec<String>,

        /// Apply only in this project (the current one when no path is given)
        /// instead of in every project.
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = ".")]
        project: Option<PathBuf>,

        /// Remove the rule after this long (`30m`, `12h`, `30d`).
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,

        /// A note `lpm firewall bypass list` shows with the rule.
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,

        /// Also allow an exact version that LPM Firewall flags as malware.
        #[arg(long)]
        allow_malware: bool,
    },

    /// Show bypass rules.
    #[command(visible_alias = "ls")]
    List {
        /// Only rules for this project (the current one when no path is given).
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            default_missing_value = ".",
            conflicts_with = "global"
        )]
        project: Option<PathBuf>,

        /// Only rules for every project.
        #[arg(long)]
        global: bool,
    },

    /// Remove bypass rules by spec or id. Needs no approval.
    #[command(visible_alias = "rm")]
    Remove {
        #[arg(required = true, value_name = "SPEC_OR_ID")]
        targets: Vec<String>,

        /// Remove this project's rule (the current one when no path is given)
        /// instead of the rule for every project.
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = ".")]
        project: Option<PathBuf>,
    },

    /// Remove every bypass rule, or only the global or one project's. Needs
    /// no approval.
    Clear {
        /// Only this project's rules (the current one when no path is given).
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            default_missing_value = ".",
            conflicts_with = "global"
        )]
        project: Option<PathBuf>,

        /// Only the rules for every project.
        #[arg(long)]
        global: bool,
    },
}

pub async fn run(
    cmd: &FirewallCmd,
    client: &RegistryClient,
    cwd: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let FirewallCmd::Bypass { action } = cmd;
    match action {
        BypassCmd::Add {
            specs,
            project,
            ttl,
            reason,
            allow_malware,
        } => {
            let request = AddRequest {
                specs,
                project: project.as_deref(),
                ttl: ttl.as_deref(),
                reason: reason.as_deref(),
                allow_malware: *allow_malware,
            };
            add(client, cwd, &request, json_output).await
        }
        BypassCmd::List { project, global } => list(cwd, project.as_deref(), *global, json_output),
        BypassCmd::Remove { targets, project } => {
            remove(cwd, targets, project.as_deref(), json_output)
        }
        BypassCmd::Clear { project, global } => {
            clear(cwd, project.as_deref(), *global, json_output)
        }
    }
}

struct AddRequest<'a> {
    specs: &'a [String],
    project: Option<&'a Path>,
    ttl: Option<&'a str>,
    reason: Option<&'a str>,
    allow_malware: bool,
}

/// Where a rule applies: every project, or one project root.
struct RuleScope {
    scope: FirewallBypassScope,
    project_root: Option<String>,
}

impl RuleScope {
    fn resolve(cwd: &Path, project: Option<&Path>) -> Result<Self, LpmError> {
        match project {
            None => Ok(Self {
                scope: FirewallBypassScope::Global,
                project_root: None,
            }),
            Some(path) => Ok(Self {
                scope: FirewallBypassScope::Project,
                project_root: Some(project_policy_root(&cwd.join(path))?.display().to_string()),
            }),
        }
    }

    fn holds(&self, rule: &FirewallBypassRule) -> bool {
        rule.scope == self.scope && rule.project_root == self.project_root
    }

    fn describe(&self) -> String {
        match &self.project_root {
            None => "in every project".to_string(),
            Some(root) => {
                let name = Path::new(root)
                    .file_name()
                    .map_or_else(|| root.clone(), |name| name.to_string_lossy().into_owned());
                format!(
                    "in the {} project",
                    lpm_common::sanitize_server_text(&name, 60)
                )
            }
        }
    }
}

fn parse_specs(raw_specs: &[String]) -> Result<Vec<FirewallBypassSpec>, LpmError> {
    let mut specs: Vec<FirewallBypassSpec> = Vec::with_capacity(raw_specs.len());
    for raw in raw_specs {
        let spec = FirewallBypassSpec::parse(raw).map_err(|error| {
            LpmError::InvalidPackageName(format!(
                "`{}`: {error}",
                lpm_common::sanitize_server_text(raw, 120)
            ))
        })?;
        if !specs
            .iter()
            .any(|existing| existing.to_string() == spec.to_string())
        {
            specs.push(spec);
        }
    }
    Ok(specs)
}

/// The verdict LPM Firewall gives an exact version right now, as `add`
/// shows it before asking for approval.
enum Preview {
    Blocked(Box<NpmFirewallDecision>),
    NotBlocked,
    Unavailable(String),
}

async fn preview_exact_specs(
    client: &RegistryClient,
    specs: &[FirewallBypassSpec],
) -> HashMap<String, Preview> {
    let packages: Vec<NpmFirewallBatchPackage> = specs
        .iter()
        .filter(|spec| spec.kind() == BypassKind::Exact)
        .filter_map(|spec| {
            Some(NpmFirewallBatchPackage {
                name: spec.name().to_string(),
                version: spec.version_text()?,
                integrity: None,
                published_at: None,
            })
        })
        .collect();
    let mut previews = HashMap::with_capacity(packages.len());
    if packages.is_empty() {
        return previews;
    }
    let profile = security_approval::load_effective_authorized_posture()
        .map(|effective| effective.posture.firewall_policy_profile())
        .unwrap_or_default();
    match client
        .npm_firewall_batch_verdicts_with_posture_and_policy(
            &packages,
            AuthPosture::AuthRequired,
            Some(profile),
        )
        .await
    {
        Ok(response) => {
            let mut blocked: HashMap<(String, String), NpmFirewallDecision> = response
                .decisions
                .into_iter()
                .filter(|decision| decision.action == NpmFirewallAction::Block)
                .map(|decision| ((decision.name.clone(), decision.version.clone()), decision))
                .collect();
            for package in packages {
                let key = (package.name, package.version);
                let preview = match blocked.remove(&key) {
                    Some(decision) => Preview::Blocked(Box::new(decision)),
                    None => Preview::NotBlocked,
                };
                previews.insert(format!("{}@{}", key.0, key.1), preview);
            }
        }
        Err(error) => {
            let reason = lpm_common::sanitize_server_text(&error.to_string(), 200);
            for package in packages {
                previews.insert(
                    format!("{}@{}", package.name, package.version),
                    Preview::Unavailable(reason.clone()),
                );
            }
        }
    }
    previews
}

fn block_class_of(decision: &NpmFirewallDecision) -> BlockClass {
    BlockClass::of(
        &decision.verdict,
        decision.policy.as_ref().map(|policy| policy.group.as_str()),
    )
}

/// Refuses a spec whose current block its rule could not lift, and
/// `--allow-malware` for anything but a version LPM Firewall currently
/// blocks as malware.
fn check_previews(
    specs: &[FirewallBypassSpec],
    previews: &HashMap<String, Preview>,
    allow_malware: bool,
) -> Result<(), LpmError> {
    for spec in specs {
        let coordinate = spec.to_string();
        let preview = previews.get(&coordinate);
        let class = match preview {
            Some(Preview::Blocked(decision)) => Some(block_class_of(decision)),
            _ => None,
        };
        if class == Some(BlockClass::ServerReview) {
            return Err(LpmError::SecurityFloor(format!(
                "{coordinate} is held for LPM review, which a local rule can't lift"
            )));
        }
        if class == Some(BlockClass::Malware) && !allow_malware {
            return Err(LpmError::SecurityFloor(format!(
                "LPM Firewall blocks {coordinate} as malware; a rule covers that only when added with `--allow-malware`"
            )));
        }
        if allow_malware && class != Some(BlockClass::Malware) {
            return Err(LpmError::SecurityFloor(match preview {
                Some(Preview::Unavailable(reason)) => format!(
                    "couldn't check the current verdict for {coordinate} ({reason}); `--allow-malware` needs LPM Firewall to report the malware verdict first"
                ),
                _ => format!(
                    "LPM Firewall doesn't block {coordinate} as malware; run the command without `--allow-malware`"
                ),
            }));
        }
    }
    Ok(())
}

fn added_verdict(preview: Option<&Preview>) -> Option<AddedVerdict> {
    let Some(Preview::Blocked(decision)) = preview else {
        return None;
    };
    Some(AddedVerdict {
        verdict: decision.verdict.clone(),
        block_class: block_class_of(decision).as_str().to_string(),
        policy_group: decision.policy.as_ref().map(|policy| policy.group.clone()),
        report_url: decision
            .display
            .as_ref()
            .and_then(|display| display.report_url.clone()),
    })
}

/// The command a person runs to add `specs` with the same options.
fn add_command_hint(specs: &[FirewallBypassSpec], request: &AddRequest<'_>) -> String {
    let coordinates: Vec<String> = specs.iter().map(ToString::to_string).collect();
    let mut command = bypass_add_command(coordinates.iter().map(String::as_str));
    if let Some(project) = request.project {
        command.push_str(" --project \"");
        command.push_str(&project.display().to_string().replace('"', ""));
        command.push('"');
    }
    if let Some(ttl) = request.ttl {
        command.push_str(" --ttl ");
        command.push_str(ttl);
    }
    if request.allow_malware {
        command.push_str(" --allow-malware");
    }
    command
}

/// The native prompt: what is allowed, where, and for how long. Built only
/// from validated specs and fixed text.
fn approval_prompt(
    specs: &[FirewallBypassSpec],
    scope: &RuleScope,
    ttl_secs: Option<u64>,
    allow_malware: bool,
) -> String {
    let mut prompt = match specs {
        [spec] => format!("Allow {}", spec.describe()),
        _ => format!("Allow {} packages", specs.len()),
    };
    if allow_malware {
        prompt.push_str(", including a malware verdict,");
    }
    prompt.push_str(" past LPM Firewall ");
    prompt.push_str(&scope.describe());
    if let Some(ttl_secs) = ttl_secs {
        prompt.push_str(" for ");
        prompt.push_str(&security_approval::format_unlock_duration(ttl_secs));
    }
    if specs.len() > 1 {
        prompt.push_str(": ");
        prompt.push_str(
            &specs
                .iter()
                .map(FirewallBypassSpec::describe)
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    prompt
}

fn print_add_request(
    specs: &[FirewallBypassSpec],
    previews: &HashMap<String, Preview>,
    scope: &RuleScope,
) {
    install_ui::warn_untrusted(&format!("LPM Firewall bypass {}:", scope.describe()));
    for spec in specs {
        match previews.get(&spec.to_string()) {
            Some(Preview::Blocked(decision)) => {
                crate::commands::install::print_npm_firewall_decisions(&[decision.as_ref()]);
            }
            Some(Preview::NotBlocked) => install_ui::detail_line(install_ui::terminal_line!(
                "  › {} - {}",
                install_ui::field(&spec.to_string()),
                install_ui::dim("not blocked by LPM Firewall right now"),
            )),
            Some(Preview::Unavailable(reason)) => {
                install_ui::detail_line(install_ui::terminal_line!(
                    "  › {} - {}",
                    install_ui::field(&spec.to_string()),
                    install_ui::dim(&format!("current verdict unavailable: {reason}")),
                ));
            }
            None => install_ui::detail_line(install_ui::terminal_line!(
                "  › {} - {}",
                install_ui::field(&spec.describe()),
                install_ui::dim("never covers malware or unscanned versions"),
            )),
        }
    }
}

fn parse_ttl(ttl: Option<&str>) -> Result<Option<u64>, LpmError> {
    let Some(raw) = ttl else {
        return Ok(None);
    };
    let secs = crate::release_age_config::parse_duration(raw).map_err(|_| invalid_ttl(raw))?;
    if secs == 0 {
        return Err(invalid_ttl(raw));
    }
    Ok(Some(secs))
}

fn invalid_ttl(raw: &str) -> LpmError {
    LpmError::Registry(format!(
        "invalid `--ttl` value `{}`; use a positive duration such as `30m`, `12h` or `30d`",
        lpm_common::sanitize_server_text(raw, 40)
    ))
}

fn refuse_under_forced_firewall_floor() -> Result<(), LpmError> {
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    if crate::security_floor::force_security_floor_enabled(&global)
        && crate::security_floor::current_firewall_floor(&global)?
            == crate::npm_firewall_config::NpmFirewallMode::Enforce
    {
        return Err(LpmError::SecurityFloor(
            "`force-security-floor = true` keeps the npm firewall enforcing every block; lower the floor intentionally in ~/.lpm/config.toml before adding a bypass rule".to_string(),
        ));
    }
    Ok(())
}

async fn add(
    client: &RegistryClient,
    cwd: &Path,
    request: &AddRequest<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let specs = parse_specs(request.specs)?;
    if request.allow_malware
        && let Some(spec) = specs.iter().find(|spec| spec.kind() != BypassKind::Exact)
    {
        return Err(LpmError::InvalidPackageName(format!(
            "`--allow-malware` applies only to exact versions such as `name@1.2.3`; `{spec}` names more"
        )));
    }
    let ttl_secs = parse_ttl(request.ttl)?;
    let scope = RuleScope::resolve(cwd, request.project)?;
    refuse_under_forced_firewall_floor()?;
    let effective = security_approval::load_effective_authorized_posture()?;
    if let Some(reason) = security_approval::local_firewall_bypass_inactive_reason(&effective) {
        return Err(LpmError::SecurityFloor(reason));
    }

    let previews = if json_output {
        HashMap::new()
    } else {
        let previews = preview_exact_specs(client, &specs).await;
        check_previews(&specs, &previews, request.allow_malware)?;
        print_add_request(&specs, &previews, &scope);
        previews
    };

    let now = Timestamp::now();
    let expires_at = ttl_secs.and_then(|secs| {
        now.checked_add(lpm_common::timestamp::Duration::seconds(
            i64::try_from(secs).unwrap_or(i64::MAX),
        ))
    });
    let mut outcome = security_approval::FirewallBypassAdded::default();
    for batch in specs.chunks(MAX_SPECS_PER_APPROVAL) {
        let rules = batch
            .iter()
            .map(|spec| {
                let mut rule = FirewallBypassRule::new(
                    spec,
                    scope.scope,
                    scope.project_root.clone(),
                    request.allow_malware,
                    now,
                );
                rule.expires_at = expires_at;
                rule.reason = request
                    .reason
                    .map(|reason| lpm_common::sanitize_server_text(reason, 200));
                rule.added_verdict = added_verdict(previews.get(&spec.to_string()));
                rule
            })
            .collect();
        let prompt = approval_prompt(batch, &scope, ttl_secs, request.allow_malware);
        let command_hint = add_command_hint(batch, request);
        let added = security_approval::add_firewall_bypass_rules(
            security_approval::FirewallBypassApproval {
                rules,
                prompt: &prompt,
                command_hint: &command_hint,
                json_output,
            },
        );
        match added {
            Ok(batch_outcome) => {
                outcome.added.extend(batch_outcome.added);
                outcome.unchanged.extend(batch_outcome.unchanged);
            }
            Err(error) => {
                if !json_output && !outcome.added.is_empty() {
                    report_added(&outcome, &scope);
                }
                return Err(error);
            }
        }
    }

    if json_output {
        let rules_total = security_approval::load_local_firewall_bypass_rules()?.len();
        print_json(&serde_json::json!({
            "schema_version": BYPASS_SCHEMA_VERSION,
            "success": true,
            "added": outcome.added.iter().map(|rule| rule_json(rule, "local", now)).collect::<Vec<_>>(),
            "unchanged": outcome.unchanged.iter().map(|rule| rule_json(rule, "local", now)).collect::<Vec<_>>(),
            "count": outcome.added.len(),
            "rules_total": rules_total,
        }));
    } else {
        report_added(&outcome, &scope);
    }
    Ok(())
}

fn report_added(outcome: &security_approval::FirewallBypassAdded, scope: &RuleScope) {
    if !outcome.added.is_empty() {
        let specs: Vec<&str> = outcome
            .added
            .iter()
            .map(|rule| rule.spec.as_str())
            .collect();
        install_ui::done_untrusted(&format!(
            "LPM Firewall now allows {} {}.",
            specs.join(", "),
            scope.describe()
        ));
    }
    if !outcome.unchanged.is_empty() {
        let specs: Vec<&str> = outcome
            .unchanged
            .iter()
            .map(|rule| rule.spec.as_str())
            .collect();
        install_ui::done_untrusted(&format!(
            "Already allowed {}: {}.",
            scope.describe(),
            specs.join(", ")
        ));
    }
}

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON values serialize")
    );
}

fn list(
    cwd: &Path,
    project: Option<&Path>,
    global: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let effective = security_approval::load_effective_authorized_posture()?;
    let inactive_reason = security_approval::local_firewall_bypass_inactive_reason(&effective);
    let filter = match (project, global) {
        (Some(path), _) => Some(RuleScope::resolve(cwd, Some(path))?),
        (None, true) => Some(RuleScope::resolve(cwd, None)?),
        (None, false) => None,
    };
    let mut rules = security_approval::load_local_firewall_bypass_rules()?;
    if let Some(filter) = &filter {
        rules.retain(|rule| filter.holds(rule));
    }
    let now = Timestamp::now();
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    let firewall_mode = crate::npm_firewall_config::runtime_request_mode(&global)?.map_or_else(
        || effective.posture.firewall_mode(),
        |request| request.mode(),
    );

    if json_output {
        print_json(&serde_json::json!({
            "schema_version": BYPASS_SCHEMA_VERSION,
            "success": true,
            "firewall_mode": firewall_mode.as_str(),
            "local_rules_apply": inactive_reason.is_none(),
            "inactive_reason": inactive_reason,
            "rules": rules.iter().map(|rule| rule_json(rule, "local", now)).collect::<Vec<_>>(),
            "managed_rules": effective
                .managed_firewall_bypass
                .iter()
                .map(|rule| serde_json::json!({
                    "spec": rule.spec,
                    "covers_malware": rule.covers_malware,
                    "source": "managed",
                }))
                .collect::<Vec<_>>(),
            "count": rules.len(),
        }));
        return Ok(());
    }

    if rules.is_empty() && effective.managed_firewall_bypass.is_empty() {
        install_ui::done("No LPM Firewall bypass rules.");
        return Ok(());
    }
    if let Some(reason) = &inactive_reason {
        install_ui::warn_untrusted(reason);
    }
    if !rules.is_empty() {
        println!("{}", install_ui::section("firewall bypass rules"));
        let mut table = install_ui::Table::new();
        for rule in &rules {
            let scope = match &rule.project_root {
                Some(root) => install_ui::cyan(root),
                None => install_ui::dim("every project"),
            };
            let mut notes = Vec::with_capacity(3);
            if rule.covers_malware {
                notes.push("includes malware".to_string());
            }
            if let Some(expires_at) = rule.expires_at {
                notes.push(if rule.is_expired(now) {
                    "expired".to_string()
                } else {
                    format!("until {}", expires_at.to_rfc3339_seconds())
                });
            }
            if let Some(reason) = &rule.reason {
                notes.push(reason.clone());
            }
            table.row([
                install_ui::field(&rule.spec),
                scope,
                install_ui::dim(&rule.id),
                install_ui::dim(&notes.join(" · ")),
            ]);
        }
        table.print_stdout();
    }
    if !effective.managed_firewall_bypass.is_empty() {
        println!("{}", install_ui::section("managed firewall bypass rules"));
        let mut table = install_ui::Table::new();
        for rule in &effective.managed_firewall_bypass {
            table.row([
                install_ui::field(&rule.spec),
                install_ui::dim(if rule.covers_malware {
                    "includes malware"
                } else {
                    ""
                }),
            ]);
        }
        table.print_stdout();
    }
    Ok(())
}

fn remove(
    cwd: &Path,
    targets: &[String],
    project: Option<&Path>,
    json_output: bool,
) -> Result<(), LpmError> {
    let scope = RuleScope::resolve(cwd, project)?;
    let mut ids = Vec::with_capacity(targets.len());
    let mut specs = Vec::with_capacity(targets.len());
    for target in targets {
        if target.starts_with("fwb_") {
            ids.push(target.clone());
        } else {
            specs.push(
                parse_specs(std::slice::from_ref(target))?
                    .remove(0)
                    .to_string(),
            );
        }
    }
    let removed = security_approval::remove_firewall_bypass_rules(
        |rule| ids.contains(&rule.id) || (scope.holds(rule) && specs.contains(&rule.spec)),
        "firewall-bypass-removed",
    )?;
    let not_found: Vec<&String> = targets
        .iter()
        .filter(|target| {
            !removed
                .iter()
                .any(|rule| &rule.id == *target || matches_spec(rule, target))
        })
        .collect();
    report_removed(&removed, &not_found, json_output)
}

fn matches_spec(rule: &FirewallBypassRule, target: &str) -> bool {
    FirewallBypassSpec::parse(target).is_ok_and(|spec| spec.to_string() == rule.spec)
}

fn clear(
    cwd: &Path,
    project: Option<&Path>,
    global: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let filter = match (project, global) {
        (Some(path), _) => Some(RuleScope::resolve(cwd, Some(path))?),
        (None, true) => Some(RuleScope::resolve(cwd, None)?),
        (None, false) => None,
    };
    let removed = security_approval::remove_firewall_bypass_rules(
        |rule| filter.as_ref().is_none_or(|filter| filter.holds(rule)),
        "firewall-bypass-cleared",
    )?;
    report_removed(&removed, &[], json_output)
}

fn report_removed(
    removed: &[FirewallBypassRule],
    not_found: &[&String],
    json_output: bool,
) -> Result<(), LpmError> {
    let now = Timestamp::now();
    if json_output {
        let rules_total = security_approval::load_local_firewall_bypass_rules()?.len();
        print_json(&serde_json::json!({
            "schema_version": BYPASS_SCHEMA_VERSION,
            "success": true,
            "removed": removed.iter().map(|rule| rule_json(rule, "local", now)).collect::<Vec<_>>(),
            "not_found": not_found,
            "count": removed.len(),
            "rules_total": rules_total,
        }));
        return Ok(());
    }
    for target in not_found {
        install_ui::warn_untrusted(&format!("No LPM Firewall bypass rule matches {target}."));
    }
    if removed.is_empty() {
        if not_found.is_empty() {
            install_ui::done("No LPM Firewall bypass rules to remove.");
        }
        return Ok(());
    }
    let specs: Vec<&str> = removed.iter().map(|rule| rule.spec.as_str()).collect();
    install_ui::done_untrusted(&format!(
        "Removed LPM Firewall bypass for {}. Copies already installed stay until you reinstall.",
        specs.join(", ")
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs(raw: &[&str]) -> Vec<FirewallBypassSpec> {
        parse_specs(
            &raw.iter()
                .map(|spec| (*spec).to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn global() -> RuleScope {
        RuleScope {
            scope: FirewallBypassScope::Global,
            project_root: None,
        }
    }

    #[test]
    fn approval_prompt_names_the_version_the_scope_and_the_duration() {
        assert_eq!(
            approval_prompt(&specs(&["foldrun@32.8.2"]), &global(), None, false),
            "Allow foldrun@32.8.2 past LPM Firewall in every project"
        );
        assert_eq!(
            approval_prompt(
                &specs(&["foldrun@32.8.2"]),
                &global(),
                Some(30 * 86_400),
                true
            ),
            "Allow foldrun@32.8.2, including a malware verdict, past LPM Firewall in every project for 30d"
        );
    }

    #[test]
    fn approval_prompt_lists_every_spec_of_a_batch() {
        let prompt = approval_prompt(
            &specs(&["a@1.0.0", "b", "c@^2.0.0"]),
            &global(),
            None,
            false,
        );

        assert_eq!(
            prompt,
            "Allow 3 packages past LPM Firewall in every project: a@1.0.0, every b version, c versions matching ^2.0.0"
        );
    }

    #[test]
    fn approval_prompt_names_the_project_for_a_project_rule() {
        let scope = RuleScope {
            scope: FirewallBypassScope::Project,
            project_root: Some("/work/sil".into()),
        };

        assert_eq!(
            approval_prompt(&specs(&["foldrun"]), &scope, None, false),
            "Allow every foldrun version past LPM Firewall in the sil project"
        );
    }

    #[test]
    fn add_command_hint_quotes_specs_for_every_shell() {
        let request = AddRequest {
            specs: &[],
            project: None,
            ttl: Some("30d"),
            reason: None,
            allow_malware: false,
        };

        assert_eq!(
            add_command_hint(&specs(&["@scope/pkg@^1.2.0", "foldrun@32.8.2"]), &request),
            "lpm firewall bypass add \"@scope/pkg@^1.2.0\" \"foldrun@32.8.2\" --ttl 30d"
        );
    }

    #[test]
    fn parse_specs_drops_duplicates_by_canonical_text() {
        assert_eq!(specs(&["react@>=18  <19", "react@>=18 <19"]).len(), 1);
    }

    fn blocked(group: &str, verdict: &str) -> Preview {
        Preview::Blocked(Box::new(
            serde_json::from_value(serde_json::json!({
                "decisionId": "d",
                "name": "foldrun",
                "version": "32.8.2",
                "action": "block",
                "verdict": verdict,
                "reason": "r",
                "matchSource": "package",
                "policyMode": "enforce",
                "policy": { "group": group }
            }))
            .unwrap(),
        ))
    }

    #[test]
    fn previews_refuse_a_malware_block_without_allow_malware() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            blocked("lpm_ai_confirmed_malware", "malicious"),
        )]);

        let error = check_previews(&specs(&["foldrun@32.8.2"]), &previews, false).unwrap_err();

        assert!(error.to_string().contains("--allow-malware"), "{error}");
        assert!(check_previews(&specs(&["foldrun@32.8.2"]), &previews, true).is_ok());
    }

    #[test]
    fn previews_refuse_allow_malware_for_a_version_not_blocked_as_malware() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            blocked("lpm_ai_agent_control_surface", "suspicious"),
        )]);

        assert!(check_previews(&specs(&["foldrun@32.8.2"]), &previews, true).is_err());
        assert!(check_previews(&specs(&["foldrun@32.8.2"]), &previews, false).is_ok());
    }

    #[test]
    fn previews_refuse_allow_malware_when_the_verdict_is_unavailable() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            Preview::Unavailable("offline".into()),
        )]);

        let error = check_previews(&specs(&["foldrun@32.8.2"]), &previews, true).unwrap_err();

        assert!(error.to_string().contains("couldn't check"), "{error}");
    }

    #[test]
    fn previews_refuse_a_server_review_hold() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            blocked("lpm_administrative_review", "clean"),
        )]);

        assert!(check_previews(&specs(&["foldrun@32.8.2"]), &previews, true).is_err());
    }
}
