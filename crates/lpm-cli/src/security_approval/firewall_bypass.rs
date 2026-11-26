//! The signed store of `lpm firewall bypass` rules and the approval that
//! guards adding to it.

use super::prelude::*;
use crate::firewall_bypass::FirewallBypassRule;

const FIREWALL_BYPASS_KIND: &str = "firewall-bypass";
const FIREWALL_BYPASS_SCHEMA_VERSION: u64 = 1;
const FIREWALL_BYPASS_AUDIT_SCOPE: &str = "firewall-bypass";

#[derive(Clone, Serialize, Deserialize)]
struct FirewallBypassFile {
    kind: String,
    schema_version: u64,
    #[serde(default)]
    rules: Vec<FirewallBypassRule>,
}

pub(crate) fn firewall_bypass_file_exists() -> Result<bool, LpmError> {
    Ok(firewall_bypass_path()?.try_exists()?)
}

/// Why a signed bypass file can't be used.
enum StoreProblem {
    WrongKind,
    Newer(u64),
    Invalid(String),
}

fn decode_store(value: serde_json::Value) -> Result<Vec<FirewallBypassRule>, StoreProblem> {
    if value.get("kind").and_then(serde_json::Value::as_str) != Some(FIREWALL_BYPASS_KIND) {
        return Err(StoreProblem::WrongKind);
    }
    match value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(FIREWALL_BYPASS_SCHEMA_VERSION) => {}
        Some(newer) if newer > FIREWALL_BYPASS_SCHEMA_VERSION => {
            return Err(StoreProblem::Newer(newer));
        }
        _ => {
            return Err(StoreProblem::Invalid(
                "missing or unknown schema_version".to_string(),
            ));
        }
    }
    serde_json::from_value::<FirewallBypassFile>(value)
        .map(|file| file.rules)
        .map_err(|error| StoreProblem::Invalid(error.to_string()))
}

/// Every local rule, expired ones included, after verifying the store's
/// signature. A missing store holds no rules.
pub(crate) fn load_local_firewall_bypass_rules() -> Result<Vec<FirewallBypassRule>, LpmError> {
    let path = firewall_bypass_path()?;
    let Some(value) = read_signed_json::<serde_json::Value>(&path)? else {
        return Ok(Vec::new());
    };
    decode_store(value).map_err(|problem| {
        LpmError::SecurityApprovalStore(match problem {
            StoreProblem::WrongKind => format!(
                "{} is not an LPM Firewall bypass rule file; run `lpm security repair`",
                path.display()
            ),
            StoreProblem::Newer(schema) => format!(
                "{} was written by a newer LPM CLI (schema {schema}); update LPM CLI to apply its bypass rules",
                path.display()
            ),
            StoreProblem::Invalid(error) => format!(
                "{} has invalid bypass rules: {error}; run `lpm security repair`",
                path.display()
            ),
        })
    })
}

/// Why `lpm security repair` quarantines a bypass file whose signature
/// verified: another kind of file, or rules this CLI can't read. A file from
/// a newer LPM CLI is kept for that CLI.
pub(super) fn firewall_bypass_store_quarantine_reason(value: serde_json::Value) -> Option<String> {
    match decode_store(value) {
        Err(StoreProblem::WrongKind) => Some("not an LPM Firewall bypass rule file".to_string()),
        Err(StoreProblem::Invalid(error)) => Some(format!("invalid bypass rules: {error}")),
        Ok(_) | Err(StoreProblem::Newer(_)) => None,
    }
}

/// Runs `change` on the local rules under the store's lock and, when it
/// changed them, saves the result without the rules that have expired. An
/// empty store is removed so a command with no rules reads nothing. Returns
/// `change`'s result and how many unexpired rules the store keeps.
///
/// `change` gets the instant the save prunes at, so a rule it judges
/// unexpired is never pruned behind its back.
pub(super) fn update_local_firewall_bypass_rules<T>(
    change: impl FnOnce(&mut Vec<FirewallBypassRule>, Timestamp) -> T,
) -> Result<(T, usize), LpmError> {
    std::fs::create_dir_all(security_dir()?)?;
    lpm_common::with_exclusive_lock(firewall_bypass_lock_path()?, || {
        let mut rules = load_local_firewall_bypass_rules()?;
        let before = rules.clone();
        let now = Timestamp::now();
        let result = change(&mut rules, now);
        if rules == before {
            let unexpired = rules.iter().filter(|rule| !rule.is_expired(now)).count();
            return Ok((result, unexpired));
        }
        rules.retain(|rule| !rule.is_expired(now));
        let rules_kept = rules.len();
        let path = firewall_bypass_path()?;
        if rules.is_empty() {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
        } else {
            write_signed_json(
                &path,
                &FirewallBypassFile {
                    kind: FIREWALL_BYPASS_KIND.to_string(),
                    schema_version: FIREWALL_BYPASS_SCHEMA_VERSION,
                    rules,
                },
            )?;
        }
        Ok((result, rules_kept))
    })
}

/// Why rules added here don't apply, when a managed policy owns the firewall.
pub(crate) fn local_firewall_bypass_inactive_reason(
    effective: &EffectiveAuthorizedPosture,
) -> Option<String> {
    let managed = matches!(
        effective.sources.firewall_mode,
        PostureSourceKind::ManagedPolicy
    ) || matches!(
        effective.sources.firewall_policies,
        PostureSourceKind::ManagedPolicy
    );
    managed.then(|| {
        let path = effective
            .managed_policy
            .as_ref()
            .map_or("the managed security policy", |policy| policy.path.as_str());
        format!(
            "{path} manages the npm firewall, so only its `[firewall].bypass` list applies; ask its administrator to add the package there"
        )
    })
}

/// The bypass status for `lpm security status`: every rule without a target,
/// the global rules for `--global`, and the global rules plus the project's
/// own for a project.
pub(crate) fn load_firewall_bypass_status(
    effective: &EffectiveAuthorizedPosture,
    project_dir: Option<&Path>,
    global: bool,
) -> FirewallBypassStatus {
    let inactive_reason = local_firewall_bypass_inactive_reason(effective);
    let now = Timestamp::now();
    let project_root = project_dir
        .filter(|_| !global)
        .and_then(|dir| crate::firewall_bypass::project_policy_root_text(dir).ok());
    let (rules, error) = match load_local_firewall_bypass_rules() {
        Ok(mut rules) => {
            rules.retain(|rule| {
                !rule.is_expired(now)
                    && match rule.scope {
                        crate::firewall_bypass::FirewallBypassScope::Global => true,
                        crate::firewall_bypass::FirewallBypassScope::Project => {
                            !global && (project_dir.is_none() || rule.project_root == project_root)
                        }
                    }
            });
            (rules, None)
        }
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    FirewallBypassStatus {
        local_rules_apply: inactive_reason.is_none(),
        inactive_reason,
        rules,
        managed_rules: effective.managed_firewall_bypass.clone(),
        error,
    }
}

/// How a requested rule compares with the saved rule it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirewallBypassChange {
    /// No unexpired rule is saved; adding it needs approval.
    New,
    /// It lasts longer than the saved rule; extending it needs approval.
    Extended,
    /// It expires sooner or carries a new note; it lets nothing more through.
    Narrowed,
    Unchanged,
}

fn firewall_bypass_change(
    saved: Option<&FirewallBypassRule>,
    requested: &FirewallBypassRule,
) -> FirewallBypassChange {
    let Some(saved) = saved else {
        return FirewallBypassChange::New;
    };
    let extends = match (saved.expires_at, requested.expires_at) {
        (Some(_), None) => true,
        (Some(saved), Some(requested)) => requested > saved,
        (None, _) => false,
    };
    if extends {
        FirewallBypassChange::Extended
    } else if requested.expires_at != saved.expires_at
        || (requested.reason.is_some() && requested.reason != saved.reason)
    {
        FirewallBypassChange::Narrowed
    } else {
        FirewallBypassChange::Unchanged
    }
}

/// The rule saved for `requested`: the requested rule, keeping the saved
/// note and verdict when it brings none, and the saved approval time when it
/// only narrows.
fn merged_rule(
    saved: Option<&FirewallBypassRule>,
    requested: FirewallBypassRule,
    change: FirewallBypassChange,
) -> FirewallBypassRule {
    let Some(saved) = saved else {
        return requested;
    };
    FirewallBypassRule {
        added_at: if change == FirewallBypassChange::Narrowed {
            saved.added_at
        } else {
            requested.added_at
        },
        reason: requested.reason.or_else(|| saved.reason.clone()),
        added_verdict: requested
            .added_verdict
            .or_else(|| saved.added_verdict.clone()),
        ..requested
    }
}

/// Requested rules sorted, against the store as it is now, by what saving
/// them takes. The save judges every requested rule again under the store's
/// lock, the unchanged ones included, so one removed or expired meanwhile
/// comes back for approval.
#[derive(Debug, Default)]
pub(crate) struct FirewallBypassRequests {
    /// New or extended rules, which a person approves.
    pub(crate) needs_approval: Vec<FirewallBypassRule>,
    /// Requested rules that only narrow a saved one.
    pub(crate) narrowed: Vec<FirewallBypassRule>,
    /// Requested rules the store already holds as asked.
    pub(crate) unchanged: Vec<FirewallBypassRule>,
}

pub(crate) fn sort_firewall_bypass_requests(
    rules: Vec<FirewallBypassRule>,
) -> Result<FirewallBypassRequests, LpmError> {
    let now = Timestamp::now();
    let existing = load_local_firewall_bypass_rules()?;
    let mut sorted = FirewallBypassRequests::default();
    for rule in rules {
        let saved = existing
            .iter()
            .find(|saved| saved.is_same_rule_as(&rule) && !saved.is_expired(now));
        match firewall_bypass_change(saved, &rule) {
            FirewallBypassChange::Unchanged => sorted.unchanged.push(rule),
            FirewallBypassChange::Narrowed => sorted.narrowed.push(rule),
            FirewallBypassChange::New | FirewallBypassChange::Extended => {
                sorted.needs_approval.push(rule);
            }
        }
    }
    Ok(sorted)
}

fn bypass_audit(event: &str, allowed: bool, rules: &[FirewallBypassRule], detail: &str) {
    let mut record = AuditRecord::new(
        event,
        allowed,
        vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
    )
    .packages(rules.iter().map(|rule| rule.spec.clone()).collect())
    .source(ApprovalSource::SecurityCommand)
    .detail(detail);
    if let Some(root) = rules.iter().find_map(|rule| rule.project_root.clone()) {
        record = record.project_root(root);
    }
    record_audit_event(record);
}

/// What one `add` saved.
#[derive(Debug, Default)]
pub(crate) struct FirewallBypassAdded {
    pub(crate) added: Vec<FirewallBypassRule>,
    pub(crate) extended: Vec<FirewallBypassRule>,
    pub(crate) narrowed: Vec<FirewallBypassRule>,
    pub(crate) unchanged: Vec<FirewallBypassRule>,
    pub(crate) rules_total: usize,
}

/// What committing a request did.
pub(crate) enum FirewallBypassCommit {
    Saved(FirewallBypassAdded),
    /// Nothing was saved: these rules, held without approval, would by now
    /// add or extend one.
    NeedsApproval(Vec<FirewallBypassRule>),
    /// Nothing was saved: the request's expiry passed before the save.
    Expired,
}

/// Saves `approved` and `unapproved` in one write under the store's lock,
/// each judged against the rule saved at that moment. An approved rule is
/// saved whatever changed since; an unapproved one only while it still
/// narrows the saved rule. When any unapproved rule would by now add or extend
/// one, the store is left as it was and those rules come back for approval,
/// so a concurrent `remove` or a newer expiry is never undone without it.
/// A request with a rule whose expiry has already passed saves nothing.
pub(crate) fn commit_firewall_bypass_rules<'a>(
    approved: &[FirewallBypassRule],
    unapproved: impl IntoIterator<Item = &'a FirewallBypassRule>,
    approval_note: &str,
) -> Result<FirewallBypassCommit, LpmError> {
    let (commit, rules_total) = update_local_firewall_bypass_rules(|saved, now| {
        let original = saved.clone();
        let mut outcome = FirewallBypassAdded::default();
        let mut needs_approval = Vec::new();
        let requested: Vec<(&FirewallBypassRule, bool)> = approved
            .iter()
            .map(|rule| (rule, true))
            .chain(unapproved.into_iter().map(|rule| (rule, false)))
            .collect();
        if requested.iter().any(|(rule, _)| rule.is_expired(now)) {
            return FirewallBypassCommit::Expired;
        }
        for (rule, is_approved) in requested {
            let live = saved
                .iter()
                .position(|saved| saved.is_same_rule_as(rule) && !saved.is_expired(now));
            let change = firewall_bypass_change(live.map(|index| &saved[index]), rule);
            let bucket = match change {
                FirewallBypassChange::Unchanged => {
                    if let Some(index) = live {
                        outcome.unchanged.push(saved[index].clone());
                    }
                    continue;
                }
                FirewallBypassChange::Narrowed => &mut outcome.narrowed,
                FirewallBypassChange::New if is_approved => &mut outcome.added,
                FirewallBypassChange::Extended if is_approved => &mut outcome.extended,
                FirewallBypassChange::New | FirewallBypassChange::Extended => {
                    needs_approval.push(rule.clone());
                    continue;
                }
            };
            let merged = merged_rule(live.map(|index| &saved[index]), rule.clone(), change);
            match live {
                Some(index) => saved[index] = merged.clone(),
                None => {
                    saved.retain(|existing| !existing.is_same_rule_as(rule));
                    saved.push(merged.clone());
                }
            }
            bucket.push(merged);
        }
        if needs_approval.is_empty() {
            FirewallBypassCommit::Saved(outcome)
        } else {
            *saved = original;
            FirewallBypassCommit::NeedsApproval(needs_approval)
        }
    })?;
    let FirewallBypassCommit::Saved(mut outcome) = commit else {
        return Ok(commit);
    };
    outcome.rules_total = rules_total;
    let allowed: Vec<FirewallBypassRule> = outcome
        .added
        .iter()
        .chain(&outcome.extended)
        .cloned()
        .collect();
    if !allowed.is_empty() {
        bypass_audit("firewall-bypass-added", true, &allowed, approval_note);
    }
    if !outcome.narrowed.is_empty() {
        bypass_audit(
            "firewall-bypass-narrowed",
            true,
            &outcome.narrowed,
            "shortened or annotated LPM Firewall bypass rules",
        );
    }
    Ok(FirewallBypassCommit::Saved(outcome))
}

/// Rules to approve and how to ask for them.
pub(crate) struct FirewallBypassApproval<'a> {
    pub(crate) rules: Vec<FirewallBypassRule>,
    /// The native prompt; it names every spec, the scope and the duration.
    pub(crate) prompt: &'a str,
    /// The command a person runs to approve the rules still waiting, for
    /// automation errors, when it can be written safely.
    pub(crate) command_hint: Option<&'a str>,
    pub(crate) json_output: bool,
}

/// Asks the person at the terminal to approve `approval.rules` with a fresh
/// native approval; saves nothing. Nothing else, such as a FloorEdit unlock,
/// stands in for the prompt, and `--json` never prompts.
pub(crate) fn approve_firewall_bypass_rules(
    approval: &FirewallBypassApproval<'_>,
) -> Result<(), LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(reason) = local_firewall_bypass_inactive_reason(&effective) {
        bypass_audit("firewall-bypass-added", false, &approval.rules, &reason);
        return Err(LpmError::SecurityFloor(reason));
    }
    // `--json` is checked on its own so it never prompts, even where tests
    // stand in for the person at a terminal.
    if approval.json_output || is_automation(approval.json_output) {
        bypass_audit(
            "firewall-bypass-added",
            false,
            &approval.rules,
            "refused without an interactive approval terminal",
        );
        return Err(approval_required_error(
            "Allowing packages past LPM Firewall needs your approval at an interactive terminal.",
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
            approval
                .rules
                .iter()
                .find_map(|rule| rule.project_root.clone()),
            approval.command_hint.map(str::to_string),
        ));
    }
    if !confirm_by_typing(approval.prompt)? || !request_native_approval(approval.prompt)? {
        bypass_audit(
            "firewall-bypass-added",
            false,
            &approval.rules,
            "the person at the terminal declined",
        );
        return Err(approval_required_error(
            "The LPM Firewall bypass was not approved, so nothing was saved.",
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
            approval
                .rules
                .iter()
                .find_map(|rule| rule.project_root.clone()),
            approval.command_hint.map(str::to_string),
        ));
    }
    Ok(())
}

/// For a request whose `--ttl` ran out while it waited for approval: it
/// needs a fresh approval, so the error names the command that asks again.
pub(crate) fn bypass_expired_before_save_error(
    command_hint: Option<String>,
    project_root: Option<String>,
) -> LpmError {
    approval_required_error(
        "The `--ttl` ran out before the LPM Firewall bypass rules were saved, so nothing was saved.",
        vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
        project_root,
        command_hint,
    )
}

/// For a request whose rules other commands kept changing while it waited
/// for approval; running it again judges them afresh.
pub(crate) fn rules_kept_changing_error(
    command_hint: Option<String>,
    project_root: Option<String>,
) -> LpmError {
    approval_required_error(
        "The LPM Firewall bypass rules kept changing while this command ran, so nothing was saved.",
        vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
        project_root,
        command_hint,
    )
}

/// [`approve_firewall_bypass_rules`] and [`commit_firewall_bypass_rules`] as
/// `lpm firewall bypass add` composes them, without its verdict preview:
/// saves `approval.rules`, asking for approval when any adds or extends a rule.
#[cfg(test)]
pub(crate) fn add_firewall_bypass_rules(
    approval: FirewallBypassApproval<'_>,
) -> Result<FirewallBypassAdded, LpmError> {
    let effective = load_effective_authorized_posture()?;
    if let Some(reason) = local_firewall_bypass_inactive_reason(&effective) {
        bypass_audit("firewall-bypass-added", false, &approval.rules, &reason);
        return Err(LpmError::SecurityFloor(reason));
    }
    let mut approved: Vec<FirewallBypassRule> = Vec::new();
    let mut unapproved = approval.rules.clone();
    for _ in 0..3 {
        match commit_firewall_bypass_rules(&approved, &unapproved, approval.prompt)? {
            FirewallBypassCommit::Saved(outcome) => return Ok(outcome),
            FirewallBypassCommit::Expired => {
                return Err(bypass_expired_before_save_error(
                    approval.command_hint.map(str::to_string),
                    project_root_of(&approval.rules),
                ));
            }
            FirewallBypassCommit::NeedsApproval(pending) => {
                approve_firewall_bypass_rules(&FirewallBypassApproval {
                    rules: pending.clone(),
                    ..approval
                })?;
                unapproved
                    .retain(|rule| !pending.iter().any(|waiting| waiting.is_same_rule_as(rule)));
                approved.extend(pending);
            }
        }
    }
    Err(rules_kept_changing_error(
        approval.command_hint.map(str::to_string),
        project_root_of(&approval.rules),
    ))
}

#[cfg(test)]
fn project_root_of(rules: &[FirewallBypassRule]) -> Option<String> {
    rules.iter().find_map(|rule| rule.project_root.clone())
}

/// Records an `add` refused before any prompt, such as under a managed policy
/// or for a malware verdict without `--allow-malware`.
pub(crate) fn record_firewall_bypass_refusal(specs: Vec<String>, reason: &str) {
    record_audit_event(
        AuditRecord::new(
            "firewall-bypass-added",
            false,
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
        )
        .packages(specs)
        .source(ApprovalSource::SecurityCommand)
        .detail(reason),
    );
}

/// Linux's polkit dialog can't show LPM's text, so the person confirms the
/// change in the terminal, where it is printed, before polkit asks for the
/// password.
#[cfg(target_os = "linux")]
fn confirm_by_typing(prompt: &str) -> Result<bool, LpmError> {
    if test_native_auth_override().is_some() {
        return Ok(true);
    }
    crate::output::warn(&format!("{prompt}."));
    eprint!("  Type `allow` and press Enter to continue: ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "allow")
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Linux asks in the terminal first and can fail reading stdin"
)]
fn confirm_by_typing(_prompt: &str) -> Result<bool, LpmError> {
    Ok(true)
}

/// Removes the local rules `selected` picks. Removing only narrows what LPM
/// Firewall lets through, so it asks for no approval.
/// Returns the removed rules and how many the store keeps.
pub(crate) fn remove_firewall_bypass_rules(
    selected: impl Fn(&FirewallBypassRule) -> bool,
    event: &str,
) -> Result<(Vec<FirewallBypassRule>, usize), LpmError> {
    let (removed, rules_total) = update_local_firewall_bypass_rules(|rules, _| {
        let mut removed = Vec::new();
        rules.retain(|rule| {
            if selected(rule) {
                removed.push(rule.clone());
                false
            } else {
                true
            }
        });
        removed
    })?;
    if !removed.is_empty() {
        bypass_audit(
            event,
            true,
            &removed,
            &format!("removed {} LPM Firewall bypass rules", removed.len()),
        );
    }
    Ok((removed, rules_total))
}
