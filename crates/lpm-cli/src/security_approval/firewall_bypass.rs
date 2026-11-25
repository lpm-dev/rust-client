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

/// Every local rule, expired ones included, after verifying the store's
/// signature. A missing store holds no rules.
pub(crate) fn load_local_firewall_bypass_rules() -> Result<Vec<FirewallBypassRule>, LpmError> {
    let path = firewall_bypass_path()?;
    let Some(value) = read_signed_json::<serde_json::Value>(&path)? else {
        return Ok(Vec::new());
    };
    if value.get("kind").and_then(serde_json::Value::as_str) != Some(FIREWALL_BYPASS_KIND) {
        return Err(LpmError::SecurityApprovalStore(format!(
            "{} is not an LPM Firewall bypass rule file; run `lpm security repair`",
            path.display()
        )));
    }
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if schema_version > FIREWALL_BYPASS_SCHEMA_VERSION {
        return Err(LpmError::SecurityApprovalStore(format!(
            "{} was written by a newer LPM CLI (schema {schema_version}); update LPM CLI to apply its bypass rules",
            path.display()
        )));
    }
    let file: FirewallBypassFile = serde_json::from_value(value).map_err(|error| {
        LpmError::SecurityApprovalStore(format!(
            "{} has invalid bypass rules: {error}; run `lpm security repair`",
            path.display()
        ))
    })?;
    Ok(file.rules)
}

/// Runs `change` on the local rules under the store's lock and saves the
/// result, dropping rules that have expired. An empty store is removed so a
/// command with no rules reads nothing.
fn update_local_firewall_bypass_rules<T>(
    change: impl FnOnce(&mut Vec<FirewallBypassRule>) -> T,
) -> Result<T, LpmError> {
    std::fs::create_dir_all(security_dir()?)?;
    lpm_common::with_exclusive_lock(firewall_bypass_lock_path()?, || {
        let mut rules = load_local_firewall_bypass_rules()?;
        let result = change(&mut rules);
        let now = Timestamp::now();
        rules.retain(|rule| !rule.is_expired(now));
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
        Ok(result)
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

pub(crate) fn load_firewall_bypass_status(
    effective: &EffectiveAuthorizedPosture,
) -> FirewallBypassStatus {
    let inactive_reason = local_firewall_bypass_inactive_reason(effective);
    let now = Timestamp::now();
    let (rules, error) = match load_local_firewall_bypass_rules() {
        Ok(mut rules) => {
            rules.retain(|rule| !rule.is_expired(now));
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

/// Rules to add and how to ask for them.
pub(crate) struct FirewallBypassApproval<'a> {
    pub(crate) rules: Vec<FirewallBypassRule>,
    /// The native prompt; it names every spec, the scope and the duration.
    pub(crate) prompt: &'a str,
    /// The command a person runs to approve these rules, for automation
    /// errors.
    pub(crate) command_hint: &'a str,
    pub(crate) json_output: bool,
}

#[derive(Debug, Default)]
pub(crate) struct FirewallBypassAdded {
    pub(crate) added: Vec<FirewallBypassRule>,
    pub(crate) unchanged: Vec<FirewallBypassRule>,
}

/// Saves `approval.rules` after a fresh native approval. Rules already saved
/// and unexpired need none; nothing else, such as a FloorEdit unlock, stands in
/// for the prompt.
pub(crate) fn add_firewall_bypass_rules(
    approval: FirewallBypassApproval<'_>,
) -> Result<FirewallBypassAdded, LpmError> {
    let specs: Vec<String> = approval
        .rules
        .iter()
        .map(|rule| rule.spec.clone())
        .collect();
    let project_root = approval
        .rules
        .iter()
        .find_map(|rule| rule.project_root.clone());
    let audit = |allowed: bool, detail: &str| {
        let mut record = AuditRecord::new(
            "firewall-bypass-added",
            allowed,
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
        )
        .packages(specs.clone())
        .source(ApprovalSource::SecurityCommand)
        .detail(detail);
        if let Some(root) = &project_root {
            record = record.project_root(root.clone());
        }
        record_audit_event(record);
    };

    let effective = load_effective_authorized_posture()?;
    if let Some(reason) = local_firewall_bypass_inactive_reason(&effective) {
        audit(false, &reason);
        return Err(LpmError::SecurityFloor(reason));
    }

    let now = Timestamp::now();
    let existing = load_local_firewall_bypass_rules()?;
    let mut outcome = FirewallBypassAdded::default();
    for rule in approval.rules {
        let saved = existing
            .iter()
            .any(|saved| saved.id == rule.id && !saved.is_expired(now));
        if saved {
            outcome.unchanged.push(rule);
        } else {
            outcome.added.push(rule);
        }
    }
    if outcome.added.is_empty() {
        return Ok(outcome);
    }

    if is_automation(approval.json_output) {
        audit(false, "refused without an interactive approval terminal");
        return Err(approval_required_error(
            "Allowing packages past LPM Firewall needs your approval at an interactive terminal.",
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
            project_root.clone(),
            Some(approval.command_hint.to_string()),
        ));
    }
    if !confirm_by_typing(approval.prompt)? || !request_native_approval(approval.prompt)? {
        audit(false, "the person at the terminal declined");
        return Err(approval_required_error(
            "The LPM Firewall bypass was not approved.",
            vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()],
            project_root.clone(),
            Some(approval.command_hint.to_string()),
        ));
    }

    let added = outcome.added.clone();
    update_local_firewall_bypass_rules(|rules| {
        for rule in added {
            rules.retain(|saved| saved.id != rule.id);
            rules.push(rule);
        }
    })?;
    audit(true, approval.prompt);
    Ok(outcome)
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
pub(crate) fn remove_firewall_bypass_rules(
    selected: impl Fn(&FirewallBypassRule) -> bool,
    event: &str,
) -> Result<Vec<FirewallBypassRule>, LpmError> {
    let removed = update_local_firewall_bypass_rules(|rules| {
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
        record_audit_event(
            AuditRecord::new(event, true, vec![FIREWALL_BYPASS_AUDIT_SCOPE.to_string()])
                .packages(removed.iter().map(|rule| rule.spec.clone()).collect())
                .source(ApprovalSource::SecurityCommand)
                .detail(format!(
                    "removed {} LPM Firewall bypass rules",
                    removed.len()
                )),
        );
    }
    Ok(removed)
}
