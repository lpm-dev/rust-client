use crate::install_ui;
use crate::security_approval::{self, ApprovalScope, UnlockTargetKind};
use clap::Subcommand;
use lpm_common::LpmError;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum SecurityScopeSelector {
    All,
    Default,
    CooldownBypass,
    CooldownWindow,
    ProvenanceIgnoreDrift,
    ProvenanceUnverified,
    ScriptsTriage,
    ScriptsAllow,
    TrustBulkApprove,
    TrustScopeWiden,
    SandboxDefault,
    SandboxNone,
    SandboxAllowDegraded,
    CapabilityWiden,
    TyposquatDisable,
    FirewallDisable,
    SourceAnalysisDisable,
    FloorEdit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum ProtectFirewallMode {
    Monitor,
    Enforce,
}

impl SecurityScopeSelector {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Default => "default",
            Self::CooldownBypass => ApprovalScope::CooldownBypass.as_str(),
            Self::CooldownWindow => ApprovalScope::CooldownWindow.as_str(),
            Self::ProvenanceIgnoreDrift => ApprovalScope::ProvenanceIgnoreDrift.as_str(),
            Self::ProvenanceUnverified => ApprovalScope::ProvenanceUnverified.as_str(),
            Self::ScriptsTriage => ApprovalScope::ScriptsTriage.as_str(),
            Self::ScriptsAllow => ApprovalScope::ScriptsAllow.as_str(),
            Self::TrustBulkApprove => ApprovalScope::TrustBulkApprove.as_str(),
            Self::TrustScopeWiden => ApprovalScope::TrustScopeWiden.as_str(),
            Self::SandboxDefault => ApprovalScope::SandboxDefault.as_str(),
            Self::SandboxNone => ApprovalScope::SandboxNone.as_str(),
            Self::SandboxAllowDegraded => ApprovalScope::SandboxAllowDegraded.as_str(),
            Self::CapabilityWiden => ApprovalScope::CapabilityWiden.as_str(),
            Self::TyposquatDisable => ApprovalScope::TyposquatDisable.as_str(),
            Self::FirewallDisable => ApprovalScope::FirewallDisable.as_str(),
            Self::SourceAnalysisDisable => ApprovalScope::SourceAnalysisDisable.as_str(),
            Self::FloorEdit => ApprovalScope::FloorEdit.as_str(),
        }
    }

    fn is_bundle(self) -> bool {
        matches!(self, Self::All | Self::Default)
    }

    fn resolve_scopes(self) -> Vec<ApprovalScope> {
        match self {
            Self::All => ApprovalScope::all_scopes().to_vec(),
            Self::Default => ApprovalScope::default_unlock_scopes().to_vec(),
            Self::CooldownBypass => vec![ApprovalScope::CooldownBypass],
            Self::CooldownWindow => vec![ApprovalScope::CooldownWindow],
            Self::ProvenanceIgnoreDrift => vec![ApprovalScope::ProvenanceIgnoreDrift],
            Self::ProvenanceUnverified => vec![ApprovalScope::ProvenanceUnverified],
            Self::ScriptsTriage => vec![ApprovalScope::ScriptsTriage],
            Self::ScriptsAllow => vec![ApprovalScope::ScriptsAllow],
            Self::TrustBulkApprove => vec![ApprovalScope::TrustBulkApprove],
            Self::TrustScopeWiden => vec![ApprovalScope::TrustScopeWiden],
            Self::SandboxDefault => vec![ApprovalScope::SandboxDefault],
            Self::SandboxNone => vec![ApprovalScope::SandboxNone],
            Self::SandboxAllowDegraded => vec![ApprovalScope::SandboxAllowDegraded],
            Self::CapabilityWiden => vec![ApprovalScope::CapabilityWiden],
            Self::TyposquatDisable => vec![ApprovalScope::TyposquatDisable],
            Self::FirewallDisable => vec![ApprovalScope::FirewallDisable],
            Self::SourceAnalysisDisable => vec![ApprovalScope::SourceAnalysisDisable],
            Self::FloorEdit => vec![ApprovalScope::FloorEdit],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSecurityTarget {
    kind: UnlockTargetKind,
    project_dir: Option<PathBuf>,
}

fn ensure_target_flags_are_mutually_exclusive(
    project: Option<&str>,
    global: bool,
) -> Result<(), LpmError> {
    if global && project.is_some() {
        return Err(LpmError::Registry(
            "use either `--global` or `--project`, not both".into(),
        ));
    }
    Ok(())
}

fn resolve_unlock_target(
    project: Option<&str>,
    global: bool,
) -> Result<ResolvedSecurityTarget, LpmError> {
    ensure_target_flags_are_mutually_exclusive(project, global)?;
    if let Some(path) = project {
        return Ok(ResolvedSecurityTarget {
            kind: UnlockTargetKind::Project,
            project_dir: Some(PathBuf::from(path)),
        });
    }
    Ok(ResolvedSecurityTarget {
        kind: UnlockTargetKind::Global,
        project_dir: None,
    })
}

fn resolve_status_target(
    project: Option<&str>,
    global: bool,
    cwd: PathBuf,
) -> Result<ResolvedSecurityTarget, LpmError> {
    ensure_target_flags_are_mutually_exclusive(project, global)?;
    if global {
        return Ok(ResolvedSecurityTarget {
            kind: UnlockTargetKind::Global,
            project_dir: None,
        });
    }
    Ok(ResolvedSecurityTarget {
        kind: UnlockTargetKind::Project,
        project_dir: Some(project.map_or(cwd, PathBuf::from)),
    })
}

fn ensure_supported_package_filters(
    selector: SecurityScopeSelector,
    packages: &[String],
) -> Result<(), LpmError> {
    if packages.iter().any(|pkg| pkg.trim().is_empty()) {
        return Err(LpmError::Registry(
            "`--package` values must not be empty".into(),
        ));
    }
    if selector.is_bundle() && !packages.is_empty() {
        return Err(LpmError::Registry(
            "`--package` can only be used with concrete scopes; `all` and `default` must be unlocked or locked without package filters".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
pub enum SecurityCmd {
    /// Temporarily approve one guarded weakening. Use --project for project operations.
    Unlock {
        /// Guarded scope to unlock, or `all` / `default`.
        scope: SecurityScopeSelector,

        /// Project root the unlock applies to.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,

        /// Create an unlock for global operations (including machine floor edits).
        #[arg(long)]
        global: bool,

        /// Time to keep the unlock active (`10m`, `1h`, `30d`, `365d`).
        #[arg(long, default_value = "10m")]
        ttl: String,

        /// Restrict the unlock to one or more package names.
        #[arg(long = "package", value_name = "PKG")]
        packages: Vec<String>,
    },

    /// Revoke one active temporary unlock. Defaults to the global target.
    Lock {
        /// Guarded scope to revoke, or `all` / `default`.
        scope: SecurityScopeSelector,

        /// Project root whose unlock applies to revoke.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,

        /// Revoke a machine-global unlock.
        #[arg(long)]
        global: bool,

        /// Restrict revocation to unlocks for exactly these package filters.
        #[arg(long = "package", value_name = "PKG")]
        packages: Vec<String>,
    },

    /// Show the effective security floor, unlock state, and policy source.
    Status {
        /// Project root whose active unlocks should be shown. Defaults to the nearest
        /// directory with a package.json.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,

        /// Show global unlock state instead of project unlocks.
        #[arg(long)]
        global: bool,
    },

    /// Install, remove, or inspect OS-managed local protection.
    Protect {
        #[command(subcommand)]
        action: ProtectCmd,
    },

    /// Quarantine signed local security state that can no longer be verified.
    Repair,
}

#[derive(Debug, Subcommand)]
pub enum ProtectCmd {
    /// Show whether OS-managed local protection is active.
    Status,

    /// Enable OS-managed protection against user-home security state bypasses.
    Enable {
        /// Managed npm firewall mode to enforce.
        #[arg(long, value_enum, default_value_t = ProtectFirewallMode::Enforce)]
        firewall: ProtectFirewallMode,
    },

    /// Remove the managed npm firewall protection entry.
    Disable,
}

/// `status_dir` is the package `lpm security status` reports without
/// `--project` or `--global`.
pub async fn run(
    cmd: &SecurityCmd,
    status_dir: Option<PathBuf>,
    json_output: bool,
) -> Result<(), LpmError> {
    match cmd {
        SecurityCmd::Unlock {
            scope,
            project,
            global,
            ttl,
            packages,
        } => {
            ensure_supported_package_filters(*scope, packages)?;
            let ttl_secs = crate::release_age_config::parse_duration(ttl)?;
            let target = resolve_unlock_target(project.as_deref(), *global)?;
            let grant = if target.kind == UnlockTargetKind::Global {
                security_approval::unlock_global_scopes_command(
                    scope.as_str(),
                    &scope.resolve_scopes(),
                    ttl_secs,
                    json_output,
                    packages,
                )?
            } else {
                security_approval::unlock_scopes_command(
                    scope.as_str(),
                    &scope.resolve_scopes(),
                    target.project_dir.as_deref().expect("project target path"),
                    ttl_secs,
                    json_output,
                    None,
                    packages,
                )?
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "scope": scope.as_str(),
                        "selector": scope.as_str(),
                        "scopes": grant.scopes.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
                        "target": grant.target.as_str(),
                        "ttl_secs": ttl_secs,
                        "ttl": security_approval::format_unlock_duration(ttl_secs),
                        "packages": grant.packages,
                        "project_root": grant.project_root,
                        "issued_at": grant.issued_at,
                        "expires_at": grant.expires_at,
                    }))
                    .unwrap()
                );
            } else {
                install_ui::done_untrusted(&format!(
                    "Temporary {} unlock for {} is active for {}.",
                    grant.target.as_str(),
                    scope.as_str(),
                    security_approval::format_unlock_duration(ttl_secs),
                ));
            }
            Ok(())
        }
        SecurityCmd::Lock {
            scope,
            project,
            global,
            packages,
        } => {
            ensure_supported_package_filters(*scope, packages)?;
            let target = resolve_unlock_target(project.as_deref(), *global)?;
            let revocations = if target.kind == UnlockTargetKind::Global {
                security_approval::lock_global_scopes_command(
                    scope.as_str(),
                    &scope.resolve_scopes(),
                    packages,
                )?
            } else {
                security_approval::lock_project_scopes_command(
                    scope.as_str(),
                    &scope.resolve_scopes(),
                    target.project_dir.as_deref().expect("project target path"),
                    packages,
                )?
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "scope": scope.as_str(),
                        "selector": scope.as_str(),
                        "scopes": scope.resolve_scopes().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
                        "target": target.kind.as_str(),
                        "packages": packages,
                        "revocations": revocations,
                    }))
                    .unwrap()
                );
                return Ok(());
            }

            if revocations.is_empty() {
                install_ui::warn_untrusted(&format!(
                    "No active {} unlocks matched {}.",
                    target.kind.as_str(),
                    scope.as_str(),
                ));
            } else {
                install_ui::done_untrusted(&format!(
                    "Revoked {} from {} {} unlock{}.",
                    scope.as_str(),
                    revocations.len(),
                    target.kind.as_str(),
                    if revocations.len() == 1 { "" } else { "s" }
                ));
            }
            Ok(())
        }
        SecurityCmd::Status { project, global } => {
            let package_dir = match status_dir {
                Some(directory) => directory,
                None => std::env::current_dir().map_err(LpmError::Io)?,
            };
            let target = resolve_status_target(project.as_deref(), *global, package_dir)?;
            let status = if target.kind == UnlockTargetKind::Global {
                security_approval::load_security_status(None, true)?
            } else {
                security_approval::load_security_status(target.project_dir.as_deref(), false)?
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "status": status,
                    }))
                    .unwrap()
                );
                return Ok(());
            }

            print_security_status(&status);
            println!();
            install_ui::done("Security floor loaded");
            Ok(())
        }
        SecurityCmd::Protect { action } => match action {
            ProtectCmd::Status => {
                let status = security_approval::load_managed_protection_status()?;
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "success": true,
                            "protect": status,
                        }))
                        .unwrap()
                    );
                } else {
                    print_protect_status(&status);
                }
                Ok(())
            }
            ProtectCmd::Enable { firewall } => {
                let action = match firewall {
                    ProtectFirewallMode::Monitor => {
                        security_approval::ManagedProtectionAction::EnableMonitor
                    }
                    ProtectFirewallMode::Enforce => {
                        security_approval::ManagedProtectionAction::EnableEnforce
                    }
                };
                let report = security_approval::apply_managed_protection_with_privilege(action)?;
                if json_output {
                    print_protect_report_json(&report);
                } else {
                    print_protect_status(&report.status);
                    print_protect_change("Protection", report.change);
                    print_protect_set_aside(&report.set_aside);
                }
                Ok(())
            }
            ProtectCmd::Disable => {
                let report = security_approval::apply_managed_protection_with_privilege(
                    security_approval::ManagedProtectionAction::Disable,
                )?;
                if json_output {
                    print_protect_report_json(&report);
                } else {
                    print_protect_status(&report.status);
                    print_protect_change("Protection", report.change);
                    print_protect_set_aside(&report.set_aside);
                }
                Ok(())
            }
        },
        SecurityCmd::Repair => {
            let report = security_approval::repair_security_state()?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "repair": report,
                    }))
                    .unwrap()
                );
                return Ok(());
            }

            println!("security dir  {}", install_ui::cyan(&report.security_dir));
            println!();
            println!("quarantined files");
            if report.quarantined.is_empty() {
                println!("  none");
                println!();
                install_ui::done("Security state already clean");
            } else {
                for item in &report.quarantined {
                    println!(
                        "  {} -> {} ({})",
                        install_ui::cyan(&item.original_path),
                        install_ui::cyan(&item.quarantine_path),
                        install_ui::dim(&item.reason)
                    );
                }
                println!();
                install_ui::done("Security state repaired");
            }
            Ok(())
        }
    }
}

fn print_protect_report_json(report: &security_approval::ManagedProtectionReport) {
    let mut output = serde_json::json!({
        "success": true,
        "change": report.change.as_str(),
        "protect": report.status,
    });
    if !report.set_aside.is_empty() {
        output["set_aside"] = serde_json::json!(report.set_aside);
    }
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Says where a policy LPM never applied was moved: an administrator who
/// made it with their own account as owner may want its settings back.
fn print_protect_set_aside(set_aside: &[String]) {
    for path in set_aside {
        install_ui::warn_untrusted(&format!(
            "Moved {path} aside: it didn't pass the managed policy's checks, so LPM never \
             applied it. Copy any settings you want to keep into the policy."
        ));
    }
}

fn print_protect_change(label: &str, change: security_approval::ManagedProtectionChange) {
    match change {
        security_approval::ManagedProtectionChange::Enabled => {
            install_ui::done_untrusted(&format!("{label} enabled."));
        }
        security_approval::ManagedProtectionChange::Disabled => {
            install_ui::done_untrusted(&format!("{label} disabled."));
        }
        security_approval::ManagedProtectionChange::Unchanged => {
            install_ui::warn_untrusted(&format!("{label} unchanged."));
        }
    }
}

fn print_protect_status(status: &security_approval::ManagedProtectionStatus) {
    println!("{}", install_ui::section("managed protection"));
    let mut fields = install_ui::Table::new();
    let active = if status.active {
        install_ui::status_ok("active")
    } else {
        install_ui::dim("inactive")
    };
    fields.row([install_ui::dim("status"), active]);
    fields.row([install_ui::dim("policy"), install_ui::cyan(&status.path)]);
    if let Some(mode) = status.firewall_mode.as_deref() {
        fields.row([install_ui::dim("firewall"), policy_value(mode)]);
    }
    if let Some(policy) = status.managed_policy.as_ref() {
        push_managed_policy_details(&mut fields, policy, "name", "source", "controls");
    }
    fields.print_stdout();
}

fn push_managed_policy_details(
    fields: &mut install_ui::Table,
    policy: &security_approval::ManagedPolicyStatus,
    name_label: &'static str,
    source_label: &'static str,
    controls_label: &'static str,
) {
    if let Some(name) = policy.name.as_deref() {
        fields.row([install_ui::dim(name_label), install_ui::yellow(name)]);
    }
    if let Some(source) = policy.source.as_deref() {
        fields.row([install_ui::dim(source_label), install_ui::dim(source)]);
    }
    if !policy.enforced_controls.is_empty() {
        fields.row([
            install_ui::dim(controls_label),
            install_ui::dim(&policy.enforced_controls.join(", ")),
        ]);
    }
}

/// Prints `lpm security status`: every section's rows line up, and a floor
/// value that comes from a built-in default is dimmed so the values an
/// approved posture or a managed policy sets stand out.
fn print_security_status(status: &security_approval::SecurityStatus) {
    let mut target = install_ui::Table::new().indent(0);
    target.row([
        install_ui::dim("target"),
        policy_value(status.target.as_str()),
    ]);
    target.row([
        install_ui::dim("root"),
        status
            .project_root
            .as_deref()
            .map_or_else(|| install_ui::dim("(none)"), install_ui::cyan),
    ]);
    target.print_stdout();

    println!();
    println!("{}", install_ui::section("effective floor"));
    let floor = &status.effective_floor;
    let sources = &status.floor_sources;
    let mut rows = install_ui::Table::new();
    for (label, value, source) in [
        (
            "script policy",
            floor.script_policy.clone(),
            sources.script_policy,
        ),
        (
            "minimum release age",
            crate::release_age_config::describe_minimum_release_age(floor.minimum_release_age_secs),
            sources.minimum_release_age_secs,
        ),
        (
            "release age policy",
            floor.release_age_policy.clone(),
            sources.release_age_policy,
        ),
        (
            "sandbox mode",
            floor.sandbox_mode.clone(),
            sources.sandbox_mode,
        ),
        (
            "sandbox allow degraded",
            bool_policy_value(floor.sandbox_allow_degraded).to_owned(),
            sources.sandbox_allow_degraded,
        ),
        (
            "sigstore verify",
            floor.sigstore_verify.clone(),
            sources.sigstore_verify,
        ),
        (
            "typosquat guard",
            floor.typosquat_guard.clone(),
            sources.typosquat_guard,
        ),
        (
            "npm firewall",
            floor.firewall_mode.clone(),
            sources.firewall_mode,
        ),
        (
            "install-time source analysis",
            bool_policy_value(floor.install_time_source_analysis).to_owned(),
            sources.install_time_source_analysis,
        ),
    ] {
        let value = if source == security_approval::PostureSourceKind::BuiltinDefault {
            install_ui::dim(&value)
        } else {
            policy_value(&value)
        };
        rows.row([
            install_ui::dim(label),
            value,
            install_ui::dim(source_name(source)),
        ]);
    }
    rows.print_stdout();

    println!();
    println!("{}", install_ui::section("policy sources"));
    let mut rows = install_ui::Table::new();
    rows.row([
        install_ui::dim("approved posture"),
        install_ui::cyan(&status.approved_posture_path),
        install_ui::dim(source_name(status.approved_posture_source)),
    ]);
    match status.managed_policy.as_ref() {
        Some(policy) => {
            rows.row([
                install_ui::dim("managed policy"),
                install_ui::cyan(&policy.path),
            ]);
            push_managed_policy_details(
                &mut rows,
                policy,
                "policy name",
                "policy source",
                "enforced controls",
            );
        }
        None => rows.row([
            install_ui::dim("managed policy"),
            install_ui::dim("inactive"),
        ]),
    }
    rows.print_stdout();

    println!();
    println!("{}", install_ui::section("runtime overrides"));
    let mut rows = install_ui::Table::new();
    if status.active_runtime_overrides.is_empty() {
        rows.row([install_ui::dim("none")]);
    }
    for override_row in &status.active_runtime_overrides {
        rows.row([
            install_ui::cyan(&override_row.control),
            policy_value(&override_row.value),
            install_ui::dim(&override_row.source),
        ]);
    }
    rows.print_stdout();

    println!();
    println!("{}", install_ui::section("active unlocks"));
    let mut rows = install_ui::Table::new();
    if status.active_unlocks.is_empty() {
        rows.row([install_ui::dim("none")]);
    }
    for grant in &status.active_unlocks {
        let scopes = grant
            .scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let mut limits = Vec::with_capacity(2);
        if !grant.packages.is_empty() {
            limits.push(format!("packages: {}", grant.packages.join(", ")));
        }
        if let Some(secs) = grant.limits.min_release_age_secs {
            limits.push(format!(
                "min-release-age >= {}",
                crate::release_age_config::describe_minimum_release_age(secs)
            ));
        }
        rows.row([
            install_ui::cyan(&grant.id),
            install_ui::cyan(&scopes),
            policy_value(grant.target.as_str()),
            install_ui::TerminalFragment::from(crate::install_ui::terminal_line!(
                "until {}",
                install_ui::status_ok(&grant.expires_at.to_rfc3339())
            )),
            install_ui::dim(&limits.join(" | ")),
        ]);
    }
    rows.print_stdout();
}

fn source_name(source: security_approval::PostureSourceKind) -> &'static str {
    match source {
        security_approval::PostureSourceKind::BuiltinDefault => "builtin-default",
        security_approval::PostureSourceKind::ApprovedStore => "approved-store",
        security_approval::PostureSourceKind::ManagedPolicy => "managed-policy",
    }
}

fn policy_value(value: &str) -> install_ui::TerminalFragment {
    install_ui::section(value)
}

fn bool_policy_value(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_target_defaults_to_global_without_flags() {
        let target = resolve_unlock_target(None, false).unwrap();
        assert_eq!(target.kind, UnlockTargetKind::Global);
        assert!(target.project_dir.is_none());
    }

    #[test]
    fn explicit_project_target_overrides_global_default() {
        let target = resolve_unlock_target(Some("./demo"), false).unwrap();
        assert_eq!(target.kind, UnlockTargetKind::Project);
        assert_eq!(target.project_dir, Some(PathBuf::from("./demo")));
    }

    #[test]
    fn status_target_stays_project_default() {
        let target = resolve_status_target(None, false, PathBuf::from("/tmp/demo")).unwrap();
        assert_eq!(target.kind, UnlockTargetKind::Project);
        assert_eq!(target.project_dir, Some(PathBuf::from("/tmp/demo")));
    }

    #[test]
    fn default_selector_resolves_only_runtime_weakeners() {
        let scopes = SecurityScopeSelector::Default.resolve_scopes();
        assert_eq!(scopes, ApprovalScope::default_unlock_scopes());
    }

    #[test]
    fn firewall_disable_selector_resolves_concrete_scope() {
        assert_eq!(
            SecurityScopeSelector::FirewallDisable.resolve_scopes(),
            vec![ApprovalScope::FirewallDisable]
        );
    }

    #[test]
    fn bundle_selectors_reject_package_filters() {
        let err =
            ensure_supported_package_filters(SecurityScopeSelector::All, &["esbuild".to_string()])
                .unwrap_err();
        assert!(err.to_string().contains("`--package`"));
    }
}
