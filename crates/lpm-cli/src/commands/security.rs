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

impl ProtectFirewallMode {
    fn as_npm_firewall_mode(self) -> crate::npm_firewall_config::NpmFirewallMode {
        match self {
            Self::Monitor => crate::npm_firewall_config::NpmFirewallMode::Monitor,
            Self::Enforce => crate::npm_firewall_config::NpmFirewallMode::Enforce,
        }
    }
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
    /// Temporarily approve one guarded weakening. Defaults to the global target.
    Unlock {
        /// Guarded scope to unlock, or `all` / `default`.
        scope: SecurityScopeSelector,

        /// Project root the unlock applies to.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,

        /// Create a machine-global unlock.
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
        /// Project root whose active unlocks should be shown. Defaults to the current directory.
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

pub async fn run(cmd: &SecurityCmd, json_output: bool) -> Result<(), LpmError> {
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
            let target = resolve_status_target(
                project.as_deref(),
                *global,
                std::env::current_dir().map_err(LpmError::Io)?,
            )?;
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

            print_status_field("target", policy_value(status.target.as_str()));
            let root_value = status
                .project_root
                .as_deref()
                .map_or_else(|| install_ui::dim("(none)"), install_ui::cyan);
            print_status_field("root", &root_value);
            println!();
            println!("{}", install_ui::section("effective floor"));
            print_effective_floor_field(
                "script policy",
                &status.effective_floor.script_policy,
                status.floor_sources.script_policy,
            );
            print_effective_floor_field(
                "minimum release age",
                &format_release_age(status.effective_floor.minimum_release_age_secs),
                status.floor_sources.minimum_release_age_secs,
            );
            print_effective_floor_field(
                "release age policy",
                &status.effective_floor.release_age_policy,
                status.floor_sources.release_age_policy,
            );
            print_effective_floor_field(
                "sandbox mode",
                &status.effective_floor.sandbox_mode,
                status.floor_sources.sandbox_mode,
            );
            print_effective_floor_field(
                "sandbox allow degraded",
                bool_policy_value(status.effective_floor.sandbox_allow_degraded),
                status.floor_sources.sandbox_allow_degraded,
            );
            print_effective_floor_field(
                "sigstore verify",
                &status.effective_floor.sigstore_verify,
                status.floor_sources.sigstore_verify,
            );
            print_effective_floor_field(
                "typosquat guard",
                &status.effective_floor.typosquat_guard,
                status.floor_sources.typosquat_guard,
            );
            print_effective_floor_field(
                "npm firewall",
                &status.effective_floor.firewall_mode,
                status.floor_sources.firewall_mode,
            );
            print_effective_floor_field(
                "install-time source analysis",
                bool_policy_value(status.effective_floor.install_time_source_analysis),
                status.floor_sources.install_time_source_analysis,
            );

            println!();
            println!("{}", install_ui::section("policy sources"));
            println!(
                "  {} {} {}",
                install_ui::dim(&format!("{:<24}", "approved posture")),
                install_ui::cyan(&status.approved_posture_path),
                source_suffix(status.approved_posture_source),
            );
            match status.managed_policy.as_ref() {
                Some(policy) => {
                    print_status_field("managed policy", install_ui::cyan(&policy.path));
                    if let Some(name) = policy.name.as_deref() {
                        print_status_field("policy name", install_ui::yellow(name));
                    }
                    if let Some(source) = policy.source.as_deref() {
                        print_status_field("policy source", install_ui::dim(source));
                    }
                    if !policy.enforced_controls.is_empty() {
                        print_status_field(
                            "enforced controls",
                            install_ui::dim(&policy.enforced_controls.join(", ")),
                        );
                    }
                }
                None => print_status_field("managed policy", install_ui::dim("inactive")),
            }

            println!();
            println!("{}", install_ui::section("runtime overrides"));
            if status.active_runtime_overrides.is_empty() {
                println!("  {}", install_ui::dim("none"));
            } else {
                for override_row in &status.active_runtime_overrides {
                    println!(
                        "  {} {} ({})",
                        install_ui::cyan(&format!("{:<24}", override_row.control)),
                        policy_value(&override_row.value),
                        install_ui::dim(&override_row.source),
                    );
                }
            }

            println!();
            println!("{}", install_ui::section("active unlocks"));
            if status.active_unlocks.is_empty() {
                println!("  {}", install_ui::dim("none"));
            } else {
                for grant in &status.active_unlocks {
                    let package_suffix = if grant.packages.is_empty() {
                        String::new()
                    } else {
                        format!(" | packages: {}", grant.packages.join(", "))
                    };
                    let limit_suffix = match grant.limits.min_release_age_secs {
                        Some(secs) => format!(" | min-release-age >= {}", format_release_age(secs)),
                        None => String::new(),
                    };
                    println!(
                        "  {}  {} [{}] until {}{}{}",
                        install_ui::cyan(&grant.id),
                        install_ui::cyan(
                            &grant
                                .scopes
                                .iter()
                                .map(|scope| scope.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        policy_value(grant.target.as_str()),
                        install_ui::status_ok(&grant.expires_at.to_rfc3339()),
                        install_ui::dim(&package_suffix),
                        install_ui::dim(&limit_suffix),
                    );
                }
            }
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
                let report = security_approval::install_managed_firewall_protection(
                    firewall.as_npm_firewall_mode(),
                )?;
                if json_output {
                    print_protect_report_json(&report);
                } else {
                    print_protect_status(&report.status);
                    print_protect_change("Protection", report.change);
                }
                Ok(())
            }
            ProtectCmd::Disable => {
                let report = security_approval::remove_managed_firewall_protection()?;
                if json_output {
                    print_protect_report_json(&report);
                } else {
                    print_protect_status(&report.status);
                    print_protect_change("Protection", report.change);
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
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "change": report.change.as_str(),
            "protect": report.status,
        }))
        .unwrap()
    );
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
    let active = if status.active {
        install_ui::status_ok("active")
    } else {
        install_ui::dim("inactive")
    };
    print_status_field("status", &active);
    print_status_field("policy", install_ui::cyan(&status.path));
    if let Some(mode) = status.firewall_mode.as_deref() {
        print_status_field("firewall", policy_value(mode));
    }
    if let Some(policy) = status.managed_policy.as_ref() {
        if let Some(name) = policy.name.as_deref() {
            print_status_field("name", install_ui::yellow(name));
        }
        if let Some(source) = policy.source.as_deref() {
            print_status_field("source", install_ui::dim(source));
        }
        if !policy.enforced_controls.is_empty() {
            print_status_field(
                "controls",
                install_ui::dim(&policy.enforced_controls.join(", ")),
            );
        }
    }
}

fn source_name(source: security_approval::PostureSourceKind) -> &'static str {
    match source {
        security_approval::PostureSourceKind::BuiltinDefault => "builtin-default",
        security_approval::PostureSourceKind::ApprovedStore => "approved-store",
        security_approval::PostureSourceKind::ManagedPolicy => "managed-policy",
    }
}

fn print_status_field<T: install_ui::TerminalValue>(label: &'static str, value: T) {
    println!(
        "{}",
        crate::install_ui::terminal_line!("{} {}", install_ui::dim(&format!("{label:<8}")), value)
    );
}

fn policy_value(value: &str) -> install_ui::TerminalFragment {
    install_ui::section(value)
}

fn source_suffix(source: security_approval::PostureSourceKind) -> install_ui::TerminalFragment {
    install_ui::dim(&format!("({})", source_name(source)))
}

fn sourced_policy_value(
    value: &str,
    source: security_approval::PostureSourceKind,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("{} {}", policy_value(value), source_suffix(source))
}

fn print_effective_floor_field(
    label: &str,
    value: &str,
    source: security_approval::PostureSourceKind,
) {
    const LABEL_WIDTH: usize = 28;
    println!(
        "  {} {}",
        install_ui::dim(&format!("{label:<width$}", width = LABEL_WIDTH)),
        sourced_policy_value(value, source),
    );
}

fn bool_policy_value(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_release_age(secs: u64) -> String {
    if secs == 0 {
        return "off".to_string();
    }
    if secs.is_multiple_of(86_400) {
        return format!("{}d", secs / 86_400);
    }
    if secs.is_multiple_of(3_600) {
        return format!("{}h", secs / 3_600);
    }
    format!("{secs}s")
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
