use crate::security_approval::{self, ApprovalScope};
use clap::Subcommand;
use lpm_common::LpmError;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum SecurityCmd {
    /// Temporarily approve one guarded weakening for the current project.
    Unlock {
        /// Guarded scope to unlock.
        scope: ApprovalScope,

        /// Project root the unlock applies to. Defaults to the current directory.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,

        /// Time to keep the unlock active (`10m`, `5m`, `30m`).
        #[arg(long, default_value = "10m")]
        ttl: String,

        /// Restrict the unlock to one or more package names.
        #[arg(long = "package", value_name = "PKG")]
        packages: Vec<String>,
    },

    /// Show the effective security floor, unlock state, and policy source.
    Status {
        /// Project root whose active unlocks should be shown. Defaults to the current directory.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,
    },
}

pub async fn run(cmd: &SecurityCmd, json_output: bool) -> Result<(), LpmError> {
    match cmd {
        SecurityCmd::Unlock {
            scope,
            project,
            ttl,
            packages,
        } => {
            let ttl_secs = crate::release_age_config::parse_duration(ttl)?;
            let project_dir = match project {
                Some(path) => PathBuf::from(path),
                None => std::env::current_dir().map_err(LpmError::Io)?,
            };
            let grant = security_approval::unlock_scope_command(
                *scope,
                &project_dir,
                ttl_secs,
                json_output,
                None,
                packages,
            )?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "scope": scope.as_str(),
                        "ttl_secs": ttl_secs,
                        "packages": packages,
                        "project_root": grant.project_root,
                        "issued_at": grant.issued_at,
                        "expires_at": grant.expires_at,
                    }))
                    .unwrap()
                );
            } else {
                crate::output::success(&format!(
                    "Temporary unlock for {} is active for {} minute{}.",
                    scope.as_str(),
                    ttl_secs / 60,
                    if ttl_secs / 60 == 1 { "" } else { "s" }
                ));
            }
            Ok(())
        }
        SecurityCmd::Status { project } => {
            let project_dir = match project {
                Some(path) => PathBuf::from(path),
                None => std::env::current_dir().map_err(LpmError::Io)?,
            };
            let status = security_approval::load_security_status(Some(&project_dir))?;

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

            crate::output::header("Security Floor");
            crate::output::field(
                "project",
                status.project_root.as_deref().unwrap_or("(none)"),
            );
            crate::output::field(
                "script-policy",
                &format!(
                    "{} ({})",
                    status.effective_floor.script_policy,
                    source_name(status.floor_sources.script_policy),
                ),
            );
            crate::output::field(
                "minimum-release-age",
                &format!(
                    "{} ({})",
                    format_release_age(status.effective_floor.minimum_release_age_secs),
                    source_name(status.floor_sources.minimum_release_age_secs),
                ),
            );
            crate::output::field(
                "sandbox.mode",
                &format!(
                    "{} ({})",
                    status.effective_floor.sandbox_mode,
                    source_name(status.floor_sources.sandbox_mode),
                ),
            );
            crate::output::field(
                "sandbox.allow-degraded",
                &format!(
                    "{} ({})",
                    status.effective_floor.sandbox_allow_degraded,
                    source_name(status.floor_sources.sandbox_allow_degraded),
                ),
            );
            crate::output::field(
                "sigstore.verify",
                &format!(
                    "{} ({})",
                    status.effective_floor.sigstore_verify,
                    source_name(status.floor_sources.sigstore_verify),
                ),
            );

            crate::output::header("Policy Sources");
            crate::output::field(
                "approved-posture",
                &format!(
                    "{} ({})",
                    status.approved_posture_path,
                    source_name(status.approved_posture_source),
                ),
            );
            match status.managed_policy.as_ref() {
                Some(policy) => {
                    crate::output::field("managed-policy", &policy.path);
                    if let Some(name) = policy.name.as_deref() {
                        crate::output::field("policy-name", name);
                    }
                    if let Some(source) = policy.source.as_deref() {
                        crate::output::field("policy-source", source);
                    }
                    if !policy.enforced_controls.is_empty() {
                        crate::output::field(
                            "enforced-controls",
                            &policy.enforced_controls.join(", "),
                        );
                    }
                }
                None => crate::output::field("managed-policy", "inactive"),
            }

            crate::output::header("Active Unlocks");
            if status.active_unlocks.is_empty() {
                crate::output::field("project", "none");
            } else {
                for grant in &status.active_unlocks {
                    crate::output::field(
                        &grant.id,
                        &format!(
                            "{} until {}",
                            grant
                                .scopes
                                .iter()
                                .map(|scope| scope.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            grant.expires_at.to_rfc3339(),
                        ),
                    );
                }
            }
            Ok(())
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
