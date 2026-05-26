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
    },
}

pub async fn run(cmd: &SecurityCmd, json_output: bool) -> Result<(), LpmError> {
    match cmd {
        SecurityCmd::Unlock {
            scope,
            project,
            ttl,
        } => {
            let ttl_secs = crate::release_age_config::parse_duration(ttl)?;
            let project_dir = match project {
                Some(path) => PathBuf::from(path),
                None => std::env::current_dir().map_err(LpmError::Io)?,
            };
            let grant =
                security_approval::unlock_scope_command(*scope, &project_dir, ttl_secs, json_output, None)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "scope": scope.as_str(),
                        "ttl_secs": ttl_secs,
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
    }
}
