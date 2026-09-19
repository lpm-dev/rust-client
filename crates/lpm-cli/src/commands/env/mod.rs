//! `lpm env` command dispatcher and domain modules.

mod arguments;
pub(crate) mod auth;
mod ci;
mod github;
mod inventory;
mod local;
mod oidc;
mod pairing;
mod platform;
mod pull;
mod push;
mod remote;
mod response;
mod rotation;
mod schema;
mod sync_payload;

mod prelude {
    pub(super) use crate::{install_ui, output};
    pub(super) use futures::StreamExt;
    pub(super) use lpm_common::LpmError;
    pub(super) use lpm_common::color::Painted;
    pub(super) use std::collections::HashMap;
}

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// Handle `lpm env` subcommands.
///
/// Local-file management (`set`, `get`, `list`, `delete`, `import`,
/// `export`, `print`, `copy`, `check`, `init`), cloud sync (`pull`,
/// `push`, `share`, `pair`, `diff`, `validate`), platform integrations
/// (`push --to <platform>`, `pull --from <platform>`, `connect`,
/// `status`), and OIDC policies (`oidc allow`, `oidc list`, `oidc pull`).
///
/// Dispatch the arguments captured by the CLI parser.
pub async fn run(
    client: &RegistryClient,
    project_dir: &std::path::Path,
    extra: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let args: Vec<&str> = extra.iter().map(String::as_str).collect();
    if args.is_empty() {
        return local::env_list(None, false, project_dir, json_output);
    }
    if let Some(action) = arguments::parse(&args)? {
        use arguments::LocalAction;
        return match action {
            LocalAction::Set {
                environment,
                assignments,
            } => local::env_set(
                environment.env.as_deref(),
                &assignments,
                project_dir,
                json_output,
            ),
            LocalAction::Get {
                environment,
                key,
                reveal,
            } => local::env_get(
                environment.env.as_deref(),
                &key,
                reveal,
                project_dir,
                json_output,
            ),
            LocalAction::List {
                environment,
                reveal,
            } => local::env_list(environment.env.as_deref(), reveal, project_dir, json_output),
            LocalAction::Delete { environment, keys } => {
                local::env_delete(environment.env.as_deref(), &keys, project_dir, json_output)
            }
            LocalAction::Import {
                environment,
                file,
                overwrite,
            } => local::env_import(
                environment.env.as_deref(),
                &file,
                overwrite,
                project_dir,
                json_output,
            ),
            LocalAction::Export {
                environment,
                file,
                ci,
            } => local::env_export(
                environment.env.as_deref(),
                &file,
                ci,
                project_dir,
                json_output,
            ),
            LocalAction::Print {
                environment,
                format,
                schema_only,
                ci,
            } => schema::vars_print(
                environment.env.as_deref(),
                format,
                schema_only,
                ci,
                project_dir,
                json_output,
            ),
            LocalAction::Example { environment } => {
                schema::vars_example(project_dir, environment.env.as_deref(), json_output)
            }
            LocalAction::Check => schema::vars_check(project_dir, json_output),
            LocalAction::Validate { strict } => {
                schema::vars_validate(project_dir, strict, json_output)
            }
            LocalAction::Init { force } => inventory::vars_init(project_dir, force, json_output),
            LocalAction::Ls => inventory::vars_ls(project_dir, json_output),
            LocalAction::Log => remote::env_log(client, project_dir, json_output).await,
            LocalAction::Unpair => pairing::env_unpair(client, json_output).await,
            LocalAction::Diff { environments } => {
                let environments: Vec<&str> = environments.iter().map(String::as_str).collect();
                remote::vars_diff(client, &environments, project_dir, json_output).await
            }
            LocalAction::Copy {
                source,
                target,
                overwrite,
            } => inventory::vars_copy(project_dir, &source, &target, overwrite, json_output),
        };
    }

    match args[0] {
        "push" => push::vars_push(client, &args, project_dir, json_output).await,
        "pull" => pull::vars_pull(client, &args, project_dir, json_output).await,
        "share" => remote::env_share(client, &args, project_dir, json_output).await,
        "rotate-key" => {
            rotation::env_rotate_key(client, &args[1..], project_dir, json_output).await
        }
        "rotate-sharing-key" => rotation::env_rotate_sharing_key(client, &args, json_output).await,
        "list-remote" | "ls-remote" => {
            let org_flag = remote::parse_list_remote_org_slug(&args)?;
            remote::vars_list_remote(client, org_flag, json_output).await
        }
        "connect" => platform::vars_connect(client, &args[1..], project_dir, json_output).await,
        "oidc" => oidc::vars_oidc(client, &args[1..], project_dir, json_output).await,
        "status" => {
            platform::vars_platform_status(client, &args[1..], project_dir, json_output).await
        }
        "pair" => pairing::env_pair(client, &args[1..], json_output).await,
        unknown => Err(LpmError::Script(format!(
            "unknown env action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, example, print, check, connect, status, log, share, rotate-key, rotate-sharing-key, pair, unpair, init, ls, copy"
        ))),
    }
}

#[cfg(test)]
mod tests {
    const PRODUCTION_SOURCES: &[&str] = &[
        include_str!("mod.rs"),
        include_str!("auth.rs"),
        include_str!("inventory.rs"),
        include_str!("local.rs"),
        include_str!("oidc.rs"),
        include_str!("pairing.rs"),
        include_str!("platform/mod.rs"),
        include_str!("platform/coolify.rs"),
        include_str!("platform/fly.rs"),
        include_str!("platform/github_actions.rs"),
        include_str!("platform/railway.rs"),
        include_str!("pull.rs"),
        include_str!("push.rs"),
        include_str!("remote.rs"),
        include_str!("response.rs"),
        include_str!("rotation.rs"),
        include_str!("schema.rs"),
        include_str!("sync_payload.rs"),
    ];

    #[test]
    fn no_old_command_name_in_source() {
        let forbidden = format!("lpm use {}", "vars");
        let count: usize = PRODUCTION_SOURCES
            .iter()
            .map(|source| source.split("#[cfg(test)]").next().unwrap_or(source))
            .map(|production_code| production_code.matches(&forbidden).count())
            .sum();
        assert_eq!(
            count, 0,
            "found {count} occurrence(s) of the old command surface in production code"
        );
    }

    #[test]
    fn env_control_plane_requires_refresh_backed_sessions() {
        let retired_requirement = format!("AuthRequirement::{}Required", "Token");
        let count: usize = PRODUCTION_SOURCES
            .iter()
            .map(|source| source.split("#[cfg(test)]").next().unwrap_or(source))
            .map(|production_code| production_code.matches(&retired_requirement).count())
            .sum();

        assert_eq!(
            count, 0,
            "found {count} env control-plane call(s) that still accept non-session tokens"
        );
    }
}
