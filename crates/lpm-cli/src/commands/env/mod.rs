//! `lpm env` command dispatcher and domain modules.

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
/// The `Env` clap variant captures everything after `lpm env` as `extra`
/// (trailing_var_arg), so this function re-parses raw argv to dispatch
/// on the subcommand.
pub async fn run(
    client: &RegistryClient,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let raw_args: Vec<String> = std::env::args().collect();
    let cmd_pos = raw_args.iter().position(|a| a == "env");
    let args: Vec<&str> = match cmd_pos {
        Some(pos) => raw_args[pos + 1..].iter().map(|s| s.as_str()).collect(),
        None => vec![],
    };

    if args.is_empty() {
        local::vars_list(project_dir, None, false, json_output)?;
        return Ok(());
    }

    match args[0] {
        "set" => local::env_set(&args[1..], project_dir, json_output)?,
        "get" => local::env_get(&args[1..], project_dir, json_output)?,
        "list" => local::env_list(&args[1..], project_dir, json_output)?,
        "delete" => local::env_delete(&args[1..], project_dir, json_output)?,
        "import" => local::env_import(&args[1..], project_dir, json_output)?,
        "export" => local::env_export(&args[1..], project_dir, json_output)?,
        "push" => return push::vars_push(client, &args, project_dir, json_output).await,
        "pull" => return pull::vars_pull(client, &args, project_dir, json_output).await,
        "log" => return remote::env_log(client, project_dir, json_output).await,
        "share" => return remote::env_share(client, &args, project_dir, json_output).await,
        "rotate-key" => {
            return rotation::env_rotate_key(client, &args[1..], project_dir, json_output).await;
        }
        "rotate-sharing-key" => {
            return rotation::env_rotate_sharing_key(client, &args, json_output).await;
        }
        "list-remote" | "ls-remote" => {
            let org_flag = remote::parse_list_remote_org_slug(&args)?;
            return remote::vars_list_remote(client, org_flag, json_output).await;
        }
        "diff" => return remote::vars_diff(client, &args[1..], project_dir, json_output).await,
        "validate" => {
            let strict = args.contains(&"--strict");
            return schema::vars_validate(project_dir, strict, json_output);
        }
        "example" => {
            let (env_input, _remaining) = local::parse_env_flag(&args[1..])?;
            return schema::vars_example(project_dir, env_input, json_output);
        }
        "print" => return schema::vars_print(&args[1..], project_dir),
        "check" => return schema::vars_check(project_dir, json_output),
        "connect" => {
            return platform::vars_connect(client, &args[1..], project_dir, json_output).await;
        }
        "oidc" => return oidc::vars_oidc(client, &args[1..], project_dir, json_output).await,
        "status" => return platform::vars_platform_status(client, project_dir, json_output).await,
        "pair" => return pairing::env_pair(client, &args[1..], json_output).await,
        "unpair" => return pairing::env_unpair(client, json_output).await,
        "init" => {
            let force = args.contains(&"--force");
            return inventory::vars_init(project_dir, force, json_output);
        }
        "ls" => return inventory::vars_ls(project_dir, json_output),
        "copy" | "cp" => {
            let remaining = &args[1..];
            if remaining.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm env copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            let overwrite = remaining.contains(&"--overwrite");
            let envs: Vec<&&str> = remaining.iter().filter(|a| **a != "--overwrite").collect();
            if envs.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm env copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            return inventory::vars_copy(project_dir, envs[0], envs[1], overwrite, json_output);
        }
        unknown => {
            return Err(LpmError::Script(format!(
                "unknown env action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, example, print, check, connect, status, log, share, rotate-key, rotate-sharing-key, pair, unpair, init, ls, copy"
            )));
        }
    }

    Ok(())
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
}
