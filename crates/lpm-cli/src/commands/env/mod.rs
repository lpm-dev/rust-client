//! `lpm env` command dispatcher and domain modules.

mod arguments;
pub(crate) mod auth;
mod characters;
mod ci;
#[cfg(debug_assertions)]
mod debug_companion;
mod generate;
mod github;
mod history;
mod inventory;
pub(crate) mod links;
mod local;
mod oidc;
mod pairing;
mod personal_overrides;
mod platform;
mod pull;
mod push;
mod remote;
mod repair;
mod response;
mod rotation;
mod schema;
mod sync_payload;
mod value_input;

mod prelude {
    pub(super) use crate::{install_ui, output};
    pub(super) use futures::StreamExt;
    pub(super) use lpm_common::LpmError;
    pub(super) use lpm_common::color::Painted;
    pub(super) use std::collections::HashMap;
}

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// Whether `extra` names an action on the account rather than on a
/// project: pairing a browser, revoking every pairing, rotating the sharing
/// key, and listing remote envs. They run anywhere, a project or not.
pub fn is_account_action(extra: &[String]) -> bool {
    matches!(
        extra.first().map(String::as_str),
        Some("pair" | "unpair" | "rotate-sharing-key" | "list-remote" | "ls-remote")
    )
}

/// Handle `lpm env` subcommands.
///
/// Local-file management (`set`, `get`, `list`, `delete`, `import`,
/// `export`, `print`, `copy`, `check`, `init`), cloud sync (`pull`,
/// `push`, `share`, `pair`, `diff`, `validate`), platform integrations
/// (`push --to <platform>`, `pull --from <platform>`, `connect`,
/// `status`), and OIDC policies (`oidc allow`, `oidc list`, `oidc pull`).
pub async fn run(
    client: &RegistryClient,
    project_dir: &std::path::Path,
    extra: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    run_action(client, project_dir, extra, json_output)
        .await
        .map_err(env_error)
}

/// `lpm env` runs no scripts, so a script error from a helper it shares
/// with `lpm run`, such as dotenv or `lpm.json` parsing, is an env error.
fn env_error(error: LpmError) -> LpmError {
    match error {
        LpmError::Script(message) => LpmError::Env(message),
        other => other,
    }
}

/// Run purely local `lpm env` subcommands synchronously without constructing a
/// Tokio runtime or registry client. Returns `None` when the action requires
/// network / remote registry access.
pub fn try_run_local_sync(
    resolve_project_dir: impl FnOnce() -> Result<std::path::PathBuf, LpmError>,
    extra: &[String],
    json_output: bool,
) -> Option<Result<(), LpmError>> {
    let args: Vec<&str> = extra.iter().map(String::as_str).collect();
    if args.is_empty() {
        return Some(
            resolve_project_dir()
                .and_then(|project_dir| {
                    links::ensure_folder_linked(&project_dir, json_output)
                        .and_then(|()| local::env_list(None, false, &project_dir, json_output))
                })
                .map_err(env_error),
        );
    }
    if !arguments::is_local_sync_subcommand(&args) {
        return None;
    }
    if arguments::try_display_help(&args) {
        return Some(Ok(()));
    }
    // Resolve the project root BEFORE `arguments::parse` prints any JSON/clap
    // diagnostic so a disallowed directory (such as LPM_HOME) emits a single
    // error envelope rather than both a clap error and a project-root error.
    let project_dir = match resolve_project_dir() {
        Ok(dir) => dir,
        Err(error) => return Some(Err(env_error(error))),
    };
    let parsed = match arguments::parse(&args, json_output) {
        Ok(Some(action)) => action,
        Ok(None) => return None,
        Err(error) => return Some(Err(env_error(error))),
    };
    Some(run_local_sync_action(parsed, &project_dir, json_output).map_err(env_error))
}

fn run_local_sync_action(
    action: arguments::LocalAction,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    use arguments::LocalAction;
    // set checks its arguments first, so a wrong one never asks to link.
    if action.uses_project_values() && !matches!(action, LocalAction::Set { .. }) {
        links::ensure_folder_linked(project_dir, json_output)?;
    }
    let result = match action {
        LocalAction::Set {
            environment,
            values,
        } => local::env_set(
            environment.env.as_deref(),
            &values,
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
            scope,
            format,
            schema_only,
            client_only,
            ci,
        } => schema::vars_print(
            environment.env.as_deref(),
            format,
            schema_only,
            client_only,
            ci,
            &scope,
            project_dir,
            json_output,
        ),
        LocalAction::Example { environment } => {
            schema::vars_example(project_dir, environment.env.as_deref(), json_output)
        }
        LocalAction::Check { environment, scope } => {
            schema::vars_check(project_dir, environment.env.as_deref(), &scope, json_output)
        }
        LocalAction::Validate { strict } => schema::vars_validate(project_dir, strict, json_output),
        LocalAction::Schema => schema::schema_definition(project_dir, json_output),
        LocalAction::Generate {
            environment,
            scope,
            out_dir,
            adapter,
            check,
        } => {
            let out_dir = match out_dir {
                Some(typed) => crate::project_fs::project_relative_path(
                    &std::env::current_dir().map_err(LpmError::Io)?,
                    project_dir,
                    &typed,
                ),
                None => std::path::PathBuf::from(generate::DEFAULT_OUT_DIR),
            };
            generate::run(
                project_dir,
                environment.env.as_deref(),
                &scope,
                &out_dir,
                adapter,
                check,
                json_output,
            )
        }
        LocalAction::Init { force } => inventory::vars_init(project_dir, force, json_output),
        LocalAction::Repair { yes } => repair::env_repair(project_dir, yes, json_output),
        LocalAction::Override { action } => {
            personal_overrides::run(action, project_dir, json_output)
        }
        #[cfg(debug_assertions)]
        LocalAction::DebugCompanion {
            state,
            environment,
            set,
            unset,
        } => debug_companion::plant(
            project_dir,
            &state,
            environment.env.as_deref(),
            &set,
            &unset,
            json_output,
        ),
        LocalAction::History {
            action,
            key,
            environment,
            source,
            limit,
            reveal,
        } => history::env_history(
            action,
            history::ListArgs {
                key: key.as_deref(),
                environment: environment.env.as_deref(),
                source,
                limit,
                reveal,
            },
            project_dir,
            json_output,
        ),
        LocalAction::Rollback {
            to,
            before,
            undo,
            environment,
            keys,
            yes,
        } => history::env_rollback(
            &history::RollbackArgs {
                to: to.as_deref(),
                before: before.as_deref(),
                undo: undo.as_deref(),
                environment: environment.env.as_deref(),
                keys: &keys,
                yes,
            },
            project_dir,
            json_output,
        ),
        LocalAction::Ls => inventory::vars_ls(project_dir, json_output),
        LocalAction::Link { yes } => links::env_link(project_dir, yes, json_output),
        LocalAction::Unlink { folder } => {
            links::env_unlink(project_dir, folder.as_deref(), json_output)
        }
        LocalAction::Links => links::env_links(project_dir, json_output),
        LocalAction::Copy {
            source,
            target,
            overwrite,
        } => inventory::vars_copy(project_dir, &source, &target, overwrite, json_output),
        LocalAction::Log | LocalAction::Unpair | LocalAction::Diff { .. } => {
            unreachable!("remote actions are handled by run_action")
        }
    };
    reported(result)
}

async fn run_action(
    client: &RegistryClient,
    project_dir: &std::path::Path,
    extra: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let args: Vec<&str> = extra.iter().map(String::as_str).collect();
    if args.is_empty() {
        links::ensure_folder_linked(project_dir, json_output)?;
        return local::env_list(None, false, project_dir, json_output);
    }
    if let Some(action) = arguments::parse(&args, json_output)? {
        use arguments::LocalAction;
        match action {
            LocalAction::Log => {
                if action.uses_project_values() {
                    links::ensure_folder_linked(project_dir, json_output)?;
                }
                return reported(remote::env_log(client, project_dir, json_output).await);
            }
            LocalAction::Unpair => {
                return reported(pairing::env_unpair(client, json_output).await);
            }
            LocalAction::Diff { ref environments } => {
                if action.uses_project_values() {
                    links::ensure_folder_linked(project_dir, json_output)?;
                }
                let environments: Vec<&str> = environments.iter().map(String::as_str).collect();
                return reported(
                    remote::vars_diff(client, &environments, project_dir, json_output).await,
                );
            }
            local_action => {
                return run_local_sync_action(local_action, project_dir, json_output);
            }
        }
    }

    let result = match args[0] {
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
        unknown => Err(LpmError::Env(format!(
            "unknown env action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, schema, generate, example, print, check, connect, status, log, history, rollback, share, rotate-key, rotate-sharing-key, pair, unpair, init, ls, list-remote, copy, oidc, override, repair, link, unlink, links"
        ))),
    };
    reported(result)
}

/// A command that failed after it wrote values still says when history
/// didn't record that write; one that succeeded said so already.
fn reported(result: Result<(), LpmError>) -> Result<(), LpmError> {
    if result.is_err() {
        history::report_write();
    }
    result
}

#[cfg(test)]
mod tests {
    const PRODUCTION_SOURCES: &[&str] = &[
        include_str!("mod.rs"),
        include_str!("auth.rs"),
        include_str!("characters.rs"),
        include_str!("inventory.rs"),
        include_str!("local.rs"),
        include_str!("oidc.rs"),
        include_str!("pairing.rs"),
        include_str!("personal_overrides.rs"),
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
        include_str!("value_input.rs"),
    ];

    /// std's buffered stdin keeps what it read in a buffer it never wipes,
    /// so secret input reads standard input from its descriptor
    /// (`secret_read::read_secret_stdin`) and never through std's reader.
    #[test]
    fn secret_input_never_reads_through_std_s_buffered_stdin() {
        // What a file holds before its tests: a test hook in production code
        // carries `#[cfg(test)]` too.
        let production = |source: &'static str| {
            source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(source)
        };
        // Here std's stdin only says whether it's a terminal.
        for (name, source) in [
            ("value_input.rs", include_str!("value_input.rs")),
            ("local.rs", include_str!("local.rs")),
            (
                "personal_overrides.rs",
                include_str!("personal_overrides.rs"),
            ),
            ("hidden_prompt.rs", include_str!("../../hidden_prompt.rs")),
            (
                "hidden_prompt/unix.rs",
                include_str!("../../hidden_prompt/unix.rs"),
            ),
            (
                "hidden_prompt/windows.rs",
                include_str!("../../hidden_prompt/windows.rs"),
            ),
        ] {
            let source = production(source);
            assert_eq!(
                source.matches("stdin()").count(),
                source.matches("stdin().is_terminal()").count(),
                "{name} uses std's stdin for more than whether it's a terminal"
            );
        }
        // The reader takes its descriptor and reads that alone.
        let secret_read = production(include_str!("../../../../lpm-common/src/secret_read.rs"));
        assert_eq!(secret_read.matches("stdin()").count(), 1);
        assert_eq!(
            secret_read.matches("stdin.").count(),
            secret_read.matches("stdin.as_raw_fd()").count()
                + secret_read.matches("stdin.as_raw_handle()").count(),
            "secret_read.rs reads std's stdin rather than its descriptor"
        );
    }

    #[test]
    fn a_script_error_from_a_shared_helper_is_reported_as_an_env_error() {
        use super::{LpmError, env_error};
        assert!(matches!(
            env_error(LpmError::Script("bad .env line".into())),
            LpmError::Env(message) if message == "bad .env line"
        ));
        assert!(matches!(
            env_error(LpmError::Network("offline".into())),
            LpmError::Network(_)
        ));
    }

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

    #[test]
    fn help_token_as_option_value_does_not_bypass_project_dir_validation() {
        let args = vec![
            "list".to_string(),
            "--env".to_string(),
            "--help".to_string(),
        ];
        let result = super::try_run_local_sync(
            || Err(super::LpmError::Env("disallowed LPM_HOME".into())),
            &args,
            false,
        );
        assert!(
            matches!(result, Some(Err(super::LpmError::Env(ref msg))) if msg == "disallowed LPM_HOME"),
            "non-help invocation containing `--help` as an option value must not swallow action or bypass project-dir check: {result:?}"
        );
    }
}
