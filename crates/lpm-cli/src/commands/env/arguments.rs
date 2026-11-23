use clap::{Args, Parser, Subcommand};
use lpm_common::LpmError;

#[derive(Args)]
pub(super) struct Environment {
    /// The environment, by name or by an alias lpm.json gives it; default
    /// when left out.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub env: Option<String>,
}

#[derive(Args)]
pub(super) struct Scope {
    /// Validate the selected command stage.
    #[arg(long, value_parser = stage_name)]
    pub stage: Option<lpm_env::EnvStage>,
    /// Validate a named service within the selected environment and stage.
    #[arg(long, value_parser = service_name)]
    pub service: Option<String>,
}

fn stage_name(value: &str) -> Result<lpm_env::EnvStage, String> {
    lpm_env::EnvStage::parse(value)
        .ok_or_else(|| "stage must be development, build, runtime, ci, or test".into())
}
fn service_name(value: &str) -> Result<String, String> {
    lpm_env::resolver::validate_env_name(value)?;
    Ok(value.into())
}

#[derive(Parser)]
#[command(name = "lpm env")]
struct LocalCommand {
    #[command(subcommand)]
    action: LocalAction,
}

/// Where `set` and `override set` take values from.
#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("values")
        .required(true)
        .multiple(true)
        .args(["entries", "from_files"])
))]
pub(super) struct Values {
    /// A key to ask for, hidden, in a terminal, or KEY=VALUE.
    #[arg(num_args = 1.., value_name = "KEY")]
    pub entries: Vec<String>,
    /// Read the value of the one KEY given without = from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// Read a key's value from a file or a pipe, at most 100 KiB. Can be
    /// repeated.
    #[arg(long = "from-file", value_name = "KEY=PATH")]
    pub from_files: Vec<String>,
}

/// The paragraphs both `set` commands end with.
macro_rules! value_entry_help {
    () => {
        "

A KEY=VALUE argument is saved in your shell history and is visible to other
processes on this computer while lpm runs. Use it only for values that aren't
secret.

From the prompt, standard input or a file, a value that is one line loses the
line break at its end. A value of several lines, such as a PEM key, is kept
exactly, except that each line break pasted into the prompt is a line feed."
    };
}

const SET_AFTER_HELP: &str = concat!(
    "\
Examples:
  lpm env set API_KEY                          Ask for the value, hidden
  op read op://dev/api/key | lpm env set API_KEY --stdin
  lpm env set --from-file TLS_KEY=./tls.key
  lpm env set --from-file A=<(op read op://dev/a) --from-file B=<(op read op://dev/b)
  lpm env set PORT=3000                        A value that isn't secret",
    value_entry_help!()
);

const OVERRIDE_SET_AFTER_HELP: &str = concat!(
    "\
Examples:
  lpm env override set DATABASE_URL --env=development    Ask for the value, hidden
  echo \"$LOCAL_URL\" | lpm env override set API_URL --stdin
  lpm env override set --from-file TLS_KEY=./dev.key
  lpm env override set LOG_LEVEL=debug                   A value that isn't secret

A personal override is this computer's own value for a key. LPM applies it when
it runs, prints or checks the project here. It never syncs, and LPM leaves it
out when it pushes values or sends them to CI or a platform. Once the project
has one, its tasks, and the tasks that depend on them, don't use the remote task
cache on this computer. LPM CLI releases 0.82.0 to 0.88.0 apply overrides but
can share outputs built with them, through the remote task cache and
`lpm env print --format=github-actions`; later releases don't, and an older one
runs with team values.",
    value_entry_help!()
);

#[derive(Subcommand)]
pub(super) enum OverrideAction {
    /// Give keys this computer's own value, on top of the team's.
    #[command(after_help = OVERRIDE_SET_AFTER_HELP)]
    Set {
        #[command(flatten)]
        environment: Environment,
        #[command(flatten)]
        values: Values,
    },
    /// Leave out the project's value for keys when LPM runs the project on
    /// this computer.
    Unset {
        #[command(flatten)]
        environment: Environment,
        /// The keys to leave out, such as `DEBUG`.
        #[arg(required = true, num_args = 1.., value_name = "KEY")]
        keys: Vec<String>,
    },
    /// Remove this computer's override of keys, so they get the project's
    /// value, if it has one.
    Remove {
        #[command(flatten)]
        environment: Environment,
        /// The keys whose override to remove.
        #[arg(required = true, num_args = 1.., value_name = "KEY")]
        keys: Vec<String>,
    },
    /// List this computer's overrides: names only, values with --reveal.
    List {
        /// Only this environment, by name or by an alias lpm.json gives it;
        /// every environment when left out.
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        env: Option<String>,
        /// Show values.
        #[arg(long)]
        reveal: bool,
    },
    /// Remove every override of one environment, or of all of them.
    #[command(group(clap::ArgGroup::new("scope").required(true).args(["env", "all"])))]
    Clear {
        /// The environment whose overrides to remove, by name or by an alias
        /// lpm.json gives it.
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        env: Option<String>,
        /// Every environment's overrides.
        #[arg(long, conflicts_with = "env")]
        all: bool,
        /// Remove them without asking first, as a script or `--json` must.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum LocalAction {
    /// Store values in this project's env.
    #[command(after_help = SET_AFTER_HELP)]
    Set {
        #[command(flatten)]
        environment: Environment,
        #[command(flatten)]
        values: Values,
    },
    Get {
        #[command(flatten)]
        environment: Environment,
        key: String,
        #[arg(long)]
        reveal: bool,
    },
    List {
        #[command(flatten)]
        environment: Environment,
        #[arg(long)]
        reveal: bool,
    },
    Delete {
        #[command(flatten)]
        environment: Environment,
        #[arg(required = true, num_args = 1..)]
        keys: Vec<String>,
    },
    /// Store the values a .env file holds.
    Import {
        #[command(flatten)]
        environment: Environment,
        /// The .env file or pipe, or - to read it from standard input
        /// (./- names a file called -).
        #[arg(value_name = "FILE")]
        file: String,
        /// Replace values the env already has.
        #[arg(long)]
        overwrite: bool,
    },
    Export {
        #[command(flatten)]
        environment: Environment,
        file: String,
        #[arg(long)]
        ci: bool,
    },
    Print {
        #[command(flatten)]
        environment: Environment,
        #[command(flatten)]
        scope: Scope,
        #[arg(long, value_parser = print_format)]
        format: Option<lpm_env::PrintFormat>,
        #[arg(long)]
        schema_only: bool,
        /// Print only declared browser-visible variables.
        #[arg(long)]
        client_only: bool,
        #[arg(long, conflicts_with_all = ["format", "schema_only", "client_only", "stage", "service"])]
        ci: bool,
    },
    Example {
        #[command(flatten)]
        environment: Environment,
    },
    Check {
        #[command(flatten)]
        environment: Environment,
        #[command(flatten)]
        scope: Scope,
    },
    /// Check stored key names against .env.example.
    Validate {
        #[arg(long)]
        strict: bool,
    },
    /// Check declarations and imports without reading environment values.
    Schema,
    /// Generate separate typed server and client environment modules.
    Generate {
        #[command(flatten)]
        environment: Environment,
        #[command(flatten)]
        scope: Scope,
        /// Where the modules go, relative to the directory the command runs in
        /// and inside the project. Defaults to `env.generated` at the project
        /// root.
        #[arg(long, value_name = "DIR")]
        out_dir: Option<std::path::PathBuf>,
        #[arg(long, default_value = "default", value_parser = adapter)]
        adapter: lpm_env_codegen::Adapter,
        /// Check every generated byte without changing files or acquiring locks.
        #[arg(long)]
        check: bool,
    },
    Init {
        #[arg(long)]
        force: bool,
    },
    /// This computer's own values for keys, on top of the team's.
    Override {
        #[command(subcommand)]
        action: OverrideAction,
    },
    /// Show what's damaged in this project's newer data, such as its personal
    /// overrides, and repair it.
    Repair {
        /// Repair without asking first.
        #[arg(long)]
        yes: bool,
    },
    /// Plant a companion storage state for this project, for trying LPM and
    /// LPM Vault against the same data by hand. Debug builds only.
    #[cfg(debug_assertions)]
    #[command(name = "debug-companion", hide = true)]
    DebugCompanion {
        /// overrides, missing-record, invalid-marker, unlisted-records,
        /// newer-version, read-only, interrupted-deletion, stuck-restore,
        /// contradictory-record, weak-values, orphans or clear.
        state: String,
        #[command(flatten)]
        environment: Environment,
        /// A personal override to plant, for the overrides state.
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// A name the overrides state unsets.
        #[arg(long = "unset", value_name = "NAME")]
        unset: Vec<String>,
    },
    #[cfg_attr(
        target_os = "macos",
        doc = "Show how this project's values changed on this Mac, from local history."
    )]
    #[cfg_attr(
        not(target_os = "macos"),
        doc = "Show how this project's values changed on this computer, from local history."
    )]
    /// lpm.dev's activity log is `lpm env log`.
    #[command(args_conflicts_with_subcommands = true)]
    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
        /// Only changes to this key.
        key: Option<String>,
        #[command(flatten)]
        environment: Environment,
        /// Only changes from one source: app, cli, import, restore, pull,
        /// rollback or outside.
        #[arg(long, value_parser = source_group)]
        source: Option<lpm_vault::history::SourceGroup>,
        /// Show at most this many changes, newest first.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Show values. Without it, values are hidden.
        #[arg(long)]
        reveal: bool,
    },
    /// Roll back changes recorded in local history. Nothing is pushed.
    #[command(group(clap::ArgGroup::new("target").required(true).multiple(false)))]
    Rollback {
        /// Roll an environment back to its state right after this entry.
        #[arg(long, value_name = "ENTRY", group = "target")]
        to: Option<String>,
        /// Roll an environment back to its state right before this entry,
        /// or with one --key, that key to its value before it.
        #[arg(long, value_name = "ENTRY", group = "target")]
        before: Option<String>,
        /// Undo the keys this entry changed, in every environment it
        /// touched unless --env picks one.
        #[arg(long, value_name = "ENTRY", group = "target")]
        undo: Option<String>,
        #[command(flatten)]
        environment: Environment,
        /// Only these keys.
        #[arg(long = "key", value_name = "KEY")]
        keys: Vec<String>,
        /// Roll back without asking first.
        #[arg(long)]
        yes: bool,
    },
    Ls,
    Log,
    Unpair,
    /// Let this folder use the env project its lpm.json names, on this
    /// machine.
    Link {
        /// Link without asking first.
        #[arg(long)]
        yes: bool,
    },
    /// Stop a folder from using this env project on this machine.
    Unlink {
        /// The folder to unlink; this one when omitted.
        folder: Option<std::path::PathBuf>,
    },
    /// Show the folders linked to this env project on this machine.
    Links,
    Diff {
        #[arg(num_args = 0..=2)]
        environments: Vec<String>,
    },
    #[command(alias = "cp")]
    Copy {
        source: String,
        target: String,
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum HistoryAction {
    /// Show one entry.
    Show {
        /// The entry's ID: the 8-digit short ID, any unique prefix of at least
        /// 6 hex digits, or all 32.
        entry: String,
        /// Show values. Without it, values are hidden.
        #[arg(long)]
        reveal: bool,
    },
    /// Show whether local history is on and how much it keeps.
    Status,
    /// Turn local history on. It starts empty at the next change.
    On,
    #[cfg_attr(
        target_os = "macos",
        doc = "Turn local history off and delete it on this Mac."
    )]
    #[cfg_attr(
        not(target_os = "macos"),
        doc = "Turn local history off and delete it on this computer."
    )]
    Off {
        /// Turn it off without asking first.
        #[arg(long)]
        yes: bool,
    },
    /// Remove one value from local history: by default KEY's value after
    /// ENTRY, from KEY in every environment.
    Forget {
        entry: String,
        key: String,
        #[command(flatten)]
        environment: Environment,
        /// The value before ENTRY instead of after it.
        #[arg(long)]
        before: bool,
        /// Only the chosen environment.
        #[arg(long)]
        only_env: bool,
        /// Every other key that holds the same value too.
        #[arg(long)]
        all_keys: bool,
        /// Remove it without asking first.
        #[arg(long)]
        yes: bool,
    },
}

impl LocalAction {
    /// Whether the action reads or writes the values of the env project
    /// the folder names, which needs the folder to be linked to it. Actions
    /// that read lpm.json once into a snapshot (`init`, `ls`, `log`, `diff`)
    /// check the snapshot's env project themselves.
    pub(super) fn uses_project_values(&self) -> bool {
        match self {
            Self::Set { .. }
            | Self::Get { .. }
            | Self::List { .. }
            | Self::Delete { .. }
            | Self::Import { .. }
            | Self::Export { .. }
            | Self::Print { .. }
            | Self::Check { .. }
            | Self::Validate { .. }
            | Self::Repair { .. }
            | Self::Override { .. }
            | Self::History { .. }
            | Self::Rollback { .. }
            | Self::Copy { .. } => true,
            #[cfg(debug_assertions)]
            Self::DebugCompanion { .. } => true,
            Self::Example { .. }
            | Self::Init { .. }
            | Self::Ls
            | Self::Log
            | Self::Diff { .. }
            | Self::Schema
            | Self::Generate { .. }
            | Self::Unpair
            | Self::Link { .. }
            | Self::Unlink { .. }
            | Self::Links => false,
        }
    }
}

fn source_group(value: &str) -> Result<lpm_vault::history::SourceGroup, String> {
    lpm_vault::history::SourceGroup::from_name(value).ok_or_else(|| {
        "source must be app, cli, import, restore, pull, rollback, or outside".into()
    })
}

const LOCAL_SYNC_SUBCOMMANDS: &[&str] = &[
    "set", "get", "list", "delete", "import", "export", "print", "example", "check", "validate",
    "schema", "generate", "init", "repair", "override", "ls", "copy", "cp", "history", "rollback", "link",
    "unlink", "links",
];

const LOCAL_ASYNC_SUBCOMMANDS: &[&str] = &["log", "unpair", "diff"];

pub(super) fn is_local_sync_subcommand(args: &[&str]) -> bool {
    let Some(first) = args.first().copied() else {
        return false;
    };
    (cfg!(debug_assertions) && first == "debug-companion")
        || LOCAL_SYNC_SUBCOMMANDS.contains(&first)
}

pub(super) fn try_display_help(args: &[&str]) -> bool {
    if !args
        .iter()
        .take_while(|&&arg| arg != "--")
        .any(|&arg| matches!(arg, "-h" | "--help"))
    {
        return false;
    }
    match LocalCommand::try_parse_from(std::iter::once("lpm env").chain(args.iter().copied())) {
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            let _ = error.print();
            true
        }
        _ => false,
    }
}

pub(super) fn parse(args: &[&str], json_output: bool) -> Result<Option<LocalAction>, LpmError> {
    let is_local_action = is_local_sync_subcommand(args)
        || args
            .first()
            .copied()
            .is_some_and(|first| LOCAL_ASYNC_SUBCOMMANDS.contains(&first));
    if !is_local_action {
        return Ok(None);
    }
    LocalCommand::try_parse_from(std::iter::once("lpm env").chain(args.iter().copied()))
        .map(|command| Some(command.action))
        .map_err(|error| {
            let status = if error.use_stderr() { 2 } else { 0 };
            if json_output && error.use_stderr() {
                let action = if args[0] == "cp" { "copy" } else { args[0] };
                let hint = format!("Run `lpm env {action} --help` for usage.");
                crate::cli::print_json_clap_error(&error, Some(&hint));
            } else {
                let _ = error.print();
            }
            LpmError::ExitCode(status)
        })
}

fn adapter(value: &str) -> Result<lpm_env_codegen::Adapter, String> {
    lpm_env_codegen::Adapter::parse(value)
        .ok_or_else(|| "adapter must be default, node, nextjs, or vite".into())
}

fn print_format(value: &str) -> Result<lpm_env::PrintFormat, String> {
    lpm_env::PrintFormat::parse(value).ok_or_else(|| {
        format!(
            "unknown format: '{value}'. Available: {}",
            lpm_env::PrintFormat::all_names()
        )
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    /// The long help of the subcommand at `path`, its whitespace collapsed.
    fn long_help(path: &[&str]) -> String {
        let mut command = super::LocalCommand::command();
        let mut subcommand = &mut command;
        for name in path {
            subcommand = subcommand
                .find_subcommand_mut(name)
                .expect("subcommand registered");
        }
        let mut buffer = Vec::new();
        subcommand
            .write_long_help(&mut buffer)
            .expect("write the help");
        String::from_utf8(buffer)
            .expect("UTF-8 help")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn both_set_commands_say_what_happens_to_a_value_s_line_breaks() {
        for path in [&["set"][..], &["override", "set"]] {
            let help = long_help(path);
            assert!(
                help.contains(
                    "From the prompt, standard input or a file, a value that is one line loses the line break at its end."
                ),
                "{path:?}: {help}"
            );
            assert!(
                help.contains("A KEY=VALUE argument is saved in your shell history"),
                "{path:?}: {help}"
            );
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_companion_help_names_every_state() {
        let command = super::LocalCommand::command();
        let help = command
            .find_subcommand("debug-companion")
            .and_then(|debug| {
                debug
                    .get_arguments()
                    .find(|argument| argument.get_id() == "state")
            })
            .and_then(|state| state.get_help())
            .expect("the state argument's help")
            .to_string();
        for name in lpm_vault::DebugCompanionState::NAMES {
            assert!(help.contains(name), "{name} is missing from: {help}");
        }
    }
}
