//! `lpm env override`: this computer's own values for a project's keys, on
//! top of its team values. The engine plans every change and validates it;
//! this module collects input, asks before clearing, and reports what each
//! change did by name, never by value.

use lpm_vault::overrides::{Edit, Effect, Previous};

use super::arguments::{OverrideAction, Values};
use super::prelude::*;
use crate::prompt::PromptResultExt as _;
use lpm_runner::dotenv::THIS_MACHINE;

/// What a value shows as when it's hidden.
const HIDDEN: &str = "••••••••";

/// The releases that support only personal overrides v1. They apply it but
/// can share what they build with it, through their remote task cache and
/// their GitHub Actions print, so this client writes v2, which they refuse.
/// An older LPM CLI runs a project with team values only.
const RELEASES_THAT_REFUSE_OVERRIDES: (&str, &str) = ("0.82.0", "0.88.0");

pub(super) fn run(
    action: OverrideAction,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        OverrideAction::Set {
            environment,
            values,
        } => set(
            environment.env.as_deref(),
            &values,
            project_dir,
            json_output,
        ),
        OverrideAction::Unset { environment, keys } => change_keys(
            environment.env.as_deref(),
            &keys,
            KeyChange::Unset,
            project_dir,
            json_output,
        ),
        OverrideAction::Remove { environment, keys } => change_keys(
            environment.env.as_deref(),
            &keys,
            KeyChange::Remove,
            project_dir,
            json_output,
        ),
        OverrideAction::List { env, reveal } => {
            list(env.as_deref(), reveal, project_dir, json_output)
        }
        OverrideAction::Clear { env, all: _, yes } => {
            clear(env.as_deref(), yes, project_dir, json_output)
        }
    }
}

/// The environment `--env` names, resolved through lpm.json's aliases to the
/// name overrides are stored under; `default` without one.
fn environment(env_input: Option<&str>, project_dir: &std::path::Path) -> Result<String, LpmError> {
    let (resolved, _config) = super::local::resolve_env_from_flag(env_input, project_dir)?;
    Ok(resolved.unwrap_or_else(|| lpm_env::DEFAULT_ENVIRONMENT.to_owned()))
}

fn vault_error(error: String) -> LpmError {
    lpm_runner::dotenv::vault_error(LpmError::Env)(error)
}

fn set(
    env_input: Option<&str>,
    values: &Values,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let environment = environment(env_input, project_dir)?;
    let request = super::value_input::Request {
        entries: &values.entries,
        stdin: values.stdin,
        from_files: &values.from_files,
        json_output,
        command: "lpm env override set",
        asking: super::value_input::Asking {
            what: "Override",
            environment: &environment,
        },
        // A project's overrides are one record, which holds no more.
        total_limit: lpm_vault::overrides::MAX_RECORD_BYTES,
    };
    let checked = super::value_input::check(&request, &super::value_input::ProcessSources)?;
    let named: Vec<Edit> = checked
        .keys()
        .into_iter()
        .map(|key| Edit::Unset {
            environment: environment.clone(),
            key: key.to_owned(),
        })
        .collect();
    lpm_vault::overrides::check_edits(&named).map_err(vault_error)?;
    super::links::ensure_folder_linked(project_dir, json_output)?;
    // Only a value that's typed, piped or read waits on the person; one in
    // the arguments needs no check before it.
    let project = checked
        .reads_input
        .then(|| {
            lpm_vault::overrides::check_before_values(project_dir, &environment, &checked.keys())
        })
        .transpose()
        .map_err(vault_error)?;
    let assignments =
        super::value_input::collect(&request, checked, &mut super::value_input::ProcessSources)?;
    // A key given twice as KEY=VALUE keeps its last value, as `env set` does.
    let mut seen = std::collections::HashSet::with_capacity(assignments.len());
    let mut edits: Vec<Edit> = assignments
        .into_iter()
        .rev()
        .filter(|assignment| seen.insert(assignment.key.clone()))
        .map(|assignment| Edit::Set {
            environment: environment.clone(),
            key: assignment.key,
            value: assignment.value,
        })
        .collect();
    edits.reverse();
    let change = match &project {
        Some(project) => lpm_vault::overrides::change_checked(project_dir, project, &edits),
        None => lpm_vault::overrides::change(project_dir, &edits),
    }
    .map_err(vault_error)?;
    let warnings: Vec<(&str, lpm_env::ValueCharacters)> = edits
        .iter()
        .filter_map(|edit| match edit {
            Edit::Set { key, value, .. } => {
                lpm_env::check_value_characters(value).map(|found| (key.as_str(), found))
            }
            _ => None,
        })
        .collect();
    if json_output {
        let mut envelope = key_changes_json(&environment, &change);
        envelope["value_warnings"] = serde_json::Value::Array(
            warnings
                .iter()
                .map(|(key, found)| super::characters::json(key, found))
                .collect(),
        );
        println!("{envelope}");
        return Ok(());
    }
    for effect in &change.effects {
        if let Effect::Key {
            key,
            previous,
            changed,
            ..
        } = effect
        {
            if *changed {
                output::success_line(install_ui::terminal_line!(
                    "{} {} on {} ({})",
                    install_ui::bold(key),
                    if *previous == Previous::None {
                        "has an override"
                    } else {
                        "has a new override"
                    },
                    THIS_MACHINE,
                    &environment,
                ));
            } else {
                output::info_line(install_ui::terminal_line!(
                    "{} already had that override ({})",
                    install_ui::bold(key),
                    &environment,
                ));
            }
        }
    }
    for (key, found) in &warnings {
        super::characters::warn_stored(key, found);
    }
    report_storage(&change);
    Ok(())
}

#[derive(Clone, Copy)]
enum KeyChange {
    Unset,
    Remove,
}

fn change_keys(
    env_input: Option<&str>,
    keys: &[String],
    kind: KeyChange,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    // A name that isn't a key may be a value typed in the wrong place, so
    // it's never repeated back.
    if !keys.iter().all(|key| lpm_env::is_valid_env_var_name(key)) {
        return Err(LpmError::Env(
            "env keys must match [A-Za-z_][A-Za-z0-9_]*".into(),
        ));
    }
    let environment = environment(env_input, project_dir)?;
    // A key named twice is one change; where names differ only in case are
    // one variable, so are they.
    let mut named = std::collections::HashSet::with_capacity(keys.len());
    let edits: Vec<Edit> = keys
        .iter()
        .filter(|key| {
            named.insert(if cfg!(windows) {
                key.to_ascii_uppercase()
            } else {
                (*key).clone()
            })
        })
        .map(|key| match kind {
            KeyChange::Unset => Edit::Unset {
                environment: environment.clone(),
                key: key.clone(),
            },
            KeyChange::Remove => Edit::Remove {
                environment: environment.clone(),
                key: key.clone(),
            },
        })
        .collect();
    lpm_vault::overrides::check_edits(&edits).map_err(vault_error)?;
    super::links::ensure_folder_linked(project_dir, json_output)?;
    let change = lpm_vault::overrides::change(project_dir, &edits).map_err(vault_error)?;
    if json_output {
        println!("{}", key_changes_json(&environment, &change));
        return Ok(());
    }
    for effect in &change.effects {
        let Effect::Key {
            key,
            previous,
            changed,
            ..
        } = effect
        else {
            continue;
        };
        match (kind, changed, previous) {
            (KeyChange::Unset, true, _) => output::success_line(install_ui::terminal_line!(
                "{} gets no value from the project on {} ({})",
                install_ui::bold(key),
                THIS_MACHINE,
                &environment,
            )),
            (KeyChange::Unset, false, _) => output::info_line(install_ui::terminal_line!(
                "{} already gets no value from the project ({})",
                install_ui::bold(key),
                &environment,
            )),
            (KeyChange::Remove, true, _) => output::success_line(install_ui::terminal_line!(
                "{} no longer has an override on {} ({})",
                install_ui::bold(key),
                THIS_MACHINE,
                &environment,
            )),
            (KeyChange::Remove, false, _) => install_ui::warn_line(install_ui::terminal_line!(
                "{} had no override ({}); nothing to remove",
                install_ui::bold(key),
                &environment,
            )),
        }
    }
    report_storage(&change);
    Ok(())
}

/// A set, unset or remove for `--json`: what each key had and whether the
/// change touched it.
fn key_changes_json(environment: &str, change: &lpm_vault::overrides::Change) -> serde_json::Value {
    let changes: Vec<serde_json::Value> = change
        .effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Key {
                key,
                previous,
                changed,
                ..
            } => Some(serde_json::json!({
                "key": key,
                "previous": previous,
                "changed": changed,
            })),
            _ => None,
        })
        .collect();
    serde_json::json!({
        "success": true,
        "env": environment,
        "changes": changes,
        "activated": change.activated,
        "over_admission_target": change.over_admission_target,
    })
}

/// Say once, when a project gets its first override, which LPM CLIs apply
/// it, and when the computer holds more newer data than it should.
fn report_storage(change: &lpm_vault::overrides::Change) {
    if change.activated {
        let (first, last) = RELEASES_THAT_REFUSE_OVERRIDES;
        output::warn_line(install_ui::terminal_line!(
            "LPM CLI releases {} to {} refuse this project now that it has personal overrides, until they're updated with `lpm self-update`; an LPM CLI older than {} runs it with team values",
            first,
            last,
            first,
        ));
    }
    if change.over_admission_target {
        output::warn_line(install_ui::terminal_line!(
            "this computer's env storage holds more newer data than it should; delete env projects you no longer use"
        ));
    }
}

fn list(
    env_input: Option<&str>,
    reveal: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let selected = env_input
        .map(|_| environment(env_input, project_dir))
        .transpose()?;
    super::links::ensure_folder_linked(project_dir, json_output)?;
    let mut all = lpm_vault::overrides::read_all(project_dir).map_err(vault_error)?;
    if let Some(selected) = &selected {
        all.retain(|name, _| name == selected);
    }
    let listed: Vec<Listed> = all
        .into_iter()
        .map(|(environment, mut overrides)| {
            let mut set: Vec<(String, String)> =
                std::mem::take(&mut overrides.set).into_iter().collect();
            set.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut unset = std::mem::take(&mut overrides.unset);
            unset.sort_unstable();
            Listed {
                environment,
                set,
                unset,
            }
        })
        .collect();
    if json_output {
        let environments: Vec<serde_json::Value> = listed
            .iter()
            .map(
                |Listed {
                     environment,
                     set,
                     unset,
                 }| {
                    serde_json::json!({
                        "env": environment,
                        "set": set.iter().map(|(key, value)| serde_json::json!({
                            "key": key,
                            "value": if reveal { value.as_str() } else { HIDDEN },
                            "passed": !lpm_env::is_denied_env_var(key),
                        })).collect::<Vec<_>>(),
                        "unset": unset.iter().map(|key| serde_json::json!({
                            "key": key,
                            "passed": !lpm_env::is_denied_env_var(key),
                        })).collect::<Vec<_>>(),
                    })
                },
            )
            .collect();
        println!(
            "{}",
            serde_json::json!({"success": true, "environments": environments})
        );
        return Ok(());
    }
    if listed.is_empty() {
        match &selected {
            Some(environment) => output::info(&format!(
                "No personal overrides on {THIS_MACHINE} ({environment})"
            )),
            None => output::info(&format!("No personal overrides on {THIS_MACHINE}")),
        }
        let example = match &selected {
            Some(environment) => format!("lpm env override set KEY --env={environment}"),
            None => "lpm env override set KEY --env=ENV".to_owned(),
        };
        println!("  Run {} to add one", example.cyan());
        return Ok(());
    }
    for Listed {
        environment,
        set,
        unset,
    } in &listed
    {
        output::info(&format!(
            "Personal overrides on {THIS_MACHINE} — {environment} ({})",
            set.len() + unset.len()
        ));
        for (key, value) in set {
            let never_passed = if lpm_env::is_denied_env_var(key) {
                "  (LPM never passes it to processes)"
            } else {
                ""
            };
            let line = if reveal {
                install_ui::terminal_line!(
                    "  {} = {}{}",
                    install_ui::bold(key),
                    value,
                    install_ui::dim(never_passed),
                )
            } else {
                install_ui::terminal_line!(
                    "  {} = {}{}",
                    install_ui::bold(key),
                    install_ui::dim(HIDDEN),
                    install_ui::dim(never_passed),
                )
            };
            println!("{line}");
        }
        for key in unset {
            let never_passed = if lpm_env::is_denied_env_var(key) {
                "  (LPM never passes it to processes)"
            } else {
                ""
            };
            println!(
                "{}",
                install_ui::terminal_line!(
                    "  {} {}{}",
                    install_ui::bold(key),
                    install_ui::dim("(no value from the project)"),
                    install_ui::dim(never_passed),
                )
            );
        }
    }
    Ok(())
}

/// One environment's overrides, in order.
struct Listed {
    environment: String,
    set: Vec<(String, String)>,
    unset: Vec<String>,
}

fn clear(
    env_input: Option<&str>,
    yes: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    use std::io::IsTerminal as _;
    let selected = env_input
        .map(|_| environment(env_input, project_dir))
        .transpose()?;
    let scope = match &selected {
        Some(environment) => environment.clone(),
        None => "every environment".to_owned(),
    };
    if yes {
        let edit = match &selected {
            Some(environment) => Edit::ClearEnvironment {
                environment: environment.clone(),
            },
            None => Edit::ClearAll,
        };
        lpm_vault::overrides::check_edits(std::slice::from_ref(&edit)).map_err(vault_error)?;
        super::links::ensure_folder_linked(project_dir, json_output)?;
        let change = lpm_vault::overrides::change(project_dir, &[edit]).map_err(vault_error)?;
        report_cleared(&selected, &scope, removed(&change), json_output);
        return Ok(());
    }
    // Whether it can ask is known before anything is read, so a command
    // that can't ask never reads overrides, or asks for approval, for
    // nothing. The question shows on standard error, the one terminal it
    // can ask on.
    if json_output || !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return Err(LpmError::ConfirmationRequired {
            command: "lpm env override clear",
            change: format!("remove the personal overrides on {THIS_MACHINE} ({scope})"),
            help: "Check them with `lpm env override list`, then run it again with `--yes`. It asks only in an interactive terminal, and never with `--json`.",
        });
    }
    super::links::ensure_folder_linked(project_dir, json_output)?;
    let Some(reviewed) = lpm_vault::overrides::review_all(project_dir).map_err(vault_error)? else {
        report_cleared(&selected, &scope, 0, json_output);
        return Ok(());
    };
    // The question counts exactly what's removed, in the project it read:
    // an override another command adds while it waits stays, and one it
    // changes stops the removal.
    let mut removals: Vec<(String, String)> = Vec::new();
    for (environment, overrides) in &reviewed.overrides {
        if selected
            .as_ref()
            .is_some_and(|selected| selected != environment)
        {
            continue;
        }
        removals.extend(
            overrides
                .set
                .keys()
                .chain(&overrides.unset)
                .map(|key| (environment.clone(), key.clone())),
        );
    }
    if removals.is_empty() {
        report_cleared(&selected, &scope, 0, json_output);
        return Ok(());
    }
    let count = removals.len();
    let question = format!(
        "Remove {count} personal override{} on {THIS_MACHINE} ({})?",
        if count == 1 { "" } else { "s" },
        removal_summary(&removals),
    );
    let confirmed = cliclack::confirm(&question)
        .initial_value(false)
        .interact()
        .map_prompt_err(|error| LpmError::Env(format!("prompt failed: {error}")))?;
    if !confirmed {
        output::info("nothing was changed");
        return Ok(());
    }
    let change = lpm_vault::overrides::remove_reviewed(project_dir, &reviewed, &removals)
        .map_err(vault_error)?;
    report_cleared(&selected, &scope, removed(&change), json_output);
    Ok(())
}

/// The most keys the clear question names; past it, it counts them.
const NAMED_IN_QUESTION: usize = 8;

/// What the clear question says it removes, environment by environment, in
/// `removals`' order: the keys, sorted, when it removes no more than
/// [`NAMED_IN_QUESTION`], or else how many in each.
fn removal_summary(removals: &[(String, String)]) -> String {
    let mut environments: Vec<(&str, Vec<&str>)> = Vec::new();
    for (environment, key) in removals {
        match environments.last_mut() {
            Some((last, keys)) if *last == environment.as_str() => keys.push(key),
            _ => environments.push((environment, vec![key])),
        }
    }
    let named = removals.len() <= NAMED_IN_QUESTION;
    environments
        .iter_mut()
        .map(|(environment, keys)| {
            let environment = lpm_common::sanitize_terminal_inline(environment);
            if named {
                keys.sort_unstable();
                let keys: Vec<_> = keys
                    .iter()
                    .map(|key| lpm_common::sanitize_terminal_inline(key))
                    .collect();
                format!("{environment}: {}", keys.join(", "))
            } else {
                format!("{environment}: {}", keys.len())
            }
        })
        .collect::<Vec<_>>()
        .join(if named { "; " } else { ", " })
}

/// How many overrides a clear removed.
fn removed(change: &lpm_vault::overrides::Change) -> usize {
    change
        .effects
        .iter()
        .map(|effect| match effect {
            Effect::Cleared { removed, .. } => *removed,
            Effect::Key { changed: true, .. } => 1,
            _ => 0,
        })
        .sum()
}

fn report_cleared(selected: &Option<String>, scope: &str, removed: usize, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "env": selected, "removed": removed})
        );
    } else if removed == 0 {
        output::info(&format!("no personal overrides to remove ({scope})"));
    } else {
        output::success_line(install_ui::terminal_line!(
            "removed {} personal override{} on {} ({})",
            install_ui::bold(&removed.to_string()),
            if removed == 1 { "" } else { "s" },
            THIS_MACHINE,
            scope,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clear_question_names_a_few_keys_and_counts_many() {
        let few = [
            ("default".to_owned(), "OTHER".to_owned()),
            ("default".to_owned(), "API_URL".to_owned()),
            ("staging".to_owned(), "API_URL".to_owned()),
        ];
        assert_eq!(
            removal_summary(&few),
            "default: API_URL, OTHER; staging: API_URL"
        );
        let many: Vec<(String, String)> = (0..NAMED_IN_QUESTION)
            .map(|index| ("default".to_owned(), format!("KEY_{index}")))
            .chain([("staging".to_owned(), "API_URL".to_owned())])
            .collect();
        assert_eq!(removal_summary(&many), "default: 8, staging: 1");
    }
}
