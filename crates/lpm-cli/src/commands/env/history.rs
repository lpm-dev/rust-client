//! `lpm env history` and `lpm env rollback`: local history on this Mac, and
//! the notice every command that writes values gives when a change wasn't
//! added to it.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Local, TimeZone as _, Utc};
use lpm_common::LpmError;
use lpm_vault::history::{
    Action, Choices, ChosenValue, EntryInfo, EnvironmentInfo, EnvironmentKindInfo, Filter,
    HistoryError, HistoryState, KeyKindInfo, KeyMatch, KeysInfo, Outcome, Place, PlaceGroup,
    Platform, Point, RelatedSide, RemoteInfo, RemoteName, RemovalReview, RevealedEntry,
    RollbackKind, RollbackPlan, RollbackRequest, Row, SideInfo, SourceGroup, TargetValue, Timeline,
    TimelineRow, UnknownReason,
};

use super::arguments::HistoryAction;
use crate::{install_ui, output};

const REMOVAL_WARNING: &str = "LPM Vault and the LPM CLI can't read it any more. Copies in Time Machine, APFS snapshots or other backups of this Mac can remain. Current values don't change.";
const OFF_WARNING: &str = "LPM deletes this project's history on this Mac and stops recording changes. Values stay as they are. Deleting means LPM Vault and the LPM CLI can't read the history any more. Copies in Time Machine, APFS snapshots or other backups of this Mac can remain. Turning history back on starts an empty history.";
const ROLLBACK_FOOTER: &str =
    "The rollback is saved as a new change in this project's history. Nothing is pushed.";

/// Report what history did after a command wrote values: a line on stderr
/// when the change wasn't recorded, and once per command when the Mac holds
/// so much LPM data that history keeps less. Returns the `history` field
/// the command's JSON gains, if any.
pub(super) fn report_write() -> Option<serde_json::Value> {
    let mut field = None;
    let mut crowded_warned = false;
    for recorded in lpm_vault::history::take_outcomes() {
        match recorded.outcome {
            Outcome::NotRecorded(reason) => {
                eprintln!("lpm: this change wasn't added to local history: {reason}");
                field = Some(serde_json::json!({
                    "recorded": false,
                    "reason": reason.code(),
                    "message": reason.to_string(),
                }));
            }
            Outcome::Recorded {
                crowded: Some(records),
                ..
            } if !crowded_warned => {
                crowded_warned = true;
                eprintln!(
                    "lpm: this Mac holds a lot of LPM data ({records} records), so LPM keeps less local history for each project."
                );
            }
            Outcome::Recorded { .. } | Outcome::Nothing | Outcome::Off => {}
        }
    }
    field
}

/// Add `history` to a command's JSON output when the change wasn't recorded.
pub(super) fn with_history_field(mut json: serde_json::Value) -> serde_json::Value {
    if let Some(field) = report_write()
        && let Some(object) = json.as_object_mut()
    {
        object.insert("history".to_owned(), field);
    }
    json
}

fn fail(error: &HistoryError, json_output: bool) -> LpmError {
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": false,
                "error": error.to_string(),
                "error_code": format!("history.{}", error.code()),
            })
        );
        LpmError::ExitCode(1)
    } else {
        LpmError::Script(error.to_string())
    }
}

/// A review was printed, but there's no terminal to confirm it on and no
/// `--yes`.
fn confirmation_required(json_output: bool, review: serde_json::Value, rerun: &str) -> LpmError {
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": false,
                "error": format!("confirm by running it again with --yes: {rerun}"),
                "error_code": "confirmation_required",
                "review": review,
            })
        );
        LpmError::ExitCode(1)
    } else {
        LpmError::Script(format!(
            "nothing was changed; confirm by running it again with --yes: {rerun}"
        ))
    }
}

/// Ask a yes-or-no question that defaults to No, or skip it with `yes`.
/// `Ok(None)` means there's no terminal to ask on.
fn confirm(question: &str, yes: bool, json_output: bool) -> Result<Option<bool>, LpmError> {
    use std::io::IsTerminal as _;
    if yes {
        return Ok(Some(true));
    }
    if json_output || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(None);
    }
    cliclack::confirm(question)
        .initial_value(false)
        .interact()
        .map(Some)
        .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))
}

fn local_time(ms: i64) -> DateTime<Local> {
    Local
        .timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(|| Local.timestamp_millis_opt(0).single().expect("the epoch"))
}

fn utc(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms)
        .single()
        .map_or_else(String::new, |time| {
            time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
}

fn day(ms: i64) -> String {
    local_time(ms).format("%b %-d, %Y").to_string()
}

fn clock(ms: i64) -> String {
    local_time(ms).format("%H:%M").to_string()
}

fn moment(ms: i64) -> String {
    local_time(ms).format("%b %-d, %H:%M").to_string()
}

fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Vercel => "Vercel",
        Platform::Coolify => "Coolify",
        Platform::Fly => "Fly.io",
        Platform::Railway => "Railway",
        Platform::GithubActions => "GitHub Actions",
    }
}

fn actor_name(info: &EntryInfo) -> &'static str {
    match info.actor {
        lpm_vault::history::Actor::App => "LPM Vault",
        lpm_vault::history::Actor::Cli => "LPM CLI",
        lpm_vault::history::Actor::Outside => "outside local history",
    }
}

/// What an entry did, as the timeline says it.
fn describe(info: &EntryInfo) -> String {
    let detail = &info.detail;
    match info.action {
        Action::Import => match (&detail.file_name, detail.pasted) {
            (Some(name), _) => format!("Imported {name}"),
            (None, true) => "Imported pasted text".to_owned(),
            (None, false) => "Imported a file".to_owned(),
        },
        Action::Restore => "Restored from a backup".to_owned(),
        Action::Pull => {
            let remote = match &detail.remote {
                Some(RemoteInfo::Org(slug)) => slug.clone(),
                Some(RemoteInfo::Personal) | None => "personal".to_owned(),
            };
            match detail.remote_version {
                Some(version) => format!("Pulled from lpm.dev ({remote}, v{version})"),
                None => format!("Pulled from lpm.dev ({remote})"),
            }
        }
        Action::PlatformPull => match detail.platform {
            Some(platform) => format!("Pulled from {}", platform_name(platform)),
            None => "Pulled from a platform".to_owned(),
        },
        Action::ProjectImport => "Added from lpm.dev".to_owned(),
        Action::Rollback => match detail.related {
            Some(related) if related.side == RelatedSide::After => {
                format!("Rolled back to {}", moment(related.time))
            }
            Some(related) => format!("Rolled back to before {}", moment(related.time)),
            None => "Rolled back".to_owned(),
        },
        Action::Undo => match detail.related {
            Some(related) => format!("Undid a change from {}", moment(related.time)),
            None => "Undid a change".to_owned(),
        },
        Action::Outside => "Changed outside local history".to_owned(),
        action => format!("{} · {}", actor_name(info), action.name()),
    }
}

fn key_names(environments: &[EnvironmentInfo]) -> Vec<String> {
    let mut names: Vec<String> = environments
        .iter()
        .flat_map(|environment| match &environment.keys {
            KeysInfo::Changes(changes) => changes.iter().map(|change| change.key.clone()).collect(),
            KeysInfo::Count(_) => Vec::new(),
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn keys_column(info_keys: &[String], count: usize) -> String {
    match info_keys.len() {
        0 if count == 0 => String::new(),
        0 => format!("{count} keys"),
        1 | 2 if info_keys.len() == count => info_keys.join(", "),
        _ => {
            let shown = &info_keys[..info_keys.len().min(2)];
            format!(
                "{count} keys: {}, +{}",
                shown.join(", "),
                count.saturating_sub(shown.len())
            )
        }
    }
}

fn side_json(side: SideInfo, value: Option<&str>) -> serde_json::Value {
    let state = match side {
        SideInfo::Absent => "absent",
        SideInfo::Kept => "kept",
        SideInfo::NotRecorded => "not_recorded",
        SideInfo::TooLarge => "too_large",
        SideInfo::Removed => "removed",
    };
    let mut object = serde_json::json!({
        "kept": side == SideInfo::Kept,
        "state": state,
    });
    if let Some(value) = value {
        object["value"] = serde_json::Value::String(value.to_owned());
    }
    object
}

fn entry_json(info: &EntryInfo, revealed: Option<&RevealedEntry>) -> serde_json::Value {
    let environments: Vec<serde_json::Value> = info
        .environments
        .iter()
        .enumerate()
        .map(|(environment_index, environment)| {
            let (change, renamed_from) = match &environment.kind {
                EnvironmentKindInfo::Unchanged => ("unchanged", None),
                EnvironmentKindInfo::Created => ("created", None),
                EnvironmentKindInfo::Removed => ("removed", None),
                EnvironmentKindInfo::RenamedFrom(from) => ("renamed", Some(from.clone())),
            };
            let mut object = serde_json::json!({
                "name": environment.name,
                "change": change,
            });
            if let Some(from) = renamed_from {
                object["renamed_from"] = serde_json::Value::String(from);
            }
            match &environment.keys {
                KeysInfo::Count(count) => object["key_count"] = serde_json::json!(count),
                KeysInfo::Changes(changes) => {
                    let keys: Vec<serde_json::Value> = changes
                        .iter()
                        .enumerate()
                        .map(|(key_index, key)| {
                            let values = revealed
                                .and_then(|revealed| revealed.values.get(environment_index))
                                .and_then(|values| values.get(key_index));
                            let (change, renamed_from) = match &key.kind {
                                KeyKindInfo::Added => ("added", None),
                                KeyKindInfo::Changed => ("changed", None),
                                KeyKindInfo::Removed => ("removed", None),
                                KeyKindInfo::RenamedFrom(from) => ("renamed", Some(from.clone())),
                            };
                            let mut object = serde_json::json!({
                                "key": key.key,
                                "change": change,
                                "before": side_json(
                                    key.before,
                                    values.and_then(|values| values.before.as_deref()).map(String::as_str),
                                ),
                                "after": side_json(
                                    key.after,
                                    values.and_then(|values| values.after.as_deref()).map(String::as_str),
                                ),
                            });
                            if let Some(from) = renamed_from {
                                object["renamed_from"] = serde_json::Value::String(from);
                            }
                            object
                        })
                        .collect();
                    object["keys"] = serde_json::Value::Array(keys);
                }
            }
            object
        })
        .collect();
    let detail = &info.detail;
    let mut object = serde_json::json!({
        "id": hex::encode(info.id),
        "short_id": hex::encode(&info.id[..4]),
        "seq": info.seq,
        "time": utc(info.time),
        "source": {
            "actor": match info.actor {
                lpm_vault::history::Actor::App => "app",
                lpm_vault::history::Actor::Cli => "cli",
                lpm_vault::history::Actor::Outside => "outside",
            },
            "action": info.action.name(),
            "group": info.source().name(),
        },
        "description": describe(info),
        "values_kept": !info.flags.values_not_kept,
        "environments": environments,
    });
    if let Some(since) = info.since {
        object["since"] = serde_json::Value::String(utc(since));
    }
    if let Some(name) = &detail.file_name {
        object["file_name"] = serde_json::Value::String(name.clone());
    }
    if let Some(remote) = &detail.remote {
        object["remote"] = match remote {
            RemoteInfo::Personal => serde_json::json!("personal"),
            RemoteInfo::Org(slug) => serde_json::json!({ "org": slug }),
        };
    }
    if let Some(version) = detail.remote_version {
        object["remote_version"] = serde_json::json!(version);
    }
    if let Some(platform) = detail.platform {
        object["platform"] = serde_json::json!(platform.name());
    }
    if let Some(related) = detail.related {
        object["related"] = serde_json::json!({
            "id": hex::encode(related.id),
            "side": match related.side {
                RelatedSide::Before => "before",
                RelatedSide::After => "after",
            },
            "time": utc(related.time),
        });
    }
    object
}

pub(super) struct ListArgs<'a> {
    pub key: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub source: Option<SourceGroup>,
    pub limit: Option<usize>,
    pub reveal: bool,
}

pub(super) fn env_history(
    action: Option<HistoryAction>,
    list: ListArgs<'_>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        None => history_list(&list, project_dir, json_output),
        Some(HistoryAction::Show { entry, reveal }) => {
            history_show(&entry, reveal, project_dir, json_output)
        }
        Some(HistoryAction::Status) => history_status(project_dir, json_output),
        Some(HistoryAction::On) => {
            lpm_vault::history::turn_on(project_dir).map_err(|error| fail(&error, json_output))?;
            if json_output {
                println!("{}", serde_json::json!({"success": true, "state": "on"}));
            } else {
                output::success("local history is on; it starts with the next change on this Mac");
            }
            Ok(())
        }
        Some(HistoryAction::Off { yes }) => history_off(yes, project_dir, json_output),
        Some(HistoryAction::Forget {
            entry,
            key,
            environment,
            before,
            only_env,
            all_keys,
            yes,
        }) => history_forget(
            &ForgetArgs {
                entry: &entry,
                key: &key,
                environment: environment.env.as_deref(),
                before,
                only_env,
                all_keys,
                yes,
            },
            project_dir,
            json_output,
        ),
    }
}

fn project_name(project_dir: &std::path::Path) -> String {
    lpm_vault::vault_id::read_project_name(project_dir)
}

fn canonical_environment(
    environment: Option<&str>,
    project_dir: &std::path::Path,
) -> Result<Option<String>, LpmError> {
    super::local::resolve_env_from_flag(environment, project_dir).map(|(resolved, _)| resolved)
}

fn history_list(
    list: &ListArgs<'_>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let environment = canonical_environment(list.environment, project_dir)?;
    let filter = Filter {
        environment: environment.as_deref(),
        key: list.key.map(KeyMatch::Exact),
        source: list.source,
        limit: list.limit,
    };
    let timeline = lpm_vault::history::timeline(project_dir, &filter)
        .map_err(|error| fail(&error, json_output))?;
    let Some(timeline) = timeline else {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "project": project_name(project_dir),
                    "state": "on",
                    "retained": 0,
                    "oldest": null,
                    "entries": [],
                    "live_gap": null,
                })
            );
        } else {
            output::info(
                "no changes recorded yet; local history starts with the next change on this Mac",
            );
        }
        return Ok(());
    };
    let revealed = if list.reveal {
        let ids: BTreeSet<[u8; 16]> = timeline
            .rows
            .iter()
            .filter_map(|row| match row {
                TimelineRow::Entry(info) => Some(info.id),
                TimelineRow::Unreadable { .. } => None,
            })
            .collect();
        lpm_vault::history::reveal(project_dir, &ids).map_err(|error| fail(&error, json_output))?
    } else {
        Vec::new()
    };
    let revealed_for = |id: &[u8; 16]| revealed.iter().find(|entry| entry.info.id == *id);
    if json_output {
        print_timeline_json(&timeline, project_dir, &revealed_for);
        return Ok(());
    }
    print_timeline(&timeline, project_dir, list.reveal, &revealed_for);
    Ok(())
}

fn print_timeline_json<'a>(
    timeline: &Timeline,
    project_dir: &std::path::Path,
    revealed_for: &dyn Fn(&[u8; 16]) -> Option<&'a RevealedEntry>,
) {
    let entries: Vec<serde_json::Value> = timeline
        .rows
        .iter()
        .map(|row| match row {
            TimelineRow::Entry(info) => entry_json(info, revealed_for(&info.id)),
            TimelineRow::Unreadable { after, before, .. } => serde_json::json!({
                "unreadable": true,
                "after": after.map(utc),
                "before": before.map(utc),
            }),
        })
        .collect();
    let counts: serde_json::Map<String, serde_json::Value> = timeline
        .counts
        .iter()
        .map(|(group, count)| (group.name().to_owned(), serde_json::json!(count)))
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "project": project_name(project_dir),
            "state": if timeline.damaged_tail { "damaged" } else { "on" },
            "retained": timeline.readable,
            "oldest": timeline.oldest.map(utc),
            "counts": counts,
            "unreadable_parts": timeline.unreadable_parts,
            "entries": entries,
            "live_gap": timeline.live_gap.as_ref().map(|gap| serde_json::json!({
                "since": gap.since.map(utc),
                "keys": key_names(&gap.environments),
                "environments": gap.environments.iter().map(|environment| environment.name.clone()).collect::<Vec<_>>(),
            })),
        })
    );
}

fn print_timeline<'a>(
    timeline: &Timeline,
    project_dir: &std::path::Path,
    reveal: bool,
    revealed_for: &dyn Fn(&[u8; 16]) -> Option<&'a RevealedEntry>,
) {
    println!(
        "Local history for {} on this Mac.{}",
        install_ui::bold(&project_name(project_dir)),
        if reveal {
            ""
        } else {
            " Values are hidden; add --reveal to show them."
        }
    );
    if let Some(gap) = &timeline.live_gap {
        println!();
        output::warn_line(install_ui::terminal_line!(
            "changed outside local history{}: {}",
            gap.since
                .map(|since| format!(" since {}", moment(since)))
                .unwrap_or_default(),
            key_names(&gap.environments).join(", ")
        ));
    }
    let mut current_day = None;
    for row in &timeline.rows {
        match row {
            TimelineRow::Entry(info) => {
                let this_day = day(info.time);
                if current_day.as_ref() != Some(&this_day) {
                    println!();
                    println!("{this_day}");
                    current_day = Some(this_day);
                }
                let environments: Vec<&str> = info
                    .environments
                    .iter()
                    .map(|environment| environment.name.as_str())
                    .collect();
                let mut line = format!(
                    "  {}  {}  {:<34}  {:<20}  {}",
                    clock(info.time),
                    hex::encode(&info.id[..4]),
                    describe(info),
                    environments.join(", "),
                    keys_column(&key_names(&info.environments), info.key_count()),
                );
                if let (Some(since), Action::Outside) = (info.since, info.action) {
                    line.push_str(&format!("   ({} to {})", clock(since), clock(info.time)));
                }
                println!("{line}");
                if let Some(revealed) = revealed_for(&info.id) {
                    print_values(info, revealed);
                }
            }
            TimelineRow::Unreadable { after, before, .. } => {
                println!();
                output::warn_line(install_ui::terminal_line!(
                    "part of this project's history couldn't be read{}",
                    match (after, before) {
                        (Some(after), Some(before)) =>
                            format!(" · {} to {}", moment(*after), moment(*before)),
                        _ => String::new(),
                    }
                ));
                current_day = None;
            }
        }
    }
    println!();
    let mut summary = format!("{} changes", timeline.readable);
    summary.push_str(if timeline.unreadable_parts > 0 {
        " readable"
    } else {
        " kept"
    });
    if let Some(oldest) = timeline.oldest {
        summary.push_str(&format!(" since {}", day(oldest)));
    }
    println!("{summary}.");
}

fn print_values(info: &EntryInfo, revealed: &RevealedEntry) {
    for (environment, values) in info.environments.iter().zip(&revealed.values) {
        let KeysInfo::Changes(changes) = &environment.keys else {
            continue;
        };
        for (change, values) in changes.iter().zip(values) {
            let show = |side: SideInfo, value: Option<&str>| match (side, value) {
                (_, Some(value)) => value.to_owned(),
                (SideInfo::Absent, None) => "(not set)".to_owned(),
                (SideInfo::NotRecorded, None) => "(not recorded)".to_owned(),
                (SideInfo::TooLarge, None) => "(too large to keep)".to_owned(),
                (SideInfo::Removed, None) => "(removed from history)".to_owned(),
                (SideInfo::Kept, None) => "(hidden)".to_owned(),
            };
            println!(
                "          {} {}: {} → {}",
                install_ui::dim(&environment.name),
                change.key,
                show(change.before, values.before.as_deref().map(String::as_str)),
                show(change.after, values.after.as_deref().map(String::as_str)),
            );
        }
    }
}

fn find_entry(
    project_dir: &std::path::Path,
    prefix: &str,
    json_output: bool,
) -> Result<(Timeline, [u8; 16]), LpmError> {
    let timeline = lpm_vault::history::timeline(project_dir, &Filter::default())
        .map_err(|error| fail(&error, json_output))?
        .ok_or_else(|| fail(&HistoryError::EntryNotFound, json_output))?;
    let id = lpm_vault::history::resolve_entry(&timeline, prefix)
        .map_err(|error| fail(&error, json_output))?;
    Ok((timeline, id))
}

fn entry_info(timeline: &Timeline, id: &[u8; 16]) -> Option<EntryInfo> {
    timeline.rows.iter().find_map(|row| match row {
        TimelineRow::Entry(info) if info.id == *id => Some(info.clone()),
        _ => None,
    })
}

fn history_show(
    prefix: &str,
    reveal: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (timeline, id) = find_entry(project_dir, prefix, json_output)?;
    let info = entry_info(&timeline, &id)
        .ok_or_else(|| fail(&HistoryError::EntryNotFound, json_output))?;
    let revealed = if reveal {
        lpm_vault::history::reveal(project_dir, &BTreeSet::from([id]))
            .map_err(|error| fail(&error, json_output))?
            .into_iter()
            .next()
    } else {
        None
    };
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "entry": entry_json(&info, revealed.as_ref()),
            })
        );
        return Ok(());
    }
    println!(
        "{}  {}  {}",
        install_ui::bold(&hex::encode(info.id)),
        local_time(info.time).format("%b %-d, %Y at %H:%M:%S"),
        describe(&info)
    );
    for environment in &info.environments {
        let heading = match &environment.kind {
            EnvironmentKindInfo::Unchanged => environment.name.clone(),
            EnvironmentKindInfo::Created => format!("{} (created)", environment.name),
            EnvironmentKindInfo::Removed => format!("{} (removed)", environment.name),
            EnvironmentKindInfo::RenamedFrom(from) => {
                format!("{} (renamed from {from})", environment.name)
            }
        };
        println!("  {heading}");
        match &environment.keys {
            KeysInfo::Count(count) => println!("    {count} keys changed; too large to keep"),
            KeysInfo::Changes(changes) => {
                for change in changes {
                    let mark = match &change.kind {
                        KeyKindInfo::Added => "+".to_owned(),
                        KeyKindInfo::Changed => "~".to_owned(),
                        KeyKindInfo::Removed => "-".to_owned(),
                        KeyKindInfo::RenamedFrom(from) => format!("~ (renamed from {from})"),
                    };
                    println!("    {mark} {}", change.key);
                }
            }
        }
    }
    if let Some(revealed) = &revealed {
        print_values(&info, revealed);
    } else {
        println!("Values are hidden; add --reveal to show them.");
    }
    Ok(())
}

fn history_status(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let status =
        lpm_vault::history::status(project_dir).map_err(|error| fail(&error, json_output))?;
    let state = match status.state {
        HistoryState::On => "on",
        HistoryState::Off => "off",
        HistoryState::Unsupported => "paused",
        HistoryState::Damaged => "paused",
    };
    if json_output {
        let mut object = serde_json::json!({
            "success": true,
            "project": project_name(project_dir),
            "state": state,
            "retained": status.retained,
            "oldest": status.oldest.map(utc),
            "unreadable_parts": status.unreadable_parts,
        });
        match status.state {
            HistoryState::Unsupported => object["reason"] = serde_json::json!("newer_version"),
            HistoryState::Damaged => object["reason"] = serde_json::json!("damaged"),
            HistoryState::On | HistoryState::Off => {}
        }
        println!("{object}");
        return Ok(());
    }
    let name = project_name(project_dir);
    match status.state {
        HistoryState::Off => output::info(&format!("local history is off for {name}")),
        HistoryState::Unsupported => output::warn(&format!(
            "local history is paused for {name}: a newer LPM keeps it; update the LPM CLI: lpm self-update"
        )),
        HistoryState::Damaged => output::warn(&format!(
            "local history is paused for {name}: it's damaged; repair it with lpm env repair"
        )),
        HistoryState::On if status.retained == 0 => output::success(&format!(
            "local history is on for {name}; it starts with the next change on this Mac"
        )),
        HistoryState::On => {
            let mut line = format!(
                "local history is on for {name}: {} changes {}",
                status.retained,
                if status.unreadable_parts > 0 {
                    "readable"
                } else {
                    "kept"
                }
            );
            if let Some(oldest) = status.oldest {
                line.push_str(&format!(" since {}", day(oldest)));
            }
            output::success(&line);
            if status.unreadable_parts > 0 {
                output::warn("part of this project's history couldn't be read");
            }
        }
    }
    Ok(())
}

fn history_off(
    yes: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let name = project_name(project_dir);
    if !json_output {
        output::warn(&format!("Turn off local history for {name}?"));
        println!("    {OFF_WARNING}");
    }
    match confirm("Turn off local history and delete it?", yes, json_output)? {
        None => {
            return Err(confirmation_required(
                json_output,
                serde_json::json!({ "action": "off", "message": OFF_WARNING }),
                "lpm env history off --yes",
            ));
        }
        Some(false) => {
            output::info("nothing was changed");
            return Ok(());
        }
        Some(true) => {}
    }
    lpm_vault::history::turn_off(project_dir).map_err(|error| fail(&error, json_output))?;
    if json_output {
        println!("{}", serde_json::json!({"success": true, "state": "off"}));
    } else {
        output::success(&format!(
            "local history is off for {name}, and its history is deleted"
        ));
    }
    Ok(())
}

struct ForgetArgs<'a> {
    entry: &'a str,
    key: &'a str,
    environment: Option<&'a str>,
    before: bool,
    only_env: bool,
    all_keys: bool,
    yes: bool,
}

/// The environment of `info` a command acts on: the one `--env` names, or
/// the entry's only one.
fn entry_environment(
    info: &EntryInfo,
    environment: Option<&str>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<String, LpmError> {
    if let Some(environment) = canonical_environment(environment, project_dir)? {
        return Ok(environment);
    }
    match info.environments.as_slice() {
        [only] => Ok(only.name.clone()),
        _ => Err(fail(
            &HistoryError::Storage(
                "that entry touched several environments; choose one with --env".to_owned(),
            ),
            json_output,
        )),
    }
}

fn occurrences(place: &Place) -> String {
    place
        .occurrences
        .iter()
        .map(|occurrence| match (occurrence.set, occurrence.replaced) {
            (Some(set), Some(replaced)) => {
                format!("set {}, replaced {}", moment(set), moment(replaced))
            }
            (Some(set), None) => format!("set {}", moment(set)),
            (None, Some(replaced)) => format!("replaced {}", moment(replaced)),
            (None, None) => String::new(),
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn forget_selection(
    review: &RemovalReview,
    environment: &str,
    args: &ForgetArgs<'_>,
) -> BTreeSet<usize> {
    review
        .places
        .iter()
        .enumerate()
        .filter(|(_, place)| !place.current)
        .filter(|(_, place)| match place.group {
            PlaceGroup::ThisKey => !args.only_env || place.environment == environment,
            PlaceGroup::OtherKey => args.all_keys,
        })
        .map(|(index, _)| index)
        .collect()
}

fn history_forget(
    args: &ForgetArgs<'_>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let (timeline, id) = find_entry(project_dir, args.entry, json_output)?;
    let info = entry_info(&timeline, &id)
        .ok_or_else(|| fail(&HistoryError::EntryNotFound, json_output))?;
    let environment = entry_environment(&info, args.environment, project_dir, json_output)?;
    let chosen = ChosenValue {
        entry: id,
        environment: environment.clone(),
        key: args.key.to_owned(),
        side: if args.before {
            RelatedSide::Before
        } else {
            RelatedSide::After
        },
    };
    let review = lpm_vault::history::review_forget(project_dir, &chosen)
        .map_err(|error| fail(&error, json_output))?;
    let selection = forget_selection(&review, &environment, args);
    let places_json: Vec<serde_json::Value> = review
        .places
        .iter()
        .enumerate()
        .map(|(index, place)| {
            serde_json::json!({
                "environment": place.environment,
                "key": place.key,
                "renamed_from": place.renamed_from,
                "group": match place.group {
                    PlaceGroup::ThisKey => "this_key",
                    PlaceGroup::OtherKey => "other_key",
                },
                "current": place.current,
                "removed": selection.contains(&index),
            })
        })
        .collect();
    if !json_output {
        println!(
            "Remove {}'s value {} {} from local history:",
            install_ui::bold(args.key),
            if args.before { "before" } else { "after" },
            moment(info.time)
        );
        for (index, place) in review.places.iter().enumerate() {
            let verdict = if selection.contains(&index) {
                install_ui::red("removes")
            } else {
                install_ui::dim("keeps  ")
            };
            let mut line = format!("  {verdict}  {} in {}", place.key, place.environment);
            if !place.renamed_from.is_empty() {
                line.push_str(&format!(
                    " (renamed from {})",
                    place.renamed_from.join(", ")
                ));
            }
            let occurrences = occurrences(place);
            if !occurrences.is_empty() {
                line.push_str(&format!(": {occurrences}"));
            }
            if place.current {
                line.push_str(" — still its current value; change it first");
            } else if place.group == PlaceGroup::OtherKey && !selection.contains(&index) {
                line.push_str(" — another key with the same value; add --all-keys to remove it");
            }
            println!("{line}");
        }
        println!("{REMOVAL_WARNING}");
    }
    if selection.is_empty() {
        return Err(fail(&HistoryError::ValueIsCurrent, json_output));
    }
    match confirm(
        "Remove this value from local history?",
        args.yes,
        json_output,
    )? {
        None => {
            return Err(confirmation_required(
                json_output,
                serde_json::json!({ "action": "forget", "places": places_json }),
                "lpm env history forget ENTRY KEY --yes",
            ));
        }
        Some(false) => {
            output::info("nothing was changed");
            return Ok(());
        }
        Some(true) => {}
    }
    lpm_vault::history::forget(project_dir, &review, &selection)
        .map_err(|error| fail(&error, json_output))?;
    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "places": places_json})
        );
    } else {
        output::success(&format!(
            "removed the value from {} {}",
            selection.len(),
            if selection.len() == 1 {
                "place"
            } else {
                "places"
            }
        ));
    }
    Ok(())
}

pub(super) struct RollbackArgs<'a> {
    pub to: Option<&'a str>,
    pub before: Option<&'a str>,
    pub undo: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub keys: &'a [String],
    pub yes: bool,
}

fn row_change(row: &Row) -> (&'static str, Option<&'static str>) {
    match (&row.target, &row.current) {
        (TargetValue::Unknown(reason), _) => (
            "unknown",
            Some(match reason {
                UnknownReason::NotRecorded => {
                    "Its earlier value wasn't recorded: it changed outside local history."
                }
                UnknownReason::TooLarge => "Too large to keep.",
                UnknownReason::Removed => "Removed from history.",
                UnknownReason::Unreadable => "Part of history couldn't be read.",
            }),
        ),
        (TargetValue::Known(_), Some(_)) => ("changed", None),
        (TargetValue::Known(_), None) => ("added", None),
        (TargetValue::Absent, _) => ("removed", None),
    }
}

fn pulled_notice(key: &str, pulled: &lpm_vault::history::Pulled) -> String {
    let source = match pulled.version {
        Some(version) => format!("pulled {}, v{version}", moment(pulled.time)),
        None => format!("pulled {}", moment(pulled.time)),
    };
    let reach = match pulled.remote {
        Some(RemoteName::Org(_)) => "replaces that value for everyone on the team",
        Some(RemoteName::Personal) | None => {
            "replaces that value on lpm.dev and on your other Macs when they pull"
        }
    };
    format!(
        "{key}'s current value came from lpm.dev ({source}). If you push this rollback, it {reach}, and the value it replaces then stays only in this Mac's history. Until you push, pulling again brings lpm.dev's value back."
    )
}

fn rollback_json(plan: &RollbackPlan, choices: &Choices) -> serde_json::Value {
    let environments: Vec<serde_json::Value> = plan
        .environments
        .iter()
        .enumerate()
        .map(|(environment_index, environment)| {
            let rows: Vec<serde_json::Value> = environment
                .rows
                .iter()
                .enumerate()
                .map(|(row_index, row)| {
                    let (change, reason) = row_change(row);
                    serde_json::json!({
                        "key": row.key,
                        "change": change,
                        "reason": reason,
                        "applied": row.changes() && !choices.skipped.contains(&(environment_index, row_index)),
                        "gaps": row.gaps.iter().map(|gap| serde_json::json!({
                            "since": gap.since.map(utc),
                            "until": gap.until.map(utc),
                        })).collect::<Vec<_>>(),
                        "pulled": row.pulled.as_ref().map(|pulled| serde_json::json!({
                            "remote": match &pulled.remote {
                                Some(RemoteName::Org(slug)) => serde_json::json!({ "org": slug }),
                                Some(RemoteName::Personal) | None => serde_json::json!("personal"),
                            },
                            "version": pulled.version,
                            "time": utc(pulled.time),
                        })),
                        "changed_again": row.changed_again.as_ref().map(|changed| utc(changed.time)),
                    })
                })
                .collect();
            serde_json::json!({
                "current": environment.current,
                "target": environment.target,
                "recreates": environment.recreates(),
                "deletes_when_empty": environment.offers_deletion(),
                "rows": rows,
            })
        })
        .collect();
    serde_json::json!({
        "kind": match plan.kind {
            RollbackKind::Environment => "environment",
            RollbackKind::Key => "key",
            RollbackKind::Undo => "undo",
        },
        "point": {
            "entry": hex::encode(plan.point.entry),
            "side": match plan.point.side {
                RelatedSide::Before => "before",
                RelatedSide::After => "after",
            },
            "time": utc(plan.point_time),
        },
        "environments": environments,
    })
}

fn print_rollback(plan: &RollbackPlan, choices: &Choices, title: &str) {
    println!("{title}");
    let mut changing = 0;
    let mut total = 0;
    for (environment_index, environment) in plan.environments.iter().enumerate() {
        if plan.environments.len() > 1 {
            println!(
                "  {}",
                install_ui::bold(
                    environment
                        .current
                        .as_deref()
                        .or(environment.target.as_deref())
                        .unwrap_or("")
                )
            );
        }
        if environment.recreates() {
            println!(
                "    {}",
                install_ui::dim(&format!(
                    "{} was deleted. Rolling back recreates it.",
                    environment.target.as_deref().unwrap_or("")
                ))
            );
        }
        if environment.offers_deletion() {
            println!(
                "    {}",
                install_ui::dim(&format!(
                    "{} didn't exist at that point; it's deleted once it's empty.",
                    environment.current.as_deref().unwrap_or("")
                ))
            );
        }
        for (row_index, row) in environment.rows.iter().enumerate() {
            total += 1;
            let skipped = choices.skipped.contains(&(environment_index, row_index));
            let (change, reason) = row_change(row);
            let mark = match change {
                "changed" => "~",
                "added" => "+",
                "removed" => "-",
                _ => "?",
            };
            if row.changes() && !skipped {
                changing += 1;
            }
            let mut line = format!("    {mark} {}", row.key);
            if skipped {
                line.push_str("  (kept)");
            }
            if let Some(reason) = reason {
                line.push_str(&format!("  ({reason})"));
            }
            println!("{line}");
            for gap in &row.gaps {
                let window = match (gap.since, gap.until) {
                    (Some(since), Some(until)) => {
                        format!(" between {} and {}", moment(since), clock(until))
                    }
                    (Some(since), None) => format!(" since {}", moment(since)),
                    _ => String::new(),
                };
                println!(
                    "        {}",
                    install_ui::dim(&format!(
                        "This also replaces a change made outside local history{window}."
                    ))
                );
            }
            if let Some(changed) = &row.changed_again {
                println!(
                    "        {}",
                    install_ui::dim(&format!(
                        "Changed again on {}. Undoing this replaces that change too.",
                        moment(changed.time)
                    ))
                );
            }
            if let Some(pulled) = &row.pulled
                && row.changes()
            {
                println!(
                    "        {}",
                    install_ui::dim(&pulled_notice(&row.key, pulled))
                );
            }
        }
    }
    println!("{changing} of {total} keys change. {ROLLBACK_FOOTER}");
}

pub(super) fn env_rollback(
    args: &RollbackArgs<'_>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let prefix = args.to.or(args.before).or(args.undo).unwrap_or_default();
    let (timeline, id) = find_entry(project_dir, prefix, json_output)?;
    let info = entry_info(&timeline, &id)
        .ok_or_else(|| fail(&HistoryError::EntryNotFound, json_output))?;
    let (request, title) = if args.undo.is_some() {
        (
            RollbackRequest::Undo { entry: id },
            format!("Undo \"{}\" from {}:", describe(&info), moment(info.time)),
        )
    } else {
        let environment = entry_environment(&info, args.environment, project_dir, json_output)?;
        let side = if args.to.is_some() {
            RelatedSide::After
        } else {
            RelatedSide::Before
        };
        match (side, args.keys) {
            (RelatedSide::Before, [key]) => (
                RollbackRequest::Key {
                    environment: environment.clone(),
                    key: key.clone(),
                    entry: id,
                },
                format!(
                    "Roll back {key} in {environment} to its value before {}:",
                    moment(info.time)
                ),
            ),
            _ => (
                RollbackRequest::Environment {
                    environment: environment.clone(),
                    point: Point { entry: id, side },
                },
                format!(
                    "Roll back {environment} to {}{}:",
                    if side == RelatedSide::Before {
                        "before "
                    } else {
                        ""
                    },
                    moment(info.time)
                ),
            ),
        }
    };
    let mut plan = lpm_vault::history::review_rollback(project_dir, &request)
        .map_err(|error| fail(&error, json_output))?;
    if args.undo.is_some()
        && let Some(environment) = canonical_environment(args.environment, project_dir)?
    {
        plan.environments.retain(|candidate| {
            candidate.current.as_deref() == Some(environment.as_str())
                || candidate.target.as_deref() == Some(environment.as_str())
        });
    }
    let wanted: HashSet<&str> = args.keys.iter().map(String::as_str).collect();
    let mut choices = Choices::default();
    if !wanted.is_empty() {
        for (environment_index, environment) in plan.environments.iter().enumerate() {
            for (row_index, row) in environment.rows.iter().enumerate() {
                if !wanted.contains(row.key.as_str()) {
                    choices.skipped.insert((environment_index, row_index));
                }
            }
        }
    }
    let changing = plan
        .environments
        .iter()
        .enumerate()
        .flat_map(|(environment_index, environment)| {
            environment
                .rows
                .iter()
                .enumerate()
                .map(move |(row_index, row)| (environment_index, row_index, row))
        })
        .filter(|(environment_index, row_index, row)| {
            row.changes() && !choices.skipped.contains(&(*environment_index, *row_index))
        })
        .count();
    let deletes = plan
        .environments
        .iter()
        .any(|environment| environment.offers_deletion());
    if !json_output {
        print_rollback(&plan, &choices, &title);
    }
    if changing == 0 && !deletes {
        return Err(fail(&HistoryError::TargetUnknown, json_output));
    }
    match confirm("Roll back these values?", args.yes, json_output)? {
        None => {
            return Err(confirmation_required(
                json_output,
                rollback_json(&plan, &choices),
                "lpm env rollback ... --yes",
            ));
        }
        Some(false) => {
            output::info("nothing was changed");
            return Ok(());
        }
        Some(true) => {}
    }
    let written = lpm_vault::history::commit_rollback(project_dir, &plan, &choices)
        .map_err(|error| fail(&error, json_output))?;
    if json_output {
        let json = with_history_field(serde_json::json!({
            "success": true,
            "rolled_back": written,
            "rollback": rollback_json(&plan, &choices),
        }));
        println!("{json}");
    } else {
        report_write();
        output::success(&format!(
            "rolled back {} ({} {}); nothing was pushed",
            written.join(", "),
            changing,
            if changing == 1 { "key" } else { "keys" }
        ));
    }
    Ok(())
}
