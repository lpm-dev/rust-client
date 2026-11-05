//! `lpm env history` and `lpm env rollback`: local history on this Mac, and
//! the notice every command that writes values gives when a change wasn't
//! added to it.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Local, TimeZone as _, Utc};
use lpm_common::LpmError;
use lpm_vault::history::{
    Action, Choices, ChosenSide, EntryInfo, EnvironmentInfo, EnvironmentKindInfo, EnvironmentName,
    EnvironmentPlan, Filter, HistoryError, HistoryState, KeyKindInfo, KeyMatch, KeysInfo, Outcome,
    Paused, Place, PlaceGroup, Platform, RelatedSide, RemoteInfo, RemoteName, RemovalReview,
    RevealedValues, RollbackKind, RollbackPlan, Row, SideInfo, SourceGroup, Target, TargetValue,
    Timeline, TimelineRow, UnknownReason,
};
use serde::Serialize;

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
fn confirmation_required(json_output: bool, review: &impl Serialize, rerun: &str) -> LpmError {
    if json_output {
        #[derive(Serialize)]
        struct Required<'a, R> {
            success: bool,
            error: String,
            error_code: &'static str,
            review: &'a R,
        }
        print_json(&Required {
            success: false,
            error: format!("confirm by running it again with --yes: {rerun}"),
            error_code: "confirmation_required",
            review,
        });
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

fn key_names(environments: &[EnvironmentInfo]) -> Vec<&str> {
    let mut names: Vec<&str> = environments
        .iter()
        .flat_map(|environment| match &environment.keys {
            KeysInfo::Changes(changes) => changes.as_slice(),
            KeysInfo::Count(_) => &[],
        })
        .map(|change| change.key.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn keys_column(info_keys: &[&str], count: usize) -> String {
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

/// Print `value` as one line of JSON, written straight to stdout.
fn print_json(value: &impl Serialize) {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    if serde_json::to_writer(&mut out, value).is_ok() {
        let _ = writeln!(out);
    }
    let _ = out.flush();
}

#[derive(Serialize)]
struct SideJson<'a> {
    kept: bool,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
}

fn side_json(side: SideInfo, value: Option<&str>) -> SideJson<'_> {
    SideJson {
        kept: side == SideInfo::Kept,
        state: match side {
            SideInfo::Absent => "absent",
            SideInfo::Kept => "kept",
            SideInfo::NotRecorded => "not_recorded",
            SideInfo::TooLarge => "too_large",
            SideInfo::Removed => "removed",
        },
        value,
    }
}

#[derive(Serialize)]
struct KeyJson<'a> {
    key: &'a str,
    change: &'static str,
    before: SideJson<'a>,
    after: SideJson<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    renamed_from: Option<&'a str>,
}

#[derive(Serialize)]
struct EnvironmentJson<'a> {
    name: &'a str,
    change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    renamed_from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyJson<'a>>>,
}

#[derive(Serialize)]
struct SourceJson {
    actor: &'static str,
    action: &'static str,
    group: &'static str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum RemoteJson<'a> {
    Personal(&'static str),
    Org { org: &'a str },
}

#[derive(Serialize)]
struct RelatedJson {
    id: String,
    side: &'static str,
    time: String,
}

#[derive(Serialize)]
struct EntryJson<'a> {
    id: String,
    short_id: String,
    seq: u64,
    time: String,
    source: SourceJson,
    description: String,
    values_kept: bool,
    environments: Vec<EnvironmentJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<RemoteJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    related: Option<RelatedJson>,
}

fn side_name(side: RelatedSide) -> &'static str {
    match side {
        RelatedSide::Before => "before",
        RelatedSide::After => "after",
    }
}

fn entry_json<'a>(
    info: &'a EntryInfo,
    revealed: Option<&'a [Vec<RevealedValues>]>,
) -> EntryJson<'a> {
    let environments = info
        .environments
        .iter()
        .enumerate()
        .map(|(environment_index, environment)| {
            let (change, renamed_from) = match &environment.kind {
                EnvironmentKindInfo::Unchanged => ("unchanged", None),
                EnvironmentKindInfo::Created => ("created", None),
                EnvironmentKindInfo::Removed => ("removed", None),
                EnvironmentKindInfo::RenamedFrom(from) => ("renamed", Some(from.as_str())),
            };
            let (key_count, keys) = match &environment.keys {
                KeysInfo::Count(count) => (Some(*count), None),
                KeysInfo::Changes(changes) => (
                    None,
                    Some(
                        changes
                            .iter()
                            .enumerate()
                            .map(|(key_index, key)| {
                                let values = revealed
                                    .and_then(|revealed| revealed.get(environment_index))
                                    .and_then(|values| values.get(key_index));
                                let (change, renamed_from) = match &key.kind {
                                    KeyKindInfo::Added => ("added", None),
                                    KeyKindInfo::Changed => ("changed", None),
                                    KeyKindInfo::Removed => ("removed", None),
                                    KeyKindInfo::RenamedFrom(from) => {
                                        ("renamed", Some(from.as_str()))
                                    }
                                };
                                KeyJson {
                                    key: &key.key,
                                    change,
                                    before: side_json(
                                        key.before,
                                        values
                                            .and_then(|values| values.before.as_deref())
                                            .map(String::as_str),
                                    ),
                                    after: side_json(
                                        key.after,
                                        values
                                            .and_then(|values| values.after.as_deref())
                                            .map(String::as_str),
                                    ),
                                    renamed_from,
                                }
                            })
                            .collect(),
                    ),
                ),
            };
            EnvironmentJson {
                name: &environment.name,
                change,
                renamed_from,
                key_count,
                keys,
            }
        })
        .collect();
    let detail = &info.detail;
    EntryJson {
        id: hex::encode(info.id),
        short_id: hex::encode(&info.id[..4]),
        seq: info.seq,
        time: utc(info.time),
        source: SourceJson {
            actor: match info.actor {
                lpm_vault::history::Actor::App => "app",
                lpm_vault::history::Actor::Cli => "cli",
                lpm_vault::history::Actor::Outside => "outside",
            },
            action: info.action.name(),
            group: info.source().name(),
        },
        description: describe(info),
        values_kept: !info.flags.values_not_kept,
        environments,
        since: info.since.map(utc),
        file_name: detail.file_name.as_deref(),
        remote: detail.remote.as_ref().map(|remote| match remote {
            RemoteInfo::Personal => RemoteJson::Personal("personal"),
            RemoteInfo::Org(slug) => RemoteJson::Org { org: slug },
        }),
        remote_version: detail.remote_version,
        platform: detail.platform.map(Platform::name),
        related: detail.related.map(|related| RelatedJson {
            id: hex::encode(related.id),
            side: side_name(related.side),
            time: utc(related.time),
        }),
    }
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
    let timeline = lpm_vault::history::timeline(project_dir, &filter, list.reveal)
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
    if json_output {
        print_timeline_json(&timeline, project_dir);
        return Ok(());
    }
    print_timeline(&timeline, project_dir, list.reveal);
    Ok(())
}

// Unreadable rows are rare, and boxing every entry would cost an allocation
// per row of every listing.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize)]
#[serde(untagged)]
enum RowJson<'a> {
    Entry(EntryJson<'a>),
    Unreadable {
        unreadable: bool,
        after: Option<String>,
        before: Option<String>,
    },
}

#[derive(Serialize)]
struct LiveGapJson<'a> {
    since: Option<String>,
    keys: Vec<&'a str>,
    environments: Vec<&'a str>,
}

#[derive(Serialize)]
struct TimelineJson<'a> {
    success: bool,
    project: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    retained: usize,
    oldest: Option<String>,
    counts: serde_json::Map<String, serde_json::Value>,
    unreadable_parts: usize,
    entries: Vec<RowJson<'a>>,
    live_gap: Option<LiveGapJson<'a>>,
}

fn print_timeline_json(timeline: &Timeline, project_dir: &std::path::Path) {
    let entries = timeline
        .rows
        .iter()
        .map(|row| match row {
            TimelineRow::Entry(info) => RowJson::Entry(entry_json(
                info,
                timeline.values.get(&info.id).map(Vec::as_slice),
            )),
            TimelineRow::Unreadable { after, before, .. } => RowJson::Unreadable {
                unreadable: true,
                after: after.map(utc),
                before: before.map(utc),
            },
        })
        .collect();
    let (state, reason) = if timeline.damaged_tail {
        ("paused", Some(Paused::Damaged.code()))
    } else {
        ("on", None)
    };
    print_json(&TimelineJson {
        success: true,
        project: project_name(project_dir),
        state,
        reason,
        retained: timeline.readable,
        oldest: timeline.oldest.map(utc),
        counts: timeline
            .counts
            .iter()
            .map(|(group, count)| (group.name().to_owned(), serde_json::json!(count)))
            .collect(),
        unreadable_parts: timeline.unreadable_parts,
        entries,
        live_gap: timeline.live_gap.as_ref().map(|gap| LiveGapJson {
            since: gap.since.map(utc),
            keys: key_names(&gap.environments),
            environments: gap
                .environments
                .iter()
                .map(|environment| environment.name.as_str())
                .collect(),
        }),
    });
}

fn print_timeline(timeline: &Timeline, project_dir: &std::path::Path, reveal: bool) {
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
                if let Some(values) = timeline.values.get(&info.id) {
                    print_values(info, values);
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

fn print_values(info: &EntryInfo, revealed: &[Vec<RevealedValues>]) {
    for (environment, values) in info.environments.iter().zip(revealed) {
        let KeysInfo::Changes(changes) = &environment.keys else {
            continue;
        };
        for (change, values) in changes.iter().zip(values) {
            fn show(side: SideInfo, value: Option<&str>) -> &str {
                match (side, value) {
                    (_, Some(value)) => value,
                    (SideInfo::Absent, None) => "(not set)",
                    (SideInfo::NotRecorded, None) => "(not recorded)",
                    (SideInfo::TooLarge, None) => "(too large to keep)",
                    (SideInfo::Removed, None) => "(removed from history)",
                    (SideInfo::Kept, None) => "(hidden)",
                }
            }
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

fn history_show(
    prefix: &str,
    reveal: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let shown = lpm_vault::history::show(project_dir, prefix, reveal)
        .map_err(|error| fail(&error, json_output))?;
    let info = &shown.info;
    if json_output {
        #[derive(Serialize)]
        struct ShowJson<'a> {
            success: bool,
            entry: EntryJson<'a>,
        }
        print_json(&ShowJson {
            success: true,
            entry: entry_json(
                info,
                shown
                    .revealed
                    .as_ref()
                    .map(|revealed| revealed.values.as_slice()),
            ),
        });
        return Ok(());
    }
    println!(
        "{}  {}  {}",
        install_ui::bold(&hex::encode(info.id)),
        local_time(info.time).format("%b %-d, %Y at %H:%M:%S"),
        describe(info)
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
    if let Some(revealed) = &shown.revealed {
        print_values(info, &revealed.values);
    } else {
        println!("Values are hidden; add --reveal to show them.");
    }
    Ok(())
}

fn history_status(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let status =
        lpm_vault::history::status(project_dir).map_err(|error| fail(&error, json_output))?;
    let paused = match &status.state {
        HistoryState::Paused(reason) => Some(reason),
        HistoryState::On | HistoryState::Off => None,
    };
    if json_output {
        let mut object = serde_json::json!({
            "success": true,
            "project": project_name(project_dir),
            "state": match status.state {
                HistoryState::On => "on",
                HistoryState::Off => "off",
                HistoryState::Paused(_) => "paused",
            },
            "retained": status.retained,
            "oldest": status.oldest.map(utc),
            "unreadable_parts": status.unreadable_parts,
        });
        if let Some(reason) = paused {
            object["reason"] = serde_json::json!(reason.code());
            if let Paused::Unavailable(message) = reason {
                object["message"] = serde_json::json!(message);
            }
        }
        println!("{object}");
        return Ok(());
    }
    let name = project_name(project_dir);
    match &status.state {
        HistoryState::Off => output::info(&format!("local history is off for {name}")),
        HistoryState::Paused(Paused::NewerVersion) => output::warn(&format!(
            "local history is paused for {name}: a newer LPM keeps it; update the LPM CLI: lpm self-update"
        )),
        HistoryState::Paused(Paused::Damaged) => output::warn(&format!(
            "local history is paused for {name}: it's damaged; repair it with lpm env repair"
        )),
        HistoryState::Paused(Paused::Limit) => output::warn(&format!(
            "local history is paused for {name}: this Mac holds too much LPM data to keep history for it"
        )),
        HistoryState::Paused(Paused::TooManyValues) => output::warn(&format!(
            "local history is paused for {name}: it has too many values to keep history"
        )),
        HistoryState::Paused(Paused::Unavailable(message)) => output::warn(&format!(
            "local history for {name} can't be read right now: the Keychain is locked or unavailable ({message})"
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
                &serde_json::json!({ "action": "off", "message": OFF_WARNING }),
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

/// The environment of `info` a removal starts from, as the entry names it:
/// the one `--env` names, under the name the entry has for it or the one it
/// had before the entry renamed it, or the entry's only one.
fn forget_environment(
    info: &EntryInfo,
    environment: Option<&str>,
    canonical: Option<&str>,
) -> Result<String, HistoryError> {
    match environment {
        Some(typed) => info
            .environments
            .iter()
            .find(|environment| {
                [Some(typed), canonical].into_iter().flatten().any(|wanted| {
                    environment.name == wanted
                        || matches!(&environment.kind, EnvironmentKindInfo::RenamedFrom(from) if from == wanted)
                })
            })
            .map(|environment| environment.name.clone())
            .ok_or(HistoryError::UnknownEnvironment),
        None => match info.environments.as_slice() {
            [only] => Ok(only.name.clone()),
            _ => Err(HistoryError::EnvironmentRequired),
        },
    }
}

/// The environment a rollback to `side` of `info` acts on: the one `--env`
/// names as it's named now, or the entry's only one as it was named at that
/// point.
fn rollback_environment(
    info: &EntryInfo,
    environment: Option<&str>,
    side: RelatedSide,
) -> Result<EnvironmentName, HistoryError> {
    if let Some(environment) = environment {
        return Ok(EnvironmentName::Now(environment.to_owned()));
    }
    let [only] = info.environments.as_slice() else {
        return Err(HistoryError::EnvironmentRequired);
    };
    Ok(EnvironmentName::AtPoint(match (&only.kind, side) {
        (EnvironmentKindInfo::RenamedFrom(from), RelatedSide::Before) => from.clone(),
        _ => only.name.clone(),
    }))
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
            PlaceGroup::ThisKey => {
                !args.only_env
                    || place.environment == environment
                    || place
                        .renamed_environments
                        .iter()
                        .any(|name| name == environment)
            }
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
    let canonical = canonical_environment(args.environment, project_dir)?;
    let mut environment = String::new();
    let (info, review) = lpm_vault::history::review_forget(project_dir, args.entry, |info| {
        environment = forget_environment(info, args.environment, canonical.as_deref())?;
        Ok(ChosenSide {
            environment: environment.clone(),
            key: args.key.to_owned(),
            side: if args.before {
                RelatedSide::Before
            } else {
                RelatedSide::After
            },
        })
    })
    .map_err(|error| fail(&error, json_output))?;
    let selection = forget_selection(&review, &environment, args);
    #[derive(Serialize)]
    struct PlaceJson<'a> {
        environment: &'a str,
        key: &'a str,
        renamed_from: &'a [String],
        group: &'static str,
        current: bool,
        removed: bool,
    }
    #[derive(Serialize)]
    struct PlacesJson<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        action: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        success: Option<bool>,
        places: Vec<PlaceJson<'a>>,
    }
    let places_json = |action: Option<&'static str>, success: Option<bool>| PlacesJson {
        action,
        success,
        places: review
            .places
            .iter()
            .enumerate()
            .map(|(index, place)| PlaceJson {
                environment: &place.environment,
                key: &place.key,
                renamed_from: &place.renamed_from,
                group: match place.group {
                    PlaceGroup::ThisKey => "this_key",
                    PlaceGroup::OtherKey => "other_key",
                },
                current: place.current,
                removed: selection.contains(&index),
            })
            .collect(),
    };
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
                &places_json(Some("forget"), None),
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
        print_json(&places_json(None, Some(true)));
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

#[derive(Serialize)]
struct GapJson {
    since: Option<String>,
    until: Option<String>,
}

#[derive(Serialize)]
struct PulledJson<'a> {
    remote: RemoteJson<'a>,
    version: Option<u64>,
    time: String,
}

#[derive(Serialize)]
struct RowJson2<'a> {
    key: &'a str,
    change: &'static str,
    reason: Option<&'static str>,
    applied: bool,
    gaps: Vec<GapJson>,
    pulled: Option<PulledJson<'a>>,
    changed_again: Option<String>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    linked: &'a [String],
}

#[derive(Serialize)]
struct EnvironmentPlanJson<'a> {
    current: Option<&'a str>,
    target: Option<&'a str>,
    recreates: bool,
    renames: bool,
    deletes_when_empty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unnamed_keys: Option<&'static str>,
    rows: Vec<RowJson2<'a>>,
}

#[derive(Serialize)]
struct PointJson {
    entry: String,
    side: &'static str,
    time: String,
}

#[derive(Serialize)]
struct RollbackJson<'a> {
    kind: &'static str,
    point: PointJson,
    environments: Vec<EnvironmentPlanJson<'a>>,
}

fn unknown_reason(reason: UnknownReason) -> &'static str {
    match reason {
        UnknownReason::NotRecorded => "not_recorded",
        UnknownReason::TooLarge => "too_large",
        UnknownReason::Removed => "removed",
        UnknownReason::Unreadable => "unreadable",
    }
}

/// The keys of an environment's rows that are switched off.
fn skipped_keys<'a>(
    environment: &'a EnvironmentPlan,
    environment_index: usize,
    choices: &Choices,
) -> HashSet<&'a str> {
    environment
        .rows
        .iter()
        .enumerate()
        .filter(|(row_index, _)| choices.skipped.contains(&(environment_index, *row_index)))
        .map(|(_, row)| row.key.as_str())
        .collect()
}

/// Whether a row applies: it changes a value, and neither it nor a row it's
/// linked to is switched off.
fn applies(row: &Row, skipped: &HashSet<&str>) -> bool {
    row.changes()
        && !skipped.contains(row.key.as_str())
        && !row.linked.iter().any(|key| skipped.contains(key.as_str()))
}

fn rollback_json<'a>(plan: &'a RollbackPlan, choices: &Choices) -> RollbackJson<'a> {
    RollbackJson {
        kind: match plan.kind {
            RollbackKind::Environment => "environment",
            RollbackKind::Key => "key",
            RollbackKind::Undo => "undo",
        },
        point: PointJson {
            entry: hex::encode(plan.point.entry),
            side: side_name(plan.point.side),
            time: utc(plan.point_time),
        },
        environments: plan
            .environments
            .iter()
            .enumerate()
            .map(|(environment_index, environment)| {
                (
                    environment,
                    skipped_keys(environment, environment_index, choices),
                )
            })
            .map(|(environment, skipped)| EnvironmentPlanJson {
                current: environment.current.as_deref(),
                target: environment.target.as_deref(),
                recreates: environment.recreates(),
                renames: environment.renames(),
                deletes_when_empty: environment.offers_deletion(),
                unnamed_keys: environment.unnamed_keys.map(unknown_reason),
                rows: environment
                    .rows
                    .iter()
                    .map(|row| {
                        let (change, reason) = row_change(row);
                        RowJson2 {
                            key: &row.key,
                            change,
                            reason,
                            applied: applies(row, &skipped),
                            gaps: row
                                .gaps
                                .iter()
                                .map(|gap| GapJson {
                                    since: gap.since.map(utc),
                                    until: gap.until.map(utc),
                                })
                                .collect(),
                            pulled: row.pulled.as_ref().map(|pulled| PulledJson {
                                remote: match &pulled.remote {
                                    Some(RemoteName::Org(slug)) => RemoteJson::Org { org: slug },
                                    Some(RemoteName::Personal) | None => {
                                        RemoteJson::Personal("personal")
                                    }
                                },
                                version: pulled.version,
                                time: utc(pulled.time),
                            }),
                            changed_again: row
                                .changed_again
                                .as_ref()
                                .map(|changed| utc(changed.time)),
                            linked: &row.linked,
                        }
                    })
                    .collect(),
            })
            .collect(),
    }
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
        let note = |text: String| println!("    {}", install_ui::dim(&text));
        let skipped_rows = skipped_keys(environment, environment_index, choices);
        if environment.recreates() {
            note(format!(
                "{} was deleted. Rolling back recreates it.",
                environment.target.as_deref().unwrap_or("")
            ));
        }
        if environment.renames() {
            note(format!(
                "{} was named {} then. Rolling back renames it back.",
                environment.current.as_deref().unwrap_or(""),
                environment.target.as_deref().unwrap_or("")
            ));
        }
        if environment.offers_deletion() {
            note(format!(
                "{} didn't exist at that point; it's deleted once it's empty.",
                environment.current.as_deref().unwrap_or("")
            ));
        }
        if environment.unnamed_keys.is_some() {
            note(
                "Some keys it had then can't be named: the change that removed them was too large to keep. They stay as they are."
                    .to_owned(),
            );
        }
        for (row_index, row) in environment.rows.iter().enumerate() {
            total += 1;
            let skipped = choices.skipped.contains(&(environment_index, row_index));
            let applied = applies(row, &skipped_rows);
            let (change, reason) = row_change(row);
            let mark = match change {
                "changed" => "~",
                "added" => "+",
                "removed" => "-",
                _ => "?",
            };
            if applied {
                changing += 1;
            }
            let mut line = format!("    {mark} {}", row.key);
            if !row.linked.is_empty() {
                line.push_str(&format!("  (renamed, with {})", row.linked.join(", ")));
            }
            if row.changes() && !applied {
                line.push_str(if skipped {
                    "  (kept)"
                } else {
                    "  (kept with its rename)"
                });
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

/// The rows a rollback leaves out when the person names keys: all but
/// those keys' rows, and the rows a renamed key's rows are linked to.
fn choices_for_keys(plan: &RollbackPlan, keys: &[String]) -> Choices {
    let mut choices = Choices::default();
    if keys.is_empty() {
        return choices;
    }
    let wanted: HashSet<&str> = keys.iter().map(String::as_str).collect();
    for (environment_index, environment) in plan.environments.iter().enumerate() {
        for (row_index, row) in environment.rows.iter().enumerate() {
            let asked = wanted.contains(row.key.as_str())
                || row.linked.iter().any(|key| wanted.contains(key.as_str()));
            if !asked {
                choices.skipped.insert((environment_index, row_index));
            }
        }
    }
    choices
}

/// How many rows applying `plan` with `choices` changes.
fn changing_rows(plan: &RollbackPlan, choices: &Choices) -> usize {
    plan.environments
        .iter()
        .enumerate()
        .map(|(environment_index, environment)| {
            let skipped = skipped_keys(environment, environment_index, choices);
            environment
                .rows
                .iter()
                .filter(|row| applies(row, &skipped))
                .count()
        })
        .sum()
}

/// Whether the rollback renames, recreates or deletes an environment, which
/// changes the project even when no value changes. One is deleted only when
/// the rows that apply empty it.
fn changes_an_environment(plan: &RollbackPlan, choices: &Choices) -> bool {
    plan.environments
        .iter()
        .enumerate()
        .any(|(environment_index, environment)| {
            environment.renames()
                || environment.recreates()
                || (environment.offers_deletion() && {
                    let skipped = skipped_keys(environment, environment_index, choices);
                    environment
                        .rows
                        .iter()
                        .filter(|row| row.current.is_some())
                        .all(|row| applies(row, &skipped))
                })
        })
}

pub(super) fn env_rollback(
    args: &RollbackArgs<'_>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let prefix = args.to.or(args.before).or(args.undo).unwrap_or_default();
    let environment = canonical_environment(args.environment, project_dir)?;
    let side = if args.to.is_some() {
        RelatedSide::After
    } else {
        RelatedSide::Before
    };
    let (info, plan) = lpm_vault::history::review_rollback(project_dir, prefix, |info| {
        if args.undo.is_some() {
            return Ok(Target::Undo {
                only: environment.clone().map(EnvironmentName::Now),
            });
        }
        let environment = rollback_environment(info, environment.as_deref(), side)?;
        Ok(match (side, args.keys) {
            (RelatedSide::Before, [key]) => Target::Key {
                environment,
                key: key.clone(),
            },
            _ => Target::Environment { environment, side },
        })
    })
    .map_err(|error| fail(&error, json_output))?;
    let target_name = plan
        .environments
        .first()
        .and_then(|environment| environment.target.clone().or(environment.current.clone()))
        .unwrap_or_default();
    let title = match plan.kind {
        RollbackKind::Undo => format!("Undo \"{}\" from {}:", describe(&info), moment(info.time)),
        RollbackKind::Key => format!(
            "Roll back {} in {target_name} to its value before {}:",
            args.keys.first().map(String::as_str).unwrap_or_default(),
            moment(info.time)
        ),
        RollbackKind::Environment => format!(
            "Roll back {target_name} to {}{}:",
            if side == RelatedSide::Before {
                "before "
            } else {
                ""
            },
            moment(info.time)
        ),
    };
    let choices = choices_for_keys(&plan, args.keys);
    let changing = changing_rows(&plan, &choices);
    if !json_output {
        print_rollback(&plan, &choices, &title);
    }
    if changing == 0 && !changes_an_environment(&plan, &choices) {
        return Err(fail(&HistoryError::TargetUnknown, json_output));
    }
    match confirm("Roll back these values?", args.yes, json_output)? {
        None => {
            return Err(confirmation_required(
                json_output,
                &rollback_json(&plan, &choices),
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
        #[derive(Serialize)]
        struct RolledBack<'a> {
            success: bool,
            rolled_back: &'a [String],
            rollback: RollbackJson<'a>,
            #[serde(skip_serializing_if = "Option::is_none")]
            history: Option<serde_json::Value>,
        }
        print_json(&RolledBack {
            success: true,
            rolled_back: &written,
            rollback: rollback_json(&plan, &choices),
            history: report_write(),
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_vault::history::{Binding, DetailInfo, Flags, Point};

    fn row(key: &str, current: Option<&str>, target: TargetValue, linked: &[&str]) -> Row {
        Row {
            key: key.to_owned(),
            current: current.map(|value| lpm_vault::history::Zeroizing::new(value.to_owned())),
            target,
            gaps: Vec::new(),
            pulled: None,
            changed_again: None,
            linked: linked.iter().map(|key| (*key).to_owned()).collect(),
        }
    }

    fn known(value: &str) -> TargetValue {
        TargetValue::Known(lpm_vault::history::Zeroizing::new(value.to_owned()))
    }

    fn plan(environments: Vec<EnvironmentPlan>) -> RollbackPlan {
        RollbackPlan {
            kind: RollbackKind::Environment,
            point: Point {
                entry: [1; 16],
                side: RelatedSide::After,
            },
            point_time: 0,
            generation: 1,
            environments,
        }
    }

    fn environment(current: &str, target: &str, rows: Vec<Row>) -> EnvironmentPlan {
        EnvironmentPlan {
            current: Some(current.to_owned()),
            target: Some(target.to_owned()),
            rows,
            binding: Binding::Environment(None),
            unnamed_keys: None,
        }
    }

    #[test]
    fn naming_a_renamed_key_keeps_both_of_its_rows() {
        let plan = plan(vec![environment(
            "e",
            "e",
            vec![
                row("NEW", Some("1"), TargetValue::Absent, &["OLD"]),
                row("OLD", None, known("1"), &["NEW"]),
                row("OTHER", Some("p"), known("o"), &[]),
            ],
        )]);
        let choices = choices_for_keys(&plan, &["NEW".to_owned()]);
        assert_eq!(choices.skipped, HashSet::from([(0, 2)]));
        assert_eq!(
            changing_rows(&plan, &choices),
            2,
            "the rename applies whole"
        );
    }

    #[test]
    fn a_rollback_that_only_renames_an_environment_changes_something() {
        let plan = plan(vec![environment("staging", "stage", Vec::new())]);
        assert_eq!(changing_rows(&plan, &Choices::default()), 0);
        assert!(changes_an_environment(&plan, &Choices::default()));
    }

    fn entry(environments: Vec<EnvironmentInfo>) -> EntryInfo {
        EntryInfo {
            seq: 1,
            id: [2; 16],
            time: 0,
            actor: lpm_vault::history::Actor::App,
            action: Action::RenameEnvironment,
            flags: Flags::default(),
            since: None,
            detail: DetailInfo::default(),
            environments,
        }
    }

    #[test]
    fn a_rollback_names_the_entry_s_environment_as_it_was_at_the_point() {
        let renamed = entry(vec![EnvironmentInfo {
            name: "staging".to_owned(),
            kind: EnvironmentKindInfo::RenamedFrom("stage".to_owned()),
            keys: KeysInfo::Changes(Vec::new()),
        }]);
        assert_eq!(
            rollback_environment(&renamed, None, RelatedSide::Before),
            Ok(EnvironmentName::AtPoint("stage".to_owned()))
        );
        assert_eq!(
            rollback_environment(&renamed, None, RelatedSide::After),
            Ok(EnvironmentName::AtPoint("staging".to_owned()))
        );
        assert_eq!(
            rollback_environment(&renamed, Some("prod"), RelatedSide::After),
            Ok(EnvironmentName::Now("prod".to_owned())),
            "--env names an environment as it is now"
        );
        let two = entry(vec![
            EnvironmentInfo {
                name: "a".to_owned(),
                kind: EnvironmentKindInfo::Unchanged,
                keys: KeysInfo::Changes(Vec::new()),
            },
            EnvironmentInfo {
                name: "b".to_owned(),
                kind: EnvironmentKindInfo::Unchanged,
                keys: KeysInfo::Changes(Vec::new()),
            },
        ]);
        assert_eq!(
            rollback_environment(&two, None, RelatedSide::After),
            Err(HistoryError::EnvironmentRequired)
        );
        assert_eq!(
            forget_environment(&renamed, Some("stage"), None),
            Ok("staging".to_owned()),
            "an entry's environment under the name it had before the entry"
        );
        assert_eq!(
            forget_environment(&two, None, None),
            Err(HistoryError::EnvironmentRequired)
        );
    }

    #[test]
    fn an_environment_a_key_filter_keeps_from_emptying_isn_t_deleted() {
        let mut leaving = environment(
            "preview",
            "preview",
            vec![
                row("A", Some("1"), TargetValue::Absent, &[]),
                row("B", Some("2"), TargetValue::Absent, &[]),
            ],
        );
        leaving.target = None;
        let plan = plan(vec![leaving]);
        assert!(changes_an_environment(&plan, &Choices::default()));
        let choices = choices_for_keys(&plan, &["A".to_owned()]);
        assert!(
            !changes_an_environment(&plan, &choices),
            "B stays, so the environment does"
        );
    }

    #[test]
    fn forget_names_the_entry_s_environment_by_its_alias() {
        let entry = entry(vec![EnvironmentInfo {
            name: "development".to_owned(),
            kind: EnvironmentKindInfo::Unchanged,
            keys: KeysInfo::Changes(Vec::new()),
        }]);
        assert_eq!(
            forget_environment(&entry, Some("dev"), Some("development")),
            Ok("development".to_owned())
        );
    }
}
