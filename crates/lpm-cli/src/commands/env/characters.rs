//! Warnings about values that hold characters that are hard to see: which
//! key, which characters and where, never the value. They never change a
//! value or a command's exit status.

use super::prelude::*;

/// One value's warning for `--json`.
pub(super) fn json(key: &str, found: &lpm_env::ValueCharacters) -> serde_json::Value {
    let characters: Vec<serde_json::Value> = found
        .characters
        .iter()
        .map(|character| {
            let runs: Vec<serde_json::Value> = character
                .runs
                .iter()
                .map(|run| serde_json::json!({"position": run.position, "count": run.count}))
                .collect();
            serde_json::json!({
                "kind": character.kind.code(),
                "code_point": character.character.code_point(),
                "escape": character.character.escape(),
                "name": character.character.name(),
                "group": character.character.group(),
                "count": character.count,
                "runs": runs,
            })
        })
        .collect();
    serde_json::json!({
        "key": key,
        "characters": characters,
        "more": found.more,
    })
}

/// Each warning for `--json`, in order.
pub(super) fn json_list(warnings: &[(String, lpm_env::ValueCharacters)]) -> Vec<serde_json::Value> {
    warnings
        .iter()
        .map(|(key, found)| json(key, found))
        .collect()
}

/// The lines that describe one value's characters, each indented under a heading.
pub(super) fn lines(found: &lpm_env::ValueCharacters) -> Vec<String> {
    let mut lines: Vec<String> = found
        .characters
        .iter()
        .map(lpm_env::FoundCharacter::describe)
        .collect();
    if found.more > 0 {
        lines.push(format!(
            "and {} more kind{} of character",
            found.more,
            if found.more == 1 { "" } else { "s" }
        ));
    }
    lines
}

/// Warns on stderr that a value just stored holds characters that are hard
/// to see, one line per character.
pub(super) fn warn_stored(key: &str, found: &lpm_env::ValueCharacters) {
    output::warn_line(install_ui::terminal_line!(
        "{} has characters that are hard to see; it was stored as given",
        install_ui::bold(key),
    ));
    for line in lines(found) {
        install_ui::detail_line(install_ui::terminal_line!("    {}", line));
    }
}
