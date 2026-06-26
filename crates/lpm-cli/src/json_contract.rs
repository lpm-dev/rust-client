pub(crate) const ERROR_ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub(crate) const INSTALL_JSON_SCHEMA_VERSION: u32 = 2;

pub(crate) fn command_next_step(description: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "command": command,
    })
}

pub(crate) fn command_next_steps(description: &str, command: &str) -> serde_json::Value {
    serde_json::Value::Array(vec![command_next_step(description, command)])
}

pub(crate) fn install_timing_requested(cli_timing: bool) -> bool {
    cli_timing || env_flag_truthy("LPM_TIMING") || std::env::var_os("LPM_TIMING_DETAIL").is_some()
}

fn env_flag_truthy(key: &str) -> bool {
    std::env::var(key).is_ok_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty()
            && trimmed != "0"
            && !trimmed.eq_ignore_ascii_case("false")
            && !trimmed.eq_ignore_ascii_case("off")
    })
}
