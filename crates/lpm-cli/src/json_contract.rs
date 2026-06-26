pub(crate) const ERROR_ENVELOPE_SCHEMA_VERSION: u32 = 1;
pub(crate) const INSTALL_JSON_SCHEMA_VERSION: u32 = 1;

pub(crate) fn command_next_step(description: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "command": command,
    })
}

pub(crate) fn command_next_steps(description: &str, command: &str) -> serde_json::Value {
    serde_json::Value::Array(vec![command_next_step(description, command)])
}
