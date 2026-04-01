use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;

/// CLI configuration management.
///
/// Stores config in ~/.lpm/config.toml (user/machine config).
/// Project config lives in package.json under "lpm" key.
pub async fn run(
    action: &str,
    key: Option<&str>,
    value: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config_path = dirs::home_dir()
        .ok_or_else(|| LpmError::Registry("could not determine home dir".into()))?
        .join(".lpm")
        .join("config.toml");

    match action {
        "get" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let config = read_config(&config_path)?;
            if let Some(val) = config.get(key).and_then(|v| v.as_str()) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "success": true, key: val })
                        )
                        .unwrap()
                    );
                } else {
                    println!("{val}");
                }
            } else if !json_output {
                output::info(&format!("{key} is not set"));
            }
        }
        "set" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let value = value.ok_or_else(|| LpmError::Registry("missing value".into()))?;
            let mut config = read_config(&config_path)?;
            if let Some(table) = config.as_table_mut() {
                table.insert(key.to_string(), toml::Value::String(value.to_string()));
            }
            write_config(&config_path, &config)?;
            if !json_output {
                output::success(&format!("Set {} = {}", key.bold(), value));
            }
        }
        "delete" | "unset" => {
            let key = key.ok_or_else(|| LpmError::Registry("missing key".into()))?;
            let mut config = read_config(&config_path)?;
            if let Some(table) = config.as_table_mut() {
                table.remove(key);
            }
            write_config(&config_path, &config)?;
            if !json_output {
                output::success(&format!("Deleted {}", key.bold()));
            }
        }
        "list" | "ls" => {
            let config = read_config(&config_path)?;
            if json_output {
                let mut json = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("success".to_string(), serde_json::Value::Bool(true));
                }
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                if let Some(table) = config.as_table() {
                    if table.is_empty() {
                        output::info("No configuration set");
                    } else {
                        for (k, v) in table {
                            output::field(k, &v.to_string());
                        }
                    }
                }
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown config action: {action}. Use: get, set, delete, list"
            )));
        }
    }

    Ok(())
}

fn read_config(path: &std::path::Path) -> Result<toml::Value, LpmError> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::map::Map::new()));
    }
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|e| LpmError::Registry(format!("config parse error: {e}")))
}

fn write_config(path: &std::path::Path, config: &toml::Value) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)
        .map_err(|e| LpmError::Registry(format!("config serialize error: {e}")))?;
    std::fs::write(path, content)?;
    Ok(())
}
