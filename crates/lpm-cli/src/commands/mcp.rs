use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use serde_json::{Map, Value};
use std::path::PathBuf;

/// MCP server management: setup, remove, status.
pub async fn run(
    action: &str,
    server_name: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "setup" => setup(server_name, json_output).await,
        "remove" => {
            let name = server_name.ok_or_else(|| {
                LpmError::Registry("specify server name: lpm mcp remove <name>".into())
            })?;
            remove(name, json_output).await
        }
        "status" => status(json_output).await,
        _ => Err(LpmError::Registry(format!(
            "unknown mcp action: {action}. Use: setup, remove, status"
        ))),
    }
}

/// Editor MCP config locations.
#[derive(Clone, Debug)]
struct EditorConfig {
    name: &'static str,
    global_path: Option<PathBuf>,
    server_key: &'static str,
}

fn get_editors() -> Vec<EditorConfig> {
    let home = dirs::home_dir().unwrap_or_default();

    #[allow(unused_mut)] // Mutated on macOS via cfg-gated .push() calls below
    let mut editors = vec![
        EditorConfig {
            name: "Claude Code",
            global_path: Some(home.join(".claude.json")),
            server_key: "mcpServers",
        },
        EditorConfig {
            name: "Cursor",
            global_path: Some(home.join(".cursor").join("mcp.json")),
            server_key: "mcpServers",
        },
        EditorConfig {
            name: "Windsurf",
            global_path: Some(
                home.join(".codeium")
                    .join("windsurf")
                    .join("mcp_config.json"),
            ),
            server_key: "mcpServers",
        },
    ];

    // Platform-specific editors
    #[cfg(target_os = "macos")]
    {
        editors.push(EditorConfig {
            name: "VS Code",
            global_path: Some(
                home.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("mcp.json"),
            ),
            server_key: "servers",
        });
        editors.push(EditorConfig {
            name: "Claude Desktop",
            global_path: Some(
                home.join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"),
            ),
            server_key: "mcpServers",
        });
    }

    #[cfg(target_os = "linux")]
    {
        editors.push(EditorConfig {
            name: "VS Code",
            global_path: Some(
                home.join(".config")
                    .join("Code")
                    .join("User")
                    .join("mcp.json"),
            ),
            server_key: "servers",
        });
    }

    editors
}

fn default_server_config() -> Value {
    serde_json::json!({
        "command": "npx",
        "args": ["-y", "@lpm.dev/lpm-mcp-server"],
    })
}

fn load_config(path: &PathBuf) -> Result<Value, LpmError> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }

    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content).map_err(|error| {
        LpmError::Registry(format!(
            "failed to parse MCP config at {}: {error}",
            path.display()
        ))
    })
}

fn write_config(path: &PathBuf, config: &Value) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content =
        serde_json::to_string_pretty(config).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(path, format!("{content}\n"))?;
    Ok(())
}

fn ensure_server_map<'a>(
    config: &'a mut Value,
    server_key: &str,
) -> Result<&'a mut Map<String, Value>, LpmError> {
    if !config.is_object() {
        return Err(LpmError::Registry(
            "MCP config root must be a JSON object".to_string(),
        ));
    }

    if config.get(server_key).is_none() {
        config[server_key] = serde_json::json!({});
    }

    config[server_key].as_object_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "MCP config key \"{server_key}\" must be a JSON object"
        ))
    })
}

fn read_server_map<'a>(
    config: &'a Value,
    server_key: &str,
) -> Result<Option<&'a Map<String, Value>>, LpmError> {
    match config.get(server_key) {
        Some(value) => value.as_object().map(Some).ok_or_else(|| {
            LpmError::Registry(format!(
                "MCP config key \"{server_key}\" must be a JSON object"
            ))
        }),
        None => Ok(None),
    }
}

fn add_server_to_config(
    config: &mut Value,
    server_key: &str,
    name: &str,
    server_config: &Value,
) -> Result<(), LpmError> {
    ensure_server_map(config, server_key)?.insert(name.to_string(), server_config.clone());
    Ok(())
}

fn remove_server_from_config(
    config: &mut Value,
    server_key: &str,
    name: &str,
) -> Result<bool, LpmError> {
    Ok(ensure_server_map(config, server_key)?
        .remove(name)
        .is_some())
}

fn list_servers(config: &Value, server_key: &str) -> Result<Vec<String>, LpmError> {
    Ok(read_server_map(config, server_key)?
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default())
}

fn setup_editors(
    editors: &[EditorConfig],
    name: &str,
    server_config: &Value,
) -> Result<Vec<&'static str>, LpmError> {
    let mut configured = Vec::new();

    for editor in editors {
        let path = match &editor.global_path {
            Some(path) => path,
            None => continue,
        };

        let mut config = load_config(path)?;
        add_server_to_config(&mut config, editor.server_key, name, server_config)?;
        write_config(path, &config)?;
        configured.push(editor.name);
    }

    Ok(configured)
}

fn remove_from_editors(editors: &[EditorConfig], name: &str) -> Result<Vec<&'static str>, LpmError> {
    let mut removed_from = Vec::new();

    for editor in editors {
        let path = match &editor.global_path {
            Some(path) if path.exists() => path,
            _ => continue,
        };

        let mut config = load_config(path)?;
        if remove_server_from_config(&mut config, editor.server_key, name)? {
            write_config(path, &config)?;
            removed_from.push(editor.name);
        }
    }

    Ok(removed_from)
}

fn status_for_editors(editors: &[EditorConfig]) -> Result<Vec<Value>, LpmError> {
    let mut results = Vec::new();

    for editor in editors {
        let path = match &editor.global_path {
            Some(path) => path,
            None => continue,
        };

        let servers = if path.exists() {
            let config = load_config(path)?;
            list_servers(&config, editor.server_key)?
        } else {
            vec![]
        };

        results.push(serde_json::json!({
            "editor": editor.name,
            "config_exists": path.exists(),
            "servers": servers,
        }));
    }

    Ok(results)
}

async fn setup(server_name: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let name = server_name.unwrap_or("lpm-registry");
    let editors = get_editors();
    let configured = setup_editors(&editors, name, &default_server_config())?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "server": name,
                "configured": configured,
            }))
            .unwrap()
        );
    } else if configured.is_empty() {
        output::warn("No supported editors detected");
    } else {
        output::success(&format!(
            "MCP server \"{}\" configured in {} editor(s)",
            name.bold(),
            configured.len()
        ));
        for editor in &configured {
            println!("  {}", editor.dimmed());
        }
        println!();
    }

    Ok(())
}

async fn remove(name: &str, json_output: bool) -> Result<(), LpmError> {
    let editors = get_editors();
    let removed_from = remove_from_editors(&editors, name)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "server": name,
                "removed_from": removed_from,
            }))
            .unwrap()
        );
    } else if removed_from.is_empty() {
        output::info(&format!("Server \"{name}\" not found in any editor config"));
    } else {
        output::success(&format!(
            "Removed \"{}\" from {} editor(s)",
            name.bold(),
            removed_from.len()
        ));
        for editor in &removed_from {
            println!("  {}", editor.dimmed());
        }
        println!();
    }

    Ok(())
}

async fn status(json_output: bool) -> Result<(), LpmError> {
    let editors = get_editors();
    let results = status_for_editors(&editors)?;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "editors": results,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!();
        for r in &results {
            let editor = r["editor"].as_str().unwrap_or("");
            let servers = r["servers"].as_array().map(|a| a.len()).unwrap_or(0);
            let icon = if servers > 0 {
                "✔".green().to_string()
            } else {
                "·".dimmed().to_string()
            };
            print!("  {icon} {} ", editor.bold());
            if servers > 0 {
                let names: Vec<&str> = r["servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                println!("{}", names.join(", ").dimmed());
            } else {
                println!("{}", "no servers".dimmed());
            }
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_editor(name: &'static str, path: PathBuf, server_key: &'static str) -> EditorConfig {
        EditorConfig {
            name,
            global_path: Some(path),
            server_key,
        }
    }

    #[test]
    fn setup_editors_creates_missing_config_and_preserves_existing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let claude_path = dir.path().join("claude.json");
        let vscode_path = dir.path().join("vscode.json");

        std::fs::write(
            &claude_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "theme": "dark",
                "mcpServers": {
                    "existing": {
                        "command": "node",
                        "args": ["server.js"]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let editors = vec![
            test_editor("Claude", claude_path.clone(), "mcpServers"),
            test_editor("VS Code", vscode_path.clone(), "servers"),
        ];

        let configured = setup_editors(&editors, "lpm-registry", &default_server_config()).unwrap();

        assert_eq!(configured, vec!["Claude", "VS Code"]);

        let claude_config: Value = serde_json::from_str(&std::fs::read_to_string(&claude_path).unwrap()).unwrap();
        assert_eq!(claude_config["theme"], "dark");
        assert!(claude_config["mcpServers"].get("existing").is_some());
        assert!(claude_config["mcpServers"].get("lpm-registry").is_some());

        let vscode_config: Value = serde_json::from_str(&std::fs::read_to_string(&vscode_path).unwrap()).unwrap();
        assert!(vscode_config["servers"].get("lpm-registry").is_some());
    }

    #[test]
    fn remove_from_editors_deletes_only_requested_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "keep": {
                        "command": "node"
                    },
                    "drop": {
                        "command": "npx"
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let editors = vec![test_editor("Claude", path.clone(), "mcpServers")];
        let removed = remove_from_editors(&editors, "drop").unwrap();

        assert_eq!(removed, vec!["Claude"]);

        let config: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(config["mcpServers"].get("drop").is_none());
        assert!(config["mcpServers"].get("keep").is_some());
    }

    #[test]
    fn status_for_editors_reports_server_lists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsurf.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "alpha": {},
                    "beta": {}
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let editors = vec![
            test_editor("Windsurf", path.clone(), "mcpServers"),
            test_editor("VS Code", dir.path().join("missing.json"), "servers"),
        ];

        let status = status_for_editors(&editors).unwrap();

        assert_eq!(status.len(), 2);
        assert_eq!(status[0]["editor"], "Windsurf");
        assert_eq!(status[0]["servers"].as_array().unwrap().len(), 2);
        assert_eq!(status[1]["editor"], "VS Code");
        assert!(!status[1]["config_exists"].as_bool().unwrap());
    }

    #[test]
    fn setup_editors_fails_on_malformed_existing_config_without_overwriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(&path, "{not json").unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let editors = vec![test_editor("Claude", path.clone(), "mcpServers")];

        let error = setup_editors(&editors, "lpm-registry", &default_server_config()).unwrap_err();

        assert!(
            error.to_string().contains("failed to parse MCP config"),
            "unexpected error: {error}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
}
