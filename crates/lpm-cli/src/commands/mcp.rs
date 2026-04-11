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

fn remove_from_editors(
    editors: &[EditorConfig],
    name: &str,
) -> Result<Vec<&'static str>, LpmError> {
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

        let claude_config: Value =
            serde_json::from_str(&std::fs::read_to_string(&claude_path).unwrap()).unwrap();
        assert_eq!(claude_config["theme"], "dark");
        assert!(claude_config["mcpServers"].get("existing").is_some());
        assert!(claude_config["mcpServers"].get("lpm-registry").is_some());

        let vscode_config: Value =
            serde_json::from_str(&std::fs::read_to_string(&vscode_path).unwrap()).unwrap();
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

    // ── Phase 32 Phase 0.1 gap-filling additions ────────────────────────

    #[test]
    fn setup_editors_creates_parent_directories_for_nested_config_path() {
        // Some editors store config under nested paths that may not exist yet
        // (e.g., ~/.cursor/mcp.json on a fresh install). The writer must
        // create the parent tree, not error.
        let dir = tempfile::tempdir().unwrap();
        let nested_path = dir
            .path()
            .join("never")
            .join("created")
            .join("yet")
            .join("config.json");
        let editors = vec![test_editor("Cursor", nested_path.clone(), "mcpServers")];

        let configured = setup_editors(&editors, "lpm-registry", &default_server_config())
            .expect("nested-path config must be created");

        assert_eq!(configured, vec!["Cursor"]);
        assert!(nested_path.exists(), "config file should now exist");
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&nested_path).unwrap()).unwrap();
        assert!(written["mcpServers"].get("lpm-registry").is_some());
    }

    #[test]
    fn add_server_to_config_overwrites_existing_entry_with_same_name() {
        // Re-running setup must update an existing entry in place rather than
        // duplicating or refusing. This is the expected idempotent behavior.
        let mut config = serde_json::json!({
            "mcpServers": {
                "lpm-registry": {
                    "command": "old-binary",
                    "args": []
                }
            }
        });
        let new_config = serde_json::json!({
            "command": "npx",
            "args": ["-y", "@lpm.dev/lpm-mcp-server"]
        });

        add_server_to_config(&mut config, "mcpServers", "lpm-registry", &new_config).unwrap();

        assert_eq!(config["mcpServers"]["lpm-registry"]["command"], "npx");
        assert_eq!(
            config["mcpServers"]["lpm-registry"]["args"],
            serde_json::json!(["-y", "@lpm.dev/lpm-mcp-server"])
        );
    }

    #[test]
    fn ensure_server_map_errors_when_root_is_not_an_object() {
        let mut config = serde_json::json!(["not", "an", "object"]);

        let error = ensure_server_map(&mut config, "mcpServers").unwrap_err();
        assert!(
            error.to_string().contains("must be a JSON object"),
            "expected root-type error, got: {error}"
        );
    }

    #[test]
    fn ensure_server_map_errors_when_server_key_has_wrong_type() {
        // If a user (or another tool) wrote `mcpServers` as an array, we
        // must hard-error rather than silently overwrite.
        let mut config = serde_json::json!({
            "mcpServers": ["not", "an", "object"]
        });

        let error = ensure_server_map(&mut config, "mcpServers").unwrap_err();
        assert!(
            error.to_string().contains("must be a JSON object"),
            "expected wrong-type error, got: {error}"
        );
    }

    #[test]
    fn read_server_map_errors_when_server_key_has_wrong_type() {
        let config = serde_json::json!({
            "servers": "not an object either"
        });

        let error = read_server_map(&config, "servers").unwrap_err();
        assert!(error.to_string().contains("must be a JSON object"));
    }

    #[test]
    fn read_server_map_returns_none_when_key_is_absent() {
        let config = serde_json::json!({});

        let result = read_server_map(&config, "mcpServers").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_servers_returns_empty_when_server_key_is_absent() {
        let config = serde_json::json!({});

        let names = list_servers(&config, "mcpServers").unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn list_servers_returns_all_keys_in_order_independent_set() {
        let config = serde_json::json!({
            "mcpServers": {
                "alpha": {},
                "beta": {},
                "gamma": {}
            }
        });

        let names = list_servers(&config, "mcpServers").unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert!(names.contains(&"gamma".to_string()));
    }

    #[test]
    fn remove_from_editors_returns_empty_when_server_is_not_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "other": { "command": "node" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let original = std::fs::read_to_string(&path).unwrap();

        let editors = vec![test_editor("Claude", path.clone(), "mcpServers")];
        let removed = remove_from_editors(&editors, "absent").unwrap();

        assert!(removed.is_empty());
        // No write should have happened — file stays byte-identical.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn remove_from_editors_skips_editors_with_no_existing_config_file() {
        // If an editor's config file doesn't exist on disk, removal should
        // skip it cleanly (no error, no created file).
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");

        let editors = vec![test_editor("Cursor", missing.clone(), "mcpServers")];
        let removed = remove_from_editors(&editors, "lpm-registry").unwrap();

        assert!(removed.is_empty());
        assert!(
            !missing.exists(),
            "remove must not create config files for absent editors"
        );
    }

    #[test]
    fn setup_editors_skips_editors_with_no_global_path() {
        let editors = vec![EditorConfig {
            name: "Phantom",
            global_path: None,
            server_key: "mcpServers",
        }];

        let configured = setup_editors(&editors, "lpm-registry", &default_server_config()).unwrap();

        assert!(configured.is_empty());
    }

    #[test]
    fn status_for_editors_reports_zero_servers_when_config_is_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "{}").unwrap();

        let editors = vec![test_editor("Empty", path.clone(), "mcpServers")];
        let status = status_for_editors(&editors).unwrap();

        assert_eq!(status.len(), 1);
        assert!(status[0]["config_exists"].as_bool().unwrap());
        assert_eq!(status[0]["servers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn status_for_editors_propagates_malformed_config_errors() {
        // Per the existing setup test, malformed configs are a hard error.
        // status() should also surface that — not silently report zero servers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.json");
        std::fs::write(&path, "{not valid json").unwrap();

        let editors = vec![test_editor("Broken", path.clone(), "mcpServers")];
        let result = status_for_editors(&editors);

        assert!(
            result.is_err(),
            "status must hard-error on malformed config, never silently report empty"
        );
    }

    #[test]
    fn default_server_config_uses_npx_invocation() {
        // Cheap canary: if anyone changes the default server invocation,
        // they must update this test deliberately.
        let cfg = default_server_config();
        assert_eq!(cfg["command"], "npx");
        let args = cfg["args"].as_array().unwrap();
        assert_eq!(args[0], "-y");
        assert_eq!(args[1], "@lpm.dev/lpm-mcp-server");
    }

    #[test]
    fn write_config_round_trips_through_load_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.json");
        let config = serde_json::json!({
            "mcpServers": {
                "lpm-registry": {
                    "command": "npx",
                    "args": ["-y", "@lpm.dev/lpm-mcp-server"]
                }
            }
        });

        write_config(&path, &config).unwrap();
        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded, config);
    }

    #[test]
    fn load_config_returns_empty_object_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");

        let config = load_config(&path).unwrap();
        assert!(config.is_object());
        assert_eq!(config.as_object().unwrap().len(), 0);
    }
}
