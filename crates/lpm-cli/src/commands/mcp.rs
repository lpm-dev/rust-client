use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
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
                LpmError::Registry("specify server name: lpm-rs mcp remove <name>".into())
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

async fn setup(server_name: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let name = server_name.unwrap_or("lpm-registry");

    // Default LPM registry MCP server config
    let server_config = serde_json::json!({
        "command": "npx",
        "args": ["-y", "@lpm.dev/lpm-mcp-server"],
    });

    let editors = get_editors();
    let mut configured = Vec::new();

    for editor in &editors {
        let path = match &editor.global_path {
            Some(p) => p,
            None => continue,
        };

        // Read or create config file
        let mut config: serde_json::Value = if path.exists() {
            let content = std::fs::read_to_string(path).unwrap_or_else(|_| "{}".into());
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        // Ensure the server key object exists
        if config.get(editor.server_key).is_none() {
            config[editor.server_key] = serde_json::json!({});
        }

        // Add server entry
        config[editor.server_key][name] = server_config.clone();

        // Write back
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content =
            serde_json::to_string_pretty(&config).map_err(|e| LpmError::Registry(e.to_string()))?;
        std::fs::write(path, format!("{content}\n"))?;

        configured.push(editor.name);
    }

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
    let mut removed_from = Vec::new();

    for editor in &editors {
        let path = match &editor.global_path {
            Some(p) if p.exists() => p,
            _ => continue,
        };

        let content = std::fs::read_to_string(path).unwrap_or_else(|_| "{}".into());
        let mut config: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));

        if let Some(servers) = config.get_mut(editor.server_key)
            && let Some(obj) = servers.as_object_mut()
            && obj.remove(name).is_some()
        {
            let content = serde_json::to_string_pretty(&config)
                .map_err(|e| LpmError::Registry(e.to_string()))?;
            std::fs::write(path, format!("{content}\n"))?;
            removed_from.push(editor.name);
        }
    }

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
    let mut results = Vec::new();

    for editor in &editors {
        let path = match &editor.global_path {
            Some(p) => p,
            None => continue,
        };

        let servers: Vec<String> = if path.exists() {
            let content = std::fs::read_to_string(path).unwrap_or_else(|_| "{}".into());
            let config: serde_json::Value =
                serde_json::from_str(&content).unwrap_or(serde_json::json!({}));

            config
                .get(editor.server_key)
                .and_then(|s| s.as_object())
                .map(|obj| obj.keys().cloned().collect())
                .unwrap_or_default()
        } else {
            vec![]
        };

        results.push(serde_json::json!({
            "editor": editor.name,
            "config_exists": path.exists(),
            "servers": servers,
        }));
    }

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
