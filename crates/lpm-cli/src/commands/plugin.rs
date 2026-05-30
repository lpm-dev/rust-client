use crate::install_ui;
use lpm_common::LpmError;

/// Handle `lpm plugin` subcommands: list, update.
pub async fn run(
    action: &str,
    plugin_name: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "list" | "ls" => list(json_output).await,
        "update" | "upgrade" => update(plugin_name, json_output).await,
        "remove" | "rm" | "uninstall" => remove(plugin_name, json_output),
        _ => Err(LpmError::Script(format!(
            "unknown plugin action: '{action}'. Available: list, update, remove"
        ))),
    }
}

/// List installed plugins and check for updates.
async fn list(json_output: bool) -> Result<(), LpmError> {
    let all_latest = lpm_plugin::versions::get_all_latest_versions().await;

    if json_output {
        let mut plugins = Vec::new();
        for def in lpm_plugin::registry::list_plugins() {
            let installed = lpm_plugin::store::list_installed_versions(def.name)?;
            let latest = all_latest
                .get(def.name)
                .cloned()
                .unwrap_or_else(|| def.latest_version.to_string());

            plugins.push(serde_json::json!({
                "name": def.name,
                "installed": installed,
                "latest": latest,
            }));
        }
        let json = serde_json::json!({
            "success": true,
            "plugins": plugins,
            "count": plugins.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    let mut rows = Vec::new();
    for def in lpm_plugin::registry::list_plugins() {
        let installed = lpm_plugin::store::list_installed_versions(def.name)?;
        let latest = all_latest
            .get(def.name)
            .cloned()
            .unwrap_or_else(|| def.latest_version.to_string());

        if !installed.is_empty() {
            let current = installed.join(", ");
            let status = if installed.iter().any(|version| version == &latest) {
                "current".to_string()
            } else {
                "update available".to_string()
            };
            rows.push((def.name.to_string(), current, latest, status));
        }
    }

    if rows.is_empty() {
        install_ui::warn("No plugins installed");
        eprintln!(
            "  {}",
            install_ui::dim("Run `lpm lint` or `lpm fmt` to install plugins on first use")
        );
        return Ok(());
    }

    print_plugin_table(&rows);
    install_ui::done(&format!(
        "{} {} installed",
        rows.len(),
        if rows.len() == 1 { "plugin" } else { "plugins" }
    ));

    Ok(())
}

fn print_plugin_table(rows: &[(String, String, String, String)]) {
    let plugin_width = rows
        .iter()
        .map(|(name, _, _, _)| name.len())
        .chain(std::iter::once("Plugin".len()))
        .max()
        .unwrap_or("Plugin".len());
    let current_width = rows
        .iter()
        .map(|(_, current, _, _)| current.len())
        .chain(std::iter::once("Current".len()))
        .max()
        .unwrap_or("Current".len());
    let latest_width = rows
        .iter()
        .map(|(_, _, latest, _)| latest.len())
        .chain(std::iter::once("Latest".len()))
        .max()
        .unwrap_or("Latest".len());

    println!(
        "{:<plugin_width$}  {:<current_width$}  {:<latest_width$}  Status",
        "Plugin", "Current", "Latest"
    );
    for (name, current, latest, status) in rows {
        println!(
            "{name:<plugin_width$}  {current:<current_width$}  {latest:<latest_width$}  {status}"
        );
    }
    println!();
}

/// Remove a plugin (specific version or all versions).
fn remove(plugin_name: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let name = plugin_name.ok_or_else(|| {
        LpmError::Script("missing plugin name. Usage: lpm plugin remove <name> [version]".into())
    })?;

    // Check if name contains @ for specific version: "oxlint@1.57.0"
    let (plugin, version) = if let Some((n, v)) = name.split_once('@') {
        (n, Some(v))
    } else {
        (name, None)
    };

    if let Some(ver) = version {
        let removed = lpm_plugin::store::remove_version(plugin, ver)?;
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "removed": removed,
                "plugin": plugin,
                "version": ver,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if removed {
            install_ui::done(&format!("Removed {plugin}@{ver}"));
        } else {
            install_ui::warn(&format!("{plugin}@{ver} not installed"));
        }
    } else {
        let count = lpm_plugin::store::remove_all(plugin)?;
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "removed": count,
                "plugin": plugin,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if count > 0 {
            install_ui::done(&format!(
                "Removed {plugin} ({count} {})",
                if count == 1 { "version" } else { "versions" }
            ));
        } else {
            install_ui::warn(&format!("{plugin} not installed"));
        }
    }

    Ok(())
}

/// Update a specific plugin or all plugins to latest version.
async fn update(plugin_name: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    if let Some(name) = plugin_name {
        // Update specific plugin
        let previous = latest_installed_version(name)?;
        let version = lpm_plugin::update_plugin(name).await?;
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "plugin": name,
                "version": version,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            install_ui::done(&format_update_message(name, previous.as_deref(), &version));
        }
    } else {
        // Update all plugins that are installed
        let mut updated = Vec::new();
        for def in lpm_plugin::registry::list_plugins() {
            let installed = lpm_plugin::store::list_installed_versions(def.name)?;
            if installed.is_empty() {
                continue; // Skip plugins that aren't installed
            }

            let previous = installed.last().map(String::as_str);
            let version = lpm_plugin::update_plugin(def.name).await?;
            if !json_output {
                install_ui::done(&format_update_message(def.name, previous, &version));
            }
            updated.push(serde_json::json!({
                "plugin": def.name,
                "version": version,
            }));
        }

        if json_output {
            let json = serde_json::json!({
                "success": true,
                "updated": updated,
                "count": updated.len(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if updated.is_empty() {
            install_ui::warn("No plugins installed to update");
            eprintln!(
                "  {}",
                install_ui::dim("Run `lpm lint` or `lpm fmt` to install plugins on first use")
            );
        }
    }

    Ok(())
}

fn latest_installed_version(plugin_name: &str) -> Result<Option<String>, LpmError> {
    let installed = lpm_plugin::store::list_installed_versions(plugin_name)?;
    Ok(installed.last().cloned())
}

fn format_update_message(plugin_name: &str, previous: Option<&str>, version: &str) -> String {
    match previous {
        Some(previous) if previous != version => {
            format!("Updated {plugin_name} {previous} → {version}")
        }
        _ => format!("Updated {plugin_name} to {version}"),
    }
}
