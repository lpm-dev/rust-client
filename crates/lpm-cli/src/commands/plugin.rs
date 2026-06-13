use crate::install_ui;
use lpm_common::LpmError;
use lpm_plugin::registry::PluginDef;

const PROJECT_OWNED_TOOLS: &[&str] = &["tsdown"];

#[derive(Debug, Clone)]
struct ManagedToolRow {
    name: String,
    installed: Vec<String>,
    current: String,
    latest: String,
    status: String,
    update_supported: bool,
    error: Option<String>,
}

/// Handle `lpm plugin` subcommands: list, update.
pub async fn run(
    action: &str,
    plugin_name: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "list" | "ls" => list(json_output).await,
        "outdated" => outdated(json_output).await,
        "update" | "upgrade" => update(plugin_name, json_output).await,
        "remove" | "rm" | "uninstall" => remove(plugin_name, json_output),
        _ => Err(LpmError::Script(format!(
            "unknown plugin action: '{action}'. Available: list, outdated, update, remove"
        ))),
    }
}

/// List installed plugins and check for updates.
async fn list(json_output: bool) -> Result<(), LpmError> {
    let rows = local_managed_tool_rows().await?;

    if json_output {
        let plugins = rows_to_json(&rows);
        let json = serde_json::json!({
            "success": true,
            "plugins": plugins,
            "count": plugins.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    print_plugin_table(&rows);
    install_ui::done(&format!(
        "{} managed {}",
        rows.len(),
        if rows.len() == 1 { "plugin" } else { "plugins" }
    ));

    Ok(())
}

async fn outdated(json_output: bool) -> Result<(), LpmError> {
    let rows = upstream_managed_tool_rows().await?;

    if json_output {
        let plugins = rows_to_json(&rows);
        let project_owned: Vec<serde_json::Value> = PROJECT_OWNED_TOOLS
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "kind": "project",
                    "update_supported": false,
                    "note": "project dependency; use lpm outdated or lpm upgrade",
                })
            })
            .collect();
        let outdated_count = rows
            .iter()
            .filter(|row| row.status == "update available")
            .count();
        let json = serde_json::json!({
            "success": true,
            "plugins": plugins,
            "project_owned": project_owned,
            "outdated_count": outdated_count,
            "count": rows.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    print_plugin_table(&rows);
    eprintln!(
        "  {}",
        install_ui::dim("tsdown is project-owned; use `lpm outdated` or `lpm upgrade`")
    );
    install_ui::done(&format!(
        "Checked {} managed {}",
        rows.len(),
        if rows.len() == 1 { "plugin" } else { "plugins" }
    ));
    Ok(())
}

fn print_plugin_table(rows: &[ManagedToolRow]) {
    let plugin_width = rows
        .iter()
        .map(|row| row.name.len())
        .chain(std::iter::once("Plugin".len()))
        .max()
        .unwrap_or("Plugin".len());
    let current_width = rows
        .iter()
        .map(|row| row.current.len())
        .chain(std::iter::once("Current".len()))
        .max()
        .unwrap_or("Current".len());
    let latest_width = rows
        .iter()
        .map(|row| row.latest.len())
        .chain(std::iter::once("Latest".len()))
        .max()
        .unwrap_or("Latest".len());

    let header = format!(
        "{:<plugin_width$}  {:<current_width$}  {:<latest_width$}  Status",
        "Plugin", "Current", "Latest"
    );
    println!("{}", install_ui::dim(&header));
    for row in rows {
        let name = &row.name;
        let current = &row.current;
        let latest = &row.latest;
        let status = &row.status;
        let current_col = install_ui::dim(&format!("{current:<current_width$}"));
        let latest_col = if status == "update available" {
            install_ui::yellow(&format!("{latest:<latest_width$}"))
        } else {
            format!("{latest:<latest_width$}")
        };
        let status_col = match status.as_str() {
            "current" => install_ui::status_ok(status),
            "update available" => install_ui::yellow(status),
            "not installed" => install_ui::dim(status),
            "check failed" => install_ui::red(status),
            _ => status.clone(),
        };
        println!("{name:<plugin_width$}  {current_col}  {latest_col}  {status_col}");
        if let Some(error) = &row.error {
            println!("{}  {}", " ".repeat(plugin_width), install_ui::dim(error));
        }
    }
    println!();
}

async fn local_managed_tool_rows() -> Result<Vec<ManagedToolRow>, LpmError> {
    let plugin_latest = lpm_plugin::versions::get_all_latest_versions().await;
    let mut rows = Vec::new();
    for def in sorted_plugin_defs() {
        let selected = plugin_latest
            .get(def.name)
            .cloned()
            .unwrap_or_else(|| def.latest_version.to_string());
        let installed = lpm_plugin::store::list_installed_versions(def.name)?;
        rows.push(local_managed_tool_row(def.name, installed, selected));
    }
    let selected_rolldown = lpm_plugin::get_latest_engine_version("rolldown")?;
    let installed_rolldown = lpm_plugin::list_installed_engine_versions("rolldown")?;
    rows.push(local_managed_tool_row(
        "rolldown",
        installed_rolldown,
        selected_rolldown,
    ));
    Ok(rows)
}

async fn upstream_managed_tool_rows() -> Result<Vec<ManagedToolRow>, LpmError> {
    let plugin_latest = lpm_plugin::versions::get_all_latest_versions().await;
    let mut rows = Vec::new();
    for def in sorted_plugin_defs() {
        let current = plugin_latest
            .get(def.name)
            .cloned()
            .unwrap_or_else(|| def.latest_version.to_string());
        let upstream = match lpm_plugin::versions::peek_latest_from_github(def).await {
            Ok(latest) => latest,
            Err(error) => {
                rows.push(managed_plugin_row(
                    def,
                    current.clone(),
                    current,
                    Some(error),
                )?);
                continue;
            }
        };
        rows.push(managed_plugin_row(def, current, upstream, None)?);
    }

    let current = lpm_plugin::get_latest_engine_version("rolldown")?;
    match lpm_plugin::peek_latest_engine_version("rolldown").await {
        Ok(latest) => rows.push(managed_engine_row("rolldown", current, latest, None)?),
        Err(error) => rows.push(managed_engine_row(
            "rolldown",
            current.clone(),
            current,
            Some(error),
        )?),
    }
    Ok(rows)
}

fn sorted_plugin_defs() -> Vec<&'static PluginDef> {
    let mut defs: Vec<&'static PluginDef> = lpm_plugin::registry::list_plugins().iter().collect();
    defs.sort_by_key(|def| def.name);
    defs
}

fn managed_plugin_row(
    def: &PluginDef,
    current: String,
    latest: String,
    error: Option<String>,
) -> Result<ManagedToolRow, LpmError> {
    let installed = lpm_plugin::store::list_installed_versions(def.name)?;
    Ok(managed_tool_row(
        def.name, installed, current, latest, error,
    ))
}

fn managed_engine_row(
    name: &str,
    current: String,
    latest: String,
    error: Option<String>,
) -> Result<ManagedToolRow, LpmError> {
    let installed = lpm_plugin::list_installed_engine_versions(name)?;
    Ok(managed_tool_row(name, installed, current, latest, error))
}

fn managed_tool_row(
    name: &str,
    installed: Vec<String>,
    current: String,
    latest: String,
    error: Option<String>,
) -> ManagedToolRow {
    let status = if error.is_some() {
        "check failed".to_string()
    } else if version_is_newer(&latest, &current) {
        "update available".to_string()
    } else if installed.is_empty() {
        "not installed".to_string()
    } else {
        "current".to_string()
    };

    ManagedToolRow {
        name: name.to_string(),
        installed,
        current,
        latest,
        status,
        update_supported: true,
        error,
    }
}

fn local_managed_tool_row(name: &str, installed: Vec<String>, selected: String) -> ManagedToolRow {
    let (current, status) = if installed.is_empty() {
        ("not installed".to_string(), "not installed".to_string())
    } else if installed.iter().any(|version| version == &selected) {
        (installed.join(", "), "current".to_string())
    } else {
        (installed.join(", "), "update available".to_string())
    };

    ManagedToolRow {
        name: name.to_string(),
        installed,
        current,
        latest: selected,
        status,
        update_supported: true,
        error: None,
    }
}

fn rows_to_json(rows: &[ManagedToolRow]) -> Vec<serde_json::Value> {
    rows.iter()
        .map(|row| {
            serde_json::json!({
                "name": row.name,
                "kind": "plugin",
                "installed": row.installed,
                "current": row.current,
                "latest": row.latest,
                "status": row.status,
                "outdated": row.status == "update available",
                "update_supported": row.update_supported,
                "error": row.error,
            })
        })
        .collect()
}

fn version_is_newer(candidate: &str, current: &str) -> bool {
    match (
        lpm_semver::Version::parse(candidate),
        lpm_semver::Version::parse(current),
    ) {
        (Ok(candidate), Ok(current)) => candidate > current,
        _ => candidate > current,
    }
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

    if PROJECT_OWNED_TOOLS.contains(&plugin) {
        return Err(LpmError::Script(format!(
            "{plugin} is project-owned. Use `lpm uninstall {plugin}` or edit package.json dependencies."
        )));
    }

    if plugin == "rolldown" {
        return remove_engine_plugin(plugin, version, json_output);
    }

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

fn remove_engine_plugin(
    plugin: &str,
    version: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(ver) = version {
        let removed = lpm_plugin::remove_engine_version(plugin, ver)?;
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
        let count = lpm_plugin::remove_all_engine_versions(plugin)?;
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
        if PROJECT_OWNED_TOOLS.contains(&name) {
            return Err(LpmError::Script(format!(
                "{name} is project-owned and is not updated by `lpm plugin update`. \
                 Use `lpm outdated` or `lpm upgrade`."
            )));
        }

        // Update specific plugin
        let previous = latest_installed_version(name)?;
        let version = if name == "rolldown" {
            if json_output {
                lpm_plugin::update_engine(name).await?
            } else {
                let mut observer = render_engine_update_event;
                lpm_plugin::update_engine_with_observer(name, &mut observer).await?
            }
        } else if json_output {
            lpm_plugin::update_plugin(name).await?
        } else {
            let mut observer = render_plugin_update_event;
            lpm_plugin::update_plugin_with_observer(name, &mut observer).await?
        };
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
        // Update all managed tools that are installed.
        let mut updated = Vec::new();
        for def in lpm_plugin::registry::list_plugins() {
            let installed = lpm_plugin::store::list_installed_versions(def.name)?;
            if installed.is_empty() {
                continue; // Skip plugins that aren't installed
            }

            let previous = installed.last().map(String::as_str);
            let version = if json_output {
                lpm_plugin::update_plugin(def.name).await?
            } else {
                let mut observer = render_plugin_update_event;
                lpm_plugin::update_plugin_with_observer(def.name, &mut observer).await?
            };
            if !json_output {
                install_ui::done(&format_update_message(def.name, previous, &version));
            }
            updated.push(serde_json::json!({
                "plugin": def.name,
                "version": version,
            }));
        }

        let installed_rolldown = lpm_plugin::list_installed_engine_versions("rolldown")?;
        if !installed_rolldown.is_empty() {
            let previous = installed_rolldown.last().map(String::as_str);
            let version = if json_output {
                lpm_plugin::update_engine("rolldown").await?
            } else {
                let mut observer = render_engine_update_event;
                lpm_plugin::update_engine_with_observer("rolldown", &mut observer).await?
            };
            if !json_output {
                install_ui::done(&format_update_message("rolldown", previous, &version));
            }
            updated.push(serde_json::json!({
                "plugin": "rolldown",
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
            install_ui::warn("No managed plugins installed to update");
            eprintln!(
                "  {}",
                install_ui::dim(
                    "Run `lpm lint`, `lpm fmt`, or `lpm bundle` to install on first use"
                )
            );
        }
    }

    Ok(())
}

fn latest_installed_version(plugin_name: &str) -> Result<Option<String>, LpmError> {
    if plugin_name == "rolldown" {
        let installed = lpm_plugin::list_installed_engine_versions(plugin_name)?;
        return Ok(installed.last().cloned());
    }
    let installed = lpm_plugin::store::list_installed_versions(plugin_name)?;
    Ok(installed.last().cloned())
}

fn render_plugin_update_event(event: lpm_plugin::PluginInstallEvent) {
    match event {
        lpm_plugin::PluginInstallEvent::Downloading { plugin, version } => {
            install_ui::phase(&format!(
                "Downloading {plugin} {}",
                install_ui::yellow(&version)
            ));
        }
        lpm_plugin::PluginInstallEvent::VerifiedChecksum { .. } => {
            install_ui::done("Verified SHA-256 checksum");
        }
    }
}

fn render_engine_update_event(event: lpm_plugin::EngineInstallEvent) {
    match event {
        lpm_plugin::EngineInstallEvent::ResolvingLatest { engine } => {
            install_ui::phase(&format!("Checking {engine} releases"));
        }
        lpm_plugin::EngineInstallEvent::Downloading { engine, version } => {
            install_ui::phase(&format!(
                "Downloading {engine} {}",
                install_ui::yellow(&version)
            ));
        }
        lpm_plugin::EngineInstallEvent::VerifiedIntegrity { .. } => {
            install_ui::done("Verified npm package integrity");
        }
    }
}

fn format_update_message(plugin_name: &str, previous: Option<&str>, version: &str) -> String {
    match previous {
        Some(previous) if previous != version => {
            format!(
                "Updated {plugin_name} {} {} {}",
                install_ui::yellow(previous),
                install_ui::dim("→"),
                install_ui::yellow(version),
            )
        }
        _ => format!("Updated {plugin_name} to {}", install_ui::yellow(version)),
    }
}

#[cfg(test)]
mod tests {
    use super::format_update_message;
    use std::sync::Mutex;

    static COLOR_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn plugin_update_message_colors_versions_and_arrow() {
        let _guard = COLOR_LOCK.lock().unwrap();
        let previous_color = lpm_common::color::enabled();
        lpm_common::color::set_enabled(true);

        let message = format_update_message("oxlint", Some("1.57.0"), "1.58.0");

        lpm_common::color::set_enabled(previous_color);
        assert!(
            message.contains("\x1b[33m1.57.0\x1b[39m")
                && message.contains("\x1b[2m→\x1b[22m")
                && message.contains("\x1b[33m1.58.0\x1b[39m"),
            "update message must color both versions yellow and dim the arrow, got: {message:?}"
        );
    }
}
