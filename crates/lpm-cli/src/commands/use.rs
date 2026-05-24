use super::use_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;

#[derive(Debug, PartialEq, Eq)]
enum UseRequest {
    InstallAndPin(String),
    Pin(String),
    Remove(String),
    List(Option<String>),
}

pub async fn run_cli(
    args: &[String],
    list: bool,
    pin: bool,
    remove: bool,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match parse_cli_request(args, list, pin, remove)? {
        UseRequest::InstallAndPin(spec) => {
            run("install", Some(spec.as_str()), project_dir, json_output).await?;
            run("pin", Some(spec.as_str()), project_dir, json_output).await
        }
        UseRequest::Pin(spec) => run("pin", Some(spec.as_str()), project_dir, json_output).await,
        UseRequest::Remove(spec) => {
            run("remove", Some(spec.as_str()), project_dir, json_output).await
        }
        UseRequest::List(spec) => run("list", spec.as_deref(), project_dir, json_output).await,
    }
}

fn parse_cli_request(
    args: &[String],
    list: bool,
    pin: bool,
    remove: bool,
) -> Result<UseRequest, LpmError> {
    if list {
        return match args {
            [] => Ok(UseRequest::List(None)),
            [runtime] => Ok(UseRequest::List(Some(runtime.clone()))),
            _ => Err(LpmError::Script(
                "too many arguments. Usage: lpm use --list [node]".into(),
            )),
        };
    }

    if pin {
        return match args {
            [spec] => Ok(UseRequest::Pin(spec.clone())),
            [] => Err(LpmError::Script(
                "missing version. Usage: lpm use --pin node@22.5.0".into(),
            )),
            _ => Err(LpmError::Script(
                "too many arguments. Usage: lpm use --pin node@22.5.0".into(),
            )),
        };
    }

    if remove {
        return match args {
            [spec] => Ok(UseRequest::Remove(spec.clone())),
            [] => Err(LpmError::Script(
                "missing version. Usage: lpm use --remove node@20".into(),
            )),
            _ => Err(LpmError::Script(
                "too many arguments. Usage: lpm use --remove node@20".into(),
            )),
        };
    }

    match args {
        [] => Ok(UseRequest::List(None)),
        [action] if matches!(action.as_str(), "list" | "ls") => Ok(UseRequest::List(None)),
        [action, runtime] if matches!(action.as_str(), "list" | "ls") => {
            Ok(UseRequest::List(Some(runtime.clone())))
        }
        [action] if matches!(action.as_str(), "pin") => Err(LpmError::Script(
            "missing version. Usage: lpm use pin node@22.5.0".into(),
        )),
        [action, spec] if action == "pin" => Ok(UseRequest::Pin(spec.clone())),
        [action] if matches!(action.as_str(), "remove" | "rm" | "uninstall") => Err(
            LpmError::Script("missing version. Usage: lpm use remove node@20".into()),
        ),
        [action, spec] if matches!(action.as_str(), "remove" | "rm" | "uninstall") => {
            Ok(UseRequest::Remove(spec.clone()))
        }
        [action] if matches!(action.as_str(), "install" | "i") => Err(LpmError::Script(
            "missing version spec. Usage: lpm use install node@22".into(),
        )),
        [action, spec] if matches!(action.as_str(), "install" | "i") => {
            Ok(UseRequest::InstallAndPin(spec.clone()))
        }
        [spec] => Ok(UseRequest::InstallAndPin(spec.clone())),
        _ => Err(LpmError::Script(
            "too many arguments. Usage: lpm use [install|pin|remove|list] [node@version]".into(),
        )),
    }
}

/// Handle `lpm use` actions: install, list, pin, remove.
///
/// `lpm use` manages Node.js runtime versions for the project. Env-vars
/// management was split into its own top-level command (`lpm env`) — see
/// [`crate::commands::env`].
pub async fn run(
    action: &str,
    spec: Option<&str>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "install" | "i" => {
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version spec. Usage: lpm use node@22".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec);
            if runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{runtime}' not yet supported. Currently supported: node"
                )));
            }

            let platform = lpm_runtime::platform::Platform::current()?;
            use_ui::phase(&format!(
                "resolving node@{} for {}...",
                version_spec, platform
            ));

            let releases = lpm_runtime::node::fetch_index(&http_client).await?;
            let release =
                lpm_runtime::node::resolve_version(&releases, &version_spec).ok_or_else(|| {
                    LpmError::Script(format!(
                        "no node.js release found matching '{version_spec}'"
                    ))
                })?;

            let version = release.version_bare().to_string();

            if lpm_runtime::node::is_installed(&version) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({"success": true, "status": "already_installed", "version": version})
                    );
                } else {
                    use_ui::done(&format!("Node {} already installed", version.bold()));
                }
                return Ok(());
            }

            use_ui::phase(&format!(
                "downloading Node.js {}...",
                release.version.bold()
            ));

            let installed =
                lpm_runtime::download::install_node(&http_client, &release, &platform).await?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "status": "installed", "version": installed})
                );
            } else {
                use_ui::done(&format!("Installed Node {}", installed.bold()));
                let bin_dir = lpm_runtime::node::node_bin_dir(&installed)?;
                use_ui::hint_line(&format!("installed at {}", bin_dir.display()));
            }
        }

        "remove" | "rm" | "uninstall" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version. Usage: lpm use remove node@20".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec);
            if runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{runtime}' not yet supported. Currently supported: node"
                )));
            }

            lpm_runtime::node::validate_version_spec(&version_spec)?;
            if matches!(version_spec.to_ascii_lowercase().as_str(), "lts" | "latest") {
                return Err(LpmError::Script(
                    "remove requires an explicit version, prefix, or semver range; `lts` and `latest` are not supported"
                        .into(),
                ));
            }

            let installed = lpm_runtime::node::list_installed()?;
            let removed_versions = matching_installed_versions(&version_spec, &installed);
            if removed_versions.is_empty() {
                return Err(LpmError::Script(format!(
                    "node@{} is not currently installed. Run `lpm use --list` to see installed versions",
                    version_spec
                )));
            }

            for version in &removed_versions {
                lpm_runtime::node::uninstall(version)?;
            }

            let pin_warning = read_pinned_node_version(project_dir)?.filter(|pinned| {
                lpm_runtime::node::find_matching_installed(pinned, &removed_versions).is_some()
            });

            if json_output {
                let mut envelope = serde_json::json!({
                    "success": true,
                    "status": "removed",
                    "runtime": "node",
                    "versions": removed_versions,
                });
                if let Some(pinned) = pin_warning {
                    envelope["warning"] = serde_json::Value::String(format!(
                        "lpm.json still pins node@{}; a later run may reinstall it",
                        pinned
                    ));
                }
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
                if removed_versions.len() == 1 {
                    use_ui::done(&format!("Removed Node {}", removed_versions[0].bold()));
                } else {
                    use_ui::done(&format!(
                        "Removed {} Node versions",
                        removed_versions.len().to_string().bold()
                    ));
                    for version in &removed_versions {
                        use_ui::list_item(version);
                    }
                }
                if let Some(pinned) = pin_warning {
                    use_ui::warn(&format!(
                        "lpm.json still pins node@{}; a later run may reinstall it",
                        pinned
                    ));
                }
            }
        }

        "list" | "ls" => {
            let filter_runtime = spec.unwrap_or("node");
            if filter_runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{filter_runtime}' not yet supported"
                )));
            }

            let versions = lpm_runtime::node::list_installed()?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"success": true, "runtime": "node", "versions": versions})
                    )
                    .unwrap()
                );
            } else if versions.is_empty() {
                use_ui::phase("No Node versions installed");
                use_ui::hint_line("Run lpm use node@22 to install one");
            } else {
                use_ui::phase(&format!("Installed Node versions ({})", versions.len()));
                for v in &versions {
                    use_ui::list_item(v);
                }
            }
        }

        "pin" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version. Usage: lpm use pin node@22.5.0".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec);
            if runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{runtime}' not yet supported"
                )));
            }

            lpm_runtime::node::validate_version_spec(&version_spec)?;

            let pinned_version = resolve_pinned_node_version(&version_spec);

            // Warn if the version is not currently installed
            if !json_output && !lpm_runtime::node::is_installed(&pinned_version) {
                use_ui::warn(&format!(
                    "node@{} is not currently installed. Run `lpm use node@{}` to install it",
                    version_spec, version_spec
                ));
            }

            write_node_pin(project_dir, &pinned_version)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "pinned": {"node": pinned_version}})
                );
            } else {
                use_ui::done(&format!(
                    "Pinned node@{} in lpm.json",
                    pinned_version.bold()
                ));
            }
        }

        _ => {
            return Err(LpmError::Script(format!(
                "unknown action: '{action}'. Available: install, list, pin, remove"
            )));
        }
    }

    Ok(())
}

fn parse_runtime_spec(spec: &str) -> (String, String) {
    if let Some((runtime, version)) = spec.split_once('@') {
        (runtime.to_string(), version.to_string())
    } else {
        // No @ sign — assume it's a node version
        ("node".to_string(), spec.to_string())
    }
}

fn select_pinned_node_version(version_spec: &str, installed: &[String]) -> String {
    lpm_runtime::node::find_matching_installed(version_spec, installed)
        .unwrap_or_else(|| version_spec.to_string())
}

fn resolve_pinned_node_version(version_spec: &str) -> String {
    lpm_runtime::node::list_installed().ok().map_or_else(
        || version_spec.to_string(),
        |installed| select_pinned_node_version(version_spec, &installed),
    )
}

fn matching_installed_versions(version_spec: &str, installed: &[String]) -> Vec<String> {
    let spec = version_spec.strip_prefix('v').unwrap_or(version_spec);

    if spec.eq_ignore_ascii_case("lts") || spec.eq_ignore_ascii_case("latest") {
        return Vec::new();
    }

    if let Some(version) = installed.iter().find(|version| version.as_str() == spec) {
        return vec![version.clone()];
    }

    if is_range_spec(spec) {
        let Ok(req) = lpm_semver::VersionReq::parse(spec) else {
            return Vec::new();
        };
        let mut matches: Vec<String> = installed
            .iter()
            .filter(|version| {
                lpm_semver::Version::parse(version)
                    .ok()
                    .is_some_and(|parsed| req.matches(&parsed))
            })
            .cloned()
            .collect();
        sort_versions_desc(&mut matches);
        return matches;
    }

    if lpm_semver::Version::parse(spec).is_ok() {
        return Vec::new();
    }

    let prefix = format!("{spec}.");
    let mut matches: Vec<String> = installed
        .iter()
        .filter(|version| version.starts_with(&prefix) || version.as_str() == spec)
        .cloned()
        .collect();
    sort_versions_desc(&mut matches);
    matches
}

fn is_range_spec(spec: &str) -> bool {
    spec.contains('>')
        || spec.contains('<')
        || spec.contains('^')
        || spec.contains('~')
        || spec.contains('|')
        || spec.contains('*')
        || spec.split_whitespace().count() > 1
}

fn sort_versions_desc(versions: &mut [String]) {
    versions.sort_by(
        |a, b| match (lpm_semver::Version::parse(a), lpm_semver::Version::parse(b)) {
            (Ok(a), Ok(b)) => b.cmp(&a),
            _ => b.cmp(a),
        },
    );
}

fn read_pinned_node_version(project_dir: &std::path::Path) -> Result<Option<String>, LpmError> {
    let lpm_json_path = project_dir.join("lpm.json");
    if !lpm_json_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&lpm_json_path)?;
    let config: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("failed to parse lpm.json: {e}")))?;

    Ok(config["runtime"]["node"].as_str().map(str::to_string))
}

fn write_node_pin(project_dir: &std::path::Path, node_version: &str) -> Result<(), LpmError> {
    let lpm_json_path = project_dir.join("lpm.json");
    let mut config: serde_json::Value = if lpm_json_path.exists() {
        let content = std::fs::read_to_string(&lpm_json_path)?;
        serde_json::from_str(&content)
            .map_err(|e| LpmError::Script(format!("failed to parse lpm.json: {e}")))?
    } else {
        serde_json::json!({})
    };

    if config.get("runtime").is_none() {
        config["runtime"] = serde_json::json!({});
    }
    config["runtime"]["node"] = serde_json::Value::String(node_version.to_string());

    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| LpmError::Script(format!("failed to serialize lpm.json: {e}")))?
        + "\n";

    let tmp_path = lpm_json_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &content)?;
    std::fs::rename(&tmp_path, &lpm_json_path)?;
    Ok(())
}

/// Validate a pin version string.
/// Must satisfy the runtime layer's safe version-spec grammar.
#[cfg(test)]
fn is_valid_pin_version(v: &str) -> bool {
    lpm_runtime::node::validate_version_spec(v).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pin_versions() {
        assert!(is_valid_pin_version("22.5.0"));
        assert!(is_valid_pin_version("22"));
        assert!(is_valid_pin_version("lts"));
        assert!(is_valid_pin_version("latest"));
        assert!(is_valid_pin_version("22.0.0-rc.1"));
        assert!(is_valid_pin_version("v20_lts"));
        assert!(is_valid_pin_version("^20"));
        assert!(is_valid_pin_version(">=20.0.0 <22.0.0"));
    }

    #[test]
    fn invalid_pin_versions() {
        assert!(!is_valid_pin_version("../../etc"));
        assert!(!is_valid_pin_version(""));
        assert!(!is_valid_pin_version("22; rm -rf /"));
        assert!(!is_valid_pin_version("path/to/node"));
        assert!(!is_valid_pin_version("22\n23"));
        assert!(!is_valid_pin_version("node@22")); // @ is not allowed
    }

    #[test]
    fn pin_prefers_highest_matching_installed_version() {
        let installed = vec![
            "22.12.0".to_string(),
            "22.8.0".to_string(),
            "20.18.0".to_string(),
        ];

        assert_eq!(select_pinned_node_version("22", &installed), "22.12.0");
        assert_eq!(
            select_pinned_node_version(">=20.0.0 <22.0.0", &installed),
            "20.18.0"
        );
    }

    #[test]
    fn pin_keeps_alias_when_it_cannot_resolve_locally() {
        let installed = vec!["22.12.0".to_string()];

        assert_eq!(select_pinned_node_version("lts", &installed), "lts");
    }

    #[test]
    fn parse_cli_request_accepts_positional_remove_action() {
        let request = parse_cli_request(
            &["remove".to_string(), "node@20".to_string()],
            false,
            false,
            false,
        )
        .unwrap();

        assert_eq!(request, UseRequest::Remove("node@20".to_string()));
    }

    #[test]
    fn parse_cli_request_preserves_legacy_bare_install_and_pin_flow() {
        let request = parse_cli_request(&["node@22".to_string()], false, false, false).unwrap();

        assert_eq!(request, UseRequest::InstallAndPin("node@22".to_string()));
    }

    #[test]
    fn matching_installed_versions_returns_all_matching_major_versions() {
        let installed = vec![
            "22.12.0".to_string(),
            "20.18.0".to_string(),
            "20.17.0".to_string(),
        ];

        assert_eq!(
            matching_installed_versions("20", &installed),
            vec!["20.18.0".to_string(), "20.17.0".to_string()]
        );
    }

    #[test]
    fn atomic_write_produces_correct_content_and_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_json_path = dir.path().join("lpm.json");

        // Simulate the atomic write path from the pin logic
        let mut config = serde_json::json!({});
        config["runtime"] = serde_json::json!({});
        config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

        let content = serde_json::to_string_pretty(&config).unwrap() + "\n";

        let tmp_path = lpm_json_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &content).unwrap();
        std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

        // Verify content is correct
        let written = std::fs::read_to_string(&lpm_json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["runtime"]["node"], "22.5.0");

        // Verify trailing newline
        assert!(
            written.ends_with('\n'),
            "lpm.json must end with a trailing newline"
        );

        // Verify no temp file remains
        assert!(
            !tmp_path.exists(),
            "temporary .json.tmp file should not remain after atomic rename"
        );
    }

    #[test]
    fn atomic_write_preserves_existing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_json_path = dir.path().join("lpm.json");

        // Pre-existing lpm.json with other fields
        let existing = serde_json::json!({
            "name": "my-project",
            "runtime": { "node": "20.0.0" }
        });
        std::fs::write(
            &lpm_json_path,
            serde_json::to_string_pretty(&existing).unwrap() + "\n",
        )
        .unwrap();

        // Simulate pin update
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&lpm_json_path).unwrap()).unwrap();
        config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

        let content = serde_json::to_string_pretty(&config).unwrap() + "\n";
        let tmp_path = lpm_json_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &content).unwrap();
        std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

        let written = std::fs::read_to_string(&lpm_json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["name"], "my-project");
        assert_eq!(parsed["runtime"]["node"], "22.5.0");
        assert!(written.ends_with('\n'));
    }
}
