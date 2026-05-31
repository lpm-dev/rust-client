use super::use_ui;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_runtime::detect::RuntimeKind;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
enum UseRequest {
    InstallAndPin(String),
    Pin(String),
    Remove(String),
    List(Option<String>),
}

#[derive(Debug, Clone)]
struct InstalledRuntime {
    runtime: RuntimeKind,
    version: String,
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
            let installed = install_runtime(spec.as_str(), json_output).await?;
            let exact_spec = format!("{}@{}", installed.runtime.as_str(), installed.version);
            run("pin", Some(exact_spec.as_str()), project_dir, json_output).await
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
                "too many arguments. Usage: lpm use --list [node|bun]".into(),
            )),
        };
    }

    if pin {
        return match args {
            [spec] => Ok(UseRequest::Pin(spec.clone())),
            [] => Err(LpmError::Script(
                "missing version. Usage: lpm use --pin node@22.5.0 or bun@1.3.14".into(),
            )),
            _ => Err(LpmError::Script(
                "too many arguments. Usage: lpm use --pin node@22.5.0 or bun@1.3.14".into(),
            )),
        };
    }

    if remove {
        return match args {
            [spec] => Ok(UseRequest::Remove(spec.clone())),
            [] => Err(LpmError::Script(
                "missing version. Usage: lpm use --remove node@20 or bun@1.3".into(),
            )),
            _ => Err(LpmError::Script(
                "too many arguments. Usage: lpm use --remove node@20 or bun@1.3".into(),
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
            "too many arguments. Usage: lpm use [install|pin|remove|list] [node@version|bun@version]".into(),
        )),
    }
}

/// Handle `lpm use` actions: install, list, pin, remove.
///
/// `lpm use` manages project runtime versions. Env-vars
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
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version spec. Usage: lpm use node@22".into())
            })?;
            let _ = install_runtime(spec, json_output).await?;
        }

        "remove" | "rm" | "uninstall" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version. Usage: lpm use remove node@20".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec)?;

            validate_runtime_spec(runtime, &version_spec)?;
            if matches!(version_spec.to_ascii_lowercase().as_str(), "lts" | "latest") {
                return Err(LpmError::Script(
                    "remove requires an explicit version, prefix, or semver range; `lts` and `latest` are not supported"
                        .into(),
                ));
            }

            let installed = list_installed(runtime)?;
            let removed_versions = matching_installed_versions(runtime, &version_spec, &installed);
            if removed_versions.is_empty() {
                return Err(LpmError::Script(format!(
                    "{}@{} is not currently installed. Run `lpm use --list {}` to see installed versions",
                    runtime.as_str(),
                    version_spec,
                    runtime.as_str()
                )));
            }

            for version in &removed_versions {
                uninstall_runtime(runtime, version)?;
            }

            let pin_warning = read_pinned_runtime_version(project_dir, runtime)?.filter(|pinned| {
                find_matching_installed(runtime, pinned, &removed_versions).is_some()
            });

            if json_output {
                let mut envelope = serde_json::json!({
                    "success": true,
                    "status": "removed",
                    "runtime": runtime.as_str(),
                    "versions": removed_versions,
                });
                if let Some(pinned) = pin_warning {
                    envelope["warning"] = serde_json::Value::String(format!(
                        "lpm.json still pins {}@{}; a later run may reinstall it",
                        runtime.as_str(),
                        pinned
                    ));
                }
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
                if removed_versions.len() == 1 {
                    use_ui::done(&format!(
                        "Removed {} {}",
                        runtime.display_name(),
                        removed_versions[0].bold()
                    ));
                } else {
                    use_ui::done(&format!(
                        "Removed {} {} versions",
                        removed_versions.len().to_string().bold(),
                        runtime.display_name()
                    ));
                    for version in &removed_versions {
                        use_ui::list_item(version);
                    }
                }
                if let Some(pinned) = pin_warning {
                    use_ui::warn(&format!(
                        "lpm.json still pins {}@{}; a later run may reinstall it",
                        runtime.as_str(),
                        pinned
                    ));
                }
            }
        }

        "list" | "ls" => {
            let runtime = parse_runtime_filter(spec.unwrap_or("node"))?;
            let versions = list_installed(runtime)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"success": true, "runtime": runtime.as_str(), "versions": versions})
                    )
                    .unwrap()
                );
            } else if versions.is_empty() {
                use_ui::phase(&format!("No {} versions installed", runtime.display_name()));
                use_ui::hint_line(&format!(
                    "Run lpm use {}@{} to install one",
                    runtime.as_str(),
                    default_install_hint(runtime)
                ));
            } else {
                use_ui::phase(&format!(
                    "Installed {} versions ({})",
                    runtime.display_name(),
                    versions.len()
                ));
                for v in &versions {
                    use_ui::list_item(v);
                }
            }
        }

        "pin" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version. Usage: lpm use pin node@22.5.0".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec)?;
            validate_runtime_spec(runtime, &version_spec)?;

            let pinned_version = resolve_pinned_runtime_version(runtime, &version_spec);

            // Warn if the version is not currently installed
            if !json_output && !is_installed(runtime, &pinned_version) {
                use_ui::warn(&format!(
                    "{}@{} is not currently installed. Run `lpm use {}@{}` to install it",
                    runtime.as_str(),
                    version_spec,
                    runtime.as_str(),
                    version_spec
                ));
            }

            write_runtime_pin(project_dir, runtime, &pinned_version)?;

            if json_output {
                let mut pinned = serde_json::Map::new();
                pinned.insert(
                    runtime.as_str().to_string(),
                    serde_json::Value::String(pinned_version),
                );
                println!("{}", serde_json::json!({"success": true, "pinned": pinned}));
            } else {
                use_ui::done(&format!(
                    "Pinned {}@{} in lpm.json",
                    runtime.as_str(),
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

async fn install_runtime(spec: &str, json_output: bool) -> Result<InstalledRuntime, LpmError> {
    let install_start = std::time::Instant::now();
    let (runtime, version_spec) = parse_runtime_spec(spec)?;
    validate_runtime_spec(runtime, &version_spec)?;

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    let platform = lpm_runtime::platform::Platform::current()?;
    use_ui::phase(&format!(
        "Resolving {}@{} for {}",
        runtime.as_str(),
        install_ui::yellow(&version_spec),
        platform
    ));

    let installed = match runtime {
        RuntimeKind::Node => {
            let releases = lpm_runtime::node::fetch_index(&http_client).await?;
            let release =
                lpm_runtime::node::resolve_version(&releases, &version_spec).ok_or_else(|| {
                    LpmError::Script(format!(
                        "no node.js release found matching '{version_spec}'"
                    ))
                })?;
            let version = release.version_bare().to_string();
            if !json_output {
                use_ui::phase(&format!(
                    "Resolving node@{} {} {}{}",
                    install_ui::yellow(&version_spec),
                    install_ui::dim("→"),
                    install_ui::yellow(&version),
                    format_node_lts_suffix(&release),
                ));
            }

            if lpm_runtime::node::is_installed(&version) {
                print_already_installed(runtime, &version, json_output);
                return Ok(InstalledRuntime { runtime, version });
            }

            use_ui::phase(&format!(
                "Downloading Node.js {}",
                install_ui::yellow(&version)
            ));
            lpm_runtime::download::install_node(&http_client, &release, &platform).await?
        }
        RuntimeKind::Bun => {
            let releases = lpm_runtime::bun::fetch_releases(&http_client).await?;
            let release =
                lpm_runtime::bun::resolve_version(&releases, &version_spec)?.ok_or_else(|| {
                    LpmError::Script(format!("no Bun release found matching '{version_spec}'"))
                })?;
            let version = release.version_bare().to_string();
            if !json_output {
                use_ui::phase(&format!(
                    "Resolving bun@{} {} {}",
                    install_ui::yellow(&version_spec),
                    install_ui::dim("→"),
                    install_ui::yellow(&version),
                ));
            }

            if lpm_runtime::bun::is_installed(&version) {
                print_already_installed(runtime, &version, json_output);
                return Ok(InstalledRuntime { runtime, version });
            }

            let asset = release.asset_for_platform(&platform).ok_or_else(|| {
                LpmError::Script(format!(
                    "no Bun asset found for platform {} in {}",
                    platform, release.tag_name
                ))
            })?;
            use_ui::phase(&format!("Downloading Bun {}", install_ui::yellow(&version)));
            if let Some(digest) = asset.digest.as_deref()
                && !digest.is_empty()
            {
                use_ui::hint_line(digest);
            }
            lpm_runtime::download::install_bun(&http_client, &release, &asset).await?
        }
    };

    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "status": "installed", "runtime": runtime.as_str(), "version": installed})
        );
    } else {
        use_ui::done(&format!("Extracted {}", runtime.display_name()));
        use_ui::done(&format!("Linked {}", runtime.display_name()));
        let duration = install_ui::format_duration(install_start.elapsed());
        use_ui::done(&format!(
            "Now using {} {} · {}",
            runtime.display_name(),
            install_ui::yellow(&installed),
            install_ui::green(&duration)
        ));
        let bin_dir = runtime_bin_dir(runtime, &installed)?;
        use_ui::hint_line(&format!("PATH {}", bin_dir.display()));
    }

    Ok(InstalledRuntime {
        runtime,
        version: installed,
    })
}

fn format_node_lts_suffix(release: &lpm_runtime::node::NodeRelease) -> String {
    release.lts.name().map_or_else(String::new, |name| {
        format!(
            " ({})",
            format!("lts/{}", name.to_ascii_lowercase()).dimmed()
        )
    })
}

fn parse_runtime_spec(spec: &str) -> Result<(RuntimeKind, String), LpmError> {
    if let Some((runtime, version)) = spec.split_once('@') {
        let runtime = parse_runtime_filter(runtime)?;
        if version.is_empty() {
            return Err(LpmError::Script(format!(
                "missing version. Usage: lpm use {}@{}",
                runtime.as_str(),
                default_install_hint(runtime)
            )));
        }
        Ok((runtime, version.to_string()))
    } else {
        Ok((RuntimeKind::Node, spec.to_string()))
    }
}

fn parse_runtime_filter(runtime: &str) -> Result<RuntimeKind, LpmError> {
    RuntimeKind::from_str(runtime).map_err(|()| {
        LpmError::Script(format!(
            "runtime '{runtime}' not supported. Currently supported: node, bun"
        ))
    })
}

fn default_install_hint(runtime: RuntimeKind) -> &'static str {
    match runtime {
        RuntimeKind::Node => "22",
        RuntimeKind::Bun => "latest",
    }
}

fn validate_runtime_spec(runtime: RuntimeKind, version_spec: &str) -> Result<(), LpmError> {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::validate_version_spec(version_spec),
        RuntimeKind::Bun => lpm_runtime::bun::validate_version_spec(version_spec),
    }
}

fn print_already_installed(runtime: RuntimeKind, version: &str, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "status": "already_installed", "runtime": runtime.as_str(), "version": version})
        );
    } else {
        use_ui::done(&format!(
            "{} {} already installed",
            runtime.display_name(),
            version.bold()
        ));
    }
}

fn select_pinned_runtime_version(
    runtime: RuntimeKind,
    version_spec: &str,
    installed: &[String],
) -> String {
    find_matching_installed(runtime, version_spec, installed)
        .unwrap_or_else(|| version_spec.to_string())
}

fn resolve_pinned_runtime_version(runtime: RuntimeKind, version_spec: &str) -> String {
    list_installed(runtime).ok().map_or_else(
        || version_spec.to_string(),
        |installed| select_pinned_runtime_version(runtime, version_spec, &installed),
    )
}

fn matching_installed_versions(
    runtime: RuntimeKind,
    version_spec: &str,
    installed: &[String],
) -> Vec<String> {
    let spec = match runtime {
        RuntimeKind::Node => version_spec
            .strip_prefix('v')
            .unwrap_or(version_spec)
            .to_string(),
        RuntimeKind::Bun => lpm_runtime::bun::normalize_spec(version_spec),
    };

    if spec.eq_ignore_ascii_case("lts") || spec.eq_ignore_ascii_case("latest") {
        return Vec::new();
    }

    if let Some(version) = installed.iter().find(|version| version.as_str() == spec) {
        return vec![version.clone()];
    }

    if is_range_spec(&spec) {
        let Ok(req) = lpm_semver::VersionReq::parse(&spec) else {
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

    if lpm_semver::Version::parse(&spec).is_ok() {
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

fn find_matching_installed(
    runtime: RuntimeKind,
    version_spec: &str,
    installed: &[String],
) -> Option<String> {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::find_matching_installed(version_spec, installed),
        RuntimeKind::Bun => lpm_runtime::bun::find_matching_installed(version_spec, installed),
    }
}

fn list_installed(runtime: RuntimeKind) -> Result<Vec<String>, LpmError> {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::list_installed(),
        RuntimeKind::Bun => lpm_runtime::bun::list_installed(),
    }
}

fn is_installed(runtime: RuntimeKind, version: &str) -> bool {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::is_installed(version),
        RuntimeKind::Bun => lpm_runtime::bun::is_installed(version),
    }
}

fn runtime_bin_dir(runtime: RuntimeKind, version: &str) -> Result<std::path::PathBuf, LpmError> {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::node_bin_dir(version),
        RuntimeKind::Bun => lpm_runtime::bun::bun_bin_dir(version),
    }
}

fn uninstall_runtime(runtime: RuntimeKind, version: &str) -> Result<(), LpmError> {
    match runtime {
        RuntimeKind::Node => lpm_runtime::node::uninstall(version),
        RuntimeKind::Bun => lpm_runtime::bun::uninstall(version),
    }
}

fn read_pinned_runtime_version(
    project_dir: &std::path::Path,
    runtime: RuntimeKind,
) -> Result<Option<String>, LpmError> {
    let lpm_json_path = project_dir.join("lpm.json");
    if !lpm_json_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&lpm_json_path)?;
    let config: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("failed to parse lpm.json: {e}")))?;

    Ok(config["runtime"][runtime.as_str()]
        .as_str()
        .map(str::to_string))
}

fn write_runtime_pin(
    project_dir: &std::path::Path,
    runtime: RuntimeKind,
    version: &str,
) -> Result<(), LpmError> {
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
    config["runtime"][runtime.as_str()] = serde_json::Value::String(version.to_string());

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
fn select_pinned_node_version(version_spec: &str, installed: &[String]) -> String {
    select_pinned_runtime_version(RuntimeKind::Node, version_spec, installed)
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
            matching_installed_versions(RuntimeKind::Node, "20", &installed),
            vec!["20.18.0".to_string(), "20.17.0".to_string()]
        );
    }

    #[test]
    fn bun_pin_prefers_highest_matching_installed_version() {
        let installed = vec![
            "1.3.14".to_string(),
            "1.3.9".to_string(),
            "1.2.23".to_string(),
        ];

        assert_eq!(
            select_pinned_runtime_version(RuntimeKind::Bun, "bun-v1.3", &installed),
            "1.3.14"
        );
    }

    #[test]
    fn matching_installed_versions_normalizes_bun_tag_prefix() {
        let installed = vec![
            "1.3.14".to_string(),
            "1.3.9".to_string(),
            "1.2.23".to_string(),
        ];

        assert_eq!(
            matching_installed_versions(RuntimeKind::Bun, "bun-v1.3", &installed),
            vec!["1.3.14".to_string(), "1.3.9".to_string()]
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
