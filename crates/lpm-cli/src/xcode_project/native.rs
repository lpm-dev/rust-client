use super::*;
use std::collections::BTreeMap;
use std::process::Command;

pub(crate) struct Container {
    path: PathBuf,
    workspace: bool,
}

impl Container {
    pub(crate) fn lockfile(&self) -> PathBuf {
        if self.workspace {
            self.path.join("xcshareddata/swiftpm/Package.resolved")
        } else {
            self.path
                .join("project.xcworkspace/xcshareddata/swiftpm/Package.resolved")
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("xcodebuild");
        crate::swift_manifest::sanitize_swift_environment(&mut command);
        command
            .arg(if self.workspace {
                "-workspace"
            } else {
                "-project"
            })
            .arg(&self.path);
        command
    }
}

pub(crate) fn containers(directory: &Path, project: &Path) -> Result<Vec<Container>, LpmError> {
    let canonical = project
        .canonicalize()
        .map_err(|e| LpmError::Registry(e.to_string()))?;
    let boundary = directory
        .canonicalize()
        .map_err(|e| LpmError::Registry(e.to_string()))?;
    let mut parent = project.parent();
    let mut containers = Vec::new();
    while let Some(directory) = parent {
        for entry in std::fs::read_dir(directory).map_err(|e| LpmError::Registry(e.to_string()))? {
            let path = entry.map_err(|e| LpmError::Registry(e.to_string()))?.path();
            if path.extension() == Some(std::ffi::OsStr::new("xcworkspace"))
                && workspace_projects(&path)?
                    .iter()
                    .any(|p| p.canonicalize().is_ok_and(|p| p == canonical))
            {
                containers.push(Container {
                    path,
                    workspace: true,
                });
            }
        }
        if directory
            .canonicalize()
            .is_ok_and(|p| p == boundary || !p.starts_with(&boundary))
        {
            break;
        }
        parent = directory.parent();
    }
    let project_container = Container {
        path: project.to_owned(),
        workspace: false,
    };
    containers.push(project_container);
    containers.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(containers)
}

fn output(command: Command, operation: &str) -> Result<Vec<u8>, LpmError> {
    let result = crate::swift_manifest::run_bounded_swift_output(command, operation)?;
    if !result.status.success() {
        let diagnostic = if result.stderr.is_empty() {
            &result.stdout
        } else {
            &result.stderr
        };
        return Err(LpmError::Registry(format!(
            "{operation} failed: {}",
            lpm_common::sanitize_terminal_inline(&String::from_utf8_lossy(diagnostic))
        )));
    }
    Ok(result.stdout)
}

fn json(command: Command, operation: &str) -> Result<serde_json::Value, LpmError> {
    serde_json::from_slice(&output(command, operation)?)
        .map_err(|e| LpmError::Registry(format!("Invalid {operation} JSON: {e}")))
}

pub(crate) fn resolve(containers: &[Container]) -> Result<(), LpmError> {
    for container in containers {
        let schemes = if container.workspace {
            let mut command = container.command();
            command.args(["-list", "-json", "-skipPackageUpdates"]);
            let listing = json(command, "Xcode scheme discovery")?;
            let mut schemes = listing["workspace"]["schemes"]
                .as_array()
                .ok_or_else(|| LpmError::Registry("Xcode workspace did not report schemes".into()))?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>();
            schemes.sort();
            schemes.dedup();
            if schemes.is_empty() || schemes.len() > 128 {
                return Err(LpmError::Registry(
                    "Xcode workspace must expose between 1 and 128 schemes for package resolution"
                        .into(),
                ));
            }
            schemes
        } else {
            vec![String::new()]
        };
        for scheme in schemes {
            let mut command = container.command();
            command.args(["-resolvePackageDependencies", "-skipPackageUpdates"]);
            if !scheme.is_empty() {
                command.arg("-scheme").arg(scheme);
            }
            output(command, "Xcode package resolution")?;
        }
    }
    Ok(())
}

pub(super) fn deployment_targets(
    project: &Path,
    target: &str,
) -> Result<BTreeMap<String, String>, LpmError> {
    let container = Container {
        path: project.to_owned(),
        workspace: false,
    };
    let mut command = container.command();
    command.args(["-list", "-json", "-skipPackageUpdates"]);
    let listing = json(command, "Xcode configuration discovery")?;
    let configurations = listing["project"]["configurations"]
        .as_array()
        .ok_or_else(|| {
            LpmError::Registry("Xcode project did not report build configurations".into())
        })?;
    if configurations.is_empty() || configurations.len() > 128 {
        return Err(LpmError::Registry(
            "Xcode project must expose between 1 and 128 build configurations".into(),
        ));
    }
    let mut platforms = BTreeMap::<String, String>::new();
    for configuration in configurations {
        let name = configuration
            .as_str()
            .ok_or_else(|| LpmError::Registry("Invalid Xcode build configuration".into()))?;
        let mut command = container.command();
        command.args([
            "-showBuildSettings",
            "-json",
            "-target",
            target,
            "-configuration",
            name,
            "-skipPackageUpdates",
        ]);
        let settings = json(command, "Xcode build settings")?;
        let settings = settings
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row["target"].as_str() == Some(target))
            })
            .and_then(|row| row["buildSettings"].as_object())
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "Xcode did not report settings for {target} ({name})"
                ))
            })?;
        for (key, platform) in DEPLOYMENT_PLATFORMS {
            let sdk = match *platform {
                "macOS" => ["macosx", "macosx"],
                "iOS" => ["iphoneos", "iphonesimulator"],
                "tvOS" => ["appletvos", "appletvsimulator"],
                "watchOS" => ["watchos", "watchsimulator"],
                "visionOS" => ["xros", "xrsimulator"],
                _ => continue,
            };
            if settings
                .get("SUPPORTED_PLATFORMS")
                .and_then(|v| v.as_str())
                .is_some_and(|supported| {
                    !supported
                        .split_whitespace()
                        .any(|platform| sdk.contains(&platform))
                })
            {
                continue;
            }
            if let Some(value) = settings
                .get(*key)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
            {
                if deployment_version(value).is_none() {
                    return Err(LpmError::Registry(format!(
                        "Unresolved {key} for {target} ({name}): {value}"
                    )));
                }
                let entry = platforms
                    .entry((*platform).to_owned())
                    .or_insert_with(|| value.to_owned());
                if deployment_version(value) < deployment_version(entry) {
                    *entry = value.to_owned();
                }
            }
        }
    }
    Ok(platforms)
}
