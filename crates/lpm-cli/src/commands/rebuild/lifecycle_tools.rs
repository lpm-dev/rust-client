use lpm_linker::v2::{LifecycleBin, LifecycleBinProvider, create_lifecycle_bin_links};
use lpm_security::reach::{ReachFinding, ScriptReach};
use lpm_security::static_gate::{GREEN_TOOLS, GreenTool, green_tool, green_tools_in};
use lpm_store::v2::LinkMeta;
use lpm_store::v2::link_meta::LinkMetaDep;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::bundled_node_gyp::BundledNodeGyp;

const NODE_GYP: &str = "node-gyp";

/// What a failed build is told when [`LifecycleTools::lacks_node_gyp`].
pub(super) const NODE_GYP_MISSING: &str = "this build needs node-gyp and none was found: add node-gyp to the project's devDependencies, or put a Node on PATH that has npm installed beside it (a version manager's shim has none)";

/// The registry packages of an install, as its lockfile pins them. A
/// dependency reached through a tarball URL, a git repository or a directory
/// can carry any name, so only a member of this set is the package the
/// registry publishes under its name.
#[derive(Default)]
pub(crate) struct RegistryPackages(HashSet<(String, String, String)>);

impl RegistryPackages {
    pub(crate) fn of(lockfile: &lpm_lockfile::Lockfile) -> Self {
        Self::new(
            lockfile
                .packages
                .iter()
                // A row without a source is a registry package, as the
                // lockfile's own graph validation reads it.
                .filter(|package| {
                    matches!(
                        package.source_kind(),
                        None | Some(Ok(lpm_lockfile::Source::Registry { .. }))
                    )
                })
                .filter_map(|package| {
                    Some((
                        package.name.clone(),
                        package.version.clone(),
                        package.integrity.clone()?,
                    ))
                }),
        )
    }

    /// From `(name, version, integrity)` of each registry package.
    pub(crate) fn new(packages: impl IntoIterator<Item = (String, String, String)>) -> Self {
        Self(packages.into_iter().collect())
    }

    fn publishes(&self, package: &LinkMeta) -> bool {
        self.0.contains(&(
            package.name.clone(),
            package.version.clone(),
            package.source_sri.clone(),
        ))
    }
}

/// Whether the installed `package` is a registry package that publishes
/// `tool`. Without the install's registry packages, none is known to be.
fn publishes_tool(
    tool: &GreenTool,
    package: &LinkMeta,
    registry_packages: Option<&RegistryPackages>,
) -> bool {
    tool.providers.contains(&package.name.as_str())
        && registry_packages.is_some_and(|registry| registry.publishes(package))
}

/// The green commands a package of this name does not publish, which it
/// therefore may not supply even to a script that trusts its other commands.
fn green_commands_of_other_packages(package: &str) -> Vec<&'static str> {
    GREEN_TOOLS
        .iter()
        .filter(|tool| !tool.providers.contains(&package))
        .map(|tool| tool.command)
        .collect()
}

/// The project's own installs of the packages that publish green tools: for
/// each link directory, the tool publisher installed there. Taken from the
/// lockfile's root selections, so a compatibility copy under the project's
/// `node_modules` doesn't stand in for the store entry.
pub(super) fn project_tool_publishers(
    lockfile: &lpm_lockfile::Lockfile,
    package_dir_of: impl Fn(lpm_common::PackageInstanceId) -> Option<PathBuf>,
) -> Vec<PathBuf> {
    lockfile
        .root_resolutions
        .values()
        .filter(|root| {
            GREEN_TOOLS
                .iter()
                .any(|tool| tool.providers.contains(&root.package.as_str()))
        })
        .filter_map(|root| package_dir_of(root.instance_id?))
        .collect()
}

/// Which package commands a lifecycle script finds on its `PATH`.
pub(super) enum ToolScope<'a> {
    /// Every command the package's direct dependencies declare, then the
    /// project's own, as npm runs a lifecycle script. For a package the
    /// user approved.
    Dependencies,
    /// Only the commands of registry packages that publish a green tool:
    /// those among the package's direct dependencies, then the project's
    /// installs of the publishers of the tools `scripts` name. For a
    /// package that runs on its green tier alone, which says what the
    /// command's text is, not which package answers to its name. A green
    /// tool's name is taken only from its own publisher. No other
    /// package's command is linked, so none can stand in for the tool or
    /// for a program the tool starts.
    GreenTools {
        registry_packages: &'a RegistryPackages,
        project_publishers: &'a [PathBuf],
        scripts: &'a HashMap<String, String>,
    },
}

pub(super) struct LifecycleTools {
    pub(super) bin_dir: PathBuf,
    pub(super) bins: Vec<LifecycleBin>,
    pub(super) read_dirs: Vec<PathBuf>,
    pub(super) graph_identities: Vec<String>,
    pub(super) has_nested_dependency: bool,
    /// Whether the script's `PATH` is npm's: the project's
    /// `node_modules/.bin` and the caller's own entries follow `bin_dir`.
    /// Otherwise only the caller's entries outside any package follow it.
    pub(super) project_bins: bool,
    /// npm's own `node-gyp`, when the script may need one and no installed
    /// package supplies it.
    pub(super) node_gyp: Option<OfferedNodeGyp>,
}

/// npm's own `node-gyp` as a script gets it: a command in a directory of
/// its own, which goes on `PATH` after every command a package supplies.
pub(super) struct OfferedNodeGyp {
    pub(super) command_dir: PathBuf,
    /// What npm names to scripts as `npm_config_node_gyp`.
    pub(super) script: PathBuf,
    /// npm's modules, which hold the command's code and what it requires.
    pub(super) modules: PathBuf,
    /// What a sandboxed script must read to run the command.
    pub(super) read_dirs: Vec<PathBuf>,
}

struct Provider {
    name: String,
    directory: PathBuf,
    except: Vec<&'static str>,
}

impl LifecycleTools {
    pub(super) fn prepare(
        package_dir: &Path,
        graph_digest: Option<&str>,
        links_root: &Path,
        scratch: &Path,
        scope: ToolScope<'_>,
        host_tools: Option<&OsStr>,
    ) -> Result<Self, String> {
        let bin_dir = scratch
            .canonicalize()
            .map_err(|e| e.to_string())?
            .join("bin");
        let mut tools = Self {
            bin_dir,
            bins: Vec::new(),
            read_dirs: Vec::new(),
            graph_identities: Vec::new(),
            has_nested_dependency: false,
            project_bins: matches!(scope, ToolScope::Dependencies),
            node_gyp: None,
        };
        // An approved script may start `node-gyp` from anywhere in what it
        // runs. A script that runs on its green tier starts only the tools
        // its commands name.
        let may_need_node_gyp = match &scope {
            ToolScope::Dependencies => true,
            ToolScope::GreenTools { scripts, .. } => tools_a_run_needs(scripts)
                .iter()
                .any(|tool| tool.command == NODE_GYP),
        };
        let Some(graph_digest) = graph_digest else {
            tools.offer_node_gyp(may_need_node_gyp, host_tools)?;
            return Ok(tools);
        };
        let root = links_root.canonicalize().map_err(|e| e.to_string())?;
        let package_dir = package_dir.canonicalize().map_err(|e| e.to_string())?;
        let metadata = read_graph(&package_dir, &root)?;
        if metadata.graph_key_digest_hex != graph_digest {
            return Err("lifecycle package graph identity changed".into());
        }
        tools.has_nested_dependency = metadata.deps.iter().any(|edge| edge.local == metadata.name);
        let mut providers = Vec::with_capacity(metadata.deps.len());
        let mut project_providers = Vec::new();
        let mut queue = vec![(package_dir.clone(), metadata)];
        let mut visited = HashSet::new();
        visited.insert(package_dir.clone());
        if let ToolScope::GreenTools {
            registry_packages,
            project_publishers,
            scripts,
        } = &scope
        {
            let needed = tools_a_run_needs(scripts);
            // Queued before the walk so the project's providers, and what
            // they depend on, are readable in the sandbox like the package's
            // own. An install that doesn't check out is left out.
            for directory in *project_publishers {
                let Ok(directory) = directory.canonicalize() else {
                    continue;
                };
                let Ok(provider) = read_graph(&directory, &root) else {
                    continue;
                };
                if !needed
                    .iter()
                    .any(|tool| publishes_tool(tool, &provider, Some(registry_packages)))
                {
                    continue;
                }
                project_providers.push(Provider {
                    except: green_commands_of_other_packages(&provider.name),
                    name: provider.name.clone(),
                    directory: directory.clone(),
                });
                if visited.insert(directory.clone()) {
                    tools.record_dependency(&directory, &provider);
                    queue.push((directory, provider));
                }
            }
        }
        while let Some((directory, mut metadata)) = queue.pop() {
            metadata.deps.sort_unstable_by(|a, b| a.local.cmp(&b.local));
            for edge in &metadata.deps {
                let provider = dependency_slot(&directory, &metadata.name, edge)?
                    .canonicalize()
                    .map_err(|error| {
                        format!(
                            "cannot resolve lifecycle dependency {}: {error}",
                            edge.local
                        )
                    })?;
                let provider_meta = read_graph(&provider, &root)?;
                if provider_meta.graph_key_digest_hex != edge.target_graph_key
                    || provider_meta.name != edge.target_name
                    || provider_meta.version != edge.target_version
                {
                    return Err(format!(
                        "lifecycle dependency {} does not match its installed graph",
                        edge.local
                    ));
                }
                if directory == package_dir {
                    let except = match &scope {
                        ToolScope::Dependencies => Some(Vec::new()),
                        ToolScope::GreenTools {
                            registry_packages, ..
                        } => GREEN_TOOLS
                            .iter()
                            .any(|tool| {
                                publishes_tool(tool, &provider_meta, Some(registry_packages))
                            })
                            .then(|| green_commands_of_other_packages(&provider_meta.name)),
                    };
                    if let Some(except) = except {
                        providers.push(Provider {
                            name: provider_meta.name.clone(),
                            directory: provider.clone(),
                            except,
                        });
                    }
                }
                if visited.insert(provider.clone()) {
                    tools.record_dependency(&provider, &provider_meta);
                    queue.push((provider, provider_meta));
                }
            }
        }
        // The package's own dependencies answer before the project's, and
        // dependencies bundled inside `<pkg>/node_modules/` answer as a
        // fallback for approved lifecycle scripts (e.g. bundled `node-pre-gyp`).
        providers.append(&mut project_providers);
        if matches!(scope, ToolScope::Dependencies) {
            append_bundled_providers(&package_dir, &mut providers);
        }
        let provider_refs = providers
            .iter()
            .map(|provider| LifecycleBinProvider {
                name: &provider.name,
                directory: &provider.directory,
                except: &provider.except,
            })
            .collect::<Vec<_>>();
        tools.bins = create_lifecycle_bin_links(&tools.bin_dir, &provider_refs)
            .map_err(|e| e.to_string())?;
        tools.read_dirs.push(tools.bin_dir.clone());
        tools.read_dirs.sort_unstable();
        tools.graph_identities.sort_unstable();
        tools.offer_node_gyp(may_need_node_gyp, host_tools)?;
        Ok(tools)
    }

    /// Offers the `node-gyp` of the npm beside the host's `node`, as npm
    /// does for the scripts it runs, unless a dependency supplies one.
    /// `host_tools` is the caller's `PATH` without the entries that hold a
    /// package's commands.
    fn offer_node_gyp(&mut self, may_need: bool, host_tools: Option<&OsStr>) -> Result<(), String> {
        if !may_need || self.bins.iter().any(|bin| bin.name == NODE_GYP) {
            return Ok(());
        }
        let Some(bundled) = host_tools.and_then(BundledNodeGyp::beside_node_on) else {
            return Ok(());
        };
        let command_dir = self.bin_dir.with_file_name("node-gyp-bin");
        self.bins.push(
            bundled
                .write_command(&command_dir)
                .map_err(|error| format!("cannot offer npm's node-gyp: {error}"))?,
        );
        let mut read_dirs = vec![command_dir.clone()];
        // On Windows npm sits inside the directory that holds `node.exe`,
        // which a sandboxed script reads as a tool directory already.
        if !cfg!(windows) {
            read_dirs.push(bundled.modules.clone());
        }
        self.node_gyp = Some(OfferedNodeGyp {
            command_dir,
            script: bundled.script,
            modules: bundled.modules,
            read_dirs,
        });
        Ok(())
    }

    /// Whether `scripts` lead to `node-gyp` and nothing supplies it: no
    /// dependency, no npm beside `node`, and no command where the script
    /// looks, which for a script with npm's `PATH` includes the project's
    /// own commands.
    pub(super) fn lacks_node_gyp(
        &self,
        scripts: &HashMap<String, String>,
        project_dir: &Path,
        host_path: Option<&OsStr>,
    ) -> bool {
        let commands: &[&str] = if cfg!(windows) {
            &["node-gyp.cmd", "node-gyp.exe", "node-gyp.bat"]
        } else {
            &[NODE_GYP]
        };
        let project_bin = self
            .project_bins
            .then(|| project_dir.join("node_modules").join(".bin"));
        let mut searched = project_bin
            .into_iter()
            .chain(host_path.into_iter().flat_map(std::env::split_paths));
        tools_a_run_needs(scripts)
            .iter()
            .any(|tool| tool.command == NODE_GYP)
            && !self.bins.iter().any(|bin| bin.name == NODE_GYP)
            && !searched.any(|directory| {
                commands
                    .iter()
                    .any(|command| directory.join(command).is_file())
            })
    }

    /// Every directory a sandboxed script reads to run the commands it is
    /// given.
    pub(super) fn sandbox_read_dirs(&self) -> Vec<PathBuf> {
        let offered = self.node_gyp.iter().flat_map(|offered| &offered.read_dirs);
        self.read_dirs.iter().chain(offered).cloned().collect()
    }

    fn record_dependency(&mut self, directory: &Path, metadata: &LinkMeta) {
        self.graph_identities.push(format!(
            "{}\0{}",
            directory.display(),
            metadata.graph_key_digest_hex
        ));
        self.read_dirs.push(directory.to_path_buf());
    }
}

/// The green tools the lifecycle commands of `scripts` name, and the green
/// tools those start.
fn tools_a_run_needs(scripts: &HashMap<String, String>) -> Vec<&'static GreenTool> {
    let mut tools = named_green_tools(scripts.values().map(String::as_str));
    let mut next = 0;
    while let Some(tool) = tools.get(next).copied() {
        for started in tool.starts.iter().filter_map(|command| green_tool(command)) {
            if !tools.contains(&started) {
                tools.push(started);
            }
        }
        next += 1;
    }
    tools
}

fn named_green_tools<'a>(scripts: impl Iterator<Item = &'a str>) -> Vec<&'static GreenTool> {
    let mut tools: Vec<&'static GreenTool> = Vec::new();
    for script in scripts {
        for tool in green_tools_in(script) {
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
    }
    tools
}

/// Where the dependency `edge` of the package `name` at `directory` is linked.
fn append_bundled_providers(package_dir: &Path, providers: &mut Vec<Provider>) {
    let bundled_root = package_dir.join("node_modules");
    let Ok(entries) = std::fs::read_dir(&bundled_root) else {
        return;
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_dir() {
            continue;
        }
        if name.starts_with('@') {
            let Ok(scoped_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for scoped in scoped_entries.flatten() {
                let scoped_name = scoped.file_name().to_string_lossy().into_owned();
                if scoped_name.starts_with('.') {
                    continue;
                }
                let scoped_path = scoped.path();
                if std::fs::symlink_metadata(&scoped_path).is_ok_and(|m| m.file_type().is_dir())
                    && scoped_path.join("package.json").is_file()
                {
                    dirs.push((format!("{name}/{scoped_name}"), scoped_path));
                }
            }
        } else if path.join("package.json").is_file() {
            dirs.push((name, path));
        }
    }
    dirs.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for (name, directory) in dirs {
        providers.push(Provider {
            name,
            directory,
            except: Vec::new(),
        });
    }
}

fn dependency_slot(directory: &Path, name: &str, edge: &LinkMetaDep) -> Result<PathBuf, String> {
    lpm_store::v2::link_meta::validate_name_for_path_join(&edge.local).map_err(str::to_string)?;
    Ok(if edge.local == name {
        directory.join("node_modules").join(&edge.local)
    } else {
        graph_node_modules(directory)?.join(&edge.local)
    })
}

/// What a package's install-time code reaches beyond the package: the scan
/// of its own files, and each green tool its lifecycle commands name that
/// one of its installed dependencies would supply without being the
/// registry package that publishes the tool.
///
/// `registry_packages` are the install's, by which a green run chooses its
/// tools too. Without them no dependency counts as a publisher, so every
/// dependency that declares the tool is reported.
pub(crate) fn script_reach(
    package_dir: &Path,
    phase_bodies: &[(String, String)],
    registry_packages: Option<&RegistryPackages>,
) -> ScriptReach {
    let mut reach = lpm_security::reach::analyze(package_dir, phase_bodies);
    let tools = named_green_tools(phase_bodies.iter().map(|(_, body)| body.as_str()));
    if !tools.is_empty() {
        reach.findings.extend(tools_from_other_packages(
            package_dir,
            &tools,
            registry_packages,
        ));
    }
    reach
}

fn tools_from_other_packages(
    package_dir: &Path,
    tools: &[&'static GreenTool],
    registry_packages: Option<&RegistryPackages>,
) -> Vec<ReachFinding> {
    // A package outside the virtual store has no dependency tool directory:
    // no dependency's command is put on its scripts' `PATH`.
    let Ok(package_dir) = package_dir.canonicalize() else {
        return Vec::new();
    };
    let Some(mut metadata) = read_link_meta(&package_dir) else {
        return Vec::new();
    };
    metadata.deps.sort_unstable_by(|a, b| a.local.cmp(&b.local));
    let mut findings: Vec<ReachFinding> = Vec::new();
    for edge in &metadata.deps {
        let Ok(slot) = dependency_slot(&package_dir, &metadata.name, edge) else {
            continue;
        };
        let Ok(content) = lpm_common::read_file_capped(
            &slot.join("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) else {
            continue;
        };
        let Ok(Some(bins)) = lpm_workspace::parse_bin_field(&content) else {
            continue;
        };
        let commands = bins.entries(&edge.target_name);
        let provider = slot
            .canonicalize()
            .ok()
            .and_then(|directory| read_link_meta(&directory));
        for tool in tools {
            let reported = findings.iter().any(|finding| {
                matches!(
                    finding,
                    ReachFinding::RunsToolFromOtherPackage { command, .. }
                        if command == tool.command
                )
            });
            if reported
                || !commands.iter().any(|(name, _)| tool.is_named(name))
                || provider
                    .as_ref()
                    .is_some_and(|provider| publishes_tool(tool, provider, registry_packages))
            {
                continue;
            }
            findings.push(ReachFinding::RunsToolFromOtherPackage {
                command: tool.command.to_string(),
                provider: format!("{}@{}", edge.target_name, edge.target_version),
            });
        }
    }
    findings
}

fn read_link_meta(package_dir: &Path) -> Option<LinkMeta> {
    let node_modules = graph_node_modules(package_dir).ok()?;
    let metadata = LinkMeta::read_from(node_modules.parent()?).ok()?;
    (node_modules.join(&metadata.name) == package_dir).then_some(metadata)
}

fn graph_node_modules(directory: &Path) -> Result<&Path, String> {
    directory
        .ancestors()
        .find(|p| p.file_name().is_some_and(|name| name == "node_modules"))
        .ok_or_else(|| "lifecycle package has no dependency directory".to_string())
}

fn read_graph(directory: &Path, links_root: &Path) -> Result<LinkMeta, String> {
    let node_modules = graph_node_modules(directory)?;
    let link_dir = node_modules
        .parent()
        .ok_or_else(|| "lifecycle package has no link directory".to_string())?;
    if link_dir.parent() != Some(links_root) {
        return Err("lifecycle dependency is outside the selected virtual store".into());
    }
    let meta = LinkMeta::read_from(link_dir).map_err(|e| e.to_string())?;
    if node_modules.join(&meta.name) != directory
        || link_dir.file_name() != Some(std::ffi::OsStr::new(&meta.graph_key))
    {
        return Err("lifecycle dependency path does not match its graph metadata".into());
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_bundled_providers_discovers_scoped_and_unscoped_bundled_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("host");
        let unscoped = pkg_dir.join("node_modules/bundled-tool");
        let scoped = pkg_dir.join("node_modules/@scope/bundled-cli");
        let hidden = pkg_dir.join("node_modules/.bin");
        let no_manifest = pkg_dir.join("node_modules/incomplete");
        std::fs::create_dir_all(&unscoped).unwrap();
        std::fs::create_dir_all(&scoped).unwrap();
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::create_dir_all(&no_manifest).unwrap();
        std::fs::write(
            unscoped.join("package.json"),
            r#"{"name":"bundled-tool","version":"1.0.0","bin":"cli.js"}"#,
        )
        .unwrap();
        std::fs::write(
            scoped.join("package.json"),
            r#"{"name":"@scope/bundled-cli","version":"1.0.0","bin":"bin.js"}"#,
        )
        .unwrap();

        let mut providers = Vec::new();
        append_bundled_providers(&pkg_dir, &mut providers);

        let names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["@scope/bundled-cli", "bundled-tool"]);
    }
}
