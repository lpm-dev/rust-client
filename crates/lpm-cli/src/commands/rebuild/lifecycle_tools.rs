use lpm_linker::v2::{LifecycleBin, LifecycleBinProvider, create_lifecycle_bin_links};
use lpm_security::reach::{ReachFinding, ScriptReach};
use lpm_security::static_gate::{GREEN_TOOLS, GreenTool, green_tools_in};
use lpm_store::v2::LinkMeta;
use lpm_store::v2::link_meta::LinkMetaDep;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The registry packages of an install, as its lockfile pins them. A
/// dependency reached through a tarball URL, a git repository or a directory
/// can carry any name, so only a member of this set is the package the
/// registry publishes under its name.
pub(crate) struct RegistryPackages(HashSet<(String, String, String)>);

impl RegistryPackages {
    pub(crate) fn of(lockfile: &lpm_lockfile::Lockfile) -> Self {
        Self(
            lockfile
                .packages
                .iter()
                .filter(|package| {
                    package
                        .source
                        .as_deref()
                        .and_then(|source| lpm_lockfile::Source::parse(source).ok())
                        .is_some_and(|source| {
                            matches!(source, lpm_lockfile::Source::Registry { .. })
                        })
                })
                .filter_map(|package| {
                    Some((
                        package.name.clone(),
                        package.version.clone(),
                        package.integrity.clone()?,
                    ))
                })
                .collect(),
        )
    }

    fn publishes(&self, package: &LinkMeta) -> bool {
        self.0.contains(&(
            package.name.clone(),
            package.version.clone(),
            package.source_sri.clone(),
        ))
    }
}

/// Which package commands a lifecycle script finds on its `PATH`.
pub(super) enum ToolScope<'a> {
    /// Every command the package's direct dependencies declare, then the
    /// project's own, as npm runs a lifecycle script. For a package the
    /// user approved.
    Dependencies,
    /// Only the tools of the green allowlist, each from a registry package
    /// that publishes it: one of the package's direct dependencies, or
    /// else one of the project's. For a package that runs on its green
    /// tier alone, which says what the command's text is, not which
    /// package answers to its name. No other package's command is on the
    /// `PATH`, so none can stand in for the tool or for a program the tool
    /// starts.
    GreenTools {
        registry_packages: &'a RegistryPackages,
        project_dir: &'a Path,
    },
}

pub(super) struct LifecycleTools {
    pub(super) bin_dir: PathBuf,
    pub(super) bins: Vec<LifecycleBin>,
    pub(super) read_dirs: Vec<PathBuf>,
    pub(super) graph_identities: Vec<String>,
    pub(super) has_nested_dependency: bool,
    /// Whether the project's `node_modules/.bin` follows `bin_dir` on the
    /// script's `PATH`.
    pub(super) project_bins: bool,
}

struct Provider {
    name: String,
    directory: PathBuf,
    commands: Option<Vec<&'static str>>,
}

impl LifecycleTools {
    pub(super) fn prepare(
        package_dir: &Path,
        graph_digest: Option<&str>,
        links_root: &Path,
        scratch: &Path,
        scope: ToolScope<'_>,
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
        };
        let Some(graph_digest) = graph_digest else {
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
        let mut queue = vec![(package_dir.clone(), metadata)];
        let mut visited = HashSet::new();
        visited.insert(package_dir.clone());
        if let ToolScope::GreenTools {
            registry_packages,
            project_dir,
        } = &scope
        {
            // Seeded before the walk so the project's providers, and what
            // they depend on, are readable in the sandbox like the package's
            // own. They are linked after the package's, so its own win.
            for (name, commands) in green_tool_publishers() {
                let Ok(directory) = project_dir.join("node_modules").join(name).canonicalize()
                else {
                    continue;
                };
                let Ok(provider) = read_graph(&directory, &root) else {
                    continue;
                };
                if provider.name != name || !registry_packages.publishes(&provider) {
                    continue;
                }
                if visited.insert(directory.clone()) {
                    tools.record_dependency(&directory, &provider);
                    queue.push((directory.clone(), provider));
                }
                providers.push((
                    false,
                    Provider {
                        name: name.to_string(),
                        directory,
                        commands: Some(commands),
                    },
                ));
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
                    let commands = match &scope {
                        ToolScope::Dependencies => Some(None),
                        ToolScope::GreenTools {
                            registry_packages, ..
                        } => Some(published_green_commands(&provider_meta.name))
                            .filter(|commands| !commands.is_empty())
                            .filter(|_| registry_packages.publishes(&provider_meta))
                            .map(Some),
                    };
                    if let Some(commands) = commands {
                        providers.push((
                            true,
                            Provider {
                                name: provider_meta.name.clone(),
                                directory: provider.clone(),
                                commands,
                            },
                        ));
                    }
                }
                if visited.insert(provider.clone()) {
                    tools.record_dependency(&provider, &provider_meta);
                    queue.push((provider, provider_meta));
                }
            }
        }
        // The package's own dependencies answer first; `sort_by_key` keeps
        // the order within each group.
        providers.sort_by_key(|(own, _)| !own);
        let provider_refs = providers
            .iter()
            .map(|(_, provider)| LifecycleBinProvider {
                name: &provider.name,
                directory: &provider.directory,
                commands: provider.commands.as_deref(),
            })
            .collect::<Vec<_>>();
        tools.bins = create_lifecycle_bin_links(&tools.bin_dir, &provider_refs)
            .map_err(|e| e.to_string())?;
        tools.read_dirs.push(tools.bin_dir.clone());
        tools.read_dirs.sort_unstable();
        tools.graph_identities.sort_unstable();
        Ok(tools)
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

/// Each package that publishes a green tool, with the tools it publishes.
fn green_tool_publishers() -> impl Iterator<Item = (&'static str, Vec<&'static str>)> {
    let mut names: Vec<&'static str> = GREEN_TOOLS
        .iter()
        .flat_map(|tool| tool.providers.iter().copied())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
        .into_iter()
        .map(|name| (name, published_green_commands(name)))
}

fn published_green_commands(package: &str) -> Vec<&'static str> {
    GREEN_TOOLS
        .iter()
        .filter(|tool| tool.providers.contains(&package))
        .map(|tool| tool.command)
        .collect()
}

/// Where the dependency `edge` of the package `name` at `directory` is linked.
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
/// one of its installed dependencies would supply without being a publisher
/// of that tool.
///
/// The second part goes by the dependency's name alone, since the lockfile
/// isn't at hand everywhere a package is classified. A package that only
/// carries a publisher's name, without being the registry's, passes here
/// and is still left off the `PATH` of a green run by
/// [`ToolScope::GreenTools`].
pub(crate) fn script_reach(package_dir: &Path, phase_bodies: &[(String, String)]) -> ScriptReach {
    let mut reach = lpm_security::reach::analyze(package_dir, phase_bodies);
    let mut tools: Vec<&'static GreenTool> = Vec::new();
    for (_, body) in phase_bodies {
        for tool in green_tools_in(body) {
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
    }
    if !tools.is_empty() {
        reach
            .findings
            .extend(tools_from_other_packages(package_dir, &tools));
    }
    reach
}

fn tools_from_other_packages(
    package_dir: &Path,
    tools: &[&'static GreenTool],
) -> Vec<ReachFinding> {
    // A package outside the virtual store has no dependency tool directory:
    // its scripts find commands on the project's and the system's `PATH`.
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
        for tool in tools {
            if tool.providers.contains(&edge.target_name.as_str())
                || !commands.iter().any(|(name, _)| name == tool.command)
                || findings.iter().any(|finding| {
                    matches!(finding, ReachFinding::RunsToolFromOtherPackage { command, .. } if command == tool.command)
                })
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
