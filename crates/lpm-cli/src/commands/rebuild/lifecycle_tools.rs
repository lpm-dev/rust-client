use lpm_linker::v2::{LifecycleBin, LifecycleBinProvider, create_lifecycle_bin_links};
use lpm_store::v2::LinkMeta;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub(super) struct LifecycleTools {
    pub(super) bin_dir: PathBuf,
    pub(super) bins: Vec<LifecycleBin>,
    pub(super) read_dirs: Vec<PathBuf>,
    pub(super) graph_identities: Vec<String>,
    pub(super) has_nested_dependency: bool,
}

impl LifecycleTools {
    pub(super) fn prepare(
        package_dir: &Path,
        graph_digest: Option<&str>,
        links_root: &Path,
        scratch: &Path,
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
        while let Some((directory, mut metadata)) = queue.pop() {
            metadata.deps.sort_unstable_by(|a, b| a.local.cmp(&b.local));
            let node_modules = graph_node_modules(&directory)?;
            for edge in &metadata.deps {
                lpm_store::v2::link_meta::validate_name_for_path_join(&edge.local)
                    .map_err(str::to_string)?;
                let slot = if edge.local == metadata.name {
                    directory.join("node_modules").join(&edge.local)
                } else {
                    node_modules.join(&edge.local)
                };
                let provider = match slot.canonicalize() {
                    Ok(provider) => provider,
                    Err(error) => {
                        return Err(format!(
                            "cannot resolve lifecycle dependency {}: {error}",
                            edge.local
                        ));
                    }
                };
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
                    providers.push((provider_meta.name.clone(), provider.clone()));
                }
                if visited.insert(provider.clone()) {
                    tools.graph_identities.push(format!(
                        "{}\0{}",
                        provider.display(),
                        provider_meta.graph_key_digest_hex
                    ));
                    tools.read_dirs.push(provider.clone());
                    queue.push((provider, provider_meta));
                }
            }
        }
        let provider_refs = providers
            .iter()
            .map(|(name, directory)| LifecycleBinProvider { name, directory })
            .collect::<Vec<_>>();
        tools.bins = create_lifecycle_bin_links(&tools.bin_dir, &provider_refs)
            .map_err(|e| e.to_string())?;
        tools.read_dirs.push(tools.bin_dir.clone());
        tools.read_dirs.sort_unstable();
        tools.graph_identities.sort_unstable();
        Ok(tools)
    }
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
