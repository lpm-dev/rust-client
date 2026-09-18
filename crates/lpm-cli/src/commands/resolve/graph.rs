use crate::install_ui;
use lpm_common::{LpmError, ResolutionNodeId};
use lpm_resolver::{ResolvedPackage, RootResolution};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;

#[derive(Clone, Copy)]
struct Edge<'a> {
    local: &'a str,
    target: ResolutionNodeId,
    peer: bool,
}

pub(super) struct Graph<'a> {
    nodes: BTreeMap<ResolutionNodeId, &'a ResolvedPackage>,
    edges: HashMap<ResolutionNodeId, Vec<Edge<'a>>>,
}

pub(super) struct RenderLimits {
    pub depth: usize,
    pub rows: usize,
    pub bytes: usize,
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self {
            depth: 128,
            rows: 10_000,
            bytes: 2 * 1024 * 1024,
        }
    }
}

impl<'a> Graph<'a> {
    pub fn new(packages: &'a [ResolvedPackage]) -> Result<Self, LpmError> {
        let mut nodes = BTreeMap::new();
        for package in packages {
            if package.resolution_id == ResolutionNodeId::UNASSIGNED
                || nodes.insert(package.resolution_id, package).is_some()
            {
                return Err(graph_error("duplicate or unassigned package identity"));
            }
        }
        let mut edges = HashMap::with_capacity(nodes.len());
        for (&id, package) in &nodes {
            for (local, _) in &package.dependencies {
                if !package.dependency_targets.contains_key(local) {
                    return Err(graph_error("dependency has no exact target"));
                }
            }
            let mut children =
                Vec::with_capacity(package.dependency_targets.len() + package.peer_targets.len());
            for (peer, targets) in [
                (false, &package.dependency_targets),
                (true, &package.peer_targets),
            ] {
                for (local, &target) in targets {
                    if !nodes.contains_key(&target) {
                        return Err(graph_error("edge references a missing package"));
                    }
                    children.push(Edge {
                        local,
                        target,
                        peer,
                    });
                }
            }
            children.sort_unstable_by(|a, b| a.local.cmp(b.local).then(a.peer.cmp(&b.peer)));
            edges.insert(id, children);
        }
        Ok(Self { nodes, edges })
    }

    pub fn roots<'b>(
        &self,
        requested: &'b [String],
        resolutions: &HashMap<String, RootResolution>,
    ) -> Result<Vec<(&'b str, ResolutionNodeId)>, LpmError> {
        requested
            .iter()
            .map(|local| {
                let root = resolutions
                    .get(local)
                    .ok_or_else(|| graph_error("requested root has no exact target"))?;
                if !self.nodes.contains_key(&root.target) {
                    return Err(graph_error("root references a missing package"));
                }
                Ok((local.as_str(), root.target))
            })
            .collect()
    }

    pub fn packages_json(&self) -> Vec<serde_json::Value> {
        self.nodes
            .iter()
            .map(|(id, package)| {
                fn targets(map: &HashMap<String, ResolutionNodeId>) -> BTreeMap<&str, u32> {
                    map.iter()
                        .map(|(name, target)| (name.as_str(), target.get()))
                        .collect()
                }
                serde_json::json!({
                    "id": id.get(),
                    "package": package.package.canonical_name(),
                    "version": package.version.to_string(),
                    "context": package.package.context(),
                    "dependencies": targets(&package.dependency_targets),
                    "peers": targets(&package.peer_targets),
                })
            })
            .collect()
    }

    pub fn render(
        &self,
        roots: &[(&str, ResolutionNodeId)],
        output: &mut impl Write,
        limits: RenderLimits,
    ) -> Result<(), LpmError> {
        enum Visit<'a> {
            Enter {
                edge: Edge<'a>,
                depth: usize,
                last: bool,
            },
            Exit(ResolutionNodeId),
        }
        let mut active = HashSet::with_capacity(self.nodes.len().min(limits.depth));
        let mut expanded = HashSet::with_capacity(self.nodes.len());
        let mut ancestry = Vec::with_capacity(limits.depth);
        let mut stack = Vec::new();
        let mut writer = TreeWriter {
            output,
            limits,
            rows: 0,
            bytes: 0,
        };
        for &(local, target) in roots {
            stack.push(Visit::Enter {
                edge: Edge {
                    local,
                    target,
                    peer: false,
                },
                depth: 0,
                last: true,
            });
            while let Some(visit) = stack.pop() {
                let (edge, depth, last) = match visit {
                    Visit::Enter { edge, depth, last } => (edge, depth, last),
                    Visit::Exit(id) => {
                        active.remove(&id);
                        continue;
                    }
                };
                let package = self.nodes[&edge.target];
                let children = &self.edges[&edge.target];
                let circular = active.contains(&edge.target);
                let shared = expanded.contains(&edge.target);
                let depth_limited = depth >= writer.limits.depth && !children.is_empty();
                let mut prefix = String::with_capacity(depth * 3 + 4);
                if depth > 0 {
                    prefix.push_str("  ");
                    for &ancestor_last in ancestry.iter().take(depth - 1) {
                        prefix.push_str(if ancestor_last { "   " } else { "│  " });
                    }
                    prefix.push_str(if last { "└─ " } else { "├─ " });
                }
                let canonical = package.package.canonical_name();
                let mut line = install_ui::TerminalLine::new("").dim(&prefix);
                if edge.local != canonical {
                    line = line.field(edge.local).text(" → ");
                }
                line = line
                    .field(&canonical)
                    .dim("@")
                    .yellow(&package.version.to_string())
                    .dim(&format!(" [#{}]", edge.target.get()));
                if edge.peer {
                    line = line.dim(" (peer)");
                }
                if circular {
                    line = line.dim(" (circular)");
                } else if shared {
                    line = line.dim(" (shared)");
                } else if depth_limited {
                    line = line.dim(" (depth limit; use --json)");
                }
                if !writer.line(line.as_ref())? {
                    return Ok(());
                }
                if circular || shared || depth_limited {
                    continue;
                }
                expanded.insert(edge.target);
                active.insert(edge.target);
                stack.push(Visit::Exit(edge.target));
                if depth > 0 {
                    ancestry.truncate(depth - 1);
                    ancestry.push(last);
                }
                for (index, child) in children.iter().enumerate().rev() {
                    stack.push(Visit::Enter {
                        edge: *child,
                        depth: depth + 1,
                        last: index + 1 == children.len(),
                    });
                }
            }
        }
        Ok(())
    }
}

const TRUNCATED: &str = "… tree truncated; use --json for the full graph\n";

struct TreeWriter<'a, W> {
    output: &'a mut W,
    limits: RenderLimits,
    rows: usize,
    bytes: usize,
}

impl<W: Write> TreeWriter<'_, W> {
    fn line(&mut self, line: &str) -> Result<bool, LpmError> {
        if self.rows + 1 >= self.limits.rows
            || self.bytes + line.len() + 1 + TRUNCATED.len() > self.limits.bytes
        {
            if self.rows < self.limits.rows && self.bytes + TRUNCATED.len() <= self.limits.bytes {
                self.output.write_all(TRUNCATED.as_bytes())?;
            }
            return Ok(false);
        }
        writeln!(self.output, "{line}")?;
        self.rows += 1;
        self.bytes += line.len() + 1;
        Ok(true)
    }
}

fn graph_error(message: &str) -> LpmError {
    LpmError::Registry(format!("invalid resolved graph: {message}"))
}
