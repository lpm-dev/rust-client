use crate::graph_render::{self, DepGraph, RenderOptions};
use crate::output;
use lpm_common::LpmError;
use std::collections::HashSet;
use std::path::Path;

/// Run the `lpm graph` command.
pub async fn run(
	project_dir: &Path,
	why: Option<&str>,
	format: &str,
	max_depth: Option<usize>,
	filter: Option<&str>,
	prod_only: bool,
	dev_only: bool,
	json_output: bool,
) -> Result<(), LpmError> {
	// Load lockfile
	let lockfile_path = project_dir.join("lpm.lock");
	let lockfile = if lockfile_path.exists() {
		lpm_lockfile::Lockfile::read_from_file(&lockfile_path)
			.map_err(|e| LpmError::Script(format!("failed to read lockfile: {e}")))?
	} else {
		return Err(LpmError::Script(
			"no lpm.lock found. Run `lpm install` first to generate the lockfile.".into(),
		));
	};

	// Read package.json for direct deps
	let pkg_json_path = project_dir.join("package.json");
	let direct_deps = if pkg_json_path.exists() {
		let content = std::fs::read_to_string(&pkg_json_path)
			.map_err(|e| LpmError::Script(format!("failed to read package.json: {e}")))?;
		let pkg: serde_json::Value = serde_json::from_str(&content)
			.map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

		let mut deps = HashSet::new();
		if !dev_only {
			if let Some(d) = pkg.get("dependencies").and_then(|d| d.as_object()) {
				for key in d.keys() {
					deps.insert(key.clone());
				}
			}
		}
		if !prod_only {
			if let Some(d) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
				for key in d.keys() {
					deps.insert(key.clone());
				}
			}
		}
		deps
	} else {
		// No package.json — treat all lockfile packages as roots
		lockfile
			.packages
			.iter()
			.map(|p| p.name.clone())
			.collect()
	};

	// Get root package name
	let root_name = if pkg_json_path.exists() {
		let content = std::fs::read_to_string(&pkg_json_path).unwrap_or_default();
		let pkg: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
		let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("project");
		let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0");
		format!("{name}@{version}")
	} else {
		"project@0.0.0".to_string()
	};

	// Build graph
	let graph = DepGraph::from_lockfile(&lockfile.packages, &direct_deps, &root_name);

	// Handle --why
	if let Some(target) = why {
		if json_output {
			println!("{}", graph_render::render_why_json(&graph, target));
		} else {
			print!("{}", graph_render::render_why(&graph, target));
		}
		return Ok(());
	}

	// Render based on format
	let options = RenderOptions {
		max_depth,
		filter: filter.map(|s| s.to_string()),
	};

	match format {
		"tree" | "" => {
			print!("{}", graph_render::render_tree(&graph, &options));
		}
		"dot" => {
			print!("{}", graph_render::render_dot(&graph));
		}
		"mermaid" => {
			print!("{}", graph_render::render_mermaid(&graph));
		}
		"json" => {
			println!("{}", graph_render::render_json(&graph));
		}
		"stats" => {
			print!("{}", graph_render::render_stats(&graph));
		}
		"html" => {
			let html = graph_render::render_html(&graph);
			let out_dir = project_dir.join(".lpm");
			std::fs::create_dir_all(&out_dir)
				.map_err(|e| LpmError::Script(format!("failed to create .lpm dir: {e}")))?;
			let out_path = out_dir.join("graph.html");
			std::fs::write(&out_path, &html)
				.map_err(|e| LpmError::Script(format!("failed to write graph.html: {e}")))?;

			let size = html.len();
			output::success(&format!(
				"generated {} ({} KB)",
				out_path.display(),
				size / 1024,
			));

			// Open in browser
			let _ = open::that(&out_path);
		}
		_ => {
			return Err(LpmError::Script(format!(
				"unknown format '{format}'. Available: tree, dot, mermaid, json, stats, html"
			)));
		}
	}

	Ok(())
}
