//! Direct file execution: `lpm exec src/seed.ts`
//!
//! Detects the file type and delegates to the appropriate runtime:
//! - `.js`, `.mjs`, `.cjs` → `node`
//! - `.ts`, `.tsx`, `.mts`, `.cts` → `tsx` (from node_modules/.bin) or fallback

use crate::bin_path;
use crate::dotenv;
use crate::shell::{self, ShellCommand};
use lpm_common::LpmError;
use std::path::Path;

/// Execute a file directly, auto-detecting the runtime.
///
/// # Arguments
/// * `project_dir` — project root (for PATH injection)
/// * `file_path` — path to the file to execute (relative or absolute)
/// * `extra_args` — additional arguments passed to the script
pub fn exec_file(
	project_dir: &Path,
	file_path: &str,
	extra_args: &[String],
) -> Result<(), LpmError> {
	let file = Path::new(file_path);

	// Verify file exists
	let resolved = if file.is_absolute() {
		file.to_path_buf()
	} else {
		project_dir.join(file)
	};

	if !resolved.exists() {
		return Err(LpmError::Script(format!(
			"file not found: {}",
			resolved.display()
		)));
	}

	let ext = resolved
		.extension()
		.and_then(|e| e.to_str())
		.unwrap_or("");

	let runtime = detect_runtime(ext, project_dir)?;
	let path = bin_path::build_path_with_bins(project_dir);
	let env_vars = dotenv::load_env_files(project_dir, None);

	// Build command: {runtime} {file} {extra_args...}
	let mut cmd_parts = vec![runtime, file_path.to_string()];
	for arg in extra_args {
		cmd_parts.push(arg.clone());
	}
	let full_cmd = cmd_parts.join(" ");

	let status = shell::spawn_shell(&ShellCommand {
		command: &full_cmd,
		cwd: project_dir,
		path: &path,
		envs: &env_vars,
	})?;

	if !status.success() {
		std::process::exit(shell::exit_code(&status));
	}

	Ok(())
}

/// Detect which runtime to use based on file extension.
fn detect_runtime(ext: &str, project_dir: &Path) -> Result<String, LpmError> {
	match ext {
		"js" | "mjs" | "cjs" => Ok("node".into()),
		"ts" | "tsx" | "mts" | "cts" => {
			// Check if tsx is available in node_modules/.bin
			let tsx_bin = project_dir.join("node_modules/.bin/tsx");
			if tsx_bin.exists() {
				Ok("tsx".into())
			} else {
				// Fall back to npx tsx
				Ok("npx tsx".into())
			}
		}
		_ => Err(LpmError::Script(format!(
			"unsupported file type '.{ext}' — supported: .js, .ts, .tsx, .mjs, .cjs, .mts, .cts"
		))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn exec_js_file() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		fs::write(dir.path().join("hello.js"), "console.log('hello')").unwrap();

		let result = exec_file(dir.path(), "hello.js", &[]);
		assert!(result.is_ok());
	}

	#[test]
	fn exec_missing_file_errors() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();

		let result = exec_file(dir.path(), "nonexistent.js", &[]);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("not found"));
	}

	#[test]
	fn exec_unsupported_ext_errors() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		fs::write(dir.path().join("data.csv"), "a,b,c").unwrap();

		let result = exec_file(dir.path(), "data.csv", &[]);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("unsupported"));
	}

	#[test]
	fn detect_runtime_js() {
		let dir = tempfile::tempdir().unwrap();
		assert_eq!(detect_runtime("js", dir.path()).unwrap(), "node");
		assert_eq!(detect_runtime("mjs", dir.path()).unwrap(), "node");
		assert_eq!(detect_runtime("cjs", dir.path()).unwrap(), "node");
	}

	#[test]
	fn detect_runtime_ts_fallback() {
		let dir = tempfile::tempdir().unwrap();
		// No tsx in .bin, should fall back to npx tsx
		let runtime = detect_runtime("ts", dir.path()).unwrap();
		assert_eq!(runtime, "npx tsx");
	}
}
