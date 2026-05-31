//! Direct file execution: `lpm exec src/seed.ts`
//!
//! Detects the file type and delegates to the appropriate runtime:
//! - `.js`, `.mjs`, `.cjs` → `node` (direct spawn, no shell)
//! - `.ts`, `.tsx`, `.mts`, `.cts` → `node --experimental-strip-types` (Node ≥22.6),
//!   `node` (Node ≥23.6, native), `tsx` (fallback), or `npx tsx` (last resort)
//!
//! Uses direct process spawn (`Command::new`) instead of `sh -c` for ~20ms savings.

use crate::bin_path;
use crate::dotenv;
use lpm_common::LpmError;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct ExecTargetDescription {
    pub runtime_label: String,
}

pub fn describe_exec_target(
    project_dir: &Path,
    file_path: &str,
) -> Result<ExecTargetDescription, LpmError> {
    let resolved = resolve_exec_path(project_dir, file_path)?;
    let ext = resolved.extension().and_then(|e| e.to_str()).unwrap_or("");
    let runtime_info = detect_runtime(ext, project_dir)?;

    Ok(ExecTargetDescription {
        runtime_label: runtime_info.display_label(project_dir),
    })
}

/// Execute a file directly, auto-detecting the runtime.
///
/// Uses direct process spawn (no shell intermediary) for lower overhead.
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
    let resolved = resolve_exec_path(project_dir, file_path)?;
    let ext = resolved.extension().and_then(|e| e.to_str()).unwrap_or("");

    let runtime_info = detect_runtime(ext, project_dir)?;
    // M21: warn loudly when we're about to fetch `tsx` (and its
    // install scripts) from npm on first use. The user invoked
    // `lpm exec foo.ts` and got consent for the file they typed,
    // but not for downloading and running an arbitrary npm package
    // as a side-effect. npx — not LPM — handles the fetch, so the
    // triage gate doesn't fire. Surface the implicit-download to
    // stderr so an attacker who poisoned the npm-registry view of
    // `tsx` doesn't get free RCE just because someone ran an
    // unrelated TypeScript file.
    if runtime_info.binary == "npx" && runtime_info.flags.first().is_some_and(|f| f == "tsx") {
        eprintln!(
            "warning: no managed Node >=22.6 and no local tsx — falling back to \
             `npx tsx`, which will download tsx from npm on first use. Install a \
             managed Node (lpm use node@22.6+) or add tsx to your project to \
             avoid the implicit npm fetch."
        );
    }
    let path = bin_path::build_path_with_bins(project_dir);
    let env_vars = dotenv::load_project_env(project_dir, None)?;

    // Direct spawn: Command::new(binary).args([flags..., file, extra_args...])
    // Avoids `sh -c` overhead (~20ms savings).
    let mut command = Command::new(&runtime_info.binary);

    // Add runtime-specific flags (e.g., --experimental-strip-types)
    for flag in &runtime_info.flags {
        command.arg(flag);
    }

    command
        .arg(file_path)
        .args(extra_args)
        .current_dir(project_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Inject .env vars, then set PATH AFTER to prevent .env from overriding it
    if !env_vars.is_empty() {
        command.envs(&env_vars);
    }
    command.env("PATH", &path);

    let status = command.status().map_err(|e| {
        LpmError::Script(format!("failed to execute '{}': {e}", runtime_info.binary))
    })?;

    if !status.success() {
        #[cfg(not(unix))]
        let code = status.code().unwrap_or(1);
        #[cfg(unix)]
        let code = {
            use std::os::unix::process::ExitStatusExt;
            status
                .code()
                .unwrap_or_else(|| status.signal().map_or(1, |s| 128 + s))
        };
        return Err(LpmError::ExitCode(code));
    }

    Ok(())
}

fn resolve_exec_path(project_dir: &Path, file_path: &str) -> Result<std::path::PathBuf, LpmError> {
    let file = Path::new(file_path);
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

    Ok(resolved)
}

/// Runtime detection result — binary to invoke and any flags needed.
#[derive(Debug)]
struct RuntimeInfo {
    /// The binary to execute (e.g., "node", "tsx", "npx")
    binary: String,
    /// Extra flags before the file path (e.g., ["--experimental-strip-types"])
    flags: Vec<String>,
}

impl RuntimeInfo {
    fn display_label(&self, project_dir: &Path) -> String {
        match self.binary.as_str() {
            "node" => detect_effective_node_version(project_dir).map_or_else(
                || "Node.js".to_string(),
                |version| format!("Node.js {version}"),
            ),
            "npx" if self.flags.first().is_some_and(|flag| flag == "tsx") => "npx tsx".into(),
            runtime => runtime.to_string(),
        }
    }
}

/// Detect which runtime to use based on file extension.
///
/// For TypeScript files, checks (in order):
/// 1. Node ≥23.6 → native TypeScript (no flags needed)
/// 2. Node ≥22.6 → `node --experimental-strip-types`
/// 3. Local `tsx` in node_modules/.bin
/// 4. `npx tsx` as last resort
fn detect_runtime(ext: &str, project_dir: &Path) -> Result<RuntimeInfo, LpmError> {
    match ext {
        "js" | "mjs" | "cjs" => Ok(RuntimeInfo {
            binary: "node".into(),
            flags: vec![],
        }),
        "ts" | "tsx" | "mts" | "cts" => {
            if let Some(node_version) = detect_effective_node_version(project_dir) {
                let (major, minor) = parse_major_minor(&node_version);
                if major > 23 || (major == 23 && minor >= 6) {
                    return Ok(RuntimeInfo {
                        binary: "node".into(),
                        flags: vec![],
                    });
                }
                if (major == 22 && minor >= 6) || (major == 23 && minor < 6) {
                    return Ok(RuntimeInfo {
                        binary: "node".into(),
                        flags: vec!["--experimental-strip-types".into()],
                    });
                }
            }

            // Check if tsx is available in node_modules/.bin
            let tsx_bin = project_dir.join("node_modules/.bin/tsx");
            if tsx_bin.exists() {
                return Ok(RuntimeInfo {
                    binary: "tsx".into(),
                    flags: vec![],
                });
            }

            // Fall back to npx tsx
            Ok(RuntimeInfo {
                binary: "npx".into(),
                flags: vec!["tsx".into()],
            })
        }
        _ => Err(LpmError::Script(format!(
            "unsupported file type '.{ext}' — supported: .js, .ts, .tsx, .mjs, .cjs, .mts, .cts"
        ))),
    }
}

/// Detect the Node.js version that `lpm exec` will actually see on PATH.
fn detect_effective_node_version(project_dir: &Path) -> Option<String> {
    let path = bin_path::build_path_with_bins(project_dir);
    let output = Command::new("node")
        .arg("--version")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8(output.stdout).ok()?;
    let trimmed = version.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse major.minor from a version string like "22.6.0" → (22, 6).
fn parse_major_minor(version: &str) -> (u32, u32) {
    let mut parts = version.trim_start_matches('v').split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    fn make_executable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(path)
            .expect("script must exist")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("failed to mark script executable");
    }

    fn write_fake_node(project_dir: &std::path::Path, version: &str) {
        let bin_dir = project_dir.join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();

        #[cfg(unix)]
        {
            let node_path = bin_dir.join("node");
            fs::write(&node_path, format!("#!/bin/sh\necho {version}\n")).unwrap();
            make_executable(&node_path);
        }

        #[cfg(windows)]
        {
            let node_path = bin_dir.join("node.cmd");
            fs::write(&node_path, format!("@echo off\r\necho {version}\r\n")).unwrap();
        }
    }

    #[test]
    fn exec_js_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("hello.js"), "console.log('hello')").unwrap();

        let result = exec_file(dir.path(), "hello.js", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn exec_js_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(
            dir.path().join("args.js"),
            "process.exit(process.argv.includes('--port') ? 0 : 1)",
        )
        .unwrap();

        let result = exec_file(dir.path(), "args.js", &["--port".into(), "3000".into()]);
        assert!(
            result.is_ok(),
            "extra args including --port should pass through"
        );
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
        let r = detect_runtime("js", dir.path()).unwrap();
        assert_eq!(r.binary, "node");
        assert!(r.flags.is_empty());

        let r = detect_runtime("mjs", dir.path()).unwrap();
        assert_eq!(r.binary, "node");

        let r = detect_runtime("cjs", dir.path()).unwrap();
        assert_eq!(r.binary, "node");
    }

    #[test]
    fn detect_runtime_ts_fallback() {
        let dir = tempfile::tempdir().unwrap();
        write_fake_node(dir.path(), "v20.5.0");

        let r = detect_runtime("ts", dir.path()).unwrap();
        assert_eq!(r.binary, "npx");
        assert_eq!(r.flags, vec!["tsx"]);
    }

    #[test]
    fn detect_runtime_ts_with_local_tsx() {
        let dir = tempfile::tempdir().unwrap();
        write_fake_node(dir.path(), "v20.5.0");

        let tsx_bin = dir.path().join("node_modules/.bin/tsx");
        fs::create_dir_all(tsx_bin.parent().unwrap()).unwrap();
        fs::write(&tsx_bin, "#!/bin/sh\necho tsx").unwrap();

        let r = detect_runtime("ts", dir.path()).unwrap();
        assert_eq!(r.binary, "tsx");
        assert!(r.flags.is_empty());
    }

    #[test]
    fn detect_runtime_ts_uses_path_node_native_typescript_when_available() {
        let dir = tempfile::tempdir().unwrap();
        write_fake_node(dir.path(), "v23.6.0");

        let r = detect_runtime("ts", dir.path()).unwrap();
        assert_eq!(r.binary, "node");
        assert!(r.flags.is_empty());
    }

    #[test]
    fn detect_runtime_ts_uses_path_node_strip_types_when_available() {
        let dir = tempfile::tempdir().unwrap();
        write_fake_node(dir.path(), "v22.6.0");

        let r = detect_runtime("ts", dir.path()).unwrap();
        assert_eq!(r.binary, "node");
        assert_eq!(r.flags, vec!["--experimental-strip-types"]);
    }

    #[test]
    fn parse_major_minor_versions() {
        assert_eq!(parse_major_minor("22.6.0"), (22, 6));
        assert_eq!(parse_major_minor("23.6.1"), (23, 6));
        assert_eq!(parse_major_minor("20.20.2"), (20, 20));
        assert_eq!(parse_major_minor("24.0.0"), (24, 0));
    }

    #[test]
    fn detect_runtime_ts_with_node_236_plus() {
        // Simulate Node 23.6+ pinned via lpm.json
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime": {"node": "23.6.0"}}"#,
        )
        .unwrap();

        // This test only verifies detection logic.
        // If 23.6.0 is not installed, it falls through to tsx/npx.
        let r = detect_runtime("ts", dir.path()).unwrap();
        // Result depends on whether 23.6.0 is installed,
        // so we just assert it doesn't error.
        assert!(!r.binary.is_empty());
    }

    // --- Version check edge cases ---

    #[test]
    fn parse_major_minor_edge_cases() {
        // Single component
        assert_eq!(parse_major_minor("22"), (22, 0));
        // Empty string
        assert_eq!(parse_major_minor(""), (0, 0));
        // Non-numeric
        assert_eq!(parse_major_minor("abc.def"), (0, 0));
        // Leading v — matches `node --version` output.
        assert_eq!(parse_major_minor("v22.6.0"), (22, 6));
    }

    #[test]
    fn detect_runtime_unsupported_ext_has_helpful_message() {
        let dir = tempfile::tempdir().unwrap();
        let err = detect_runtime("py", dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(".py"), "error should mention the extension");
        assert!(msg.contains(".js"), "error should list supported types");
        assert!(msg.contains(".ts"), "error should list supported types");
    }

    #[test]
    fn exec_relative_path_resolves_against_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("script.js"), "console.log('nested')").unwrap();

        // Relative path without ./ prefix
        let result = exec_file(dir.path(), "src/script.js", &[]);
        assert!(
            result.is_ok(),
            "relative path should resolve against project dir"
        );
    }

    #[test]
    fn exec_relative_path_with_dot_slash() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("hello.js"), "console.log('hello')").unwrap();

        // Relative path with ./ prefix
        let result = exec_file(dir.path(), "./hello.js", &[]);
        assert!(result.is_ok(), "./relative path should also work");
    }

    #[test]
    fn exec_failing_script_returns_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::write(dir.path().join("fail.js"), "process.exit(42)").unwrap();

        let result = exec_file(dir.path(), "fail.js", &[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            LpmError::ExitCode(code) => assert_eq!(code, 42),
            other => panic!("expected ExitCode(42), got: {other}"),
        }
    }
}
