//! Framework detection and HTTPS environment variable injection.
//!
//! Reads `package.json` to detect the dev framework and returns the appropriate
//! environment variables for enabling HTTPS on that framework's dev server.

use std::collections::HashMap;
use std::path::Path;

/// Detected dev framework.
#[derive(Debug, Clone, PartialEq)]
pub enum Framework {
    NextJs,
    Vite,
    CreateReactApp,
    Nuxt,
    SvelteKit,
    Remix,
    Astro,
    Express,
    Unknown,
}

/// Reusable command analyzer built from one `package.json` read.
#[derive(Debug, Clone)]
pub struct CommandPortPlanner {
    framework: Framework,
    scripts: HashMap<String, String>,
}

impl CommandPortPlanner {
    /// Load the project manifest once for all command-port decisions in this directory.
    pub fn load(project_dir: &Path) -> Self {
        Self::load_with(project_dir, |path| {
            lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES).ok()
        })
    }

    fn load_with(
        project_dir: &Path,
        mut read_manifest: impl FnMut(&Path) -> Option<String>,
    ) -> Self {
        let package = read_manifest(&project_dir.join("package.json"))
            .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok());
        let framework = package
            .as_ref()
            .map_or(Framework::Unknown, detect_framework_from_package);
        let scripts = package
            .as_ref()
            .and_then(|package| package.get("scripts"))
            .and_then(serde_json::Value::as_object)
            .map(|scripts| {
                scripts
                    .iter()
                    .filter_map(|(name, command)| {
                        command
                            .as_str()
                            .map(|command| (name.clone(), command.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { framework, scripts }
    }

    /// Return managed arguments or an actionable conflict from one command analysis.
    pub fn managed_port_args(&self, command: &str, port: u16) -> Result<Vec<String>, String> {
        let analysis = self.analyze_command(command, 0);
        if let Some(value) = analysis.explicit_port {
            if is_managed_port_value(&value) || value.parse::<u16>() == Ok(port) {
                return Ok(Vec::new());
            }
            return Err(format!(
                "dev command configures port `{value}`, which conflicts with managed port {port}; use `$PORT` (or remove the command-level port flag)"
            ));
        }
        Ok(analysis
            .framework
            .map_or_else(Vec::new, |framework| explicit_port_args(&framework, port)))
    }

    fn analyze_command(&self, command: &str, depth: u8) -> CommandPortAnalysis {
        if depth > 2 {
            return CommandPortAnalysis::default();
        }
        let Some(words) = shlex::split(command) else {
            return CommandPortAnalysis::default();
        };
        let Some(executable_index) = first_executable_index(&words) else {
            return CommandPortAnalysis::default();
        };
        if let Some(script_name) = package_manager_script_name(&words, executable_index)
            && let Some(script) = self.scripts.get(script_name)
        {
            let nested = self.analyze_command(script, depth + 1);
            let explicit_port = port_argument_value(
                &words[executable_index + 1..],
                nested
                    .framework
                    .as_ref()
                    .is_some_and(framework_supports_short_port),
            )
            .or(nested.explicit_port);
            return CommandPortAnalysis {
                framework: nested.framework,
                explicit_port,
            };
        }

        let executable = package_runner_executable(&words, executable_index)
            .unwrap_or(words[executable_index].as_str());
        let framework = command_framework(executable, &self.framework);
        let explicit_port = port_argument_value(
            &words[executable_index + 1..],
            framework
                .as_ref()
                .is_some_and(framework_supports_short_port),
        );
        CommandPortAnalysis {
            framework,
            explicit_port,
        }
    }
}

#[derive(Default)]
struct CommandPortAnalysis {
    framework: Option<Framework>,
    explicit_port: Option<String>,
}

/// Detect the framework from package.json dependencies and return env vars for HTTPS.
pub fn detect_and_get_env(
    project_dir: &Path,
    cert_path: &str,
    key_path: &str,
) -> Vec<(String, String)> {
    let framework = detect_framework(project_dir);
    get_framework_env(&framework, cert_path, key_path)
}

/// Detect the dev framework by inspecting package.json dependencies.
pub fn detect_framework(project_dir: &Path) -> Framework {
    CommandPortPlanner::load(project_dir).framework
}

fn detect_framework_from_package(pkg: &serde_json::Value) -> Framework {
    let has_dep = |name: &str| -> bool {
        for key in ["dependencies", "devDependencies", "peerDependencies"] {
            if pkg.get(key).and_then(|d| d.get(name)).is_some() {
                return true;
            }
        }
        false
    };

    // Order matters: more specific frameworks first
    if has_dep("next") {
        Framework::NextJs
    } else if has_dep("nuxt") || has_dep("nuxt3") {
        Framework::Nuxt
    } else if has_dep("@sveltejs/kit") {
        Framework::SvelteKit
    } else if has_dep("@remix-run/dev") || has_dep("@remix-run/node") {
        Framework::Remix
    } else if has_dep("astro") {
        Framework::Astro
    } else if has_dep("vite") {
        Framework::Vite
    } else if has_dep("react-scripts") {
        Framework::CreateReactApp
    } else if has_dep("express") {
        Framework::Express
    } else {
        Framework::Unknown
    }
}

/// Return framework CLI arguments that enforce an explicitly managed dev port.
pub fn explicit_port_args(framework: &Framework, port: u16) -> Vec<String> {
    let port = port.to_string();
    match framework {
        Framework::Vite => vec!["--port".to_string(), port, "--strictPort".to_string()],
        Framework::NextJs
        | Framework::Nuxt
        | Framework::SvelteKit
        | Framework::Remix
        | Framework::Astro => vec!["--port".to_string(), port],
        Framework::CreateReactApp | Framework::Express | Framework::Unknown => Vec::new(),
    }
}

/// Return managed port arguments only when the command launches a compatible framework.
pub fn explicit_port_args_for_command(project_dir: &Path, command: &str, port: u16) -> Vec<String> {
    CommandPortPlanner::load(project_dir)
        .managed_port_args(command, port)
        .unwrap_or_default()
}

/// Return an actionable conflict when a command hard-codes a different port.
/// Values derived from the managed `PORT` environment variable and literals
/// equal to the requested port already satisfy the contract.
pub fn explicit_port_conflict_for_command(
    project_dir: &Path,
    command: &str,
    port: u16,
) -> Option<String> {
    CommandPortPlanner::load(project_dir)
        .managed_port_args(command, port)
        .err()
}

/// Return whether managed arguments must pass through npm's script separator.
pub fn npm_script_requires_argument_separator(command: &str) -> bool {
    let Some(words) = shlex::split(command) else {
        return false;
    };
    let Some(executable_index) = first_executable_index(&words) else {
        return false;
    };
    words.get(executable_index).map(String::as_str) == Some("npm")
        && package_manager_script_name(&words, executable_index).is_some()
}

fn command_framework(executable: &str, detected: &Framework) -> Option<Framework> {
    match executable {
        "vite" => Some(match detected {
            Framework::SvelteKit => Framework::SvelteKit,
            _ => Framework::Vite,
        }),
        "next" => Some(Framework::NextJs),
        "nuxt" | "nuxi" => Some(Framework::Nuxt),
        "svelte-kit" => Some(Framework::SvelteKit),
        "remix" | "react-router" => Some(Framework::Remix),
        "astro" => Some(Framework::Astro),
        "react-scripts" => Some(Framework::CreateReactApp),
        _ => None,
    }
}

fn port_argument_value(arguments: &[String], allow_short: bool) -> Option<String> {
    let mut value = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--port" || (allow_short && argument == "-p") {
            value = Some(arguments.get(index + 1).cloned().unwrap_or_default());
            index += 2;
            continue;
        }
        if let Some(explicit) = argument.strip_prefix("--port=") {
            value = Some(explicit.to_string());
        } else if allow_short
            && let Some(explicit) = argument
                .strip_prefix("-p=")
                .or_else(|| argument.strip_prefix("-p"))
                .filter(|value| is_numeric_or_managed_port_value(value))
        {
            value = Some(explicit.to_string());
        }
        index += 1;
    }
    value
}

fn framework_supports_short_port(framework: &Framework) -> bool {
    matches!(framework, Framework::NextJs | Framework::Nuxt)
}

fn is_numeric_or_managed_port_value(value: &str) -> bool {
    value.parse::<u16>().is_ok() || is_managed_port_value(value)
}

fn is_managed_port_value(value: &str) -> bool {
    matches!(value, "$PORT" | "${PORT}" | "%PORT%" | "$env:PORT")
}

fn first_executable_index(words: &[String]) -> Option<usize> {
    let mut index = 0usize;
    while index < words.len() {
        let word = words[index].as_str();
        if is_shell_assignment(word) || matches!(word, "env" | "command") {
            index += 1;
            continue;
        }
        if matches!(word, "cross-env" | "cross-env-shell") {
            index += 1;
            while index < words.len() && is_shell_assignment(&words[index]) {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn is_shell_assignment(word: &str) -> bool {
    let Some((key, _)) = word.split_once('=') else {
        return false;
    };
    let mut characters = key.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn package_manager_script_name(words: &[String], executable_index: usize) -> Option<&str> {
    let executable = words.get(executable_index)?.as_str();
    let arguments = words.get(executable_index + 1..)?;
    match executable {
        "npm" | "lpm" => {
            if arguments.first().map(String::as_str) == Some("run") {
                arguments.get(1).map(String::as_str)
            } else {
                None
            }
        }
        "pnpm" | "yarn" | "bun" => {
            if matches!(
                arguments.first().map(String::as_str),
                Some("exec" | "dlx" | "x")
            ) {
                return None;
            }
            let arguments = if arguments.first().map(String::as_str) == Some("run") {
                &arguments[1..]
            } else {
                arguments
            };
            arguments
                .first()
                .filter(|argument| !argument.starts_with('-'))
                .map(String::as_str)
        }
        _ => None,
    }
}

fn package_runner_executable(words: &[String], executable_index: usize) -> Option<&str> {
    let executable = words.get(executable_index)?.as_str();
    let arguments = words.get(executable_index + 1..)?;
    match executable {
        "npx" | "bunx" => arguments
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .map(String::as_str),
        "pnpm" | "yarn" | "bun"
            if matches!(
                arguments.first().map(String::as_str),
                Some("exec" | "dlx" | "x")
            ) =>
        {
            arguments
                .iter()
                .skip(1)
                .find(|argument| !argument.starts_with('-'))
                .map(String::as_str)
        }
        _ => None,
    }
}

/// Get framework-specific environment variables for HTTPS.
fn get_framework_env(
    framework: &Framework,
    cert_path: &str,
    key_path: &str,
) -> Vec<(String, String)> {
    match framework {
        Framework::NextJs => vec![
            // Next.js respects HTTPS env when using custom server
            ("HTTPS".to_string(), "true".to_string()),
        ],
        Framework::Vite => vec![
            // Vite can pick up HTTPS via env, but typically needs vite.config
            // The NODE_EXTRA_CA_CERTS (set by caller) handles Node trust
            (
                "VITE_DEV_SERVER_HTTPS_CERT".to_string(),
                cert_path.to_string(),
            ),
            (
                "VITE_DEV_SERVER_HTTPS_KEY".to_string(),
                key_path.to_string(),
            ),
        ],
        Framework::CreateReactApp => vec![
            ("HTTPS".to_string(), "true".to_string()),
            ("SSL_CRT_FILE".to_string(), cert_path.to_string()),
            ("SSL_KEY_FILE".to_string(), key_path.to_string()),
        ],
        Framework::Nuxt => vec![
            // Nuxt 3 uses devServer.https in nuxt.config
            (
                "NUXT_DEVSERVER_HTTPS_CERT".to_string(),
                cert_path.to_string(),
            ),
            ("NUXT_DEVSERVER_HTTPS_KEY".to_string(), key_path.to_string()),
        ],
        Framework::SvelteKit | Framework::Remix | Framework::Astro => vec![
            // These use Vite under the hood — pass Vite's cert env vars
            ("HTTPS".to_string(), "true".to_string()),
            (
                "VITE_DEV_SERVER_HTTPS_CERT".to_string(),
                cert_path.to_string(),
            ),
            (
                "VITE_DEV_SERVER_HTTPS_KEY".to_string(),
                key_path.to_string(),
            ),
        ],
        Framework::Express | Framework::Unknown => vec![
            // Generic: set HTTPS=true and cert/key paths
            ("HTTPS".to_string(), "true".to_string()),
            ("SSL_CRT_FILE".to_string(), cert_path.to_string()),
            ("SSL_KEY_FILE".to_string(), key_path.to_string()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_nextjs() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"next":"^14.0.0","react":"^18.0.0"}}"#,
        )
        .unwrap();

        assert_eq!(detect_framework(tmp.path()), Framework::NextJs);
    }

    #[test]
    fn detect_vite() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"devDependencies":{"vite":"^5.0.0"}}"#,
        )
        .unwrap();

        assert_eq!(detect_framework(tmp.path()), Framework::Vite);
    }

    #[test]
    fn detect_unknown_no_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(detect_framework(tmp.path()), Framework::Unknown);
    }

    #[test]
    fn vite_explicit_port_is_strict() {
        assert_eq!(
            explicit_port_args(&Framework::Vite, 5174),
            ["--port", "5174", "--strictPort"]
        );
    }

    #[test]
    fn generic_servers_receive_explicit_ports_through_the_port_environment() {
        assert!(explicit_port_args(&Framework::Express, 4000).is_empty());
        assert!(explicit_port_args(&Framework::Unknown, 4000).is_empty());
    }

    #[test]
    fn command_specific_port_args_do_not_follow_unrelated_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{
                "scripts":{"web":"vite","api":"node api.js"},
                "devDependencies":{"vite":"^7.0.0"}
            }"#,
        )
        .unwrap();

        assert!(explicit_port_args_for_command(tmp.path(), "node api.js", 4000).is_empty());
        assert!(explicit_port_args_for_command(tmp.path(), "npm run api", 4000).is_empty());
        assert_eq!(
            explicit_port_args_for_command(tmp.path(), "npm run web", 5174),
            ["--port", "5174", "--strictPort"]
        );
        assert_eq!(
            explicit_port_args_for_command(tmp.path(), "npx vite", 5175),
            ["--port", "5175", "--strictPort"]
        );
    }

    #[test]
    fn astro_command_with_a_port_flag_does_not_receive_a_duplicate_port_flag() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"astro":"^5.9.0"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_args_for_command(
                tmp.path(),
                "astro dev --host 127.0.0.1 --port $PORT",
                5174,
            )
            .is_empty()
        );
    }

    #[test]
    fn conflicting_literal_port_is_reported_instead_of_silently_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"astro":"^5.9.0"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_conflict_for_command(tmp.path(), "astro dev --port 4321", 5174).is_some()
        );
        assert!(
            explicit_port_conflict_for_command(tmp.path(), "astro dev --port 5174", 5174).is_none()
        );
    }

    #[test]
    fn forwarded_and_short_port_arguments_are_detected() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"^15.0.0"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_args_for_command(tmp.path(), "npm run dev -- --port $PORT", 5174)
                .is_empty()
        );
        assert!(explicit_port_conflict_for_command(tmp.path(), "next dev -p 4321", 5174).is_some());
        assert!(explicit_port_conflict_for_command(tmp.path(), "next dev -p4321", 5174).is_some());
        assert!(
            explicit_port_conflict_for_command(tmp.path(), "npm run dev -- -p=4321", 5174,)
                .is_some()
        );
    }

    #[test]
    fn generic_commands_ignore_unrelated_short_p_options() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"scripts":{"dev":"node server.js"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_conflict_for_command(tmp.path(), "node server.js -production", 5174)
                .is_none()
        );
        assert!(
            explicit_port_conflict_for_command(tmp.path(), "npm run dev -- -p preview", 5174,)
                .is_none()
        );
    }

    #[test]
    fn generic_commands_report_conflicting_long_port_options() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"scripts":{"dev":"node server.js"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_conflict_for_command(tmp.path(), "node server.js --port 4321", 5174)
                .is_some()
        );
        assert!(
            explicit_port_conflict_for_command(tmp.path(), "npm run dev -- --port=4321", 5174,)
                .is_some()
        );
    }

    #[test]
    fn command_port_planner_reads_the_manifest_once_for_multiple_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let reads = std::cell::Cell::new(0);
        let planner = CommandPortPlanner::load_with(tmp.path(), |_| {
            reads.set(reads.get() + 1);
            Some(
                r#"{
                    "scripts":{"web":"vite","api":"node api.js"},
                    "devDependencies":{"vite":"^7.0.0"}
                }"#
                .to_string(),
            )
        });

        assert_eq!(
            planner.managed_port_args("npm run web", 5174).unwrap(),
            ["--port", "5174", "--strictPort"]
        );
        assert!(
            planner
                .managed_port_args("npm run api -- --port=$PORT", 4000)
                .unwrap()
                .is_empty()
        );
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn compact_short_port_values_must_be_numeric_or_managed() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"next":"^15.0.0"}}"#,
        )
        .unwrap();

        assert!(
            explicit_port_conflict_for_command(tmp.path(), "next dev -production", 5174).is_none()
        );
        assert!(explicit_port_args_for_command(tmp.path(), "next dev -p$PORT", 5174).is_empty());
    }

    #[test]
    fn nextjs_env_vars() {
        let env = get_framework_env(&Framework::NextJs, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, v)| k == "HTTPS" && v == "true"));
    }

    #[test]
    fn cra_env_vars_include_cert_paths() {
        let env = get_framework_env(&Framework::CreateReactApp, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, _)| k == "SSL_CRT_FILE"));
        assert!(env.iter().any(|(k, _)| k == "SSL_KEY_FILE"));
    }

    #[test]
    fn sveltekit_env_vars_include_vite_cert_paths() {
        let env = get_framework_env(&Framework::SvelteKit, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, v)| k == "HTTPS" && v == "true"));
        assert!(
            env.iter()
                .any(|(k, v)| k == "VITE_DEV_SERVER_HTTPS_CERT" && v == "/cert.pem")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "VITE_DEV_SERVER_HTTPS_KEY" && v == "/key.pem")
        );
    }

    #[test]
    fn remix_env_vars_include_vite_cert_paths() {
        let env = get_framework_env(&Framework::Remix, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_CERT"));
        assert!(env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_KEY"));
    }

    #[test]
    fn astro_env_vars_include_vite_cert_paths() {
        let env = get_framework_env(&Framework::Astro, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_CERT"));
        assert!(env.iter().any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_KEY"));
    }

    #[test]
    fn express_env_vars_include_generic_cert_paths() {
        let env = get_framework_env(&Framework::Express, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, v)| k == "HTTPS" && v == "true"));
        assert!(
            env.iter()
                .any(|(k, v)| k == "SSL_CRT_FILE" && v == "/cert.pem")
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "SSL_KEY_FILE" && v == "/key.pem")
        );
    }

    #[test]
    fn unknown_env_vars_include_generic_cert_paths() {
        let env = get_framework_env(&Framework::Unknown, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, _)| k == "SSL_CRT_FILE"));
        assert!(env.iter().any(|(k, _)| k == "SSL_KEY_FILE"));
    }

    #[test]
    fn detect_sveltekit() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"devDependencies":{"@sveltejs/kit":"^2.0.0","svelte":"^4.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(tmp.path()), Framework::SvelteKit);
    }

    #[test]
    fn detect_remix() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"devDependencies":{"@remix-run/dev":"^2.0.0","react":"^18.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(tmp.path()), Framework::Remix);
    }

    #[test]
    fn detect_astro() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"astro":"^4.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(tmp.path()), Framework::Astro);
    }

    #[test]
    fn detect_nuxt() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"nuxt":"^3.0.0","vue":"^3.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(detect_framework(tmp.path()), Framework::Nuxt);
    }
}
