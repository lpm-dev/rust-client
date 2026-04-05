//! Framework detection and HTTPS environment variable injection.
//!
//! Reads `package.json` to detect the dev framework and returns the appropriate
//! environment variables for enabling HTTPS on that framework's dev server.

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
    let pkg_json_path = project_dir.join("package.json");
    let Ok(contents) = std::fs::read_to_string(&pkg_json_path) else {
        return Framework::Unknown;
    };

    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return Framework::Unknown;
    };

    // Check all dependency groups
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
        assert!(env
            .iter()
            .any(|(k, v)| k == "VITE_DEV_SERVER_HTTPS_CERT" && v == "/cert.pem"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "VITE_DEV_SERVER_HTTPS_KEY" && v == "/key.pem"));
    }

    #[test]
    fn remix_env_vars_include_vite_cert_paths() {
        let env = get_framework_env(&Framework::Remix, "/cert.pem", "/key.pem");
        assert!(env
            .iter()
            .any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_CERT"));
        assert!(env
            .iter()
            .any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_KEY"));
    }

    #[test]
    fn astro_env_vars_include_vite_cert_paths() {
        let env = get_framework_env(&Framework::Astro, "/cert.pem", "/key.pem");
        assert!(env
            .iter()
            .any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_CERT"));
        assert!(env
            .iter()
            .any(|(k, _)| k == "VITE_DEV_SERVER_HTTPS_KEY"));
    }

    #[test]
    fn express_env_vars_include_generic_cert_paths() {
        let env = get_framework_env(&Framework::Express, "/cert.pem", "/key.pem");
        assert!(env.iter().any(|(k, v)| k == "HTTPS" && v == "true"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SSL_CRT_FILE" && v == "/cert.pem"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SSL_KEY_FILE" && v == "/key.pem"));
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
