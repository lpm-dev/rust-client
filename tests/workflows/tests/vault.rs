//! Workflow tests for `lpm vault open / update / version`.
//!
//! `lpm vault` is the macOS GUI-app launcher (see
//! `crates/lpm-cli/src/commands/vault.rs`). On Linux and Windows the
//! command short-circuits to a "Vault is macOS only" error — that
//! error path is what we lock here cross-platform.
//!
//! On macOS the command would hit GitHub Releases and the local app
//! cache, both of which are environment-dependent; those paths stay
//! out of the workflow tier.

mod support;

use support::{TempProject, lpm};

#[cfg(not(target_os = "macos"))]
mod non_macos {
    use super::*;

    #[test]
    fn vault_open_on_non_macos_fails_with_unsupported_message() {
        let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

        let out = lpm(&project)
            .args(["vault", "open"])
            .output()
            .expect("failed to run lpm vault open");

        assert!(
            !out.status.success(),
            "lpm vault on non-macOS must exit non-zero"
        );

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("macOS only") || stderr.contains("not yet supported"),
            "stderr must explain the macOS-only restriction, got:\n{stderr}",
        );
    }

    #[test]
    fn vault_bare_defaults_to_open_action_and_fails_on_non_macos() {
        let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

        let out = lpm(&project)
            .args(["vault"])
            .output()
            .expect("failed to run bare lpm vault");

        assert!(
            !out.status.success(),
            "bare lpm vault on non-macOS must exit non-zero (defaults to open)"
        );
    }

    #[test]
    fn vault_update_on_non_macos_fails_with_unsupported_message() {
        let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

        let out = lpm(&project)
            .args(["vault", "update"])
            .output()
            .expect("failed to run lpm vault update");

        assert!(
            !out.status.success(),
            "lpm vault update on non-macOS must exit non-zero"
        );
    }

    #[test]
    fn vault_version_on_non_macos_fails_with_unsupported_message() {
        let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

        let out = lpm(&project)
            .args(["vault", "version"])
            .output()
            .expect("failed to run lpm vault version");

        assert!(
            !out.status.success(),
            "lpm vault version on non-macOS must exit non-zero"
        );
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// On macOS, `lpm vault` is a real surface. We can pin only the
    /// "unknown action" path safely without depending on the local
    /// app cache or GitHub. The happy paths (open / update / version)
    /// hit GitHub + on-disk caches and are out of scope for the
    /// workflow tier.
    #[test]
    fn vault_unknown_action_fails_with_helpful_message() {
        let project = TempProject::empty(r#"{"name":"vault","version":"1.0.0"}"#);

        let out = lpm(&project)
            .args(["vault", "not-a-real-action"])
            .output()
            .expect("failed to run lpm vault bogus");

        assert!(
            !out.status.success(),
            "unknown vault action must exit non-zero"
        );

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("open") && stderr.contains("update") && stderr.contains("version"),
            "stderr must enumerate the available actions, got:\n{stderr}",
        );
    }
}
