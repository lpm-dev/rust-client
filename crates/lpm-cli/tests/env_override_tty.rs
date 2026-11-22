//! Cli-binary coverage for what `lpm env override` asks in a terminal.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers standard input, files and the refusals without a
//! terminal. These tests use a real PTY for the hidden value prompt of
//! `override set` and the question `override clear` asks before it removes
//! anything.

mod common;

#[cfg(unix)]
mod tty {
    use crate::common;
    use crate::common::pty::run_in_pty;

    use tempfile::TempDir;

    /// A project with a team value, so it can have overrides.
    fn project() -> (TempDir, TempDir) {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"env-override-tty","version":"1.0.0"}"#,
        )
        .expect("write package.json");
        let (status, _, stderr) = common::run_lpm(
            project.path(),
            lpm_home.path(),
            None,
            &["env", "set", "API_URL=team"],
        );
        assert!(status.success(), "{stderr}");
        (project, lpm_home)
    }

    fn overrides(project: &std::path::Path, lpm_home: &std::path::Path) -> serde_json::Value {
        let (status, stdout, stderr) = common::run_lpm(
            project,
            lpm_home,
            None,
            &["--json", "env", "override", "list", "--reveal"],
        );
        assert!(status.success(), "{stderr}");
        serde_json::from_str::<serde_json::Value>(&stdout).expect("override list JSON")["environments"]
            .clone()
    }

    #[test]
    fn override_set_asks_for_the_value_hidden() {
        let (project, lpm_home) = project();
        let session = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "set", "API_URL"],
            &[(b"Value for API_URL (hidden): ", b"fixture-mine\r")],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert!(
            !session.transcript.contains("fixture-mine"),
            "{}",
            session.transcript
        );
        assert!(session.echo_restored);
        assert_eq!(
            overrides(project.path(), lpm_home.path())[0]["set"][0]["value"],
            "fixture-mine"
        );
    }

    #[test]
    fn override_clear_removes_nothing_unless_the_person_says_yes() {
        let (project, lpm_home) = project();
        let (status, _, stderr) = common::run_lpm(
            project.path(),
            lpm_home.path(),
            None,
            &["env", "override", "set", "API_URL=mine"],
        );
        assert!(status.success(), "{stderr}");

        let declined = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--env", "default"],
            &[(b"Remove 1 personal override", b"n\r")],
        );
        assert!(declined.status.success(), "{}", declined.transcript);
        assert!(
            declined.transcript.contains("nothing was changed"),
            "{}",
            declined.transcript
        );
        assert_eq!(
            overrides(project.path(), lpm_home.path())
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        let accepted = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--env", "default"],
            &[(b"Remove 1 personal override", b"y\r")],
        );
        assert!(accepted.status.success(), "{}", accepted.transcript);
        assert!(
            accepted.transcript.contains("removed 1 personal override"),
            "{}",
            accepted.transcript
        );
        assert_eq!(
            overrides(project.path(), lpm_home.path()),
            serde_json::json!([])
        );
    }
}
