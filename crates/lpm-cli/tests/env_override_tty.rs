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
    use crate::common::pty::{
        PtyOptions, run_in_pty, run_in_pty_answering, run_in_pty_with_stdout_captured,
    };

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
            &[(
                b"Override for API_URL (default, hidden): ",
                b"fixture-mine\r",
            )],
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

    #[test]
    fn override_clear_asks_on_the_terminal_while_its_output_goes_elsewhere() {
        let (project, lpm_home) = project();
        let (status, _, stderr) = common::run_lpm(
            project.path(),
            lpm_home.path(),
            None,
            &["env", "override", "set", "API_URL=mine"],
        );
        assert!(status.success(), "{stderr}");

        let (accepted, _) = run_in_pty_with_stdout_captured(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--env", "default"],
            &[(b"Remove 1 personal override", b"y\r")],
        );

        assert!(accepted.status.success(), "{}", accepted.transcript);
        assert_eq!(
            overrides(project.path(), lpm_home.path()),
            serde_json::json!([])
        );
    }

    #[test]
    fn override_clear_of_every_environment_counts_each_one_it_asks_about() {
        let (project, lpm_home) = project();
        for args in [
            &["env", "override", "set", "API_URL=mine", "OTHER=mine"][..],
            &[
                "env",
                "override",
                "set",
                "--env",
                "staging",
                "API_URL=staged",
            ],
        ] {
            let (status, _, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);
            assert!(status.success(), "{stderr}");
        }

        let declined = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--all"],
            &[(b"Remove 3 personal overrides", b"n\r")],
        );

        assert!(declined.status.success(), "{}", declined.transcript);
        assert!(
            declined.transcript.contains("(default: 2, staging: 1)?"),
            "{}",
            declined.transcript
        );
    }

    #[test]
    fn override_clear_removes_only_the_overrides_it_asked_about() {
        let (project, lpm_home) = project();
        let (status, _, stderr) = common::run_lpm(
            project.path(),
            lpm_home.path(),
            None,
            &["env", "override", "set", "API_URL=mine"],
        );
        assert!(status.success(), "{stderr}");

        let accepted = run_in_pty_answering(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--env", "default"],
            &[(b"Remove 1 personal override", b"y\r")],
            &PtyOptions::default(),
            &mut |_, _| {
                // Another command adds an override while the question waits.
                let (status, _, stderr) = common::run_lpm(
                    project.path(),
                    lpm_home.path(),
                    None,
                    &["env", "override", "set", "LATER=added"],
                );
                assert!(status.success(), "{stderr}");
            },
        );
        assert!(accepted.status.success(), "{}", accepted.transcript);
        assert!(
            accepted.transcript.contains("removed 1 personal override"),
            "{}",
            accepted.transcript
        );
        let left = overrides(project.path(), lpm_home.path());
        assert_eq!(left[0]["set"][0]["key"], "LATER", "{left}");
        assert_eq!(left[0]["set"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn override_clear_removes_nothing_from_a_project_that_took_the_folder_while_it_asked() {
        let (project, lpm_home) = project();
        let run = |args: &[&str]| {
            let (status, _, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);
            assert!(status.success(), "{args:?}: {stderr}");
        };
        run(&["env", "override", "set", "API_URL=mine"]);
        let lpm_json = project.path().join("lpm.json");
        let reviewed_project = std::fs::read_to_string(&lpm_json).expect("lpm.json");
        let another_project = r#"{"vault":"another-project"}"#;
        std::fs::write(&lpm_json, another_project).expect("another project");
        run(&["env", "set", "API_URL=theirs-team"]);
        run(&["env", "override", "set", "API_URL=theirs"]);
        std::fs::write(&lpm_json, &reviewed_project).expect("the reviewed project");

        let accepted = run_in_pty_answering(
            project.path(),
            lpm_home.path(),
            &["env", "override", "clear", "--env", "default"],
            &[(b"Remove 1 personal override", b"y\r")],
            &PtyOptions::default(),
            &mut |_, _| std::fs::write(&lpm_json, another_project).expect("switch projects"),
        );

        assert!(!accepted.status.success(), "{}", accepted.transcript);
        assert!(
            accepted.transcript.contains("nothing was changed"),
            "{}",
            accepted.transcript
        );
        assert_eq!(
            overrides(project.path(), lpm_home.path())[0]["set"][0]["value"],
            "theirs"
        );
    }

    #[test]
    fn override_set_stores_nothing_when_the_folder_names_another_project_by_the_answer() {
        let (project, lpm_home) = project();
        let run = |args: &[&str]| {
            let (status, _, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);
            assert!(status.success(), "{args:?}: {stderr}");
        };
        let lpm_json = project.path().join("lpm.json");
        let checked_project = std::fs::read_to_string(&lpm_json).expect("lpm.json");
        let another_project = r#"{"vault":"another-project"}"#;
        std::fs::write(&lpm_json, another_project).expect("another project");
        run(&["env", "set", "API_URL=theirs-team"]);
        std::fs::write(&lpm_json, &checked_project).expect("the checked project");

        let answered = run_in_pty_answering(
            project.path(),
            lpm_home.path(),
            &["env", "override", "set", "API_URL"],
            &[(
                b"Override for API_URL (default, hidden): ",
                b"fixture-mine\r",
            )],
            &PtyOptions::default(),
            &mut |_, _| std::fs::write(&lpm_json, another_project).expect("switch projects"),
        );

        assert!(!answered.status.success(), "{}", answered.transcript);
        assert!(
            answered.transcript.contains("nothing was stored"),
            "{}",
            answered.transcript
        );
        assert_eq!(
            overrides(project.path(), lpm_home.path()),
            serde_json::json!([])
        );
        std::fs::write(&lpm_json, &checked_project).expect("the checked project");
        assert_eq!(
            overrides(project.path(), lpm_home.path()),
            serde_json::json!([])
        );
    }

    #[test]
    fn override_clear_removes_nothing_when_an_override_it_asked_about_changes() {
        for change in [
            &["env", "override", "set", "API_URL=changed"][..],
            &["env", "override", "unset", "API_URL"],
        ] {
            let (project, lpm_home) = project();
            let (status, _, stderr) = common::run_lpm(
                project.path(),
                lpm_home.path(),
                None,
                &["env", "override", "set", "API_URL=mine"],
            );
            assert!(status.success(), "{stderr}");

            let accepted = run_in_pty_answering(
                project.path(),
                lpm_home.path(),
                &["env", "override", "clear", "--env", "default"],
                &[(b"Remove 1 personal override", b"y\r")],
                &PtyOptions::default(),
                &mut |_, _| {
                    let (status, _, stderr) =
                        common::run_lpm(project.path(), lpm_home.path(), None, change);
                    assert!(status.success(), "{stderr}");
                },
            );

            assert!(
                !accepted.status.success(),
                "{change:?}: {}",
                accepted.transcript
            );
            assert!(
                accepted.transcript.contains("nothing was changed"),
                "{change:?}: {}",
                accepted.transcript
            );
            let left = overrides(project.path(), lpm_home.path());
            assert_eq!(left.as_array().map(Vec::len), Some(1), "{change:?}: {left}");
        }
    }

    #[test]
    fn override_set_refuses_what_it_can_before_asking_for_a_value() {
        let (project, lpm_home) = project();
        let denied = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "set", "NODE_OPTIONS"],
            &[],
        );
        assert!(!denied.status.success(), "{}", denied.transcript);
        assert!(
            denied
                .transcript
                .contains("so it can't be a personal override"),
            "{}",
            denied.transcript
        );
        assert!(
            !denied.transcript.contains("Override for"),
            "{}",
            denied.transcript
        );

        let elsewhere = TempDir::new().expect("create a directory without an env project");
        let unlinked = run_in_pty(
            elsewhere.path(),
            lpm_home.path(),
            &["env", "override", "set", "API_URL"],
            &[],
        );
        assert!(!unlinked.status.success(), "{}", unlinked.transcript);
        assert!(
            unlinked.transcript.contains("store a value first"),
            "{}",
            unlinked.transcript
        );
        assert!(
            !unlinked.transcript.contains("Override for"),
            "{}",
            unlinked.transcript
        );
    }

    #[test]
    fn override_set_refuses_a_project_it_cant_change_before_asking_for_a_value() {
        let (project, lpm_home) = project();
        let another_computer = TempDir::new().expect("create an LPM home without its values");
        let without_values = run_in_pty(
            project.path(),
            another_computer.path(),
            &["env", "override", "set", "API_URL"],
            &[],
        );
        assert!(
            !without_values.status.success(),
            "{}",
            without_values.transcript
        );
        assert!(
            without_values
                .transcript
                .contains("has no values on this computer")
                && without_values.transcript.contains("lpm env pull"),
            "{}",
            without_values.transcript
        );
        assert!(
            !without_values.transcript.contains("Override for"),
            "{}",
            without_values.transcript
        );

        let (status, _, stderr) = common::run_lpm(
            project.path(),
            lpm_home.path(),
            None,
            &["env", "debug-companion", "newer-version"],
        );
        assert!(status.success(), "{stderr}");
        let newer = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "override", "set", "API_URL"],
            &[],
        );
        assert!(!newer.status.success(), "{}", newer.transcript);
        assert!(
            newer.transcript.contains("lpm self-update"),
            "{}",
            newer.transcript
        );
        assert!(
            !newer.transcript.contains("Override for"),
            "{}",
            newer.transcript
        );
    }
}
