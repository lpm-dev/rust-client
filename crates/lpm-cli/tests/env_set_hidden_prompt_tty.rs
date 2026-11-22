//! Cli-binary coverage for the hidden prompt `lpm env set KEY` shows.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers standard input, files and the refusal without a
//! terminal. These tests use a real PTY to cover what only a terminal shows:
//! that nothing typed is echoed, that a paste of several lines arrives as one
//! value, that Ctrl+C restores the terminal, and that lines a terminal sends
//! after Enter are refused instead of left for the shell.

mod common;

#[cfg(unix)]
mod tty {
    use crate::common;
    use crate::common::pty::{PtySession, run_in_pty};

    use tempfile::TempDir;

    const BRACKETED_PASTE_ON: &[u8] = b"\x1b[?2004h";

    fn project() -> (TempDir, TempDir) {
        let project = TempDir::new().expect("create project");
        let lpm_home = TempDir::new().expect("create LPM home");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"env-set-hidden-prompt","version":"1.0.0"}"#,
        )
        .expect("write package.json");
        (project, lpm_home)
    }

    /// `run_in_pty`, checking that a prompt turned bracketed paste on.
    fn prompted(
        project: &std::path::Path,
        lpm_home: &std::path::Path,
        args: &[&str],
        steps: &[(&[u8], &[u8])],
    ) -> PtySession {
        let session = run_in_pty(project, lpm_home, args, steps);
        assert!(
            steps.is_empty()
                || session
                    .raw
                    .windows(BRACKETED_PASTE_ON.len())
                    .any(|window| window == BRACKETED_PASTE_ON),
            "the prompt turns bracketed paste on:\n{}",
            session.transcript
        );
        session
    }

    fn stored(project: &std::path::Path, lpm_home: &std::path::Path, key: &str) -> Option<String> {
        let (status, stdout, _) = common::run_lpm(
            project,
            lpm_home,
            None,
            &["--json", "env", "get", key, "--reveal"],
        );
        if !status.success() {
            return None;
        }
        let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("env get JSON");
        envelope["value"].as_str().map(str::to_owned)
    }

    #[test]
    fn a_typed_value_is_never_echoed_and_is_stored_as_typed() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "API_KEY"],
            &[(b"Value for API_KEY (hidden): ", b"fixture-typed\r")],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert!(
            !session.transcript.contains("fixture-typed"),
            "{}",
            session.transcript
        );
        assert!(
            session.transcript.contains("stored API_KEY (default)"),
            "{}",
            session.transcript
        );
        assert!(
            session.echo_restored,
            "the terminal echoes again after the prompt"
        );
        assert_eq!(
            stored(project.path(), lpm_home.path(), "API_KEY").as_deref(),
            Some("fixture-typed")
        );
    }

    #[test]
    fn each_key_without_a_value_is_asked_for_in_turn() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "FIRST", "PLAIN=fixture-plain", "SECOND"],
            &[
                (b"Value for FIRST (hidden): ", b"fixture-first\r"),
                (b"Value for SECOND (hidden): ", b"fixture-second\r"),
            ],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "FIRST").as_deref(),
            Some("fixture-first")
        );
        assert_eq!(
            stored(project.path(), lpm_home.path(), "SECOND").as_deref(),
            Some("fixture-second")
        );
        assert_eq!(
            stored(project.path(), lpm_home.path(), "PLAIN").as_deref(),
            Some("fixture-plain")
        );
    }

    #[test]
    fn a_pasted_value_of_several_lines_arrives_whole() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TLS_KEY"],
            &[(
                b"Value for TLS_KEY (hidden): ",
                b"\x1b[200~-----BEGIN KEY-----\rZml4dHVyZQ==\r-----END KEY-----\r\x1b[201~\r",
            )],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert!(
            !session.transcript.contains("Zml4dHVyZQ"),
            "{}",
            session.transcript
        );
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TLS_KEY").as_deref(),
            Some("-----BEGIN KEY-----\nZml4dHVyZQ==\n-----END KEY-----\n")
        );
    }

    #[test]
    fn a_pasted_line_loses_the_line_break_copied_with_it() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (hidden): ",
                b"\x1b[200~fixture-line\r\x1b[201~\r",
            )],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-line")
        );
    }

    #[test]
    fn lines_sent_after_enter_are_refused_rather_than_left_for_the_shell() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (hidden): ", b"fixture-one\rfixture-two\r")],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("the value pasted for TOKEN has more than one line"),
            "{}",
            session.transcript
        );
        assert!(
            !session.transcript.contains("fixture-"),
            "{}",
            session.transcript
        );
        assert!(session.echo_restored);
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn ctrl_c_cancels_with_the_interrupt_status_and_restores_the_terminal() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (hidden): ", b"fixture-partial\x03")],
        );
        assert_eq!(session.status.code(), Some(130), "{}", session.transcript);
        assert!(
            session.echo_restored,
            "the terminal echoes again after Ctrl+C"
        );
        assert!(
            !session.transcript.contains("fixture-partial"),
            "{}",
            session.transcript
        );
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn an_empty_answer_stores_nothing_and_says_how_to_store_an_empty_value() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (hidden): ", b"\r")],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("the prompt gave TOKEN an empty value, so nothing was stored"),
            "{}",
            session.transcript
        );
        assert!(
            session.transcript.contains("`lpm env set TOKEN=`"),
            "{}",
            session.transcript
        );
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn json_output_refuses_to_prompt_even_in_a_terminal() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["--json", "env", "set", "TOKEN"],
            &[],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            !session.transcript.contains("Value for TOKEN"),
            "{}",
            session.transcript
        );
        assert!(
            session
                .transcript
                .contains("doesn't ask for values with --json"),
            "{}",
            session.transcript
        );
    }
}
