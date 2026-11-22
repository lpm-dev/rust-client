//! Cli-binary coverage for the hidden prompt `lpm env set KEY` shows.
//!
//! **Tier-placement justification:** TTY/stdin interactive behavior.
//! The workflow tier covers standard input, files and the refusal without a
//! terminal. These tests use a real PTY to cover what only a terminal shows:
//! that nothing typed is echoed, that a paste of several lines arrives as one
//! value, that Ctrl+C restores the terminal, and that lines a terminal sends
//! after Enter, or after Ctrl+C, are refused or discarded instead of left for
//! the shell.

mod common;

#[cfg(unix)]
mod tty {
    use crate::common;
    use crate::common::pty::{
        PtyOptions, PtySession, run_in_pty, run_in_pty_chunked, run_in_pty_with,
        run_in_pty_with_stdout_captured,
    };
    use std::time::Duration;

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
            &[(b"Value for API_KEY (default, hidden): ", b"fixture-typed\r")],
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
                (b"Value for FIRST (default, hidden): ", b"fixture-first\r"),
                (b"Value for SECOND (default, hidden): ", b"fixture-second\r"),
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
                b"Value for TLS_KEY (default, hidden): ",
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
                b"Value for TOKEN (default, hidden): ",
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
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture-one\rfixture-two\r",
            )],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("more input arrived right after the value for TOKEN"),
            "{}",
            session.transcript
        );
        assert!(
            !session.transcript.contains("fixture-"),
            "{}",
            session.transcript
        );
        assert!(session.echo_restored);
        assert_eq!(session.left_unread, 0, "nothing is left for the shell");
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn ctrl_c_cancels_with_the_interrupt_status_and_restores_the_terminal() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture-partial\x03",
            )],
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
            &[(b"Value for TOKEN (default, hidden): ", b"\r")],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("no value was entered for TOKEN, so nothing was stored"),
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

    #[test]
    fn input_is_hidden_before_the_prompt_asks_for_it() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (default, hidden): ", b"fixture-order\r")],
        );
        assert!(session.status.success(), "{}", session.transcript);
        let position = |needle: &[u8]| {
            session
                .raw
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("written")
        };
        assert!(
            position(BRACKETED_PASTE_ON) < position(b"Value for TOKEN"),
            "the terminal is set up before the prompt shows:\n{}",
            session.transcript
        );
    }

    #[test]
    fn a_paste_split_across_writes_is_refused_and_nothing_reaches_the_shell() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"fixture-one\r", b"fixture-two\r"],
            )],
            Duration::from_millis(10),
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("more input arrived right after the value for TOKEN"),
            "{}",
            session.transcript
        );
        assert!(
            !session.transcript.contains("fixture-"),
            "{}",
            session.transcript
        );
        assert_eq!(session.left_unread, 0, "nothing is left for the shell");
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn what_follows_ctrl_c_is_discarded_rather_than_left_for_the_shell() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"fixture-partial\x03", b"fixture-rest\r"],
            )],
            Duration::from_millis(10),
        );
        assert_eq!(session.status.code(), Some(130), "{}", session.transcript);
        assert!(
            !session.transcript.contains("fixture-"),
            "{}",
            session.transcript
        );
        assert_eq!(session.left_unread, 0, "nothing is left for the shell");
    }

    #[test]
    fn a_line_feed_submits_and_ctrl_h_erases_like_backspace() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture-abX\x08c\n",
            )],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-abc")
        );
    }

    #[test]
    fn ctrl_w_erases_the_last_word_typed() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture-kept typo \x17\r",
            )],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-kept ")
        );
    }

    #[test]
    fn a_typed_tab_is_part_of_the_value() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (default, hidden): ", b"fixture\tvalue\r")],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture\tvalue")
        );
    }

    #[test]
    fn a_paste_larger_than_one_value_can_hold_is_refused_whole() {
        let (project, lpm_home) = project();
        let mut paste = b"\x1b[200~".to_vec();
        paste.extend(std::iter::repeat_n(b'x', 100 * 1024 + 1));
        paste.extend_from_slice(b"\x1b[201~\r");
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(b"Value for TOKEN (default, hidden): ", &paste)],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("the value entered for TOKEN is larger than 100 KiB"),
            "{}",
            session.transcript
        );
        assert_eq!(session.left_unread, 0, "nothing is left for the shell");
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn the_prompt_names_the_environment_the_value_is_for() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "--env", "staging", "TOKEN"],
            &[(b"Value for TOKEN (staging, hidden): ", b"fixture-staged\r")],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert!(
            session.transcript.contains("stored TOKEN (staging)"),
            "{}",
            session.transcript
        );
    }

    #[test]
    fn import_from_standard_input_refuses_a_terminal_instead_of_reading_it() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "import", "-"],
            &[],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session
                .transcript
                .contains("standard input is this terminal"),
            "{}",
            session.transcript
        );
    }

    #[test]
    fn a_prompt_shown_on_the_terminal_is_asked_when_standard_output_is_captured() {
        let (project, lpm_home) = project();
        let (session, stdout) = run_in_pty_with_stdout_captured(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture-captured\r",
            )],
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert!(!stdout.contains("fixture-"), "{stdout}");
        assert!(
            !session.transcript.contains("fixture-"),
            "{}",
            session.transcript
        );
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-captured")
        );
    }

    #[test]
    fn ctrl_c_cancels_once_a_paste_that_never_ends_goes_quiet() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"\x1b[200~fixture-part", b"\x03"],
            )],
            Duration::from_millis(2500),
        );
        assert_eq!(session.status.code(), Some(130), "{}", session.transcript);
        assert!(session.echo_restored);
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn a_paste_that_never_ends_stores_nothing_when_enter_follows() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"\x1b[200~fixture-part", b"\r"],
            )],
            Duration::from_millis(2500),
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session.transcript.contains("never ended"),
            "{}",
            session.transcript
        );
        assert!(session.echo_restored);
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn a_project_whose_newer_data_refuses_writes_is_refused_before_the_prompt() {
        let (project, lpm_home) = project();
        for args in [
            &["env", "set", "SEEDED=team"][..],
            &["env", "debug-companion", "read-only"],
        ] {
            let (status, _, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);
            assert!(status.success(), "{args:?}: {stderr}");
        }

        let session = run_in_pty(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[],
        );

        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            !session.transcript.contains("Value for"),
            "{}",
            session.transcript
        );
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn ctrl_c_a_moment_after_a_paste_that_never_ends_cancels() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"\x1b[200~fixture-part", b"\x03"],
            )],
            Duration::from_millis(1500),
        );
        assert_eq!(session.status.code(), Some(130), "{}", session.transcript);
        assert!(session.echo_restored);
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn ctrl_c_cancels_once_a_terminal_string_that_never_ends_goes_quiet() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"\x1b]0;fixture-title", b"\x03"],
            )],
            Duration::from_millis(2500),
        );
        assert_eq!(session.status.code(), Some(130), "{}", session.transcript);
        assert!(session.echo_restored);
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }

    #[test]
    fn a_terminal_left_non_blocking_still_answers_the_prompt() {
        let (project, lpm_home) = project();
        let options = PtyOptions {
            nonblocking_stdin: true,
            ..PtyOptions::default()
        };
        let (session, _) = run_in_pty_with(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"fixture-typed\r"],
            )],
            &options,
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-typed")
        );
    }

    #[test]
    fn a_dumb_terminal_or_none_gets_no_paste_marking_sequences() {
        for term in [Some("dumb"), None] {
            let (project, lpm_home) = project();
            let options = PtyOptions {
                term,
                ..PtyOptions::default()
            };
            let (session, _) = run_in_pty_with(
                project.path(),
                lpm_home.path(),
                &["env", "set", "TOKEN"],
                &[(
                    b"Value for TOKEN (default, hidden): ",
                    vec![b"fixture-plain\r"],
                )],
                &options,
            );
            assert!(session.status.success(), "{term:?}: {}", session.transcript);
            assert!(
                !session.raw.windows(3).any(|window| window == b"\x1b[?"),
                "{term:?}: {:?}",
                String::from_utf8_lossy(&session.raw)
            );
            assert_eq!(
                stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
                Some("fixture-plain")
            );
        }
    }

    #[test]
    fn an_arrow_key_whose_bytes_arrive_apart_adds_nothing() {
        let (project, lpm_home) = project();
        let session = run_in_pty_chunked(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                vec![b"\x1b", b"[Afixture-key\r"],
            )],
            Duration::from_millis(120),
        );
        assert!(session.status.success(), "{}", session.transcript);
        assert_eq!(
            stored(project.path(), lpm_home.path(), "TOKEN").as_deref(),
            Some("fixture-key")
        );
    }

    #[test]
    fn a_typed_nul_is_refused_like_one_from_any_other_source() {
        let (project, lpm_home) = project();
        let session = prompted(
            project.path(),
            lpm_home.path(),
            &["env", "set", "TOKEN"],
            &[(
                b"Value for TOKEN (default, hidden): ",
                b"fixture\x00value\r",
            )],
        );
        assert!(!session.status.success(), "{}", session.transcript);
        assert!(
            session.transcript.contains("contains a NUL character"),
            "{}",
            session.transcript
        );
        assert_eq!(stored(project.path(), lpm_home.path(), "TOKEN"), None);
    }
}
