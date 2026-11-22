//! Values for `lpm env set` and `lpm env override set` from places that
//! keep them out of shell history and process listings: a hidden prompt,
//! standard input, or a file. `KEY=VALUE` arguments still work, but reach
//! both.
//!
//! A value from standard input, a file or the prompt loses the one line
//! break that ends a single line, which `echo`, heredocs and editors add
//! ([`lpm_env::strip_single_line_end`]); a value that spans lines is kept
//! exactly. Such a value can't be empty or hold a NUL: an empty pipe or file
//! is almost always a mistake, and `KEY=` stores an empty value on purpose
//! without exposing anything.

use std::collections::HashMap;
use std::io::{self, IsTerminal as _};

use lpm_common::secret_read::{SecretReadError, read_secret_stdin, read_secret_text_file};
use zeroize::Zeroizing;

use super::prelude::*;
use crate::hidden_prompt::PromptError;

/// The most one value may hold: what one macOS Keychain item stores, which
/// holds every value of a project.
pub(super) const MAX_VALUE_BYTES: usize = 100 * 1024;

const KEY_RULE: &str = "env keys must match [A-Za-z_][A-Za-z0-9_]*";

/// What a command was given to find its values.
pub(super) struct Request<'a> {
    /// `KEY=VALUE`, or a bare `KEY` whose value comes from `--stdin` or the
    /// prompt.
    pub entries: &'a [String],
    pub stdin: bool,
    /// `KEY=PATH`.
    pub from_files: &'a [String],
    pub json_output: bool,
    /// The command, for the hints an error gives, such as `lpm env set`.
    pub command: &'static str,
    /// What the prompt asks for.
    pub asking: Asking<'a>,
}

/// What a prompt asks for, such as a value for `default`: `Value for
/// API_KEY (default, hidden): `.
#[derive(Clone, Copy)]
pub(super) struct Asking<'a> {
    pub what: &'static str,
    pub environment: &'a str,
}

impl Asking<'_> {
    fn label(self, key: &str) -> String {
        format!("{} for {key} ({}, hidden): ", self.what, self.environment)
    }
}

/// Where values that aren't arguments come from.
pub(super) trait Sources {
    fn stdin_is_terminal(&self) -> bool;
    /// Whether a person is at a terminal to answer a prompt: stdin is one,
    /// and so is stderr, where the prompt shows, or stdout, where it shows
    /// when stderr is redirected.
    fn can_prompt(&self) -> bool;
    /// Whether the terminal can hide what's typed; on Windows only a console
    /// can, not a pty such as Git Bash's mintty.
    fn can_hide_input(&self) -> bool;
    fn read_stdin(&mut self, limit: usize) -> Result<Zeroizing<String>, SecretReadError>;
    fn read_file(&mut self, path: &str, limit: usize)
    -> Result<Zeroizing<String>, SecretReadError>;
    /// Ask for one value, showing `label`.
    fn prompt(&mut self, label: &str) -> Result<Zeroizing<String>, PromptError>;
}

/// The process's own standard input, files and terminal.
pub(super) struct ProcessSources;

impl Sources for ProcessSources {
    fn stdin_is_terminal(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn can_prompt(&self) -> bool {
        io::stdin().is_terminal() && (io::stderr().is_terminal() || io::stdout().is_terminal())
    }

    fn can_hide_input(&self) -> bool {
        crate::hidden_prompt::can_hide_input()
    }

    fn read_stdin(&mut self, limit: usize) -> Result<Zeroizing<String>, SecretReadError> {
        read_secret_stdin(limit)
    }

    fn read_file(
        &mut self,
        path: &str,
        limit: usize,
    ) -> Result<Zeroizing<String>, SecretReadError> {
        read_secret_text_file(
            &std::path::absolute(path).map_err(SecretReadError::Io)?,
            limit,
        )
    }

    fn prompt(&mut self, label: &str) -> Result<Zeroizing<String>, PromptError> {
        crate::install_ui::settle_spinner();
        crate::hidden_prompt::read_hidden(label, MAX_VALUE_BYTES)
    }
}

/// One key and the value it gets.
pub(super) struct Assignment {
    pub key: String,
    pub value: Zeroizing<String>,
}

enum Entry<'a> {
    Given(&'a str, &'a str),
    Bare(&'a str),
}

/// Every key's value, in the order the arguments name them, then the
/// `--from-file` keys. Nothing is read or asked until every argument is
/// valid, and nothing is asked until every file and standard input are read.
pub(super) fn collect(
    request: &Request<'_>,
    sources: &mut impl Sources,
) -> Result<Vec<Assignment>, LpmError> {
    let entries = request
        .entries
        .iter()
        .map(|entry| parse_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let files = request
        .from_files
        .iter()
        .map(|file| parse_from_file(file))
        .collect::<Result<Vec<_>, _>>()?;
    let bare: Vec<&str> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Bare(key) => Some(*key),
            Entry::Given(..) => None,
        })
        .collect();
    refuse_repeated_keys(&entries, &files, cfg!(windows))?;
    check_how_bare_keys_get_values(request, &bare, sources)?;

    let mut from_files = Vec::with_capacity(files.len());
    for (key, path) in &files {
        let text = sources
            .read_file(path, MAX_VALUE_BYTES)
            .map_err(|error| file_error(path, &error))?;
        from_files.push(Assignment {
            key: (*key).to_owned(),
            value: finish(key, text, Origin::File(path), request.command)?,
        });
    }

    let mut piped = None;
    if request.stdin
        && let Some(key) = bare.first()
    {
        let text = sources
            .read_stdin(MAX_VALUE_BYTES)
            .map_err(|error| stdin_error(key, &error))?;
        piped = Some(finish(key, text, Origin::Stdin, request.command)?);
    }

    let mut assignments = Vec::with_capacity(entries.len() + from_files.len());
    for entry in entries {
        let (key, value) = match entry {
            Entry::Given(key, value) => (key, Zeroizing::new(value.to_owned())),
            Entry::Bare(key) => match piped.take() {
                Some(value) => (key, value),
                None => (key, prompted(key, sources, request)?),
            },
        };
        assignments.push(Assignment {
            key: key.to_owned(),
            value,
        });
    }
    assignments.extend(from_files);
    Ok(assignments)
}

fn parse_entry(entry: &str) -> Result<Entry<'_>, LpmError> {
    match entry.split_once('=') {
        Some((key, value)) if lpm_env::is_valid_env_var_name(key) => Ok(Entry::Given(key, value)),
        Some(_) => Err(LpmError::Env(KEY_RULE.into())),
        None if lpm_env::is_valid_env_var_name(entry) => Ok(Entry::Bare(entry)),
        // The argument may be a value typed without its key, so it's never repeated.
        None => Err(LpmError::Env(format!(
            "expected KEY or KEY=VALUE; {KEY_RULE}"
        ))),
    }
}

fn parse_from_file(entry: &str) -> Result<(&str, &str), LpmError> {
    match entry.split_once('=') {
        Some((key, path)) if lpm_env::is_valid_env_var_name(key) && !path.is_empty() => {
            Ok((key, path))
        }
        Some((key, _)) if lpm_env::is_valid_env_var_name(key) => Err(LpmError::Env(format!(
            "--from-file {key}= names no file; use --from-file KEY=PATH"
        ))),
        _ => Err(LpmError::Env(format!(
            "--from-file takes KEY=PATH; {KEY_RULE}"
        ))),
    }
}

/// A key whose value comes from standard input, the prompt or a file can't
/// also be given elsewhere: which value wins would be a guess. Repeating
/// `KEY=VALUE` keeps its meaning, the last one. Where keys differing only in
/// case name one variable, as on Windows (`fold_case`), so do these.
fn refuse_repeated_keys(
    entries: &[Entry<'_>],
    files: &[(&str, &str)],
    fold_case: bool,
) -> Result<(), LpmError> {
    let fold = |key: &str| {
        if fold_case {
            key.to_ascii_uppercase()
        } else {
            key.to_owned()
        }
    };
    let mut given: HashMap<String, &str> = HashMap::with_capacity(entries.len());
    let mut sourced: HashMap<String, &str> = HashMap::with_capacity(entries.len() + files.len());
    for entry in entries {
        match entry {
            Entry::Given(key, _) => {
                if let Some(earlier) = given.insert(fold(key), key)
                    && earlier != *key
                {
                    return Err(repeated(earlier, key));
                }
            }
            Entry::Bare(key) => {
                if let Some(earlier) = sourced.insert(fold(key), key) {
                    return Err(repeated(earlier, key));
                }
            }
        }
    }
    for (key, _) in files {
        if let Some(earlier) = sourced.insert(fold(key), key) {
            return Err(repeated(earlier, key));
        }
    }
    match sourced
        .iter()
        .find_map(|(folded, key)| given.get(folded).map(|earlier| (*earlier, *key)))
    {
        Some((earlier, key)) => Err(repeated(earlier, key)),
        None => Ok(()),
    }
}

fn repeated(earlier: &str, key: &str) -> LpmError {
    LpmError::Env(if earlier == key {
        format!("{key} is given more than once")
    } else {
        format!("{earlier} and {key} name the same variable on this system, so give only one")
    })
}

fn check_how_bare_keys_get_values(
    request: &Request<'_>,
    bare: &[&str],
    sources: &impl Sources,
) -> Result<(), LpmError> {
    let command = request.command;
    if request.stdin {
        return match bare {
            [] => Err(LpmError::Env(format!(
                "--stdin reads one value: name its key without =, such as `{command} API_KEY --stdin`"
            ))),
            [key] if sources.stdin_is_terminal() && sources.can_hide_input() => {
                Err(LpmError::Env(format!(
                    "--stdin reads a value piped to lpm, but standard input is this terminal. To type the value hidden, leave out --stdin: `{command} {key}`"
                )))
            }
            [key] if sources.stdin_is_terminal() => Err(LpmError::Env(format!(
                "--stdin reads a value piped to lpm, but standard input is this terminal, which can't hide what's typed. Pipe the value in, or read it from a file with `{command} --from-file {key}=PATH`"
            ))),
            [_] => Ok(()),
            keys => Err(LpmError::Env(format!(
                "--stdin reads one value, but {} keys have none: {}",
                keys.len(),
                keys.join(", ")
            ))),
        };
    }
    match bare.first() {
        Some(key) if request.json_output || !sources.can_prompt() || !sources.can_hide_input() => {
            let reason = if request.json_output {
                "LPM doesn't ask for values with --json"
            } else if !sources.can_prompt() {
                "LPM asks for a value, hidden, only in an interactive terminal"
            } else {
                "This terminal can't hide what's typed, as Git Bash's mintty can't"
            };
            Err(LpmError::Env(format!(
                "{key} has no value. {reason}. Pipe it in with `{command} {key} --stdin`, or read it from a file with `{command} --from-file {key}=PATH`"
            )))
        }
        _ => Ok(()),
    }
}

fn prompted(
    key: &str,
    sources: &mut impl Sources,
    request: &Request<'_>,
) -> Result<Zeroizing<String>, LpmError> {
    let command = request.command;
    let typed = sources
        .prompt(&request.asking.label(key))
        .map_err(|error| match error {
            PromptError::Cancelled => {
                LpmError::ExitCode(crate::prompt::PROMPT_CANCELLED_EXIT_CODE)
            }
            PromptError::SeveralLines => LpmError::Env(format!(
                "more input arrived right after the value for {key}: the rest of a paste this terminal can't mark as one, or keys typed too soon. Nothing was stored. Enter it again; for a value of several lines, pipe it in with `{command} {key} --stdin`, or read it from a file with `{command} --from-file {key}=PATH`"
            )),
            PromptError::TooLarge => LpmError::Env(format!(
                "the value entered for {key} is larger than {} KiB, the most one value can hold. Nothing was stored",
                MAX_VALUE_BYTES / 1024
            )),
            PromptError::IncompletePaste => LpmError::Env(format!(
                "the paste of the value for {key} never ended, so nothing was stored. Paste it again, pipe it in with `{command} {key} --stdin`, or read it from a file with `{command} --from-file {key}=PATH`"
            )),
            PromptError::NotText => LpmError::Env(format!(
                "the value entered for {key} isn't UTF-8 text, so this terminal may use another encoding. Nothing was stored. Pipe it in with `{command} {key} --stdin`"
            )),
            PromptError::Terminal(error) => LpmError::Env(format!(
                "failed to read the value for {key} from the terminal: {error}"
            )),
        })?;
    finish(key, typed, Origin::Prompt, command)
}

/// Where a value came from, to say so without showing it.
#[derive(Clone, Copy)]
enum Origin<'a> {
    Stdin,
    File(&'a str),
    Prompt,
}

/// Apply the rules every value from standard input, a file or the prompt
/// follows.
fn finish(
    key: &str,
    mut value: Zeroizing<String>,
    origin: Origin<'_>,
    command: &str,
) -> Result<Zeroizing<String>, LpmError> {
    let kept = lpm_env::strip_single_line_end(&value).len();
    value.truncate(kept);
    if value.is_empty() {
        let what = match origin {
            Origin::Stdin => format!("the value piped in for {key} is empty"),
            Origin::File(path) => format!("--from-file: {path} holds an empty value for {key}"),
            Origin::Prompt => format!("no value was entered for {key}"),
        };
        return Err(LpmError::Env(format!(
            "{what}, so nothing was stored. To store an empty value on purpose, run `{command} {key}=`"
        )));
    }
    if value.contains('\0') {
        let what = match origin {
            Origin::Stdin => format!("the value piped in for {key}"),
            Origin::File(path) => format!("--from-file: {path}"),
            Origin::Prompt => format!("the value entered for {key}"),
        };
        return Err(LpmError::Env(format!(
            "{what} contains a NUL character, which no process environment can hold"
        )));
    }
    Ok(value)
}

fn stdin_error(key: &str, error: &SecretReadError) -> LpmError {
    LpmError::Env(match error {
        SecretReadError::TooLarge => format!(
            "the value piped in for {key} is larger than {} KiB, the most one value can hold",
            MAX_VALUE_BYTES / 1024
        ),
        SecretReadError::NotText => format!("the value piped in for {key} isn't UTF-8 text"),
        SecretReadError::NotFileOrPipe => format!(
            "--stdin reads a value piped to lpm or redirected from a file, but standard input is a device; nothing was read for {key}"
        ),
        other => format!("failed to read the value for {key} from standard input: {other}"),
    })
}

fn file_error(path: &str, error: &SecretReadError) -> LpmError {
    LpmError::Env(match error {
        SecretReadError::NotFound => format!("--from-file: {path} doesn't exist"),
        SecretReadError::Directory => format!("--from-file: {path} is a directory"),
        SecretReadError::NotFileOrPipe => format!("--from-file: {path} isn't a file or a pipe"),
        SecretReadError::TooLarge => format!(
            "--from-file: {path} is larger than {} KiB, the most one value can hold",
            MAX_VALUE_BYTES / 1024
        ),
        SecretReadError::NotText => format!("--from-file: {path} isn't UTF-8 text"),
        SecretReadError::Io(error) => format!("--from-file: failed to read {path}: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    #[derive(Default)]
    struct Fake {
        terminal: bool,
        /// The terminal can't hide what's typed, as a mintty pty can't.
        cant_hide: bool,
        stdin: Option<Vec<u8>>,
        files: HashMap<String, Result<String, &'static str>>,
        typed: VecDeque<Result<&'static str, PromptError>>,
        asked: Vec<String>,
        stdin_reads: usize,
    }

    impl Sources for Fake {
        fn stdin_is_terminal(&self) -> bool {
            self.terminal
        }

        fn can_prompt(&self) -> bool {
            self.terminal
        }

        fn can_hide_input(&self) -> bool {
            !self.cant_hide
        }

        fn read_stdin(&mut self, limit: usize) -> Result<Zeroizing<String>, SecretReadError> {
            self.stdin_reads += 1;
            let bytes = self.stdin.clone().unwrap_or_default();
            if bytes.len() > limit {
                return Err(SecretReadError::TooLarge);
            }
            String::from_utf8(bytes)
                .map(Zeroizing::new)
                .map_err(|_| SecretReadError::NotText)
        }

        fn read_file(
            &mut self,
            path: &str,
            limit: usize,
        ) -> Result<Zeroizing<String>, SecretReadError> {
            match self.files.get(path) {
                None => Err(SecretReadError::NotFound),
                Some(Ok(text)) if text.len() > limit => Err(SecretReadError::TooLarge),
                Some(Ok(text)) => Ok(Zeroizing::new(text.clone())),
                Some(Err(_)) => Err(SecretReadError::NotFileOrPipe),
            }
        }

        fn prompt(&mut self, label: &str) -> Result<Zeroizing<String>, PromptError> {
            self.asked.push(label.to_owned());
            self.typed
                .pop_front()
                .expect("a prompt the test expected")
                .map(|text| Zeroizing::new(text.to_owned()))
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn run(
        entries: &[&str],
        stdin: bool,
        from_files: &[&str],
        json_output: bool,
        fake: &mut Fake,
    ) -> Result<Vec<(String, String)>, String> {
        let entries = strings(entries);
        let from_files = strings(from_files);
        collect(
            &Request {
                entries: &entries,
                stdin,
                from_files: &from_files,
                json_output,
                command: "lpm env set",
                asking: Asking {
                    what: "Value",
                    environment: "default",
                },
            },
            fake,
        )
        .map(|assignments| {
            assignments
                .into_iter()
                .map(|assignment| (assignment.key, assignment.value.to_string()))
                .collect()
        })
        .map_err(|error| match error {
            LpmError::Env(message) => message,
            other => format!("{other:?}"),
        })
    }

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn arguments_with_a_value_need_no_other_source() {
        let mut fake = Fake::default();
        assert_eq!(
            run(&["A=1", "B=", "C=x=y"], false, &[], false, &mut fake),
            Ok(pairs(&[("A", "1"), ("B", ""), ("C", "x=y")]))
        );
        assert_eq!(fake.stdin_reads, 0);
    }

    #[test]
    fn stdin_gives_its_one_key_the_value_without_the_line_end_echo_adds() {
        let mut fake = Fake {
            stdin: Some(b"s3cret\n".to_vec()),
            ..Fake::default()
        };
        assert_eq!(
            run(&["PLAIN=1", "TOKEN"], true, &[], false, &mut fake),
            Ok(pairs(&[("PLAIN", "1"), ("TOKEN", "s3cret")]))
        );
    }

    #[test]
    fn a_value_that_spans_lines_is_kept_exactly() {
        let pem = "-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n";
        let mut fake = Fake {
            stdin: Some(pem.as_bytes().to_vec()),
            files: HashMap::from([("key.pem".to_owned(), Ok(pem.to_owned()))]),
            ..Fake::default()
        };
        assert_eq!(
            run(&["PIPED"], true, &["FILED=key.pem"], false, &mut fake),
            Ok(pairs(&[("PIPED", pem), ("FILED", pem)]))
        );
    }

    #[test]
    fn stdin_needs_exactly_one_key_without_a_value() {
        let mut fake = Fake {
            stdin: Some(b"x".to_vec()),
            ..Fake::default()
        };
        let none = run(&["A=1"], true, &[], false, &mut fake).unwrap_err();
        assert!(none.contains("--stdin reads one value"), "{none}");
        let two = run(&["A", "B"], true, &[], false, &mut fake).unwrap_err();
        assert!(two.contains("2 keys have none: A, B"), "{two}");
        assert_eq!(
            fake.stdin_reads, 0,
            "nothing is read before the arguments are valid"
        );
    }

    #[test]
    fn stdin_that_is_the_terminal_is_refused_rather_than_echoed() {
        let mut fake = Fake {
            terminal: true,
            ..Fake::default()
        };
        let error = run(&["TOKEN"], true, &[], false, &mut fake).unwrap_err();
        assert!(
            error.contains("leave out --stdin: `lpm env set TOKEN`"),
            "{error}"
        );
        assert_eq!(fake.stdin_reads, 0);
    }

    #[test]
    fn a_key_without_a_value_fails_without_a_terminal_and_never_waits() {
        let mut fake = Fake::default();
        let error = run(&["TOKEN"], false, &[], false, &mut fake).unwrap_err();
        assert!(error.starts_with("TOKEN has no value."), "{error}");
        assert!(error.contains("`lpm env set TOKEN --stdin`"), "{error}");
        assert!(
            error.contains("`lpm env set --from-file TOKEN=PATH`"),
            "{error}"
        );
        assert_eq!(fake.stdin_reads, 0);
        assert!(fake.asked.is_empty());
    }

    #[test]
    fn json_output_never_prompts_even_at_a_terminal() {
        let mut fake = Fake {
            terminal: true,
            ..Fake::default()
        };
        let error = run(&["TOKEN"], false, &[], true, &mut fake).unwrap_err();
        assert!(
            error.contains("doesn't ask for values with --json"),
            "{error}"
        );
        assert!(fake.asked.is_empty());
    }

    #[test]
    fn each_key_without_a_value_is_asked_for_in_order_after_files_are_read() {
        let mut fake = Fake {
            terminal: true,
            files: HashMap::from([("cert.pem".to_owned(), Ok("CERT\n".to_owned()))]),
            typed: VecDeque::from([Ok("first"), Ok("second\n")]),
            ..Fake::default()
        };
        assert_eq!(
            run(&["A", "B=b", "C"], false, &["D=cert.pem"], false, &mut fake),
            Ok(pairs(&[
                ("A", "first"),
                ("B", "b"),
                ("C", "second"),
                ("D", "CERT")
            ]))
        );
        assert_eq!(
            fake.asked,
            [
                "Value for A (default, hidden): ",
                "Value for C (default, hidden): "
            ]
        );
    }

    #[test]
    fn a_failed_file_read_asks_for_nothing() {
        let mut fake = Fake {
            terminal: true,
            ..Fake::default()
        };
        let error = run(&["A"], false, &["B=missing.txt"], false, &mut fake).unwrap_err();
        assert_eq!(error, "--from-file: missing.txt doesn't exist");
        assert!(fake.asked.is_empty());
    }

    #[test]
    fn empty_values_from_every_source_are_refused_with_the_way_to_store_one() {
        for (stdin, files, typed, said) in [
            (
                Some(b"".to_vec()),
                vec![],
                None,
                "the value piped in for A is empty",
            ),
            (
                Some(b"\n".to_vec()),
                vec![],
                None,
                "the value piped in for A is empty",
            ),
            (
                None,
                vec!["A=empty.txt"],
                None,
                "--from-file: empty.txt holds an empty value for A",
            ),
            (None, vec![], Some(""), "no value was entered for A"),
        ] {
            let piped = stdin.is_some();
            let mut fake = Fake {
                terminal: typed.is_some(),
                stdin,
                files: HashMap::from([("empty.txt".to_owned(), Ok(String::new()))]),
                typed: typed.into_iter().map(Ok).collect(),
                ..Fake::default()
            };
            let entries: &[&str] = if files.is_empty() { &["A"] } else { &[] };
            let error = run(entries, piped, &files, false, &mut fake).unwrap_err();
            assert_eq!(
                error,
                format!(
                    "{said}, so nothing was stored. To store an empty value on purpose, run `lpm env set A=`"
                )
            );
        }
    }

    #[test]
    fn nul_characters_are_refused_and_never_shown() {
        let mut fake = Fake {
            stdin: Some(b"sec\0ret".to_vec()),
            terminal: false,
            files: HashMap::from([("nul.txt".to_owned(), Ok("sec\0ret".to_owned()))]),
            ..Fake::default()
        };
        let error = run(&["A"], true, &[], false, &mut fake).unwrap_err();
        assert_eq!(
            error,
            "the value piped in for A contains a NUL character, which no process environment can hold"
        );
        let error = run(&[], false, &["A=nul.txt"], false, &mut fake).unwrap_err();
        assert_eq!(
            error,
            "--from-file: nul.txt contains a NUL character, which no process environment can hold"
        );
        fake.terminal = true;
        fake.typed = VecDeque::from([Ok("sec\0ret")]);
        let error = run(&["A"], false, &[], false, &mut fake).unwrap_err();
        assert!(
            error.starts_with("the value entered for A contains a NUL"),
            "{error}"
        );
    }

    #[test]
    fn oversized_and_non_utf8_input_is_refused() {
        let mut fake = Fake {
            stdin: Some(vec![b'x'; MAX_VALUE_BYTES + 1]),
            files: HashMap::from([
                ("big.txt".to_owned(), Ok("x".repeat(MAX_VALUE_BYTES + 1))),
                ("fifo".to_owned(), Err("special")),
            ]),
            ..Fake::default()
        };
        let piped = run(&["A"], true, &[], false, &mut fake).unwrap_err();
        assert!(piped.contains("larger than 100 KiB"), "{piped}");
        let filed = run(&[], false, &["A=big.txt"], false, &mut fake).unwrap_err();
        assert_eq!(
            filed,
            "--from-file: big.txt is larger than 100 KiB, the most one value can hold"
        );
        let special = run(&[], false, &["A=fifo"], false, &mut fake).unwrap_err();
        assert_eq!(special, "--from-file: fifo isn't a file or a pipe");
        fake.stdin = Some(vec![0xff, 0xfe]);
        let binary = run(&["A"], true, &[], false, &mut fake).unwrap_err();
        assert!(binary.contains("isn't UTF-8 text"), "{binary}");
    }

    #[test]
    fn exactly_the_largest_value_is_accepted() {
        let largest = "x".repeat(MAX_VALUE_BYTES);
        let mut fake = Fake {
            stdin: Some(largest.clone().into_bytes()),
            ..Fake::default()
        };
        assert_eq!(
            run(&["A"], true, &[], false, &mut fake),
            Ok(vec![("A".to_owned(), largest)])
        );
    }

    #[test]
    fn a_key_from_another_source_can_be_given_only_once() {
        let mut fake = Fake {
            terminal: true,
            files: HashMap::from([("v".to_owned(), Ok("v".to_owned()))]),
            ..Fake::default()
        };
        for (entries, files) in [
            (&["A", "A"][..], &[][..]),
            (&["A=1", "A"][..], &[][..]),
            (&["A=1"][..], &["A=v"][..]),
            (&[][..], &["A=v", "A=v"][..]),
        ] {
            assert_eq!(
                run(entries, false, files, false, &mut fake),
                Err("A is given more than once".to_owned()),
                "{entries:?} {files:?}"
            );
        }
        assert!(fake.asked.is_empty());
        assert_eq!(
            run(&["A=1", "A=2"], false, &[], false, &mut fake),
            Ok(pairs(&[("A", "1"), ("A", "2")])),
            "repeated assignments keep their meaning: the last one is stored"
        );
    }

    #[test]
    fn invalid_arguments_are_never_repeated_back() {
        let mut fake = Fake::default();
        for entry in ["sk-live-0123", "1A=x", "=x"] {
            let error = run(&[entry], false, &[], false, &mut fake).unwrap_err();
            assert!(!error.contains(entry), "{error}");
            assert!(error.contains(KEY_RULE), "{error}");
        }
        let error = run(&[], false, &["A="], false, &mut fake).unwrap_err();
        assert!(error.contains("names no file"), "{error}");
        let error = run(&[], false, &["path-only"], false, &mut fake).unwrap_err();
        assert!(
            !error.contains("path-only") && error.contains("KEY=PATH"),
            "{error}"
        );
    }

    #[test]
    fn keys_differing_only_in_case_are_one_key_where_the_system_says_so() {
        let bare = [Entry::Bare("TOKEN"), Entry::Bare("token")];
        assert!(refuse_repeated_keys(&bare, &[], false).is_ok());
        let error = refuse_repeated_keys(&bare, &[], true).unwrap_err();
        assert!(
            matches!(&error, LpmError::Env(message) if message == "TOKEN and token name the same variable on this system, so give only one"),
            "{error:?}"
        );
        for (entries, files) in [
            (
                &[Entry::Given("TOKEN", "1"), Entry::Bare("Token")][..],
                &[][..],
            ),
            (&[Entry::Given("TOKEN", "1")][..], &[("token", "v")][..]),
            (
                &[Entry::Given("TOKEN", "1"), Entry::Given("token", "2")][..],
                &[][..],
            ),
        ] {
            assert!(refuse_repeated_keys(entries, files, false).is_ok());
            assert!(refuse_repeated_keys(entries, files, true).is_err());
        }
        assert!(
            refuse_repeated_keys(
                &[Entry::Given("TOKEN", "1"), Entry::Given("TOKEN", "2")],
                &[],
                true
            )
            .is_ok(),
            "the same spelling twice is still the last one wins"
        );
    }

    #[test]
    fn every_way_a_prompt_fails_stores_nothing_and_says_why() {
        let mut fake = Fake {
            terminal: true,
            typed: VecDeque::from([
                Err(PromptError::Cancelled),
                Err(PromptError::SeveralLines),
                Err(PromptError::TooLarge),
                Err(PromptError::NotText),
                Err(PromptError::IncompletePaste),
            ]),
            ..Fake::default()
        };
        let cancelled = collect(
            &Request {
                entries: &strings(&["A"]),
                stdin: false,
                from_files: &[],
                json_output: false,
                command: "lpm env set",
                asking: Asking {
                    what: "Value",
                    environment: "default",
                },
            },
            &mut fake,
        );
        assert!(matches!(
            cancelled,
            Err(LpmError::ExitCode(
                crate::prompt::PROMPT_CANCELLED_EXIT_CODE
            ))
        ));
        let pasted = run(&["A"], false, &[], false, &mut fake).unwrap_err();
        assert!(
            pasted.contains("more input arrived right after the value for A"),
            "{pasted}"
        );
        assert!(pasted.contains("Nothing was stored"), "{pasted}");
        let large = run(&["A"], false, &[], false, &mut fake).unwrap_err();
        assert_eq!(
            large,
            "the value entered for A is larger than 100 KiB, the most one value can hold. Nothing was stored"
        );
        let not_text = run(&["A"], false, &[], false, &mut fake).unwrap_err();
        assert!(not_text.contains("isn't UTF-8 text"), "{not_text}");
        assert!(not_text.contains("`lpm env set A --stdin`"), "{not_text}");
        let cut = run(&["A"], false, &[], false, &mut fake).unwrap_err();
        assert!(cut.contains("never ended, so nothing was stored"), "{cut}");
    }

    #[test]
    fn a_terminal_that_cant_hide_input_gets_the_ways_that_work() {
        let mut fake = Fake {
            terminal: true,
            cant_hide: true,
            ..Fake::default()
        };
        let bare = run(&["TOKEN"], false, &[], false, &mut fake).unwrap_err();
        assert!(bare.contains("can't hide what's typed"), "{bare}");
        assert!(bare.contains("`lpm env set TOKEN --stdin`"), "{bare}");
        let piped = run(&["TOKEN"], true, &[], false, &mut fake).unwrap_err();
        assert!(!piped.contains("leave out --stdin"), "{piped}");
        assert!(piped.contains("--from-file TOKEN=PATH"), "{piped}");
        assert!(fake.asked.is_empty());
        assert_eq!(fake.stdin_reads, 0);
    }
}
