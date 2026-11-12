//! Package.json script execution with PATH injection, .env loading, and pre/post hooks.
//!
//! The main entry point is `run_script()`, which:
//! 1. Reads scripts from package.json (via lpm-workspace)
//! 2. Loads `.env` files (with optional mode from `--env` flag or `lpm.json` mapping)
//! 3. Checks for and runs pre-hooks
//! 4. Injects `node_modules/.bin` into PATH + `.env` vars into environment
//! 5. Runs the script via shell
//! 6. Checks for and runs post-hooks

mod environment;
use environment::print_env_context;
pub(crate) use environment::resolve_and_load_env_with_schema_validation;
pub use environment::{
    load_script_child_env_with_config, load_script_env, load_script_env_with_config,
};

use crate::bin_path;
use crate::bin_path::ManagedRuntimeHint;
use crate::dotenv;
use crate::hooks;
use crate::lpm_json;
use crate::npm_context::NpmScriptContext;
use crate::shell::{self, ShellCommand};
use lpm_common::LpmError;
use lpm_workspace::read_package_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to skip env schema validation (set by `--no-env-check`).
static SKIP_ENV_VALIDATION: AtomicBool = AtomicBool::new(false);

const LPM_SCRIPT_CHILD_ENV: &str = "LPM_SCRIPT_CHILD";

/// Set the global flag to skip env schema validation.
///
/// Called by the CLI layer when `--no-env-check` is passed.
pub fn set_skip_env_validation(skip: bool) {
    SKIP_ENV_VALIDATION.store(skip, Ordering::Relaxed);
}

pub(crate) fn should_skip_env_validation() -> bool {
    SKIP_ENV_VALIDATION.load(Ordering::Relaxed)
}

pub fn is_hidden_script_name(name: &str) -> bool {
    name.starts_with('.')
}

pub fn hidden_script_direct_invocation_allowed() -> bool {
    std::env::var_os(LPM_SCRIPT_CHILD_ENV).is_some()
}

fn mark_script_child_env(env_vars: &mut dotenv::ChildEnv) {
    env_vars.insert_runtime(LPM_SCRIPT_CHILD_ENV.to_string(), "1".to_string());
}

/// Escape a runtime argument so the platform shell treats it as data.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation can reject unsafe cmd.exe arguments"
)]
fn shell_quote_arg(
    arg: &str,
    _script_cmd: &str,
    _project_dir: &Path,
    _path: &str,
    _envs: &HashMap<String, String>,
) -> Result<String, LpmError> {
    let escaped = arg.replace('\'', "'\\''");
    Ok(format!("'{escaped}'"))
}

#[cfg(windows)]
fn shell_quote_arg(
    arg: &str,
    script_cmd: &str,
    project_dir: &Path,
    path: &str,
    envs: &HashMap<String, String>,
) -> Result<String, LpmError> {
    windows_shell_quote_arg(
        arg,
        windows_argument_receiver(script_cmd, project_dir, path, envs),
    )
}

/// What gets the arguments appended to a script run through cmd.exe: the
/// command that starts the script's last command, such as `jest` in
/// `tsc && jest` — not the script's first word.
#[cfg(any(test, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsArgumentReceiver {
    /// A program, which gets the arguments as cmd.exe read them once.
    Program,
    /// A batch file, such as a `node_modules\.bin` shim, whose `%*` has
    /// cmd.exe read them a second time.
    BatchFile,
    /// A command named by a variable or after a redirection, in a group, or
    /// one reached through a pipe or after an `if` or `for` that follows
    /// one, which have cmd.exe read the arguments again a number of times
    /// that depends on what runs, so no escaping is right for all of them.
    Unknown,
    /// No command: the script ends in an operator, a redirection or an
    /// escape, so the arguments would make a command of their own or name a
    /// redirection's file; or its last command is an `if` or a `for`, where
    /// they could be the command, the condition or the `else` branch, or a
    /// nested cmd.exe, `call` or `start`, which read them again as part of
    /// a command line of their own; or a variable it uses holds something
    /// that could make any of those so once cmd.exe expands it; or one of
    /// those is so where a pipe's cmd.exe reads the line again.
    Nothing,
}

#[cfg(any(test, windows))]
fn windows_shell_quote_arg(
    arg: &str,
    receiver: WindowsArgumentReceiver,
) -> Result<String, LpmError> {
    if arg
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(LpmError::Script(
            "runtime arguments containing line breaks cannot be passed safely through cmd.exe"
                .to_string(),
        ));
    }
    if receiver == WindowsArgumentReceiver::Nothing {
        return Err(LpmError::Script(format!(
            "cannot pass {arg:?} to this script: it ends in an operator, a redirection or an \
             escape; its last command is an `if`, a `for`, a nested cmd.exe, `call`, `start` or \
             a variable that could be one; a variable it uses holds a quote, an operator, a \
             redirection or a parenthesis; or a pipe's cmd.exe would find one of those reading \
             it again. On Windows its arguments could then make a command of their own or name \
             a file"
        )));
    }
    // Words cmd.exe gives no meaning to arrive intact however often it
    // reads them, so they need no quoting whatever receives them.
    if !arg.is_empty()
        && arg.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'.' | b'/' | b':' | b'\\' | b'@' | b'+' | b'='
                )
        })
    {
        return Ok(arg.to_string());
    }
    if receiver == WindowsArgumentReceiver::Unknown {
        return Err(LpmError::Script(format!(
            "cannot pass {arg:?} to this script safely: on Windows, arguments go to the script's \
             last command, and here cmd.exe would read them again on the way (through a pipe, \
             an `if` or `for` after one, parentheses, a variable, a redirection or a `/` right \
             after the command's name). Only arguments made of letters, digits and -_./:\\@+= \
             can be passed to it."
        )));
    }

    let mut quoted = String::with_capacity(arg.len().saturating_mul(2).saturating_add(2));
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in arg.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            for _ in 0..backslashes.saturating_mul(2).saturating_add(1) {
                quoted.push('\\');
            }
            quoted.push('"');
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        backslashes = 0;
    }
    for _ in 0..backslashes.saturating_mul(2) {
        quoted.push('\\');
    }
    quoted.push('"');

    let escaped = windows_escape_cmd_metacharacters(&quoted);
    if receiver == WindowsArgumentReceiver::BatchFile {
        Ok(windows_escape_cmd_metacharacters(&escaped))
    } else {
        Ok(escaped)
    }
}

#[cfg(any(test, windows))]
fn windows_escape_cmd_metacharacters(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len().saturating_mul(2));
    for character in value.chars() {
        if matches!(
            character,
            '(' | ')'
                | '['
                | ']'
                | '%'
                | '!'
                | '^'
                | '"'
                | '`'
                | '<'
                | '>'
                | '&'
                | '|'
                | ';'
                | ','
                | ' '
                | '*'
                | '?'
        ) {
            escaped.push('^');
        }
        escaped.push(character);
    }
    escaped
}

/// The `PATHEXT` cmd.exe uses when none is set.
#[cfg(windows)]
const WINDOWS_DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";

/// Makes cmd.exe leave the current directory out of its search for a
/// command named without a path.
#[cfg(windows)]
const NO_CURRENT_DIRECTORY_SEARCH_ENV: &str = "NoDefaultCurrentDirectoryInExePath";

/// The receiver as the script's cmd.exe finds it: with `envs`, the
/// project's environment, over the one LPM inherited, as the script gets
/// them, since a project's `.env` can set `PATHEXT` or
/// `NoDefaultCurrentDirectoryInExePath` too.
#[cfg(windows)]
fn windows_argument_receiver(
    script_cmd: &str,
    project_dir: &Path,
    path: &str,
    envs: &HashMap<String, String>,
) -> WindowsArgumentReceiver {
    // Windows matches variable names whatever their case, past ASCII too.
    let project_value = |name: &str| {
        envs.iter()
            .find(|(key, _)| key.to_uppercase() == name.to_uppercase())
            .map(|(_, value)| value.clone())
    };
    // cmd.exe expands `%NAME%` before it reads the commands on the line.
    let variable = |name: &str| {
        if name.is_empty() || name.contains('\0') {
            None
        } else if name.contains('=') {
            // Only cmd.exe's hidden variables have one, at the start.
            windows_dynamic_variable(name, script_cmd, project_dir)
        } else if name.eq_ignore_ascii_case("PATH") {
            Some(path.to_owned())
        } else {
            project_value(name)
                .or_else(|| {
                    std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
                })
                .or_else(|| windows_dynamic_variable(name, script_cmd, project_dir))
        }
    };
    if windows_expansion_may_change_commands(script_cmd, &variable) {
        return WindowsArgumentReceiver::Nothing;
    }
    let search_current_directory = project_value(NO_CURRENT_DIRECTORY_SEARCH_ENV).is_none()
        && std::env::var_os(NO_CURRENT_DIRECTORY_SEARCH_ENV).is_none();
    let pathext = project_value("PATHEXT")
        .or_else(|| std::env::var("PATHEXT").ok())
        .filter(|pathext| !pathext.trim().is_empty());
    let receiver = |script: &str| {
        windows_argument_receiver_in(
            script,
            project_dir,
            path,
            search_current_directory,
            pathext.as_deref().unwrap_or(WINDOWS_DEFAULT_PATHEXT),
        )
    };
    // What runs is found in the script as written and as cmd.exe expands
    // it, where `"%ComSpec%"` is cmd.exe itself; the stricter answer holds.
    match (
        receiver(script_cmd),
        receiver(&windows_expand_variables(script_cmd, &variable)),
    ) {
        (WindowsArgumentReceiver::Nothing, _) | (_, WindowsArgumentReceiver::Nothing) => {
            WindowsArgumentReceiver::Nothing
        }
        (WindowsArgumentReceiver::Unknown, _) | (_, WindowsArgumentReceiver::Unknown) => {
            WindowsArgumentReceiver::Unknown
        }
        (_, expanded) => expanded,
    }
}

/// `script_cmd` as cmd.exe expands it on a command line: each `%NAME%` that
/// `value` gives a value replaced by it. An unset name keeps its `%`, and
/// cmd.exe reads on from the `%` that closed it, which may open the next;
/// a reference with a `:` (`%NAME:~1%`, `%NAME:a=b%`) is left as written,
/// to be read as a variable.
#[cfg(any(test, windows))]
fn windows_expand_variables(script_cmd: &str, value: &dyn Fn(&str) -> Option<String>) -> String {
    let mut expanded = String::with_capacity(script_cmd.len());
    let mut rest = script_cmd;
    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            rest = &rest[start..];
            break;
        };
        let reference = &after[..end];
        let name = reference.split(':').next().unwrap_or_default();
        match value(name) {
            Some(value) if !reference.contains(':') => {
                expanded.push_str(&value);
                rest = &after[end + 1..];
            }
            Some(_) => {
                expanded.push('%');
                expanded.push_str(reference);
                expanded.push('%');
                rest = &after[end + 1..];
            }
            None => {
                expanded.push('%');
                expanded.push_str(reference);
                rest = &after[end..];
            }
        }
    }
    expanded.push_str(rest);
    expanded
}

/// What cmd.exe expands `%name%` to for a variable it provides itself when
/// the environment sets none: the current directory for `CD`; for
/// `CMDCMDLINE`, its own command line, which holds the script and its
/// arguments in quotes; for its hidden ones, such as `=C:`, the current
/// directory of drive C:, something taken as able to hold anything, a quote
/// included; and digits, a date, a time or its own directory for the rest.
#[cfg(windows)]
fn windows_dynamic_variable(name: &str, script_cmd: &str, project_dir: &Path) -> Option<String> {
    match name.to_ascii_uppercase().as_str() {
        "CD" | "__CD__" => Some(project_dir.display().to_string()),
        "CMDCMDLINE" => Some(format!("\"{script_cmd}\"")),
        hidden if hidden.starts_with('=') => Some("\"".to_owned()),
        "CMDEXTVERSION"
        | "DATE"
        | "ERRORLEVEL"
        | "HIGHESTNUMANODENUMBER"
        | "RANDOM"
        | "TIME"
        | "__APPDIR__" => Some(String::new()),
        _ => None,
    }
}

/// Whether expanding `%NAME%`, which cmd.exe does before it reads the
/// commands on the line, could change where [`windows_script_tail`] finds
/// them: a variable holds a quote or a line break, or, where it isn't
/// quoted, an operator, a redirection, a parenthesis or an escape, such as
/// `CHAIN=&&` in `node -e 0 %CHAIN%`, which would make the arguments a
/// command. `value` gives a variable's value as the script's cmd.exe sees
/// it, or `None` where it has none, which leaves `%NAME%` as written. Each
/// two neighbouring `%`s are taken as a variable, so whichever way cmd.exe
/// pairs them is covered.
#[cfg(any(test, windows))]
fn windows_expansion_may_change_commands(
    script_cmd: &str,
    value: &dyn Fn(&str) -> Option<String>,
) -> bool {
    // Each `%`, and whether it is in quotes as [`windows_script_tail`] reads
    // them, which is how cmd.exe reads them after the expansion as long as
    // no value checked holds a quote.
    let mut percents = Vec::new();
    let mut quoted = false;
    let mut characters = script_cmd.char_indices();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => quoted = !quoted,
            '%' => percents.push((index, quoted)),
            // A `^` doesn't keep a `%` from expanding: the expansion comes first.
            '^' if !quoted => {
                if let Some((next, '%')) = characters.next() {
                    percents.push((next, quoted));
                }
            }
            _ => {}
        }
    }
    let changes = |text: &str, quoted: bool| {
        text.chars().any(|character| {
            matches!(character, '"' | '\r' | '\n') || (!quoted && "&|<>()^".contains(character))
        })
    };
    percents.windows(2).any(|pair| {
        let ((start, quoted), (end, _)) = (pair[0], pair[1]);
        let reference = &script_cmd[start + 1..end];
        // `%NAME:~1,3%` and `%NAME:old=new%` expand NAME, changed.
        let name = reference
            .split_once(':')
            .map_or(reference, |(name, _)| name);
        value(name).is_some_and(|value| changes(&value, quoted) || changes(reference, false))
    })
}

/// [`windows_argument_receiver`], given whether cmd.exe looks for commands
/// in the current directory and the `PATHEXT` it tries.
#[cfg(windows)]
fn windows_argument_receiver_in(
    script_cmd: &str,
    project_dir: &Path,
    path: &str,
    search_current_directory: bool,
    pathext: &str,
) -> WindowsArgumentReceiver {
    let command_name = match windows_script_tail(script_cmd) {
        WindowsScriptTail::Command(command_name) => command_name,
        WindowsScriptTail::Unknown => return WindowsArgumentReceiver::Unknown,
        WindowsScriptTail::Nothing => return WindowsArgumentReceiver::Nothing,
    };
    let command_path = Path::new(command_name);
    let receiver_for = |extension: &str| {
        if extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd") {
            WindowsArgumentReceiver::BatchFile
        } else {
            WindowsArgumentReceiver::Program
        }
    };

    // Scripts run in the project directory. cmd.exe looks there for a name
    // with a directory in it, and first for a bare name unless
    // NoDefaultCurrentDirectoryInExePath is set, then along PATH. In each
    // directory it tries a name with an extension as it is, then the name
    // with each PATHEXT extension added, so `tool.exe` can be `tool.exe.cmd`.
    let bare_name = command_path.components().count() == 1;
    let mut search_dirs = Vec::new();
    if !bare_name || search_current_directory {
        search_dirs.push(project_dir.to_path_buf());
    }
    if bare_name {
        search_dirs.extend(std::env::split_paths(path));
    }
    let own_extension = command_path
        .extension()
        .map(|extension| extension.to_string_lossy().into_owned());
    let extensions = pathext
        .split(';')
        .map(str::trim)
        .filter(|extension| extension.len() > 1 && extension.starts_with('.'))
        .collect::<Vec<_>>();
    for directory in search_dirs {
        let candidate = directory.join(command_path);
        if let Some(own_extension) = &own_extension
            && candidate.is_file()
        {
            return receiver_for(own_extension);
        }
        for extension in &extensions {
            let mut with_extension = candidate.clone().into_os_string();
            with_extension.push(extension);
            if Path::new(&with_extension).is_file() {
                return receiver_for(&extension[1..]);
            }
        }
    }
    WindowsArgumentReceiver::Program
}

/// Whether cmd.exe takes `character` as space between words, as the C
/// runtime's `iswspace` does. That differs from Rust's whitespace at U+180E
/// (MONGOLIAN VOWEL SEPARATOR) alone, among all of the BMP.
#[cfg(any(test, windows))]
fn windows_is_space(character: char) -> bool {
    character.is_whitespace() || character == '\u{180E}'
}

/// The cmd.exe built-in among those that run another command, `call`,
/// `start`, `if` and `for`, that `word`, a first word as
/// [`windows_first_word`] gives it, names. As measured: `call` and `start`
/// also when one of `.+[]\:(/` follows (`start.`, `call:label`); `if` and
/// `for` also when `(` does, and no other (`if/i` is a program named `if`).
#[cfg(any(test, windows))]
fn windows_command_builtin(word: &str) -> Option<&'static str> {
    let word = word.to_ascii_lowercase();
    let names = |keyword: &str, endings: &str| {
        word.strip_prefix(keyword).is_some_and(|rest| {
            rest.chars()
                .next()
                .is_none_or(|next| endings.contains(next))
        })
    };
    if names("call", ".+[]\\:(/") {
        Some("call")
    } else if names("start", ".+[]\\:(/") {
        Some("start")
    } else if names("if", "(") {
        Some("if")
    } else if names("for", "(") {
        Some("for")
    } else {
        None
    }
}

/// The first word of a command as cmd.exe reads it to decide what runs:
/// after any leading delimiters, `@`, `(` and redirections, which can come
/// before the command (`2>nul call …`; cmd.exe refuses a line with one
/// before `if` or `for`, read here as one anyway), up to the next
/// delimiter, with each `^` taken out and the character after it kept
/// (`i^f` is `if`). `None` where a redirection's file name runs into an
/// unclosed quote, so what follows can't be told.
#[cfg(any(test, windows))]
fn windows_first_word(command: &str) -> Option<String> {
    let mut word = String::new();
    let mut characters = windows_after_redirections(command)?.chars();
    while let Some(character) = characters.next() {
        match character {
            '^' => word.extend(characters.next()),
            _ if windows_is_space(character) || ",;=".contains(character) => break,
            _ => word.push(character),
        }
    }
    Some(word)
}

/// `command` from where its first word starts: after leading delimiters,
/// `@`, `(`, and redirections such as `2>nul`, `>> "out file"` or `2>&1`.
#[cfg(any(test, windows))]
fn windows_after_redirections(command: &str) -> Option<&str> {
    let mut rest = command;
    loop {
        rest = rest.trim_start_matches(|character: char| {
            windows_is_space(character) || "@,;=(".contains(character)
        });
        let operator = rest
            .strip_prefix(|character: char| character.is_ascii_digit())
            .filter(|after| after.starts_with(['<', '>']))
            .unwrap_or(rest);
        let Some(after) = operator.strip_prefix(['<', '>']) else {
            return Some(rest);
        };
        let after = after.strip_prefix('>').unwrap_or(after);
        rest = match after.strip_prefix('&') {
            // `2>&1` names a handle, not a file.
            Some(handle) => handle.trim_start_matches(|character: char| character.is_ascii_digit()),
            None => windows_after_word(after.trim_start_matches(windows_is_space))?,
        };
    }
}

/// `text` after its first word, a redirection's file name, which ends at a
/// delimiter or another operator outside quotes and not escaped with `^`.
/// `None` where a quote in it never closes.
#[cfg(any(test, windows))]
fn windows_after_word(text: &str) -> Option<&str> {
    let mut quoted = false;
    let mut characters = text.char_indices();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '^' => {
                characters.next();
            }
            _ if windows_is_space(character) || ",;=<>|&".contains(character) => {
                return Some(&text[index..]);
            }
            _ => {}
        }
    }
    (!quoted).then_some("")
}

/// Whether a command whose first word is `word` is, or may be once a
/// variable in it expands, an `if` or a `for`. A quoted word is neither.
#[cfg(any(test, windows))]
fn windows_may_be_conditional(word: &str) -> bool {
    (word.contains('%') && !word.starts_with('"'))
        || matches!(windows_command_builtin(word), Some("if" | "for"))
}

/// Where cmd.exe takes the arguments appended to a script.
#[cfg(any(test, windows))]
#[derive(Debug, PartialEq, Eq)]
enum WindowsScriptTail<'a> {
    /// The command that starts the script's last command, which gets them
    /// after a single reading.
    Command(&'a str),
    /// Some command, through something that has cmd.exe read them again
    /// (see [`WindowsArgumentReceiver::Unknown`]).
    Unknown,
    /// No command (see [`WindowsArgumentReceiver::Nothing`]).
    Nothing,
}

#[cfg(any(test, windows))]
fn windows_script_tail(script_cmd: &str) -> WindowsScriptTail<'_> {
    // The last command starts after the last `&`, `&&`, `|` or `||` outside
    // quotes, not escaped with `^` and not part of a redirection like `2>&1`.
    let mut start = 0;
    let mut piped = false;
    // An `if` or `for` after a pipe takes the rest of the line as its body,
    // `&` and all, into the pipe's cmd.exe.
    let mut piped_body = false;
    // Where the pipe's own cmd.exe starts reading the rest of the line.
    let mut piped_from = None;
    let mut grouped = false;
    let mut quoted = false;
    let mut redirects_last = false;
    let mut previous = '\0';
    let mut characters = script_cmd.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        match character {
            // cmd.exe would stop reading before the arguments.
            '\r' | '\n' => return WindowsScriptTail::Nothing,
            '"' => quoted = !quoted,
            _ if quoted => {}
            '^' => {
                // A trailing `^` would escape the space before the arguments.
                if characters.next().is_none() {
                    return WindowsScriptTail::Nothing;
                }
                previous = '\0';
                redirects_last = false;
                continue;
            }
            '(' | ')' => grouped = true,
            '&' if matches!(previous, '<' | '>') => {}
            '&' | '|' => {
                let doubled = characters.next_if(|&(_, next)| next == character).is_some();
                piped = character == '|' && !doubled;
                grouped = false;
                start = index + if doubled { 2 } else { 1 };
                if !piped_body {
                    piped_from = piped.then_some(start);
                }
                if piped
                    && windows_first_word(&script_cmd[start..])
                        .is_none_or(|word| windows_may_be_conditional(&word))
                {
                    piped_body = true;
                }
            }
            _ => {}
        }
        if !windows_is_space(character) {
            redirects_last = !quoted
                && (matches!(character, '<' | '>')
                    || (character == '&' && matches!(previous, '<' | '>')));
        }
        previous = character;
    }
    if quoted {
        return WindowsScriptTail::Unknown;
    }
    let command = script_cmd[start..].trim_start_matches(|character: char| {
        windows_is_space(character) || "@,;=".contains(character)
    });
    // After a trailing operator the arguments would be a command; after a
    // trailing `>` or `<`, the redirection's file.
    if command.is_empty() || redirects_last {
        return WindowsScriptTail::Nothing;
    }
    // Whether arguments after `if <condition>` or `for … do`, with or
    // without a command or an `else`, end up a command, a condition or an
    // argument depends on what precedes them.
    let Some(first_word) = windows_first_word(command) else {
        return WindowsScriptTail::Nothing;
    };
    if windows_may_be_conditional(&first_word) {
        return WindowsScriptTail::Nothing;
    }
    // cmd.exe, `call` and `start` read what follows them again as a command
    // line of their own, where the arguments could be anything; none go to
    // them. Asked before anything else that ends the reading here.
    if windows_command_builtin(&first_word).is_some() || windows_reads_a_command_line(&first_word) {
        return WindowsScriptTail::Nothing;
    }
    // A pipe runs its commands in another cmd.exe, which reads them again.
    if let Some(from) = piped_from.filter(|_| piped || piped_body) {
        return windows_read_again(&script_cmd[from..]);
    }
    if grouped {
        return WindowsScriptTail::Unknown;
    }

    let (name, quoted_name) = match command.strip_prefix('"') {
        Some(rest) => {
            let Some((name, after)) = rest.split_once('"') else {
                return WindowsScriptTail::Unknown;
            };
            if !after.is_empty() && !after.starts_with(windows_is_space) {
                return WindowsScriptTail::Unknown;
            }
            (name, true)
        }
        None => (
            command.split(windows_is_space).next().unwrap_or_default(),
            false,
        ),
    };
    if windows_reads_a_command_line(name) {
        return WindowsScriptTail::Nothing;
    }
    // cmd.exe ends an unquoted name at a `/`, as in `capture/flag`, so the
    // command is not the one this name reads as.
    if !quoted_name && name.contains('/') {
        return WindowsScriptTail::Unknown;
    }
    // A name with these in it is a variable, a redirection, an escape or
    // more than one word to cmd.exe.
    if name.is_empty() || name.contains(|character: char| "%!^<>\",;=".contains(character)) {
        return WindowsScriptTail::Unknown;
    }
    // Split as Windows does, on either slash, whatever platform this runs on.
    let file_name = name.rsplit(['\\', '/']).next().unwrap_or_default();
    if file_name.is_empty()
        || ["if", "for"]
            .iter()
            .any(|keyword| file_name.eq_ignore_ascii_case(keyword))
    {
        return WindowsScriptTail::Unknown;
    }
    WindowsScriptTail::Command(name)
}

/// Whether a command whose first word or name is `word` is, or may be,
/// cmd.exe, `call` or `start`, which read what follows them again as a
/// command line of their own: by its file name, or that of what precedes a
/// `/` or `(` in it, where cmd.exe ends a name (`cmd/c`), quotes left out.
#[cfg(any(test, windows))]
fn windows_reads_a_command_line(word: &str) -> bool {
    let word = word.replace('"', "");
    let reads = |name: &str| {
        let file_name = name.rsplit(['\\', '/']).next().unwrap_or_default();
        ["cmd", "cmd.exe", "call", "start"]
            .iter()
            .any(|shell| file_name.eq_ignore_ascii_case(shell))
    };
    reads(&word) || word.split(['/', '(']).next().is_some_and(reads)
}

/// [`WindowsScriptTail::Unknown`], or `Nothing` where the pipe's cmd.exe,
/// reading `text`, the rest of the line from the pipe, again, could leave
/// the arguments with no command: the first reading took one level of `^`
/// out, so `^&` is an operator to the second, and the second expands
/// variables again, so a value holding `%OTHER%` expands there.
#[cfg(any(test, windows))]
fn windows_read_again(text: &str) -> WindowsScriptTail<'static> {
    if text.matches('%').count() > 1
        || text.matches('!').count() > 1
        || windows_script_tail(&windows_without_escapes(text)) == WindowsScriptTail::Nothing
    {
        WindowsScriptTail::Nothing
    } else {
        WindowsScriptTail::Unknown
    }
}

/// `text` with one level of `^` taken out outside quotes, as cmd.exe's
/// first reading leaves it for another.
#[cfg(any(test, windows))]
fn windows_without_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quoted = false;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '^' if !quoted => out.extend(characters.next()),
            '"' => {
                quoted = !quoted;
                out.push(character);
            }
            _ => out.push(character),
        }
    }
    out
}

/// Build the shell command for a script invocation by quoting every runtime
/// argument for the platform shell. The script body is owned by
/// `package.json` (developer-authored) and legitimately contains shell
/// metacharacters (pipes, redirects, `$VAR`), so it is concatenated
/// verbatim. Extra args, however, come from the CLI tail (already
/// split into argv by the user's shell) and must not re-introduce
/// metacharacter semantics — otherwise `lpm run x -- "; rm -rf ~"`
/// detonates inside `sh -c`. `envs` is what the script's environment adds
/// to LPM's, which on Windows decides how cmd.exe finds the receiver.
pub fn assemble_shell_command(
    script_cmd: &str,
    extra_args: &[String],
    project_dir: &Path,
    path: &str,
    envs: &HashMap<String, String>,
) -> Result<String, LpmError> {
    if extra_args.is_empty() {
        return Ok(script_cmd.to_string());
    }
    let mut full_command = String::with_capacity(
        script_cmd.len() + extra_args.iter().map(|arg| arg.len() + 3).sum::<usize>(),
    );
    full_command.push_str(script_cmd);
    for arg in extra_args {
        full_command.push(' ');
        full_command.push_str(&shell_quote_arg(arg, script_cmd, project_dir, path, envs)?);
    }
    Ok(full_command)
}

/// Run a package.json script by name, with PATH injection, .env loading, and hooks.
///
/// # Arguments
/// * `project_dir` — project root (where package.json lives)
/// * `script_name` — the script key (e.g., "build", "dev", "test")
/// * `extra_args` — additional arguments appended to the script command
/// * `env_mode` — optional env mode from `--env` flag (e.g., "staging")
/// * `bin_hint` — pre-resolved managed-runtime bin from `lpm_runtime::ensure_runtime`,
///   or `Unknown` to fall back to silent detect.
pub fn run_script(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_script_with_envs(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run a package.json script with additional environment variables.
///
/// Like `run_script`, but accepts extra env vars to inject into the child process
/// without mutating global process state (safe alternative to `std::env::set_var`).
pub fn run_script_with_envs(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_script_with_envs_and_config(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
        config.as_ref(),
    )
}

pub fn run_script_with_envs_and_config(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let ResolvedScript {
        command: script_cmd,
        scripts,
        context,
    } = resolve_script_command_with_config(
        project_dir,
        script_name,
        config,
        ScriptPreference::PackageScript,
    )?;

    // Build PATH with .bin dirs prepended
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;

    // Load .env files + merge extra env vars (from HTTPS/tunnel/network setup)
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        script_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(script_name),
        service: None,
    };
    print_env_context(&loaded);
    let mut env_vars = loaded.layers.take_child_env()?;
    for (key, value) in extra_envs {
        env_vars.insert_runtime(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);
    env_vars.apply_npm_context(&context, script_name, &script_cmd);
    let pre_command = hooks::find_pre_hook(&scripts, script_name);
    if pre_command.is_some() {
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
    }

    // Run pre-hook if it exists
    if let Some(pre_cmd) = pre_command {
        let pre_name = hooks::pre_hook_name(script_name);
        env_vars.apply_npm_context(&context, &pre_name, pre_cmd);
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
        tracing::debug!("running pre-hook: {pre_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: pre_cmd,
            cwd: project_dir,
            path: &path,
            envs: env_vars.vars(),
        })?;

        if !status.success() {
            return Err(script_phase_error(
                &pre_name,
                &status,
                String::new(),
                String::new(),
            ));
        }
    }

    env_vars.apply_npm_context(&context, script_name, &script_cmd);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;
    let full_cmd =
        assemble_shell_command(&script_cmd, extra_args, project_dir, &path, env_vars.vars())?;

    // Run the main script
    let status = shell::spawn_shell(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: env_vars.vars(),
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    // Run post-hook if it exists
    if let Some(post_cmd) = hooks::find_post_hook(&scripts, script_name) {
        let post_name = hooks::post_hook_name(script_name);
        env_vars.apply_npm_context(&context, &post_name, post_cmd);
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
        tracing::debug!("running post-hook: {post_name}");

        let status = shell::spawn_shell(&ShellCommand {
            command: post_cmd,
            cwd: project_dir,
            path: &path,
            envs: env_vars.vars(),
        })?;

        if !status.success() {
            return Err(script_phase_error(
                &post_name,
                &status,
                String::new(),
                String::new(),
            ));
        }
    }

    Ok(())
}

pub struct DevScriptEndpointOptions {
    pub requested_port: Option<u16>,
    pub discovery: shell::EndpointDiscovery,
    pub stop_requested: Arc<AtomicBool>,
    pub on_endpoint: shell::EndpointResultCallback,
    pub on_shutdown_started: Option<crate::ShutdownStartedCallback>,
}

pub fn run_dev_script_with_envs(
    project_dir: &Path,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    endpoint_options: DevScriptEndpointOptions,
) -> Result<(), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_dev_script_with_envs_and_config(
        project_dir,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
        config.as_ref(),
        endpoint_options,
    )
}

pub fn run_dev_script_with_envs_and_config(
    project_dir: &Path,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
    endpoint_options: DevScriptEndpointOptions,
) -> Result<(), LpmError> {
    #[cfg(unix)]
    let _stop_signals = shell::register_stop_signals(&endpoint_options.stop_requested)?;
    let ResolvedScript {
        command: script_cmd,
        scripts,
        context,
    } = resolve_script_command_with_config(
        project_dir,
        "dev",
        config,
        ScriptPreference::TaskCommand,
    )?;
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        "dev",
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    print_env_context(&loaded);
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::Development,
        service: None,
    };
    let mut env_vars = loaded.layers.take_child_env()?;
    for (key, value) in extra_envs {
        env_vars.insert_runtime(key.clone(), value.clone());
    }
    mark_script_child_env(&mut env_vars);
    env_vars.apply_npm_context(&context, "dev", &script_cmd);
    let pre_command = hooks::find_pre_hook(&scripts, "dev");
    if pre_command.is_some() {
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
    }

    if let Some(pre_cmd) = pre_command {
        env_vars.apply_npm_context(&context, "predev", pre_cmd);
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
        let status = shell::spawn_shell_cancellable(
            &ShellCommand {
                command: pre_cmd,
                cwd: project_dir,
                path: &path,
                envs: env_vars.vars(),
            },
            &endpoint_options.stop_requested,
        )?;
        if endpoint_options.stop_requested.load(Ordering::Acquire) {
            return Ok(());
        }
        if !status.success() {
            return Err(script_phase_error(
                "predev",
                &status,
                String::new(),
                String::new(),
            ));
        }
    }

    env_vars.apply_npm_context(&context, "dev", &script_cmd);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;
    let full_cmd =
        assemble_shell_command(&script_cmd, extra_args, project_dir, &path, env_vars.vars())?;
    let status = shell::spawn_shell_with_endpoint(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: env_vars.vars(),
        },
        endpoint_options.requested_port,
        endpoint_options.discovery,
        Arc::clone(&endpoint_options.stop_requested),
        endpoint_options.on_endpoint,
        endpoint_options.on_shutdown_started,
    )?;
    if endpoint_options
        .stop_requested
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(());
    }
    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    if let Some(post_cmd) = hooks::find_post_hook(&scripts, "dev") {
        env_vars.apply_npm_context(&context, "postdev", post_cmd);
        dotenv::validate_child_env(
            &mut env_vars,
            validator.as_ref(),
            eval_context,
            &path,
            validate_schema,
        )?;
        let status = shell::spawn_shell_cancellable(
            &ShellCommand {
                command: post_cmd,
                cwd: project_dir,
                path: &path,
                envs: env_vars.vars(),
            },
            &endpoint_options.stop_requested,
        )?;
        if endpoint_options.stop_requested.load(Ordering::Acquire) {
            return Ok(());
        }
        if !status.success() {
            return Err(script_phase_error(
                "postdev",
                &status,
                String::new(),
                String::new(),
            ));
        }
    }
    Ok(())
}

fn script_phase_error(
    phase: &str,
    status: &std::process::ExitStatus,
    stdout: String,
    stderr: String,
) -> LpmError {
    LpmError::ScriptPhase {
        phase: phase.to_string(),
        code: shell::exit_code(status),
        stdout,
        stderr,
    }
}

/// Result of a captured script execution.
pub struct ScriptOutput {
    /// Captured stdout (also displayed to terminal in real-time).
    pub stdout: String,
    /// Captured stderr (also displayed to terminal in real-time).
    pub stderr: String,
}

/// Run a script with tee-captured stdout/stderr.
///
/// Like `run_script`, but captures output for caching while still streaming
/// to the terminal. The capture includes pre/post hooks.
pub fn run_script_captured(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_script_captured_with_reserved_stdout(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        bin_hint,
        false,
    )
}

/// Run package scripts and their hooks with live output on stderr when stdout is reserved.
pub fn run_script_captured_with_reserved_stdout(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
) -> Result<ScriptOutput, LpmError> {
    run_script_with_output(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        bin_hint,
        |command| shell::spawn_shell_tee_with_reserved_stdout(command, reserve_stdout),
    )
    .map_err(without_echoed_output)
}

fn without_echoed_output(error: LpmError) -> LpmError {
    match error {
        LpmError::ScriptPhase { phase, code, .. } => LpmError::ScriptPhase {
            phase,
            code,
            stdout: String::new(),
            stderr: String::new(),
        },
        LpmError::ScriptWithOutput { code, .. } => LpmError::ExitCode(code),
        error => error,
    }
}

/// Run a script with fully captured output (no terminal echo).
///
/// Used by buffered parallel mode. Output is captured but NOT displayed
/// to the terminal — the caller prints it after the task completes.
pub fn run_script_buffered(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_script_with_output(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        bin_hint,
        shell::spawn_shell_capture,
    )
}

fn run_script_with_output(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
    mut spawn: impl FnMut(&ShellCommand<'_>) -> Result<shell::CapturedOutput, LpmError>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    run_script_with_output_at_path(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        &path,
        &mut spawn,
    )
}

/// Run a package script and its hooks within a workspace PATH boundary.
/// A shared signal scope prevents later hooks from starting after cancellation.
pub fn run_package_script_bounded(
    project_dir: &Path,
    boundary: &Path,
    script_name: &str,
    extra_args: &[String],
    bin_hint: &ManagedRuntimeHint,
    signals: &crate::execution::ExecutionSignals,
    capture: bool,
) -> Result<ScriptOutput, LpmError> {
    let mut capture_session = lpm_common::process_output::CaptureSession::default();
    let path = bin_path::build_path_with_bins_bounded(project_dir, boundary, bin_hint)?;
    run_script_with_output_at_path(project_dir, script_name, extra_args, None, &path, |spec| {
        let mut command = shell::shell_process(spec.command)?;
        shell::strip_inherited_env_hooks(&mut command);
        command
            .current_dir(spec.cwd)
            .envs(spec.envs)
            .env("PATH", spec.path);
        if capture {
            signals.capture_in_session(&mut command, &mut capture_session)
        } else {
            let status = signals.run(&mut command)?;
            Ok(shell::CapturedOutput {
                status,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    })
}

fn run_script_with_output_at_path(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    path: &str,
    spawn: impl FnMut(&ShellCommand<'_>) -> Result<shell::CapturedOutput, LpmError>,
) -> Result<ScriptOutput, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_script_with_output_at_path_and_config(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        path,
        config.as_ref(),
        spawn,
    )
}

fn run_script_with_output_at_path_and_config(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    path: &str,
    config: Option<&lpm_json::LpmJsonConfig>,
    mut spawn: impl FnMut(&ShellCommand<'_>) -> Result<shell::CapturedOutput, LpmError>,
) -> Result<ScriptOutput, LpmError> {
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let ResolvedScript {
        command,
        scripts,
        context,
    } = resolve_script_command_with_config(
        project_dir,
        script_name,
        config,
        ScriptPreference::PackageScript,
    )?;
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        script_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(script_name),
        service: None,
    };
    let mut environment = loaded.layers.take_child_env()?;
    dotenv::announce_personal_overrides(
        &environment,
        loaded.env_name.as_deref().unwrap_or("default"),
    );
    mark_script_child_env(&mut environment);
    let pre_command = hooks::find_pre_hook(&scripts, script_name);
    if pre_command.is_some() {
        environment.apply_npm_context(&context, script_name, &command);
        dotenv::validate_child_env(
            &mut environment,
            validator.as_ref(),
            eval_context,
            path,
            validate_schema,
        )?;
    }
    let pre_name = hooks::pre_hook_name(script_name);
    let post_name = hooks::post_hook_name(script_name);
    let phases = [
        (pre_name.as_str(), pre_command),
        (script_name, Some(command.as_str())),
        (
            post_name.as_str(),
            hooks::find_post_hook(&scripts, script_name),
        ),
    ];
    let mut output = ScriptOutput {
        stdout: String::new(),
        stderr: String::new(),
    };
    for (phase, declared_command) in phases {
        let Some(declared_command) = declared_command else {
            continue;
        };
        environment.apply_npm_context(&context, phase, declared_command);
        dotenv::validate_child_env(
            &mut environment,
            validator.as_ref(),
            eval_context,
            path,
            validate_schema,
        )?;
        let full_command;
        let command = if phase == script_name {
            full_command = assemble_shell_command(
                declared_command,
                extra_args,
                project_dir,
                path,
                environment.vars(),
            )?;
            full_command.as_str()
        } else {
            declared_command
        };
        let captured = match spawn(&ShellCommand {
            command,
            cwd: project_dir,
            path,
            envs: environment.vars(),
        }) {
            Ok(captured) => captured,
            Err(LpmError::ExitCode(code)) => {
                return Err(LpmError::ScriptPhase {
                    phase: phase.to_string(),
                    code,
                    stdout: output.stdout,
                    stderr: output.stderr,
                });
            }
            Err(error) => return Err(error),
        };
        shell::append_capped_output(&mut output.stdout, &captured.stdout);
        shell::append_capped_output(&mut output.stderr, &captured.stderr);
        if !captured.status.success() {
            return Err(script_phase_error(
                phase,
                &captured.status,
                output.stdout,
                output.stderr,
            ));
        }
    }
    Ok(output)
}

/// Run an explicit command with fully captured output (no terminal echo).
pub fn run_command_buffered(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

pub fn run_task_command_buffered(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run an explicit command with fully captured output and additional env vars.
pub fn run_command_buffered_with_envs(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
    )
}

fn run_command_buffered_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_command_buffered_named_with_config(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
        config.as_ref(),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "runner inputs include a caller-owned configuration snapshot"
)]
fn run_command_buffered_named_with_config(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        task_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(task_name),
        service: None,
    };
    let mut env_vars = loaded.layers.take_child_env()?;
    dotenv::announce_personal_overrides(&env_vars, loaded.env_name.as_deref().unwrap_or("default"));
    for (key, value) in extra_envs {
        env_vars.insert_runtime(key.clone(), value.clone());
    }
    if !task_name.is_empty() {
        env_vars.apply_npm_context(
            &NpmScriptContext::load(project_dir, &std::env::current_dir()?)?,
            task_name,
            command,
        );
    }
    mark_script_child_env(&mut env_vars);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;

    let full_cmd =
        assemble_shell_command(command, extra_args, project_dir, &path, env_vars.vars())?;

    let captured = shell::spawn_shell_capture(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: env_vars.vars(),
    })?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run a script with prefixed live output (for streaming parallel mode).
pub fn run_script_prefixed(
    project_dir: &Path,
    script_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_script_with_output(
        project_dir,
        script_name,
        extra_args,
        env_mode,
        bin_hint,
        |command| shell::spawn_shell_prefixed(command, prefix, color),
    )
}

/// Run an explicit command with prefixed live output.
pub fn run_command_prefixed(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_prefixed_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        prefix,
        color,
        bin_hint,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the runner boundary keeps the task, shell, environment, output, and runtime inputs explicit"
)]
pub fn run_task_command_prefixed(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_prefixed_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        prefix,
        color,
        bin_hint,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the runner boundary keeps the task, shell, environment, output, and runtime inputs explicit"
)]
fn run_command_prefixed_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_command_prefixed_named_with_config(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        prefix,
        color,
        bin_hint,
        config.as_ref(),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "runner inputs include a caller-owned configuration snapshot"
)]
fn run_command_prefixed_named_with_config(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    prefix: &str,
    color: &str,
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        task_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(task_name),
        service: None,
    };
    let mut env_vars = loaded.layers.take_child_env()?;
    dotenv::announce_personal_overrides(&env_vars, loaded.env_name.as_deref().unwrap_or("default"));
    if !task_name.is_empty() {
        env_vars.apply_npm_context(
            &NpmScriptContext::load(project_dir, &std::env::current_dir()?)?,
            task_name,
            command,
        );
    }
    mark_script_child_env(&mut env_vars);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;

    let full_cmd =
        assemble_shell_command(command, extra_args, project_dir, &path, env_vars.vars())?;

    let captured = shell::spawn_shell_prefixed(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: env_vars.vars(),
        },
        prefix,
        color,
    )?;

    if !captured.status.success() {
        return Err(LpmError::ScriptWithOutput {
            code: shell::exit_code(&captured.status),
            stdout: captured.stdout,
            stderr: captured.stderr,
        });
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Run an explicit command string (from lpm.json task config).
///
/// Unlike `run_script`, this does NOT look up package.json scripts —
/// it executes the given command directly with the same PATH, .env, and
/// vault environment as a normal script run. Pre/post hooks are not applied
/// since command tasks are not package.json scripts.
pub fn run_command(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

pub fn run_task_command(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        &[],
        bin_hint,
    )
}

/// Run an explicit command string with additional environment variables.
pub fn run_command_with_envs(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    run_command_named_with_envs(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
    )
}

fn run_command_named_with_envs(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_command_named_with_envs_and_config(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        extra_envs,
        bin_hint,
        config.as_ref(),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "runner inputs include a caller-owned configuration snapshot"
)]
fn run_command_named_with_envs_and_config(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    extra_envs: &[(String, String)],
    bin_hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        task_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(task_name),
        service: None,
    };
    let mut env_vars = loaded.layers.take_child_env()?;
    dotenv::announce_personal_overrides(&env_vars, loaded.env_name.as_deref().unwrap_or("default"));
    for (key, value) in extra_envs {
        env_vars.insert_runtime(key.clone(), value.clone());
    }
    if !task_name.is_empty() {
        env_vars.apply_npm_context(
            &NpmScriptContext::load(project_dir, &std::env::current_dir()?)?,
            task_name,
            command,
        );
    }
    mark_script_child_env(&mut env_vars);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;

    let full_cmd =
        assemble_shell_command(command, extra_args, project_dir, &path, env_vars.vars())?;

    let status = shell::spawn_shell(&ShellCommand {
        command: &full_cmd,
        cwd: project_dir,
        path: &path,
        envs: env_vars.vars(),
    })?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    Ok(())
}

/// Build a direct process command for a project-local binary.
///
/// Resolves `command_name` only from `node_modules/.bin` directories discovered
/// from `project_dir` upward. The caller gets npm/pnpm-style local-bin PATH
/// precedence without a fallback to arbitrary system PATH executables.
pub fn build_local_bin_command(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<Command, LpmError> {
    let bin_path = resolve_local_bin_path(project_dir, command_name)?;
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    build_configured_local_bin_command(
        project_dir,
        bin_path,
        extra_args,
        env_mode,
        no_env_check,
        path,
        lpm_env::EnvStage::Runtime,
        None,
    )
}

/// Build a direct process command for a project-local binary without allowing
/// binary or PATH discovery above `boundary`.
pub fn build_local_bin_command_bounded(
    project_dir: &Path,
    boundary: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<Command, LpmError> {
    build_local_bin_command_bounded_with_stage(
        project_dir,
        boundary,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        bin_hint,
        lpm_env::EnvStage::Runtime,
    )
}

/// Build a bounded local binary command with the caller's execution stage.
#[expect(clippy::too_many_arguments)]
pub fn build_local_bin_command_bounded_with_stage(
    project_dir: &Path,
    boundary: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
    stage: lpm_env::EnvStage,
) -> Result<Command, LpmError> {
    build_local_bin_command_bounded_for_script(
        project_dir,
        boundary,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        bin_hint,
        stage,
        None,
    )
}

/// Build a bounded local runner with the environment selected by its script name.
#[expect(clippy::too_many_arguments)]
pub fn build_local_bin_command_bounded_for_script(
    project_dir: &Path,
    boundary: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
    stage: lpm_env::EnvStage,
    script_name: Option<&str>,
) -> Result<Command, LpmError> {
    let bin_dirs = bin_path::find_bin_dirs_bounded(project_dir, boundary)?;
    let bin_path = resolve_local_bin_path_from_dirs(command_name, &bin_dirs)?;
    let path = bin_path::build_path_from_bin_dirs(project_dir, &bin_dirs, bin_hint)?;
    build_configured_local_bin_command(
        project_dir,
        bin_path,
        extra_args,
        env_mode,
        no_env_check,
        path,
        stage,
        script_name,
    )
}

#[expect(clippy::too_many_arguments)]
fn build_configured_local_bin_command(
    project_dir: &Path,
    bin_path: PathBuf,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    path: String,
    stage: lpm_env::EnvStage,
    script_name: Option<&str>,
) -> Result<Command, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    let explicit_mode = env_mode.or_else(|| {
        config
            .as_ref()?
            .tasks
            .get(script_name?)
            .and_then(|task| task.env.as_deref())
    });
    let resolved = if explicit_mode.is_some() {
        dotenv::resolve_project_environment(explicit_mode, config.as_ref())?
    } else if let Some(resolved) = config.as_ref().and_then(|config| {
        lpm_env::resolver::resolve_from_script(
            script_name?,
            &config.env,
            config.environments.as_ref(),
        )
    }) {
        lpm_env::resolver::validate_env_name(&resolved.canonical).map_err(|_| {
            LpmError::EnvValidation(lpm_env::resolver::invalid_identity_message(
                &resolved.canonical,
                resolved.alias.as_deref(),
            ))
        })?;
        resolved
    } else {
        dotenv::resolve_project_environment(None, config.as_ref())?
    };

    let mut env_vars = dotenv::load_project_env_unvalidated_for_resolved(
        project_dir,
        &resolved,
        config.as_ref(),
        dotenv::OverridePolicy::Apply,
    )?;
    dotenv::announce_personal_overrides(&env_vars, &resolved.canonical);
    let validator = config
        .as_ref()
        .filter(|_| !no_env_check)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        lpm_env::EvalContext {
            environment: &resolved.canonical,
            stage,
            service: None,
        },
        &path,
        !no_env_check,
    )?;
    let env_vars = env_vars.into_vars();

    let mut command = Command::new(&bin_path);
    shell::strip_inherited_env_hooks(&mut command);
    command
        .args(extra_args)
        .current_dir(project_dir)
        .env("PATH", &path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if !env_vars.is_empty() {
        command.envs(&env_vars);
    }

    Ok(command)
}

/// Execute a project-local binary directly, with LPM env and PATH handling.
pub fn run_local_bin(
    project_dir: &Path,
    command_name: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_env_check: bool,
    bin_hint: &ManagedRuntimeHint,
) -> Result<(), LpmError> {
    let command = build_local_bin_command(
        project_dir,
        command_name,
        extra_args,
        env_mode,
        no_env_check,
        bin_hint,
    )?;
    run_built_local_bin_command(command)
}

/// Run a command from [`build_local_bin_command`], forwarding signals and
/// the child's exit code.
pub fn run_built_local_bin_command(mut command: Command) -> Result<(), LpmError> {
    let signals = crate::execution::ExecutionSignals::new()?;
    let status = signals.run(&mut command)?;

    if !status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&status)));
    }

    Ok(())
}

/// Return whether `command_name` resolves to a project-local binary.
///
/// The lookup is intentionally the same `node_modules/.bin`-only resolution
/// used by [`run_local_bin`]; it never consults the inherited system PATH.
pub fn local_bin_exists(project_dir: &Path, command_name: &str) -> bool {
    resolve_local_bin_path(project_dir, command_name).is_ok()
}

fn resolve_local_bin_path(project_dir: &Path, command_name: &str) -> Result<PathBuf, LpmError> {
    if command_name.trim().is_empty() {
        return Err(LpmError::Script(
            "`lpm exec` requires a project-local binary name".into(),
        ));
    }
    if is_path_like_command(command_name) {
        return Err(LpmError::Script(format!(
            "`lpm exec` runs project-local binaries, not file paths. Use `lpm {command_name}` to run a JS/TS source file directly."
        )));
    }

    let bin_dirs = bin_path::find_bin_dirs(project_dir);
    resolve_local_bin_path_from_dirs(command_name, &bin_dirs)
}

/// Resolve a project-local executable without searching above the project or workspace boundary.
pub fn resolve_local_bin_path_bounded(
    project_dir: &Path,
    boundary: &Path,
    command_name: &str,
) -> Result<PathBuf, LpmError> {
    let bin_dirs = bin_path::find_bin_dirs_bounded(project_dir, boundary)?;
    resolve_local_bin_path_from_dirs(command_name, &bin_dirs)
}

fn resolve_local_bin_path_from_dirs(
    command_name: &str,
    bin_dirs: &[PathBuf],
) -> Result<PathBuf, LpmError> {
    if command_name.trim().is_empty() {
        return Err(LpmError::Script(
            "`lpm exec` requires a project-local binary name".into(),
        ));
    }
    if is_path_like_command(command_name) {
        return Err(LpmError::Script(format!(
            "`lpm exec` runs project-local binaries, not file paths. Use `lpm {command_name}` to run a JS/TS source file directly."
        )));
    }

    let candidate_names = local_bin_candidate_names(command_name);
    for bin_dir in bin_dirs {
        for candidate_name in &candidate_names {
            let candidate = bin_dir.join(candidate_name);
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
    }

    let searched = if bin_dirs.is_empty() {
        "no node_modules/.bin directories were found".to_string()
    } else {
        format!(
            "searched {}",
            bin_dirs
                .iter()
                .map(|dir| dir.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Err(LpmError::Script(format!(
        "project-local binary '{command_name}' was not found ({searched}). Run `lpm install` to link dependencies, or use `lpm dlx <pkg>` to run a package without adding it to the project."
    )))
}

fn is_path_like_command(command_name: &str) -> bool {
    command_name.contains('/')
        || command_name.contains('\\')
        || Path::new(command_name).is_absolute()
}

fn local_bin_candidate_names(command_name: &str) -> Vec<String> {
    local_bin_candidate_names_for_platform(command_name, cfg!(windows))
}

fn local_bin_candidate_names_for_platform(command_name: &str, windows: bool) -> Vec<String> {
    if !windows || Path::new(command_name).extension().is_some() {
        return vec![command_name.to_string()];
    }
    ["cmd", "exe", "bat", ""]
        .iter()
        .map(|ext| {
            if ext.is_empty() {
                command_name.to_string()
            } else {
                format!("{command_name}.{ext}")
            }
        })
        .collect()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Run an explicit command with tee-captured output (for caching).
pub fn run_command_captured(
    project_dir: &Path,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named(
        project_dir,
        "",
        command,
        extra_args,
        env_mode,
        bin_hint,
        false,
    )
}

pub fn run_task_command_captured(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        bin_hint,
        false,
    )
}

pub fn run_task_command_captured_with_reserved_stdout(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        bin_hint,
        reserve_stdout,
    )
}

fn run_command_captured_named(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
) -> Result<ScriptOutput, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    run_command_captured_named_with_config(
        project_dir,
        task_name,
        command,
        extra_args,
        env_mode,
        bin_hint,
        reserve_stdout,
        config.as_ref(),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "runner inputs include a caller-owned configuration snapshot"
)]
fn run_command_captured_named_with_config(
    project_dir: &Path,
    task_name: &str,
    command: &str,
    extra_args: &[String],
    env_mode: Option<&str>,
    bin_hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, bin_hint)?;
    let validate_schema = !should_skip_env_validation();
    let validator = config
        .filter(|_| validate_schema)
        .and_then(|config| config.env_schema.as_ref())
        .map(lpm_env::EnvValidator::new);
    let mut loaded = resolve_and_load_env_with_schema_validation(
        project_dir,
        task_name,
        env_mode,
        config,
        false,
        dotenv::OverridePolicy::Apply,
    )?;
    let eval_context = lpm_env::EvalContext {
        environment: loaded.env_name.as_deref().unwrap_or("default"),
        stage: lpm_env::EnvStage::for_script(task_name),
        service: None,
    };
    let mut env_vars = loaded.layers.take_child_env()?;
    dotenv::announce_personal_overrides(&env_vars, loaded.env_name.as_deref().unwrap_or("default"));
    if !task_name.is_empty() {
        env_vars.apply_npm_context(
            &NpmScriptContext::load(project_dir, &std::env::current_dir()?)?,
            task_name,
            command,
        );
    }
    mark_script_child_env(&mut env_vars);
    dotenv::validate_child_env(
        &mut env_vars,
        validator.as_ref(),
        eval_context,
        &path,
        validate_schema,
    )?;

    let full_cmd =
        assemble_shell_command(command, extra_args, project_dir, &path, env_vars.vars())?;

    let captured = shell::spawn_shell_tee_with_reserved_stdout(
        &ShellCommand {
            command: &full_cmd,
            cwd: project_dir,
            path: &path,
            envs: env_vars.vars(),
        },
        reserve_stdout,
    )?;

    if !captured.status.success() {
        return Err(LpmError::ExitCode(shell::exit_code(&captured.status)));
    }

    Ok(ScriptOutput {
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Resolve a development command, preferring an explicit lpm.json task command.
pub fn script_command(project_dir: &Path, script_name: &str) -> Result<String, LpmError> {
    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    script_command_with_config(project_dir, script_name, config.as_ref())
}

pub fn script_command_with_config(
    project_dir: &Path,
    script_name: &str,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<String, LpmError> {
    resolve_script_command_with_config(
        project_dir,
        script_name,
        config,
        ScriptPreference::TaskCommand,
    )
    .map(|resolved| resolved.command)
}

/// Resolve a script command from package.json or lpm.json tasks.
///
/// Lookup order:
/// 1. `package.json` scripts (standard npm convention)
/// 2. `lpm.json` tasks with a `command` field (pure lpm.json projects)
///
/// Returns `(script_command, all_scripts_map)` for hook resolution.
struct ResolvedScript {
    command: String,
    scripts: HashMap<String, String>,
    context: NpmScriptContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScriptPreference {
    PackageScript,
    TaskCommand,
}

fn resolve_script_command_with_config(
    project_dir: &Path,
    script_name: &str,
    lpm_config: Option<&lpm_json::LpmJsonConfig>,
    preference: ScriptPreference,
) -> Result<ResolvedScript, LpmError> {
    let pkg_json_path = project_dir.join("package.json");

    let package = match read_package_json(&pkg_json_path) {
        Ok(package) => Some(package),
        Err(lpm_workspace::WorkspaceError::NotFound(_)) => None,
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };

    let context = NpmScriptContext::new(
        package.as_ref().and_then(|pkg| pkg.name.as_deref()),
        package.as_ref().and_then(|pkg| pkg.version.as_deref()),
        project_dir,
        &std::env::current_dir()?,
    );

    let task_command = lpm_config
        .and_then(|config| config.tasks.get(script_name))
        .and_then(|task| task.command.as_ref());

    if (preference == ScriptPreference::PackageScript || task_command.is_none())
        && let Some(pkg) = &package
        && let Some(command) = pkg.scripts.get(script_name)
    {
        return Ok(ResolvedScript {
            command: command.clone(),
            scripts: pkg.scripts.clone(),
            context,
        });
    }

    if let Some(command) = task_command {
        return Ok(ResolvedScript {
            command: command.clone(),
            scripts: HashMap::new(),
            context,
        });
    }

    // Neither package.json nor lpm.json had the script
    if let Some(pkg) = package {
        Err(script_not_found_error(script_name, &pkg.scripts))
    } else {
        let lpm_tasks = lpm_config
            .map(|c| {
                c.tasks
                    .iter()
                    .filter_map(|(k, v)| v.command.as_ref().map(|c| (k.clone(), c.clone())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();

        if lpm_tasks.is_empty() {
            Err(LpmError::Script(format!(
                "no '{script_name}' command configured; add scripts.{script_name} to package.json or tasks.{script_name}.command to lpm.json"
            )))
        } else {
            Err(script_not_found_error(script_name, &lpm_tasks))
        }
    }
}

/// Validate that an env mode string is safe to use in path construction.
///
/// Rejects modes containing path separators, parent-directory traversal,
/// null bytes, or empty strings — preventing path injection via lpm.json.
///
/// Validation is now performed inside `dotenv::load_project_env`. This function
/// is retained for backward compatibility with existing tests.
#[cfg(test)]
fn validate_env_mode(mode: &str) -> bool {
    !mode.is_empty()
        && !mode.contains('/')
        && !mode.contains('\\')
        && !mode.contains("..")
        && !mode.contains('\0')
}

/// List available scripts from package.json and lpm.json tasks.
/// Returns (script_name, command) pairs, sorted alphabetically.
pub fn list_scripts(project_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let mut all_scripts: HashMap<String, String> = HashMap::new();

    // Load from package.json
    let pkg_json_path = project_dir.join("package.json");
    match read_package_json(&pkg_json_path) {
        Ok(pkg) => {
            all_scripts.extend(
                pkg.scripts
                    .into_iter()
                    .filter(|(name, _)| !is_hidden_script_name(name)),
            );
        }
        Err(lpm_workspace::WorkspaceError::NotFound(_)) => {}
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    }

    if let Some(config) = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)? {
        for (name, task) in &config.tasks {
            if let Some(cmd) = &task.command {
                all_scripts
                    .entry(name.clone())
                    .or_insert_with(|| cmd.clone());
            }
        }
    }

    if all_scripts.is_empty() {
        return Err(LpmError::Script(
            "no scripts found in package.json or lpm.json".into(),
        ));
    }

    let mut scripts: Vec<(String, String)> = all_scripts.into_iter().collect();
    scripts.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(scripts)
}

/// Build a descriptive "script not found" error with available scripts listed.
fn script_not_found_error(script_name: &str, scripts: &HashMap<String, String>) -> LpmError {
    if scripts.is_empty() {
        return LpmError::Script(format!(
            "script '{script_name}' not found — no scripts defined in package.json or lpm.json"
        ));
    }

    let mut available: Vec<&str> = scripts
        .keys()
        .map(|k| k.as_str())
        .filter(|name| !is_hidden_script_name(name))
        .collect();
    available.sort();
    if available.is_empty() {
        return LpmError::Script(format!(
            "script '{script_name}' not found — no visible scripts defined in package.json or lpm.json"
        ));
    }

    LpmError::Script(format!(
        "script '{script_name}' not found. Available: {}",
        available.join(", ")
    ))
}

/// Execute a package script using the configuration snapshot retained by the caller.
pub fn run_script_with_config(
    project_dir: &Path,
    name: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    run_script_with_envs_and_config(project_dir, name, args, mode, &[], hint, config)
}

fn run_script_output_with_config(
    project_dir: &Path,
    name: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
    spawn: impl FnMut(&ShellCommand<'_>) -> Result<shell::CapturedOutput, LpmError>,
) -> Result<ScriptOutput, LpmError> {
    let path = bin_path::build_path_with_bins_pre_resolved(project_dir, hint)?;
    run_script_with_output_at_path_and_config(project_dir, name, args, mode, &path, config, spawn)
}

pub fn run_script_captured_with_config(
    project_dir: &Path,
    name: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_script_output_with_config(project_dir, name, args, mode, hint, config, |command| {
        shell::spawn_shell_tee_with_reserved_stdout(command, reserve_stdout)
    })
    .map_err(without_echoed_output)
}
pub fn run_script_buffered_with_config(
    project_dir: &Path,
    name: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_script_output_with_config(
        project_dir,
        name,
        args,
        mode,
        hint,
        config,
        shell::spawn_shell_capture,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "streaming execution accepts output labels and a configuration snapshot"
)]
pub fn run_script_prefixed_with_config(
    project_dir: &Path,
    name: &str,
    args: &[String],
    mode: Option<&str>,
    prefix: &str,
    color: &str,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_script_output_with_config(project_dir, name, args, mode, hint, config, |command| {
        shell::spawn_shell_prefixed(command, prefix, color)
    })
}
pub fn run_task_command_with_config(
    project_dir: &Path,
    name: &str,
    command: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    run_command_named_with_envs_and_config(
        project_dir,
        name,
        command,
        args,
        mode,
        &[],
        hint,
        config,
    )
}
pub fn run_task_command_buffered_with_config(
    project_dir: &Path,
    name: &str,
    command: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_command_buffered_named_with_config(
        project_dir,
        name,
        command,
        args,
        mode,
        &[],
        hint,
        config,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "captured execution accepts output policy and a configuration snapshot"
)]
pub fn run_task_command_captured_with_config(
    project_dir: &Path,
    name: &str,
    command: &str,
    args: &[String],
    mode: Option<&str>,
    hint: &ManagedRuntimeHint,
    reserve_stdout: bool,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_command_captured_named_with_config(
        project_dir,
        name,
        command,
        args,
        mode,
        hint,
        reserve_stdout,
        config,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "streaming execution accepts output labels and a configuration snapshot"
)]
pub fn run_task_command_prefixed_with_config(
    project_dir: &Path,
    name: &str,
    command: &str,
    args: &[String],
    mode: Option<&str>,
    prefix: &str,
    color: &str,
    hint: &ManagedRuntimeHint,
    config: Option<&lpm_json::LpmJsonConfig>,
) -> Result<ScriptOutput, LpmError> {
    run_command_prefixed_named_with_config(
        project_dir,
        name,
        command,
        args,
        mode,
        prefix,
        color,
        hint,
        config,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn windows_local_bin_candidates_prefer_cmd_shims_over_posix_scripts() {
        assert_eq!(
            super::local_bin_candidate_names_for_platform("tsdown", true)[0],
            "tsdown.cmd"
        );
    }

    use super::*;
    use crate::bin_path::ManagedRuntimeHint::Unknown;
    use std::fs;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    fn write_local_bin(project_dir: &Path, name: &str) -> PathBuf {
        let bin_dir = project_dir.join("node_modules").join(".bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = if cfg!(windows) {
            bin_dir.join(format!("{name}.cmd"))
        } else {
            bin_dir.join(name)
        };
        let script = if cfg!(windows) {
            "@echo off\r\necho local-bin %*\r\n"
        } else {
            "#!/bin/sh\necho local-bin \"$@\"\n"
        };
        fs::write(&bin_path, script).unwrap();
        make_executable(&bin_path);
        bin_path
    }

    #[test]
    fn run_simple_script() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo hello-from-script"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "hello", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_script_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"greet": "echo"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "greet", &["world".into()], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_nonexistent_script_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "echo build"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "nonexistent", &[], None, &Unknown);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
        assert!(err.contains("build"));
    }

    #[test]
    fn build_local_bin_command_resolves_project_bin_without_shell() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        let bin_path = write_local_bin(dir.path(), "eslint");

        let command = build_local_bin_command(
            dir.path(),
            "eslint",
            &["--fix".into(), "src/index.ts".into()],
            None,
            false,
            &Unknown,
        )
        .unwrap();

        assert_eq!(command.get_program(), bin_path.as_os_str());
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["--fix", "src/index.ts"]);
    }

    #[test]
    fn build_local_bin_command_keeps_shell_metacharacters_as_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        write_local_bin(dir.path(), "tool");

        let command = build_local_bin_command(
            dir.path(),
            "tool",
            &["; touch pwned".into(), "$(whoami)".into()],
            None,
            false,
            &Unknown,
        )
        .unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(args, vec!["; touch pwned", "$(whoami)"]);
    }

    #[test]
    fn build_local_bin_command_rejects_path_like_command_names() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let err =
            build_local_bin_command(dir.path(), "scripts/seed.ts", &[], None, false, &Unknown)
                .unwrap_err();

        assert!(err.to_string().contains("Use `lpm scripts/seed.ts`"));
    }

    #[test]
    fn build_local_bin_command_errors_when_project_bin_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();

        let err =
            build_local_bin_command(dir.path(), "eslint", &[], None, false, &Unknown).unwrap_err();

        assert!(err.to_string().contains("project-local binary 'eslint'"));
    }

    #[test]
    fn build_local_bin_command_strips_credential_and_hijack_env_carriers() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        write_local_bin(dir.path(), "tool");

        let command =
            build_local_bin_command(dir.path(), "tool", &[], None, false, &Unknown).unwrap();
        let stripped = command
            .get_envs()
            .filter_map(|(key, value)| if value.is_none() { key.to_str() } else { None })
            .collect::<Vec<_>>();

        for required in ["LPM_TOKEN", "NODE_OPTIONS", "BASH_ENV", "GIT_SSH_COMMAND"] {
            assert!(
                stripped.contains(&required),
                "local-bin exec must strip {required}"
            );
        }
    }

    #[test]
    fn run_pre_hook() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pre-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"prebuild": "touch {}", "build": "echo building"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_ok());
        assert!(marker.exists(), "pre-hook should have created marker file");
    }

    #[test]
    fn run_post_hook() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("post-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"build": "echo building", "postbuild": "touch {}"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_ok());
        assert!(marker.exists(), "post-hook should have created marker file");
    }

    #[test]
    fn pre_hook_failure_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("build-ran");

        fs::write(
            dir.path().join("package.json"),
            format!(
                r#"{{"scripts": {{"prebuild": "exit 1", "build": "touch {}"}}}}"#,
                marker.display()
            ),
        )
        .unwrap();

        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_err());
        assert!(
            !marker.exists(),
            "build should NOT have run after pre-hook failure"
        );
    }

    #[test]
    fn no_package_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = run_script(dir.path(), "build", &[], None, &Unknown);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("package.json"));
    }

    #[test]
    fn list_scripts_sorted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"test": "vitest", "build": "tsup", "dev": "vite"}}"#,
        )
        .unwrap();

        let scripts = list_scripts(dir.path()).unwrap();
        assert_eq!(scripts.len(), 3);
        assert_eq!(scripts[0].0, "build");
        assert_eq!(scripts[1].0, "dev");
        assert_eq!(scripts[2].0, "test");
    }

    #[test]
    fn list_scripts_omits_hidden_package_json_scripts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "tsup", ".build": "node internal.js"}}"#,
        )
        .unwrap();

        let scripts = list_scripts(dir.path()).unwrap();
        assert_eq!(scripts, vec![("build".to_string(), "tsup".to_string())]);
    }

    #[test]
    fn missing_script_suggestions_omit_hidden_package_json_scripts() {
        let mut scripts = HashMap::new();
        scripts.insert("build".to_string(), "tsup".to_string());
        scripts.insert(".build".to_string(), "node internal.js".to_string());

        let err = script_not_found_error("missing", &scripts);
        let msg = err.to_string();
        assert!(msg.contains("build"));
        assert!(!msg.contains(".build"));
    }

    #[test]
    fn script_children_receive_hidden_script_marker() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check": "test \"$LPM_SCRIPT_CHILD\" = \"1\" "}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn path_injection_makes_bin_available() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let fake_bin = bin_dir.join("my-tool");
        fs::write(&fake_bin, "#!/bin/sh\necho my-tool-ran").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).unwrap();
        }

        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check": "my-tool"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check", &[], None, &Unknown);
        assert!(result.is_ok(), "should find my-tool via PATH injection");
    }

    #[test]
    fn dotenv_vars_injected_into_script() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "MY_TEST_VAR=hello_from_env").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check-env": "test \"$MY_TEST_VAR\" = \"hello_from_env\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check-env", &[], None, &Unknown);
        assert!(result.is_ok(), ".env var should be available in script");
    }

    #[test]
    fn env_mode_flag_loads_extra_file() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "VAR=default").unwrap();
        fs::write(dir.path().join(".env.staging"), "VAR=staging_value").unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"check-env": "test \"$VAR\" = \"staging_value\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "check-env", &[], Some("staging"), &Unknown);
        assert!(result.is_ok(), "--env=staging should load .env.staging");
    }

    #[test]
    fn script_command_with_config_does_not_reread_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            lpm_json::parse_lpm_json(r#"{"tasks":{"dev":{"command":"echo configured"}}}"#).unwrap();
        fs::write(dir.path().join("lpm.json"), "{").unwrap();

        let command = script_command_with_config(dir.path(), "dev", Some(&config)).unwrap();

        assert_eq!(command, "echo configured");
    }

    #[test]
    fn failing_script_returns_exit_code_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"fail": "exit 42"}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "fail", &[], None, &Unknown);
        assert!(result.is_err());
        match result.unwrap_err() {
            LpmError::ExitCode(code) => assert_eq!(code, 42),
            other => panic!("expected ExitCode(42), got: {other}"),
        }
    }

    #[test]
    fn validate_env_mode_rejects_path_traversal() {
        assert!(validate_env_mode("staging"), "normal mode should be valid");
        assert!(validate_env_mode("dev"), "normal mode should be valid");
        assert!(
            validate_env_mode("production"),
            "normal mode should be valid"
        );
        assert!(
            !validate_env_mode("../../etc/passwd"),
            "path traversal should be rejected"
        );
        assert!(
            !validate_env_mode("foo/bar"),
            "forward slash should be rejected"
        );
        assert!(
            !validate_env_mode("foo\\bar"),
            "backslash should be rejected"
        );
        assert!(!validate_env_mode(""), "empty mode should be rejected");
        assert!(
            !validate_env_mode("foo\0bar"),
            "null byte should be rejected"
        );
    }

    #[test]
    fn lpm_json_env_mapping() {
        let dir = tempfile::tempdir().unwrap();

        fs::write(dir.path().join(".env"), "API=default").unwrap();
        fs::write(dir.path().join(".env.development"), "API=dev_api").unwrap();
        fs::write(
            dir.path().join("lpm.json"),
            r#"{"env": {"dev": ".env.development"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"dev": "test \"$API\" = \"dev_api\""}}"#,
        )
        .unwrap();

        let result = run_script(dir.path(), "dev", &[], None, &Unknown);
        assert!(
            result.is_ok(),
            "lpm.json env mapping should auto-load .env.development for 'dev' script"
        );
    }

    // --- run_command tests ---

    #[test]
    fn run_command_executes_arbitrary_command() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "echo command-ran", &[], None, &Unknown);
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_with_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(
            dir.path(),
            "echo",
            &["hello".into(), "world".into()],
            None,
            &Unknown,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn run_command_failure_returns_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command(dir.path(), "exit 42", &[], None, &Unknown);
        assert!(result.is_err());
        if let Err(LpmError::ExitCode(code)) = result {
            assert_eq!(code, 42);
        }
    }

    // --- run_command_captured tests ---

    #[test]
    fn run_command_captured_captures_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

        let result = run_command_captured(dir.path(), "echo captured-cmd", &[], None, &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("captured-cmd"));
    }

    // --- run_script_buffered tests ---

    #[cfg(unix)]
    #[test]
    fn script_phase_boundary_cancellation_preserves_completed_hook_output() {
        use std::os::unix::process::ExitStatusExt;
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"pretest":"pre","test":"main"}}"#,
        )
        .unwrap();
        let mut calls = 0;
        let result =
            run_script_with_output_at_path(dir.path(), "test", &[], None, "/usr/bin:/bin", |_| {
                calls += 1;
                if calls == 1 {
                    Ok(shell::CapturedOutput {
                        status: std::process::ExitStatus::from_raw(0),
                        stdout: "PRE_LOG\n".into(),
                        stderr: "PRE_ERROR\n".into(),
                    })
                } else {
                    Err(LpmError::ExitCode(143))
                }
            });
        match result {
            Err(LpmError::ScriptPhase {
                code,
                stdout,
                stderr,
                ..
            }) => {
                assert_eq!(code, 143);
                assert_eq!(stdout, "PRE_LOG\n");
                assert_eq!(stderr, "PRE_ERROR\n");
            }
            other => panic!(
                "phase cancellation lost prior output: {}",
                other.err().unwrap()
            ),
        }
    }

    #[test]
    fn run_script_buffered_captures_without_tee() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo buffered-hello"}}"#,
        )
        .unwrap();

        let result = run_script_buffered(dir.path(), "hello", &[], None, &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("buffered-hello"));
    }

    #[test]
    fn run_script_buffered_caps_combined_hook_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"preprobe":"node output.cjs","probe":"node output.cjs"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("output.cjs"),
            "process.stdout.write('x'.repeat(6*1024*1024)+'\\n');",
        )
        .unwrap();
        let output = run_script_buffered(dir.path(), "probe", &[], None, &Unknown).unwrap();
        assert!(
            output.stdout.len() <= lpm_common::TASK_OUTPUT_CAPTURE_BYTES + 64,
            "{}",
            output.stdout.len()
        );
        assert!(output.stdout.contains("output truncated"));
    }

    #[test]
    fn run_script_buffered_failure_preserves_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"fail": "echo fail-output >&2 && exit 1"}}"#,
        )
        .unwrap();

        let result = run_script_buffered(dir.path(), "fail", &[], None, &Unknown);
        assert!(result.is_err());
        if let Err(LpmError::ScriptPhase {
            phase,
            code,
            stderr,
            ..
        }) = result
        {
            assert_eq!(phase, "fail");
            assert_eq!(code, 1);
            assert!(stderr.contains("fail-output"));
        } else {
            panic!("expected ScriptPhase error");
        }
    }

    // --- run_script_prefixed tests ---

    #[test]
    fn run_script_prefixed_captures() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"hello": "echo prefixed-test"}}"#,
        )
        .unwrap();

        let result = run_script_prefixed(dir.path(), "hello", &[], None, "my-task", "36", &Unknown);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.stdout.contains("prefixed-test"));
    }

    #[cfg(not(windows))]
    #[test]
    fn assemble_shell_command_quotes_extra_args_against_injection() {
        let project = Path::new(".");
        let path = "";
        // Each runtime arg becomes a single-quoted POSIX shell word so
        // a malicious tail like `; rm -rf ~` lands as one literal token.
        let cmd = assemble_shell_command(
            "echo hello",
            &["; rm -rf ~".into()],
            project,
            path,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(cmd, "echo hello '; rm -rf ~'");

        // Embedded single quotes are escaped via the close-escape-reopen
        // dance — the resulting word reaches the script as the literal
        // string `it's fine`.
        let cmd = assemble_shell_command(
            "echo",
            &["it's fine".into()],
            project,
            path,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(cmd, r#"echo 'it'\''s fine'"#);

        // Shell metacharacters in extra args are inert.
        let cmd = assemble_shell_command(
            "echo",
            &["$HOME".into(), "`pwd`".into(), "&& whoami".into()],
            project,
            path,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(cmd, "echo '$HOME' '`pwd`' '&& whoami'");

        // Empty extra-args list returns the script body verbatim — the
        // body itself is package.json-authored and may contain pipes,
        // redirects, env expansion that must work as written.
        let cmd =
            assemble_shell_command("cat file | grep foo", &[], project, path, &HashMap::new())
                .unwrap();
        assert_eq!(cmd, "cat file | grep foo");
    }

    #[test]
    fn windows_shell_argument_escaping_preserves_words_and_metacharacters() {
        let cases = [
            ("", "^\"^\""),
            ("two words", "^\"two^ words^\""),
            ("a&b", "^\"a^&b^\""),
            ("c|d", "^\"c^|d^\""),
            ("e<f", "^\"e^<f^\""),
            ("g>h", "^\"g^>h^\""),
            ("%PATH%", "^\"^%PATH^%^\""),
            ("!delayed!", "^\"^!delayed^!^\""),
            ("quoted\"value", "^\"quoted\\^\"value^\""),
            ("two words\\", "^\"two^ words\\\\^\""),
            ("x^(y)", "^\"x^^^(y^)^\""),
            ("snowman-☃", "^\"snowman-☃^\""),
            ("*.ts", "^\"^*.ts^\""),
        ];

        for (input, expected) in cases {
            assert_eq!(
                windows_shell_quote_arg(input, WindowsArgumentReceiver::Program).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn windows_shell_argument_escaping_rejects_line_breaks() {
        for input in ["one\ntwo", "one\rtwo", "one\0two"] {
            assert!(windows_shell_quote_arg(input, WindowsArgumentReceiver::Program).is_err());
        }
    }

    #[test]
    fn windows_batch_shim_argument_escaping_adds_a_second_cmd_layer() {
        let once = windows_shell_quote_arg("a&b", WindowsArgumentReceiver::Program).unwrap();
        let twice = windows_shell_quote_arg("a&b", WindowsArgumentReceiver::BatchFile).unwrap();

        assert_eq!(once, "^\"a^&b^\"");
        assert_eq!(twice, "^^^\"a^^^&b^^^\"");
    }

    #[test]
    fn windows_plain_words_pass_unquoted_to_any_receiver() {
        for receiver in [
            WindowsArgumentReceiver::Program,
            WindowsArgumentReceiver::BatchFile,
            WindowsArgumentReceiver::Unknown,
        ] {
            for word in [
                "--watch",
                "--max-warnings=0",
                "src/index.ts",
                r"C:\project\out\",
                "@scope/pkg",
                "a+b",
            ] {
                assert_eq!(
                    windows_shell_quote_arg(word, receiver).unwrap(),
                    word,
                    "{receiver:?}"
                );
            }
        }
    }

    #[test]
    fn windows_arguments_needing_escapes_are_refused_for_an_unknown_receiver() {
        for arg in ["", "two words", "a&b", "%PATH%", "x\" & calc & \""] {
            let error = windows_shell_quote_arg(arg, WindowsArgumentReceiver::Unknown)
                .unwrap_err()
                .to_string();
            assert!(error.contains("cannot pass"), "{arg:?}: {error}");
        }
    }

    #[test]
    fn windows_scripts_ending_without_a_command_take_no_arguments() {
        for arg in ["mkdir", "--watch", "plain-target.txt", "a&b"] {
            let error = windows_shell_quote_arg(arg, WindowsArgumentReceiver::Nothing)
                .unwrap_err()
                .to_string();
            assert!(error.contains("ends in an operator"), "{arg:?}: {error}");
        }
    }

    #[test]
    fn windows_arguments_go_to_the_command_starting_the_scripts_last_command() {
        use WindowsScriptTail::{Command, Nothing, Unknown};
        let cases = [
            ("capture", Command("capture")),
            ("  @capture --flag", Command("capture")),
            ("node -e 0 && capture", Command("capture")),
            ("capture && node tools/capture.js", Command("node")),
            ("tsc & jest", Command("jest")),
            ("node -e 0 || capture", Command("capture")),
            ("(node -e 0) && capture", Command("capture")),
            ("capture > out.txt", Command("capture")),
            ("capture 2>&1", Command("capture")),
            ("capture 2>& 1", Command("capture")),
            ("node -e \"a && b | c\" && capture", Command("capture")),
            ("echo a ^& b ^| c", Command("echo")),
            (
                "node -e 0 && \"node_modules/.bin/capture.cmd\"",
                Command("node_modules/.bin/capture.cmd"),
            ),
            (
                r"tsc && C:\tools\capture.cmd",
                Command(r"C:\tools\capture.cmd"),
            ),
            (
                r"tsc && node_modules\.bin\capture",
                Command(r"node_modules\.bin\capture"),
            ),
            // Through a pipe or a grouping, or named indirectly: how often
            // cmd.exe reads the arguments depends on what runs.
            ("node -e 0 | capture", Unknown),
            ("capture | node -e 0", Unknown),
            ("node -e 0 && (capture)", Unknown),
            ("(node -e 0 && capture)", Unknown),
            // A nested cmd.exe, `call` and `start` read what follows them
            // again as a command line of their own: they get no arguments.
            ("call capture", Nothing),
            ("node -e 0 && call capture", Nothing),
            ("cmd /c capture", Nothing),
            (r"C:\Windows\System32\CMD.EXE /c capture", Nothing),
            ("start /b /wait capture", Nothing),
            // However cmd.exe finds its switches and command, and whatever
            // else is on the line (all of these ran `else mkdir INJ` or
            // `mkdir INJ` as a command before).
            ("cmd /d /c if 1==2 (echo a)", Nothing),
            ("call cmd /d /c if 1==2 (echo a)", Nothing),
            ("node -e 0 | cmd /d /c if 1==2 (echo a)", Nothing),
            ("cmd /d /c \"if 1==1\"", Nothing),
            ("cmd /d /c \"node -e 0 &&\"", Nothing),
            ("cmd /d /r if 1==1", Nothing),
            ("cmd /d x /c if 1==1", Nothing),
            ("cmd \"/c\" if 1==1", Nothing),
            ("cmd; /d /c if 1==1", Nothing),
            ("cmd, /d /c if 1==1", Nothing),
            ("cmd= /d /c if 1==1", Nothing),
            ("cmd;/d /c if 1==1", Nothing),
            ("cmd.exe; /d /c if 1==1", Nothing),
            ("\"cmd\" /d /c if 1==1", Nothing),
            (r#""C:\Windows\System32\cmd.exe" /d /c if 1==1"#, Nothing),
            ("(cmd /d /c if 1==1)", Nothing),
            // An `if` or `for` after a pipe takes `& capture` into its body.
            ("node -e 0 | if 1==1 node -e 0 & capture", Unknown),
            ("node -e 0 | for %a in (1) do node -e 0 & capture", Unknown),
            // cmd.exe takes the `^` out before it looks, and a variable can
            // be either.
            ("node -e 0 | i^f 1==1 node -e 0 & capture", Unknown),
            ("node -e 0 | ^if 1==1 node -e 0 & capture", Unknown),
            ("node -e 0 | f^or %a in (1) do node -e 0 & capture", Unknown),
            ("node -e 0 | %CONDITION% node -e 0 & capture", Nothing),
            ("if 1==1 node -e 0 & capture", Command("capture")),
            // cmd.exe also ends `call`'s and `start`'s names at `.+[]\:(`.
            ("start.capture", Nothing),
            ("node -e 0 && start+ /b capture", Nothing),
            ("start[x capture", Nothing),
            ("start] capture", Nothing),
            (r"start\capture", Nothing),
            ("call:label", Nothing),
            ("CALL.", Nothing),
            (
                "start-server-and-test dev",
                Command("start-server-and-test"),
            ),
            ("forever start", Command("forever")),
            ("caller", Command("caller")),
            ("%TOOL% build", Nothing),
            (r#""%LOCALAPPDATA%\tool.exe" build"#, Unknown),
            ("!TOOL! build", Unknown),
            (">out.txt capture", Unknown),
            ("2>nul capture", Unknown),
            ("\"capture\"x", Unknown),
            (r"tsc && tools\ capture", Unknown),
            // cmd.exe ends an unquoted name at a `/`.
            ("cmd/c capture", Nothing),
            ("cmd.exe/c capture", Nothing),
            ("node -e 0 && cmd/c capture", Nothing),
            ("start/b /wait capture", Nothing),
            ("node -e 0 && START/B/WAIT capture", Nothing),
            ("capture/x", Unknown),
            ("node -e 0 && capture/flag", Unknown),
            ("tsc && C:/Windows/System32/cmd /c capture", Nothing),
            ("tsc && node_modules/.bin/capture", Unknown),
            // Inside an unclosed quote.
            ("node -e \"console.log(1)", Unknown),
            // Where the arguments would be a command or a redirection's file,
            // or cmd.exe would stop before them.
            ("node -e 0 &&", Nothing),
            ("node -e 0 ||", Nothing),
            ("node -e 0 |", Nothing),
            ("capture &", Nothing),
            ("capture & ", Nothing),
            ("", Nothing),
            ("   ", Nothing),
            ("capture >", Nothing),
            ("capture >>", Nothing),
            ("capture 2>", Nothing),
            ("capture <", Nothing),
            ("capture 2>&", Nothing),
            ("capture ^", Nothing),
            ("capture\r\nother", Nothing),
            // After `if <condition>` or `for … do` the arguments can become
            // the command, the condition or the `else` branch.
            ("if 1==2 (node -e 0) else", Nothing),
            ("for %a in (1) do", Nothing),
            ("if exist dist", Nothing),
            ("if exist x capture", Nothing),
            ("for %a in (x) do capture", Nothing),
            // `if/i` is a program named `if`; the `/` makes it unknown anyway.
            ("if/i a==a capture", Unknown),
            ("node -e 0 && i^f 1==2 (node -e 0) else", Nothing),
            ("node -e 0 && f^or %a in (1) do", Nothing),
            // `if` is also the built-in before `(`.
            ("node -e 0 | if(1)==(1) node -e 0 & capture", Unknown),
            ("node -e 0 | i^f(1)==(1) node -e 0 & capture", Unknown),
            ("node -e 0 && if(1)==(2) (node -e 0) else", Nothing),
            // cmd.exe also takes U+180E as a space, as `iswspace` does.
            ("node -e 0 | if\u{180E}1==1 node -e 0 & capture", Unknown),
            ("node -e 0 && capture\u{180E}--x", Command("capture")),
            ("node -e 0 && if 1==1 capture", Nothing),
            ("node -e 0 | if 1==1 capture", Nothing),
            // What another cmd.exe reads again: one level of `^` out, so
            // `^&` is an operator there, and variables expanded once more.
            ("node -e 0 | echo X ^&", Nothing),
            ("node -e 0 | echo ^>", Nothing),
            ("node -e 0 | capture %FLAG%", Nothing),
            ("node -e 0 | capture !FLAG!", Nothing),
            ("node -e 0 | capture ^^^& x", Unknown),
            ("node -e 0 | cmd /c if 1==1", Nothing),
            ("cmd /c echo X ^&", Nothing),
            ("cmd /d /s /c if 1==1", Nothing),
            ("cmd/c if 1==1", Nothing),
            ("C:/Windows/System32/cmd /c if 1==1", Nothing),
            (r"C:\Windows\System32\cmd.exe /k if 1==1", Nothing),
            ("call echo X ^&", Nothing),
            ("2>nul call echo X ^&", Nothing),
            ("start /b cmd /c if 1==1", Nothing),
            (r#"start "title" /d C:\ cmd /c if 1==1"#, Nothing),
            (r#"start "title" /b capture"#, Nothing),
            // A redirection, or a parenthesis, can come before the command.
            // cmd.exe refuses a line with one before `if` or `for`; it is
            // read as one anyway.
            ("node -e 0 | 2>nul if 1==1 node -e 0 & capture", Unknown),
            (
                "node -e 0 | >out.txt for %a in (1) do node -e 0 & capture",
                Unknown,
            ),
            ("node -e 0 | 2>&1 if 1==1 node -e 0 & capture", Unknown),
            (
                "node -e 0 | 2>> \"out file\" if 1==1 node -e 0 & capture",
                Unknown,
            ),
            ("node -e 0 | >o^ x if 1==1 node -e 0 & capture", Unknown),
            ("node -e 0 | (if 1==1 node -e 0 & capture", Unknown),
            ("2>nul if 1==1", Nothing),
            ("node -e 0 && 2>nul if 1==1 capture", Nothing),
            ("node -e 0 | 2>nul if 1==1", Nothing),
            (">o^ x if 1==1", Nothing),
            ("2>nul for %a in (1) do", Nothing),
            ("(if 1==1", Nothing),
            ("2>nul capture --flag", Unknown),
        ];
        for (script, expected) in cases {
            assert_eq!(windows_script_tail(script), expected, "{script:?}");
        }
    }

    /// As measured with cmd.exe: an unset name keeps its `%`, and the `%`
    /// that closed it may open the next reference.
    #[test]
    fn windows_variables_expand_as_cmd_expands_them() {
        let value = |name: &str| name.eq_ignore_ascii_case("A").then(|| "x".to_owned());
        for (script, expanded) in [
            ("echo [%U%A%]", "echo [%Ux]"),
            ("echo [%A%%A%]", "echo [xx]"),
            ("echo [%U%%A%]", "echo [%U%x]"),
            ("echo [a%b%A%c]", "echo [a%bxc]"),
            ("echo [%%A%%]", "echo [%x%]"),
            // Left to be read as a variable: cmd.exe gives `[y]`.
            ("echo [%A:x=y%]", "echo [%A:x=y%]"),
            ("echo 100%", "echo 100%"),
        ] {
            assert_eq!(
                windows_expand_variables(script, &value),
                expanded,
                "{script:?}"
            );
        }
    }

    /// cmd.exe expands `%NAME%` before it reads the commands on the line, so
    /// a variable holding an operator can make the arguments a command.
    #[test]
    fn windows_variables_that_could_change_the_commands_are_found() {
        let value = |name: &str| match name.to_ascii_uppercase().as_str() {
            "CHAIN" => Some("&&".to_owned()),
            "URL" => Some("https://registry.test/?a=1&b=2".to_owned()),
            "QUOTE" => Some("a\"b".to_owned()),
            "FLAG" => Some("--watch".to_owned()),
            "BREAK" => Some("a\nb".to_owned()),
            _ => None,
        };
        for (script, changes) in [
            ("node -e 0 %CHAIN%", true),
            ("node -e 0 %chain%", true),
            ("node -e 0 %CHAIN% capture", true),
            ("node build.js %URL%", true),
            ("node build.js \"%URL%\"", false),
            ("node build.js \"%QUOTE%\"", true),
            ("node build.js %QUOTE%", true),
            ("node build.js %FLAG%", false),
            ("node build.js %BREAK%", true),
            ("node build.js %UNSET%", false),
            ("node build.js %~dp0 %CHAIN%", true),
            ("node build.js ^%CHAIN%", true),
            ("node build.js %CHAIN:~0,0%", true),
            ("node build.js %FLAG:~0,2%", false),
            ("node build.js %FLAG:w=&%", true),
            ("node build.js 100% done", false),
            ("node build.js", false),
        ] {
            assert_eq!(
                windows_expansion_may_change_commands(script, &value),
                changes,
                "{script:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_argument_receiver_finds_the_command_as_cmd_does() {
        let project = tempfile::tempdir().unwrap();
        let bin = project.path().join(r"node_modules\.bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("shim.cmd"), "").unwrap();
        std::fs::write(bin.join("tool.exe"), "").unwrap();
        std::fs::write(bin.join("both.exe"), "").unwrap();
        std::fs::write(project.path().join("both.cmd"), "").unwrap();
        std::fs::write(project.path().join("local.bat"), "").unwrap();
        // A script of the shim's name in the project, which cmd.exe runs
        // through Windows Script Host when it looks there first.
        std::fs::write(project.path().join("shim.js"), "").unwrap();
        std::fs::write(bin.join("ordered.vbs"), "").unwrap();
        std::fs::write(bin.join("ordered.cmd"), "").unwrap();
        // A bin named `named.exe` gets the shim `named.exe.cmd`; with both
        // there, cmd.exe runs the name as written.
        std::fs::write(bin.join("named.exe.cmd"), "").unwrap();
        std::fs::write(bin.join("written.exe"), "").unwrap();
        std::fs::write(bin.join("written.exe.cmd"), "").unwrap();
        let path = bin.to_str().unwrap();
        let receiver = |script: &str, search_current_directory: bool| {
            windows_argument_receiver_in(
                script,
                project.path(),
                path,
                search_current_directory,
                WINDOWS_DEFAULT_PATHEXT,
            )
        };

        for (script, in_project_first, on_path_only) in [
            (
                "tool && shim",
                WindowsArgumentReceiver::Program,
                WindowsArgumentReceiver::BatchFile,
            ),
            (
                "shim && tool",
                WindowsArgumentReceiver::Program,
                WindowsArgumentReceiver::Program,
            ),
            (
                "tool && local",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::Program,
            ),
            (
                "tool && both",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::Program,
            ),
            (
                "tool && ordered",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::BatchFile,
            ),
            (
                r"tool && node_modules\.bin\shim",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::BatchFile,
            ),
            (
                "tool &&",
                WindowsArgumentReceiver::Nothing,
                WindowsArgumentReceiver::Nothing,
            ),
            (
                "tool && SHIM.CMD",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::BatchFile,
            ),
            (
                "tool && named.exe",
                WindowsArgumentReceiver::BatchFile,
                WindowsArgumentReceiver::BatchFile,
            ),
            (
                "tool && written.exe",
                WindowsArgumentReceiver::Program,
                WindowsArgumentReceiver::Program,
            ),
            (
                "tool && missing",
                WindowsArgumentReceiver::Program,
                WindowsArgumentReceiver::Program,
            ),
            (
                "tool | shim",
                WindowsArgumentReceiver::Unknown,
                WindowsArgumentReceiver::Unknown,
            ),
        ] {
            assert_eq!(receiver(script, true), in_project_first, "{script:?}");
            assert_eq!(receiver(script, false), on_path_only, "{script:?}");
        }
    }

    /// A project's `.env` reaches the script's cmd.exe, so its `PATHEXT` and
    /// `NoDefaultCurrentDirectoryInExePath` decide what runs.
    #[cfg(windows)]
    #[test]
    fn windows_argument_receiver_follows_the_scripts_environment() {
        let project = tempfile::tempdir().unwrap();
        let bin = project.path().join(r"node_modules\.bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("tool.exe"), "").unwrap();
        std::fs::write(bin.join("tool.cmd"), "").unwrap();
        std::fs::write(bin.join("other.exe"), "").unwrap();
        std::fs::write(project.path().join("local.bat"), "").unwrap();
        let path = bin.to_str().unwrap();
        let envs = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect::<HashMap<_, _>>()
        };

        assert_eq!(
            windows_argument_receiver(
                "other && tool",
                project.path(),
                path,
                &envs(&[("pathext", ".CMD;.EXE;.COM")])
            ),
            WindowsArgumentReceiver::BatchFile
        );
        assert_eq!(
            windows_argument_receiver(
                "other && tool",
                project.path(),
                path,
                &envs(&[("PATHEXT", ".COM;.EXE;.BAT;.CMD")])
            ),
            WindowsArgumentReceiver::Program
        );
        assert_eq!(
            windows_argument_receiver(
                "other && local",
                project.path(),
                path,
                &envs(&[("NoDefaultCurrentDirectoryInExePath", "1")])
            ),
            WindowsArgumentReceiver::Program
        );

        // A variable cmd.exe expands into an operator, from the project's
        // environment or its own, as `CD` is in a folder named `R&D`.
        assert_eq!(
            windows_argument_receiver(
                "other %CHAIN%",
                project.path(),
                path,
                &envs(&[("chain", "&&")])
            ),
            WindowsArgumentReceiver::Nothing
        );
        let r_and_d = project.path().join("R&D");
        std::fs::create_dir(&r_and_d).unwrap();
        for (directory, expected) in [
            (r_and_d.as_path(), WindowsArgumentReceiver::Nothing),
            (project.path(), WindowsArgumentReceiver::Program),
        ] {
            assert_eq!(
                windows_argument_receiver(r"other %CD%\build.js", directory, path, &envs(&[])),
                expected,
                "{}",
                directory.display()
            );
        }
        for script in ["other %CMDCMDLINE%", r"other %=C:%\build.js"] {
            assert_eq!(
                windows_argument_receiver(script, project.path(), path, &envs(&[])),
                WindowsArgumentReceiver::Nothing,
                "{script:?}"
            );
        }
        // Expanded, `"%ComSpec%"` is cmd.exe, which gets no arguments; and
        // Windows matches a variable's name whatever its case, past ASCII.
        assert_eq!(
            windows_argument_receiver(
                r#""%ComSpec%" /d /c if 1==1"#,
                project.path(),
                path,
                &envs(&[])
            ),
            WindowsArgumentReceiver::Nothing
        );
        assert_eq!(
            windows_argument_receiver(
                "other %ÇHAIN%",
                project.path(),
                path,
                &envs(&[("çhain", "&&")])
            ),
            WindowsArgumentReceiver::Nothing
        );
    }

    #[test]
    fn extra_args_with_shell_metachars_do_not_detonate() {
        // End-to-end: a malicious extra arg must not chain a second
        // command. The script body is a no-op `:` that swallows all
        // positional args; if injection succeeded the marker file
        // would be created by the chained `touch`.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pwn");
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"noop": ":"}}"#,
        )
        .unwrap();

        let payload = format!("; touch {}", marker.display());
        let result = run_script(dir.path(), "noop", &[payload], None, &Unknown);
        assert!(result.is_ok());
        assert!(
            !marker.exists(),
            "shell-injected extra arg created marker — escaping is broken"
        );
    }
}
