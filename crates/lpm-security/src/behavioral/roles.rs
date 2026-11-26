//! What a package file is for, as far as its behavioral tags go: a test, a
//! native addon, or a file the package's manifest runs or exports.
//!
//! A test file counts as code the package runs when the manifest names it, or
//! when the package's code reaches it: a string literal there names it as a
//! path, as a `require`, an `import` or a process launch does, directly or
//! through other test files it reaches. lpm.dev reads its tags with this
//! crate, so a tag the registry reports as found only in tests is one a local
//! scan reports the same way.

/// Directories whose files are tests, compared case-insensitively.
const TEST_DIRECTORIES: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "__test__",
    "spec",
    "specs",
    "__mocks__",
    "__fixtures__",
];

/// Scripts the package manager runs when the package is installed or removed.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
];

/// Manifest fields whose paths a consumer's code or shell runs, and
/// `imports`, whose `#` aliases the package's own code loads.
const ENTRY_FIELDS: &[&str] = &["main", "module", "browser", "bin", "exports", "imports"];

/// Scripts a lifecycle script's chain of scripts run by name may reach.
/// Past this, what the rest run isn't known.
const MAX_SCRIPTS_RUN_BY_NAME: usize = 64;

/// Programs that run the command after them: a shell's own (`exec`,
/// `command`, `nohup`, `time`, `nice`), `env` and `cross-env`, which set
/// variables first, `sudo`, and `xargs`.
const COMMAND_WRAPPERS: &[&str] = &[
    "env",
    "exec",
    "command",
    "nohup",
    "time",
    "nice",
    "cross-env",
    "cross-env-shell",
    "sudo",
    "xargs",
];

/// Package manager options that take the next word as their value.
const VALUE_OPTIONS: &[&str] = &[
    "--prefix",
    "-C",
    "--dir",
    "--cwd",
    "--workspace",
    "-w",
    "--filter",
    "-F",
    "--userconfig",
    "--cache",
    "--registry",
];

/// The commands of a shell script, each as its words from the program it
/// runs: past the variable assignments and the [`COMMAND_WRAPPERS`] (with
/// their options) before it. Commands split at `;`, `|`, `&`, line breaks,
/// parentheses and backticks, as a shell's command lists, subshells and
/// command substitutions do.
fn shell_commands(script: &str) -> impl Iterator<Item = Vec<&str>> {
    script
        .split([';', '|', '&', '\n', '\r', '(', ')', '`'])
        .map(|command| {
            let words: Vec<&str> = command
                .split(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '"' | '\'')
                })
                .filter(|word| !word.is_empty())
                .collect();
            let mut start = 0;
            while let Some(word) = words.get(start) {
                if word.contains('=') && !word.starts_with('-') {
                    start += 1;
                } else if COMMAND_WRAPPERS.contains(&program_name(word).as_str()) {
                    start += 1;
                    while words.get(start).is_some_and(|word| word.starts_with('-')) {
                        start += 1;
                    }
                } else {
                    break;
                }
            }
            words[start..].to_vec()
        })
        .filter(|words| !words.is_empty())
}

/// A program's name as a shell finds it: the last part of its path, in
/// lower case.
fn program_name(word: &str) -> String {
    word.rsplit(['/', '\\'])
        .next()
        .unwrap_or(word)
        .to_ascii_lowercase()
}

/// The scripts a command runs by name: `npm run x` (or `run-script`, `rum`,
/// `urn`), `npm test`, `npm start`, `npm stop`, `npm restart`, `yarn x`,
/// `yarn run x`, `pnpm x`, `pnpm run x`, `bun x`, `bun run x`, past the
/// package manager's options. Each brings its `pre` and `post` scripts,
/// which npm and Yarn 1 run around it.
fn scripts_run_by_name(script: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for words in shell_commands(script) {
        let program = program_name(words[0]);
        let mut arguments = Vec::with_capacity(words.len());
        let mut rest = words[1..].iter();
        while let Some(word) = rest.next() {
            if VALUE_OPTIONS.contains(word) {
                rest.next();
            } else if !word.starts_with('-') {
                arguments.push(*word);
            }
        }
        let mut arguments = arguments.into_iter();
        let mut run = |name: &str| {
            for script in [format!("pre{name}"), name.to_owned(), format!("post{name}")] {
                if !names.contains(&script) {
                    names.push(script);
                }
            }
        };
        match program.as_str() {
            "npm" => match arguments.next() {
                Some("run" | "run-script" | "rum" | "urn") => {
                    if let Some(name) = arguments.next() {
                        run(name);
                    }
                }
                Some("test" | "tst" | "t") => run("test"),
                Some(verb @ ("start" | "stop")) => run(verb),
                Some("restart") => {
                    run("restart");
                    run("stop");
                    run("start");
                }
                _ => {}
            },
            "yarn" | "pnpm" | "bun" => match arguments.next() {
                Some("run" | "run-script") => {
                    if let Some(name) = arguments.next() {
                        run(name);
                    }
                }
                Some(name) => run(name),
                None => {}
            },
            _ => {}
        }
    }
    names
}

/// Programs that run JavaScript or TypeScript, and the shells and
/// interpreters an install script hands a script to: the word after one is a
/// path even without a slash.
const RUNTIMES: &[&str] = &["node", "nodejs", "bun", "deno", "tsx", "ts-node"];

/// Whether a word is a program whose next argument names the script it runs.
fn runs_a_script(word: &str) -> bool {
    let name = program_name(word);
    RUNTIMES.contains(&name.as_str())
        || matches!(
            name.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "python" | "python3" | "perl" | "ruby"
        )
}

/// Extensions of scripts an install script can run that the analysis doesn't read.
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "py", "pl", "rb", "ps1", "bat", "cmd"];

/// Whether a package-relative path is a test: under a test directory, named
/// `*.test.*` or `*.spec.*`, or a Python `test_*.py` or `*_test.py` file.
pub fn is_test_path(path: &str) -> bool {
    let (directories, name) = path.rsplit_once('/').unwrap_or(("", path));
    if directories.split('/').any(|segment| {
        TEST_DIRECTORIES
            .iter()
            .any(|directory| segment.eq_ignore_ascii_case(directory))
    }) {
        return true;
    }
    if let Some((stem, extension)) = name.rsplit_once('.')
        && !extension.is_empty()
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        let stem = stem.as_bytes();
        let marked = |marker: &[u8]| {
            stem.len() >= marker.len()
                && stem[stem.len() - marker.len()..].eq_ignore_ascii_case(marker)
        };
        if marked(b".test") || marked(b".spec") {
            return true;
        }
    }
    name.strip_suffix(".py").is_some_and(|stem| {
        stem.strip_prefix("test_")
            .is_some_and(|rest| !rest.is_empty())
            || stem.ends_with("_test")
    })
}

/// Whether a package file is native code: a compiled `.node` addon, or the
/// `binding.gyp` node-gyp builds one from on install.
pub fn is_native_artifact_path(path: &str) -> bool {
    is_native_artifact_name(path.rsplit('/').next().unwrap_or(path).as_bytes())
}

/// [`is_native_artifact_path`] by the file's name alone.
#[inline]
pub fn is_native_artifact_name(name: &[u8]) -> bool {
    name.ends_with(b".node") || name == b"binding.gyp"
}

/// The strings of a manifest's lifecycle scripts and entry points. A file one
/// of them names runs whatever its path says, so it's never only a test.
#[derive(Debug, Default)]
pub(super) struct EntryReferences(Vec<String>, ManifestCode, usize);

/// What else a manifest says about the code it runs.
#[derive(Debug, Default)]
pub(super) struct ManifestCode {
    /// The package's own name.
    pub name: Option<String>,
    /// A script that runs on install or removal hands a script to a shell
    /// or another language's interpreter, which the analysis doesn't read,
    /// or runs more scripts by name than are followed, so what it starts
    /// isn't known.
    pub runs_unread_code: bool,
}

impl EntryReferences {
    pub(super) fn from_manifest(manifest: &serde_json::Value) -> Self {
        let mut references = Vec::new();
        let (scripts, chain_cut) = scripts_that_run(manifest.get("scripts"));
        let code = ManifestCode {
            name: manifest
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_owned),
            runs_unread_code: chain_cut || runs_unread_code(&scripts),
        };
        // As the shell reads each script, and with backslashes as cmd reads them.
        for script in &scripts {
            references.push(script.replace('\\', "/"));
            references.extend(shell_unquoted(script));
        }
        let script_count = references.len();
        let mut pending: Vec<&serde_json::Value> = ENTRY_FIELDS
            .iter()
            .filter_map(|field| manifest.get(field))
            .collect();
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::String(text) => references.push(text.replace('\\', "/")),
                serde_json::Value::Array(items) => pending.extend(items),
                serde_json::Value::Object(entries) => pending.extend(entries.values()),
                _ => {}
            }
        }
        Self(references, code, script_count)
    }

    /// The package files the manifest's strings name, resolved from the
    /// package root as [`FileReferences`] resolves a literal: the scripts
    /// that run as commands, the entry fields with every word a possible
    /// path, since they are paths. Incomplete past the manifest's own
    /// budget.
    pub(super) fn paths(&self) -> FileReferences {
        let (scripts, entries) = self.0.split_at(self.2);
        FileReferences::resolve_manifest(scripts, entries)
    }

    #[inline]
    pub(super) fn code(&self) -> &ManifestCode {
        &self.1
    }

    #[cfg(test)]
    fn of(references: Vec<String>) -> Self {
        Self(references, ManifestCode::default(), 0)
    }

    /// Whether a script or entry point names `path`, with or without its
    /// extension, or names the directory of an `index` file as Node resolves
    /// a directory to it.
    pub(super) fn name(&self, path: &str) -> bool {
        let (directory, name) = match path.rsplit_once('/') {
            Some((directory, name)) => (Some(directory), name),
            None => (None, path),
        };
        let stem = match name.rfind('.') {
            Some(dot) => &path[..path.len() - name.len() + dot],
            None => path,
        };
        let index_directory = directory.filter(|_| {
            name.rsplit_once('.')
                .map_or(name, |(stem, _)| stem)
                .eq("index")
        });
        self.0.iter().any(|reference| {
            reference.contains(path)
                || reference.contains(stem)
                || index_directory.is_some_and(|directory| names_directory(reference, directory))
        })
    }
}

/// How [`EntryReferences::names`] must find a path's needle in a reference.
#[derive(Clone, Copy)]
enum Needle {
    /// Anywhere: the path itself, or the path without its extension.
    Anywhere,
    /// As a whole path, by [`names_directory`]'s rule: the directory of an
    /// `index` file.
    WholeDirectory,
}

/// Matches [`EntryReferences::names`] reports before it gives up and names
/// every path, per byte of references and for any references. A match is a
/// needle ending at a position, so needles that are suffixes of each other
/// can match at every position; real manifests report a few per reference.
const MATCHES_PER_REFERENCE_BYTE: usize = 4;
const MATCHES_FLOOR: usize = 1 << 20;

/// Bytes of distinct needles [`EntryReferences::names`] builds a matcher
/// for before it names every path. The matcher's memory grows with them,
/// and thousands of test paths kilobytes long would cost gigabytes; the
/// most a real package's test files need is about 13 KB.
const MAX_NEEDLE_BYTES: usize = 1 << 20;

impl EntryReferences {
    /// [`EntryReferences::name`] for each of `paths`, in one pass over the
    /// references. Asking `name` for every test file searched every
    /// reference once per file. If the references make the pass report
    /// more matches than they are allowed, every path is named: a named
    /// file counts as code the package runs, never as only a test.
    pub(super) fn names(&self, paths: &[&str]) -> Vec<bool> {
        let mut named = self.names_literally(paths);
        self.name_pattern_matches(paths, &mut named);
        named
    }

    /// Paths a reference names as a whole path, or without its extension, or
    /// as the directory of its `index` file.
    fn names_literally(&self, paths: &[&str]) -> Vec<bool> {
        let mut named = vec![false; paths.len()];
        if paths.is_empty() || self.0.is_empty() {
            return named;
        }
        let mut needles: Vec<&str> = Vec::new();
        // The paths still waiting on each needle, anywhere and as a whole
        // directory. A tarball can repeat an entry, so many paths can share
        // a needle; each list empties the first time it can be answered,
        // and an occurrence answers a whole list at once.
        let mut owners: Vec<(Vec<usize>, Vec<usize>)> = Vec::new();
        let mut needle_bytes = 0usize;
        let mut index_of: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (path_index, path) in paths.iter().enumerate() {
            let (directory, name) = match path.rsplit_once('/') {
                Some((directory, name)) => (Some(directory), name),
                None => (None, *path),
            };
            let stem = match name.rfind('.') {
                Some(dot) => &path[..path.len() - name.len() + dot],
                None => path,
            };
            let index_directory = directory.filter(|_| {
                name.rsplit_once('.')
                    .map_or(name, |(stem, _)| stem)
                    .eq("index")
            });
            let wanted = [
                Some((*path, Needle::Anywhere)),
                Some((stem, Needle::Anywhere)),
                index_directory.map(|directory| (directory, Needle::WholeDirectory)),
            ];
            for (needle, kind) in wanted.into_iter().flatten() {
                if needle.is_empty() {
                    match kind {
                        Needle::Anywhere => named[path_index] = true,
                        Needle::WholeDirectory => {
                            if self
                                .0
                                .iter()
                                .any(|reference| names_directory(reference, needle))
                            {
                                named[path_index] = true;
                            }
                        }
                    }
                    continue;
                }
                let slot = *index_of.entry(needle).or_insert_with(|| {
                    needle_bytes += needle.len();
                    needles.push(needle);
                    owners.push((Vec::new(), Vec::new()));
                    needles.len() - 1
                });
                match kind {
                    Needle::Anywhere => owners[slot].0.push(path_index),
                    Needle::WholeDirectory => owners[slot].1.push(path_index),
                }
            }
        }
        if needles.is_empty() {
            return named;
        }
        if needle_bytes > MAX_NEEDLE_BYTES {
            return vec![true; paths.len()];
        }
        let Ok(matcher) = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&needles)
        else {
            return vec![true; paths.len()];
        };
        let reference_bytes: usize = self.0.iter().map(String::len).sum();
        let mut budget = reference_bytes
            .saturating_mul(MATCHES_PER_REFERENCE_BYTE)
            .max(MATCHES_FLOOR);
        let mut unnamed = named.iter().filter(|named| !**named).count();
        // `names_directory` reads a directory's occurrences as
        // `match_indices` finds them: left to right, each search starting
        // where the last occurrence ended. One needle's matches all have its
        // length, so an occurrence counts when it starts at or past the end
        // of the last one that counted in the same reference.
        let mut counted_until: Vec<(usize, usize)> = vec![(usize::MAX, 0); needles.len()];
        for (reference_index, reference) in self.0.iter().enumerate() {
            for found in matcher.find_overlapping_iter(reference) {
                if unnamed == 0 {
                    return named;
                }
                if budget == 0 {
                    return vec![true; paths.len()];
                }
                budget -= 1;
                let slot = found.pattern().as_usize();
                let (counted_in, until) = counted_until[slot];
                let counted = counted_in != reference_index || found.start() >= until;
                if counted {
                    counted_until[slot] = (reference_index, found.end());
                }
                let (anywhere, whole_directory) = &mut owners[slot];
                let mut answered = std::mem::take(anywhere);
                if !whole_directory.is_empty()
                    && counted
                    && names_directory_at(reference, found.start(), found.end())
                {
                    answered.append(whole_directory);
                }
                for path_index in answered {
                    if !named[path_index] {
                        named[path_index] = true;
                        unnamed -= 1;
                    }
                }
            }
        }
        named
    }

    /// Marks the paths a pattern in a reference matches: an `exports` or
    /// `imports` subpath pattern such as `./tests/*.js`, or a glob in a
    /// script. Its `*` matches any run of characters, `/` included, as Node's
    /// patterns do; `?` and a `[…]` class match one character. When checking
    /// every pattern against every path would take more than
    /// [`MATCHES_PER_REFERENCE_BYTE`] steps per pattern byte, and at least
    /// [`MATCHES_FLOOR`], every path is named.
    fn name_pattern_matches(&self, paths: &[&str], named: &mut [bool]) {
        let patterns: Vec<Vec<u8>> = self
            .0
            .iter()
            .flat_map(|reference| reference.split_ascii_whitespace())
            .filter(|token| token.contains(['*', '?', '[']))
            .map(|token| collapse_stars(token.strip_prefix("./").unwrap_or(token)))
            .collect();
        if patterns.is_empty() {
            return;
        }
        let pattern_bytes: usize = patterns.iter().map(|pattern| pattern.len()).sum();
        let mut steps = pattern_bytes
            .saturating_mul(MATCHES_PER_REFERENCE_BYTE)
            .max(MATCHES_FLOOR);
        for index in 0..paths.len() {
            if named[index] {
                continue;
            }
            for pattern in &patterns {
                match wildcard_matches(pattern, paths[index].as_bytes(), &mut steps) {
                    Some(true) => {
                        named[index] = true;
                        break;
                    }
                    Some(false) => {}
                    None => {
                        named.fill(true);
                        return;
                    }
                }
            }
        }
    }

    /// Whether a script or entry point mentions a path under `directory`.
    pub(super) fn mention_directory(&self, directory: &str) -> bool {
        self.0.iter().any(|reference| {
            reference
                .match_indices(directory)
                .any(|(start, _)| reference[start + directory.len()..].starts_with('/'))
        })
    }
}

/// `pattern` with each run of `*` made one, and each `[…]` class made `?`:
/// a class matches one character, so `?` matches all a class could.
fn collapse_stars(pattern: &str) -> Vec<u8> {
    let bytes = pattern.as_bytes();
    let last_close = bytes.iter().rposition(|&byte| byte == b']');
    let mut collapsed = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'*' if collapsed.last() == Some(&b'*') => index += 1,
            b'[' if last_close.is_some_and(|close| close > index) => {
                let close = index
                    + bytes[index..]
                        .iter()
                        .position(|&byte| byte == b']')
                        .unwrap_or(0);
                collapsed.push(b'?');
                index = close + 1;
            }
            byte => {
                collapsed.push(byte);
                index += 1;
            }
        }
    }
    collapsed
}

/// Whether `text` matches `pattern`, whose `*` matches any run of bytes and
/// `?` any one, or `None` when that takes more than the `steps` left. The
/// greedy walk backtracks only to the last `*`, so it takes linear time for a
/// pattern with one `*`, as Node's subpath patterns have, and at most
/// `pattern.len() * text.len()` steps otherwise.
fn wildcard_matches(pattern: &[u8], text: &[u8], steps: &mut usize) -> Option<bool> {
    let (mut p, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        *steps = steps.checked_sub(1)?;
        if p < pattern.len() && pattern[p] == b'*' {
            resume = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'?' {
            p += 1;
            t += utf8_width(text[t]).min(text.len() - t);
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star, matched)) = resume {
            p = star + 1;
            t = matched + 1;
            resume = Some((star, matched + 1));
        } else {
            return Some(false);
        }
    }
    *steps = steps.checked_sub(1)?;
    Some(pattern[p..].iter().all(|&byte| byte == b'*'))
}

/// The bytes of the UTF-8 character `lead` starts, as a glob's `?` matches one.
fn utf8_width(lead: u8) -> usize {
    match lead {
        0xf0..=0xf7 => 4,
        0xe0..=0xef => 3,
        0xc0..=0xdf => 2,
        _ => 1,
    }
}

/// Whether an install script runs a script of another language, which the
/// analysis doesn't read: a script with that language's extension
/// (`setup.sh`), or anything a shell or another interpreter is given to run
/// (`sh scripts/setup`, `python install.py`).
/// The scripts that run when the package is installed or removed: its
/// lifecycle scripts, and those they run by name (`npm run setup`) with
/// their `pre` and `post` scripts, once each. `true` with them when the
/// chain names more scripts than are followed.
fn scripts_that_run(scripts: Option<&serde_json::Value>) -> (Vec<&str>, bool) {
    let script = |name: &str| {
        scripts
            .and_then(|scripts| scripts.get(name))
            .and_then(serde_json::Value::as_str)
    };
    let mut running: Vec<&str> = LIFECYCLE_SCRIPTS
        .iter()
        .filter_map(|name| script(name))
        .collect();
    let mut followed: Vec<String> = LIFECYCLE_SCRIPTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut queue = running.clone();
    while let Some(text) = queue.pop() {
        for name in scripts_run_by_name(text) {
            if followed.contains(&name) {
                continue;
            }
            let Some(text) = script(&name) else {
                continue;
            };
            if running.len() >= LIFECYCLE_SCRIPTS.len() + MAX_SCRIPTS_RUN_BY_NAME {
                return (running, true);
            }
            followed.push(name);
            running.push(text);
            queue.push(text);
        }
    }
    (running, false)
}

/// `script` as a POSIX shell reads its words, when that differs from how it
/// is written: quotes joined to what they touch (`te''st`), and a backslash
/// escaping the character after it (`te\\st`). An unterminated quote runs to
/// the end. A path a backslash separates, as cmd reads it, is the script as
/// written.
fn shell_unquoted(script: &str) -> Option<String> {
    if !script.contains(['\'', '"', '\\']) {
        return None;
    }
    let mut unquoted = String::with_capacity(script.len());
    let mut characters = script.chars();
    let mut quote: Option<char> = None;
    while let Some(character) = characters.next() {
        match (quote, character) {
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if character == open => quote = None,
            (None, '\\') => unquoted.extend(characters.next()),
            (Some('"'), '\\') => match characters.next() {
                Some(escaped @ ('$' | '`' | '"' | '\\' | '\n')) => unquoted.push(escaped),
                Some(other) => {
                    unquoted.push('\\');
                    unquoted.push(other);
                }
                None => unquoted.push('\\'),
            },
            _ => unquoted.push(character),
        }
    }
    (unquoted != script).then_some(unquoted)
}

fn runs_unread_code(scripts: &[&str]) -> bool {
    // A command whose words another command's output decides runs code no
    // file says.
    if scripts
        .iter()
        .any(|script| script.contains('`') || script.contains("$("))
    {
        return true;
    }
    let unquoted: Vec<String> = scripts
        .iter()
        .filter_map(|script| shell_unquoted(script))
        .collect();
    let scripts: Vec<&str> = scripts
        .iter()
        .copied()
        .chain(unquoted.iter().map(String::as_str))
        .collect();
    // `node test/setup` resolves to a source, so only another language's
    // extension makes a script unread.
    let unread_extension = |path: &str| {
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        name.rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .is_some_and(|(_, extension)| {
                SCRIPT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
            })
    };
    const INTERPRETERS: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "python",
        "python3",
        "perl",
        "ruby",
        "php",
        "pwsh",
        "powershell",
        "cmd",
    ];
    scripts
        .iter()
        .flat_map(|script| shell_commands(script))
        .any(|words| {
            let program = words[0];
            let name = program_name(program);
            let arguments = &words[1..];
            // Whatever another language's interpreter runs is a script of that
            // language, and make runs its makefile's commands.
            (INTERPRETERS.contains(&name.as_str())
            && arguments.iter().any(|word| !word.starts_with('-')))
            || matches!(name.as_str(), "make" | "gmake")
            // Node given code to run, or a script whose name a variable or a
            // command's output decides.
            || (RUNTIMES.contains(&name.as_str())
                && (arguments.iter().any(|word| {
                    matches!(*word, "-e" | "--eval" | "-p" | "--print")
                        || word.starts_with("--eval=")
                        || word.starts_with("--print=")
                        || word.contains(['$', '`'])
                })
                    // Node runs the script its input redirects to it.
                    || arguments
                        .iter()
                        .find(|word| !word.starts_with('-'))
                        .is_some_and(|word| word.starts_with('<'))))
            || unread_extension(program)
            // A package file run by its path, without an extension that says
            // what it is.
            || (program.contains(['/', '\\'])
                && !program.contains("node_modules")
                && !program
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(program)
                    .contains('.'))
        })
}

/// Whether `reference` names `directory` as a whole path, optionally after
/// `./`: the path starts the reference or follows a character that can't be
/// part of a path in a script, and ends the reference or is followed by `/`
/// or such a character.
fn names_directory(reference: &str, directory: &str) -> bool {
    reference
        .match_indices(directory)
        .any(|(start, _)| names_directory_at(reference, start, start + directory.len()))
}

/// Whether the occurrence at `start..end` of a directory in `reference` is
/// a whole path, by [`names_directory`]'s rule.
fn names_directory_at(reference: &str, start: usize, end: usize) -> bool {
    let before = &reference[..start];
    let before = before.strip_suffix("./").unwrap_or(before);
    let starts_path = before
        .chars()
        .next_back()
        .is_none_or(|character| !is_path_character(character));
    let ends_path = reference[end..]
        .chars()
        .next()
        .is_none_or(|character| character == '/' || !is_path_character(character));
    starts_path && ends_path
}

fn is_path_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '/' | '.' | '-' | '_' | '@' | '+' | '~')
}

/// Longest literal also read whole as one path, for a file name that holds a
/// space or a shell character.
const MAX_WHOLE_LITERAL_BYTES: usize = 512;

/// Most path references one file keeps. A file with more is read as one
/// whose references aren't all known.
const MAX_FILE_REFERENCES: usize = 256;

/// How many paths, and how many bytes of them, one resolution may keep before
/// its references count as unknown.
#[derive(Clone, Copy)]
struct ReferenceBudget {
    paths: usize,
    bytes: usize,
}

impl ReferenceBudget {
    const FILE: Self = Self {
        paths: MAX_FILE_REFERENCES,
        bytes: MAX_FILE_REFERENCE_BYTES,
    };
    /// A manifest's strings: an exports map can name thousands of files, and
    /// the manifest is read once per package.
    const MANIFEST: Self = Self {
        paths: 1 << 16,
        bytes: 4 * 1024 * 1024,
    };
}

/// Distinct directories a file's `cd`s may enter before its references
/// count as unknown.
const MAX_ENTERED_DIRECTORIES: usize = 16;
const MAX_FILE_REFERENCE_BYTES: usize = 8 * 1024;

/// Whether a string literal in a source file could name a package file a
/// test-file reachability check follows. In package code, it must mention a
/// test directory or a `.test.` or `.spec.` name, as any path from outside a
/// test directory into one does, before or after percent-decoding. In a test
/// file, any relative path counts, since it can name a test file next to it.
/// A literal needs a path separator, a leading `.`, or a `cd` command; a URL
/// names no package file.
/// Marks a path literal that is a bare module specifier a `require` or an
/// `import` loads (`require("foo")`), which Node finds in a `node_modules`
/// directory of the file's directory or one above it. No file name holds it.
pub(super) const MODULE_SPECIFIER: char = '\0';

/// Whether `specifier` names a module by package name, as Node resolves it
/// through `node_modules`: not a relative or absolute path, a URL, a builtin
/// with a scheme, or an `imports` entry.
pub(super) fn is_bare_specifier(specifier: &str) -> bool {
    specifier
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && !specifier.contains(':')
        && !specifier.contains('\\')
}

pub(super) fn may_name_package_file(literal: &str, in_test_file: bool) -> bool {
    let trimmed = literal.trim();
    let changes_directory = trimmed.split_ascii_whitespace().any(changes_directory);
    if !(trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.starts_with('.')
        || changes_directory)
        || is_url(trimmed)
    {
        return false;
    }
    (in_test_file
        && (matches!(trimmed, "." | "..")
            || trimmed.contains("./")
            || trimmed.contains(".\\")
            || changes_directory))
        || mentions_test_marker(trimmed)
        || (trimmed.contains('%') && mentions_test_marker(&percent_decode(trimmed)))
}

/// Whether a shell word changes the working directory: `cd` or `pushd`, in
/// any case, as cmd reads them.
fn changes_directory(word: &str) -> bool {
    word.eq_ignore_ascii_case("cd") || word.eq_ignore_ascii_case("pushd")
}

fn is_url(text: &str) -> bool {
    !text.bytes().any(|byte| byte.is_ascii_whitespace())
        && (text.starts_with("http://") || text.starts_with("https://") || text.starts_with("//"))
}

pub(super) fn mentions_test_marker(literal: &str) -> bool {
    const MARKERS: [&[u8]; 4] = [b"test", b"spec", b"__mocks__", b"__fixtures__"];
    let bytes = literal.as_bytes();
    MARKERS.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
    })
}

/// A string literal's text as written between its quotes, with JavaScript's
/// escapes decoded: `\xHH`, `\uHHHH`, `\u{H…}`, the single-character escapes
/// and line continuations. Source the parser couldn't read gives its
/// literals this way, so an escaped path names what it would at run time.
pub(super) fn decode_string_escapes(raw: &str) -> std::borrow::Cow<'_, str> {
    if !raw.contains('\\') {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars().peekable();
    let hex = |digits: &str| {
        u32::from_str_radix(digits, 16)
            .ok()
            .and_then(char::from_u32)
    };
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            break;
        };
        match escaped {
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'b' => decoded.push('\u{8}'),
            'f' => decoded.push('\u{c}'),
            'v' => decoded.push('\u{b}'),
            '0' if !characters.peek().is_some_and(char::is_ascii_digit) => decoded.push('\0'),
            '\n' | '\u{2028}' | '\u{2029}' => {}
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
            }
            'x' => {
                let digits: String = characters.by_ref().take(2).collect();
                match hex(&digits).filter(|_| digits.len() == 2) {
                    Some(value) => decoded.push(value),
                    None => decoded.push_str(&digits),
                }
            }
            'u' if characters.peek() == Some(&'{') => {
                characters.next();
                let digits: String = characters
                    .by_ref()
                    .take_while(|&c| c != '}')
                    .take(8)
                    .collect();
                if let Some(value) = hex(&digits) {
                    decoded.push(value);
                }
            }
            'u' => {
                let digits: String = characters.by_ref().take(4).collect();
                match hex(&digits).filter(|_| digits.len() == 4) {
                    Some(value) => decoded.push(value),
                    None => decoded.push_str(&digits),
                }
            }
            other => decoded.push(other),
        }
    }
    std::borrow::Cow::Owned(decoded)
}

/// `text` with each `%XX` escape decoded once, as Node decodes an ES module
/// specifier.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes
                    .get(index + 1)
                    .and_then(|&byte| (byte as char).to_digit(16)),
                bytes
                    .get(index + 2)
                    .and_then(|&byte| (byte as char).to_digit(16)),
            )
        {
            decoded.push((high * 16 + low) as u8);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The package files a source file's string literals name. Each word of a
/// literal, split at spaces, quotes and shell operators, is a path, and so is
/// a short literal with a `/`, whose file name may hold a space. A path
/// resolves relative to the file's directory, and when it doesn't start with
/// `./` or `../`, also to the package root, where a process the package starts
/// runs, and under `node_modules/` there, where a bare module name resolves. A
/// query or fragment (`?v=1`, `#x`) is dropped, a percent-encoded path is
/// decoded, backslashes read as slashes, and the word after `cd` or `pushd`,
/// or one ending in `/`, is a directory. A path that climbs one level out of
/// the package is kept as `../…`, since a package can name itself that way.
/// Paths are compared in lower case, as a case-insensitive volume resolves
/// them.
#[derive(Debug, Default)]
pub struct FileReferences {
    paths: Vec<String>,
    /// Every literal of the file was read, and none was left out for space.
    complete: bool,
}

impl FileReferences {
    /// References whose literals the analysis couldn't read in full, such as
    /// a sampled file's.
    pub(super) fn unknown() -> Self {
        Self::default()
    }

    pub(super) fn resolve<'l>(
        file: &str,
        literals: impl IntoIterator<Item = &'l str>,
        complete: bool,
    ) -> Self {
        let directory = file.rsplit_once('/').map_or("", |(directory, _)| directory);
        let literals: Vec<&str> = literals.into_iter().collect();
        let unquoted: Vec<String> = literals
            .iter()
            .filter_map(|literal| shell_unquoted(literal))
            .collect();
        Self::resolve_from(
            directory,
            literals
                .into_iter()
                .chain(unquoted.iter().map(String::as_str)),
            complete,
            false,
            ReferenceBudget::FILE,
        )
    }

    /// [`Self::resolve`] for the manifest's strings, from the package root:
    /// its `scripts` as commands, its entry fields with every word a
    /// possible path, within the manifest's budget.
    fn resolve_manifest(scripts: &[String], entries: &[String]) -> Self {
        let budget = ReferenceBudget::MANIFEST;
        let commands =
            Self::resolve_from("", scripts.iter().map(String::as_str), true, false, budget);
        let paths = Self::resolve_from("", entries.iter().map(String::as_str), true, true, budget);
        if !(commands.complete && paths.complete) {
            return Self::unknown();
        }
        let mut references = commands;
        references.paths.extend(paths.paths);
        references.paths.sort_unstable();
        references.paths.dedup();
        references
    }

    fn resolve_from<'l>(
        directory: &str,
        literals: impl IntoIterator<Item = &'l str>,
        complete: bool,
        every_word_a_path: bool,
        budget: ReferenceBudget,
    ) -> Self {
        let mut references = Self {
            paths: Vec::new(),
            complete,
        };
        let mut bytes = 0usize;
        let mut add = |path: String, references: &mut Self| -> bool {
            bytes += path.len();
            if references.paths.len() >= budget.paths || bytes > budget.bytes {
                return false;
            }
            references.paths.push(path);
            true
        };
        let literals: Vec<&str> = literals.into_iter().collect();
        // A `cd` moves what the paths after it resolve from. Which command a
        // path belongs to isn't tracked, so every path-like word of the
        // file also resolves from each directory one of its `cd`s enters.
        let mut entered: Vec<String> = Vec::new();
        for literal in literals
            .iter()
            .filter(|literal| !literal.starts_with(MODULE_SPECIFIER))
        {
            let mut after_cd = false;
            for word in shell_words(literal) {
                if after_cd {
                    for spelling in path_spellings(word) {
                        let path = spelling.trim_start_matches('/');
                        for base in [directory, ""] {
                            if let Some(path) = normalize_package_path(base, path)
                                && !entered.contains(&path)
                            {
                                if entered.len() >= MAX_ENTERED_DIRECTORIES {
                                    return Self::unknown();
                                }
                                entered.push(path);
                            }
                        }
                    }
                }
                after_cd = changes_directory(word);
            }
        }
        for literal in literals {
            if let Some(specifier) = literal.strip_prefix(MODULE_SPECIFIER) {
                // From the file's directory up to the package root.
                let mut base = Some(directory);
                while let Some(current) = base {
                    if let Some(path) =
                        join_package_path(current, &format!("node_modules/{specifier}"))
                        && !add(path.to_ascii_lowercase(), &mut references)
                    {
                        return Self::unknown();
                    }
                    base = match current.rsplit_once('/') {
                        Some((parent, _)) => Some(parent),
                        None if current.is_empty() => None,
                        None => Some(""),
                    };
                }
                continue;
            }
            let mut after_cd = false;
            let whole = literal.trim();
            // A file name with a space or a bracket, which splitting into words would break.
            if whole.contains('/')
                && whole.len() <= MAX_WHOLE_LITERAL_BYTES
                && whole.contains(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '(' | ')')
                })
            {
                for spelling in path_spellings(whole) {
                    for base in [directory, ""]
                        .into_iter()
                        .chain(entered.iter().map(String::as_str))
                    {
                        if let Some(path) =
                            join_package_path(base, spelling.trim_start_matches('/'))
                            && !add(path.to_ascii_lowercase(), &mut references)
                        {
                            return Self::unknown();
                        }
                    }
                }
            }
            // The first argument after a runtime or interpreter names the
            // script it runs, a path even without a slash (`node run.js`).
            let mut after_runtime = false;
            for (word, directory_word) in shell_words(literal).map(|word| {
                let flag = word.starts_with('-');
                let directory_word = every_word_a_path
                    || after_cd
                    || (after_runtime && !flag && !word.contains(['/', '\\']))
                    || (word.len() > 1 && word.ends_with('/'));
                after_cd = changes_directory(word);
                if !flag {
                    after_runtime = runs_a_script(word);
                }
                (word, directory_word)
            }) {
                // A flag, or a word without a dot or a slash (`node`, `&&`),
                // names no file from an entered directory.
                let from_entered = !entered.is_empty()
                    && !word.starts_with('-')
                    && word.contains(['.', '/', '\\']);
                for candidate in path_spellings(word) {
                    for path in candidate_paths(directory, &candidate, directory_word) {
                        if !add(path, &mut references) {
                            return Self::unknown();
                        }
                    }
                    if from_entered {
                        let relative = candidate.trim_start_matches('/');
                        for base in &entered {
                            if let Some(path) = join_package_path(base, relative)
                                && !add(path, &mut references)
                            {
                                return Self::unknown();
                            }
                        }
                    }
                }
            }
        }
        references.paths.sort_unstable();
        references.paths.dedup();
        references
    }

    #[inline]
    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    #[inline]
    pub(super) fn paths(&self) -> &[String] {
        &self.paths
    }

    pub(super) fn byte_len(&self) -> usize {
        self.paths.iter().map(String::len).sum()
    }

    pub(super) fn into_paths(self) -> Vec<String> {
        self.paths
    }
}

/// The ways a word can spell a path: as written, without a query or fragment,
/// and percent-decoded, with backslashes read as slashes and in lower case.
fn path_spellings(word: &str) -> Vec<String> {
    // A fragment with a separator at both ends (`/test/`) is what a filter
    // compares paths against, not a path.
    if word.len() > 1 && word.starts_with('/') && word.ends_with('/') {
        return Vec::new();
    }
    let word = word.trim_end_matches('/');
    let drive = word.as_bytes().get(1) == Some(&b':');
    if word.is_empty() || word.contains("://") || drive {
        return Vec::new();
    }
    let mut spellings = Vec::with_capacity(3);
    let mut push = |spelling: &str| {
        let spelling = spelling.replace('\\', "/").to_ascii_lowercase();
        if !spelling.is_empty() && !spellings.contains(&spelling) {
            spellings.push(spelling);
        }
    };
    push(word);
    let bare = word
        .find(['?', '#'])
        .filter(|&end| end > 0)
        .map_or(word, |end| &word[..end]);
    push(bare);
    if bare.contains('%') {
        push(&percent_decode(bare));
    }
    spellings
}

/// The package paths a path spelling names, relative to the file's
/// `directory` and to the package root.
fn candidate_paths(directory: &str, spelling: &str, directory_word: bool) -> Vec<String> {
    let relative = spelling == "."
        || spelling == ".."
        || spelling.starts_with("./")
        || spelling.starts_with("../");
    let rooted = spelling.starts_with('/');
    if !relative && !rooted && !spelling.contains('/') && !directory_word {
        return Vec::new();
    }
    let path = spelling.trim_start_matches('/');
    let mut candidates = Vec::with_capacity(4);
    let mut push = |base: &str, path: &str| {
        if let Some(joined) = join_package_path(base, path) {
            let joined = joined.to_ascii_lowercase();
            if !candidates.contains(&joined) {
                candidates.push(joined);
            }
        }
    };
    push(directory, path);
    if !relative {
        push("", path);
        if !rooted && !directory_word {
            push("node_modules", path);
            if !directory.is_empty() {
                push(&format!("{directory}/node_modules"), path);
            }
        }
    }
    candidates
}

/// The words of a literal as a shell or a module path splits it.
fn shell_words(literal: &str) -> impl Iterator<Item = &str> {
    literal
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '`' | '=' | ';' | '(' | ')' | '|' | '&' | '<' | '>'
                )
        })
        .filter(|word| !word.is_empty())
}

/// Levels above the package root a path keeps: from its install directory,
/// a path can climb out and come back in through `node_modules`.
const MAX_CLIMBS: usize = 16;

/// `path` joined to the package directory `base` and normalized, with the
/// package root as `""`, its parent as `..` and each level above that as
/// another `../`. `None` past [`MAX_CLIMBS`] levels out.
fn normalize_package_path(base: &str, path: &str) -> Option<String> {
    let mut segments: Vec<&str> = Vec::new();
    let mut climbs = 0;
    for segment in base.split('/').chain(path.split('/')) {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    climbs += 1;
                    if climbs > MAX_CLIMBS {
                        return None;
                    }
                }
            }
            segment => segments.push(segment),
        }
    }
    let mut normalized =
        String::with_capacity(climbs * 3 + segments.iter().map(|s| s.len() + 1).sum::<usize>());
    for _ in 0..climbs {
        normalized.push_str("../");
    }
    for segment in segments {
        normalized.push_str(segment);
        normalized.push('/');
    }
    normalized.pop();
    Some(normalized)
}

/// [`normalize_package_path`] for a path that names a file or a directory
/// below the root: `None` for the root itself and the directories above it.
fn join_package_path(base: &str, path: &str) -> Option<String> {
    normalize_package_path(base, path)
        .filter(|path| !path.is_empty() && !path.split('/').all(|segment| segment == ".."))
}

/// The package path a reference that leaves the package names when it comes
/// back in under the package's own name, as the package installed at
/// `node_modules/<name>` sees it: `<name>/…` (a bare self-reference),
/// `../<name>/…`, or for a scoped `@scope/name`, `../name/…` and
/// `../../@scope/name/…`, and from any number of levels up,
/// `node_modules/<name>/…`. `name` is in lower case, as references are.
fn own_path<'r>(reference: &'r str, name: &str) -> Option<&'r str> {
    let mut rest = reference;
    let mut climbs = 0;
    while let Some(after) = rest.strip_prefix("../") {
        rest = after;
        climbs += 1;
    }
    let below = |prefix: &str| rest.strip_prefix(prefix)?.strip_prefix('/');
    let last = name
        .split_once('/')
        .filter(|(scope, _)| scope.starts_with('@'))
        .map(|(_, last)| last);
    let from_parent = match (climbs, last) {
        (0, _) => below(name),
        (1, None) => below(name),
        (1, Some(last)) => below(last),
        (2, Some(_)) => below(name),
        _ => None,
    };
    from_parent.or_else(|| {
        (climbs > 0)
            .then(|| below("node_modules"))
            .flatten()
            .and_then(|rest| rest.strip_prefix(name)?.strip_prefix('/'))
    })
}

/// The keys under which a reference names a package file, as slices of its
/// lower-case `path`: the path, the path without the extension, and for an
/// `index` file its directory, as Node resolves a module path; and each
/// directory at or under a test directory, since a reference to such a
/// directory can load any test file in it, as a directory `package.json` or
/// a `cd` can.
fn reference_keys(path: &str) -> Vec<&str> {
    let (directory, name) = match path.rsplit_once('/') {
        Some((directory, name)) => (Some(directory), name),
        None => (None, path),
    };
    let mut keys = vec![path];
    if let Some(dot) = name.rfind('.').filter(|&dot| dot > 0) {
        keys.push(&path[..path.len() - name.len() + dot]);
    }
    if let Some(directory) = directory {
        if name.rsplit_once('.').map_or(name, |(stem, _)| stem) == "index" {
            keys.push(directory);
        }
        let mut inside_test_directory = false;
        let mut end = 0;
        for segment in directory.split('/') {
            end += segment.len();
            inside_test_directory |= TEST_DIRECTORIES.contains(&segment);
            if inside_test_directory {
                keys.push(&directory[..end]);
            }
            end += 1;
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Bytes of keys [`reachable_tests`] indexes test files under before every
/// test file counts: a crafted package's deep, distinct test paths would
/// otherwise make its index grow with their depth times their length.
const MAX_KEY_BYTES: usize = 8 * 1024 * 1024;

/// Whether a reference names a path a test file could have.
fn names_a_test_path(reference: &str) -> bool {
    is_test_path(reference)
        || reference.split('/').any(|segment| {
            TEST_DIRECTORIES
                .iter()
                .any(|directory| segment.eq_ignore_ascii_case(directory))
        })
}

/// A test file or test addon, for [`reachable_tests`].
pub(super) struct TestFile<'a> {
    pub path: &'a str,
    /// What the file names, or `None` when it names nothing it can load: an
    /// addon.
    pub references: Option<&'a FileReferences>,
    /// The file loads a module, starts a script or a worker from a path it
    /// computes.
    pub loads_computed_code: bool,
}

/// What a package's code and manifest say about its test files, for
/// [`reachable_tests`].
pub(super) struct Reachability<'a> {
    /// The test files the manifest names.
    pub named_by_manifest: Vec<bool>,
    /// The package files code the package runs names.
    pub runtime_references: &'a [String],
    /// Code the package runs, or code its manifest runs, wasn't read whole,
    /// or loads code from a path it computes.
    pub runtime_is_opaque: bool,
    /// The package's own name, by which its code can name its files.
    pub package_name: Option<&'a str>,
    /// Test files a budget left unread, in lower case.
    pub unread_tests: &'a [String],
    /// A file limit left out test files whose paths aren't known.
    pub unknown_tests_left_out: bool,
    /// The test files named more paths together than are kept, so a reached
    /// test file's references aren't known.
    pub test_references_incomplete: bool,
}

/// Which test files the package runs: those the manifest names, those code
/// the package runs names, and those a test file it runs names, transitively.
/// Any test file could be the one it runs, and all count, when code it runs
/// is opaque, a test file it runs computes what it loads or names more than
/// was kept, or a reference reaches a test file a budget left unread.
pub(super) fn reachable_tests(tests: &[TestFile<'_>], facts: Reachability<'_>) -> Vec<bool> {
    let everything = vec![true; tests.len()];
    if facts.runtime_is_opaque {
        return everything;
    }
    let paths: Vec<String> = tests
        .iter()
        .map(|test| test.path.to_ascii_lowercase())
        .collect();
    let unread_paths: Vec<String> = facts
        .unread_tests
        .iter()
        .map(|path| path.to_ascii_lowercase())
        .collect();
    let mut key_bytes = 0usize;
    let mut by_key: std::collections::HashMap<&str, Vec<usize>> =
        std::collections::HashMap::with_capacity(tests.len() * 3);
    for (index, path) in paths.iter().enumerate() {
        for key in reference_keys(path) {
            key_bytes += key.len();
            if key_bytes > MAX_KEY_BYTES {
                return everything;
            }
            by_key.entry(key).or_default().push(index);
        }
    }
    let mut unread: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for path in &unread_paths {
        for key in reference_keys(path) {
            key_bytes += key.len();
            if key_bytes > MAX_KEY_BYTES {
                return everything;
            }
            unread.insert(key);
        }
    }
    let own_name = facts.package_name.map(str::to_ascii_lowercase);
    let mut named = facts.named_by_manifest;
    let mut reached: Vec<usize> = named
        .iter()
        .enumerate()
        .filter_map(|(index, named)| named.then_some(index))
        .collect();
    let mut pending: Vec<&str> = facts
        .runtime_references
        .iter()
        .map(String::as_str)
        .collect();
    loop {
        while let Some(reference) = pending.pop() {
            let own = own_name
                .as_deref()
                .and_then(|name| own_path(reference, name));
            for reference in std::iter::once(reference).chain(own) {
                // Each key's files are taken the first time it is reached.
                let found = by_key.get_mut(reference).map(std::mem::take);
                if unread.contains(reference)
                    || (found.is_none()
                        && facts.unknown_tests_left_out
                        && names_a_test_path(reference))
                {
                    return everything;
                }
                for index in found.into_iter().flatten() {
                    if !named[index] {
                        named[index] = true;
                        reached.push(index);
                    }
                }
            }
        }
        let Some(index) = reached.pop() else {
            return named;
        };
        let test = &tests[index];
        if let Some(references) = test.references {
            if test.loads_computed_code
                || !references.is_complete()
                || facts.test_references_incomplete
            {
                return everything;
            }
            pending.extend(references.paths().iter().map(String::as_str));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_test_files_by_their_directory_or_name() {
        for path in [
            "test/a.js",
            "src/tests/b.ts",
            "lib/__tests__/c.js",
            "__mocks__/d.js",
            "Tests/KitTests/KitTests.swift",
            "src/e.test.ts",
            "src/f.spec.mjs",
            "src/G.Test.JS",
            "pkg/test_g.py",
            "pkg/h_test.py",
        ] {
            assert!(is_test_path(path), "{path}");
        }
        for path in [
            "dist/index.js",
            "src/testing-library.js",
            "lib/contest.js",
            "examples/jsm/loaders/GLTFLoader.js",
            "src/latest.ts",
            "test.js",
            "pkg/test_.py",
            "src/e.test.d-ts",
        ] {
            assert!(!is_test_path(path), "{path}");
        }
    }

    #[test]
    fn native_artifacts_are_node_addons_and_binding_gyp() {
        for path in [
            "build/Release/addon.node",
            "addon.node",
            "binding.gyp",
            "native/binding.gyp",
        ] {
            assert!(is_native_artifact_path(path), "{path}");
        }
        for path in [
            "server.node.js",
            "my-binding.gyp",
            "binding.gyp.bak",
            "node",
        ] {
            assert!(!is_native_artifact_path(path), "{path}");
        }
    }

    #[test]
    fn entry_references_cover_lifecycle_scripts_and_entry_points() {
        let manifest = serde_json::json!({
            "main": "./tests/main.js",
            "bin": { "kit": "spec/cli.js" },
            "exports": { ".": { "import": ["./__mocks__/esm.mjs"] } },
            "scripts": { "postinstall": "node test/setup", "test": "node test/other.js" },
        });
        let references = EntryReferences::from_manifest(&manifest);

        for path in [
            "tests/main.js",
            "spec/cli.js",
            "__mocks__/esm.mjs",
            "test/setup.js",
        ] {
            assert!(references.name(path), "{path}");
        }
        assert!(!references.name("test/other.js"));
        assert!(!EntryReferences::default().name("test/setup.js"));
    }

    #[test]
    fn entry_references_name_the_index_of_a_directory_and_windows_style_paths() {
        let manifest = serde_json::json!({
            "main": "./spec",
            "bin": "tests\\cli.js",
            "module": "lib/specs/",
        });
        let references = EntryReferences::from_manifest(&manifest);

        for path in [
            "spec/index.js",
            "spec/index.mjs",
            "tests/cli.js",
            "lib/specs/index.ts",
        ] {
            assert!(references.name(path), "{path}");
        }
        for path in ["spec/helper.js", "specs/index.js", "lib/spec/index.js"] {
            assert!(!references.name(path), "{path}");
        }
    }

    #[test]
    fn naming_paths_together_answers_what_naming_each_answers() {
        struct Rng(u64);
        impl Rng {
            fn below(&mut self, n: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                (self.0 % n as u64) as usize
            }
        }
        const SEGMENTS: &[&str] = &[
            "test",
            "lib",
            "src",
            "index",
            "a",
            "b.js",
            "index.js",
            "index.mjs",
            ".js",
            "é",
            "x-y",
            "",
            "aa",
            "aaa",
            "a a",
            "test/a test/a",
        ];
        const GLUE: &[&str] = &[
            "", "./", " ", "/", ".", "node ", " && ", "@", "+", "~", "\"\"", ":", "-", "é",
        ];
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let piece = |rng: &mut Rng, parts: usize| {
            let mut text = String::new();
            for part in 0..parts {
                if part > 0 && rng.below(3) == 0 {
                    text.push('/');
                }
                text.push_str(GLUE[rng.below(GLUE.len())]);
                text.push_str(SEGMENTS[rng.below(SEGMENTS.len())]);
            }
            text
        };
        for _ in 0..3_000 {
            let references: Vec<String> = (0..rng.below(4))
                .map(|_| {
                    let parts = 1 + rng.below(6);
                    piece(&mut rng, parts)
                })
                .collect();
            let references = EntryReferences::of(references);
            let paths: Vec<String> = (0..1 + rng.below(6))
                .map(|_| {
                    let parts = 1 + rng.below(4);
                    let path = piece(&mut rng, parts);
                    if rng.below(2) == 0 {
                        path
                    } else {
                        path.replace(' ', "")
                    }
                })
                .collect();
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            let each: Vec<bool> = paths.iter().map(|path| references.name(path)).collect();
            assert_eq!(
                references.names(&paths),
                each,
                "{:?} {paths:?}",
                references.0
            );
        }
        for (references, paths) in [
            (vec![], vec!["test/a.js"]),
            (vec!["lib"], vec!["/index.js", ".js", "", "lib/index.js"]),
            (
                vec!["./lib/x", "node lib"],
                vec!["lib/index.js", "lib/index.mjs"],
            ),
            (vec!["mylib/x"], vec!["lib/index.js"]),
            (
                vec!["test/a"],
                vec!["test/a.js", "test/a.js", "test/a.spec.js"],
            ),
            // An occurrence of an `index` file's directory that overlaps one
            // already checked is never checked itself.
            (
                vec!["xtest/a test/a test/a"],
                vec!["test/a test/a/index.js"],
            ),
            (
                vec!["aaa/", "xaaa", "aaaa a"],
                vec!["aa/index.js", "aaa/index.js"],
            ),
        ] {
            let references =
                EntryReferences::of(references.into_iter().map(String::from).collect());
            let each: Vec<bool> = paths.iter().map(|path| references.name(path)).collect();
            assert_eq!(
                references.names(&paths),
                each,
                "{:?} {paths:?}",
                references.0
            );
        }
    }

    #[test]
    fn references_that_report_too_many_matches_name_every_path() {
        // Paths that are suffixes of each other all match at every
        // position of a reference made of them: 200 of them in 40,000
        // bytes report about 4 million matches.
        let mut paths: Vec<String> = (1..=200).map(|depth| vec!["a"; depth].join("/")).collect();
        paths.push("zzz/q.js".to_owned());
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        let references = EntryReferences::of(vec!["a/".repeat(20_000)]);
        assert!(!references.name("zzz/q.js"));
        assert_eq!(references.names(&paths), vec![true; paths.len()]);
    }

    #[test]
    fn paths_sharing_a_needle_are_resolved_once_each() {
        // A tarball can repeat an entry: thousands of copies of one path
        // shared a needle, and every occurrence of it revisited them all
        // while one unnamed path kept the pass going.
        let references = EntryReferences::of(vec!["test/a ".repeat(100_000)]);
        let time = |copies: usize| {
            let mut paths = vec!["test/a.node"; copies];
            paths.push("test/z.node");
            let started = std::time::Instant::now();
            let named = references.names(&paths);
            assert_eq!(named.iter().filter(|named| **named).count(), copies);
            started.elapsed()
        };
        let one = time(1);
        let many = time(5_000);
        assert!(
            many < one * 5 + std::time::Duration::from_millis(50),
            "5,000 copies {many:?}, one {one:?}"
        );
    }

    #[test]
    fn test_paths_too_long_to_build_a_matcher_for_are_all_named() {
        // Thousands of test paths kilobytes long made a matcher of
        // gigabytes; past the needle cap every path counts as package code.
        let padding = "x".repeat(4_000);
        let paths: Vec<String> = (0..300)
            .map(|i| format!("test/{i}{padding}.node"))
            .collect();
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        let references = EntryReferences::of(vec!["main.js".to_owned()]);
        assert!(paths.iter().all(|path| !references.name(path)));
        assert_eq!(references.names(&paths), vec![true; paths.len()]);
    }

    #[test]
    fn a_file_names_paths_relative_to_itself_and_command_paths_relative_to_the_package_too() {
        let references = FileReferences::resolve(
            "lib/cli/index.js",
            [
                "../../tests/run.js",
                "./helper/",
                "node scripts/test/a.js --flag",
                "--require=./spec/setup.js",
                "https://example.com/test/x.js",
                "/usr/lib/test/y.js",
                "../../../outside/test.js",
                "C:\\test\\z.js",
            ],
            true,
        );
        assert_eq!(
            references.paths(),
            [
                // One level above the package root, where it can name itself.
                "../outside/test.js",
                "lib/cli/helper",
                // The whole command, as a file name with a space would be.
                "lib/cli/node scripts/test/a.js --flag",
                "lib/cli/node_modules/scripts/test/a.js",
                "lib/cli/scripts/test/a.js",
                "lib/cli/spec/setup.js",
                "lib/cli/usr/lib/test/y.js",
                "node scripts/test/a.js --flag",
                "node_modules/scripts/test/a.js",
                "scripts/test/a.js",
                "tests/run.js",
                "usr/lib/test/y.js",
            ]
        );
        assert!(references.is_complete());
    }

    #[test]
    fn a_file_naming_too_many_paths_has_unknown_references() {
        let literals: Vec<String> = (0..=MAX_FILE_REFERENCES)
            .map(|index| format!("./test/{index}.js"))
            .collect();
        let references =
            FileReferences::resolve("index.js", literals.iter().map(String::as_str), true);
        assert!(!references.is_complete());
        assert!(references.paths().is_empty());
    }

    #[test]
    fn only_literals_that_can_reach_a_test_file_are_kept() {
        assert!(may_name_package_file("./tests/run.js", false));
        assert!(may_name_package_file("node Spec/setup.js", false));
        assert!(may_name_package_file("../lib/x.test.js", false));
        assert!(!may_name_package_file("./helper", false));
        assert!(may_name_package_file("./helper", true));
        assert!(!may_name_package_file("test", false));
        assert!(!may_name_package_file("lodash", true));
    }

    #[test]
    fn a_pattern_star_matches_any_run_of_characters_slashes_included() {
        let matches = |pattern: &str, text: &str| {
            let mut steps = usize::MAX;
            wildcard_matches(pattern.as_bytes(), text.as_bytes(), &mut steps).unwrap()
        };
        assert!(matches("tests/*.js", "tests/run.js"));
        assert!(matches("tests/*.js", "tests/deep/run.js"));
        assert!(!matches("tests/*.js", "tests/run.ts"));
        assert!(matches("*", ""));
        assert!(matches("a*b*c", "aXbYbZc"));
        assert!(!matches("a*b*c", "aXbY"));
    }

    #[test]
    fn unclosed_glob_classes_collapse_in_linear_time() {
        let pattern = "[".repeat(200_000) + "*";
        let started = std::time::Instant::now();
        assert_eq!(collapse_stars(&pattern).len(), 200_001);
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    #[test]
    fn a_glob_question_mark_matches_one_character_of_any_width() {
        let mut steps = usize::MAX;
        assert_eq!(
            wildcard_matches(b"tests/?un.js", "tests/\u{e9}un.js".as_bytes(), &mut steps),
            Some(true)
        );
    }

    #[test]
    fn deep_distinct_test_paths_stay_within_the_key_budget() {
        let deep = "test/".to_owned() + &"d/".repeat(8_000);
        let paths: Vec<String> = (0..300).map(|index| format!("{deep}{index}.js")).collect();
        let references: Vec<FileReferences> =
            paths.iter().map(|_| FileReferences::default()).collect();
        let tests: Vec<TestFile<'_>> = paths
            .iter()
            .zip(&references)
            .map(|(path, references)| TestFile {
                path,
                references: Some(references),
                loads_computed_code: false,
            })
            .collect();
        let started = std::time::Instant::now();
        let reached = reachable_tests(
            &tests,
            Reachability {
                named_by_manifest: vec![false; tests.len()],
                runtime_references: &[],
                runtime_is_opaque: false,
                package_name: None,
                unread_tests: &[],
                unknown_tests_left_out: false,
                test_references_incomplete: false,
            },
        );
        assert!(
            reached.iter().all(|reached| *reached),
            "past the key budget every test counts"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn patterns_too_costly_to_match_name_every_test_path() {
        // After each failed try the walk restarts the run of `a`s one byte
        // further on, so matching costs the pattern's length times the path's.
        let pattern = format!("*{}b", "a".repeat(2_000));
        let path = format!("test/{}.js", "a".repeat(30_000));
        let references = EntryReferences::of(vec![pattern]);
        let started = std::time::Instant::now();
        assert_eq!(references.names(&[path.as_str()]), [true]);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn a_reached_test_file_that_computes_a_module_name_makes_every_test_file_reachable() {
        let loader = FileReferences::resolve("test/loader.js", [], true);
        let other = FileReferences::resolve("test/other.js", [], true);
        let tests = [
            TestFile {
                path: "test/loader.js",
                references: Some(&loader),
                loads_computed_code: true,
            },
            TestFile {
                path: "test/other.js",
                references: Some(&other),
                loads_computed_code: false,
            },
        ];
        let reached = |runtime_references: &[String]| {
            reachable_tests(
                &tests,
                Reachability {
                    named_by_manifest: vec![false, false],
                    runtime_references,
                    runtime_is_opaque: false,
                    package_name: None,
                    unread_tests: &[],
                    unknown_tests_left_out: false,
                    test_references_incomplete: false,
                },
            )
        };
        assert_eq!(reached(&[]), [false, false]);
        assert_eq!(reached(&["test/loader".to_owned()]), [true, true]);
    }
}
