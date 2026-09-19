use crate::CheckEngine;
use lpm_common::LpmError;
use std::fs::OpenOptions;
use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 65_536;
const MAX_DEPTH: usize = 16;

pub(super) struct Arguments {
    pub(super) values: Vec<String>,
    pub(super) watch: bool,
    _snapshots: Option<tempfile::TempDir>,
}

#[derive(Default)]
struct Audit {
    build: bool,
    watch: bool,
    init: bool,
    clean: bool,
    help: bool,
    all: bool,
    version: bool,
    show_config: bool,
    bytes: usize,
    tokens: usize,
    stack: Vec<PathBuf>,
    snapshots: Option<tempfile::TempDir>,
    next_snapshot: usize,
}

impl Arguments {
    pub(super) fn prepare(
        cwd: &Path,
        args: &[String],
        engine: CheckEngine,
    ) -> Result<Self, LpmError> {
        if matches!(engine, CheckEngine::Tsgo)
            && args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "--api" | "--lsp"))
        {
            return Err(error("tsgo server modes are not supported by lpm check"));
        }
        let mut audit = Audit {
            build: args
                .first()
                .is_some_and(|arg| matches!(option_name(arg).as_deref(), Some("b" | "build"))),
            ..Default::default()
        };
        let mut values = args.to_vec();
        audit.frame(cwd, &mut values, engine)?;
        let finite = if audit.build {
            audit.help
        } else {
            audit.version || audit.help || audit.all || audit.show_config
        };
        if (!audit.build && audit.init) || (audit.build && audit.clean && !finite) {
            return Err(error(
                "lpm check does not create configuration or clean build outputs; run the compiler directly for --init or --clean",
            ));
        }
        // A dangling value option can consume one flag. The second always sets noEmit.
        values.extend(["--noEmit".into(), "--noEmit".into()]);
        Ok(Self {
            values,
            watch: audit.watch && !finite,
            _snapshots: audit.snapshots,
        })
    }
}

impl Audit {
    fn frame(
        &mut self,
        cwd: &Path,
        args: &mut [String],
        engine: CheckEngine,
    ) -> Result<(), LpmError> {
        self.tokens = self.tokens.saturating_add(args.len());
        if self.tokens > MAX_ARGUMENTS {
            return Err(error("compiler arguments exceed the 65536-token limit"));
        }
        let mut index = 0;
        while index < args.len() {
            if let Some(file) = args[index].strip_prefix('@') {
                args[index] = format!("@{}", snapshot_text(&self.response(cwd, file, engine)?)?);
                index += 1;
                continue;
            }
            let Some(name) = option_name(&args[index]) else {
                index += 1;
                continue;
            };
            let next = args.get(index + 1).map(String::as_str);
            let boolean = match next {
                Some("false" | "null") => Some(false),
                Some("true") => Some(true),
                _ => None,
            };
            let value = boolean.unwrap_or(true);
            match name.as_str() {
                "watch" | "w" => self.watch = value,
                "init" => self.init = value,
                "clean" => self.clean = value,
                "help" | "h" | "?" => self.help = value,
                "all" => self.all = value,
                "version" | "v" if !self.build => self.version = value,
                "showconfig" => self.show_config = value,
                _ => {}
            }
            let consumed = match arity(&name, engine) {
                Arity::Scalar => next.is_some(),
                Arity::List => next.is_some_and(|value| !value.trim_start().starts_with('-')),
                Arity::Config => {
                    next.is_some_and(|value| !value.is_empty() && !value.starts_with('-'))
                }
                Arity::Boolean => boolean.is_some(),
            };
            index += 1 + usize::from(consumed);
        }
        Ok(())
    }

    fn response(
        &mut self,
        cwd: &Path,
        file: &str,
        engine: CheckEngine,
    ) -> Result<PathBuf, LpmError> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(error(
                "compiler response files exceed the 16-level nesting limit",
            ));
        }
        let path = cwd.join(file);
        let canonical = path
            .canonicalize()
            .map_err(|e| error(format!("cannot read response file {}: {e}", path.display())))?;
        if self.stack.contains(&canonical) {
            return Err(error(format!(
                "recursive compiler response file: {}",
                path.display()
            )));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let input = options
            .open(&canonical)
            .map_err(|e| error(format!("cannot read response file {}: {e}", path.display())))?;
        if !input.metadata()?.is_file() {
            return Err(error(format!(
                "response file is not a regular file: {}",
                path.display()
            )));
        }
        let mut bytes = Vec::new();
        input
            .take((MAX_RESPONSE_BYTES - self.bytes + 1) as u64)
            .read_to_end(&mut bytes)?;
        self.bytes += bytes.len();
        if self.bytes > MAX_RESPONSE_BYTES {
            return Err(error(
                "compiler response files exceed the 4 MiB input limit",
            ));
        }
        let text = decode_response(&bytes)?;
        let tokens = tokenize(&text)?;
        let mut args = tokens
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        self.stack.push(canonical);
        self.frame(cwd, &mut args, engine)?;
        self.stack.pop();
        let mut captured = String::with_capacity(text.len() + 2);
        captured.push('\n');
        let mut offset = 0;
        for ((span, original), replacement) in tokens.iter().zip(&args) {
            if original != replacement {
                captured.push_str(&text[offset..span.start]);
                captured.push_str(&quote_response_token(replacement)?);
                offset = span.end;
            }
        }
        captured.push_str(&text[offset..]);
        // The pinned native compiler reads past an unquoted token at EOF without whitespace.
        captured.push('\n');
        if self.snapshots.is_none() {
            self.snapshots = Some(tempfile::Builder::new().prefix("lpm-check-").tempdir()?);
        }
        let dir = self
            .snapshots
            .as_ref()
            .ok_or_else(|| error("response snapshot directory is unavailable"))?;
        let snapshot = dir.path().join(format!("{}.args", self.next_snapshot));
        self.next_snapshot += 1;
        std::fs::write(&snapshot, captured)?;
        Ok(snapshot)
    }
}

fn snapshot_text(path: &Path) -> Result<&str, LpmError> {
    path.to_str()
        .ok_or_else(|| error("compiler response snapshots require a UTF-8 temporary directory"))
}

fn quote_response_token(value: &str) -> Result<String, LpmError> {
    if !value.bytes().any(|byte| byte <= b' ') {
        return Ok(value.to_owned());
    }
    if value.contains('"') {
        return Err(error(
            "compiler response snapshots require a temporary directory without both quotes and whitespace",
        ));
    }
    Ok(format!("\"{value}\""))
}

fn option_name(value: &str) -> Option<String> {
    let name = value.strip_prefix('-')?;
    Some(name.strip_prefix('-').unwrap_or(name).to_ascii_lowercase())
}

enum Arity {
    Boolean,
    Scalar,
    List,
    Config,
}

fn arity(name: &str, engine: CheckEngine) -> Arity {
    match name {
        "generatecpuprofile"
        | "generatetrace"
        | "locale"
        | "project"
        | "p"
        | "target"
        | "t"
        | "module"
        | "m"
        | "jsx"
        | "outfile"
        | "outdir"
        | "rootdir"
        | "tsbuildinfofile"
        | "importsnotusedasvalues"
        | "moduleresolution"
        | "baseurl"
        | "sourceroot"
        | "maproot"
        | "jsxfactory"
        | "jsxfragmentfactory"
        | "jsximportsource"
        | "out"
        | "reactnamespace"
        | "charset"
        | "newline"
        | "declarationdir"
        | "maxnodemodulejsdepth"
        | "moduledetection"
        | "ignoredeprecations"
        | "watchfile"
        | "watchdirectory"
        | "fallbackpolling" => Arity::Scalar,
        "pprofdir" | "checkers" | "builders" | "watchinterval"
            if matches!(engine, CheckEngine::Tsgo) =>
        {
            Arity::Scalar
        }
        "lib" | "typeroots" | "types" | "modulesuffixes" | "customconditions"
        | "excludedirectories" | "excludefiles" => Arity::List,
        "paths" | "rootdirs" | "plugins" => Arity::Config,
        _ => Arity::Boolean,
    }
}

fn tokenize(text: &str) -> Result<Vec<(Range<usize>, String)>, LpmError> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] <= b' ' {
            index += 1;
            continue;
        }
        let start = index;
        let value = if bytes[index] == b'"' {
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            if index == bytes.len() {
                return Err(error(
                    "unterminated quoted string in compiler response file",
                ));
            }
            let value = text[value_start..index].to_owned();
            index += 1;
            value
        } else {
            while index < bytes.len() && bytes[index] > b' ' {
                index += 1;
            }
            text[start..index].to_owned()
        };
        tokens.push((start..index, value));
        if tokens.len() > MAX_ARGUMENTS {
            return Err(error(
                "compiler response file exceeds the 65536-token limit",
            ));
        }
    }
    Ok(tokens)
}

fn decode_response(bytes: &[u8]) -> Result<String, LpmError> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        if !bytes.len().is_multiple_of(2) {
            return Err(error("invalid UTF-16 compiler response file"));
        }
        let units = bytes[2..].chunks_exact(2).map(|chunk| {
            if little {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        });
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| error("invalid UTF-16 compiler response file"))
    } else {
        String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_vec(),
        )
        .map_err(|_| error("invalid UTF-8 compiler response file"))
    }
}

fn error(message: impl Into<String>) -> LpmError {
    LpmError::Script(message.into())
}
