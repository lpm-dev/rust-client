//! CSS-like selector engine for querying the dependency tree.
//!
//! Parses selectors like `:eval`, `:network:shell`, `:eval,:network`,
//! `:not(:built)`, `#express`, `:root > :scripts`, `:critical`.
//!
//! ## Selector syntax
//!
//! - `:pseudo-class` — behavioral tag, state, or severity alias
//! - `#name` — exact package name match
//! - `:not(...)` — negation
//! - `:a:b` — AND (juxtaposition)
//! - `:a,:b` — OR (comma-separated union)
//! - `>` — direct dependency combinator
//! - `:root` — the project itself (package.json)
//!
//! ## Severity aliases
//!
//! - `:critical` = `:obfuscated` OR `:protestware` OR `:high-entropy`
//! - `:high` = `:eval` OR `:child-process` OR `:shell` OR `:dynamic-require` OR `:scripts` OR `:vulnerable`
//! - `:medium` = `:network` OR `:git-dep` OR `:http-dep` OR `:wildcard-dep` OR `:no-license` OR `:native`
//! - `:info` = `:fs` OR `:crypto` OR `:env` OR `:ws` OR `:telemetry` OR `:trivial` OR `:copyleft` OR `:minified` OR `:url-strings`

use crate::behavioral::PackageAnalysis;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// A parsed selector expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Selector {
    /// Match a single pseudo-class (`:eval`, `:network`, etc.)
    PseudoClass(PseudoClass),
    /// Match a package by exact name (`#express`)
    Id(String),
    /// AND: all sub-selectors must match (`:eval:network`)
    And(Vec<Selector>),
    /// OR: any sub-selector must match (`:eval,:network`)
    Or(Vec<Selector>),
    /// NOT: the sub-selector must NOT match (`:not(:eval)`)
    Not(Box<Selector>),
    /// Direct dependency combinator: `parent > child`
    DirectChild {
        parent: Box<Selector>,
        child: Box<Selector>,
    },
}

/// All recognized pseudo-class selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PseudoClass {
    // Source behavior selectors (10)
    Eval,
    Network,
    Fs,
    Shell,
    ChildProcess,
    Native,
    Crypto,
    DynamicRequire,
    Env,
    Ws,

    // Supply chain selectors (7)
    Obfuscated,
    HighEntropy,
    Minified,
    Telemetry,
    UrlStrings,
    Trivial,
    Protestware,

    // Manifest selectors (5)
    GitDep,
    HttpDep,
    WildcardDep,
    Copyleft,
    NoLicense,

    // State & metadata selectors
    Scripts,
    Built,
    Vulnerable,
    Deprecated,
    Lpm,
    Npm,

    // Severity aliases (expand to OR of constituent tags)
    Critical,
    High,
    Medium,
    Info,

    // Special
    Root,
    /// `:workspace-root` — the workspace root when in a monorepo.
    /// Distinct from `:root` in monorepos: `:root` is the invocation root
    /// (the `package.json` closest to where the command ran), while
    /// `:workspace-root` is the workspace container.
    WorkspaceRoot,
}

impl PseudoClass {
    /// Parse a pseudo-class name (without the leading colon).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            // Source tags
            "eval" => Some(Self::Eval),
            "network" => Some(Self::Network),
            "fs" => Some(Self::Fs),
            "shell" => Some(Self::Shell),
            "child-process" => Some(Self::ChildProcess),
            "native" => Some(Self::Native),
            "crypto" => Some(Self::Crypto),
            "dynamic-require" => Some(Self::DynamicRequire),
            "env" => Some(Self::Env),
            "ws" => Some(Self::Ws),

            // Supply chain tags
            "obfuscated" => Some(Self::Obfuscated),
            "high-entropy" => Some(Self::HighEntropy),
            "minified" => Some(Self::Minified),
            "telemetry" => Some(Self::Telemetry),
            "url-strings" => Some(Self::UrlStrings),
            "trivial" => Some(Self::Trivial),
            "protestware" => Some(Self::Protestware),

            // Manifest tags
            "git-dep" => Some(Self::GitDep),
            "http-dep" => Some(Self::HttpDep),
            "wildcard-dep" => Some(Self::WildcardDep),
            "copyleft" => Some(Self::Copyleft),
            "no-license" => Some(Self::NoLicense),

            // State/metadata
            "scripts" => Some(Self::Scripts),
            "built" => Some(Self::Built),
            "vulnerable" => Some(Self::Vulnerable),
            "deprecated" => Some(Self::Deprecated),
            "lpm" => Some(Self::Lpm),
            "npm" => Some(Self::Npm),

            // Severity aliases
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "info" => Some(Self::Info),

            // Special
            "root" => Some(Self::Root),
            "workspace-root" => Some(Self::WorkspaceRoot),

            _ => None,
        }
    }

    /// Display name for this pseudo-class (with colon).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Eval => ":eval",
            Self::Network => ":network",
            Self::Fs => ":fs",
            Self::Shell => ":shell",
            Self::ChildProcess => ":child-process",
            Self::Native => ":native",
            Self::Crypto => ":crypto",
            Self::DynamicRequire => ":dynamic-require",
            Self::Env => ":env",
            Self::Ws => ":ws",
            Self::Obfuscated => ":obfuscated",
            Self::HighEntropy => ":high-entropy",
            Self::Minified => ":minified",
            Self::Telemetry => ":telemetry",
            Self::UrlStrings => ":url-strings",
            Self::Trivial => ":trivial",
            Self::Protestware => ":protestware",
            Self::GitDep => ":git-dep",
            Self::HttpDep => ":http-dep",
            Self::WildcardDep => ":wildcard-dep",
            Self::Copyleft => ":copyleft",
            Self::NoLicense => ":no-license",
            Self::Scripts => ":scripts",
            Self::Built => ":built",
            Self::Vulnerable => ":vulnerable",
            Self::Deprecated => ":deprecated",
            Self::Lpm => ":lpm",
            Self::Npm => ":npm",
            Self::Critical => ":critical",
            Self::High => ":high",
            Self::Medium => ":medium",
            Self::Info => ":info",
            Self::Root => ":root",
            Self::WorkspaceRoot => ":workspace-root",
        }
    }

    /// All 22 behavioral tag pseudo-classes (excludes state/severity/special).
    pub fn all_behavioral() -> &'static [PseudoClass] {
        &[
            Self::Eval,
            Self::Network,
            Self::Fs,
            Self::Shell,
            Self::ChildProcess,
            Self::Native,
            Self::Crypto,
            Self::DynamicRequire,
            Self::Env,
            Self::Ws,
            Self::Obfuscated,
            Self::HighEntropy,
            Self::Minified,
            Self::Telemetry,
            Self::UrlStrings,
            Self::Trivial,
            Self::Protestware,
            Self::GitDep,
            Self::HttpDep,
            Self::WildcardDep,
            Self::Copyleft,
            Self::NoLicense,
        ]
    }

    /// Severity tier for this pseudo-class (for --count grouping).
    pub fn severity(self) -> Severity {
        match self {
            Self::Obfuscated | Self::Protestware | Self::HighEntropy => Severity::Critical,
            Self::Eval
            | Self::ChildProcess
            | Self::Shell
            | Self::DynamicRequire
            | Self::Scripts
            | Self::Vulnerable => Severity::High,
            Self::Network
            | Self::GitDep
            | Self::HttpDep
            | Self::WildcardDep
            | Self::NoLicense
            | Self::Native => Severity::Medium,
            Self::Fs
            | Self::Crypto
            | Self::Env
            | Self::Ws
            | Self::Telemetry
            | Self::Trivial
            | Self::Copyleft
            | Self::Minified
            | Self::UrlStrings => Severity::Info,
            // Severity aliases return their own severity
            Self::Critical => Severity::Critical,
            Self::High => Severity::High,
            Self::Medium => Severity::Medium,
            Self::Info => Severity::Info,
            // State/special have no severity
            Self::Built
            | Self::Deprecated
            | Self::Lpm
            | Self::Npm
            | Self::Root
            | Self::WorkspaceRoot => Severity::Info,
        }
    }
}

/// Severity tier for grouping output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Info => write!(f, "Info"),
        }
    }
}

// ─── Parser ──────────────────────────────────────────────────────────────────

/// Token produced by the lexer.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// `:pseudo-class` (name without colon)
    Colon(String),
    /// `#package-name`
    Hash(String),
    /// `,` (OR separator)
    Comma,
    /// `>` (direct child combinator)
    Gt,
    /// `(` opening paren (inside :not)
    LParen,
    /// `)` closing paren
    RParen,
    /// `*` wildcard (matches any package)
    Star,
}

/// Parse error with position info.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parse error at position {}: {}",
            self.position, self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Tokenize a selector string into tokens.
fn tokenize(input: &str) -> Result<Vec<(Token, usize)>, ParseError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' => {
                i += 1;
            }
            ':' => {
                let start = i;
                i += 1;
                let name_start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '-' || chars[i] == '_')
                {
                    i += 1;
                }
                if i == name_start {
                    return Err(ParseError {
                        message: "expected pseudo-class name after ':'".into(),
                        position: start,
                    });
                }
                let name: String = chars[name_start..i].iter().collect();
                tokens.push((Token::Colon(name), start));
            }
            '#' => {
                let start = i;
                i += 1;
                let name_start = i;
                // Package names can contain @, /, ., -, _
                while i < chars.len()
                    && (chars[i].is_alphanumeric()
                        || chars[i] == '-'
                        || chars[i] == '_'
                        || chars[i] == '.'
                        || chars[i] == '/'
                        || chars[i] == '@')
                {
                    i += 1;
                }
                if i == name_start {
                    return Err(ParseError {
                        message: "expected package name after '#'".into(),
                        position: start,
                    });
                }
                let name: String = chars[name_start..i].iter().collect();
                tokens.push((Token::Hash(name), start));
            }
            ',' => {
                tokens.push((Token::Comma, i));
                i += 1;
            }
            '>' => {
                tokens.push((Token::Gt, i));
                i += 1;
            }
            '(' => {
                tokens.push((Token::LParen, i));
                i += 1;
            }
            ')' => {
                tokens.push((Token::RParen, i));
                i += 1;
            }
            '*' => {
                tokens.push((Token::Star, i));
                i += 1;
            }
            c => {
                return Err(ParseError {
                    message: format!("unexpected character '{c}'"),
                    position: i,
                });
            }
        }
    }

    Ok(tokens)
}

/// Recursive-descent parser for selector expressions.
struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<(Token, usize)>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn position(&self) -> usize {
        self.tokens.get(self.pos).map(|(_, p)| *p).unwrap_or(0)
    }

    fn advance(&mut self) -> Option<(Token, usize)> {
        let item = self.tokens.get(self.pos).cloned();
        if item.is_some() {
            self.pos += 1;
        }
        item
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        match self.advance() {
            Some((ref t, _)) if t == expected => Ok(()),
            Some((t, pos)) => Err(ParseError {
                message: format!("expected {expected:?}, got {t:?}"),
                position: pos,
            }),
            None => Err(ParseError {
                message: format!("expected {expected:?}, got end of input"),
                position: self.position(),
            }),
        }
    }

    /// Parse the full expression: `or_expr`
    fn parse(&mut self) -> Result<Selector, ParseError> {
        let sel = self.parse_or()?;
        if self.pos < self.tokens.len() {
            let (t, pos) = &self.tokens[self.pos];
            return Err(ParseError {
                message: format!("unexpected token {t:?}"),
                position: *pos,
            });
        }
        Ok(sel)
    }

    /// Parse OR expressions: `and_expr (',' and_expr)*`
    fn parse_or(&mut self) -> Result<Selector, ParseError> {
        let mut parts = vec![self.parse_child()?];

        while matches!(self.peek(), Some(Token::Comma)) {
            self.advance(); // consume ','
            parts.push(self.parse_child()?);
        }

        if parts.len() == 1 {
            Ok(parts.pop().unwrap())
        } else {
            Ok(Selector::Or(parts))
        }
    }

    /// Parse child combinator: `and_expr ('>' and_expr)*`
    fn parse_child(&mut self) -> Result<Selector, ParseError> {
        let mut left = self.parse_and()?;

        while matches!(self.peek(), Some(Token::Gt)) {
            self.advance(); // consume '>'
            let right = self.parse_and()?;
            left = Selector::DirectChild {
                parent: Box::new(left),
                child: Box::new(right),
            };
        }

        Ok(left)
    }

    /// Parse AND expressions: `atom+` (juxtaposition)
    fn parse_and(&mut self) -> Result<Selector, ParseError> {
        let mut parts = vec![self.parse_atom()?];

        // Juxtaposition: `:eval:network` is AND — keep consuming atoms
        // as long as the next token starts a new atom (colon or hash) but NOT comma/gt
        while matches!(
            self.peek(),
            Some(Token::Colon(_) | Token::Hash(_) | Token::Star)
        ) {
            parts.push(self.parse_atom()?);
        }

        if parts.len() == 1 {
            Ok(parts.pop().unwrap())
        } else {
            Ok(Selector::And(parts))
        }
    }

    /// Parse an atom: pseudo-class, id, :not(), or *
    fn parse_atom(&mut self) -> Result<Selector, ParseError> {
        match self.peek().cloned() {
            Some(Token::Colon(ref name)) => {
                let name = name.clone();
                let pos = self.position();
                self.advance();

                if name == "not" {
                    // :not(inner)
                    self.expect(&Token::LParen)?;
                    let inner = self.parse_or()?;
                    self.expect(&Token::RParen)?;
                    return Ok(Selector::Not(Box::new(inner)));
                }

                let pc = PseudoClass::from_name(&name).ok_or_else(|| ParseError {
                    message: format!("unknown pseudo-class ':{name}'"),
                    position: pos,
                })?;
                Ok(Selector::PseudoClass(pc))
            }
            Some(Token::Hash(_)) => {
                if let Some((Token::Hash(name), _)) = self.advance() {
                    Ok(Selector::Id(name))
                } else {
                    unreachable!()
                }
            }
            Some(Token::Star) => {
                self.advance();
                // * matches any package — represent as an empty And (always true)
                Ok(Selector::And(Vec::new()))
            }
            Some(token) => Err(ParseError {
                message: format!("unexpected token {token:?}"),
                position: self.position(),
            }),
            None => Err(ParseError {
                message: "unexpected end of input".into(),
                position: self.position(),
            }),
        }
    }
}

/// Parse a selector string into a `Selector` AST.
pub fn parse_selector(input: &str) -> Result<Selector, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError {
            message: "empty selector".into(),
            position: 0,
        });
    }

    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(ParseError {
            message: "empty selector".into(),
            position: 0,
        });
    }

    let mut parser = Parser::new(tokens);
    parser.parse()
}

// ─── Matching ────────────────────────────────────────────────────────────────

/// Context for matching a package against selectors.
///
/// Contains all the data needed to evaluate any selector against a single package.
pub struct PackageContext<'a> {
    /// Package name (e.g., "express" or "@lpm.dev/neo.highlight")
    pub name: &'a str,
    /// Package version
    pub version: &'a str,
    /// Instance path — unique key for this specific installation.
    /// For lockfile-based packages: `"node_modules/express"` or `"node_modules/a/node_modules/qs"`.
    /// For LPM store packages: lockfile key.
    /// When empty, falls back to name-based matching (backward compat).
    pub path: &'a str,
    /// Behavioral analysis (from .lpm-security.json)
    pub analysis: Option<&'a PackageAnalysis>,
    /// Whether the package has lifecycle scripts
    pub has_scripts: bool,
    /// Whether the package has been built (.lpm-built exists)
    pub is_built: bool,
    /// Whether the package has known vulnerabilities
    pub is_vulnerable: bool,
    /// Whether the package is deprecated
    pub is_deprecated: bool,
    /// Whether this is the root project (not a dependency)
    pub is_root: bool,
    /// Whether this is a direct dependency of the workspace root
    /// (only meaningful in monorepos where `is_root` refers to
    /// the invocation workspace, not the workspace container).
    pub is_workspace_root_dep: bool,
}

/// How the dependency graph is keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphKeyMode {
    /// Keys are package names (e.g., `"leftpad"`). Used by LPM lockfiles.
    Name,
    /// Keys are instance paths (e.g., `"node_modules/express"`). Used by npm/pnpm/yarn/bun.
    Path,
}

/// Dependency graph for evaluating `>` combinators.
///
/// Keys are instance paths (e.g., `"node_modules/express"`) when available,
/// falling back to package names for backward compatibility with `lpm.lock`.
pub struct DepGraph<'a> {
    /// How this graph is keyed — determines which `PackageContext` field
    /// is used for graph lookups in `matches()`.
    pub key_mode: GraphKeyMode,
    /// Map from package key to its direct dependency keys.
    pub children: HashMap<&'a str, Vec<&'a str>>,
    /// Map from package key to packages that directly depend on it.
    pub parents: HashMap<&'a str, Vec<&'a str>>,
    /// Keys of the root project's direct dependencies.
    pub root_deps: HashSet<&'a str>,
    /// Keys of the workspace root's direct dependencies (monorepo only).
    /// Empty when not in a workspace or when workspace root == invocation root.
    pub workspace_root_deps: HashSet<&'a str>,
}

/// A lightweight package reference for building dependency graphs.
/// Used by `DepGraph::from_instances()` to decouple the graph from
/// specific lockfile or discovery structs.
pub struct DepGraphEntry<'a> {
    /// Package name.
    pub name: &'a str,
    /// Package version.
    pub version: &'a str,
    /// Instance path (unique key, e.g., `"node_modules/express"`).
    pub path: &'a str,
    /// Direct dependencies: `(name, version)` pairs.
    pub dependencies: &'a [(String, String)],
}

impl<'a> DepGraph<'a> {
    /// Build a dependency graph from lockfile packages and root dependencies.
    ///
    /// Uses package name as the graph key (no instance support).
    /// Kept for backward compatibility with `lpm query` in LPM-managed projects.
    pub fn from_lockfile(
        packages: &'a [lpm_lockfile::LockedPackage],
        root_dep_names: &'a HashSet<String>,
    ) -> Self {
        let mut children: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
        let mut parents: HashMap<&'a str, Vec<&'a str>> = HashMap::new();

        // Build a name→package lookup for resolving dep references
        let pkg_by_name: HashMap<&str, &lpm_lockfile::LockedPackage> =
            packages.iter().map(|p| (p.name.as_str(), p)).collect();

        for pkg in packages {
            let pkg_name = pkg.name.as_str();
            let deps: Vec<&str> = pkg
                .dependencies
                .iter()
                .filter_map(|dep_ref| {
                    // Format: "name@version" — extract the name
                    dep_ref.rfind('@').map(|at| &dep_ref[..at])
                })
                .filter(|dep_name| pkg_by_name.contains_key(dep_name))
                .collect();

            for dep_name in &deps {
                parents.entry(dep_name).or_default().push(pkg_name);
            }

            children.insert(pkg_name, deps);
        }

        let root_deps: HashSet<&str> = root_dep_names.iter().map(|s| s.as_str()).collect();

        Self {
            key_mode: GraphKeyMode::Name,
            children,
            parents,
            root_deps,
            workspace_root_deps: HashSet::new(),
        }
    }

    /// Build an instance-based dependency graph from discovered packages.
    ///
    /// Uses `path` as the graph key (unique per instance). Resolves
    /// `(name, version)` dependency pairs to the correct path using
    /// npm-style walk-up resolution: for a package at `node_modules/a`,
    /// its dep `qs@1.0.0` resolves to `node_modules/a/node_modules/qs`
    /// first, then falls back to `node_modules/qs`.
    pub fn from_instances(entries: &[DepGraphEntry<'a>], root_dep_names: &HashSet<String>) -> Self {
        // Build (name, version) → paths lookup.
        let mut nv_to_paths: HashMap<(&str, &str), Vec<&str>> = HashMap::new();

        for entry in entries {
            nv_to_paths
                .entry((entry.name, entry.version))
                .or_default()
                .push(entry.path);
        }

        let mut children: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
        let mut parents: HashMap<&'a str, Vec<&'a str>> = HashMap::new();

        for entry in entries {
            let mut deps: Vec<&str> = Vec::new();
            for (dep_name, dep_ver) in entry.dependencies {
                if let Some(paths) = nv_to_paths.get(&(dep_name.as_str(), dep_ver.as_str())) {
                    // Resolve to the closest matching path (npm walk-up).
                    // A package at `node_modules/a` prefers
                    // `node_modules/a/node_modules/qs` over `node_modules/qs`.
                    let dep_path = resolve_closest_path(entry.path, dep_name, paths);
                    deps.push(dep_path);
                    parents.entry(dep_path).or_default().push(entry.path);
                }
            }
            children.insert(entry.path, deps);
        }

        // Root deps: only top-level instances (node_modules/<name>, not nested).
        // A package at node_modules/a/node_modules/qs is NOT a root dep even
        // if "qs" is in root_dep_names — only node_modules/qs is.
        let root_deps: HashSet<&str> = entries
            .iter()
            .filter(|e| root_dep_names.contains(e.name) && is_top_level_node_modules_path(e.path))
            .map(|e| e.path)
            .collect();

        Self {
            key_mode: GraphKeyMode::Path,
            children,
            parents,
            root_deps,
            workspace_root_deps: HashSet::new(),
        }
    }

    /// Set workspace root dependencies (call after construction for monorepos).
    pub fn set_workspace_root_deps(&mut self, deps: HashSet<&'a str>) {
        self.workspace_root_deps = deps;
    }

    /// Get direct dependencies of a package (by key).
    pub fn direct_deps(&self, key: &str) -> &[&'a str] {
        self.children.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Resolve a dependency to the closest matching path using npm-style walk-up.
///
/// For a parent at `node_modules/a`, dep `qs` resolves to:
/// 1. `node_modules/a/node_modules/qs` (nested under parent) — preferred
/// 2. `node_modules/qs` (hoisted to root) — fallback
///
/// When only one candidate path exists, returns it directly.
fn resolve_closest_path<'a>(parent_path: &str, dep_name: &str, candidates: &[&'a str]) -> &'a str {
    if candidates.len() == 1 {
        return candidates[0];
    }

    // Build the nested path prefix: strip trailing package name from parent,
    // then append `node_modules/<dep_name>`.
    // e.g., parent="node_modules/a" → check "node_modules/a/node_modules/<dep>"
    let nested_prefix = format!("{parent_path}/node_modules/{dep_name}");

    // Prefer the exact nested match
    for &path in candidates {
        if path == nested_prefix {
            return path;
        }
    }

    // Walk up: try progressively shorter prefixes
    // e.g., parent="node_modules/a/node_modules/b"
    //   → try "node_modules/a/node_modules/<dep>"
    //   → try "node_modules/<dep>"
    let mut current = parent_path;
    while let Some(pos) = current.rfind("/node_modules/") {
        current = &current[..pos];
        let check = format!("{current}/node_modules/{dep_name}");
        for &path in candidates {
            if path == check {
                return path;
            }
        }
    }

    // Final fallback: top-level
    let top_level = format!("node_modules/{dep_name}");
    for &path in candidates {
        if path == top_level {
            return path;
        }
    }

    // No resolution found — return first candidate
    candidates[0]
}

/// Check if a path is a top-level node_modules entry (not nested).
///
/// `"node_modules/qs"` → true
/// `"node_modules/@scope/pkg"` → true
/// `"node_modules/a/node_modules/qs"` → false
fn is_top_level_node_modules_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("node_modules/") else {
        return false;
    };
    // For scoped packages, rest is "@scope/name" — no further "node_modules/"
    !rest.contains("node_modules/")
}

/// Evaluate a selector against a package, considering the dependency graph
/// for `>` combinators.
///
/// The `all_packages` map should be keyed by the same key used in `DepGraph`:
/// - For instance-based graphs (`from_instances`): use `path` as key
/// - For name-based graphs (`from_lockfile`): use `name` as key
///
/// Returns `true` if the package matches the selector.
pub fn matches(
    selector: &Selector,
    pkg: &PackageContext<'_>,
    graph: &DepGraph<'_>,
    all_packages: &HashMap<&str, PackageContext<'_>>,
) -> bool {
    match selector {
        Selector::PseudoClass(pc) => matches_pseudo_class(*pc, pkg),
        Selector::Id(id) => matches_id(id, pkg),
        Selector::And(parts) => {
            // Empty And = wildcard (*), always true
            parts.is_empty() || parts.iter().all(|s| matches(s, pkg, graph, all_packages))
        }
        Selector::Or(parts) => parts.iter().any(|s| matches(s, pkg, graph, all_packages)),
        Selector::Not(inner) => !matches(inner, pkg, graph, all_packages),
        Selector::DirectChild { parent, child } => {
            // The current package must match `child`, and at least one
            // of its parents in the graph must match `parent`.
            if !matches(child, pkg, graph, all_packages) {
                return false;
            }

            // Graph key: determined by the graph's key mode
            let graph_key = match graph.key_mode {
                GraphKeyMode::Name => pkg.name,
                GraphKeyMode::Path => pkg.path,
            };

            // Check if parent is :root or :workspace-root
            if matches!(
                parent.as_ref(),
                Selector::PseudoClass(PseudoClass::WorkspaceRoot)
            ) {
                return graph.workspace_root_deps.contains(graph_key);
            }
            if is_root_selector(parent) {
                return graph.root_deps.contains(graph_key);
            }

            // Check actual parents
            if let Some(parent_keys) = graph.parents.get(graph_key) {
                parent_keys.iter().any(|parent_key| {
                    if let Some(parent_pkg) = all_packages.get(parent_key) {
                        matches(parent, parent_pkg, graph, all_packages)
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        }
    }
}

/// Match `#id` selector against a package.
///
/// Supports three forms:
/// - `#express` — matches all instances of package named "express"
/// - `#express@4.22.1` — matches only express at version 4.22.1
/// - `#@scope/name` — matches scoped package names
/// - `#@scope/name@1.0.0` — matches scoped package at specific version
fn matches_id(id: &str, pkg: &PackageContext<'_>) -> bool {
    // Check for version qualifier: find @ that separates name from version.
    // Scoped packages start with @, so we need to skip the leading @ and
    // any @ that's part of the scope (e.g., @lpm.dev/owner.pkg).
    let search_start = if id.starts_with('@') {
        // Scoped package: skip past the scope (find / first)
        id.find('/').map(|p| p + 1).unwrap_or(1)
    } else {
        0
    };

    if let Some(at_pos) = id[search_start..].find('@') {
        let at_pos = search_start + at_pos;
        let name = &id[..at_pos];
        let version = &id[at_pos + 1..];
        pkg.name == name && pkg.version == version
    } else {
        // No version qualifier — match by name only (all instances)
        pkg.name == id
    }
}

/// Check if a selector is `:root` or `:workspace-root` (used for `>` combinator).
fn is_root_selector(sel: &Selector) -> bool {
    matches!(
        sel,
        Selector::PseudoClass(PseudoClass::Root | PseudoClass::WorkspaceRoot)
    )
}

/// Evaluate a pseudo-class against a package's data.
fn matches_pseudo_class(pc: PseudoClass, pkg: &PackageContext<'_>) -> bool {
    match pc {
        // Source tags
        PseudoClass::Eval => tag_check(pkg, |a| a.source.eval),
        PseudoClass::Network => tag_check(pkg, |a| a.source.network),
        PseudoClass::Fs => tag_check(pkg, |a| a.source.filesystem),
        PseudoClass::Shell => tag_check(pkg, |a| a.source.shell),
        PseudoClass::ChildProcess => tag_check(pkg, |a| a.source.child_process),
        PseudoClass::Native => tag_check(pkg, |a| a.source.native_bindings),
        PseudoClass::Crypto => tag_check(pkg, |a| a.source.crypto),
        PseudoClass::DynamicRequire => tag_check(pkg, |a| a.source.dynamic_require),
        PseudoClass::Env => tag_check(pkg, |a| a.source.environment_vars),
        PseudoClass::Ws => tag_check(pkg, |a| a.source.web_socket),

        // Supply chain tags
        PseudoClass::Obfuscated => tag_check(pkg, |a| a.supply_chain.obfuscated),
        PseudoClass::HighEntropy => tag_check(pkg, |a| a.supply_chain.high_entropy_strings),
        PseudoClass::Minified => tag_check(pkg, |a| a.supply_chain.minified),
        PseudoClass::Telemetry => tag_check(pkg, |a| a.supply_chain.telemetry),
        PseudoClass::UrlStrings => tag_check(pkg, |a| a.supply_chain.url_strings),
        PseudoClass::Trivial => tag_check(pkg, |a| a.supply_chain.trivial),
        PseudoClass::Protestware => tag_check(pkg, |a| a.supply_chain.protestware),

        // Manifest tags
        PseudoClass::GitDep => tag_check(pkg, |a| a.manifest.git_dependency),
        PseudoClass::HttpDep => tag_check(pkg, |a| a.manifest.http_dependency),
        PseudoClass::WildcardDep => tag_check(pkg, |a| a.manifest.wildcard_dependency),
        PseudoClass::Copyleft => tag_check(pkg, |a| a.manifest.copyleft_license),
        PseudoClass::NoLicense => tag_check(pkg, |a| a.manifest.no_license),

        // State selectors
        PseudoClass::Scripts => pkg.has_scripts,
        PseudoClass::Built => pkg.is_built,
        PseudoClass::Vulnerable => pkg.is_vulnerable,
        PseudoClass::Deprecated => pkg.is_deprecated,
        PseudoClass::Lpm => pkg.name.starts_with("@lpm.dev/"),
        PseudoClass::Npm => !pkg.name.starts_with("@lpm.dev/"),
        PseudoClass::Root => pkg.is_root,
        PseudoClass::WorkspaceRoot => pkg.is_workspace_root_dep,

        // Severity aliases — expand to OR of constituent tags
        PseudoClass::Critical => {
            matches_pseudo_class(PseudoClass::Obfuscated, pkg)
                || matches_pseudo_class(PseudoClass::Protestware, pkg)
                || matches_pseudo_class(PseudoClass::HighEntropy, pkg)
        }
        PseudoClass::High => {
            matches_pseudo_class(PseudoClass::Eval, pkg)
                || matches_pseudo_class(PseudoClass::ChildProcess, pkg)
                || matches_pseudo_class(PseudoClass::Shell, pkg)
                || matches_pseudo_class(PseudoClass::DynamicRequire, pkg)
                || matches_pseudo_class(PseudoClass::Scripts, pkg)
                || matches_pseudo_class(PseudoClass::Vulnerable, pkg)
        }
        PseudoClass::Medium => {
            matches_pseudo_class(PseudoClass::Network, pkg)
                || matches_pseudo_class(PseudoClass::GitDep, pkg)
                || matches_pseudo_class(PseudoClass::HttpDep, pkg)
                || matches_pseudo_class(PseudoClass::WildcardDep, pkg)
                || matches_pseudo_class(PseudoClass::NoLicense, pkg)
                || matches_pseudo_class(PseudoClass::Native, pkg)
        }
        PseudoClass::Info => {
            matches_pseudo_class(PseudoClass::Fs, pkg)
                || matches_pseudo_class(PseudoClass::Crypto, pkg)
                || matches_pseudo_class(PseudoClass::Env, pkg)
                || matches_pseudo_class(PseudoClass::Ws, pkg)
                || matches_pseudo_class(PseudoClass::Telemetry, pkg)
                || matches_pseudo_class(PseudoClass::Trivial, pkg)
                || matches_pseudo_class(PseudoClass::Copyleft, pkg)
                || matches_pseudo_class(PseudoClass::Minified, pkg)
                || matches_pseudo_class(PseudoClass::UrlStrings, pkg)
        }
    }
}

/// Helper: check a behavioral tag from analysis data.
/// Returns `false` if no analysis is available.
#[inline]
fn tag_check(pkg: &PackageContext<'_>, f: impl FnOnce(&PackageAnalysis) -> bool) -> bool {
    pkg.analysis.is_some_and(f)
}

// ─── Count Mode ──────────────────────────────────────────────────────────────

/// Tag count entry for `--count` output.
#[derive(Debug, Clone)]
pub struct TagCount {
    pub pseudo_class: PseudoClass,
    pub count: usize,
}

/// Count how many packages match each behavioral tag, grouped by severity.
pub fn count_all_tags(packages: &[PackageContext<'_>]) -> Vec<TagCount> {
    let mut counts = Vec::new();

    for &pc in PseudoClass::all_behavioral() {
        let count = packages
            .iter()
            .filter(|pkg| matches_pseudo_class(pc, pkg))
            .count();
        counts.push(TagCount {
            pseudo_class: pc,
            count,
        });
    }

    // Also count state selectors
    let state_selectors = [PseudoClass::Scripts, PseudoClass::Vulnerable];
    for pc in state_selectors {
        let count = packages
            .iter()
            .filter(|pkg| matches_pseudo_class(pc, pkg))
            .count();
        counts.push(TagCount {
            pseudo_class: pc,
            count,
        });
    }

    counts
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavioral::{
        AnalysisMeta, PackageAnalysis, manifest::ManifestTags, source::SourceTags,
        supply_chain::SupplyChainTags,
    };

    fn default_analysis() -> PackageAnalysis {
        PackageAnalysis {
            version: 2,
            analyzed_at: String::new(),
            source: SourceTags::default(),
            supply_chain: SupplyChainTags::default(),
            manifest: ManifestTags::default(),
            meta: AnalysisMeta::default(),
        }
    }

    fn make_pkg<'a>(name: &'a str, analysis: Option<&'a PackageAnalysis>) -> PackageContext<'a> {
        PackageContext {
            name,
            version: "1.0.0",
            path: "",
            analysis,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        }
    }

    fn empty_graph<'a>() -> DepGraph<'a> {
        DepGraph {
            key_mode: GraphKeyMode::Name,
            children: HashMap::new(),
            parents: HashMap::new(),
            root_deps: HashSet::new(),
            workspace_root_deps: HashSet::new(),
        }
    }

    // ─── Tokenizer tests ─────────────────────────────────────────────────

    #[test]
    fn tokenize_simple_pseudo() {
        let tokens = tokenize(":eval").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, Token::Colon("eval".into()));
    }

    #[test]
    fn tokenize_and() {
        let tokens = tokenize(":eval:network").unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].0, Token::Colon("eval".into()));
        assert_eq!(tokens[1].0, Token::Colon("network".into()));
    }

    #[test]
    fn tokenize_or() {
        let tokens = tokenize(":eval,:network").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].0, Token::Colon("eval".into()));
        assert_eq!(tokens[1].0, Token::Comma);
        assert_eq!(tokens[2].0, Token::Colon("network".into()));
    }

    #[test]
    fn tokenize_id() {
        let tokens = tokenize("#express").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, Token::Hash("express".into()));
    }

    #[test]
    fn tokenize_scoped_id() {
        let tokens = tokenize("#@lpm.dev/neo.highlight").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, Token::Hash("@lpm.dev/neo.highlight".into()));
    }

    #[test]
    fn tokenize_not() {
        let tokens = tokenize(":not(:built)").unwrap();
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0].0, Token::Colon("not".into()));
        assert_eq!(tokens[1].0, Token::LParen);
        assert_eq!(tokens[2].0, Token::Colon("built".into()));
        assert_eq!(tokens[3].0, Token::RParen);
    }

    #[test]
    fn tokenize_child_combinator() {
        let tokens = tokenize(":root > :scripts").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].0, Token::Colon("root".into()));
        assert_eq!(tokens[1].0, Token::Gt);
        assert_eq!(tokens[2].0, Token::Colon("scripts".into()));
    }

    #[test]
    fn tokenize_star() {
        let tokens = tokenize("#express > *").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].0, Token::Hash("express".into()));
        assert_eq!(tokens[1].0, Token::Gt);
        assert_eq!(tokens[2].0, Token::Star);
    }

    #[test]
    fn tokenize_error_empty_pseudo() {
        assert!(tokenize(":").is_err());
    }

    #[test]
    fn tokenize_error_empty_hash() {
        assert!(tokenize("#").is_err());
    }

    #[test]
    fn tokenize_error_unknown_char() {
        assert!(tokenize("?eval").is_err());
    }

    // ─── Parser tests ────────────────────────────────────────────────────

    #[test]
    fn parse_single_pseudo() {
        let sel = parse_selector(":eval").unwrap();
        assert_eq!(sel, Selector::PseudoClass(PseudoClass::Eval));
    }

    #[test]
    fn parse_and() {
        let sel = parse_selector(":eval:network").unwrap();
        assert_eq!(
            sel,
            Selector::And(vec![
                Selector::PseudoClass(PseudoClass::Eval),
                Selector::PseudoClass(PseudoClass::Network),
            ])
        );
    }

    #[test]
    fn parse_or() {
        let sel = parse_selector(":eval,:network").unwrap();
        assert_eq!(
            sel,
            Selector::Or(vec![
                Selector::PseudoClass(PseudoClass::Eval),
                Selector::PseudoClass(PseudoClass::Network),
            ])
        );
    }

    #[test]
    fn parse_not() {
        let sel = parse_selector(":not(:built)").unwrap();
        assert_eq!(
            sel,
            Selector::Not(Box::new(Selector::PseudoClass(PseudoClass::Built)))
        );
    }

    #[test]
    fn parse_complex_not() {
        let sel = parse_selector(":scripts:not(:built)").unwrap();
        assert_eq!(
            sel,
            Selector::And(vec![
                Selector::PseudoClass(PseudoClass::Scripts),
                Selector::Not(Box::new(Selector::PseudoClass(PseudoClass::Built))),
            ])
        );
    }

    #[test]
    fn parse_direct_child() {
        let sel = parse_selector(":root > :scripts").unwrap();
        assert_eq!(
            sel,
            Selector::DirectChild {
                parent: Box::new(Selector::PseudoClass(PseudoClass::Root)),
                child: Box::new(Selector::PseudoClass(PseudoClass::Scripts)),
            }
        );
    }

    #[test]
    fn parse_id() {
        let sel = parse_selector("#express").unwrap();
        assert_eq!(sel, Selector::Id("express".into()));
    }

    #[test]
    fn parse_id_child_wildcard() {
        let sel = parse_selector("#express > *").unwrap();
        assert_eq!(
            sel,
            Selector::DirectChild {
                parent: Box::new(Selector::Id("express".into())),
                child: Box::new(Selector::And(Vec::new())),
            }
        );
    }

    #[test]
    fn parse_severity_alias() {
        let sel = parse_selector(":critical").unwrap();
        assert_eq!(sel, Selector::PseudoClass(PseudoClass::Critical));
    }

    #[test]
    fn parse_unknown_pseudo_error() {
        assert!(parse_selector(":foobar").is_err());
    }

    #[test]
    fn parse_empty_error() {
        assert!(parse_selector("").is_err());
        assert!(parse_selector("   ").is_err());
    }

    #[test]
    fn parse_or_with_and() {
        // `:eval:network,:shell` = OR(AND(eval,network), shell)
        let sel = parse_selector(":eval:network,:shell").unwrap();
        assert_eq!(
            sel,
            Selector::Or(vec![
                Selector::And(vec![
                    Selector::PseudoClass(PseudoClass::Eval),
                    Selector::PseudoClass(PseudoClass::Network),
                ]),
                Selector::PseudoClass(PseudoClass::Shell),
            ])
        );
    }

    #[test]
    fn parse_not_with_or() {
        let sel = parse_selector(":not(:eval,:network)").unwrap();
        assert_eq!(
            sel,
            Selector::Not(Box::new(Selector::Or(vec![
                Selector::PseudoClass(PseudoClass::Eval),
                Selector::PseudoClass(PseudoClass::Network),
            ])))
        );
    }

    #[test]
    fn parse_chained_child() {
        // `:root > #express > :eval`
        let sel = parse_selector(":root > #express > :eval").unwrap();
        assert_eq!(
            sel,
            Selector::DirectChild {
                parent: Box::new(Selector::DirectChild {
                    parent: Box::new(Selector::PseudoClass(PseudoClass::Root)),
                    child: Box::new(Selector::Id("express".into())),
                }),
                child: Box::new(Selector::PseudoClass(PseudoClass::Eval)),
            }
        );
    }

    // ─── Matching tests ──────────────────────────────────────────────────

    #[test]
    fn match_eval_tag() {
        let mut analysis = default_analysis();
        analysis.source.eval = true;
        let pkg = make_pkg("terser", Some(&analysis));
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector(":eval").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let sel_fs = parse_selector(":fs").unwrap();
        assert!(!matches(&sel_fs, &pkg, &graph, &all));
    }

    #[test]
    fn match_and() {
        let mut analysis = default_analysis();
        analysis.source.eval = true;
        analysis.source.network = true;
        let pkg = make_pkg("bad-pkg", Some(&analysis));
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector(":eval:network").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        // Only one matches
        let mut analysis2 = default_analysis();
        analysis2.source.eval = true;
        let pkg2 = make_pkg("ok-pkg", Some(&analysis2));
        assert!(!matches(&sel, &pkg2, &graph, &all));
    }

    #[test]
    fn match_or() {
        let mut analysis = default_analysis();
        analysis.source.eval = true;
        let pkg = make_pkg("terser", Some(&analysis));
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector(":eval,:network").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        // Neither matches
        let analysis_clean = default_analysis();
        let pkg_clean = make_pkg("clean-pkg", Some(&analysis_clean));
        assert!(!matches(&sel, &pkg_clean, &graph, &all));
    }

    #[test]
    fn match_not() {
        let pkg = PackageContext {
            name: "pkg",
            version: "1.0.0",
            path: "",
            analysis: None,
            has_scripts: true,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector(":scripts:not(:built)").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let built_pkg = PackageContext {
            is_built: true,
            ..pkg
        };
        assert!(!matches(&sel, &built_pkg, &graph, &all));
    }

    #[test]
    fn match_id() {
        let pkg = make_pkg("express", None);
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector("#express").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let sel2 = parse_selector("#react").unwrap();
        assert!(!matches(&sel2, &pkg, &graph, &all));
    }

    #[test]
    fn match_lpm_npm() {
        let lpm_pkg = make_pkg("@lpm.dev/neo.highlight", None);
        let npm_pkg = make_pkg("express", None);
        let graph = empty_graph();
        let all = HashMap::new();

        let sel_lpm = parse_selector(":lpm").unwrap();
        assert!(matches(&sel_lpm, &lpm_pkg, &graph, &all));
        assert!(!matches(&sel_lpm, &npm_pkg, &graph, &all));

        let sel_npm = parse_selector(":npm").unwrap();
        assert!(matches(&sel_npm, &npm_pkg, &graph, &all));
        assert!(!matches(&sel_npm, &lpm_pkg, &graph, &all));
    }

    #[test]
    fn match_severity_alias() {
        let mut analysis = default_analysis();
        analysis.supply_chain.obfuscated = true;
        let pkg = make_pkg("bad-pkg", Some(&analysis));
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector(":critical").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let sel_high = parse_selector(":high").unwrap();
        assert!(!matches(&sel_high, &pkg, &graph, &all));
    }

    #[test]
    fn match_wildcard() {
        let pkg = make_pkg("anything", None);
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector("*").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));
    }

    #[test]
    fn match_root_child() {
        let pkg = PackageContext {
            name: "express",
            version: "4.18.2",
            path: "",
            analysis: None,
            has_scripts: true,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let mut root_deps = HashSet::new();
        root_deps.insert("express");

        let graph = DepGraph {
            key_mode: GraphKeyMode::Name,
            children: HashMap::new(),
            parents: HashMap::new(),
            root_deps,
            workspace_root_deps: HashSet::new(),
        };
        let all = HashMap::new();

        let sel = parse_selector(":root > :scripts").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        // Non-root-dep should not match
        let other_pkg = PackageContext {
            name: "body-parser",
            has_scripts: true,
            ..pkg
        };
        assert!(!matches(&sel, &other_pkg, &graph, &all));
    }

    #[test]
    fn match_parent_child() {
        let mut analysis = default_analysis();
        analysis.source.eval = true;
        let child_pkg = PackageContext {
            name: "acorn",
            version: "8.12.0",
            path: "",
            analysis: Some(&analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let parent_analysis = default_analysis();
        let parent_pkg = PackageContext {
            name: "terser",
            version: "5.31.0",
            path: "",
            analysis: Some(&parent_analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let mut parents = HashMap::new();
        parents.insert("acorn", vec!["terser"]);
        let mut children = HashMap::new();
        children.insert("terser", vec!["acorn"]);

        let graph = DepGraph {
            key_mode: GraphKeyMode::Name,
            children,
            parents,
            root_deps: HashSet::new(),
            workspace_root_deps: HashSet::new(),
        };

        let mut all = HashMap::new();
        all.insert("terser", parent_pkg);
        all.insert("acorn", child_pkg);

        let child_ref = all.get("acorn").unwrap();
        let sel = parse_selector("#terser > :eval").unwrap();
        assert!(matches(&sel, child_ref, &graph, &all));

        // acorn is not a direct child of a non-existent parent
        let sel2 = parse_selector("#react > :eval").unwrap();
        assert!(!matches(&sel2, child_ref, &graph, &all));
    }

    #[test]
    fn match_no_analysis() {
        let pkg = make_pkg("unknown", None);
        let graph = empty_graph();
        let all = HashMap::new();

        // All behavioral tags should return false when no analysis exists
        let sel = parse_selector(":eval").unwrap();
        assert!(!matches(&sel, &pkg, &graph, &all));
    }

    // ─── Count tests ─────────────────────────────────────────────────────

    #[test]
    fn count_tags() {
        let mut a1 = default_analysis();
        a1.source.eval = true;
        a1.source.network = true;

        let mut a2 = default_analysis();
        a2.source.eval = true;
        a2.source.filesystem = true;

        let pkgs = vec![make_pkg("pkg1", Some(&a1)), make_pkg("pkg2", Some(&a2))];

        let counts = count_all_tags(&pkgs);
        let eval_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Eval)
            .unwrap();
        assert_eq!(eval_count.count, 2);

        let network_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Network)
            .unwrap();
        assert_eq!(network_count.count, 1);

        let fs_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Fs)
            .unwrap();
        assert_eq!(fs_count.count, 1);
    }

    // ─── PseudoClass exhaustiveness ──────────────────────────────────────

    #[test]
    fn all_pseudo_classes_parse() {
        let names = [
            "eval",
            "network",
            "fs",
            "shell",
            "child-process",
            "native",
            "crypto",
            "dynamic-require",
            "env",
            "ws",
            "obfuscated",
            "high-entropy",
            "minified",
            "telemetry",
            "url-strings",
            "trivial",
            "protestware",
            "git-dep",
            "http-dep",
            "wildcard-dep",
            "copyleft",
            "no-license",
            "scripts",
            "built",
            "vulnerable",
            "deprecated",
            "lpm",
            "npm",
            "critical",
            "high",
            "medium",
            "info",
            "root",
        ];
        for name in names {
            assert!(
                PseudoClass::from_name(name).is_some(),
                "PseudoClass::from_name({name:?}) should be Some"
            );
        }
    }

    #[test]
    fn all_pseudo_classes_have_display_names() {
        let names = [
            "eval",
            "network",
            "fs",
            "shell",
            "child-process",
            "native",
            "crypto",
            "dynamic-require",
            "env",
            "ws",
            "obfuscated",
            "high-entropy",
            "minified",
            "telemetry",
            "url-strings",
            "trivial",
            "protestware",
            "git-dep",
            "http-dep",
            "wildcard-dep",
            "copyleft",
            "no-license",
            "scripts",
            "built",
            "vulnerable",
            "deprecated",
            "lpm",
            "npm",
            "critical",
            "high",
            "medium",
            "info",
            "root",
        ];
        for name in names {
            let pc = PseudoClass::from_name(name).unwrap();
            let display = pc.display_name();
            assert!(
                display.starts_with(':'),
                "display name for {name} should start with ':', got {display}"
            );
        }
    }

    // ─── Fixture lockfile tests ──────────────────────────────────

    fn make_lockfile_packages() -> Vec<lpm_lockfile::LockedPackage> {
        vec![
            lpm_lockfile::LockedPackage {
                name: "express".into(),
                version: "4.18.2".into(),
                source: None,
                integrity: None,
                dependencies: vec!["body-parser@1.20.0".into(), "debug@4.3.4".into()],
                alias_dependencies: vec![],
            },
            lpm_lockfile::LockedPackage {
                name: "body-parser".into(),
                version: "1.20.0".into(),
                source: None,
                integrity: None,
                dependencies: vec!["debug@4.3.4".into()],
                alias_dependencies: vec![],
            },
            lpm_lockfile::LockedPackage {
                name: "debug".into(),
                version: "4.3.4".into(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
            },
            lpm_lockfile::LockedPackage {
                name: "@lpm.dev/neo.highlight".into(),
                version: "2.0.0".into(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
            },
        ]
    }

    #[test]
    fn fixture_lockfile_count_tags() {
        let mut a_express = default_analysis();
        a_express.source.eval = true;
        a_express.source.network = true;

        let mut a_body = default_analysis();
        a_body.source.filesystem = true;

        let a_debug = default_analysis();
        let a_lpm = default_analysis();

        let pkgs = vec![
            make_pkg("express", Some(&a_express)),
            make_pkg("body-parser", Some(&a_body)),
            make_pkg("debug", Some(&a_debug)),
            make_pkg("@lpm.dev/neo.highlight", Some(&a_lpm)),
        ];

        let counts = count_all_tags(&pkgs);

        let eval_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Eval)
            .unwrap();
        assert_eq!(eval_count.count, 1, "only express has eval");

        let fs_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Fs)
            .unwrap();
        assert_eq!(fs_count.count, 1, "only body-parser has fs");

        let network_count = counts
            .iter()
            .find(|c| c.pseudo_class == PseudoClass::Network)
            .unwrap();
        assert_eq!(network_count.count, 1, "only express has network");
    }

    #[test]
    fn fixture_lockfile_dep_graph() {
        let packages = make_lockfile_packages();
        let mut root_deps = HashSet::new();
        root_deps.insert("express".to_string());
        root_deps.insert("@lpm.dev/neo.highlight".to_string());

        let graph = DepGraph::from_lockfile(&packages, &root_deps);

        // express depends on body-parser and debug
        assert_eq!(graph.direct_deps("express").len(), 2);
        // body-parser depends on debug
        assert_eq!(graph.direct_deps("body-parser").len(), 1);
        // debug has no deps
        assert_eq!(graph.direct_deps("debug").len(), 0);
        // express and lpm are root deps
        assert!(graph.root_deps.contains("express"));
        assert!(graph.root_deps.contains("@lpm.dev/neo.highlight"));
        assert!(!graph.root_deps.contains("body-parser"));
    }

    #[test]
    fn fixture_root_child_only_matches_direct_deps() {
        let packages = make_lockfile_packages();
        let mut root_deps = HashSet::new();
        root_deps.insert("express".to_string());

        let graph = DepGraph::from_lockfile(&packages, &root_deps);

        let express_pkg = make_pkg("express", None);
        let body_parser_pkg = make_pkg("body-parser", None);
        let debug_pkg = make_pkg("debug", None);
        let all = HashMap::new();

        let sel = parse_selector(":root > *").unwrap();
        assert!(
            matches(&sel, &express_pkg, &graph, &all),
            "express is a root dep"
        );
        assert!(
            !matches(&sel, &body_parser_pkg, &graph, &all),
            "body-parser is NOT a root dep"
        );
        assert!(
            !matches(&sel, &debug_pkg, &graph, &all),
            "debug is NOT a root dep"
        );
    }

    #[test]
    fn fixture_lpm_vs_npm_filter() {
        let a = default_analysis();
        let pkgs = [
            make_pkg("express", Some(&a)),
            make_pkg("@lpm.dev/neo.highlight", Some(&a)),
        ];
        let graph = empty_graph();
        let all = HashMap::new();

        let sel_lpm = parse_selector(":lpm").unwrap();
        let sel_npm = parse_selector(":npm").unwrap();

        assert!(!matches(&sel_lpm, &pkgs[0], &graph, &all));
        assert!(matches(&sel_npm, &pkgs[0], &graph, &all));
        assert!(matches(&sel_lpm, &pkgs[1], &graph, &all));
        assert!(!matches(&sel_npm, &pkgs[1], &graph, &all));
    }

    // ─── Circular dependency edge case ───────────────────────────

    #[test]
    fn circular_dependency_no_infinite_loop() {
        // A depends on B, B depends on A (circular)
        let mut parents = HashMap::new();
        parents.insert("a", vec!["b"]);
        parents.insert("b", vec!["a"]);

        let mut children = HashMap::new();
        children.insert("a", vec!["b"]);
        children.insert("b", vec!["a"]);

        let graph = DepGraph {
            key_mode: GraphKeyMode::Name,
            children,
            parents,
            root_deps: HashSet::new(),
            workspace_root_deps: HashSet::new(),
        };

        let mut a_analysis = default_analysis();
        a_analysis.source.eval = true;
        let b_analysis = default_analysis();

        let pkg_a = PackageContext {
            name: "a",
            version: "1.0.0",
            path: "",
            analysis: Some(&a_analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let pkg_b = PackageContext {
            name: "b",
            version: "1.0.0",
            path: "",
            analysis: Some(&b_analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let mut all = HashMap::new();
        all.insert(
            "a",
            PackageContext {
                name: "a",
                version: "1.0.0",
                path: "",
                analysis: Some(&a_analysis),
                has_scripts: false,
                is_built: false,
                is_vulnerable: false,
                is_deprecated: false,
                is_root: false,
                is_workspace_root_dep: false,
            },
        );
        all.insert(
            "b",
            PackageContext {
                name: "b",
                version: "1.0.0",
                path: "",
                analysis: Some(&b_analysis),
                has_scripts: false,
                is_built: false,
                is_vulnerable: false,
                is_deprecated: false,
                is_root: false,
                is_workspace_root_dep: false,
            },
        );

        // The point: no infinite loop when evaluating combinators on cyclic graphs
        let sel = parse_selector("#a > :eval").unwrap();
        // b is a child of a, but b doesn't have eval → false
        assert!(!matches(&sel, &pkg_b, &graph, &all));
        // a IS a child of b (circular), and a has eval → check if parent (b) matches #a
        // b is NOT #a, so this should be false
        assert!(!matches(&sel, &pkg_a, &graph, &all));

        // #b > :eval — a is child of b, a has eval → true
        let sel2 = parse_selector("#b > :eval").unwrap();
        assert!(matches(&sel2, &pkg_a, &graph, &all));
    }

    // ─── 1000-package query performance ──────────────────────────

    #[test]
    fn query_1000_packages_performance() {
        let analyses: Vec<PackageAnalysis> = (0..1000)
            .map(|i| {
                let mut a = default_analysis();
                if i % 10 == 0 {
                    a.source.eval = true;
                }
                if i % 5 == 0 {
                    a.source.network = true;
                }
                if i % 20 == 0 {
                    a.source.filesystem = true;
                }
                a
            })
            .collect();

        let pkgs: Vec<PackageContext<'_>> = analyses
            .iter()
            .enumerate()
            .map(|(i, a)| PackageContext {
                name: Box::leak(format!("pkg-{i}").into_boxed_str()),
                version: "1.0.0",
                path: "",
                analysis: Some(a),
                has_scripts: i % 50 == 0,
                is_built: false,
                is_vulnerable: false,
                is_deprecated: false,
                is_root: false,
                is_workspace_root_dep: false,
            })
            .collect();

        let graph = empty_graph();
        let all: HashMap<&str, PackageContext<'_>> = HashMap::new();

        let sel = parse_selector(":eval").unwrap();
        let start = std::time::Instant::now();

        let matched: Vec<_> = pkgs
            .iter()
            .filter(|pkg| super::matches(&sel, pkg, &graph, &all))
            .collect();

        let elapsed = start.elapsed();
        assert_eq!(matched.len(), 100, "10% of 1000 packages have eval");
        assert!(
            elapsed.as_millis() < 2000,
            "query on 1000 packages must complete in < 2s, took {}ms",
            elapsed.as_millis()
        );
    }

    // ─── Instance-based matching tests ──────────────────────────────

    #[test]
    fn id_selector_matches_name_only() {
        let pkg = make_pkg("express", None);
        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector("#express").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let sel2 = parse_selector("#react").unwrap();
        assert!(!matches(&sel2, &pkg, &graph, &all));
    }

    #[test]
    fn id_selector_matches_name_at_version() {
        let mut pkg = make_pkg("qs", None);
        pkg.version = "6.14.0";

        let graph = empty_graph();
        let all = HashMap::new();

        // Exact match
        let sel = parse_selector("#qs@6.14.0").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        // Wrong version
        let sel2 = parse_selector("#qs@6.5.3").unwrap();
        assert!(!matches(&sel2, &pkg, &graph, &all));

        // Name-only still matches
        let sel3 = parse_selector("#qs").unwrap();
        assert!(matches(&sel3, &pkg, &graph, &all));
    }

    #[test]
    fn id_selector_scoped_package_with_version() {
        let mut pkg = make_pkg("@lpm.dev/neo.highlight", None);
        pkg.version = "2.0.0";

        let graph = empty_graph();
        let all = HashMap::new();

        let sel = parse_selector("#@lpm.dev/neo.highlight@2.0.0").unwrap();
        assert!(matches(&sel, &pkg, &graph, &all));

        let sel2 = parse_selector("#@lpm.dev/neo.highlight@1.0.0").unwrap();
        assert!(!matches(&sel2, &pkg, &graph, &all));

        let sel3 = parse_selector("#@lpm.dev/neo.highlight").unwrap();
        assert!(matches(&sel3, &pkg, &graph, &all));
    }

    #[test]
    fn dep_graph_from_instances() {
        let deps_express = vec![
            ("qs".to_string(), "6.14.0".to_string()),
            ("accepts".to_string(), "1.3.8".to_string()),
        ];
        let deps_empty: Vec<(String, String)> = vec![];

        let entries = vec![
            DepGraphEntry {
                name: "express",
                version: "4.22.1",
                path: "node_modules/express",
                dependencies: &deps_express,
            },
            DepGraphEntry {
                name: "qs",
                version: "6.14.0",
                path: "node_modules/qs",
                dependencies: &deps_empty,
            },
            DepGraphEntry {
                name: "accepts",
                version: "1.3.8",
                path: "node_modules/accepts",
                dependencies: &deps_empty,
            },
        ];

        let root_deps: HashSet<String> = ["express".to_string()].into_iter().collect();
        let graph = DepGraph::from_instances(&entries, &root_deps);

        // express should be a root dep
        assert!(graph.root_deps.contains("node_modules/express"));

        // express → [qs, accepts]
        let express_children = graph.direct_deps("node_modules/express");
        assert_eq!(express_children.len(), 2);
        assert!(express_children.contains(&"node_modules/qs"));
        assert!(express_children.contains(&"node_modules/accepts"));

        // qs parents should include express
        assert!(
            graph
                .parents
                .get("node_modules/qs")
                .unwrap()
                .contains(&"node_modules/express")
        );
    }

    #[test]
    fn instance_graph_child_combinator() {
        let mut eval_analysis = default_analysis();
        eval_analysis.source.eval = true;
        let clean_analysis = default_analysis();

        let deps_express = vec![("qs".to_string(), "6.14.0".to_string())];
        let deps_empty: Vec<(String, String)> = vec![];

        let entries = vec![
            DepGraphEntry {
                name: "express",
                version: "4.22.1",
                path: "node_modules/express",
                dependencies: &deps_express,
            },
            DepGraphEntry {
                name: "qs",
                version: "6.14.0",
                path: "node_modules/qs",
                dependencies: &deps_empty,
            },
        ];

        let root_deps: HashSet<String> = ["express".to_string()].into_iter().collect();
        let graph = DepGraph::from_instances(&entries, &root_deps);

        let qs_pkg = PackageContext {
            name: "qs",
            version: "6.14.0",
            path: "node_modules/qs",
            analysis: Some(&eval_analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let express_pkg = PackageContext {
            name: "express",
            version: "4.22.1",
            path: "node_modules/express",
            analysis: Some(&clean_analysis),
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        let mut all: HashMap<&str, PackageContext<'_>> = HashMap::new();
        all.insert("node_modules/express", express_pkg);
        all.insert("node_modules/qs", qs_pkg);

        let qs_ref = all.get("node_modules/qs").unwrap();

        // #express > :eval — qs is child of express and has eval → true
        let sel = parse_selector("#express > :eval").unwrap();
        assert!(matches(&sel, qs_ref, &graph, &all));

        // :root > :eval — express is root dep but qs is not → false
        let sel2 = parse_selector(":root > :eval").unwrap();
        assert!(!matches(&sel2, qs_ref, &graph, &all));
    }

    #[test]
    fn dep_graph_resolves_closest_path_for_duplicate_instances() {
        // Bug: when qs@1.0.0 exists at both node_modules/qs and
        // node_modules/a/node_modules/qs, the graph should resolve
        // a's dependency on qs to the nested instance, not fan out to both.
        let deps_a = vec![("qs".to_string(), "1.0.0".to_string())];
        let deps_empty: Vec<(String, String)> = vec![];

        let entries = vec![
            DepGraphEntry {
                name: "a",
                version: "1.0.0",
                path: "node_modules/a",
                dependencies: &deps_a,
            },
            DepGraphEntry {
                name: "qs",
                version: "1.0.0",
                path: "node_modules/a/node_modules/qs",
                dependencies: &deps_empty,
            },
            DepGraphEntry {
                name: "qs",
                version: "1.0.0",
                path: "node_modules/qs",
                dependencies: &deps_empty,
            },
        ];

        let root_deps: HashSet<String> = ["a".to_string(), "qs".to_string()].into_iter().collect();
        let graph = DepGraph::from_instances(&entries, &root_deps);

        // a → qs should resolve to the NESTED instance only
        let a_children = graph.direct_deps("node_modules/a");
        assert_eq!(a_children.len(), 1);
        assert_eq!(
            a_children[0], "node_modules/a/node_modules/qs",
            "a should resolve qs to nested instance, not hoisted"
        );

        // The hoisted qs should NOT have a as parent
        let hoisted_parents = graph.parents.get("node_modules/qs");
        assert!(
            hoisted_parents.is_none() || !hoisted_parents.unwrap().contains(&"node_modules/a"),
            "hoisted qs should not have a as parent"
        );
    }

    #[test]
    fn root_deps_only_marks_top_level_instances() {
        // Bug: root_deps matched by name, so nested qs@1.0.0 at
        // node_modules/a/node_modules/qs was also marked as root dep.
        // Only node_modules/qs (top-level) should be a root dep.
        let deps_a = vec![("qs".to_string(), "1.0.0".to_string())];
        let deps_empty: Vec<(String, String)> = vec![];

        let entries = vec![
            DepGraphEntry {
                name: "a",
                version: "1.0.0",
                path: "node_modules/a",
                dependencies: &deps_a,
            },
            DepGraphEntry {
                name: "qs",
                version: "1.0.0",
                path: "node_modules/qs",
                dependencies: &deps_empty,
            },
            DepGraphEntry {
                name: "qs",
                version: "1.0.0",
                path: "node_modules/a/node_modules/qs",
                dependencies: &deps_empty,
            },
        ];

        let root_deps: HashSet<String> = ["a".to_string(), "qs".to_string()].into_iter().collect();
        let graph = DepGraph::from_instances(&entries, &root_deps);

        // Only top-level instances should be root deps
        assert!(
            graph.root_deps.contains("node_modules/a"),
            "a is a direct root dep"
        );
        assert!(
            graph.root_deps.contains("node_modules/qs"),
            "hoisted qs is a direct root dep"
        );
        assert!(
            !graph.root_deps.contains("node_modules/a/node_modules/qs"),
            "nested qs must NOT be a root dep"
        );
    }

    #[test]
    fn lpm_name_keyed_graph_works_with_nonempty_path() {
        // Regression: after PackageInventory refactor, LPM packages get
        // path="node_modules/leftpad" (non-empty), but the graph is keyed
        // by name. The matcher must use graph.key_mode to pick the right key.
        let packages = vec![
            lpm_lockfile::LockedPackage {
                name: "leftpad".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: vec!["qs@1.0.0".to_string()],
                alias_dependencies: vec![],
            },
            lpm_lockfile::LockedPackage {
                name: "qs".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
            },
        ];
        let root_deps: HashSet<String> = ["leftpad".to_string()].into_iter().collect();
        let graph = DepGraph::from_lockfile(&packages, &root_deps);

        // Packages have non-empty paths (as they would after inventory refactor)
        let leftpad = PackageContext {
            name: "leftpad",
            version: "1.0.0",
            path: "node_modules/leftpad", // non-empty!
            analysis: None,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };
        let qs = PackageContext {
            name: "qs",
            version: "1.0.0",
            path: "node_modules/qs", // non-empty!
            analysis: None,
            has_scripts: false,
            is_built: false,
            is_vulnerable: false,
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: false,
        };

        // Graph is name-keyed, so all_packages must be name-keyed too
        let mut all = HashMap::new();
        all.insert("leftpad", PackageContext { ..leftpad });
        all.insert("qs", PackageContext { ..qs });

        let qs_ref = all.get("qs").unwrap();
        let leftpad_ref = all.get("leftpad").unwrap();

        // :root > #leftpad — leftpad is root dep
        let sel = parse_selector(":root > #leftpad").unwrap();
        assert!(
            matches(&sel, leftpad_ref, &graph, &all),
            ":root > #leftpad must match even with non-empty path"
        );

        // #leftpad > #qs — qs is child of leftpad
        let sel2 = parse_selector("#leftpad > #qs").unwrap();
        assert!(
            matches(&sel2, qs_ref, &graph, &all),
            "#leftpad > #qs must match even with non-empty path"
        );
    }
}
