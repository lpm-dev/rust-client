use oxc_allocator::{Address, Allocator, GetAddress};
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, Expression, JSXText, RegExpLiteral, Statement, StringLiteral, TemplateElement,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use regex::Regex;
use std::borrow::Cow;
use std::cell::Cell;
use std::panic::AssertUnwindSafe;

pub(super) struct SourceContext<'s> {
    pub stripped: Cow<'s, str>,
    pub executable: Vec<u8>,
    pub complete: bool,
    pub calls: Option<super::bindings::CallFacts>,
    /// Whether the parser found a random-looking string literal, or `None`
    /// when it didn't read the literals.
    pub random_literal: Option<bool>,
    /// The string literals that may name another package file, or `None`
    /// when the parser didn't read the literals.
    pub path_literals: Option<PathLiterals>,
}

/// String literals of a source file that may name another package file
/// ([`super::roles::may_name_package_file`]).
#[derive(Debug, Default)]
pub(super) struct PathLiterals {
    pub literals: Vec<String>,
    /// No literal was left out for space.
    pub complete: bool,
}

/// Most literals and bytes of them [`PathLiterals`] keeps; past them, it
/// keeps none and is incomplete.
const MAX_PATH_LITERALS: usize = 256;
const MAX_PATH_LITERAL_BYTES: usize = 16 * 1024;

/// Most nodes and bytes a constant `+` chain is folded through. Deeper
/// chains aren't static to the call analysis either, so a `require` of one
/// counts as computed.
const MAX_FOLDED_NODES: usize = 64;
const MAX_FOLDED_BYTES: usize = 4096;

/// The value of a string literal, or of a template literal without
/// expressions.
fn static_string<'e>(expression: &'e Expression<'_>) -> Option<&'e str> {
    match expression.get_inner_expression() {
        Expression::StringLiteral(literal) => literal.value.as_str(),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            let quasi = template.quasis.first()?;
            match &quasi.value.cooked {
                Some(cooked) => cooked.as_str(),
                None => Some(quasi.value.raw.as_str()),
            }
        }
        _ => None,
    }
}

/// The segment a folded path gives the module's own file (`__filename`,
/// `import.meta.url`), so `path.join(__filename, "..", x)` and
/// `path.dirname(__filename)` normalize to its directory. No package file is
/// named this.
const OWN_FILE: &str = "./\u{1}";

/// Whether `expression` is a path known before the code runs, as
/// [`fold_static_path`] folds one. A process launch whose script path isn't
/// could run any file.
pub(super) fn is_static_path(expression: &Expression<'_>) -> bool {
    fold_static_path(expression, &mut 0, &mut String::new())
}

/// Appends the path an expression builds to `folded`: string literals, `+`
/// chains and templates of them, the module's own location (`__dirname` and
/// `import.meta.dirname` as `.`, its directory; `__filename`,
/// `import.meta.filename` and `import.meta.url` as its file), and calls that
/// join, resolve or convert such parts (`path.join`, `path.dirname`,
/// `require.resolve`, `fileURLToPath`, `new URL`). `false` when a part is
/// computed, or the expression is longer than the fold allows.
fn fold_static_path(expression: &Expression<'_>, nodes: &mut usize, folded: &mut String) -> bool {
    *nodes += 1;
    if *nodes > MAX_FOLDED_NODES || folded.len() > MAX_FOLDED_BYTES {
        return false;
    }
    if let Some(value) = static_string(expression) {
        folded.push_str(value);
        return true;
    }
    match expression.get_inner_expression() {
        Expression::Identifier(identifier) if identifier.name == "__dirname" => {
            folded.push('.');
            true
        }
        Expression::Identifier(identifier) if identifier.name == "__filename" => {
            folded.push_str(OWN_FILE);
            true
        }
        Expression::StaticMemberExpression(member)
            if matches!(
                member.object.get_inner_expression(),
                Expression::ImportMeta(_)
            ) =>
        {
            match member.property.name.as_str() {
                "dirname" => folded.push('.'),
                "filename" | "url" => folded.push_str(OWN_FILE),
                _ => return false,
            }
            true
        }
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            fold_static_path(&binary.left, nodes, folded)
                && fold_static_path(&binary.right, nodes, folded)
        }
        Expression::TemplateLiteral(template) => {
            for (index, quasi) in template.quasis.iter().enumerate() {
                folded.push_str(quasi.value.raw.as_str());
                if let Some(part) = template.expressions.get(index)
                    && !fold_static_path(part, nodes, folded)
                {
                    return false;
                }
            }
            true
        }
        Expression::CallExpression(call) => {
            fold_path_call(&call.callee, &call.arguments, nodes, folded)
        }
        Expression::NewExpression(new) => {
            fold_path_call(&new.callee, &new.arguments, nodes, folded)
        }
        _ => false,
    }
}

/// [`fold_static_path`] for `path.join(…)`, `path.resolve(…)`,
/// `path.dirname(…)`, `require.resolve(…)`, `fileURLToPath(…)` and
/// `URL(…)`.
fn fold_path_call(
    callee: &Expression<'_>,
    arguments: &[Argument<'_>],
    nodes: &mut usize,
    folded: &mut String,
) -> bool {
    let name = match callee.get_inner_expression() {
        Expression::StaticMemberExpression(member) => member.property.name.as_str(),
        Expression::Identifier(identifier) => identifier.name.as_str(),
        _ => return false,
    };
    match name {
        "join" | "resolve" | "normalize" if !arguments.is_empty() => {
            for (index, argument) in arguments.iter().enumerate() {
                if index > 0 {
                    folded.push('/');
                }
                let Some(argument) = argument.as_expression() else {
                    return false;
                };
                if !fold_static_path(argument, nodes, folded) {
                    return false;
                }
            }
            true
        }
        "dirname" | "fileURLToPath" if arguments.len() == 1 => {
            let Some(argument) = arguments[0].as_expression() else {
                return false;
            };
            if !fold_static_path(argument, nodes, folded) {
                return false;
            }
            if name == "dirname" {
                folded.truncate(folded.trim_end_matches('/').len());
                folded.push_str("/..");
            }
            true
        }
        "URL" => {
            let mut parts = arguments.iter().map(Argument::as_expression);
            let Some(Some(target)) = parts.next() else {
                return false;
            };
            let mut relative = String::new();
            if !fold_static_path(target, nodes, &mut relative) {
                return false;
            }
            match parts.next() {
                None => {}
                Some(Some(base)) if !relative.starts_with('/') && !relative.contains("://") => {
                    // A URL resolves against its base's directory: the base
                    // without the segment after its last slash.
                    let start = folded.len();
                    if !fold_static_path(base, nodes, folded) {
                        return false;
                    }
                    let directory = folded[start..]
                        .rfind('/')
                        .map_or(start, |slash| start + slash);
                    folded.truncate(directory);
                    if folded.len() == start {
                        folded.push('.');
                    }
                    folded.push('/');
                }
                Some(Some(base)) => {
                    if !fold_static_path(base, nodes, &mut String::new()) {
                        return false;
                    }
                }
                Some(None) => return false,
            }
            folded.push_str(&relative);
            true
        }
        _ => false,
    }
}

/// The working directory a call sets, as a `cd` command: `process.chdir(…)`,
/// or a `cwd` option, when the path is static.
fn working_directory(callee: &Expression<'_>, arguments: &[Argument<'_>]) -> Option<String> {
    let fold = |expression: &Expression<'_>| {
        let mut folded = String::from("cd ");
        fold_static_path(expression, &mut 0, &mut folded).then_some(folded)
    };
    let chdir = match callee.get_inner_expression() {
        Expression::StaticMemberExpression(member) => member.property.name == "chdir",
        // `const { chdir } = process; chdir(…)`.
        Expression::Identifier(identifier) => identifier.name == "chdir",
        _ => false,
    };
    if chdir {
        return arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(fold);
    }
    arguments.iter().find_map(|argument| {
        let Some(Expression::ObjectExpression(object)) = argument.as_expression() else {
            return None;
        };
        object.properties.iter().find_map(|property| {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) = property else {
                return None;
            };
            (property.key.static_name().is_some_and(|name| name == "cwd"))
                .then(|| fold(&property.value))
                .flatten()
        })
    })
}

#[derive(Default)]
struct PathLiteralCollector {
    in_test_file: bool,
    literals: Vec<String>,
    bytes: usize,
    overflowed: bool,
}

impl PathLiteralCollector {
    fn for_file(in_test_file: bool) -> Self {
        Self {
            in_test_file,
            ..Self::default()
        }
    }

    fn note(&mut self, value: &str) {
        if !super::roles::may_name_package_file(value, self.in_test_file) {
            return;
        }
        self.keep(value);
    }

    /// Notes a bare module specifier a `require` or an `import` loads, which
    /// Node finds in a `node_modules` directory: one a test file loads, and
    /// one package code loads that names a test directory (`require("test")`),
    /// can be a test file the package bundles.
    fn note_module(&mut self, specifier: &str) {
        if super::roles::is_bare_specifier(specifier)
            && (self.in_test_file || super::roles::mentions_test_marker(specifier))
        {
            self.keep(&format!("{}{specifier}", super::roles::MODULE_SPECIFIER));
        }
    }

    /// Notes a working directory the code enters (`cd <path>`), which names
    /// no test file itself but moves what the file's other paths resolve
    /// from.
    fn note_working_directory(&mut self, cd: &str) {
        self.keep(cd);
    }

    /// Notes the script a launch runs (`fork(script)`, an argument of
    /// `spawn("node", [script])`), as node is given it: a bare name is a path
    /// to node, resolved from the launch's working directory.
    fn note_launch_script(&mut self, script: &str) {
        if self.in_test_file || super::roles::mentions_test_marker(script) {
            self.keep(&format!("node {script}"));
        }
    }

    /// Notes a literal that is one part of a path the code builds: a part
    /// written as a directory between separators (`"/tests/"`) names that
    /// directory under the part before it, so it's kept as a directory, not
    /// read as a filter fragment.
    fn note_part(&mut self, value: &str) {
        if value.len() > 1 && value.starts_with('/') && value.ends_with('/') {
            self.note(&value[1..]);
        } else {
            self.note(value);
        }
    }

    fn keep(&mut self, value: &str) {
        if self.overflowed {
            return;
        }
        self.bytes += value.len();
        if self.literals.len() >= MAX_PATH_LITERALS || self.bytes > MAX_PATH_LITERAL_BYTES {
            self.overflowed = true;
            self.literals = Vec::new();
            return;
        }
        self.literals.push(value.to_owned());
    }

    fn finish(self) -> PathLiterals {
        PathLiterals {
            literals: self.literals,
            complete: !self.overflowed,
        }
    }
}

/// Room kept below a parse's stack floor: the parser checks the floor once
/// per token, the literal visitor once per node, so this covers the frames
/// between two checks and the unwinding after one fails.
const STACK_RED_ZONE: usize = 256 * 1024;

/// How far below the stack floor the literal visitor gives up on a node
/// by unwinding. Expressions and statements, which deep nesting recurses
/// through, stop at the floor itself without unwinding; only recursion
/// through other nodes gets this far. The red zone below the floor holds
/// it.
const UNWIND_BELOW_FLOOR: usize = 64 * 1024;

/// Stack for a parse that ran out of the stack its caller had left. A
/// source that runs out of this too is read without parsing; an adversary
/// can make a parse touch at most this much of it.
const DEEP_PARSE_STACK: usize = 64 * 1024 * 1024;

/// Stack semantic analysis takes before any nesting, and per level of AST
/// depth: at least twice the most measured for any construct, so platforms
/// with larger frames fit too. Semantic analysis is the one recursive pass
/// that can't check the stack itself, so the literal visitor measures the
/// AST's depth first, and the pass runs on a stack this large.
const SEMANTIC_BASE_STACK: usize = 128 * 1024;
const SEMANTIC_LEVEL_STACK: usize = if cfg!(debug_assertions) {
    8 * 1024
} else {
    2 * 1024
};

/// The most stack semantic analysis is given. Only pages it touches use
/// memory, and a left-deep chain, the deepest AST a source can have without
/// the parser recursing, touches a small fraction of its reservation.
const SEMANTIC_MAX_STACK: usize = 256 * 1024 * 1024;

/// Lookups semantic analysis may spend binding and resolving names, per
/// byte of source and for any source. Resolving a reference looks for its
/// name in each scope around it, and a reference in a function's
/// parameters is looked up again for each function around it. A `var`,
/// or a function declared in a block, is recorded in each block between
/// it and its function, and a labelled `break` or `continue` is looked up
/// in the labels around it. A source that nests thousands of scopes or
/// labels around each of its names makes the analysis quadratic. Real
/// code nests a few deep.
const RESOLUTION_LOOKUPS_PER_BYTE: u64 = 16;
const RESOLUTION_LOOKUPS_FLOOR: u64 = 1 << 20;

/// Work the parser may spend on speculative parses, per byte of source and
/// for any source: the bytes it reads again after rewinds. A TypeScript `<`
/// that may open a generic arrow function or type arguments is parsed one
/// way and, when that fails, parsed again the other way with all it holds.
/// The arguments of an `async(…)` that mention `await` are parsed again as
/// parameters when `=>` follows. Nested speculation can make parsing
/// quadratic. Real code spends under one per byte.
const PARSE_SPECULATION_PER_BYTE: u64 = 2;
const PARSE_SPECULATION_FLOOR: u64 = 64 * 1024;

/// The most parentheses, TypeScript wrappers (`as`, `satisfies`, `!`, `<T>`)
/// and sequences, through their last expression, an expression may sit in
/// directly for the rules to run on its source. The rules read through them,
/// and read a binding's initializer again for each reference to it, so an
/// initializer wrapped thousands of times made the analysis quadratic. Real
/// code wraps at most 5 deep.
const MAX_WRAPPER_RUN: u32 = 32;

fn parse_speculation_budget(source: &str) -> u64 {
    (source.len() as u64)
        .saturating_mul(PARSE_SPECULATION_PER_BYTE)
        .max(PARSE_SPECULATION_FLOOR)
}

/// A visitor stopped at the stack floor.
struct StackExhausted;

struct LiteralSpans<'s> {
    executable: &'s mut [u8],
    random_literal: bool,
    paths: PathLiteralCollector,
    /// The expression being visited is an operand of a `+` chain that was
    /// folded where it starts.
    inside_concatenation: bool,
    /// Where the string literal that is an operand of the `+` chain around
    /// it starts: one part of a path the code builds. Set without a restore,
    /// so deep chains don't grow the visitor's frames.
    concatenated_literal: Option<u32>,
    /// The template being visited has expressions: its elements are parts
    /// of a path the code builds.
    in_built_template: bool,
    stack_floor: usize,
    depth: usize,
    max_depth: usize,
    /// Scopes around the node being visited.
    scopes: u64,
    /// Function parameter lists around the node being visited.
    parameter_lists: u64,
    /// Scopes around the node being visited, up to the nearest function
    /// or the program: the blocks a `var` there is recorded in.
    block_scopes: u64,
    /// `block_scopes` of each function the visit is inside.
    outer_block_scopes: Vec<u64>,
    /// Labelled statements around the node being visited.
    labels: u64,
    /// The most lookups semantic analysis can make resolving the
    /// references visited so far.
    resolution_lookups: u64,
    /// The visitor reached the stack floor and skips the rest.
    stopped: bool,
    /// Wrappers the expression being visited sits in directly, itself
    /// included when it is one.
    wrapper_run: u32,
    /// The most wrappers any expression visited sits in directly.
    longest_wrapper_run: u32,
    /// The expression that continues the run of the wrapper being visited:
    /// the one it wraps, or the last expression of a sequence.
    run_continues_into: Option<Address>,
}

/// Whether nodes of this kind get a scope that `var` declarations are
/// hoisted to. Treating another scope as one would undercount the blocks
/// a `var` is recorded in.
fn is_var_scope(kind: AstKind<'_>) -> bool {
    matches!(
        kind,
        AstKind::Program(_)
            | AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::StaticBlock(_)
    )
}

/// Whether semantic analysis gives nodes of this kind a scope of their own.
fn has_scope(kind: AstKind<'_>) -> bool {
    matches!(
        kind,
        AstKind::Program(_)
            | AstKind::BlockStatement(_)
            | AstKind::ForStatement(_)
            | AstKind::ForInStatement(_)
            | AstKind::ForOfStatement(_)
            | AstKind::SwitchStatement(_)
            | AstKind::CatchClause(_)
            | AstKind::WithStatement(_)
            | AstKind::Function(_)
            | AstKind::ArrowFunctionExpression(_)
            | AstKind::Class(_)
            | AstKind::StaticBlock(_)
            | AstKind::TSEnumBody(_)
            | AstKind::TSTypeAliasDeclaration(_)
            | AstKind::TSInterfaceDeclaration(_)
            | AstKind::TSCallSignatureDeclaration(_)
            | AstKind::TSConstructSignatureDeclaration(_)
            | AstKind::TSMethodSignature(_)
            | AstKind::TSConstructorType(_)
            | AstKind::TSFunctionType(_)
            | AstKind::TSConditionalType(_)
            | AstKind::TSMappedType(_)
            | AstKind::TSExternalModuleDeclaration(_)
            | AstKind::TSNamespaceDeclaration(_)
            | AstKind::TSGlobalDeclaration(_)
    )
}

impl LiteralSpans<'_> {
    fn note_value(&mut self, value: Option<&str>) {
        self.random_literal |= value.is_some_and(super::supply_chain::looks_random);
    }

    /// Notes each run of two or more string arguments joined with `/`, as
    /// `path.join(__dirname, "test", "run.js")` joins them.
    fn note_joined_arguments(&mut self, arguments: &[Argument<'_>]) {
        let mut run: Vec<&str> = Vec::new();
        for argument in arguments.iter().map(Some).chain(std::iter::once(None)) {
            match argument
                .and_then(Argument::as_expression)
                .and_then(static_string)
            {
                Some(value) => run.push(value),
                None => {
                    if run.len() >= 2 {
                        self.paths.note(&run.join("/"));
                    }
                    run.clear();
                }
            }
        }
    }

    /// Notes the paths a call names: its joined arguments, a path call's
    /// folded result, a launch's script and its working directory. Kept out
    /// of [`Visit::visit_expression`] so deep nesting doesn't pay for its
    /// locals in every frame.
    #[inline(never)]
    fn note_call(&mut self, callee: &Expression<'_>, arguments: &[Argument<'_>]) {
        self.note_joined_arguments(arguments);
        let mut folded = String::new();
        if fold_path_call(callee, arguments, &mut 0, &mut folded) {
            self.paths.note(&folded);
        }
        let launcher = match callee.get_inner_expression() {
            Expression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
            Expression::Identifier(identifier) => Some(identifier.name.as_str()),
            _ => None,
        };
        let loads_module = match callee.get_inner_expression() {
            Expression::Identifier(identifier) => identifier.name == "require",
            Expression::StaticMemberExpression(member) => {
                member.property.name == "resolve"
                    && member
                        .object
                        .get_inner_expression()
                        .is_specific_id("require")
            }
            _ => false,
        };
        if loads_module
            && let Some(specifier) = arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(static_string)
        {
            self.paths.note_module(specifier);
        }
        match launcher {
            Some("fork" | "Worker") => {
                if let Some(script) = arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .and_then(static_string)
                {
                    self.paths.note_launch_script(script);
                }
            }
            Some("spawn" | "spawnSync" | "execFile" | "execFileSync") => {
                for argument in arguments.iter().filter_map(Argument::as_expression) {
                    if let Expression::ArrayExpression(array) = argument.get_inner_expression() {
                        for script in array
                            .elements
                            .iter()
                            .filter_map(|element| element.as_expression())
                            .filter_map(static_string)
                        {
                            self.paths.note_launch_script(script);
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some(directory) = working_directory(callee, arguments) {
            self.paths.note_working_directory(&directory);
            // A launch's script and arguments resolve from its working
            // directory, so each is noted run from there.
            for argument in arguments.iter().filter_map(Argument::as_expression) {
                let values: Vec<&str> = match argument.get_inner_expression() {
                    Expression::ArrayExpression(array) => array
                        .elements
                        .iter()
                        .filter_map(|element| element.as_expression())
                        .filter_map(static_string)
                        .collect(),
                    other => static_string(other).into_iter().collect(),
                };
                for value in values {
                    self.paths.note(&format!("{directory} && {value}"));
                }
            }
        }
    }

    /// Whether the visitor reached the stack floor. Expressions and
    /// statements are the nodes deep nesting recurses through, and skipping
    /// them there returns up the stack. Unwinding instead costs microseconds
    /// a frame, and a crafted source can put tens of thousands of frames
    /// above the floor.
    fn reached_floor(&mut self) -> bool {
        self.stopped |= stack_address() < self.stack_floor;
        self.stopped
    }
}

fn mask(bytes: &mut [u8], span: Span) {
    if let Some(range) = bytes.get_mut(span.start as usize..span.end as usize) {
        for byte in range {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
}

/// An address in the calling frame, close to the stack pointer.
#[inline(always)]
fn stack_address() -> usize {
    let marker = 0u8;
    (&raw const marker).addr()
}

impl<'a> Visit<'a> for LiteralSpans<'_> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if self.reached_floor() {
            return;
        }
        let continued_into = self.run_continues_into.take();
        let outer_run = self.wrapper_run;
        let wrapped = match expression {
            Expression::ParenthesizedExpression(wrapper) => Some(&wrapper.expression),
            Expression::TSAsExpression(wrapper) => Some(&wrapper.expression),
            Expression::TSSatisfiesExpression(wrapper) => Some(&wrapper.expression),
            Expression::TSNonNullExpression(wrapper) => Some(&wrapper.expression),
            Expression::TSTypeAssertion(wrapper) => Some(&wrapper.expression),
            Expression::TSInstantiationExpression(wrapper) => Some(&wrapper.expression),
            Expression::SequenceExpression(sequence) => sequence.expressions.last(),
            _ => None,
        };
        self.wrapper_run = match wrapped {
            Some(_) if continued_into == Some(expression.address()) => outer_run + 1,
            Some(_) => 1,
            None => 0,
        };
        self.longest_wrapper_run = self.longest_wrapper_run.max(self.wrapper_run);
        self.run_continues_into = wrapped.map(GetAddress::address);
        let concatenation = matches!(
            expression,
            Expression::BinaryExpression(binary) if binary.operator.as_str() == "+"
        );
        if concatenation && !self.inside_concatenation {
            let mut folded = String::new();
            if fold_static_path(expression, &mut 0, &mut folded) {
                self.paths.note(&folded);
            }
        }
        let call = match expression {
            Expression::CallExpression(call) => Some((&call.callee, &call.arguments)),
            Expression::NewExpression(new) => Some((&new.callee, &new.arguments)),
            _ => None,
        };
        if let Some((callee, arguments)) = call {
            self.note_call(callee, arguments);
        }
        let outer_concatenation = self.inside_concatenation;
        if outer_concatenation && let Expression::StringLiteral(literal) = expression {
            self.concatenated_literal = Some(literal.span.start);
        }
        self.inside_concatenation = concatenation;
        walk::walk_expression(self, expression);
        self.inside_concatenation = outer_concatenation;
        self.wrapper_run = outer_run;
        self.run_continues_into = continued_into;
    }

    fn visit_statement(&mut self, statement: &Statement<'a>) {
        if !self.reached_floor() {
            walk::walk_statement(self, statement);
        }
    }

    fn enter_node(&mut self, kind: AstKind<'a>) {
        if stack_address() < self.stack_floor.saturating_sub(UNWIND_BELOW_FLOOR) {
            std::panic::resume_unwind(Box::new(StackExhausted));
        }
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
        let lookups = match kind {
            AstKind::IdentifierReference(_) => self.scopes.saturating_mul(1 + self.parameter_lists),
            // A `var` is recorded in every block up to its function, and a
            // function declared in a block is hoisted out of them. A `let`
            // or `const` costs less, but counting it the same keeps the
            // bound an upper one.
            AstKind::BindingIdentifier(_)
            | AstKind::VariableDeclarator(_)
            | AstKind::Function(_) => self.block_scopes,
            AstKind::BreakStatement(_) | AstKind::ContinueStatement(_) => self.labels,
            _ => 0,
        };
        self.resolution_lookups = self.resolution_lookups.saturating_add(lookups);
        match kind {
            AstKind::FormalParameters(_) => self.parameter_lists += 1,
            AstKind::LabeledStatement(_) => self.labels += 1,
            _ => {}
        }
        if has_scope(kind) {
            self.scopes += 1;
            if is_var_scope(kind) {
                self.outer_block_scopes
                    .push(std::mem::take(&mut self.block_scopes));
            } else {
                self.block_scopes += 1;
            }
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        self.depth -= 1;
        match kind {
            AstKind::FormalParameters(_) => self.parameter_lists -= 1,
            AstKind::LabeledStatement(_) => self.labels -= 1,
            _ => {}
        }
        if has_scope(kind) {
            self.scopes -= 1;
            if is_var_scope(kind) {
                self.block_scopes = self.outer_block_scopes.pop().unwrap_or(0);
            } else {
                self.block_scopes -= 1;
            }
        }
    }

    fn visit_import_declaration(&mut self, declaration: &oxc_ast::ast::ImportDeclaration<'a>) {
        if let Some(specifier) = declaration.source.value.as_str() {
            self.paths.note_module(specifier);
        }
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_export_all_declaration(
        &mut self,
        declaration: &oxc_ast::ast::ExportAllDeclaration<'a>,
    ) {
        if let Some(specifier) = declaration.source.value.as_str() {
            self.paths.note_module(specifier);
        }
        walk::walk_export_all_declaration(self, declaration);
    }

    fn visit_export_from_declaration(
        &mut self,
        declaration: &oxc_ast::ast::ExportFromDeclaration<'a>,
    ) {
        if let Some(specifier) = declaration.source.value.as_str() {
            self.paths.note_module(specifier);
        }
        walk::walk_export_from_declaration(self, declaration);
    }

    fn visit_import_expression(&mut self, expression: &oxc_ast::ast::ImportExpression<'a>) {
        if let Some(specifier) = static_string(&expression.source) {
            self.paths.note_module(specifier);
        }
        walk::walk_import_expression(self, expression);
    }

    fn visit_string_literal(&mut self, literal: &StringLiteral<'a>) {
        mask(self.executable, literal.span);
        if !self.random_literal {
            self.note_value(literal.value.as_str());
        }
        if let Some(value) = literal.value.as_str() {
            if self.concatenated_literal == Some(literal.span.start) {
                self.paths.note_part(value);
            } else {
                self.paths.note(value);
            }
        }
    }

    fn visit_template_literal(&mut self, template: &oxc_ast::ast::TemplateLiteral<'a>) {
        let outer = self.in_built_template;
        self.in_built_template = !template.expressions.is_empty();
        walk::walk_template_literal(self, template);
        self.in_built_template = outer;
    }

    fn visit_object_property(&mut self, property: &oxc_ast::ast::ObjectProperty<'a>) {
        // A working directory set wherever the options are written, for the
        // launch they're handed to.
        if property.key.static_name().is_some_and(|name| name == "cwd") {
            let mut folded = String::from("cd ");
            if fold_static_path(&property.value, &mut 0, &mut folded) {
                self.paths.note_working_directory(&folded);
            }
        }
        walk::walk_object_property(self, property);
    }

    fn visit_reg_exp_literal(&mut self, literal: &RegExpLiteral<'a>) {
        mask(self.executable, literal.span);
    }

    fn visit_template_element(&mut self, literal: &TemplateElement<'a>) {
        mask(self.executable, literal.span);
        let value = match literal.value.cooked {
            Some(cooked) => cooked.as_str(),
            None => Some(literal.value.raw.as_str()),
        };
        if !self.random_literal {
            self.note_value(value);
        }
        if let Some(value) = value {
            if self.in_built_template {
                self.paths.note_part(value);
            } else {
                self.paths.note(value);
            }
        }
    }

    fn visit_jsx_text(&mut self, literal: &JSXText<'a>) {
        mask(self.executable, literal.span);
    }
}

/// What parsing a source file found.
struct Parsed {
    executable: Vec<u8>,
    complete: bool,
    /// The parser reported a syntax error.
    syntax_error: bool,
    calls: Option<super::bindings::CallFacts>,
    random_literal: Option<bool>,
    path_literals: Option<PathLiterals>,
}

/// Why a source wasn't parsed.
enum Unparsed {
    /// It nests too deeply for the stack the parse had; more may do.
    OutOfStack,
    /// Its AST is too deep for semantic analysis on any stack it's given.
    TooDeep,
    /// Resolving its names would take more lookups than a source its size
    /// is given.
    TooManyNestedReferences,
    /// Parsing it would take more speculative work than
    /// [`PARSE_SPECULATION_PER_BYTE`] allows.
    OverSpeculationBudget,
}

/// Parses `source` and runs the syntax passes over it, masking its comments
/// in `stripped`, which holds a copy of it. The parser and the literal
/// visitor stop at `stack_floor`; semantic analysis runs on a stack sized
/// for the AST's depth.
fn parse_above(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
    in_test_file: bool,
    stack_floor: usize,
) -> Result<Parsed, Unparsed> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            stack_floor,
            speculation_budget: parse_speculation_budget(source),
            ..ParseOptions::default()
        })
        .parse();
    if parsed.speculation_budget_exhausted {
        return Err(Unparsed::OverSpeculationBudget);
    }
    if parsed.stack_exhausted {
        return Err(Unparsed::OutOfStack);
    }
    for comment in &parsed.program.comments {
        mask(stripped, comment.span);
    }
    let mut executable = stripped.to_vec();
    let mut literals = LiteralSpans {
        executable: &mut executable,
        random_literal: false,
        paths: PathLiteralCollector::for_file(in_test_file),
        inside_concatenation: false,
        concatenated_literal: None,
        in_built_template: false,
        stack_floor,
        depth: 0,
        max_depth: 0,
        scopes: 0,
        parameter_lists: 0,
        block_scopes: 0,
        outer_block_scopes: Vec::new(),
        labels: 0,
        resolution_lookups: 0,
        stopped: false,
        wrapper_run: 0,
        longest_wrapper_run: 0,
        run_continues_into: None,
    };
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        literals.visit_program(&parsed.program);
    }))
    .map_err(|_| Unparsed::OutOfStack)?;
    if literals.stopped {
        return Err(Unparsed::OutOfStack);
    }
    let random_literal = (!parsed.fatal_error).then_some(literals.random_literal);
    let path_literals = (!parsed.fatal_error).then(|| std::mem::take(&mut literals.paths).finish());
    // A source with a longer run of wrappers keeps its comments and literals
    // masked, but the rules that read through wrappers don't run on it.
    let complete = !parsed.fatal_error
        && !parsed.diagnostics.has_errors()
        && literals.longest_wrapper_run <= MAX_WRAPPER_RUN;
    let resolution_budget = (source.len() as u64)
        .saturating_mul(RESOLUTION_LOOKUPS_PER_BYTE)
        .max(RESOLUTION_LOOKUPS_FLOOR);
    if complete && literals.resolution_lookups > resolution_budget {
        return Err(Unparsed::TooManyNestedReferences);
    }
    let calls = if complete {
        let semantic_stack = literals
            .max_depth
            .saturating_mul(SEMANTIC_LEVEL_STACK)
            .saturating_add(SEMANTIC_BASE_STACK);
        let analyze = || super::bindings::analyze(&parsed.program, complete_input);
        Some(
            if stack_address().saturating_sub(stack_floor) >= semantic_stack {
                analyze()
            } else if semantic_stack <= SEMANTIC_MAX_STACK {
                on_new_stack(semantic_stack, analyze).ok_or(Unparsed::TooDeep)?
            } else {
                return Err(Unparsed::TooDeep);
            },
        )
    } else {
        None
    };
    // Rules that ran out of steps keep what they found, but the file's
    // coverage is incomplete.
    let complete = complete && !calls.as_ref().is_some_and(|calls| calls.over_budget);
    Ok(Parsed {
        executable,
        complete,
        syntax_error: parsed.fatal_error || parsed.diagnostics.has_errors(),
        calls,
        random_literal,
        path_literals,
    })
}

/// Runs `task` on a new stack segment of `bytes`. `None` when the segment
/// can't be mapped: the stack crate panics then, before switching stacks.
fn on_new_stack<T>(bytes: usize, task: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(AssertUnwindSafe(|| stacker::grow(bytes, task))).ok()
}

/// The lowest address a parse on the current stack may use, or `None` when
/// the stack's extent isn't known or less than the red zone is left.
fn current_stack_floor() -> Option<usize> {
    let remaining = stacker::remaining_stack()?;
    (remaining > 2 * STACK_RED_ZONE)
        .then(|| stack_address().saturating_sub(remaining) + STACK_RED_ZONE)
}

/// Parses `source` on the stack its caller has left, or, when it nests too
/// deeply for that, on a [`DEEP_PARSE_STACK`] segment. `None` when it nests
/// too deeply for that too.
fn parse(
    source: &str,
    source_type: SourceType,
    stripped: &mut [u8],
    complete_input: bool,
    in_test_file: bool,
) -> Option<Parsed> {
    let remaining = stacker::remaining_stack().unwrap_or(0);
    if let Some(floor) = current_stack_floor() {
        match parse_above(
            source,
            source_type,
            stripped,
            complete_input,
            in_test_file,
            floor,
        ) {
            Ok(parsed) => return Some(parsed),
            Err(
                Unparsed::TooDeep
                | Unparsed::TooManyNestedReferences
                | Unparsed::OverSpeculationBudget,
            ) => return None,
            Err(Unparsed::OutOfStack) => {}
        }
    }
    if remaining >= DEEP_PARSE_STACK {
        return None;
    }
    on_new_stack(DEEP_PARSE_STACK, || {
        let floor = current_stack_floor()?;
        parse_above(
            source,
            source_type,
            stripped,
            complete_input,
            in_test_file,
            floor,
        )
        .ok()
    })
    .flatten()
}

/// [`parse`], and for JavaScript that has a syntax error and may close a JSX
/// element ([`may_close_jsx_element`]), parsing again with JSX: React and
/// React Native packages ship JSX in `.js` files.
/// The JSX parse is kept when it has no syntax error; otherwise the first
/// parse is.
fn parse_javascript_or_jsx(
    source: &str,
    source_type: SourceType,
    stripped: &mut Vec<u8>,
    complete_input: bool,
    in_test_file: bool,
) -> Option<Parsed> {
    let parsed = parse(source, source_type, stripped, complete_input, in_test_file)?;
    if !parsed.syntax_error
        || !source_type.is_javascript()
        || source_type.is_jsx()
        || !may_close_jsx_element(source.as_bytes())
    {
        return Some(parsed);
    }
    let masked = std::mem::replace(stripped, source.as_bytes().to_vec());
    match parse(
        source,
        source_type.with_jsx(true),
        stripped,
        complete_input,
        in_test_file,
    ) {
        Some(jsx) if !jsx.syntax_error => Some(jsx),
        _ => {
            *stripped = masked;
            Some(parsed)
        }
    }
}

/// Whether `source` has a `/` right after a `<` or right before a `>`, with
/// only whitespace between them, as every JSX element's closing tag or
/// self-closing end has (`</a>`, `<a />`, `< /a>`, `<a / >`). Each
/// whitespace run is crossed at most twice, so the check is linear.
fn may_close_jsx_element(source: &[u8]) -> bool {
    memchr::memchr_iter(b'/', source).any(|slash| {
        let before = source[..slash]
            .iter()
            .rev()
            .find(|byte| !byte.is_ascii_whitespace());
        let after = source[slash + 1..]
            .iter()
            .find(|byte| !byte.is_ascii_whitespace());
        before == Some(&b'<') || after == Some(&b'>')
    })
}

/// Parse options a caller of [`inspect_program`] chooses. The stack floor and
/// speculation budget are always lpm-security's own.
#[derive(Clone, Copy, Debug, Default)]
pub struct ParseSettings {
    /// Accept `return` outside a function, as Node.js does in a CommonJS
    /// module.
    pub allow_return_outside_function: bool,
    /// Parse regular expression patterns, so an invalid one is a syntax
    /// error.
    pub parse_regular_expression: bool,
}

/// The stack floor an [`inspect_program`] parse ran above, for the
/// inspector's own recursion through the program. The parse kept the
/// program's depth to what the parser's frames fit above the floor, but an
/// inspector's frames per level may be larger: one that recurses checks
/// [`reached`](Self::reached) at each node it recurses through and stops
/// once it has.
#[derive(Debug)]
pub struct StackFloor {
    address: usize,
    reached: Cell<bool>,
}

impl StackFloor {
    fn new(address: usize) -> Self {
        Self {
            address,
            reached: Cell::new(false),
        }
    }

    /// Whether the stack has reached the floor.
    #[inline]
    pub fn reached(&self) -> bool {
        let reached = stack_address() < self.address;
        if reached {
            self.reached.set(true);
        }
        reached
    }
}

/// Why [`inspect_program`] gave no program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unparsable {
    /// The parser stopped at a syntax error it can't recover from.
    SyntaxError,
    /// The source nests too deeply for a 64 MiB stack segment, or no
    /// segment could be mapped.
    TooDeep,
    /// Parsing it takes more speculative work than its length allows.
    OverSpeculationBudget,
}

/// Parses `source` as `source_type` with lpm-security's stack floor and
/// speculation budget, and gives `inspect` the program, whether it parsed
/// without a syntax error, and the [`StackFloor`] for its own recursion.
///
/// A parse, or an inspection, that reaches the floor on the caller's stack
/// runs again on a 64 MiB stack segment, so `inspect` may run twice.
/// An inspection that reaches the floor there too returns what it found.
pub fn inspect_program<T>(
    source: &str,
    source_type: SourceType,
    settings: ParseSettings,
    mut inspect: impl FnMut(&oxc_ast::ast::Program<'_>, bool, &StackFloor) -> T,
) -> Result<T, Unparsable> {
    let remaining = stacker::remaining_stack().unwrap_or(0);
    let mut on_caller_stack = Err(Unparsable::TooDeep);
    if let Some(floor) = current_stack_floor() {
        match inspect_above(source, source_type, settings, floor, &mut inspect) {
            Attempt::Finished(result) => return result,
            Attempt::ParseReachedFloor => {}
            Attempt::InspectionReachedFloor(partial) => on_caller_stack = Ok(partial),
        }
    }
    if remaining >= DEEP_PARSE_STACK {
        return on_caller_stack;
    }
    on_new_stack(DEEP_PARSE_STACK, || {
        let floor = current_stack_floor().ok_or(Unparsable::TooDeep)?;
        match inspect_above(source, source_type, settings, floor, &mut inspect) {
            Attempt::Finished(result) => result,
            Attempt::ParseReachedFloor => Err(Unparsable::TooDeep),
            Attempt::InspectionReachedFloor(partial) => Ok(partial),
        }
    })
    .unwrap_or(Err(Unparsable::TooDeep))
}

enum Attempt<T> {
    Finished(Result<T, Unparsable>),
    ParseReachedFloor,
    /// What an inspection that reached the floor returned.
    InspectionReachedFloor(T),
}

fn inspect_above<T>(
    source: &str,
    source_type: SourceType,
    settings: ParseSettings,
    stack_floor: usize,
    inspect: &mut impl FnMut(&oxc_ast::ast::Program<'_>, bool, &StackFloor) -> T,
) -> Attempt<T> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            allow_return_outside_function: settings.allow_return_outside_function,
            parse_regular_expression: settings.parse_regular_expression,
            stack_floor,
            speculation_budget: parse_speculation_budget(source),
            ..ParseOptions::default()
        })
        .parse();
    if parsed.speculation_budget_exhausted {
        return Attempt::Finished(Err(Unparsable::OverSpeculationBudget));
    }
    if parsed.stack_exhausted {
        return Attempt::ParseReachedFloor;
    }
    if parsed.fatal_error {
        return Attempt::Finished(Err(Unparsable::SyntaxError));
    }
    let floor = StackFloor::new(stack_floor);
    let result = inspect(&parsed.program, !parsed.diagnostics.has_errors(), &floor);
    if floor.reached.get() {
        Attempt::InspectionReachedFloor(result)
    } else {
        Attempt::Finished(Ok(result))
    }
}

impl<'s> SourceContext<'s> {
    pub fn new(source: &str, filename: &str, stripped: &'s mut Vec<u8>) -> Self {
        Self::with_complete_input(source, filename, stripped, true)
    }

    /// Reads `source`, parsed when `filename` names JavaScript or
    /// TypeScript and it nests no deeper than a parse has stack for. Other
    /// source is read without parsing, by the linear detectors.
    pub fn with_complete_input(
        source: &str,
        filename: &str,
        stripped: &'s mut Vec<u8>,
        complete_input: bool,
    ) -> Self {
        stripped.clear();
        stripped.extend_from_slice(source.as_bytes());
        let in_test_file = super::roles::is_test_path(filename);
        let parsed = SourceType::from_path(filename)
            .ok()
            .or_else(|| {
                // A script whose extension says nothing is parsed as its
                // shebang line's runtime runs it.
                super::may_be_shebang_script(std::path::Path::new(filename))
                    .then(|| super::shebang_script_extension(source.as_bytes()))
                    .flatten()
                    .and_then(|extension| SourceType::from_extension(extension).ok())
            })
            .and_then(|source_type| {
                parse_javascript_or_jsx(source, source_type, stripped, complete_input, in_test_file)
            });
        let Parsed {
            executable,
            complete,
            calls,
            random_literal,
            path_literals,
            ..
        } = parsed.unwrap_or_else(|| Parsed {
            executable: source.as_bytes().to_vec(),
            complete: false,
            syntax_error: true,
            calls: None,
            random_literal: None,
            path_literals: None,
        });
        Self {
            stripped: String::from_utf8_lossy(stripped),
            executable,
            complete,
            calls,
            random_literal,
            path_literals,
        }
    }

    pub fn find_with_context(&self, regex: &Regex, bare: bool) -> Option<usize> {
        self.matches_with_context(regex, bare).next()
    }

    pub fn count_with_context(&self, regex: &Regex, bare: bool) -> usize {
        self.matches_with_context(regex, bare).count()
    }

    /// Starts of the matches that begin in code, outside comments and literals,
    /// and with `bare`, not as a property of something else.
    fn matches_with_context<'r>(
        &'r self,
        regex: &'r Regex,
        bare: bool,
    ) -> impl Iterator<Item = usize> + 'r {
        regex
            .find_iter(&self.stripped)
            .filter(move |matched| {
                self.executable
                    .get(matched.start())
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                    && (!bare
                        || !self.stripped.as_bytes()[..matched.start()]
                            .iter()
                            .rev()
                            .find(|byte| !byte.is_ascii_whitespace())
                            .is_some_and(|byte| matches!(byte, b'.' | b'$')))
            })
            .map(|matched| matched.start())
    }
}

/// Whether parsing `source`, named `filename`, on a stack deep enough for
/// it, stops at the speculation budget [`parse`] gives it.
#[cfg(test)]
pub(super) fn exhausts_the_speculation_budget(filename: &str, source: &str) -> bool {
    let source_type = SourceType::from_path(filename).unwrap();
    let source = source.to_owned();
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            let allocator = Allocator::default();
            Parser::new(&allocator, &source, source_type)
                .with_options(ParseOptions {
                    stack_floor: current_stack_floor().unwrap(),
                    speculation_budget: parse_speculation_budget(&source),
                    ..ParseOptions::default()
                })
                .parse()
                .speculation_budget_exhausted
        })
        .unwrap()
        .join()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_MIB: usize = 2 * 1024 * 1024;

    /// How deep `[[[…]]]` nests below `expression`, taking `PADDING` bytes
    /// of stack per level. `None` once it reaches the floor.
    fn array_depth<const PADDING: usize>(
        expression: &Expression<'_>,
        floor: &StackFloor,
    ) -> Option<usize> {
        let padding = std::hint::black_box([0u8; PADDING]);
        if floor.reached() {
            return None;
        }
        let Expression::ArrayExpression(array) = expression else {
            return Some(usize::from(padding[0]));
        };
        match array
            .elements
            .first()
            .and_then(|element| element.as_expression())
        {
            Some(inner) => array_depth::<PADDING>(inner, floor).map(|depth| depth + 1),
            None => Some(1),
        }
    }

    /// The depth of the array `x = [[[…]]]` holds, inspected on a thread
    /// with `stack` bytes of stack, `PADDING` of them per level, and how
    /// many times the program was inspected.
    fn inspect_nested_arrays<const PADDING: usize>(
        stack: usize,
        depth: usize,
    ) -> Result<(Option<usize>, u32), Unparsable> {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let source = format!("x={}{};", "[".repeat(depth), "]".repeat(depth));
                let mut inspections = 0;
                let depth = inspect_program(
                    &source,
                    SourceType::cjs(),
                    ParseSettings::default(),
                    |program, _, floor| {
                        inspections += 1;
                        let Some(Statement::ExpressionStatement(statement)) = program.body.first()
                        else {
                            return None;
                        };
                        let Expression::AssignmentExpression(assignment) = &statement.expression
                        else {
                            return None;
                        };
                        array_depth::<PADDING>(&assignment.right, floor)
                    },
                )?;
                Ok((depth, inspections))
            })
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn an_inspection_that_reaches_the_floor_runs_again_on_a_deep_stack_and_finishes() {
        // The parse fits in 2 MiB; 200 levels of 16 KiB don't, but fit in
        // 64 MiB.
        assert_eq!(
            inspect_nested_arrays::<{ 16 * 1024 }>(TWO_MIB, 200),
            Ok((Some(200), 2))
        );
        assert_eq!(inspect_nested_arrays::<64>(TWO_MIB, 20), Ok((Some(20), 1)));
    }

    #[test]
    fn an_inspection_that_reaches_the_floor_on_the_deep_stack_too_returns_what_it_found() {
        // The parse fits in 8 MiB; 600 levels of 128 KiB don't fit in
        // 64 MiB either.
        assert_eq!(
            inspect_nested_arrays::<{ 128 * 1024 }>(8 * 1024 * 1024, 600),
            Ok((None, 2))
        );
        // A caller with more stack left than the deep stack has isn't moved.
        assert_eq!(
            inspect_nested_arrays::<{ 128 * 1024 }>(128 * 1024 * 1024, 1_100),
            Ok((None, 1))
        );
    }

    #[test]
    fn inspect_program_reports_a_parse_too_deep_for_the_deep_stack() {
        assert_eq!(
            inspect_nested_arrays::<64>(TWO_MIB, 8_000_000),
            Err(Unparsable::TooDeep)
        );
    }

    #[test]
    fn inspect_program_reports_a_syntax_error_it_can_t_recover_from() {
        let inspected = inspect_program(
            "x = (;",
            SourceType::cjs(),
            ParseSettings::default(),
            |_, _, _| (),
        );
        assert_eq!(inspected, Err(Unparsable::SyntaxError));
    }

    #[test]
    fn inspect_program_reports_a_parse_past_the_speculation_budget() {
        let source = format!(
            "x={}\"{}\"{};",
            "<T>(a=".repeat(2_000),
            "a".repeat(256 * 1024),
            ")".repeat(2_000)
        );
        assert!(exhausts_the_speculation_budget("index.ts", &source));
        let inspected = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                inspect_program(
                    &source,
                    SourceType::ts(),
                    ParseSettings::default(),
                    |_, _, _| (),
                )
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(inspected, Err(Unparsable::OverSpeculationBudget));
    }

    #[test]
    fn inspect_program_parses_with_the_settings_its_caller_chooses() {
        let complete = |source: &str, settings| {
            inspect_program(source, SourceType::mjs(), settings, |_, complete, _| {
                complete
            })
        };
        let returns = ParseSettings {
            allow_return_outside_function: true,
            ..ParseSettings::default()
        };
        let regular_expressions = ParseSettings {
            parse_regular_expression: true,
            ..ParseSettings::default()
        };
        assert_eq!(complete("return 1;", ParseSettings::default()), Ok(false));
        assert_eq!(complete("return 1;", returns), Ok(true));
        assert_eq!(complete("x = /(/;", ParseSettings::default()), Ok(true));
        assert_eq!(complete("x = /(/;", regular_expressions), Ok(false));
    }

    /// Whether parsing `source`, which is valid, with the floor
    /// [`current_stack_floor`] stopped at it. A parse that didn't must have
    /// read the source whole.
    fn parse_reaches_the_floor(source: &str, source_type: SourceType) -> bool {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, source_type)
            .with_options(ParseOptions {
                stack_floor: current_stack_floor().unwrap(),
                ..ParseOptions::default()
            })
            .parse();
        assert!(
            parsed.stack_exhausted || (!parsed.fatal_error && !parsed.diagnostics.has_errors()),
            "{}: {:?}",
            &source[..source.len().min(40)],
            parsed.diagnostics
        );
        parsed.stack_exhausted
    }

    #[test]
    fn parenthesized_lists_parsed_just_above_the_floor_become_parameters_or_expressions_without_overflowing()
     {
        // The elements of a parenthesized list are parsed once, and turned
        // into arrow parameters at `=>`, or into an expression, by recursing
        // through them without reading a token. At the deepest nesting the
        // parse fits above the floor, that recursion must fit too.
        let (js, ts) = (SourceType::cjs(), SourceType::ts());
        let shapes: [(SourceType, &str, &str, &str, &str, &str); 17] = [
            (js, "x=(", "[", "a", "]", ");"),
            (js, "x=(", "[", "a", "]", "=0);"),
            (js, "x=(", "{a:", "b", "}", ");"),
            (js, "x=(", "{a:", "b", "}", "=0);"),
            (js, "x=(", "[a=", "0", "]", ");"),
            (js, "x=(", "[", "a", "]", ",b);"),
            (js, "x=", "(", "a", ")", "=0;"),
            (js, "x=(", "[", "a", "]", ")=>0;"),
            (js, "x=(", "[", "a", "]", "=0)=>0;"),
            (js, "x=(", "{a:", "b", "}", ")=>0;"),
            (js, "x=(", "[", "a", "]=0", ")=>0;"),
            (js, "x=(", "{a:", "b", "}=0", ")=>0;"),
            (js, "x=(", "[...", "a", "]", ")=>0;"),
            (js, "x=async(", "[", "a", "]", ")=>0;"),
            (js, "x=async(...", "[", "a", "]", ")=>0;"),
            (ts, "x=(", "[", "a", "]", "):T=>0;"),
            (ts, "x=(", "[", "a", "]", ":T)=>0;"),
        ];
        for stack in [2 * 1024 * 1024, DEEP_PARSE_STACK] {
            for (source_type, prefix, open, middle, close, suffix) in shapes {
                let deepest = std::thread::Builder::new()
                    .stack_size(stack)
                    .spawn(move || {
                        let source = |depth: usize| {
                            format!(
                                "{prefix}{}{middle}{}{suffix}",
                                open.repeat(depth),
                                close.repeat(depth)
                            )
                        };
                        let reaches_the_floor =
                            |depth| parse_reaches_the_floor(&source(depth), source_type);
                        let (mut fits, mut too_deep) = (1, 8_000_000);
                        assert!(!reaches_the_floor(fits));
                        assert!(reaches_the_floor(too_deep));
                        while too_deep - fits > 1 {
                            let depth = fits + (too_deep - fits) / 2;
                            if reaches_the_floor(depth) {
                                too_deep = depth;
                            } else {
                                fits = depth;
                            }
                        }
                        fits
                    })
                    .unwrap()
                    .join()
                    .unwrap();
                assert!(deepest >= 100, "{prefix}{open}{close}{suffix}: {deepest}");
            }
        }
    }

    #[test]
    fn pure_comments_and_jsx_names_on_member_chains_of_any_length_parse_without_overflowing() {
        // The parser reads a member chain without recursing, so what runs
        // over the chain afterwards must not recurse once per member either.
        for (filename, source) in [
            (
                "index.js",
                format!("x=/*#__PURE__*/a{};", ".a".repeat(200_000)),
            ),
            (
                "index.jsx",
                format!("x=<a{0}></a{0}>;", ".b".repeat(200_000)),
            ),
        ] {
            let parsed = std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    let allocator = Allocator::default();
                    let source_type = SourceType::from_path(filename).unwrap();
                    let parsed = Parser::new(&allocator, &source, source_type)
                        .with_options(ParseOptions {
                            stack_floor: current_stack_floor().unwrap(),
                            ..ParseOptions::default()
                        })
                        .parse();
                    (
                        parsed.stack_exhausted,
                        parsed.fatal_error,
                        parsed.diagnostics.has_errors(),
                    )
                })
                .unwrap()
                .join()
                .unwrap();
            assert_eq!(parsed, (false, false, false), "{filename}");
        }
    }

    #[test]
    fn lookahead_that_reads_past_the_speculation_budget_stops_the_parse() {
        // Deciding whether `(` starts a function type reads tokens ahead and
        // rewinds only the lexer; no speculative parse follows to check the
        // budget.
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, "type T = (LongTypeName);", SourceType::ts())
            .with_options(ParseOptions {
                speculation_budget: 1,
                ..ParseOptions::default()
            })
            .parse();
        assert!(parsed.speculation_budget_exhausted);
        assert!(parsed.fatal_error);
    }

    /// How long parsing `source`, which is valid, takes on a stack deep
    /// enough for it, with no speculation budget.
    fn time_to_parse(source: String, source_type: SourceType) -> std::time::Duration {
        std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(move || {
                let allocator = Allocator::default();
                let started = std::time::Instant::now();
                let parsed = Parser::new(&allocator, &source, source_type)
                    .with_options(ParseOptions {
                        stack_floor: current_stack_floor().unwrap(),
                        ..ParseOptions::default()
                    })
                    .parse();
                let elapsed = started.elapsed();
                assert!(!parsed.stack_exhausted && !parsed.fatal_error);
                elapsed
            })
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn parentheses_nested_tens_of_thousands_of_levels_deep_parse_in_linear_time() {
        // Each closing parenthesis records where the expression innermost in
        // it starts, and must not walk every parenthesis inside it to find it.
        let depth = 40_000;
        let nested = time_to_parse(
            format!("x={}a{};", "(".repeat(depth), ")".repeat(depth)),
            SourceType::cjs(),
        );
        let flat = time_to_parse("x;".repeat(depth + 1), SourceType::cjs());
        assert!(
            nested < flat * 5 + std::time::Duration::from_millis(200),
            "nested {nested:?}, flat {flat:?}"
        );
    }

    #[test]
    fn async_arrow_heads_parsed_again_after_many_spread_literals_parse_in_linear_time() {
        // Parsing the arguments of an `async(…)` again as parameters forgets
        // what was recorded about the literals inside them, and must not walk
        // what was recorded about every literal before them.
        let literals = 32_768;
        let source = format!(
            "{}{}",
            "[...a,];".repeat(literals),
            "async(a=function(){await})=>0;".repeat(literals / 2)
        );
        let flat = "x;".repeat(source.len() / 2);
        let parsed_again = time_to_parse(source, SourceType::cjs());
        let flat = time_to_parse(flat, SourceType::cjs());
        assert!(
            parsed_again < flat * 5 + std::time::Duration::from_millis(200),
            "parsed again {parsed_again:?}, flat {flat:?}"
        );
    }

    #[test]
    fn exports_of_many_imported_names_resolve_in_linear_time() {
        // Each local export looks its name up among the import entries.
        let names = 20_000;
        let source = format!(
            "import{{{}}}from'x';export{{{}}};",
            "a,".repeat(names),
            "b,".repeat(names)
        );
        let flat = "x;".repeat(source.len() / 2);
        let resolved = time_to_parse(source, SourceType::mjs());
        let flat = time_to_parse(flat, SourceType::mjs());
        assert!(
            resolved < flat * 5 + std::time::Duration::from_millis(200),
            "resolved {resolved:?}, flat {flat:?}"
        );
    }

    #[test]
    fn pure_comments_on_nested_parentheses_apply_in_linear_time() {
        // A pure comment applies to the call inside the parentheses after it,
        // and each level must not walk every parenthesis inside it again, even
        // when a pure comment inside a computed key walks in between.
        let depth = 30_000;
        for source in [
            format!(
                "{}a(){};",
                "/*#__PURE__*/(".repeat(depth),
                ")".repeat(depth)
            ),
            format!(
                "{}a{};",
                "/*#__PURE__*/(".repeat(depth),
                ")[/*#__PURE__*/k()]".repeat(depth)
            ),
        ] {
            let flat = "x;".repeat(source.len() / 2);
            let end = source[source.len() - 40..].to_owned();
            let applied = time_to_parse(source, SourceType::cjs());
            let flat = time_to_parse(flat, SourceType::cjs());
            assert!(
                applied < flat * 5 + std::time::Duration::from_millis(200),
                "{end}: applied {applied:?}, flat {flat:?}"
            );
        }
    }

    #[test]
    fn pure_comments_on_nested_wrappers_mark_the_call_inside_them() {
        struct Calls {
            pure: usize,
        }
        impl<'a> Visit<'a> for Calls {
            fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
                self.pure += usize::from(call.pure);
                walk::walk_call_expression(self, call);
            }
        }
        for (source, source_type, pure_calls, applied_comments) in [
            (
                "x=/*#__PURE__*/(/*#__PURE__*/(/*#__PURE__*/(a())));",
                SourceType::cjs(),
                1,
                3,
            ),
            (
                "x=/*#__PURE__*/(/*#__PURE__*/(a));",
                SourceType::cjs(),
                0,
                0,
            ),
            (
                "x=/*#__PURE__*/(/*#__PURE__*/(a()).b);",
                SourceType::cjs(),
                1,
                2,
            ),
            (
                "x=/*#__PURE__*/<T>/*#__PURE__*/<T>a();",
                SourceType::ts(),
                1,
                2,
            ),
        ] {
            let allocator = Allocator::default();
            let parsed = Parser::new(&allocator, source, source_type).parse();
            assert!(parsed.diagnostics.is_empty(), "{source}");
            let mut calls = Calls { pure: 0 };
            calls.visit_program(&parsed.program);
            let applied = parsed
                .program
                .comments
                .iter()
                .filter(|comment| comment.content == oxc_ast::CommentContent::Pure)
                .count();
            assert_eq!(
                (calls.pure, applied),
                (pure_calls, applied_comments),
                "{source}"
            );
        }
    }

    #[test]
    fn a_top_level_await_parsed_again_replaces_the_statements_it_takes_in() {
        // Found to be a module, `await\nawait\n0;` is one statement. In
        // `await\nawait /x/\nfoo();` the second line was `await / x / foo()`
        // as a script, so the statement parsed again ends inside it, and
        // `foo();` is parsed again too.
        for (source, expected) in [
            (
                "await\nawait\n0;\nexport {};\n",
                &["await\nawait\n0;", "export {};"][..],
            ),
            (
                "await\nawait /x/\nfoo();\nexport {};\n",
                &["await\nawait /x/", "foo();", "export {};"][..],
            ),
            (
                "await\nlet\nx = eval(y)\nexport {};\n",
                &["await\nlet", "x = eval(y)", "export {};"][..],
            ),
            (
                "await / a; x = /;0/ + eval(y);\nexport {};\n",
                &["await / a; x = /;", "0/ + eval(y);", "export {};"][..],
            ),
            (
                "await /a/\neval(y)\nexport {};\n",
                &["await /a/", "eval(y)", "export {};"][..],
            ),
        ] {
            let allocator = Allocator::default();
            let parsed = Parser::new(&allocator, source, SourceType::unambiguous()).parse();
            assert!(parsed.diagnostics.is_empty(), "{source}");
            let statements: Vec<&str> = parsed
                .program
                .body
                .iter()
                .map(|statement| {
                    let span = oxc_span::GetSpan::span(statement);
                    &source[span.start as usize..span.end as usize]
                })
                .collect();
            assert_eq!(statements, expected, "{source}");
        }
    }

    #[test]
    fn a_top_level_await_parsed_again_records_its_dynamic_import_once() {
        let allocator = Allocator::default();
        let source = "await\nimport('x');\nexport {};\n";
        let parsed = Parser::new(&allocator, source, SourceType::unambiguous()).parse();
        assert!(parsed.diagnostics.is_empty());
        assert_eq!(parsed.module_record.dynamic_imports.len(), 1);
    }

    #[test]
    fn top_level_awaits_parsed_again_as_a_module_take_linear_time() {
        // A source whose module syntax is found late parses its statements
        // that start with `await` again, and one parse again can take in the
        // statements after it.
        let awaits = 10_000;
        let source = format!("{}0;\nexport {{}};\n", "await\n".repeat(awaits));
        let flat = "x;".repeat(source.len() / 2);
        let parsed_again = time_to_parse(source, SourceType::unambiguous());
        let flat = time_to_parse(flat, SourceType::unambiguous());
        assert!(
            parsed_again < flat * 5 + std::time::Duration::from_millis(200),
            "parsed again {parsed_again:?}, flat {flat:?}"
        );
    }

    /// Visits `source` with the floor `room` bytes below where the visit
    /// starts, on a stack deep enough to parse it, and returns whether the
    /// visitor stopped at the floor and whether it unwound.
    fn visit_with_floor_below_here(source: String, room: usize) -> (bool, bool) {
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || visit_with_floor(&source, room))
            .unwrap()
            .join()
            .unwrap()
    }

    fn visit_with_floor(source: &str, room: usize) -> (bool, bool) {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();
        assert!(!parsed.stack_exhausted);
        let mut executable = source.as_bytes().to_vec();
        let mut literals = LiteralSpans {
            executable: &mut executable,
            random_literal: false,
            paths: PathLiteralCollector::default(),
            inside_concatenation: false,
            concatenated_literal: None,
            in_built_template: false,
            stack_floor: stack_address().saturating_sub(room),
            depth: 0,
            max_depth: 0,
            scopes: 0,
            parameter_lists: 0,
            block_scopes: 0,
            outer_block_scopes: Vec::new(),
            labels: 0,
            resolution_lookups: 0,
            stopped: false,
            wrapper_run: 0,
            longest_wrapper_run: 0,
            run_continues_into: None,
        };
        let unwound = std::panic::catch_unwind(AssertUnwindSafe(|| {
            literals.visit_program(&parsed.program);
        }))
        .is_err();
        (literals.stopped, unwound)
    }

    #[test]
    fn a_visitor_that_reaches_the_floor_inside_nested_expressions_returns_without_unwinding() {
        // The parser reads a left-deep chain without recursing, so only the
        // visitor goes deep; unwinding from its floor cost a second.
        for source in [
            format!("x=a{};", ".b".repeat(20_000)),
            format!("x=a{};", "/b".repeat(20_000)),
            format!("x={}0{};", "f(".repeat(20_000), ")".repeat(20_000)),
            format!("{}0;{}", "{".repeat(20_000), "}".repeat(20_000)),
        ] {
            let start = source[..40].to_owned();
            assert_eq!(
                visit_with_floor_below_here(source, 64 * 1024),
                (true, false),
                "{start}"
            );
        }
    }

    #[test]
    fn a_visitor_with_room_for_the_whole_source_visits_it_all() {
        let (stopped, unwound) =
            visit_with_floor_below_here(format!("x=a{};", ".b".repeat(200)), 1024 * 1024);
        assert!(!stopped && !unwound);
    }
}
