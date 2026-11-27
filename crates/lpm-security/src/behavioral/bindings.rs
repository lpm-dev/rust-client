use oxc_ast::{AstKind, ast::*};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{Semantic, SemanticBuilder, SymbolId};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct CallFacts {
    pub process: Option<usize>,
    pub credential_exfiltration: Option<super::threats::Leak>,
    pub encrypted_execution: Option<usize>,
    pub downloaded_execution: Option<usize>,
    pub destructive_filesystem: Option<usize>,
    pub shell: Option<usize>,
    pub dynamic_load: Option<usize>,
    /// The code runs a file it can't name: a `fork` or a `Worker` starts a
    /// script from a path the code computes, a `Worker` runs code, or the
    /// `require` loader is handed on as a value.
    pub computed_script: Option<usize>,
    pub evaluation: Option<usize>,
    pub unresolved_evaluation: Option<usize>,
    /// Every call or construction `evaluation` and `unresolved_evaluation` found.
    pub evaluation_calls: usize,
    /// The threat rules ran out of the steps a file of this size is given,
    /// so they may have missed a flow.
    pub over_budget: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Module {
    Process,
    Execa,
    Shell,
    Loader,
    Util,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Namespace,
    Exec,
    ExecSync,
    ExecFile,
    ExecFileSync,
    Spawn,
    SpawnSync,
    Fork,
    Require,
    CreateRequire,
    Promisify,
    Other,
}

const MODULE_BITS: u32 = (Module::Util as u32 + 1) * (Method::Other as u32 + 1);
const _: () = assert!(MODULE_BITS + 4 <= u64::BITS);

#[derive(Clone, Copy)]
struct Origin(u64);

impl Origin {
    const EVAL: Self = Self(1 << MODULE_BITS);
    const FUNCTION: Self = Self(1 << (MODULE_BITS + 1));
    const GLOBAL: Self = Self(1 << (MODULE_BITS + 2));
    const VM: Self = Self(1 << (MODULE_BITS + 3));

    fn new(module: Module, method: Method) -> Self {
        Self(1 << (module as u32 * (Method::Other as u32 + 1) + method as u32))
    }

    fn contains(self, module: Module, method: Method) -> bool {
        self.0 & Self::new(module, method).0 != 0
    }

    fn includes_module(self, module: Module) -> bool {
        self.0
            & (((1 << (Method::Other as u32 + 1)) - 1)
                << (module as u32 * (Method::Other as u32 + 1)))
            != 0
    }

    fn evaluates(self) -> bool {
        self.0 & (Self::EVAL.0 | Self::FUNCTION.0) != 0
    }

    fn member(self, name: &str) -> Self {
        let method = method(name);
        if method == Method::Namespace {
            return Self(self.0 & (((1 << MODULE_BITS) - 1) | Self::VM.0));
        }
        let mut result = Self(0);
        if self.0 & Self::GLOBAL.0 != 0 {
            result.0 |= match name {
                "eval" => Self::EVAL.0,
                "Function" => Self::FUNCTION.0,
                _ => 0,
            };
        }
        if self.0 & Self::VM.0 != 0 {
            result.0 |= match name {
                "runInContext" | "runInNewContext" | "runInThisContext" | "compileFunction" => {
                    Self::EVAL.0
                }
                "Script" | "SourceTextModule" => Self::FUNCTION.0,
                _ => 0,
            };
        }
        for module in [
            Module::Process,
            Module::Execa,
            Module::Shell,
            Module::Loader,
            Module::Util,
        ] {
            if self.includes_module(module) {
                result.0 |= Self::new(module, method).0;
            }
        }
        result
    }
}

fn union(a: Option<Origin>, b: Option<Origin>) -> Option<Origin> {
    match (a, b) {
        (Some(a), Some(b)) => Some(Origin(a.0 | b.0)),
        (a, b) => a.or(b),
    }
}

fn module(name: &str) -> Option<Origin> {
    let module = match name.strip_prefix("node:").unwrap_or(name) {
        "child_process" => Module::Process,
        // cross-spawn is called, or its `spawn` and `sync` are, as execa is.
        "execa" | "cross-spawn" => Module::Execa,
        "shelljs" => Module::Shell,
        "module" => Module::Loader,
        "util" => Module::Util,
        "vm" => return Some(Origin::VM),
        _ => return None,
    };
    Some(Origin::new(module, Method::Namespace))
}

fn method(name: &str) -> Method {
    match name {
        "exec" => Method::Exec,
        "execSync" => Method::ExecSync,
        "execFile" => Method::ExecFile,
        "execFileSync" => Method::ExecFileSync,
        "spawn" | "execa" | "execaCommand" | "execaNode" | "$" => Method::Spawn,
        "spawnSync" | "execaSync" | "execaCommandSync" | "sync" => Method::SpawnSync,
        "fork" => Method::Fork,
        "require" => Method::Require,
        "createRequire" => Method::CreateRequire,
        "promisify" => Method::Promisify,
        "default" => Method::Namespace,
        _ => Method::Other,
    }
}

fn static_string<'s>(expression: &'s Expression<'_>, depth: usize) -> Option<Cow<'s, str>> {
    if depth >= 8 {
        return None;
    }
    match expression.get_inner_expression() {
        Expression::StringLiteral(value) => Some(Cow::Borrowed(value.value.as_str()?)),
        Expression::TemplateLiteral(value) if value.expressions.is_empty() => {
            Some(Cow::Borrowed(value.quasis.first()?.value.cooked?.as_str()?))
        }
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            let left = static_string(&binary.left, depth + 1)?;
            let right = static_string(&binary.right, depth + 1)?;
            // Only short built-in module names need reconstruction for binding lookup.
            if left.len() + right.len() > 32 {
                return None;
            }
            let mut name = String::with_capacity(left.len() + right.len());
            name.push_str(&left);
            name.push_str(&right);
            Some(Cow::Owned(name))
        }
        _ => None,
    }
}

fn is_static_string(expression: &Expression<'_>, depth: usize) -> bool {
    if depth >= 8 {
        return false;
    }
    match expression.get_inner_expression() {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            is_static_string(&binary.left, depth + 1) && is_static_string(&binary.right, depth + 1)
        }
        _ => false,
    }
}

/// Answers the analysis reuses within one file. Several questions follow
/// a binding to its declaration and read the whole object or pattern
/// there, and a file can ask them of the same declaration once per call:
/// quadratic in a file that repeats one call, and worse when objects
/// spread each other.
#[derive(Default)]
struct Memo {
    /// [`shell_option`] by expression address and depth.
    shell: HashMap<(usize, usize), Option<bool>>,
    /// [`has_local_eval_method`]'s scan of an object literal or class
    /// body, by its address.
    local_eval: HashMap<usize, bool>,
    /// For each binding a declarator destructures from an object, the
    /// property name [`origin`] reads: the first property of the
    /// declarator's own pattern that binds it and has a static name.
    destructured: HashMap<SymbolId, String>,
    /// Set once the assignment rounds settle: from then on an expression's
    /// [`origin`] at a depth never changes, and a conditional or logical
    /// expression that branches at every level asks for each node up to
    /// 2⁸ times.
    settled: bool,
    origins: std::cell::RefCell<HashMap<(usize, usize), Option<Origin>>>,
}

impl Memo {
    fn new(semantic: &Semantic<'_>) -> Self {
        let mut destructured = HashMap::new();
        for node in semantic.nodes().iter() {
            let AstKind::VariableDeclarator(variable) = node.kind() else {
                continue;
            };
            let BindingPattern::ObjectPattern(pattern) = &variable.id else {
                continue;
            };
            for property in &pattern.properties {
                let BindingPattern::BindingIdentifier(binding) = &property.value else {
                    continue;
                };
                let Some(symbol) = binding.symbol_id.get() else {
                    continue;
                };
                if let Some(name) = property.key.static_name()
                    && let Some(name) = name.as_str()
                    && semantic.scoping().symbol_declaration(symbol) == node.id()
                {
                    destructured
                        .entry(symbol)
                        .or_insert_with(|| name.to_owned());
                }
            }
        }
        Self {
            destructured,
            ..Self::default()
        }
    }
}

/// The module a call loads by name: the global `require(name)`, or
/// `process.getBuiltinModule(name)`, Node's loader of its own modules.
fn required_module(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> Option<Origin> {
    let global = |expression: &Expression<'_>, name: &str| {
        expression
            .get_identifier_reference()
            .is_some_and(|identifier| {
                identifier.name == name && semantic.is_reference_to_global_variable(identifier)
            })
    };
    let loads = match call.callee.get_inner_expression() {
        callee @ Expression::Identifier(_) => global(callee, "require"),
        Expression::StaticMemberExpression(member) => {
            member.property.name == "getBuiltinModule"
                && global(member.object.get_inner_expression(), "process")
        }
        _ => false,
    };
    if !loads {
        return None;
    }
    module(static_string(call.arguments.first()?.as_expression()?, 0)?.as_ref())
}

fn origin(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
    memo: &Memo,
    depth: usize,
) -> Option<Origin> {
    if depth >= 8 {
        return None;
    }
    let expression = expression.get_inner_expression();
    if !memo.settled {
        return origin_of(expression, semantic, assignments, memo, depth);
    }
    let key = (std::ptr::from_ref(expression).addr(), depth);
    if let Some(&known) = memo.origins.borrow().get(&key) {
        return known;
    }
    let result = origin_of(expression, semantic, assignments, memo, depth);
    memo.origins.borrow_mut().insert(key, result);
    result
}

fn origin_of(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
    memo: &Memo,
    depth: usize,
) -> Option<Origin> {
    match expression {
        Expression::Identifier(identifier) => {
            let reference = semantic
                .scoping()
                .get_reference(identifier.reference_id.get()?);
            let Some(symbol) = reference.symbol_id() else {
                return match identifier.name.as_str() {
                    "module" => Some(Origin::new(Module::Loader, Method::Namespace)),
                    "require" => Some(Origin::new(Module::Loader, Method::Require)),
                    "eval" => Some(Origin::EVAL),
                    "Function" => Some(Origin::FUNCTION),
                    "globalThis" | "global" | "window" | "self" => Some(Origin::GLOBAL),
                    _ => None,
                };
            };
            let declaration = semantic.scoping().symbol_declaration(symbol);
            let kind = semantic.nodes().kind(declaration);
            match kind {
                AstKind::ImportSpecifier(_)
                | AstKind::ImportDefaultSpecifier(_)
                | AstKind::ImportNamespaceSpecifier(_) => {
                    let imported =
                        semantic
                            .nodes()
                            .ancestor_kinds(declaration)
                            .find_map(|kind| {
                                if let AstKind::ImportDeclaration(imported) = kind {
                                    Some(imported)
                                } else {
                                    None
                                }
                            })?;
                    let imported_origin = module(imported.source.value.as_str()?)?;
                    if let AstKind::ImportSpecifier(specifier) = kind {
                        Some(imported_origin.member(specifier.imported.name().as_str()))
                    } else {
                        Some(imported_origin)
                    }
                }
                AstKind::VariableDeclarator(variable) => {
                    let initial = variable
                        .init
                        .as_ref()
                        .and_then(|init| origin(init, semantic, assignments, memo, depth + 1));
                    let initial = if let BindingPattern::ObjectPattern(_) = &variable.id {
                        initial
                            .zip(memo.destructured.get(&symbol))
                            .map(|(initial, name)| initial.member(name))
                    } else {
                        initial
                    };
                    union(initial, assignments.get(&symbol).copied())
                }
                _ => None,
            }
        }
        Expression::StaticMemberExpression(member) => Some(
            origin(&member.object, semantic, assignments, memo, depth + 1)?
                .member(member.property.name.as_str()),
        ),
        Expression::ComputedMemberExpression(member) => {
            let property = static_string(&member.expression, 0)?;
            Some(
                origin(&member.object, semantic, assignments, memo, depth + 1)?
                    .member(property.as_ref()),
            )
        }
        Expression::CallExpression(call) => {
            if let Some(module) = required_module(call, semantic) {
                return Some(module);
            }
            let callee = origin(&call.callee, semantic, assignments, memo, depth + 1)?;
            if callee.contains(Module::Loader, Method::CreateRequire) {
                return Some(Origin::new(Module::Loader, Method::Require));
            }
            if callee.contains(Module::Util, Method::Promisify) {
                return origin(
                    call.arguments.first()?.as_expression()?,
                    semantic,
                    assignments,
                    memo,
                    depth + 1,
                );
            }
            None
        }
        Expression::AwaitExpression(awaited) => {
            origin(&awaited.argument, semantic, assignments, memo, depth + 1)
        }
        Expression::ImportExpression(import) => module(static_string(&import.source, 0)?.as_ref()),
        Expression::SequenceExpression(sequence) => origin(
            sequence.expressions.last()?,
            semantic,
            assignments,
            memo,
            depth + 1,
        ),
        Expression::ConditionalExpression(conditional) => union(
            origin(
                &conditional.consequent,
                semantic,
                assignments,
                memo,
                depth + 1,
            ),
            origin(
                &conditional.alternate,
                semantic,
                assignments,
                memo,
                depth + 1,
            ),
        ),
        Expression::LogicalExpression(logical) => union(
            origin(&logical.left, semantic, assignments, memo, depth + 1),
            origin(&logical.right, semantic, assignments, memo, depth + 1),
        ),
        _ => None,
    }
}

fn invocation_receiver<'s, 'a>(expression: &'s Expression<'a>) -> Option<&'s Expression<'a>> {
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member)
            if matches!(member.property.name.as_str(), "call" | "apply") =>
        {
            Some(&member.object)
        }
        Expression::ComputedMemberExpression(member)
            if matches!(
                static_string(&member.expression, 0).as_deref(),
                Some("call" | "apply")
            ) =>
        {
            Some(&member.object)
        }
        _ => None,
    }
}

fn is_invocation_helper(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
    memo: &Memo,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    if let Some(receiver) = invocation_receiver(expression) {
        return origin(receiver, semantic, assignments, memo, 0).is_some_and(Origin::evaluates)
            || is_invocation_helper(receiver, semantic, assignments, memo, depth + 1);
    }
    let Expression::Identifier(identifier) = expression.get_inner_expression() else {
        return false;
    };
    let Some(symbol) = identifier
        .reference_id
        .get()
        .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
    else {
        return false;
    };
    let AstKind::VariableDeclarator(variable) = semantic
        .nodes()
        .kind(semantic.scoping().symbol_declaration(symbol))
    else {
        return false;
    };
    matches!(&variable.id, BindingPattern::BindingIdentifier(_))
        && variable.init.as_ref().is_some_and(|initial| {
            is_invocation_helper(initial, semantic, assignments, memo, depth + 1)
        })
}

fn indirect_evaluation(
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
    memo: &Memo,
) -> bool {
    let Some(receiver) = invocation_receiver(&call.callee) else {
        return false;
    };
    if origin(receiver, semantic, assignments, memo, 0).is_some_and(Origin::evaluates) {
        return true;
    }
    // Borrowed call/apply helpers invoke their supplied receiver, not their original owner.
    call.arguments
        .first()
        .and_then(Argument::as_expression)
        .and_then(|argument| origin(argument, semantic, assignments, memo, 0))
        .is_some_and(Origin::evaluates)
        && is_invocation_helper(receiver, semantic, assignments, memo, 0)
}

fn shell_option(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    memo: &mut Memo,
    depth: usize,
) -> Option<bool> {
    if depth >= 8 {
        return None;
    }
    let expression = expression.get_inner_expression();
    let key = (std::ptr::from_ref(expression).addr(), depth);
    if let Some(&known) = memo.shell.get(&key) {
        return known;
    }
    let result = match expression {
        Expression::ObjectExpression(options) => {
            options
                .properties
                .iter()
                .rev()
                .find_map(|property| match property {
                    ObjectPropertyKind::ObjectProperty(property)
                        if property
                            .key
                            .static_name()
                            .is_some_and(|name| name.as_js_str() == "shell") =>
                    {
                        match property.value.get_inner_expression() {
                            Expression::BooleanLiteral(value) => Some(value.value),
                            Expression::StringLiteral(value) => Some(!value.value.is_empty()),
                            _ => Some(true),
                        }
                    }
                    ObjectPropertyKind::SpreadProperty(spread) => {
                        shell_option(&spread.argument, semantic, memo, depth + 1)
                    }
                    _ => None,
                })
        }
        Expression::Identifier(identifier) => (|| {
            let reference = semantic
                .scoping()
                .get_reference(identifier.reference_id.get()?);
            let declaration = semantic
                .scoping()
                .symbol_declaration(reference.symbol_id()?);
            let AstKind::VariableDeclarator(variable) = semantic.nodes().kind(declaration) else {
                return None;
            };
            shell_option(variable.init.as_ref()?, semantic, memo, depth + 1)
        })(),
        Expression::ConditionalExpression(conditional) => {
            let left = shell_option(&conditional.consequent, semantic, memo, depth + 1);
            let right = shell_option(&conditional.alternate, semantic, memo, depth + 1);
            left.zip(right).map(|(a, b)| a || b).or(left).or(right)
        }
        _ => None,
    };
    memo.shell.insert(key, result);
    result
}

fn has_shell_option(call: &CallExpression<'_>, semantic: &Semantic<'_>, memo: &mut Memo) -> bool {
    call.arguments
        .iter()
        .skip(1)
        .filter_map(Argument::as_expression)
        .any(|argument| shell_option(argument, semantic, memo, 0) == Some(true))
}

/// Aliases (`const W = Worker`) a binding is followed through to what it
/// names. Real code aliases a module or a constructor once or twice. Past
/// this, a binding is taken to be what it's asked about, so neither a long
/// chain nor a cycle (`var a = b, b = a`) hides one.
const MAX_ALIAS_DEPTH: usize = 16;

/// The symbol an identifier reads and the node that declares it.
fn declaration_of(
    identifier: &IdentifierReference<'_>,
    semantic: &Semantic<'_>,
) -> Option<(SymbolId, oxc_semantic::NodeId)> {
    let symbol = identifier
        .reference_id
        .get()
        .and_then(|id| semantic.scoping().get_reference(id).symbol_id())?;
    Some((symbol, semantic.scoping().symbol_declaration(symbol)))
}

/// Whether `pattern` binds `symbol` itself, with or without a default.
fn binds(pattern: &BindingPattern<'_>, symbol: SymbolId) -> bool {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => identifier.symbol_id.get() == Some(symbol),
        BindingPattern::AssignmentPattern(assignment) => binds(&assignment.left, symbol),
        _ => false,
    }
}

/// Whether a destructuring takes `symbol` from the property `name`:
/// `{ Worker }`, `{ Worker: W }`, `{ Worker = Fallback }`.
fn destructures(pattern: &ObjectPattern<'_>, name: &str, symbol: SymbolId) -> bool {
    pattern.properties.iter().any(|property| {
        property.key.static_name().is_some_and(|key| key == name) && binds(&property.value, symbol)
    })
}

/// Whether the import declaration around `specifier` imports a module
/// `is_name` accepts.
fn imports_from(
    specifier: oxc_semantic::NodeId,
    is_name: fn(&str) -> bool,
    semantic: &Semantic<'_>,
) -> bool {
    matches!(
        semantic.nodes().kind(semantic.nodes().parent_id(specifier)),
        AstKind::ImportDeclaration(import) if import.source.value.as_str().is_some_and(is_name)
    )
}

/// Whether `callee` is Node's `worker_threads` `Worker`, which runs a script
/// file: a `.Worker` member of that module, a binding taken from it
/// (`import { Worker as W }`, `const { Worker } = require(…)`, `const W =
/// threads.Worker`, a later `W = threads.Worker`), or a class extending it.
/// A browser's global `Worker` loads a URL, not a package file, and a local
/// class named `Worker` is neither. A `Worker` whose binding can't be
/// followed, such as one a dynamic import's callback destructures, is
/// Node's when the file names `worker_threads` (`mentions_worker_threads`).
fn is_worker_constructor(
    callee: &Expression<'_>,
    semantic: &Semantic<'_>,
    mentions_worker_threads: bool,
    depth: usize,
) -> bool {
    if depth >= MAX_ALIAS_DEPTH {
        return true;
    }
    let follow = |expression: &Expression<'_>| {
        is_worker_constructor(expression, semantic, mentions_worker_threads, depth + 1)
    };
    match callee.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            member.property.name == "Worker"
                && (is_module(&member.object, is_worker_threads, semantic, depth + 1)
                    || mentions_worker_threads)
        }
        Expression::ComputedMemberExpression(member) => {
            static_string(&member.expression, 0).is_some_and(|name| name == "Worker")
                && (is_module(&member.object, is_worker_threads, semantic, depth + 1)
                    || mentions_worker_threads)
        }
        Expression::Identifier(identifier) => {
            let named_worker = identifier.name == "Worker";
            let Some((symbol, declaration)) = declaration_of(identifier, semantic) else {
                return named_worker && mentions_worker_threads;
            };
            let declared = match semantic.nodes().kind(declaration) {
                AstKind::ImportSpecifier(specifier) => {
                    specifier.imported.name() == "Worker"
                        && imports_from(declaration, is_worker_threads, semantic)
                }
                AstKind::Class(class) => class
                    .heritage
                    .as_ref()
                    .is_some_and(|heritage| follow(&heritage.expression)),
                AstKind::Function(_) => false,
                AstKind::VariableDeclarator(variable) => match (&variable.id, &variable.init) {
                    (BindingPattern::ObjectPattern(pattern), Some(init)) => {
                        destructures(pattern, "Worker", symbol)
                            && (is_module(init, is_worker_threads, semantic, depth + 1)
                                || mentions_worker_threads)
                    }
                    (BindingPattern::BindingIdentifier(_), Some(init)) => follow(init),
                    _ => false,
                },
                _ => named_worker && mentions_worker_threads,
            };
            declared || assigned_values(symbol, semantic).any(follow)
        }
        _ => false,
    }
}

/// The values assigned to `symbol` after its declaration (`W = value`).
fn assigned_values<'s>(
    symbol: SymbolId,
    semantic: &'s Semantic<'_>,
) -> impl Iterator<Item = &'s Expression<'s>> {
    semantic
        .scoping()
        .get_resolved_reference_ids(symbol)
        .iter()
        .map(|&id| semantic.scoping().get_reference(id))
        .filter(|reference| reference.is_write())
        .filter_map(|reference| {
            semantic
                .nodes()
                .ancestor_kinds(reference.node_id())
                .take(3)
                .find_map(|kind| match kind {
                    AstKind::AssignmentExpression(assignment) => Some(&assignment.right),
                    _ => None,
                })
        })
}

/// Whether `expression` is a module `is_name` accepts: `require` of it, or a
/// binding of that, of an alias of it, or of `import * as m` or a default
/// import of it.
fn is_module(
    expression: &Expression<'_>,
    is_name: fn(&str) -> bool,
    semantic: &Semantic<'_>,
    depth: usize,
) -> bool {
    if depth >= MAX_ALIAS_DEPTH {
        return true;
    }
    let names_module = |argument: Option<&Expression<'_>>| {
        argument
            .and_then(|argument| static_string(argument, 0))
            .is_some_and(|name| is_name(name.as_ref()))
    };
    match expression.get_inner_expression() {
        Expression::CallExpression(call) => {
            let loader = match call.callee.get_inner_expression() {
                Expression::Identifier(identifier) => identifier.name == "require",
                // `process.getBuiltinModule(name)`, Node's loader of its own modules.
                Expression::StaticMemberExpression(member) => {
                    member.property.name == "getBuiltinModule"
                        && member
                            .object
                            .get_inner_expression()
                            .is_specific_id("process")
                }
                _ => false,
            };
            loader && names_module(call.arguments.first().and_then(Argument::as_expression))
        }
        Expression::AwaitExpression(awaited) => {
            is_module(&awaited.argument, is_name, semantic, depth + 1)
        }
        Expression::ImportExpression(import) => names_module(Some(&import.source)),
        Expression::Identifier(identifier) => {
            let Some((_, declaration)) = declaration_of(identifier, semantic) else {
                return false;
            };
            match semantic.nodes().kind(declaration) {
                AstKind::VariableDeclarator(variable) => {
                    matches!(variable.id, BindingPattern::BindingIdentifier(_))
                        && variable
                            .init
                            .as_ref()
                            .is_some_and(|init| is_module(init, is_name, semantic, depth + 1))
                }
                AstKind::ImportNamespaceSpecifier(_) | AstKind::ImportDefaultSpecifier(_) => {
                    imports_from(declaration, is_name, semantic)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether a module name is Node's `worker_threads`, whose `Worker` starts a
/// script.
fn is_worker_threads(name: &str) -> bool {
    name.strip_prefix("node:").unwrap_or(name) == "worker_threads"
}

/// Whether `expression` is one of Node's module objects: the global `module`,
/// `process.mainModule` or `require.main`.
fn is_module_instance(expression: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let global = |expression: &Expression<'_>, name: &str| {
        expression
            .get_inner_expression()
            .get_identifier_reference()
            .is_some_and(|identifier| {
                identifier.name == name && semantic.is_reference_to_global_variable(identifier)
            })
    };
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member) => match member.property.name.as_str() {
            "mainModule" => global(&member.object, "process"),
            "main" => global(&member.object, "require"),
            _ => false,
        },
        expression => global(expression, "module"),
    }
}

/// Whether a module name is Node's `module`, whose `Module._load` loads a
/// module by name.
fn is_node_module(name: &str) -> bool {
    name.strip_prefix("node:").unwrap_or(name) == "module"
}

/// Whether `object` is Node's `Module` class: the `module` builtin or its
/// `Module` export, the CommonJS `module.constructor`, or a binding of one
/// of those.
fn is_module_class(object: &Expression<'_>, semantic: &Semantic<'_>, depth: usize) -> bool {
    if depth >= MAX_ALIAS_DEPTH {
        return true;
    }
    match object.get_inner_expression() {
        Expression::CallExpression(_) => is_module(object, is_node_module, semantic, depth + 1),
        Expression::StaticMemberExpression(member) => match member.property.name.as_str() {
            "constructor" => is_module_instance(&member.object, semantic),
            "Module" => is_module(&member.object, is_node_module, semantic, depth + 1),
            _ => false,
        },
        Expression::Identifier(identifier) => {
            let Some((symbol, declaration)) = declaration_of(identifier, semantic) else {
                return false;
            };
            match semantic.nodes().kind(declaration) {
                AstKind::ImportSpecifier(specifier) => {
                    specifier.imported.name() == "Module"
                        && imports_from(declaration, is_node_module, semantic)
                }
                AstKind::ImportNamespaceSpecifier(_) | AstKind::ImportDefaultSpecifier(_) => {
                    imports_from(declaration, is_node_module, semantic)
                }
                AstKind::VariableDeclarator(variable) => match (&variable.id, &variable.init) {
                    (BindingPattern::ObjectPattern(pattern), Some(init)) => {
                        destructures(pattern, "Module", symbol)
                            && is_module(init, is_node_module, semantic, depth + 1)
                    }
                    (BindingPattern::BindingIdentifier(_), Some(init)) => {
                        is_module_class(init, semantic, depth + 1)
                    }
                    _ => false,
                },
                _ => false,
            }
        }
        _ => false,
    }
}

/// The module name of a load that doesn't call `require` directly:
/// `require.call(this, name)`, `require.apply(this, [name])`, the same of a
/// `require` method (`Module.prototype.require.call(module, name)`),
/// `require.extensions[ext](module, name)`, `Module._load(name)`,
/// `Module.register(name)`, which loads hooks, and `module._compile(source)`.
fn indirect_load_argument<'c>(
    call: &'c CallExpression<'_>,
    semantic: &Semantic<'_>,
) -> Option<&'c Expression<'c>> {
    let global_require = |expression: &Expression<'_>| {
        expression
            .get_inner_expression()
            .get_identifier_reference()
            .is_some_and(|identifier| {
                identifier.name == "require" && semantic.is_reference_to_global_variable(identifier)
            })
    };
    let extensions = |expression: &Expression<'_>| match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            (member.property.name == "extensions" && global_require(&member.object))
                || (member.property.name == "_extensions"
                    && is_module_class(&member.object, semantic, 0))
        }
        _ => false,
    };
    if let Expression::ComputedMemberExpression(member) = call.callee.get_inner_expression()
        && extensions(&member.object)
    {
        return call.arguments.get(1).and_then(Argument::as_expression);
    }
    let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
        return None;
    };
    if extensions(&member.object) {
        return call.arguments.get(1).and_then(Argument::as_expression);
    }
    let requires = || {
        global_require(&member.object)
            || matches!(
                member.object.get_inner_expression(),
                Expression::StaticMemberExpression(method) if method.property.name == "require"
            )
    };
    match member.property.name.as_str() {
        "call" if requires() => call.arguments.get(1).and_then(Argument::as_expression),
        "apply" if requires() => match call.arguments.get(1).and_then(Argument::as_expression) {
            Some(Expression::ArrayExpression(array)) => array
                .elements
                .first()
                .and_then(|element| element.as_expression()),
            other => other,
        },
        "_load" | "register" if is_module_class(&member.object, semantic, 0) => {
            call.arguments.first().and_then(Argument::as_expression)
        }
        // Compiles the source it is given as a module.
        "_compile" if is_module_instance(&member.object, semantic) => {
            call.arguments.first().and_then(Argument::as_expression)
        }
        _ => None,
    }
}

/// Whether a launch's script, its first argument, is computed: spread into
/// the call, or neither a literal nor a path [`is_built_path`] accepts and
/// [`super::syntax::is_static_path`] folds, which the file's path literals
/// then name. A computed script could be any file.
fn computed_script(arguments: &[Argument<'_>], semantic: &Semantic<'_>) -> bool {
    match arguments.first() {
        None => false,
        Some(Argument::SpreadElement(_)) => true,
        Some(argument) => argument
            .as_expression()
            .is_none_or(|argument| computed_script_path(argument, semantic)),
    }
}

fn computed_script_path(argument: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let argument = argument.get_inner_expression();
    !(argument.is_literal()
        || is_static_string(argument, 0)
        || (is_built_path(argument, semantic, 0) && super::syntax::is_static_path(argument)))
}

/// Whether `expression` builds a path from strings and the module's own
/// location alone: string literals, `+` and templates of them, the global
/// `__dirname` and `__filename` (not a binding of that name), `import.meta`'s
/// `dirname`, `filename` and `url`, Node's path functions (`join`, `resolve`,
/// `normalize`, `dirname` of the `path` module, `require.resolve`,
/// `fileURLToPath` of the `url` module) and the global `URL` applied to such
/// parts.
fn is_built_path(expression: &Expression<'_>, semantic: &Semantic<'_>, depth: usize) -> bool {
    if depth >= MAX_ALIAS_DEPTH {
        return false;
    }
    let expression = expression.get_inner_expression();
    if expression.is_literal() || is_static_string(expression, 0) {
        return true;
    }
    let built = |part: &Expression<'_>| is_built_path(part, semantic, depth + 1);
    let all_built = |arguments: &oxc_allocator::Vec<'_, Argument<'_>>| {
        arguments
            .iter()
            .all(|argument| argument.as_expression().is_some_and(built))
    };
    match expression {
        Expression::Identifier(identifier) => {
            matches!(identifier.name.as_str(), "__dirname" | "__filename")
                && semantic.is_reference_to_global_variable(identifier)
        }
        Expression::StaticMemberExpression(member) => {
            matches!(
                member.object.get_inner_expression(),
                Expression::ImportMeta(_)
            ) && matches!(
                member.property.name.as_str(),
                "dirname" | "filename" | "url"
            )
        }
        Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
            built(&binary.left) && built(&binary.right)
        }
        Expression::TemplateLiteral(template) => template.expressions.iter().all(built),
        Expression::CallExpression(call) => {
            is_path_function(&call.callee, semantic, depth + 1) && all_built(&call.arguments)
        }
        Expression::NewExpression(new) => {
            new.callee
                .get_inner_expression()
                .get_identifier_reference()
                .is_some_and(|identifier| {
                    identifier.name == "URL" && semantic.is_reference_to_global_variable(identifier)
                })
                && (1..=2).contains(&new.arguments.len())
                && all_built(&new.arguments)
        }
        _ => false,
    }
}

/// Node's functions that build a path from their arguments: `join`,
/// `resolve`, `normalize` and `dirname` of the `path` module, the global
/// `require.resolve`, and `fileURLToPath` of the `url` module, by their
/// bindings, so a local function of the same name isn't one.
fn is_path_function(callee: &Expression<'_>, semantic: &Semantic<'_>, depth: usize) -> bool {
    const PATH_FUNCTIONS: &[&str] = &["join", "resolve", "normalize", "dirname"];
    match callee.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            let name = member.property.name.as_str();
            (PATH_FUNCTIONS.contains(&name) && is_path_module(&member.object, semantic, depth))
                || (name == "resolve"
                    && member
                        .object
                        .get_inner_expression()
                        .get_identifier_reference()
                        .is_some_and(|identifier| {
                            identifier.name == "require"
                                && semantic.is_reference_to_global_variable(identifier)
                        }))
                || (name == "fileURLToPath"
                    && is_module(&member.object, is_url_module, semantic, depth))
        }
        Expression::Identifier(identifier) => {
            let Some((symbol, declaration)) = declaration_of(identifier, semantic) else {
                return false;
            };
            match semantic.nodes().kind(declaration) {
                AstKind::ImportSpecifier(specifier) => {
                    let imported = specifier.imported.name();
                    (PATH_FUNCTIONS.contains(&imported.as_str())
                        && imports_from(declaration, is_path_module_name, semantic))
                        || (imported == "fileURLToPath"
                            && imports_from(declaration, is_url_module, semantic))
                }
                AstKind::VariableDeclarator(variable) => match (&variable.id, &variable.init) {
                    (BindingPattern::ObjectPattern(pattern), Some(init)) => {
                        (PATH_FUNCTIONS
                            .iter()
                            .any(|function| destructures(pattern, function, symbol))
                            && is_path_module(init, semantic, depth))
                            || (destructures(pattern, "fileURLToPath", symbol)
                                && is_module(init, is_url_module, semantic, depth))
                    }
                    _ => false,
                },
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether `expression` is Node's `path` module, or its `posix` or `win32`.
fn is_path_module(expression: &Expression<'_>, semantic: &Semantic<'_>, depth: usize) -> bool {
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member)
            if matches!(member.property.name.as_str(), "posix" | "win32") =>
        {
            is_path_module(&member.object, semantic, depth + 1)
        }
        other => is_module(other, is_path_module_name, semantic, depth),
    }
}

fn is_path_module_name(name: &str) -> bool {
    matches!(
        name.strip_prefix("node:").unwrap_or(name),
        "path" | "path/posix" | "path/win32"
    )
}

fn is_url_module(name: &str) -> bool {
    name.strip_prefix("node:").unwrap_or(name) == "url"
}

/// Whether a script path is fixed by the module's own location
/// (`__dirname`, `__filename`, `import.meta`, `require.resolve`), so where the
/// launch runs from doesn't move it.
fn is_anchored_path(expression: &Expression<'_>, semantic: &Semantic<'_>, depth: usize) -> bool {
    if depth >= MAX_ALIAS_DEPTH {
        return false;
    }
    let anchored = |part: &Expression<'_>| is_anchored_path(part, semantic, depth + 1);
    match expression.get_inner_expression() {
        Expression::Identifier(identifier) => {
            matches!(identifier.name.as_str(), "__dirname" | "__filename")
                && semantic.is_reference_to_global_variable(identifier)
        }
        Expression::StaticMemberExpression(member) => {
            matches!(
                member.object.get_inner_expression(),
                Expression::ImportMeta(_)
            )
        }
        Expression::BinaryExpression(binary) => anchored(&binary.left),
        Expression::TemplateLiteral(template) => template.expressions.first().is_some_and(anchored),
        Expression::CallExpression(call) => {
            matches!(
                call.callee.get_inner_expression(),
                Expression::StaticMemberExpression(member)
                    if member.property.name == "resolve"
                        && member.object.get_inner_expression().is_specific_id("require")
            ) || call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .is_some_and(anchored)
        }
        Expression::NewExpression(new) => new
            .arguments
            .get(1)
            .and_then(Argument::as_expression)
            .is_some_and(anchored),
        _ => false,
    }
}

/// Whether a `fork`'s working directory moves a script that isn't
/// [`is_anchored_path`] somewhere unknown: a computed `cwd`, or options the
/// call doesn't spell out.
fn launch_directory_unknown(arguments: &[Argument<'_>], semantic: &Semantic<'_>) -> bool {
    let Some(script) = arguments.first().and_then(Argument::as_expression) else {
        return false;
    };
    if is_anchored_path(script, semantic, 0) {
        return false;
    }
    arguments[1..].iter().any(|argument| match argument {
        Argument::SpreadElement(_) => true,
        Argument::ArrayExpression(_) => false,
        Argument::ObjectExpression(options) => {
            options.properties.iter().any(|property| match property {
                ObjectPropertyKind::SpreadProperty(_) => true,
                ObjectPropertyKind::ObjectProperty(property) => {
                    property.key.static_name().is_some_and(|name| name == "cwd")
                        && computed_script_path(&property.value, semantic)
                }
            })
        }
        _ => true,
    })
}

/// The options of a launch, as Node reads its arguments: a `fork`'s are the
/// third argument, or the second when that isn't a list of arguments; a
/// `Worker`'s are the second.
fn launch_options<'a>(arguments: &'a [Argument<'a>], forks: bool) -> Option<&'a Argument<'a>> {
    match (forks, arguments) {
        (true, [_, _, options, ..]) => Some(options),
        (true, [_, Argument::ArrayExpression(_)]) => None,
        (_, [_, options, ..]) => Some(options),
        _ => None,
    }
}

/// Whether a launch's options preload code from somewhere unknown: an
/// `execArgv`, whose `--require`, `--import` and `--loader` load what they
/// name, that isn't spelled out, or, for a process, an environment whose
/// `NODE_OPTIONS` isn't, or options that aren't written out. The parent's own
/// `process.execArgv` and `process.env` are how the package was started, not
/// code it chose.
fn launch_preloads_unknown_code(
    arguments: &[Argument<'_>],
    forks: bool,
    semantic: &Semantic<'_>,
) -> bool {
    let Some(options) = launch_options(arguments, forks) else {
        return false;
    };
    let options = match options {
        Argument::SpreadElement(_) => return true,
        _ => match options
            .as_expression()
            .map(Expression::get_inner_expression)
        {
            Some(Expression::ObjectExpression(options)) => options,
            Some(Expression::Identifier(identifier)) => match written_value(identifier, semantic) {
                Some(Expression::ObjectExpression(options)) => options,
                Some(Expression::ArrayExpression(_)) if forks && arguments.len() == 2 => {
                    return false;
                }
                _ => return true,
            },
            Some(Expression::NullLiteral(_)) => return false,
            Some(expression) if expression.is_undefined() => return false,
            _ => return true,
        },
    };
    options.properties.iter().any(|property| match property {
        ObjectPropertyKind::SpreadProperty(_) => true,
        ObjectPropertyKind::ObjectProperty(property) => match property.key.static_name() {
            Some(name) if name == "execArgv" => !spelled_out_exec_argv(&property.value),
            Some(name) if name == "env" => forks && !spelled_out_environment(&property.value),
            Some(_) => false,
            None => true,
        },
    })
}

/// The value a `const`, `let` or `var` binding of `identifier` starts with.
fn written_value<'s>(
    identifier: &IdentifierReference<'_>,
    semantic: &'s Semantic<'_>,
) -> Option<&'s Expression<'s>> {
    let (_, declaration) = declaration_of(identifier, semantic)?;
    match semantic.nodes().kind(declaration) {
        AstKind::VariableDeclarator(variable)
            if matches!(variable.id, BindingPattern::BindingIdentifier(_)) =>
        {
            variable.init.as_ref().map(Expression::get_inner_expression)
        }
        _ => None,
    }
}

/// Whether `expression` is the parent's own `process.execArgv`, or a filter
/// or slice of it.
fn is_parent_exec_argv(expression: &Expression<'_>) -> bool {
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            member.property.name == "execArgv"
                && member
                    .object
                    .get_inner_expression()
                    .is_specific_id("process")
        }
        Expression::CallExpression(call) => match call.callee.get_inner_expression() {
            Expression::StaticMemberExpression(method) => {
                matches!(method.property.name.as_str(), "filter" | "slice")
                    && is_parent_exec_argv(&method.object)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether an `execArgv` lists only literal flags, or the parent's own.
fn spelled_out_exec_argv(value: &Expression<'_>) -> bool {
    match value.get_inner_expression() {
        Expression::ArrayExpression(array) => array.elements.iter().all(|element| match element {
            ArrayExpressionElement::SpreadElement(spread) => is_parent_exec_argv(&spread.argument),
            element => element
                .as_expression()
                .is_some_and(|element| static_string(element, 0).is_some()),
        }),
        value => is_parent_exec_argv(value),
    }
}

/// Whether a process environment's `NODE_OPTIONS` is spelled out: it is the
/// parent's own `process.env`, or an object of it and literal values.
fn spelled_out_environment(value: &Expression<'_>) -> bool {
    let parent = |expression: &Expression<'_>| match expression.get_inner_expression() {
        Expression::StaticMemberExpression(member) => {
            member.property.name == "env"
                && member
                    .object
                    .get_inner_expression()
                    .is_specific_id("process")
        }
        _ => false,
    };
    match value.get_inner_expression() {
        Expression::ObjectExpression(environment) => {
            environment
                .properties
                .iter()
                .all(|property| match property {
                    ObjectPropertyKind::SpreadProperty(spread) => parent(&spread.argument),
                    ObjectPropertyKind::ObjectProperty(property) => {
                        match property.key.static_name() {
                            Some(name) if name == "NODE_OPTIONS" => {
                                static_string(&property.value, 0).is_some()
                            }
                            Some(_) => true,
                            None => false,
                        }
                    }
                })
        }
        value => parent(value),
    }
}

/// Whether a `worker_threads` `Worker` runs its first argument as code, not
/// as a file: options with `eval` set, or options the call doesn't spell out.
fn worker_runs_code(arguments: &[Argument<'_>]) -> bool {
    match arguments.get(1) {
        None => false,
        Some(Argument::ObjectExpression(options)) => {
            options.properties.iter().any(|property| match property {
                ObjectPropertyKind::SpreadProperty(_) => true,
                ObjectPropertyKind::ObjectProperty(property) => {
                    property
                        .key
                        .static_name()
                        .is_some_and(|name| name == "eval")
                        && !matches!(
                            property.value.get_inner_expression(),
                            Expression::BooleanLiteral(literal) if !literal.value
                        )
                }
            })
        }
        Some(_) => true,
    }
}

/// Whether a reference to the global `require` passes the loader on as a
/// value (`require.bind(null)`, `Reflect.apply(require, …)`, `const load =
/// require`, `list.map(require)`), so what it loads isn't known. A call of
/// it, `require.call` and `.apply` (read where they're called), its
/// properties and `typeof require` aren't.
fn passes_require_on(
    node: oxc_semantic::NodeId,
    span: oxc_span::Span,
    semantic: &Semantic<'_>,
) -> bool {
    use oxc_span::GetSpan as _;
    match semantic.nodes().parent_kind(node) {
        AstKind::CallExpression(call) => call.callee.span() != span,
        AstKind::StaticMemberExpression(member) => {
            member.object.span() == span && member.property.name == "bind"
        }
        AstKind::ComputedMemberExpression(_) => false,
        AstKind::UnaryExpression(unary) => unary.operator.as_str() != "typeof",
        AstKind::BinaryExpression(binary) => !binary.operator.is_equality(),
        _ => true,
    }
}

/// Whether `fork.call(this, script, …)` or `fork.apply(this, [script, …])`
/// starts a script whose path is computed, as a direct `fork` would.
fn forwarded_fork_script_computed(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
        return false;
    };
    let forwards_fork = match member.object.get_inner_expression() {
        Expression::StaticMemberExpression(inner) => inner.property.name == "fork",
        Expression::Identifier(identifier) => identifier.name == "fork",
        _ => false,
    };
    if !forwards_fork {
        return false;
    }
    match member.property.name.as_str() {
        "call" => computed_script(call.arguments.get(1..).unwrap_or_default(), semantic),
        "apply" => match call.arguments.get(1) {
            None => false,
            Some(Argument::ArrayExpression(array)) => match array.elements.first() {
                None => false,
                Some(element) => element
                    .as_expression()
                    .is_none_or(|script| computed_script_path(script, semantic)),
            },
            Some(_) => true,
        },
        _ => false,
    }
}

/// Whether a loader's argument is a spread, whose module isn't known.
fn spread_first(arguments: &[Argument<'_>]) -> bool {
    matches!(arguments.first(), Some(Argument::SpreadElement(_)))
}

fn dynamic_argument(argument: Option<&Expression<'_>>) -> bool {
    argument.is_some_and(|argument| {
        let argument = argument.get_inner_expression();
        !argument.is_literal() && !is_static_string(argument, 0)
    })
}

fn has_local_eval_method(
    object: &Expression<'_>,
    semantic: &Semantic<'_>,
    mutated: &HashSet<SymbolId>,
    memo: &mut Memo,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match object.get_inner_expression() {
        Expression::ObjectExpression(object) => *memo
            .local_eval
            .entry(std::ptr::from_ref(object).addr())
            .or_insert_with(|| object_has_eval_method(object)),
        Expression::Identifier(identifier) => {
            let Some(symbol) = identifier
                .reference_id
                .get()
                .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            else {
                return false;
            };
            if mutated.contains(&symbol) {
                return false;
            }
            let declaration = semantic.scoping().symbol_declaration(symbol);
            let AstKind::VariableDeclarator(variable) = semantic.nodes().kind(declaration) else {
                return false;
            };
            variable.init.as_ref().is_some_and(|value| {
                has_local_eval_method(value, semantic, mutated, memo, depth + 1)
            })
        }
        Expression::NewExpression(instance) => {
            let Some(identifier) = instance
                .callee
                .get_inner_expression()
                .get_identifier_reference()
            else {
                return false;
            };
            let Some(symbol) = identifier
                .reference_id
                .get()
                .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            else {
                return false;
            };
            let declaration = semantic.scoping().symbol_declaration(symbol);
            if mutated.contains(&symbol) {
                return false;
            }
            let AstKind::Class(class) = semantic.nodes().kind(declaration) else {
                return false;
            };
            *memo
                .local_eval
                .entry(std::ptr::from_ref(class).addr())
                .or_insert_with(|| {
                    class.body.body.iter().any(|element| {
                        matches!(element,
                        ClassElement::MethodDefinition(method)
                            if !method.r#static && method.kind == MethodDefinitionKind::Method
                                && method.decorators.is_empty()
                                && method.key.static_name().is_some_and(|name| name.as_js_str() == "eval"))
                    })
                })
        }
        _ => false,
    }
}

/// Whether an object literal's own `eval` is a plain function: the last
/// `eval` property, unless a spread follows it.
fn object_has_eval_method(object: &ObjectExpression<'_>) -> bool {
    object
        .properties
        .iter()
        .rev()
        .find_map(|property| match property {
            ObjectPropertyKind::SpreadProperty(_) => Some(false),
            ObjectPropertyKind::ObjectProperty(property)
                if property
                    .key
                    .static_name()
                    .is_some_and(|name| name.as_js_str() == "eval") =>
            {
                Some(
                    property.kind == PropertyKind::Init
                        && matches!(
                            property.value.get_inner_expression(),
                            Expression::FunctionExpression(_)
                                | Expression::ArrowFunctionExpression(_)
                        ),
                )
            }
            _ => None,
        })
        .unwrap_or(false)
}

fn unresolved_eval_call(
    callee: &Expression<'_>,
    semantic: &Semantic<'_>,
    mutated: &HashSet<SymbolId>,
    memo: &mut Memo,
) -> bool {
    let object = match callee.get_inner_expression() {
        Expression::StaticMemberExpression(member) if member.property.name == "eval" => {
            &member.object
        }
        Expression::ComputedMemberExpression(member)
            if static_string(&member.expression, 0).as_deref() == Some("eval") =>
        {
            &member.object
        }
        _ => return false,
    };
    !has_local_eval_method(object, semantic, mutated, memo, 0)
}

pub(super) fn mark_mutated_receiver(
    object: &Expression<'_>,
    semantic: &Semantic<'_>,
    mutated: &mut HashSet<SymbolId>,
    depth: usize,
) {
    if depth >= 8 {
        return;
    }
    match object.get_inner_expression() {
        Expression::Identifier(identifier) => {
            let Some(symbol) = identifier
                .reference_id
                .get()
                .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            else {
                return;
            };
            if !mutated.insert(symbol) {
                return;
            }
            let declaration = semantic.scoping().symbol_declaration(symbol);
            if let AstKind::VariableDeclarator(variable) = semantic.nodes().kind(declaration)
                && let Some(initial) = &variable.init
            {
                mark_mutated_receiver(initial, semantic, mutated, depth + 1);
            }
        }
        Expression::StaticMemberExpression(member) => {
            mark_mutated_receiver(&member.object, semantic, mutated, depth + 1)
        }
        Expression::ComputedMemberExpression(member) => {
            mark_mutated_receiver(&member.object, semantic, mutated, depth + 1)
        }
        _ => {}
    }
}

struct CallCandidates {
    found: bool,
    include_threats: bool,
}

impl<'a> Visit<'a> for CallCandidates {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if !self.found {
            walk::walk_expression(self, expression);
        }
    }

    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.found |= matches!(
            identifier.name.as_str(),
            "require"
                | "exec"
                | "execSync"
                | "execFile"
                | "execFileSync"
                | "spawn"
                | "spawnSync"
                | "fork"
                | "Worker"
                | "eval"
                | "Function"
                | "globalThis"
                | "global"
                | "window"
                | "self"
        );
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.found |= self.include_threats && super::threats::is_candidate(call);
        if call.callee.get_inner_expression().is_specific_id("require")
            && call.arguments.len() == 1
            && let Some(name) = call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .and_then(|argument| static_string(argument, 0))
        {
            self.found |= module(name.as_ref()).is_some()
                || is_worker_threads(name.as_ref())
                || (self.include_threats
                    && matches!(
                        name.strip_prefix("node:").unwrap_or(&name),
                        "fs" | "fs/promises" | "crypto" | "http" | "https"
                    ));
            return;
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        self.found |= matches!(
            member.property.name.as_str(),
            "require"
                | "eval"
                | "Worker"
                | "_load"
                | "getBuiltinModule"
                | "extensions"
                | "_extensions"
                | "_compile"
        );
        walk::walk_static_member_expression(self, member);
    }

    fn visit_computed_member_expression(&mut self, member: &ComputedMemberExpression<'a>) {
        self.found |= matches!(
            static_string(&member.expression, 0).as_deref(),
            Some("require" | "eval")
        );
        walk::walk_computed_member_expression(self, member);
    }

    fn visit_import_expression(&mut self, import: &ImportExpression<'a>) {
        self.found |= dynamic_argument(Some(&import.source))
            || static_string(&import.source, 0).is_some_and(|name| module(name.as_ref()).is_some());
        walk::walk_import_expression(self, import);
    }

    fn visit_import_declaration(&mut self, import: &ImportDeclaration<'a>) {
        self.found |= import.source.value.as_str().and_then(module).is_some()
            || import.source.value.as_str().is_some_and(is_worker_threads)
            || (self.include_threats
                && matches!(
                    import
                        .source
                        .value
                        .as_str()
                        .map(|source| source.strip_prefix("node:").unwrap_or(source)),
                    Some("fs" | "fs/promises" | "crypto" | "http" | "https")
                ));
    }
}

pub(super) fn analyze(program: &Program<'_>, complete_input: bool) -> CallFacts {
    let mut candidates = CallCandidates {
        found: false,
        include_threats: complete_input,
    };
    candidates.visit_program(program);
    if !candidates.found {
        return CallFacts::default();
    }
    // The analysis walks every node, and oxc builds the node store only on request.
    let built = SemanticBuilder::new().with_build_nodes(true).build(program);
    let semantic = &built.semantic;
    let mut memo = Memo::new(semantic);
    let mut assignments = HashMap::new();
    let mut mutated_receivers = HashSet::new();
    // Union possible assignments without assuming execution order or following control flow.
    for round in 0..8 {
        let mut changed = false;
        for node in semantic.nodes().iter() {
            let AstKind::AssignmentExpression(assignment) = node.kind() else {
                continue;
            };
            let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left else {
                if round == 0 {
                    match &assignment.left {
                        AssignmentTarget::StaticMemberExpression(member)
                            if matches!(member.property.name.as_str(), "eval" | "prototype") =>
                        {
                            mark_mutated_receiver(
                                &member.object,
                                semantic,
                                &mut mutated_receivers,
                                0,
                            );
                        }
                        AssignmentTarget::ComputedMemberExpression(member) if !matches!(static_string(&member.expression, 0).as_deref(), Some(name) if name != "eval" && name != "prototype") =>
                        {
                            mark_mutated_receiver(
                                &member.object,
                                semantic,
                                &mut mutated_receivers,
                                0,
                            );
                        }
                        _ => {}
                    }
                }
                continue;
            };
            let Some(symbol) = identifier
                .reference_id
                .get()
                .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            else {
                continue;
            };
            if round == 0 {
                mutated_receivers.insert(symbol);
            }
            if let Some(value) = origin(&assignment.right, semantic, &assignments, &memo, 0) {
                let previous = assignments.entry(symbol).or_insert(Origin(0));
                let combined = previous.0 | value.0;
                changed |= previous.0 != combined;
                previous.0 = combined;
            }
        }
        if !changed {
            break;
        }
    }
    memo.settled = true;
    let mut facts = CallFacts::default();
    let mentions_worker_threads =
        memchr::memmem::find(semantic.source_text().as_bytes(), b"worker_threads").is_some();
    for node in semantic.nodes().iter() {
        match node.kind() {
            // The loader handed on as a value can load anything, so no test file
            // is known to stay unrun. That isn't a computed `require` argument,
            // the dynamic require tag's meaning: a UMD wrapper hands its
            // factory the loader to call with constant names.
            AstKind::IdentifierReference(identifier)
                if identifier.name == "require"
                    && semantic.is_reference_to_global_variable(identifier)
                    && passes_require_on(node.id(), identifier.span, semantic) =>
            {
                facts
                    .computed_script
                    .get_or_insert(identifier.span.start as usize);
            }
            AstKind::ImportExpression(import) if dynamic_argument(Some(&import.source)) => {
                facts.dynamic_load.get_or_insert(import.span.start as usize);
            }
            AstKind::NewExpression(expression) => {
                let worker =
                    is_worker_constructor(&expression.callee, semantic, mentions_worker_threads, 0);
                if worker
                    && (computed_script(&expression.arguments, semantic)
                        || worker_runs_code(&expression.arguments)
                        || launch_preloads_unknown_code(&expression.arguments, false, semantic))
                {
                    facts
                        .computed_script
                        .get_or_insert(expression.span.start as usize);
                }
                if origin(&expression.callee, semantic, &assignments, &memo, 0)
                    .is_some_and(|value| value.0 & Origin::FUNCTION.0 != 0)
                {
                    facts
                        .evaluation
                        .get_or_insert(expression.span.start as usize);
                    facts.evaluation_calls += 1;
                }
            }
            AstKind::CallExpression(call) => {
                let mut value = origin(&call.callee, semantic, &assignments, &memo, 0);
                if value.is_some_and(Origin::evaluates)
                    || indirect_evaluation(call, semantic, &assignments, &memo)
                {
                    facts.evaluation.get_or_insert(call.span.start as usize);
                    facts.evaluation_calls += 1;
                } else if unresolved_eval_call(
                    &call.callee,
                    semantic,
                    &mutated_receivers,
                    &mut memo,
                ) {
                    facts
                        .unresolved_evaluation
                        .get_or_insert(call.span.start as usize);
                    facts.evaluation_calls += 1;
                }
                if value.is_some_and(|value| value.contains(Module::Util, Method::Promisify)) {
                    value = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|argument| origin(argument, semantic, &assignments, &memo, 0));
                }
                let global_name = call
                    .callee
                    .get_inner_expression()
                    .get_identifier_reference()
                    .filter(|identifier| semantic.is_reference_to_global_variable(identifier))
                    .map(|identifier| identifier.name.as_str());
                let method = global_name.map_or(Method::Other, method);
                let process = required_module(call, semantic)
                    .is_some_and(|value| value.includes_module(Module::Process))
                    || value.is_some_and(|value| {
                        value.includes_module(Module::Process)
                            || [
                                Method::Namespace,
                                Method::Spawn,
                                Method::SpawnSync,
                                Method::Fork,
                            ]
                            .iter()
                            .any(|method| value.contains(Module::Execa, *method))
                            || value.contains(Module::Shell, Method::Exec)
                    })
                    || matches!(
                        global_name,
                        Some(
                            "exec"
                                | "execSync"
                                | "execFile"
                                | "execFileSync"
                                | "spawn"
                                | "spawnSync"
                                | "fork"
                        )
                    );
                let forks = global_name == Some("fork")
                    || value.is_some_and(|value| {
                        value.contains(Module::Process, Method::Fork)
                            || value.contains(Module::Execa, Method::Fork)
                    });
                if forks
                    && (computed_script(&call.arguments, semantic)
                        || launch_directory_unknown(&call.arguments, semantic)
                        || launch_preloads_unknown_code(&call.arguments, true, semantic))
                {
                    facts
                        .computed_script
                        .get_or_insert(call.span.start as usize);
                }
                if process {
                    facts.process.get_or_insert(call.span.start as usize);
                    let shell = matches!(method, Method::Exec | Method::ExecSync)
                        || value.is_some_and(|value| {
                            value.contains(Module::Shell, Method::Exec)
                                || value.contains(Module::Process, Method::Exec)
                                || value.contains(Module::Process, Method::ExecSync)
                        })
                        || has_shell_option(call, semantic, &mut memo);
                    if shell {
                        facts.shell.get_or_insert(call.span.start as usize);
                    }
                }
                let loader = global_name == Some("require")
                    || value.is_some_and(|value| value.contains(Module::Loader, Method::Require))
                    || matches!(call.callee.get_inner_expression(), Expression::StaticMemberExpression(member) if member.property.name == "require");
                if loader
                    && (spread_first(&call.arguments)
                        || dynamic_argument(
                            call.arguments.first().and_then(Argument::as_expression),
                        ))
                {
                    facts.dynamic_load.get_or_insert(call.span.start as usize);
                }
                if forwarded_fork_script_computed(call, semantic) {
                    facts
                        .computed_script
                        .get_or_insert(call.span.start as usize);
                }
                if dynamic_argument(indirect_load_argument(call, semantic)) {
                    facts.dynamic_load.get_or_insert(call.span.start as usize);
                }
            }
            _ => {}
        }
    }
    if complete_input {
        super::threats::analyze(semantic, &mut facts);
    }
    facts
}
