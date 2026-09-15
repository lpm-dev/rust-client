use oxc_ast::{AstKind, ast::*};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{Semantic, SemanticBuilder, SymbolId};
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct CallFacts {
    pub process: Option<usize>,
    pub shell: Option<usize>,
    pub dynamic_load: Option<usize>,
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

const _: () = assert!((Module::Util as u32 + 1) * (Method::Other as u32 + 1) <= u64::BITS);

#[derive(Clone, Copy)]
struct Origin(u64);

impl Origin {
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

    fn member(self, method: Method) -> Self {
        if method == Method::Namespace {
            return self;
        }
        let mut result = Self(0);
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

fn module(name: &str) -> Option<Module> {
    match name.strip_prefix("node:").unwrap_or(name) {
        "child_process" => Some(Module::Process),
        "execa" => Some(Module::Execa),
        "shelljs" => Some(Module::Shell),
        "module" => Some(Module::Loader),
        "util" => Some(Module::Util),
        _ => None,
    }
}

fn method(name: &str) -> Method {
    match name {
        "exec" => Method::Exec,
        "execSync" => Method::ExecSync,
        "execFile" => Method::ExecFile,
        "execFileSync" => Method::ExecFileSync,
        "spawn" | "execa" | "execaCommand" | "execaNode" | "$" => Method::Spawn,
        "spawnSync" | "execaSync" | "execaCommandSync" => Method::SpawnSync,
        "fork" => Method::Fork,
        "require" => Method::Require,
        "createRequire" => Method::CreateRequire,
        "promisify" => Method::Promisify,
        "default" => Method::Namespace,
        _ => Method::Other,
    }
}

fn origin(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
    depth: usize,
) -> Option<Origin> {
    if depth >= 8 {
        return None;
    }
    match expression.get_inner_expression() {
        Expression::Identifier(identifier) => {
            let reference = semantic
                .scoping()
                .get_reference(identifier.reference_id.get()?);
            let Some(symbol) = reference.symbol_id() else {
                return match identifier.name.as_str() {
                    "module" => Some(Origin::new(Module::Loader, Method::Namespace)),
                    "require" => Some(Origin::new(Module::Loader, Method::Require)),
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
                    let method = if let AstKind::ImportSpecifier(specifier) = kind {
                        method(specifier.imported.name().as_str())
                    } else {
                        Method::Namespace
                    };
                    Some(Origin::new(module(imported.source.value.as_str())?, method))
                }
                AstKind::VariableDeclarator(variable) => {
                    let initial = variable
                        .init
                        .as_ref()
                        .and_then(|init| origin(init, semantic, assignments, depth + 1));
                    let initial = if let BindingPattern::ObjectPattern(pattern) = &variable.id {
                        pattern.properties.iter().find_map(|property| {
                            if matches!(&property.value, BindingPattern::BindingIdentifier(binding) if binding.symbol_id.get() == Some(symbol)) {
                                Some(initial?.member(method(property.key.static_name()?.as_ref())))
                            } else {
                                None
                            }
                        })
                    } else {
                        initial
                    };
                    union(initial, assignments.get(&symbol).copied())
                }
                _ => None,
            }
        }
        Expression::StaticMemberExpression(member) => Some(
            origin(&member.object, semantic, assignments, depth + 1)?
                .member(method(member.property.name.as_str())),
        ),
        Expression::ComputedMemberExpression(member) => {
            let Expression::StringLiteral(property) = member.expression.get_inner_expression()
            else {
                return None;
            };
            Some(
                origin(&member.object, semantic, assignments, depth + 1)?
                    .member(method(property.value.as_str())),
            )
        }
        Expression::CallExpression(call) => {
            if let Expression::Identifier(identifier) = call.callee.get_inner_expression()
                && identifier.name == "require"
                && semantic.is_reference_to_global_variable(identifier)
                && let Some(Argument::StringLiteral(name)) = call.arguments.first()
            {
                return Some(Origin::new(module(name.value.as_str())?, Method::Namespace));
            }
            let callee = origin(&call.callee, semantic, assignments, depth + 1)?;
            if callee.contains(Module::Loader, Method::CreateRequire) {
                return Some(Origin::new(Module::Loader, Method::Require));
            }
            if callee.contains(Module::Util, Method::Promisify) {
                return origin(
                    call.arguments.first()?.as_expression()?,
                    semantic,
                    assignments,
                    depth + 1,
                );
            }
            None
        }
        Expression::SequenceExpression(sequence) => origin(
            sequence.expressions.last()?,
            semantic,
            assignments,
            depth + 1,
        ),
        Expression::ConditionalExpression(conditional) => union(
            origin(&conditional.consequent, semantic, assignments, depth + 1),
            origin(&conditional.alternate, semantic, assignments, depth + 1),
        ),
        Expression::LogicalExpression(logical) => union(
            origin(&logical.left, semantic, assignments, depth + 1),
            origin(&logical.right, semantic, assignments, depth + 1),
        ),
        _ => None,
    }
}

fn shell_option(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    depth: usize,
) -> Option<bool> {
    if depth >= 8 {
        return None;
    }
    match expression.get_inner_expression() {
        Expression::ObjectExpression(options) => {
            options
                .properties
                .iter()
                .rev()
                .find_map(|property| match property {
                    ObjectPropertyKind::ObjectProperty(property)
                        if property.key.static_name().as_deref() == Some("shell") =>
                    {
                        match property.value.get_inner_expression() {
                            Expression::BooleanLiteral(value) => Some(value.value),
                            Expression::StringLiteral(value) => Some(!value.value.is_empty()),
                            _ => Some(true),
                        }
                    }
                    ObjectPropertyKind::SpreadProperty(spread) => {
                        shell_option(&spread.argument, semantic, depth + 1)
                    }
                    _ => None,
                })
        }
        Expression::Identifier(identifier) => {
            let reference = semantic
                .scoping()
                .get_reference(identifier.reference_id.get()?);
            let declaration = semantic
                .scoping()
                .symbol_declaration(reference.symbol_id()?);
            let AstKind::VariableDeclarator(variable) = semantic.nodes().kind(declaration) else {
                return None;
            };
            shell_option(variable.init.as_ref()?, semantic, depth + 1)
        }
        Expression::ConditionalExpression(conditional) => {
            let left = shell_option(&conditional.consequent, semantic, depth + 1);
            let right = shell_option(&conditional.alternate, semantic, depth + 1);
            left.zip(right).map(|(a, b)| a || b).or(left).or(right)
        }
        _ => None,
    }
}

fn has_shell_option(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    call.arguments
        .iter()
        .skip(1)
        .filter_map(Argument::as_expression)
        .any(|argument| shell_option(argument, semantic, 0) == Some(true))
}

fn dynamic_argument(argument: Option<&Expression<'_>>) -> bool {
    argument.is_some_and(|argument| {
        let argument = argument.get_inner_expression();
        !argument.is_literal()
            && !matches!(argument, Expression::TemplateLiteral(template) if template.expressions.is_empty())
    })
}

#[derive(Default)]
struct CallCandidates(bool);

impl<'a> Visit<'a> for CallCandidates {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if !self.0 {
            walk::walk_expression(self, expression);
        }
    }

    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.0 |= matches!(
            identifier.name.as_str(),
            "require"
                | "exec"
                | "execSync"
                | "execFile"
                | "execFileSync"
                | "spawn"
                | "spawnSync"
                | "fork"
        );
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if call.callee.get_inner_expression().is_specific_id("require")
            && let Some(Argument::StringLiteral(name)) = call.arguments.first()
            && call.arguments.len() == 1
        {
            self.0 |= module(name.value.as_str()).is_some();
            return;
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        self.0 |= member.property.name == "require";
        walk::walk_static_member_expression(self, member);
    }

    fn visit_computed_member_expression(&mut self, member: &ComputedMemberExpression<'a>) {
        self.0 |= matches!(member.expression.get_inner_expression(), Expression::StringLiteral(name) if name.value == "require");
        walk::walk_computed_member_expression(self, member);
    }

    fn visit_import_expression(&mut self, import: &ImportExpression<'a>) {
        self.0 |= dynamic_argument(Some(&import.source));
        walk::walk_import_expression(self, import);
    }

    fn visit_import_declaration(&mut self, import: &ImportDeclaration<'a>) {
        self.0 |= module(import.source.value.as_str()).is_some();
    }
}

pub(super) fn analyze(program: &Program<'_>) -> CallFacts {
    let mut candidates = CallCandidates::default();
    candidates.visit_program(program);
    if !candidates.0 {
        return CallFacts::default();
    }
    let built = SemanticBuilder::new().build(program);
    let semantic = &built.semantic;
    let mut assignments = HashMap::new();
    // Union possible assignments without assuming execution order or following control flow.
    for _ in 0..8 {
        let mut changed = false;
        for node in semantic.nodes().iter() {
            let AstKind::AssignmentExpression(assignment) = node.kind() else {
                continue;
            };
            let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left else {
                continue;
            };
            let Some(symbol) = identifier
                .reference_id
                .get()
                .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            else {
                continue;
            };
            if let Some(value) = origin(&assignment.right, semantic, &assignments, 0) {
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
    let mut facts = CallFacts::default();
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ImportExpression(import) if dynamic_argument(Some(&import.source)) => {
                facts.dynamic_load.get_or_insert(import.span.start as usize);
            }
            AstKind::CallExpression(call) => {
                let mut value = origin(&call.callee, semantic, &assignments, 0);
                if value.is_some_and(|value| value.contains(Module::Util, Method::Promisify)) {
                    value = call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .and_then(|argument| origin(argument, semantic, &assignments, 0));
                }
                let global_name = call
                    .callee
                    .get_inner_expression()
                    .get_identifier_reference()
                    .filter(|identifier| semantic.is_reference_to_global_variable(identifier))
                    .map(|identifier| identifier.name.as_str());
                let method = global_name.map_or(Method::Other, method);
                let process = value.is_some_and(|value| {
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
                }) || matches!(
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
                if process {
                    facts.process.get_or_insert(call.span.start as usize);
                    let shell = matches!(method, Method::Exec | Method::ExecSync)
                        || value.is_some_and(|value| {
                            value.contains(Module::Shell, Method::Exec)
                                || value.contains(Module::Process, Method::Exec)
                                || value.contains(Module::Process, Method::ExecSync)
                        })
                        || has_shell_option(call, semantic);
                    if shell {
                        facts.shell.get_or_insert(call.span.start as usize);
                    }
                }
                let loader = global_name == Some("require")
                    || value.is_some_and(|value| value.contains(Module::Loader, Method::Require))
                    || matches!(call.callee.get_inner_expression(), Expression::StaticMemberExpression(member) if member.property.name == "require");
                if loader
                    && dynamic_argument(call.arguments.first().and_then(Argument::as_expression))
                {
                    facts.dynamic_load.get_or_insert(call.span.start as usize);
                }
            }
            _ => {}
        }
    }
    facts
}
