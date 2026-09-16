use oxc_ast::{AstKind, ast::*};
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{Semantic, SemanticBuilder, SymbolId};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct CallFacts {
    pub process: Option<usize>,
    pub credential_exfiltration: Option<super::threats::Leak>,
    pub shell: Option<usize>,
    pub dynamic_load: Option<usize>,
    pub evaluation: Option<usize>,
    pub unresolved_evaluation: Option<usize>,
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
        "execa" => Module::Execa,
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
        "spawnSync" | "execaSync" | "execaCommandSync" => Method::SpawnSync,
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
        Expression::StringLiteral(value) => Some(Cow::Borrowed(value.value.as_str())),
        Expression::TemplateLiteral(value) if value.expressions.is_empty() => Some(Cow::Borrowed(
            value.quasis.first()?.value.cooked.as_ref()?.as_str(),
        )),
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

fn required_module(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> Option<Origin> {
    let Expression::Identifier(identifier) = call.callee.get_inner_expression() else {
        return None;
    };
    if identifier.name != "require" || !semantic.is_reference_to_global_variable(identifier) {
        return None;
    }
    module(static_string(call.arguments.first()?.as_expression()?, 0)?.as_ref())
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
                    let imported_origin = module(imported.source.value.as_str())?;
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
                        .and_then(|init| origin(init, semantic, assignments, depth + 1));
                    let initial = if let BindingPattern::ObjectPattern(pattern) = &variable.id {
                        pattern.properties.iter().find_map(|property| {
                            if matches!(&property.value, BindingPattern::BindingIdentifier(binding) if binding.symbol_id.get() == Some(symbol)) {
                                Some(initial?.member(property.key.static_name()?.as_ref()))
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
                .member(member.property.name.as_str()),
        ),
        Expression::ComputedMemberExpression(member) => {
            let property = static_string(&member.expression, 0)?;
            Some(
                origin(&member.object, semantic, assignments, depth + 1)?.member(property.as_ref()),
            )
        }
        Expression::CallExpression(call) => {
            if let Some(module) = required_module(call, semantic) {
                return Some(module);
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
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    if let Some(receiver) = invocation_receiver(expression) {
        return origin(receiver, semantic, assignments, 0).is_some_and(Origin::evaluates)
            || is_invocation_helper(receiver, semantic, assignments, depth + 1);
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
        && variable
            .init
            .as_ref()
            .is_some_and(|initial| is_invocation_helper(initial, semantic, assignments, depth + 1))
}

fn indirect_evaluation(
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    assignments: &HashMap<SymbolId, Origin>,
) -> bool {
    let Some(receiver) = invocation_receiver(&call.callee) else {
        return false;
    };
    if origin(receiver, semantic, assignments, 0).is_some_and(Origin::evaluates) {
        return true;
    }
    // Borrowed call/apply helpers invoke their supplied receiver, not their original owner.
    call.arguments
        .first()
        .and_then(Argument::as_expression)
        .and_then(|argument| origin(argument, semantic, assignments, 0))
        .is_some_and(Origin::evaluates)
        && is_invocation_helper(receiver, semantic, assignments, 0)
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
        !argument.is_literal() && !is_static_string(argument, 0)
    })
}

fn has_local_eval_method(
    object: &Expression<'_>,
    semantic: &Semantic<'_>,
    mutated: &HashSet<SymbolId>,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match object.get_inner_expression() {
        Expression::ObjectExpression(object) => object
            .properties
            .iter()
            .rev()
            .find_map(|property| match property {
                ObjectPropertyKind::SpreadProperty(_) => Some(false),
                ObjectPropertyKind::ObjectProperty(property)
                    if property.key.static_name().as_deref() == Some("eval") =>
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
            .unwrap_or(false),
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
            variable
                .init
                .as_ref()
                .is_some_and(|value| has_local_eval_method(value, semantic, mutated, depth + 1))
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
            class.body.body.iter().any(|element| {
                matches!(element,
                ClassElement::MethodDefinition(method)
                    if !method.r#static && method.kind == MethodDefinitionKind::Method
                        && method.decorators.is_empty()
                        && method.key.static_name().as_deref() == Some("eval"))
            })
        }
        _ => false,
    }
}

fn unresolved_eval_call(
    callee: &Expression<'_>,
    semantic: &Semantic<'_>,
    mutated: &HashSet<SymbolId>,
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
    !has_local_eval_method(object, semantic, mutated, 0)
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
            self.found |= module(name.as_ref()).is_some();
            return;
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_static_member_expression(&mut self, member: &StaticMemberExpression<'a>) {
        self.found |= matches!(member.property.name.as_str(), "require" | "eval");
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
        self.found |= dynamic_argument(Some(&import.source));
        walk::walk_import_expression(self, import);
    }

    fn visit_import_declaration(&mut self, import: &ImportDeclaration<'a>) {
        self.found |= module(import.source.value.as_str()).is_some();
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
    let built = SemanticBuilder::new().build(program);
    let semantic = &built.semantic;
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
            AstKind::NewExpression(expression) => {
                if origin(&expression.callee, semantic, &assignments, 0)
                    .is_some_and(|value| value.0 & Origin::FUNCTION.0 != 0)
                {
                    facts
                        .evaluation
                        .get_or_insert(expression.span.start as usize);
                }
            }
            AstKind::CallExpression(call) => {
                let mut value = origin(&call.callee, semantic, &assignments, 0);
                if value.is_some_and(Origin::evaluates)
                    || indirect_evaluation(call, semantic, &assignments)
                {
                    facts.evaluation.get_or_insert(call.span.start as usize);
                } else if unresolved_eval_call(&call.callee, semantic, &mutated_receivers) {
                    facts
                        .unresolved_evaluation
                        .get_or_insert(call.span.start as usize);
                }
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
    if complete_input {
        facts.credential_exfiltration = super::threats::analyze(semantic);
    }
    facts
}
