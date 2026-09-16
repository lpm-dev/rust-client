use super::{Flow, MAX_DEPTH, MAX_STEPS, callee, member, name};
use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;
use std::collections::HashMap;

const DECRYPTED: u8 = 1;
const DOWNLOADED: u8 = 2;

pub(super) struct Api<'a> {
    pub module: &'a str,
    pub method: Option<&'a str>,
}

impl<'s, 'a> Flow<'s, 'a> {
    pub(super) fn api<'e>(&self, expression: &'e Expression<'a>, depth: usize) -> Option<Api<'e>>
    where
        'a: 'e,
    {
        if depth >= 12 {
            return None;
        }
        let next = depth + 1;
        match callee(expression) {
            Expression::Identifier(identifier) => {
                let symbol = self.symbol(identifier)?;
                if self.written.contains(&symbol) {
                    return None;
                }
                let declaration = self.semantic.scoping().symbol_declaration(symbol);
                let kind = self.semantic.nodes().kind(declaration);
                match kind {
                    AstKind::ImportSpecifier(_)
                    | AstKind::ImportDefaultSpecifier(_)
                    | AstKind::ImportNamespaceSpecifier(_) => {
                        let import =
                            self.semantic
                                .nodes()
                                .ancestor_kinds(declaration)
                                .find_map(|kind| {
                                    if let AstKind::ImportDeclaration(import) = kind {
                                        Some(import)
                                    } else {
                                        None
                                    }
                                })?;
                        Some(Api {
                            module: import
                                .source
                                .value
                                .as_str()
                                .strip_prefix("node:")
                                .unwrap_or(import.source.value.as_str()),
                            method: if let AstKind::ImportSpecifier(specifier) = kind {
                                Some(specifier.imported.name().as_str())
                            } else {
                                None
                            },
                        })
                    }
                    AstKind::VariableDeclarator(variable) => {
                        let mut api = self.api(variable.init.as_ref()?, next)?;
                        if let BindingPattern::ObjectPattern(pattern) = &variable.id {
                            api.method = Some(pattern.properties.iter().find_map(|property| {
                                if matches!(&property.value, BindingPattern::BindingIdentifier(binding) if binding.symbol_id.get() == Some(symbol)) {
                                    match &property.key {
                                        PropertyKey::StaticIdentifier(key) => Some(key.name.as_str()),
                                        PropertyKey::StringLiteral(key) => Some(key.value.as_str()),
                                        _ => None,
                                    }
                                } else { None }
                            })?);
                        } else if !matches!(&variable.id, BindingPattern::BindingIdentifier(_)) {
                            return None;
                        }
                        Some(api)
                    }
                    _ => None,
                }
            }
            Expression::CallExpression(call) if self.global(&call.callee, "require") => {
                let Expression::StringLiteral(module) = call
                    .arguments
                    .first()?
                    .as_expression()?
                    .get_inner_expression()
                else {
                    return None;
                };
                Some(Api {
                    module: module
                        .value
                        .as_str()
                        .strip_prefix("node:")
                        .unwrap_or(module.value.as_str()),
                    method: None,
                })
            }
            expression => {
                let (object, property) = member(expression)?;
                let mut api = self.api(object, next)?;
                if api.method.is_some() {
                    return None;
                }
                if property == "promises" && api.module == "fs" {
                    api.module = "fs/promises";
                } else if property != "default" {
                    api.method = Some(property);
                }
                Some(api)
            }
        }
    }

    pub(super) fn http_request(&self, expression: &Expression<'a>, depth: usize) -> bool {
        if depth >= 12 {
            return false;
        }
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .is_some_and(|initial| self.http_request(initial, depth + 1)),
            Expression::CallExpression(call) => self.api(&call.callee, 0).is_some_and(|api| {
                matches!(api.module, "http" | "https") && api.method == Some("request")
            }),
            _ => false,
        }
    }

    fn credential_path(&mut self, expression: &Expression<'a>, depth: usize) -> bool {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return false;
        }
        self.steps -= 1;
        match expression.get_inner_expression() {
            Expression::StringLiteral(value) => {
                let path = value.value.as_str();
                path == ".env"
                    || path.ends_with("/.env")
                    || path == ".npmrc"
                    || path.ends_with("/.npmrc")
                    || path.ends_with(".aws/credentials")
                    || path.ends_with(".ssh/id_rsa")
                    || path.ends_with(".ssh/id_ed25519")
                    || path.ends_with(".kube/config")
                    || path.ends_with(".git-credentials")
            }
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .is_some_and(|initial| self.credential_path(initial, depth + 1)),
            Expression::CallExpression(call)
                if self.api(&call.callee, 0).is_some_and(|api| {
                    api.module == "path" && matches!(api.method, Some("join" | "resolve"))
                }) =>
            {
                let args: Vec<_> = call
                    .arguments
                    .iter()
                    .filter_map(Argument::as_expression)
                    .collect();
                if let Some(last) = args.last()
                    && self.credential_path(last, depth + 1)
                {
                    return true;
                }
                let literals: Vec<_> = args
                    .iter()
                    .rev()
                    .take(2)
                    .map(|arg| {
                        if let Expression::StringLiteral(s) = arg.get_inner_expression() {
                            Some(s.value.as_str())
                        } else {
                            None
                        }
                    })
                    .collect();
                matches!(
                    literals.as_slice(),
                    [Some("credentials"), Some(".aws")]
                        | [Some("id_rsa" | "id_ed25519"), Some(".ssh")]
                        | [Some("config"), Some(".kube")]
                )
            }
            _ => false,
        }
    }

    pub(super) fn credential_read(&mut self, call: &CallExpression<'a>, depth: usize) -> bool {
        self.api(&call.callee, 0)
            .is_some_and(|api| api.module == "fs" && api.method == Some("readFileSync"))
            && call
                .arguments
                .first()
                .and_then(Argument::as_expression)
                .is_some_and(|path| self.credential_path(path, depth))
    }

    fn fetch(&self, expression: &Expression<'a>) -> bool {
        self.global(expression, "fetch")
            || member(expression).is_some_and(|(object, property)| {
                property == "fetch"
                    && (self.global(object, "globalThis") || self.global(object, "window"))
            })
    }

    fn response(&self, expression: &Expression<'a>, depth: usize) -> bool {
        if depth >= MAX_DEPTH {
            return false;
        }
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .is_some_and(|initial| self.response(initial, depth + 1)),
            Expression::AwaitExpression(value) => self.response(&value.argument, depth + 1),
            Expression::CallExpression(call) => self.fetch(&call.callee),
            _ => false,
        }
    }

    fn decipher(&self, expression: &Expression<'a>, depth: usize) -> bool {
        if depth >= MAX_DEPTH {
            return false;
        }
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .is_some_and(|initial| self.decipher(initial, depth + 1)),
            Expression::CallExpression(call) => self.api(&call.callee, 0).is_some_and(|api| {
                api.module == "crypto"
                    && matches!(api.method, Some("createDecipheriv" | "createDecipher"))
            }),
            _ => false,
        }
    }

    fn artifact(&mut self, expression: &Expression<'a>, depth: usize) -> u8 {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return 0;
        }
        self.steps -= 1;
        let next = depth + 1;
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .map_or(0, |initial| self.artifact(initial, next)),
            Expression::AwaitExpression(value) => self.artifact(&value.argument, next),
            Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
                self.artifact(&binary.left, next) | self.artifact(&binary.right, next)
            }
            Expression::ArrayExpression(array) => {
                let mut value = 0;
                for expression in array
                    .elements
                    .iter()
                    .filter_map(ArrayExpressionElement::as_expression)
                {
                    value |= self.artifact(expression, next);
                    if self.steps == 0 {
                        break;
                    }
                }
                value
            }
            Expression::CallExpression(call) => {
                if let Some(target) = self.target(&call.callee, 0) {
                    let count = self.returns.get(&target).map_or(0, Vec::len);
                    let mut value = 0;
                    for index in 0..count {
                        let expression = self.returns[&target][index];
                        value |= self.artifact(expression, next);
                        if self.steps == 0 {
                            break;
                        }
                    }
                    return value;
                }
                if let Some((object, method)) = member(&call.callee) {
                    if matches!(method, "update" | "final") && self.decipher(object, 0) {
                        return DECRYPTED;
                    }
                    if matches!(method, "text" | "json" | "arrayBuffer") && self.response(object, 0)
                    {
                        return DOWNLOADED;
                    }
                    if method == "toString" {
                        return self.artifact(object, next);
                    }
                    if matches!(method, "concat" | "from") && self.global(object, "Buffer") {
                        return call
                            .arguments
                            .first()
                            .and_then(Argument::as_expression)
                            .map_or(0, |argument| self.artifact(argument, next));
                    }
                }
                0
            }
            _ => 0,
        }
    }

    fn interpreter(&mut self, expression: &Expression<'a>, depth: usize) -> bool {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return false;
        }
        self.steps -= 1;
        match expression.get_inner_expression() {
            Expression::StringLiteral(value) => {
                matches!(
                    value.value.as_str(),
                    "node"
                        | "nodejs"
                        | "sh"
                        | "bash"
                        | "python"
                        | "python3"
                        | "python3.8"
                        | "python3.9"
                        | "python3.10"
                        | "python3.11"
                        | "python3.12"
                )
            }
            Expression::Identifier(identifier) => self
                .initial(identifier)
                .is_some_and(|initial| self.interpreter(initial, depth + 1)),
            Expression::ComputedMemberExpression(member) => {
                let array = match member.object.get_inner_expression() {
                    Expression::Identifier(identifier) => self.initial(identifier),
                    value => Some(value),
                };
                let Some(Expression::ArrayExpression(array)) =
                    array.map(Expression::get_inner_expression)
                else {
                    return false;
                };
                !array.elements.is_empty()
                    && array.elements.iter().all(|element| {
                        element
                            .as_expression()
                            .is_some_and(|value| self.interpreter(value, depth + 1))
                    })
            }
            Expression::CallExpression(call) => {
                let Some(target) = self.target(&call.callee, 0) else {
                    return false;
                };
                let count = self.returns.get(&target).map_or(0, Vec::len);
                let mut found = false;
                for index in 0..count {
                    let value = self.returns[&target][index];
                    if matches!(value.get_inner_expression(), Expression::NullLiteral(_)) {
                        continue;
                    }
                    if !self.interpreter(value, depth + 1) {
                        return false;
                    }
                    found = true;
                }
                found
            }
            _ => false,
        }
    }

    fn path_key<'e>(&self, expression: &'e Expression<'a>, depth: usize) -> Option<PathKey<'e>>
    where
        'a: 'e,
    {
        if depth >= 12 {
            return None;
        }
        match expression.get_inner_expression() {
            Expression::StringLiteral(value) => Some(PathKey::Literal(value.value.as_str())),
            Expression::Identifier(identifier) => {
                let symbol = self.symbol(identifier)?;
                if self.written.contains(&symbol) {
                    return None;
                }
                if let Some(initial) = self.initial(identifier)
                    && matches!(
                        initial.get_inner_expression(),
                        Expression::Identifier(_) | Expression::StringLiteral(_)
                    )
                {
                    return self.path_key(initial, depth + 1);
                }
                Some(PathKey::Symbol(symbol))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum PathKey<'a> {
    Symbol(SymbolId),
    Literal(&'a str),
}

pub(super) fn terminators(semantic: &Semantic<'_>) -> HashMap<u32, u32> {
    semantic
        .nodes()
        .iter()
        .filter_map(|node| {
            let (block, statements) = match node.kind() {
                AstKind::BlockStatement(block) => (block.span.start, &block.body),
                AstKind::FunctionBody(body) => (body.span.start, &body.statements),
                AstKind::Program(program) => (0, &program.body),
                _ => return None,
            };
            statements
                .iter()
                .find(|statement| {
                    matches!(
                        statement,
                        Statement::ReturnStatement(_) | Statement::ThrowStatement(_)
                    )
                })
                .map(|statement| (block, statement.span().end))
        })
        .collect()
}

pub(super) fn reachable(
    semantic: &Semantic<'_>,
    terminators: &HashMap<u32, u32>,
    id: NodeId,
) -> bool {
    let start = semantic.nodes().kind(id).span().start;
    for kind in semantic.nodes().ancestor_kinds(id) {
        let block = match kind {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
            AstKind::IfStatement(statement) => {
                if let Expression::BooleanLiteral(test) = statement.test.get_inner_expression() {
                    if !test.value
                        && statement
                            .consequent
                            .span()
                            .contains_inclusive(oxc_span::Span::new(start, start))
                    {
                        return false;
                    }
                    if test.value
                        && statement.alternate.as_ref().is_some_and(|alternate| {
                            alternate
                                .span()
                                .contains_inclusive(oxc_span::Span::new(start, start))
                        })
                    {
                        return false;
                    }
                }
                continue;
            }
            AstKind::BlockStatement(block) => block.span.start,
            AstKind::FunctionBody(body) => body.span.start,
            AstKind::Program(_) => 0,
            _ => continue,
        };
        if terminators.get(&block).is_some_and(|end| *end <= start) {
            return false;
        }
    }
    true
}

pub(super) fn has_candidates(semantic: &Semantic<'_>) -> bool {
    semantic.nodes().iter().any(|node| match node.kind() {
        AstKind::CallExpression(call) => matches!(
            name(&call.callee),
            Some("createDecipheriv" | "createDecipher" | "rmSync" | "rm" | "eval" | "Function")
        ),
        AstKind::NewExpression(call) => name(&call.callee) == Some("Function"),
        AstKind::ImportSpecifier(specifier) => matches!(
            specifier.imported.name().as_str(),
            "rmSync" | "rm" | "createDecipheriv" | "createDecipher"
        ),
        AstKind::BindingProperty(property) => matches!(
            property.key.static_name().as_deref(),
            Some("rmSync" | "rm" | "createDecipheriv" | "createDecipher")
        ),
        AstKind::StaticMemberExpression(member) => matches!(
            member.property.name.as_str(),
            "rmSync" | "rm" | "createDecipheriv" | "createDecipher"
        ),
        _ => false,
    })
}

pub(super) fn analyze(flow: &mut Flow<'_, '_>, facts: &mut crate::behavioral::bindings::CallFacts) {
    let semantic = flow.semantic;
    let mut writes: HashMap<(_, _), Vec<(u32, u8)>> = HashMap::new();
    for node in semantic.nodes().iter() {
        if let AstKind::CallExpression(call) = node.kind()
            && flow
                .api(&call.callee, 0)
                .is_some_and(|api| api.module == "fs" && api.method == Some("writeFileSync"))
            && let (Some(path), Some(value)) = (
                call.arguments.first().and_then(Argument::as_expression),
                call.arguments.get(1).and_then(Argument::as_expression),
            )
        {
            let block = semantic
                .nodes()
                .ancestor_kinds(node.id())
                .find_map(|kind| match kind {
                    AstKind::BlockStatement(block) => Some(block.span.start),
                    AstKind::FunctionBody(body) => Some(body.span.start),
                    AstKind::Program(_) => Some(0),
                    _ => None,
                });
            if !reachable(semantic, &flow.terminators, node.id()) {
                continue;
            }
            flow.steps = MAX_STEPS;
            if let Some(key) = flow.path_key(path, 0) {
                writes
                    .entry((block, key))
                    .or_default()
                    .push((call.span.start, flow.artifact(value, 0)));
            }
        }
    }
    for values in writes.values_mut() {
        values.sort_unstable_by_key(|(offset, _)| *offset);
    }
    for node in semantic.nodes().iter() {
        let (function, arguments, start) = match node.kind() {
            AstKind::CallExpression(call) => (&call.callee, &call.arguments, call.span.start),
            AstKind::NewExpression(call) => (&call.callee, &call.arguments, call.span.start),
            _ => continue,
        };
        let api = flow.api(function, 0);
        let evaluation = flow.global(function, "eval") || flow.global(function, "Function");
        if !evaluation
            && !api.as_ref().is_some_and(|api| {
                (api.module == "fs" && matches!(api.method, Some("rmSync" | "rm")))
                    || (api.module == "child_process"
                        && matches!(
                            api.method,
                            Some("spawn" | "spawnSync" | "execFile" | "execFileSync" | "fork")
                        ))
            })
        {
            continue;
        }
        if !reachable(semantic, &flow.terminators, node.id()) {
            continue;
        }
        flow.steps = MAX_STEPS;
        let code = if flow.global(function, "eval") {
            arguments.first()
        } else {
            arguments.last()
        };
        if evaluation && let Some(value) = code.and_then(Argument::as_expression) {
            let value = flow.artifact(value, 0);
            if value & DECRYPTED != 0 {
                facts.encrypted_execution.get_or_insert(start as usize);
            }
            if value & DOWNLOADED != 0 {
                facts.downloaded_execution.get_or_insert(start as usize);
            }
        }
        let Some(api) = api else {
            continue;
        };
        if api.module == "fs"
            && matches!(api.method, Some("rmSync" | "rm"))
            && let Some(path) = arguments.first().and_then(Argument::as_expression)
            && flow.broad_directory(path, 0)
            && let Some(options) = arguments.get(1).and_then(Argument::as_expression)
            && matches!(flow.field(options, "recursive", 0).map(Expression::get_inner_expression), Some(Expression::BooleanLiteral(value)) if value.value)
        {
            facts.destructive_filesystem.get_or_insert(start as usize);
        }
        if api.module != "child_process"
            || !matches!(
                api.method,
                Some("spawn" | "spawnSync" | "execFile" | "execFileSync" | "fork")
            )
        {
            continue;
        }
        let block = semantic
            .nodes()
            .ancestor_kinds(node.id())
            .find_map(|kind| match kind {
                AstKind::BlockStatement(block) => Some(block.span.start),
                AstKind::FunctionBody(body) => Some(body.span.start),
                AstKind::Program(_) => Some(0),
                _ => None,
            });
        let mut paths = Vec::with_capacity(2);
        if let Some(path) = arguments.first().and_then(Argument::as_expression) {
            paths.push(path);
        }
        let interpreter = arguments
            .first()
            .and_then(Argument::as_expression)
            .is_some_and(|command| flow.interpreter(command, 0));
        if interpreter
            && let Some(Expression::ArrayExpression(array)) = arguments
                .get(1)
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
            && let Some(path) = array
                .elements
                .first()
                .and_then(ArrayExpressionElement::as_expression)
        {
            paths.push(path);
        }
        for path in paths {
            if let Some(key) = flow.path_key(path, 0)
                && let Some(values) = writes.get(&(block, key))
                && let Some(index) = values
                    .partition_point(|(offset, _)| *offset < start)
                    .checked_sub(1)
            {
                let value = values[index].1;
                if value & DECRYPTED != 0 {
                    facts.encrypted_execution.get_or_insert(start as usize);
                }
                if value & DOWNLOADED != 0 {
                    facts.downloaded_execution.get_or_insert(start as usize);
                }
            }
        }
    }
}
