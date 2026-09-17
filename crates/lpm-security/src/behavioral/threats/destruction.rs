use super::{Flow, MAX_DEPTH, member};
use oxc_ast::{AstKind, ast::*};
use oxc_span::GetSpan;

const ROOT: u8 = 1;
const ENTRIES: u8 = 2;
const ENTRY: u8 = 4;
const NAME: u8 = 8;
const SELF_FILE: u8 = 16;
const CHILD: u8 = 32;

impl<'a> Flow<'_, 'a> {
    pub(super) fn broad_directory(&mut self, expression: &Expression<'a>, depth: usize) -> bool {
        self.path_fact(expression, depth) & (ROOT | CHILD) != 0
    }

    fn path_fact(&mut self, expression: &Expression<'a>, depth: usize) -> u8 {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return 0;
        }
        self.steps -= 1;
        let next = depth + 1;
        match expression.get_inner_expression() {
            Expression::StringLiteral(value)
                if matches!(value.value.as_str(), "/" | "C:\\" | "C:/") =>
            {
                ROOT
            }
            Expression::Identifier(identifier) => {
                if self.global(expression, "__filename") {
                    return SELF_FILE;
                }
                if let Some(initial) = self.initial(identifier) {
                    return self.path_fact(initial, next);
                }
                let Some(symbol) = self.symbol(identifier) else {
                    return 0;
                };
                if self.written.contains(&symbol) {
                    return 0;
                }
                let declaration = self.semantic.scoping().symbol_declaration(symbol);
                if let AstKind::VariableDeclarator(variable) =
                    self.semantic.nodes().kind(declaration)
                    && variable.init.is_none()
                {
                    let iterable = self.semantic.nodes().ancestor_kinds(declaration).find_map(
                        |kind| match kind {
                            AstKind::ForOfStatement(statement)
                                if statement.left.span().contains_inclusive(variable.span) =>
                            {
                                Some(&statement.right)
                            }
                            _ => None,
                        },
                    );
                    return iterable.map_or(0, |value| {
                        if self.path_fact(value, next) == ENTRIES {
                            ENTRY
                        } else {
                            0
                        }
                    });
                }
                if let Some(iterable) = self.iterations.get(&symbol).copied() {
                    return if self.path_fact(iterable, next) == ENTRIES {
                        ENTRY
                    } else {
                        0
                    };
                }
                let mut value = self
                    .defaults
                    .get(&symbol)
                    .copied()
                    .map_or(0, |value| self.path_fact(value, next));
                if let Some(&(owner, index)) = self.parameters.get(&symbol) {
                    let count = self.callers.get(&owner).map_or(0, Vec::len);
                    for position in 0..count {
                        let call = self.callers[&owner][position];
                        if let Some(argument) =
                            call.arguments.get(index).and_then(Argument::as_expression)
                        {
                            value |= self.path_fact(argument, next);
                        }
                        if self.steps == 0 {
                            break;
                        }
                    }
                }
                value
            }
            Expression::LogicalExpression(value) => {
                self.path_fact(&value.left, next) | self.path_fact(&value.right, next)
            }
            Expression::CallExpression(call) => {
                if let Some((object, "cwd")) = member(&call.callee)
                    && self.global(object, "process")
                {
                    return ROOT;
                }
                if let Some(api) = self.api(&call.callee, 0) {
                    match (api.module, api.method) {
                        ("os", Some("homedir")) => return ROOT,
                        ("path", Some("resolve")) if call.arguments.len() == 1 => {
                            return call
                                .arguments
                                .first()
                                .and_then(Argument::as_expression)
                                .map_or(0, |arg| self.path_fact(arg, next));
                        }
                        ("path", Some("join")) if call.arguments.len() == 2 => {
                            let root = call
                                .arguments
                                .first()
                                .and_then(Argument::as_expression)
                                .map_or(0, |arg| self.path_fact(arg, next));
                            let entry = call
                                .arguments
                                .get(1)
                                .and_then(Argument::as_expression)
                                .map_or(0, |arg| self.path_fact(arg, next));
                            return if root == ROOT && entry == NAME {
                                CHILD
                            } else {
                                0
                            };
                        }
                        ("fs", Some("readdirSync")) => {
                            let value = call
                                .arguments
                                .first()
                                .and_then(Argument::as_expression)
                                .map_or(0, |arg| self.path_fact(arg, next));
                            return if value == ROOT { ENTRIES } else { 0 };
                        }
                        _ => {}
                    }
                }
                if let Some(target) = self.target(&call.callee, 0) {
                    let count = self.returns.get(&target).map_or(0, Vec::len);
                    let mut result = 0;
                    for index in 0..count {
                        result |= self.path_fact(self.returns[&target][index], next);
                        if self.steps == 0 {
                            break;
                        }
                    }
                    return result;
                }
                if let Some((object, "filter")) = member(&call.callee)
                    && self.path_fact(object, next) == ENTRIES
                    && let Some(predicate) =
                        call.arguments.first().and_then(Argument::as_expression)
                    && let Some(target) = self.target(predicate, 0)
                    && self
                        .returns
                        .get(&target)
                        .is_some_and(|values| values.len() == 1)
                    && let Expression::BinaryExpression(binary) =
                        self.returns[&target][0].get_inner_expression()
                    && matches!(binary.operator.as_str(), "!==" | "!=")
                {
                    let left = self.path_fact(&binary.left, next);
                    let right = self.path_fact(&binary.right, next);
                    if (left == CHILD && right == SELF_FILE)
                        || (right == CHILD && left == SELF_FILE)
                    {
                        return ENTRIES;
                    }
                }
                0
            }
            expression => {
                if let Some((object, "name")) = member(expression)
                    && self.path_fact(object, next) == ENTRY
                {
                    NAME
                } else {
                    0
                }
            }
        }
    }
}
