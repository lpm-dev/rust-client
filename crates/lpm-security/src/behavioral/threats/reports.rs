use super::{CREDENTIAL_FILE, Flow, MAX_DEPTH, member};
use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{NodeId, Semantic, SymbolId};
use oxc_span::GetSpan;
use std::collections::{HashMap, HashSet};

pub(super) struct Write<'a> {
    key: &'a str,
    offset: u32,
    value: &'a Expression<'a>,
}

fn owner(semantic: &Semantic<'_>, id: NodeId) -> u32 {
    semantic
        .nodes()
        .ancestor_kinds(id)
        .find_map(|kind| match kind {
            AstKind::Function(function) => Some(function.span.start),
            AstKind::ArrowFunctionExpression(function) => Some(function.span.start),
            _ => None,
        })
        .unwrap_or(0)
}

fn safe_member_parent(kind: Option<AstKind<'_>>) -> bool {
    match kind {
        Some(
            AstKind::CallExpression(_) | AstKind::UnaryExpression(_) | AstKind::UpdateExpression(_),
        ) => false,
        Some(AstKind::AssignmentExpression(assignment)) => assignment.operator.as_str() == "=",
        _ => true,
    }
}

pub(super) fn collect<'a>(flow: &Flow<'_, 'a>) -> HashMap<SymbolId, Vec<Write<'a>>> {
    let mut writes: HashMap<SymbolId, Vec<Write<'a>>> = HashMap::new();
    for node in flow.semantic.nodes().iter() {
        let AstKind::AssignmentExpression(assignment) = node.kind() else {
            continue;
        };
        let (object, key) = match &assignment.left {
            AssignmentTarget::StaticMemberExpression(member) => {
                (&member.object, member.property.name.as_str())
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                let Expression::StringLiteral(key) = member.expression.get_inner_expression()
                else {
                    continue;
                };
                (&member.object, key.value.as_str())
            }
            _ => continue,
        };
        let Some(symbol) = object
            .get_inner_expression()
            .get_identifier_reference()
            .and_then(|id| flow.symbol(id))
        else {
            continue;
        };
        if assignment.operator.as_str() != "="
            || !super::operations::reachable(flow.semantic, &flow.terminators, node.id())
        {
            continue;
        }
        writes.entry(symbol).or_default().push(Write {
            key,
            offset: assignment.span.start,
            value: &assignment.right,
        });
    }
    writes.retain(|symbol, values| {
        let declaration = flow.semantic.scoping().symbol_declaration(*symbol);
        let AstKind::VariableDeclarator(variable) = flow.semantic.nodes().kind(declaration) else {
            return false;
        };
        if !matches!(
            variable.init.as_ref().map(Expression::get_inner_expression),
            Some(Expression::ObjectExpression(_))
        ) {
            return false;
        }
        let function = owner(flow.semantic, declaration);
        let safe = flow
            .semantic
            .scoping()
            .get_resolved_references(*symbol)
            .all(|reference| {
                if reference.is_write() || owner(flow.semantic, reference.node_id()) != function {
                    return false;
                }
                let mut ancestors = flow.semantic.nodes().ancestor_kinds(reference.node_id());
                match ancestors.next() {
                    Some(AstKind::StaticMemberExpression(_)) => {
                        safe_member_parent(ancestors.next())
                    }
                    Some(AstKind::ComputedMemberExpression(member))
                        if matches!(
                            member.expression.get_inner_expression(),
                            Expression::StringLiteral(_)
                        ) =>
                    {
                        safe_member_parent(ancestors.next())
                    }
                    Some(AstKind::CallExpression(call)) => {
                        member(&call.callee).is_some_and(|(object, method)| {
                            method == "stringify" && flow.global(object, "JSON")
                        })
                    }
                    _ => false,
                }
            });
        values.sort_unstable_by_key(|write| write.offset);
        safe
    });
    writes
}

impl<'a> Flow<'_, 'a> {
    pub(super) fn report_value(
        &mut self,
        identifier: &IdentifierReference<'a>,
        depth: usize,
    ) -> u8 {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return 0;
        }
        let Some(symbol) = self.symbol(identifier) else {
            return 0;
        };
        let count = self.report_writes.get(&symbol).map_or(0, Vec::len);
        let mut fields = HashSet::new();
        let mut result = 0;
        for index in (0..count).rev() {
            if self.steps == 0 {
                break;
            }
            self.steps -= 1;
            let write = &self.report_writes[&symbol][index];
            if write.offset >= identifier.span().start || !fields.insert(write.key) {
                continue;
            }
            let value = write.value;
            result |= self.value(value, depth + 1) & CREDENTIAL_FILE;
        }
        result
    }
}
