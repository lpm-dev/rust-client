use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{Semantic, SymbolId};
use oxc_str::JSStr;
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct Bundles {
    loaders: HashMap<SymbolId, SymbolId>,
    exports: HashMap<(SymbolId, u64), HashMap<super::NameKey, SymbolId>>,
}

fn symbol(semantic: &Semantic<'_>, expression: &Expression<'_>) -> Option<SymbolId> {
    let identifier = expression
        .get_inner_expression()
        .get_identifier_reference()?;
    semantic
        .scoping()
        .get_reference(identifier.reference_id.get()?)
        .symbol_id()
}

fn module_id(expression: &Expression<'_>) -> Option<u64> {
    let Expression::NumericLiteral(number) = expression.get_inner_expression() else {
        return None;
    };
    (number.value >= 0.0 && number.value <= u32::MAX as f64 && number.value.fract() == 0.0)
        .then_some(number.value as u64)
}

impl Bundles {
    pub(super) fn collect(semantic: &Semantic<'_>) -> Self {
        let mut result = Self::default();
        for node in semantic.nodes().iter() {
            match node.kind() {
                AstKind::CallExpression(call) => {
                    let Some((object, "call")) = super::named_member(&call.callee) else {
                        continue;
                    };
                    let Expression::ComputedMemberExpression(slot) = object.get_inner_expression()
                    else {
                        continue;
                    };
                    let Some(table) = symbol(semantic, &slot.object) else {
                        continue;
                    };
                    let Some(index) = symbol(semantic, &slot.expression) else {
                        continue;
                    };
                    let function =
                        semantic
                            .nodes()
                            .ancestor_kinds(node.id())
                            .find_map(|kind| match kind {
                                AstKind::Function(function) => Some(function),
                                _ => None,
                            });
                    let Some(function) = function else { continue };
                    let Some(parameter) = function.params.items.first() else {
                        continue;
                    };
                    let BindingPattern::BindingIdentifier(parameter) = &parameter.pattern else {
                        continue;
                    };
                    if parameter.symbol_id.get() != Some(index) {
                        continue;
                    }
                    if let Some(loader) = function.id.as_ref().and_then(|id| id.symbol_id.get()) {
                        result.loaders.insert(loader, table);
                    }
                }
                AstKind::ObjectProperty(property) => {
                    let Expression::ArrowFunctionExpression(getter) =
                        property.value.get_inner_expression()
                    else {
                        continue;
                    };
                    if !getter.params.items.is_empty() {
                        continue;
                    }
                    let Some(exported) = getter.get_expression() else {
                        continue;
                    };
                    let Some(class) = symbol(semantic, exported) else {
                        continue;
                    };
                    if !matches!(
                        semantic
                            .nodes()
                            .kind(semantic.scoping().symbol_declaration(class)),
                        AstKind::Class(_)
                    ) {
                        continue;
                    }
                    let Some(export) = property.key.static_name() else {
                        continue;
                    };
                    let mut module = None;
                    for kind in semantic.nodes().ancestor_kinds(node.id()) {
                        match kind {
                            AstKind::ObjectProperty(factory) if module.is_none() => {
                                if let PropertyKey::NumericLiteral(key) = &factory.key {
                                    module = Some(key.value as u64);
                                }
                            }
                            AstKind::VariableDeclarator(table) if module.is_some() => {
                                let Some(module) = module else { continue };
                                if let BindingPattern::BindingIdentifier(table) = &table.id
                                    && let Some(table) = table.symbol_id.get()
                                {
                                    result
                                        .exports
                                        .entry((table, module))
                                        .or_default()
                                        .insert(export.as_js_str().as_bytes().into(), class);
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }

    pub(super) fn class<'a>(
        &self,
        semantic: &Semantic<'a>,
        request: &CallExpression<'_>,
        export: JSStr<'_>,
    ) -> Option<&'a Class<'a>> {
        let loader = symbol(semantic, &request.callee)?;
        let table = self.loaders.get(&loader)?;
        let module = module_id(request.arguments.first()?.as_expression()?)?;
        let class = self
            .exports
            .get(&(*table, module))?
            .get(export.as_bytes())?;
        match semantic
            .nodes()
            .kind(semantic.scoping().symbol_declaration(*class))
        {
            AstKind::Class(class) => Some(class),
            _ => None,
        }
    }
}
