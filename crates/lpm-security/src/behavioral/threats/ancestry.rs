use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::GetSpan;
use std::collections::HashMap;

/// What encloses each node of a file, and whether it can run.
///
/// The rules ask these questions of many nodes. Walking up from each one
/// costs its depth, and a crafted file can nest tens of thousands of
/// levels around every node a rule asks about. Nodes are numbered
/// parents first, so one pass in node order answers every question for
/// every node.
pub(super) struct Ancestry {
    unreachable: Vec<bool>,
    function_or_arrow: Vec<Option<NodeId>>,
    function: Vec<Option<NodeId>>,
    block: Vec<Option<NodeId>>,
    numeric_property: Vec<Option<NodeId>>,
    declarator: Vec<Option<NodeId>>,
    for_of_left: Vec<Option<NodeId>>,
}

impl Ancestry {
    pub(super) fn new(semantic: &Semantic<'_>) -> Self {
        let nodes = semantic.nodes();
        let terminators = terminators(semantic);
        let len = nodes.len();
        let mut ancestry = Self {
            unreachable: vec![false; len],
            function_or_arrow: vec![None; len],
            function: vec![None; len],
            block: vec![None; len],
            numeric_property: vec![None; len],
            declarator: vec![None; len],
            for_of_left: vec![None; len],
        };
        for (id, node) in nodes.iter_enumerated() {
            if id == NodeId::ROOT {
                continue;
            }
            let parent = nodes.parent_id(id);
            let (child, up) = (id.index(), parent.index());
            debug_assert!(up < child, "a parent precedes its children");
            let parent_kind = nodes.kind(parent);
            let start = node.kind().span().start;
            ancestry.unreachable[child] = match parent_kind {
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => false,
                AstKind::IfStatement(statement) => {
                    skipped_branch(statement, start) || ancestry.unreachable[up]
                }
                _ => {
                    block_key(parent_kind)
                        .and_then(|block| terminators.get(&block))
                        .is_some_and(|end| *end <= start)
                        || ancestry.unreachable[up]
                }
            };
            ancestry.function_or_arrow[child] = match parent_kind {
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => Some(parent),
                _ => ancestry.function_or_arrow[up],
            };
            ancestry.function[child] = match parent_kind {
                AstKind::Function(_) => Some(parent),
                _ => ancestry.function[up],
            };
            ancestry.block[child] = match block_key(parent_kind) {
                Some(_) => Some(parent),
                None => ancestry.block[up],
            };
            ancestry.numeric_property[child] = match parent_kind {
                AstKind::ObjectProperty(property)
                    if matches!(property.key, PropertyKey::NumericLiteral(_)) =>
                {
                    Some(parent)
                }
                _ => ancestry.numeric_property[up],
            };
            ancestry.declarator[child] = match parent_kind {
                AstKind::VariableDeclarator(_) => Some(parent),
                _ => ancestry.declarator[up],
            };
            ancestry.for_of_left[child] = match parent_kind {
                AstKind::ForOfStatement(statement)
                    if statement.left.span().contains_inclusive(node.kind().span()) =>
                {
                    Some(parent)
                }
                _ => ancestry.for_of_left[up],
            };
        }
        ancestry
    }

    /// Whether the node can run as far as its own function can tell:
    /// it isn't in the untaken branch of an `if` on a boolean literal, or
    /// after a block's `return` or `throw`.
    pub(super) fn reachable(&self, id: NodeId) -> bool {
        !self.unreachable[id.index()]
    }

    /// The start of the nearest function or arrow function around the
    /// node.
    pub(super) fn function_or_arrow_start(
        &self,
        semantic: &Semantic<'_>,
        id: NodeId,
    ) -> Option<u32> {
        self.function_or_arrow[id.index()]
            .map(|function| semantic.nodes().kind(function).span().start)
    }

    /// The nearest `function` (not an arrow function) around the node.
    pub(super) fn function<'a>(
        &self,
        semantic: &Semantic<'a>,
        id: NodeId,
    ) -> Option<&'a Function<'a>> {
        match semantic.nodes().kind(self.function[id.index()]?) {
            AstKind::Function(function) => Some(function),
            _ => None,
        }
    }

    /// The key of the nearest block around the node, as [`terminators`]
    /// keys it.
    pub(super) fn block(&self, semantic: &Semantic<'_>, id: NodeId) -> Option<u32> {
        block_key(semantic.nodes().kind(self.block[id.index()]?))
    }

    /// The nearest object property with a numeric key around the node.
    pub(super) fn numeric_property(&self, id: NodeId) -> Option<NodeId> {
        self.numeric_property[id.index()]
    }

    /// The nearest `for…of` whose left side holds the node.
    pub(super) fn for_of_left<'a>(
        &self,
        semantic: &Semantic<'a>,
        id: NodeId,
    ) -> Option<&'a ForOfStatement<'a>> {
        match semantic.nodes().kind(self.for_of_left[id.index()]?) {
            AstKind::ForOfStatement(statement) => Some(statement),
            _ => None,
        }
    }

    /// The nearest variable declarator around the node.
    pub(super) fn declarator<'a>(
        &self,
        semantic: &Semantic<'a>,
        id: NodeId,
    ) -> Option<&'a VariableDeclarator<'a>> {
        match semantic.nodes().kind(self.declarator[id.index()]?) {
            AstKind::VariableDeclarator(declarator) => Some(declarator),
            _ => None,
        }
    }
}

/// Whether a node starting at `start`, under `statement`, is in the branch
/// an `if` on a boolean literal never takes.
fn skipped_branch(statement: &IfStatement<'_>, start: u32) -> bool {
    let Expression::BooleanLiteral(test) = statement.test.get_inner_expression() else {
        return false;
    };
    let at = oxc_span::Span::new(start, start);
    if test.value {
        statement
            .alternate
            .as_ref()
            .is_some_and(|alternate| alternate.span().contains_inclusive(at))
    } else {
        statement.consequent.span().contains_inclusive(at)
    }
}

/// The key of a block-like node: its start, or 0 for the program.
fn block_key(kind: AstKind<'_>) -> Option<u32> {
    match kind {
        AstKind::BlockStatement(block) => Some(block.span.start),
        AstKind::FunctionBody(body) => Some(body.span.start),
        AstKind::Program(_) => Some(0),
        _ => None,
    }
}

/// The end of the first `return` or `throw` among each block's own
/// statements, keyed by [`block_key`].
fn terminators(semantic: &Semantic<'_>) -> HashMap<u32, u32> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;
    use oxc_parser::{ParseOptions, Parser};
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;

    /// The walk up from one node that the table replaces.
    fn walked_reachable(
        semantic: &Semantic<'_>,
        terminators: &HashMap<u32, u32>,
        id: NodeId,
    ) -> bool {
        let start = semantic.nodes().kind(id).span().start;
        for kind in semantic.nodes().ancestor_kinds(id) {
            let block = match kind {
                AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => break,
                AstKind::IfStatement(statement) => {
                    if skipped_branch(statement, start) {
                        return false;
                    }
                    continue;
                }
                _ => match block_key(kind) {
                    Some(block) => block,
                    None => continue,
                },
            };
            if terminators.get(&block).is_some_and(|end| *end <= start) {
                return false;
            }
        }
        true
    }

    fn walked(
        semantic: &Semantic<'_>,
        id: NodeId,
        matches: impl Fn(AstKind<'_>) -> bool,
    ) -> Option<NodeId> {
        semantic
            .nodes()
            .ancestor_ids(id)
            .find(|&ancestor| matches(semantic.nodes().kind(ancestor)))
    }

    fn assert_matches_walks(source: &str) {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source, SourceType::cjs())
            .with_options(ParseOptions {
                allow_return_outside_function: true,
                ..ParseOptions::default()
            })
            .parse();
        assert!(
            parsed.diagnostics.is_empty(),
            "{source}: {:?}",
            parsed.diagnostics
        );
        let built = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program);
        let semantic = &built.semantic;
        let ancestry = Ancestry::new(semantic);
        let terminators = terminators(semantic);
        let mut unreachable = 0;
        for (id, node) in semantic.nodes().iter_enumerated() {
            // Zero-width nodes, such as an empty template element, are
            // never asked about.
            if node.kind().span().is_empty() {
                continue;
            }
            let reachable = walked_reachable(semantic, &terminators, id);
            unreachable += usize::from(!reachable);
            assert_eq!(
                ancestry.reachable(id),
                reachable,
                "{source}: reachable({:?})",
                node.kind().debug_name()
            );
            assert_eq!(
                ancestry.function_or_arrow[id.index()],
                walked(semantic, id, |kind| matches!(
                    kind,
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
                )),
            );
            assert_eq!(
                ancestry.function[id.index()],
                walked(semantic, id, |kind| matches!(kind, AstKind::Function(_))),
            );
            assert_eq!(
                ancestry.block[id.index()],
                walked(semantic, id, |kind| block_key(kind).is_some()),
            );
            assert_eq!(
                ancestry.numeric_property(id),
                walked(
                    semantic,
                    id,
                    |kind| matches!(kind, AstKind::ObjectProperty(property) if matches!(property.key, PropertyKey::NumericLiteral(_)))
                ),
            );
            assert_eq!(
                ancestry.declarator[id.index()],
                walked(semantic, id, |kind| matches!(
                    kind,
                    AstKind::VariableDeclarator(_)
                )),
            );
            let span = node.kind().span();
            assert_eq!(
                ancestry.for_of_left[id.index()],
                walked(semantic, id, |kind| matches!(
                    kind,
                    AstKind::ForOfStatement(statement)
                        if statement.left.span().contains_inclusive(span)
                )),
                "{source}: for_of_left({:?})",
                node.kind().debug_name()
            );
        }
        assert!(
            unreachable > 0 || !source.contains("dead"),
            "{source}: nothing was unreachable"
        );
    }

    #[test]
    fn the_table_answers_what_walking_up_from_each_node_answers() {
        for source in [
            "eval(a); if (false) { eval(dead) } else { eval(b) }",
            "if (true) { eval(a) } else { eval(dead); if (x) { eval(dead) } }",
            "if (!0) { eval(a) } if ((false)) { eval(dead) }",
            "function f() { eval(a); return 1; eval(dead); { eval(dead) } }",
            "function f() { { eval(a); throw e; eval(dead) } eval(b); return; const g = () => { eval(c) }; }",
            "{return 1} eval(dead); function g() { eval(c) }",
            " {return 1} eval(b)",
            "return; eval(dead); (function () { eval(c) })()",
            "const f = () => { return eval(a) }; const g = () => eval(b);",
            "if (false) function h() { eval(c) }",
            "label: { eval(a); break label; } try { eval(b); throw x } catch (e) { eval(c) } finally { eval(d) }",
            "switch (x) { case 1: eval(a); return; eval(later) }",
            "const tpl = `${eval(a)}${b}`; class C { m() { return; eval(dead) } static { eval(e) } }",
            "var t = {1: {a: () => C, 2: {b: () => C}}, x: {3: () => C}}; class C {}",
            "var m = {}; function r(i) { return m[i].call(m[i].call(0)) } var w = function () { m[i].call(1) };",
            "for (const [k] of Object.entries(o)) { eval(k) } while (0) { eval(a) } do { return } while (1); eval(after)",
            "var x; for (const y of a) { var z; for (x of b) {} for (var w of c) { var v; } }",
        ] {
            assert_matches_walks(source);
        }
    }

    #[test]
    fn nesting_ten_thousand_levels_deep_takes_one_pass() {
        // Parsing and semantic analysis recurse once per level; give them
        // the stack the analysis gives them in production.
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(ten_thousand_levels_deep)
            .unwrap()
            .join()
            .unwrap();
    }

    fn ten_thousand_levels_deep() {
        let depth = 10_000;
        let mut source = String::new();
        for _ in 0..depth {
            source.push_str("{eval(a);");
        }
        for _ in 0..depth {
            source.push_str("return;}");
        }
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, &source, SourceType::cjs())
            .with_options(ParseOptions {
                allow_return_outside_function: true,
                ..ParseOptions::default()
            })
            .parse();
        let built = SemanticBuilder::new()
            .with_build_nodes(true)
            .build(&parsed.program);
        let started = std::time::Instant::now();
        let ancestry = Ancestry::new(&built.semantic);
        let reachable = built
            .semantic
            .nodes()
            .iter_enumerated()
            .filter(|(id, node)| {
                matches!(node.kind(), AstKind::CallExpression(_)) && ancestry.reachable(*id)
            })
            .count();
        assert_eq!(reachable, depth);
        // Walking up from each of the 10,000 calls reads 50 million
        // ancestors; the table reads each node once.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
}
